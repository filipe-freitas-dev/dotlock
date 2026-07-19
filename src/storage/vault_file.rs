use std::path::Path;

use base64::{Engine, engine::general_purpose};

use crate::{
    crypto::{
        VaultKeyMetadata,
        integrity::{decrypt_hash, encrypt_hash},
        sdk,
        share::{recipient_alg_for_public_key_b64, wrap_dek_for_public_key_b64},
    },
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    storage::secure_fs,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetSummary {
    pub old_kek_version: u32,
    pub new_kek_version: u32,
    pub secrets_rewrapped: usize,
    pub recipients_rewrapped: usize,
    /// Recipients that did NOT receive the new project key because their
    /// grant signature failed verification against the vault's authorized
    /// signers (H3). Always 0 on vaults without authorized signers.
    pub recipients_skipped: usize,
}

pub fn save_vault_metadata<P: AsRef<Path>>(
    path: P,
    metadata: &VaultKeyMetadata,
) -> DotLockResult<()> {
    let path = path.as_ref();
    let mut metadata = metadata.clone();
    metadata.version = metadata.version.max(2);

    let content =
        toml::to_string_pretty(&metadata).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(path, &content, 0o700, 0o600)
}

pub fn load_vault_metadata<P: AsRef<Path>>(path: P) -> DotLockResult<VaultKeyMetadata> {
    let content = secure_fs::read_to_string(path.as_ref())?;
    let metadata = toml::from_str::<VaultKeyMetadata>(&content)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    Ok(metadata)
}

pub fn record_vault_write(metadata: &mut VaultKeyMetadata) {
    metadata.kek_writes_since_rotate = metadata.kek_writes_since_rotate.saturating_add(1);
}

pub fn should_auto_ratchet_for_next_write(metadata: &VaultKeyMetadata) -> bool {
    metadata
        .config
        .auto_ratchet_after_writes
        .is_some_and(|threshold| {
            threshold > 0 && metadata.kek_writes_since_rotate.saturating_add(1) >= threshold
        })
}

/// FG5: decides whether `dl rotate --if-due` should rotate NOW, returning a
/// human-readable reason (or `None` when nothing is due). Two policies, both
/// opt-in via `dl config set`:
/// - `rotate_max_age_days`: age since `last_rotated_at` crossed the limit. A
///   vault that never recorded a rotation (`last_rotated_at == 0`) is due
///   immediately, establishing the baseline on the first scheduled run.
/// - `auto_ratchet_after_writes`: the write counter already reached the
///   threshold (the ratchet normally fires on the next write; a scheduled
///   `--if-due` run rotates without waiting for one).
pub fn rotation_due(metadata: &VaultKeyMetadata, now_unix: i64) -> Option<String> {
    if let Some(max_age_days) = metadata.config.rotate_max_age_days
        && max_age_days > 0
    {
        if metadata.last_rotated_at == 0 {
            return Some("no rotation recorded yet (rotate_max_age_days is set)".to_string());
        }
        let age_secs = now_unix.saturating_sub(metadata.last_rotated_at);
        let max_age_secs = (max_age_days as i64).saturating_mul(86_400);
        if age_secs >= max_age_secs {
            return Some(format!(
                "last rotation is {} day(s) old (policy: rotate_max_age_days = {max_age_days})",
                age_secs / 86_400
            ));
        }
    }
    if let Some(threshold) = metadata.config.auto_ratchet_after_writes
        && threshold > 0
        && metadata.kek_writes_since_rotate >= threshold
    {
        return Some(format!(
            "{} write(s) since the last rotation (policy: auto_ratchet_after_writes = {threshold})",
            metadata.kek_writes_since_rotate
        ));
    }
    None
}

/// Rotates the PROJECT KEY (DEK) wrapping model: every per-secret SDK and
/// every recipient's `wrapped_dek_b64` is rewrapped under `new_project_key`,
/// and the integrity hash is re-encrypted. `kek_version` is bumped only
/// because the KEK that wraps the new DEK is derived with it — `dl rotate`
/// rotates the DEK, not "the KEK" in isolation.
pub fn rotate_project_key_wrapping(
    metadata: &mut VaultKeyMetadata,
    current_project_key: &ProjectKey,
    new_project_key: &ProjectKey,
) -> DotLockResult<RatchetSummary> {
    let old_kek_version = metadata.kek_version;
    let mut secrets_rewrapped = 0usize;
    let mut rewrapped_sdks = std::collections::HashMap::new();

    for (secret_id, wrapped_sdk) in &metadata.wrapped_sdks_under_dek {
        let secret_key = sdk::unwrap_sdk_with_project_key(wrapped_sdk, current_project_key)?;
        rewrapped_sdks.insert(
            secret_id.clone(),
            sdk::wrap_sdk_for_project_key(&secret_key, new_project_key)?,
        );
        secrets_rewrapped += 1;
    }
    metadata.wrapped_sdks_under_dek = rewrapped_sdks;

    // H3: once the vault records authorized signers, only recipients whose
    // grant signature verifies receive the fresh project key. A recipient
    // injected without a valid grant (e.g. via a manually accepted merge)
    // keeps only its stale wrapping, which the rotation makes useless.
    let enforce_grants = !metadata.authorized_signers.is_empty();
    let project_uuid = metadata.project_uuid.clone();
    let signers = metadata.authorized_signers.clone();
    let mut recipients_rewrapped = 0usize;
    let mut recipients_skipped = 0usize;
    for recipient in &mut metadata.recipients {
        if recipient.wrapped_dek_b64.is_empty() {
            continue;
        }
        if enforce_grants
            && !crate::storage::shared_access::recipient_grant_is_valid(
                &project_uuid,
                &signers,
                recipient,
            )
        {
            recipients_skipped += 1;
            continue;
        }
        // The wrap dispatches on the recipient's key type (X25519 sealed box
        // or legacy RSA-OAEP), so mixed vaults rotate correctly; the alg tag
        // is normalized to match the key.
        recipient.wrapped_dek_b64 =
            wrap_dek_for_public_key_b64(new_project_key.as_bytes(), &recipient.public_key_b64)?;
        recipient.alg = recipient_alg_for_public_key_b64(&recipient.public_key_b64)?.to_string();
        recipients_rewrapped += 1;
    }

    // Re-encrypt the secrets integrity hash under the NEW project key in the
    // same metadata object, so a single transactional write commits the rewrap
    // and the hash together (a crash can never leave the hash encrypted under
    // an unrecoverable key).
    reencrypt_secrets_hash(metadata, current_project_key, new_project_key)?;

    metadata.kek_version = metadata.kek_version.saturating_add(1);
    metadata.kek_writes_since_rotate = 0;
    // FG5: the timestamp feeds the `rotate_max_age_days` policy and is
    // MAC-covered from here on (the caller reseals before committing).
    metadata.last_rotated_at = crate::storage::secrets_lock::current_unix_timestamp();

    Ok(RatchetSummary {
        old_kek_version,
        new_kek_version: metadata.kek_version,
        secrets_rewrapped,
        recipients_rewrapped,
        recipients_skipped,
    })
}

fn reencrypt_secrets_hash(
    metadata: &mut VaultKeyMetadata,
    current_project_key: &ProjectKey,
    new_project_key: &ProjectKey,
) -> DotLockResult<()> {
    if metadata.secrets_hash_b64.is_empty() || metadata.secrets_hash_nonce_b64.is_empty() {
        return Ok(());
    }

    let nonce_bytes = general_purpose::STANDARD
        .decode(&metadata.secrets_hash_nonce_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| DotLockError::LegacyVaultFormat)?;
    let ciphertext = general_purpose::STANDARD
        .decode(&metadata.secrets_hash_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let hash = decrypt_hash(&nonce, &ciphertext, current_project_key)?;
    let encrypted = encrypt_hash(&hash, new_project_key)?;
    metadata.secrets_hash_nonce_b64 = general_purpose::STANDARD.encode(encrypted.nonce);
    metadata.secrets_hash_b64 = general_purpose::STANDARD.encode(encrypted.ciphertext);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{AccessMode, VaultConfig, VaultKeyMetadata, sdk},
        domain::keys::{ProjectKey, SecretKey},
        storage::vault_file::rotate_project_key_wrapping,
    };

    const TEST_SECRETS_HASH: [u8; 32] = [7u8; 32];

    fn metadata_with_hash_key(hash_key: &ProjectKey) -> VaultKeyMetadata {
        use base64::{Engine, engine::general_purpose};

        let encrypted = crate::crypto::integrity::encrypt_hash(&TEST_SECRETS_HASH, hash_key)
            .expect("encrypt hash");
        VaultKeyMetadata {
            version: 3,
            project_uuid: "project".to_string(),
            project: "dotlock".to_string(),
            environment: "dev".to_string(),
            kdf: "argon2id".to_string(),
            salt_b64: "salt".to_string(),
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
            kek_version: 1,
            kek_writes_since_rotate: 7,
            wrapped_dek_nonce_b64: "nonce".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks_under_dek: std::collections::HashMap::new(),
            access_mode: AccessMode::MasterPassword,
            recipients: Vec::new(),
            authorized_signers: Vec::new(),
            config: VaultConfig {
                auto_ratchet_after_writes: Some(10),
                ..VaultConfig::default()
            },
            secrets_hash_nonce_b64: general_purpose::STANDARD.encode(encrypted.nonce),
            secrets_hash_b64: general_purpose::STANDARD.encode(encrypted.ciphertext),
            secrets_hash_sha256_b64: "hash_plain".to_string(),
            last_rotated_at: 0,
            vault_epoch: 0,
            metadata_mac_b64: String::new(),
        }
    }

    fn metadata() -> VaultKeyMetadata {
        metadata_with_hash_key(&ProjectKey::new([8u8; 32]))
    }

    #[test]
    fn rotate_project_key_wrapping_rewraps_sdks_without_changing_secret_keys() {
        let old_project_key = ProjectKey::new([8u8; 32]);
        let new_project_key = ProjectKey::new([9u8; 32]);
        let sdk = SecretKey::new([3u8; 32]);
        let mut metadata = metadata();
        metadata.wrapped_sdks_under_dek.insert(
            "secret-id".to_string(),
            sdk::wrap_sdk_for_project_key(&sdk, &old_project_key).expect("wrap old sdk"),
        );
        let before = metadata.wrapped_sdks_under_dek["secret-id"].clone();

        let summary =
            rotate_project_key_wrapping(&mut metadata, &old_project_key, &new_project_key)
                .expect("rotate");

        let after = metadata.wrapped_sdks_under_dek["secret-id"].clone();
        assert_ne!(before, after);
        assert_eq!(
            sdk::unwrap_sdk_with_project_key(&after, &new_project_key)
                .expect("unwrap new sdk")
                .as_bytes(),
            sdk.as_bytes()
        );
        assert_eq!(metadata.kek_version, 2);
        assert_eq!(metadata.kek_writes_since_rotate, 0);
        assert_eq!(summary.secrets_rewrapped, 1);
    }

    #[test]
    fn rotate_project_key_wrapping_can_rewrap_legacy_recipients_without_plaintext_decrypt() {
        let old_project_key = ProjectKey::new([8u8; 32]);
        let new_project_key = ProjectKey::new([9u8; 32]);
        let mut metadata = metadata();
        let identity = crate::crypto::share::generate_identity(
            crate::crypto::share::IdentityProtection::Plain,
        )
        .expect("identity");
        let before = crate::crypto::share::wrap_dek_for_public_key(
            old_project_key.as_bytes(),
            &identity.public_key_pem,
        )
        .expect("wrap old project key");
        metadata.recipients.push(crate::crypto::VaultRecipient {
            id: "alice".to_string(),
            label: "alice".to_string(),
            alg: crate::crypto::share::RECIPIENT_ALG.to_string(),
            public_key_fingerprint: identity.fingerprint,
            public_key_b64: crate::crypto::share::encode_public_key_b64(&identity.public_key_pem)
                .expect("pub b64"),
            wrapped_dek_b64: before.clone(),
            wrapped_sdks: std::collections::HashMap::new(),
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
            full_access: true,
        });

        let summary =
            rotate_project_key_wrapping(&mut metadata, &old_project_key, &new_project_key)
                .expect("rotate");

        assert_ne!(metadata.recipients[0].wrapped_dek_b64, before);
        assert_eq!(summary.recipients_rewrapped, 1);
    }

    #[test]
    fn rotate_project_key_wrapping_reencrypts_secrets_hash_under_new_project_key() {
        use base64::{Engine, engine::general_purpose};

        let old_project_key = ProjectKey::new([8u8; 32]);
        let new_project_key = ProjectKey::new([9u8; 32]);
        let mut metadata = metadata();
        let old_nonce = metadata.secrets_hash_nonce_b64.clone();
        let old_hash = metadata.secrets_hash_b64.clone();

        rotate_project_key_wrapping(&mut metadata, &old_project_key, &new_project_key)
            .expect("rotate");

        assert_ne!(metadata.secrets_hash_nonce_b64, old_nonce);
        assert_ne!(metadata.secrets_hash_b64, old_hash);

        let nonce: [u8; 24] = general_purpose::STANDARD
            .decode(&metadata.secrets_hash_nonce_b64)
            .expect("nonce b64")
            .try_into()
            .expect("nonce len");
        let ciphertext = general_purpose::STANDARD
            .decode(&metadata.secrets_hash_b64)
            .expect("hash b64");
        // Decryptable under the NEW key with the same plaintext hash...
        let hash = crate::crypto::integrity::decrypt_hash(&nonce, &ciphertext, &new_project_key)
            .expect("decrypt under new key");
        assert_eq!(hash, super::tests::TEST_SECRETS_HASH);
        // ...and no longer under the old key.
        assert!(
            crate::crypto::integrity::decrypt_hash(&nonce, &ciphertext, &old_project_key).is_err()
        );
    }

    /// Mixed-recipient rotation (ADR 0001 transition window): one legacy RSA
    /// recipient and one modern Ed25519 recipient both receive the fresh
    /// project key, each wrapped with THEIR key's algorithm — RSA-OAEP (a
    /// public-key operation, not Marvin-affected) and X25519 sealed box.
    #[test]
    fn rotate_project_key_wrapping_handles_mixed_rsa_and_ed25519_recipients() {
        use crate::crypto::share::{
            IdentityProtection, RECIPIENT_ALG, RECIPIENT_ALG_X25519, encode_public_key_b64,
            generate_identity, generate_legacy_rsa_identity, unwrap_dek_with_private_key,
        };

        let old_project_key = ProjectKey::new([8u8; 32]);
        let new_project_key = ProjectKey::new([9u8; 32]);
        let legacy = generate_legacy_rsa_identity(IdentityProtection::Plain).expect("legacy");
        let modern = generate_identity(IdentityProtection::Plain).expect("modern");

        let mut metadata = metadata();
        for (identity, alg) in [(&legacy, RECIPIENT_ALG), (&modern, RECIPIENT_ALG_X25519)] {
            metadata.recipients.push(crate::crypto::VaultRecipient {
                id: identity.fingerprint.clone(),
                label: identity.fingerprint.clone(),
                alg: alg.to_string(),
                public_key_fingerprint: identity.fingerprint.clone(),
                public_key_b64: encode_public_key_b64(&identity.public_key_pem).expect("pub b64"),
                wrapped_dek_b64: crate::crypto::share::wrap_dek_for_public_key(
                    old_project_key.as_bytes(),
                    &identity.public_key_pem,
                )
                .expect("wrap old key"),
                wrapped_sdks: std::collections::HashMap::new(),
                grant_signature_b64: String::new(),
                grant_signer_fingerprint: String::new(),
                full_access: true,
            });
        }

        let summary =
            rotate_project_key_wrapping(&mut metadata, &old_project_key, &new_project_key)
                .expect("rotate");

        assert_eq!(summary.recipients_rewrapped, 2);
        for (index, identity) in [&legacy, &modern].into_iter().enumerate() {
            let recipient = &metadata.recipients[index];
            let unwrapped =
                unwrap_dek_with_private_key(&recipient.wrapped_dek_b64, &identity.private_key_pem)
                    .expect("unwrap rotated key");
            assert_eq!(&unwrapped, new_project_key.as_bytes());
        }
        // Alg tags stay true to each recipient's key type.
        assert_eq!(metadata.recipients[0].alg, RECIPIENT_ALG);
        assert_eq!(metadata.recipients[1].alg, RECIPIENT_ALG_X25519);
    }

    /// H3 sink: once the vault has authorized signers, a rotation never wraps
    /// the fresh project key for a recipient whose grant signature does not
    /// verify — its stale wrapping is left behind and becomes useless.
    #[test]
    fn rotate_project_key_wrapping_skips_recipients_without_valid_grant() {
        use crate::{
            crypto::{AuthorizedSigner, VaultRecipient},
            storage::shared_access::{recipient_grant_is_valid, recipient_grant_payload},
        };

        let old_project_key = ProjectKey::new([8u8; 32]);
        let new_project_key = ProjectKey::new([9u8; 32]);
        let owner = crate::crypto::share::generate_identity(
            crate::crypto::share::IdentityProtection::Plain,
        )
        .expect("identity");
        let owner_pub_b64 =
            crate::crypto::share::encode_public_key_b64(&owner.public_key_pem).expect("pub b64");

        let mut metadata = metadata();
        metadata.authorized_signers = vec![AuthorizedSigner {
            fingerprint: owner.fingerprint.clone(),
            public_key_b64: owner_pub_b64.clone(),
            label: "owner".to_string(),
        }];

        // A properly signed recipient (real public key, valid grant).
        let payload = recipient_grant_payload(
            &metadata.project_uuid,
            &owner.fingerprint,
            &owner_pub_b64,
            &owner.fingerprint,
        );
        let signature =
            crate::crypto::share::sign_recipient_grant(&payload, &owner.private_key_pem)
                .expect("sign grant");
        let signed_recipient = VaultRecipient {
            id: "signed-id".to_string(),
            label: "signed".to_string(),
            alg: crate::crypto::share::RECIPIENT_ALG.to_string(),
            public_key_fingerprint: owner.fingerprint.clone(),
            public_key_b64: owner_pub_b64.clone(),
            wrapped_dek_b64: "old-signed-wrap".to_string(),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: true,
            grant_signature_b64: signature,
            grant_signer_fingerprint: owner.fingerprint.clone(),
        };
        // An injected recipient without a valid grant.
        let injected_recipient = VaultRecipient {
            id: "injected-id".to_string(),
            label: "injected".to_string(),
            alg: crate::crypto::share::RECIPIENT_ALG.to_string(),
            public_key_fingerprint: "injected-fp".to_string(),
            public_key_b64: "aW5qZWN0ZWQ=".to_string(),
            wrapped_dek_b64: "old-injected-wrap".to_string(),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: true,
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
        };
        assert!(recipient_grant_is_valid(
            &metadata.project_uuid,
            &metadata.authorized_signers,
            &signed_recipient
        ));
        metadata.recipients = vec![signed_recipient, injected_recipient];

        let summary =
            rotate_project_key_wrapping(&mut metadata, &old_project_key, &new_project_key)
                .expect("rotate");

        assert_eq!(summary.recipients_rewrapped, 1);
        assert_eq!(summary.recipients_skipped, 1);
        // The valid recipient got the new key (its wrapping changed and
        // unwraps to the new project key with the owner's private key)...
        assert_ne!(metadata.recipients[0].wrapped_dek_b64, "old-signed-wrap");
        let unwrapped = crate::crypto::share::unwrap_dek_with_private_key(
            &metadata.recipients[0].wrapped_dek_b64,
            &owner.private_key_pem,
        )
        .expect("unwrap new project key");
        assert_eq!(&unwrapped, new_project_key.as_bytes());
        // ...while the injected one was never wrapped to the new key.
        assert_eq!(metadata.recipients[1].wrapped_dek_b64, "old-injected-wrap");
    }

    /// FG5: the due-decision for `dl rotate --if-due`.
    #[test]
    fn rotation_due_honors_age_and_write_count_policies() {
        use crate::storage::vault_file::rotation_due;

        let now = 1_700_000_000i64;
        let day = 86_400i64;

        // No policy configured: never due.
        let mut metadata = metadata();
        metadata.config.auto_ratchet_after_writes = None;
        assert!(rotation_due(&metadata, now).is_none());

        // Age policy: not due while younger than the limit, due once crossed,
        // and due immediately when no rotation was ever recorded.
        metadata.config.rotate_max_age_days = Some(30);
        metadata.last_rotated_at = now - 29 * day;
        assert!(rotation_due(&metadata, now).is_none());
        metadata.last_rotated_at = now - 30 * day;
        assert!(rotation_due(&metadata, now).is_some());
        metadata.last_rotated_at = 0;
        assert!(rotation_due(&metadata, now).is_some());

        // Write-count policy: due once the counter reaches the threshold.
        let mut by_writes = super::tests::metadata();
        by_writes.config.auto_ratchet_after_writes = Some(10);
        by_writes.kek_writes_since_rotate = 9;
        assert!(rotation_due(&by_writes, now).is_none());
        by_writes.kek_writes_since_rotate = 10;
        assert!(rotation_due(&by_writes, now).is_some());
    }

    /// FG5: a project-key rotation records its timestamp so the age policy
    /// has a baseline.
    #[test]
    fn rotate_project_key_wrapping_records_last_rotated_at() {
        let old_project_key = ProjectKey::new([8u8; 32]);
        let new_project_key = ProjectKey::new([9u8; 32]);
        let mut metadata = metadata();
        assert_eq!(metadata.last_rotated_at, 0);

        rotate_project_key_wrapping(&mut metadata, &old_project_key, &new_project_key)
            .expect("rotate");

        assert!(metadata.last_rotated_at > 0);
    }

    #[test]
    fn rotate_project_key_wrapping_leaves_legacy_empty_hash_untouched() {
        let old_project_key = ProjectKey::new([8u8; 32]);
        let new_project_key = ProjectKey::new([9u8; 32]);
        let mut metadata = metadata();
        metadata.secrets_hash_nonce_b64 = String::new();
        metadata.secrets_hash_b64 = String::new();

        rotate_project_key_wrapping(&mut metadata, &old_project_key, &new_project_key)
            .expect("rotate");

        assert!(metadata.secrets_hash_nonce_b64.is_empty());
        assert!(metadata.secrets_hash_b64.is_empty());
    }
}
