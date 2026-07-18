use std::{collections::HashMap, path::Path};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        AccessMode, VaultKeyMetadata, VaultRecipient,
        dek::generate_dek,
        share::{
            RECIPIENT_ALG, encode_public_key_b64, fingerprint_public_key, wrap_dek_for_public_key,
            wrap_dek_for_public_key_b64,
        },
        update_master_password_metadata,
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        vault_file::{
            RatchetSummary, load_vault_metadata, record_vault_write, rotate_kek_wrapping,
            save_vault_metadata,
        },
        vault_txn::{VaultPairWrite, commit_vault_pair},
    },
};

pub fn enable_shared_access(vault_path: &str) -> DotLockResult<bool> {
    let mut metadata = load_vault_metadata(vault_path)?;
    let changed = metadata.access_mode != AccessMode::Shared;
    metadata.access_mode = AccessMode::Shared;
    if changed {
        record_vault_write(&mut metadata);
    }
    save_vault_metadata(vault_path, &metadata)?;
    Ok(changed)
}

pub fn list_recipients(vault_path: &str) -> DotLockResult<Vec<VaultRecipient>> {
    let metadata = load_vault_metadata(vault_path)?;
    Ok(metadata.recipients)
}

pub fn grant_recipient(
    vault_path: &str,
    public_key_pem: &str,
    label: &str,
    dek: &[u8; 32],
) -> DotLockResult<VaultRecipient> {
    grant_recipient_with_secret_ids(vault_path, public_key_pem, label, dek, None)
}

pub fn grant_recipient_with_secret_ids(
    vault_path: &str,
    public_key_pem: &str,
    label: &str,
    dek: &[u8; 32],
    allowed_secret_ids: Option<&[String]>,
) -> DotLockResult<VaultRecipient> {
    let mut metadata = load_vault_metadata(vault_path)?;
    metadata.access_mode = AccessMode::Shared;

    let fingerprint = fingerprint_public_key(public_key_pem)?;
    let public_key_b64 = encode_public_key_b64(public_key_pem)?;
    let full_access = allowed_secret_ids.is_none();
    let wrapped_dek_b64 = if full_access {
        wrap_dek_for_public_key(dek, public_key_pem)?
    } else {
        String::new()
    };
    let wrapped_sdks = wrap_allowed_sdks(&metadata, public_key_pem, dek, allowed_secret_ids)?;

    if let Some(existing) = metadata
        .recipients
        .iter_mut()
        .find(|recipient| recipient.public_key_fingerprint == fingerprint)
    {
        existing.label = label.to_string();
        existing.public_key_b64 = public_key_b64;
        existing.wrapped_dek_b64 = wrapped_dek_b64;
        existing.wrapped_sdks = wrapped_sdks;
        existing.full_access = full_access;
        existing.alg = RECIPIENT_ALG.to_string();
        let recipient = existing.clone();
        record_vault_write(&mut metadata);
        save_vault_metadata(vault_path, &metadata)?;
        return Ok(recipient);
    }

    let recipient = VaultRecipient {
        id: Uuid::new_v4().to_string(),
        label: label.to_string(),
        alg: RECIPIENT_ALG.to_string(),
        public_key_fingerprint: fingerprint,
        public_key_b64,
        wrapped_dek_b64,
        wrapped_sdks,
        full_access,
    };
    metadata.recipients.push(recipient.clone());
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)?;

    Ok(recipient)
}

fn wrap_allowed_sdks(
    metadata: &VaultKeyMetadata,
    public_key_pem: &str,
    dek: &[u8; 32],
    allowed_secret_ids: Option<&[String]>,
) -> DotLockResult<HashMap<String, String>> {
    let ids: Vec<String> = match allowed_secret_ids {
        Some(ids) => ids.to_vec(),
        None => metadata.wrapped_sdks_under_kek.keys().cloned().collect(),
    };
    let mut wrapped = HashMap::new();
    for secret_id in ids {
        let Some(project_wrapped_sdk) = metadata.wrapped_sdks_under_kek.get(&secret_id) else {
            continue;
        };
        let sdk = crate::crypto::sdk::unwrap_sdk_with_project_key(project_wrapped_sdk, dek)?;
        wrapped.insert(secret_id, wrap_dek_for_public_key(&sdk, public_key_pem)?);
    }
    Ok(wrapped)
}

pub fn revoke_recipient_in_memory(
    metadata: &mut VaultKeyMetadata,
    query: &str,
) -> DotLockResult<VaultRecipient> {
    let index = metadata
        .recipients
        .iter()
        .position(|recipient| {
            recipient.id == query
                || recipient.label == query
                || recipient.public_key_fingerprint == query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: query.to_string(),
        })?;
    Ok(metadata.recipients.remove(index))
}

/// Outcome of [`revoke_recipient_and_rotate`].
pub struct RevokeOutcome {
    pub removed: VaultRecipient,
    /// The freshly rotated project key. The CLI invalidates the session cache
    /// instead of reusing it; tests use it to verify the vault stays readable.
    #[allow(dead_code)]
    pub new_dek: Zeroizing<[u8; 32]>,
    pub summary: RatchetSummary,
}

/// Revokes a recipient and rotates the project key (DEK) in one transaction.
///
/// The ciphertexts in `secrets.lock` stay under their per-secret SDKs and are
/// untouched; what changes ownership is the *wrapping*: every SDK is unwrapped
/// under the old DEK and rewrapped under a fresh one, the remaining full-access
/// recipients get the fresh DEK wrapped for their public keys, the master
/// password wrapping is refreshed, and the integrity hash is re-encrypted
/// under the fresh DEK — all committed atomically via `commit_vault_pair`.
///
/// Note: revocation cannot remove access to ciphertexts the revoked identity
/// already obtained (e.g. from git history); rotating sensitive values is the
/// only remedy for that.
pub fn revoke_recipient_and_rotate(
    vault_path: &str,
    secrets_path: &str,
    query: &str,
    current_dek: &[u8; 32],
    passphrase: &str,
) -> DotLockResult<RevokeOutcome> {
    let mut metadata = load_vault_metadata(vault_path)?;
    let removed = revoke_recipient_in_memory(&mut metadata, query)?;

    let new_dek = Zeroizing::new(generate_dek().map_err(|e| DotLockError::Crypto(e.to_string()))?);
    // Rewraps every per-secret SDK and every remaining recipient's DEK under
    // the new project key, and re-encrypts `secrets_hash_*` under it, in the
    // same metadata object.
    let summary = rotate_kek_wrapping(&mut metadata, current_dek, &new_dek)?;
    update_master_password_metadata(&mut metadata, &new_dek, passphrase)?;

    commit_vault_pair(
        Path::new(vault_path),
        Path::new(secrets_path),
        VaultPairWrite {
            metadata: &metadata,
            secrets_lock_bytes: None,
        },
    )?;

    Ok(RevokeOutcome {
        removed,
        new_dek,
        summary,
    })
}

pub fn list_recipient_acl(vault_path: &str, query: &str) -> DotLockResult<Vec<String>> {
    let metadata = load_vault_metadata(vault_path)?;
    let recipient = metadata
        .recipients
        .iter()
        .find(|recipient| {
            recipient.id == query
                || recipient.label == query
                || recipient.public_key_fingerprint == query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: query.to_string(),
        })?;
    let mut ids = recipient.wrapped_sdks.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    Ok(ids)
}

pub fn add_recipient_secret_ids(
    vault_path: &str,
    query: &str,
    secret_ids: &[String],
    dek: &[u8; 32],
) -> DotLockResult<usize> {
    let mut metadata = load_vault_metadata(vault_path)?;
    let recipient = metadata
        .recipients
        .iter_mut()
        .find(|recipient| {
            recipient.id == query
                || recipient.label == query
                || recipient.public_key_fingerprint == query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: query.to_string(),
        })?;

    let mut added = 0usize;
    for secret_id in secret_ids {
        if recipient.wrapped_sdks.contains_key(secret_id) {
            continue;
        }
        let Some(project_wrapped_sdk) = metadata.wrapped_sdks_under_kek.get(secret_id) else {
            continue;
        };
        let sdk = crate::crypto::sdk::unwrap_sdk_with_project_key(project_wrapped_sdk, dek)?;
        recipient.wrapped_sdks.insert(
            secret_id.clone(),
            wrap_dek_for_public_key_b64(&sdk, &recipient.public_key_b64)?,
        );
        added += 1;
    }
    recipient.full_access = false;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)?;
    Ok(added)
}

pub fn load_public_key_from_file(path: &Path) -> DotLockResult<String> {
    std::fs::read_to_string(path).map_err(DotLockError::from)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        crypto::{
            AccessMode, VaultConfig, VaultKeyMetadata,
            share::{IdentityProtection, generate_identity},
        },
        storage::vault_file::{load_vault_metadata, save_vault_metadata},
    };

    use super::{
        grant_recipient, grant_recipient_with_secret_ids, list_recipients,
        revoke_recipient_and_rotate, revoke_recipient_in_memory,
    };

    fn temp_file(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("dotlock-{name}-{unique}.toml"))
    }

    fn metadata() -> VaultKeyMetadata {
        VaultKeyMetadata {
            version: 1,
            project_uuid: "project".to_string(),
            project: "dotlock".to_string(),
            environment: "dev".to_string(),
            kdf: "argon2id".to_string(),
            salt_b64: "salt".to_string(),
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
            kek_version: 1,
            kek_writes_since_rotate: 0,
            wrapped_dek_nonce_b64: "nonce".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks_under_kek: std::collections::HashMap::new(),
            access_mode: AccessMode::MasterPassword,
            recipients: Vec::new(),
            config: VaultConfig::default(),
            secrets_hash_nonce_b64: "hash_nonce".to_string(),
            secrets_hash_b64: "hash".to_string(),
            secrets_hash_sha256_b64: "hash_plain".to_string(),
        }
    }

    #[test]
    fn grant_and_revoke_update_recipients() {
        let path = temp_file("shared-access");
        save_vault_metadata(&path, &metadata()).expect("save metadata");
        let identity =
            generate_identity(IdentityProtection::Encrypted("hunter2")).expect("identity");

        let granted = grant_recipient(
            path.to_str().expect("path"),
            &identity.public_key_pem,
            "alice",
            &[3u8; 32],
        )
        .expect("grant");
        let listed = list_recipients(path.to_str().expect("path")).expect("list");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label, "alice");
        assert_eq!(
            listed[0].public_key_fingerprint,
            granted.public_key_fingerprint
        );

        let mut metadata = load_vault_metadata(path.to_str().expect("path")).expect("load vault");
        let removed = revoke_recipient_in_memory(&mut metadata, "alice").expect("revoke");
        save_vault_metadata(path.to_str().expect("path"), &metadata).expect("save after revoke");
        let listed = list_recipients(path.to_str().expect("path")).expect("list after revoke");

        assert_eq!(
            removed.public_key_fingerprint,
            granted.public_key_fingerprint
        );
        assert!(listed.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn revoke_rotates_project_key_without_bricking_envelope_vaults() {
        use base64::{Engine, engine::general_purpose};

        use crate::{
            crypto::{
                dek::{WrappedDek, unwrap_dek},
                integrity::verify_secrets_integrity,
                kdf::{KdfParams, derive_master_key},
                kek::derive_kek,
                sdk,
                secret_cipher::decryption_process,
                update_master_password_metadata,
            },
            domain::{error::DotLockError, model::Alg},
            storage::secrets_lock::{load_secrets_file, upsert_plain_secret},
        };

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-revoke-rotate-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        let vault_path = dir.join("vault.toml");
        let secrets_path = dir.join("secrets.lock");
        let vault_str = vault_path.to_str().expect("vault path");
        let secrets_str = secrets_path.to_str().expect("secrets path");

        let old_dek = [8u8; 32];
        let passphrase = "test-passphrase";
        let mut metadata = metadata();
        update_master_password_metadata(&mut metadata, &old_dek, passphrase).expect("wrap dek");
        save_vault_metadata(&vault_path, &metadata).expect("save vault");

        // Secrets set through the normal envelope path (v5, per-secret SDKs).
        upsert_plain_secret(
            &secrets_path,
            "A".to_string(),
            "1".to_string(),
            Alg::XChaCha20Poly1305,
            &old_dek,
            vault_str,
        )
        .expect("set A");
        upsert_plain_secret(
            &secrets_path,
            "B".to_string(),
            "2".to_string(),
            Alg::XChaCha20Poly1305,
            &old_dek,
            vault_str,
        )
        .expect("set B");

        // A second identity granted full access.
        let bob = crate::crypto::share::generate_identity(
            crate::crypto::share::IdentityProtection::Plain,
        )
        .expect("identity");
        let granted =
            grant_recipient(vault_str, &bob.public_key_pem, "bob", &old_dek).expect("grant");
        assert!(!granted.wrapped_dek_b64.is_empty());

        // (1) revoke succeeds (the old flow aborted with an AEAD error here).
        let outcome =
            revoke_recipient_and_rotate(vault_str, secrets_str, "bob", &old_dek, passphrase)
                .expect("revoke succeeds for envelope vaults");
        assert_eq!(
            outcome.removed.public_key_fingerprint,
            granted.public_key_fingerprint
        );

        // (2) the revoked recipient's wrapped material is gone from vault.toml.
        let metadata = load_vault_metadata(vault_str).expect("reload vault");
        assert!(metadata.recipients.is_empty());
        let raw = fs::read_to_string(&vault_path).expect("read vault.toml");
        assert!(!raw.contains(&granted.wrapped_dek_b64));
        assert!(!raw.contains(&granted.public_key_fingerprint));

        // (3) the owner can still read A under the new DEK (vault not bricked)
        //     and the ciphertexts were NOT re-encrypted (SDK envelope intact).
        let file = load_secrets_file(&secrets_path).expect("load secrets");
        let record_a = file
            .secrets
            .iter()
            .find(|secret| secret.name == "A")
            .expect("record A");
        let wrapped_sdk = metadata
            .wrapped_sdks_under_kek
            .get(&record_a.id)
            .expect("SDK wrapping for A");
        let sdk_a = sdk::unwrap_sdk_with_project_key(wrapped_sdk, &outcome.new_dek)
            .expect("unwrap SDK under new DEK");
        assert_eq!(
            decryption_process(record_a.data.clone(), Alg::XChaCha20Poly1305, &sdk_a)
                .expect("decrypt A"),
            "1"
        );

        // (4) unlock with the revoked/old key material fails: the old DEK can
        //     no longer unwrap any SDK, and no recipient entry remains for bob.
        assert!(sdk::unwrap_sdk_with_project_key(wrapped_sdk, &old_dek).is_err());

        // Owner master-password unlock still works end to end.
        let salt = general_purpose::STANDARD
            .decode(&metadata.salt_b64)
            .expect("salt");
        let master_key = derive_master_key(
            passphrase,
            &salt,
            KdfParams {
                memory_kib: metadata.memory_kib,
                iterations: metadata.iterations,
                parallelism: metadata.parallelism,
            },
        )
        .expect("master key");
        let kek = derive_kek(
            &master_key,
            &metadata.project,
            &metadata.environment,
            metadata.kek_version,
        )
        .expect("kek");
        let nonce: [u8; 24] = general_purpose::STANDARD
            .decode(&metadata.wrapped_dek_nonce_b64)
            .expect("nonce b64")
            .try_into()
            .expect("nonce len");
        let wrapped = WrappedDek {
            nonce,
            ciphertext: general_purpose::STANDARD
                .decode(&metadata.wrapped_dek_b64)
                .expect("wrapped dek b64"),
        };
        let unlocked_dek = unwrap_dek(&kek, &wrapped, &metadata.project, &metadata.environment)
            .expect("owner password unlock");
        assert_eq!(unlocked_dek, *outcome.new_dek);

        // (5) integrity verifies under the new DEK and rejects the old one.
        verify_secrets_integrity(&secrets_path, &metadata, &outcome.new_dek)
            .expect("integrity under new DEK");
        assert!(matches!(
            verify_secrets_integrity(&secrets_path, &metadata, &old_dek),
            Err(DotLockError::TamperedSecretsFile)
        ));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn grant_can_limit_recipient_to_allowed_secret_sdks() {
        let path = temp_file("shared-access-allow");
        let mut metadata = metadata();
        metadata.wrapped_sdks_under_kek.insert(
            "foo-id".to_string(),
            crate::crypto::sdk::wrap_sdk_for_project_key(&[1u8; 32], &[3u8; 32]).expect("wrap foo"),
        );
        metadata.wrapped_sdks_under_kek.insert(
            "bar-id".to_string(),
            crate::crypto::sdk::wrap_sdk_for_project_key(&[2u8; 32], &[3u8; 32]).expect("wrap bar"),
        );
        save_vault_metadata(&path, &metadata).expect("save metadata");
        let identity =
            generate_identity(IdentityProtection::Encrypted("hunter2")).expect("identity");

        let granted = grant_recipient_with_secret_ids(
            path.to_str().expect("path"),
            &identity.public_key_pem,
            "alice",
            &[3u8; 32],
            Some(&["foo-id".to_string()]),
        )
        .expect("grant");

        assert!(!granted.full_access);
        assert!(granted.wrapped_sdks.contains_key("foo-id"));
        assert!(!granted.wrapped_sdks.contains_key("bar-id"));

        let _ = fs::remove_file(path);
    }
}
