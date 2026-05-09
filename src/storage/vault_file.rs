use std::path::Path;

use crate::{
    crypto::{
        VaultKeyMetadata, sdk,
        share::{RECIPIENT_ALG, wrap_dek_for_public_key_b64},
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::secure_fs,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetSummary {
    pub old_kek_version: u32,
    pub new_kek_version: u32,
    pub secrets_rewrapped: usize,
    pub recipients_rewrapped: usize,
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

pub fn rotate_kek_wrapping(
    metadata: &mut VaultKeyMetadata,
    current_project_key: &[u8; 32],
    new_project_key: &[u8; 32],
) -> DotLockResult<RatchetSummary> {
    let old_kek_version = metadata.kek_version;
    let mut secrets_rewrapped = 0usize;
    let mut rewrapped_sdks = std::collections::HashMap::new();

    for (secret_id, wrapped_sdk) in &metadata.wrapped_sdks_under_kek {
        let secret_key = sdk::unwrap_sdk_with_project_key(wrapped_sdk, current_project_key)?;
        rewrapped_sdks.insert(
            secret_id.clone(),
            sdk::wrap_sdk_for_project_key(&secret_key, new_project_key)?,
        );
        secrets_rewrapped += 1;
    }
    metadata.wrapped_sdks_under_kek = rewrapped_sdks;

    let mut recipients_rewrapped = 0usize;
    for recipient in &mut metadata.recipients {
        if recipient.wrapped_dek_b64.is_empty() {
            continue;
        }
        recipient.wrapped_dek_b64 =
            wrap_dek_for_public_key_b64(new_project_key, &recipient.public_key_b64)?;
        recipient.alg = RECIPIENT_ALG.to_string();
        recipients_rewrapped += 1;
    }

    metadata.kek_version = metadata.kek_version.saturating_add(1);
    metadata.kek_writes_since_rotate = 0;

    Ok(RatchetSummary {
        old_kek_version,
        new_kek_version: metadata.kek_version,
        secrets_rewrapped,
        recipients_rewrapped,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{AccessMode, VaultConfig, VaultKeyMetadata, sdk},
        storage::vault_file::rotate_kek_wrapping,
    };

    fn metadata() -> VaultKeyMetadata {
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
            wrapped_sdks_under_kek: std::collections::HashMap::new(),
            access_mode: AccessMode::MasterPassword,
            recipients: Vec::new(),
            config: VaultConfig {
                auto_ratchet_after_writes: Some(10),
                ..VaultConfig::default()
            },
            secrets_hash_nonce_b64: "hash_nonce".to_string(),
            secrets_hash_b64: "hash".to_string(),
            secrets_hash_sha256_b64: "hash_plain".to_string(),
        }
    }

    #[test]
    fn rotate_kek_wrapping_rewraps_sdks_without_changing_secret_keys() {
        let old_project_key = [8u8; 32];
        let new_project_key = [9u8; 32];
        let sdk = [3u8; 32];
        let mut metadata = metadata();
        metadata.wrapped_sdks_under_kek.insert(
            "secret-id".to_string(),
            sdk::wrap_sdk_for_project_key(&sdk, &old_project_key).expect("wrap old sdk"),
        );
        let before = metadata.wrapped_sdks_under_kek["secret-id"].clone();

        let summary =
            rotate_kek_wrapping(&mut metadata, &old_project_key, &new_project_key).expect("rotate");

        let after = metadata.wrapped_sdks_under_kek["secret-id"].clone();
        assert_ne!(before, after);
        assert_eq!(
            sdk::unwrap_sdk_with_project_key(&after, &new_project_key).expect("unwrap new sdk"),
            sdk
        );
        assert_eq!(metadata.kek_version, 2);
        assert_eq!(metadata.kek_writes_since_rotate, 0);
        assert_eq!(summary.secrets_rewrapped, 1);
    }

    #[test]
    fn rotate_kek_wrapping_can_rewrap_legacy_project_key_recipients_without_plaintext_decrypt() {
        let old_project_key = [8u8; 32];
        let new_project_key = [9u8; 32];
        let mut metadata = metadata();
        let identity = crate::crypto::share::generate_identity(
            crate::crypto::share::IdentityProtection::Plain,
        )
        .expect("identity");
        let before = crate::crypto::share::wrap_dek_for_public_key(
            &old_project_key,
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
            full_access: true,
        });

        let summary =
            rotate_kek_wrapping(&mut metadata, &old_project_key, &new_project_key).expect("rotate");

        assert_ne!(metadata.recipients[0].wrapped_dek_b64, before);
        assert_eq!(summary.recipients_rewrapped, 1);
    }
}
