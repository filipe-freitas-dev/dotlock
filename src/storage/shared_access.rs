use std::path::Path;

use uuid::Uuid;

use crate::{
    crypto::{
        AccessMode, VaultKeyMetadata, VaultRecipient,
        share::{
            RECIPIENT_ALG, encode_public_key_b64, fingerprint_public_key, wrap_dek_for_public_key,
            wrap_dek_for_public_key_b64,
        },
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::vault_file::{load_vault_metadata, save_vault_metadata},
};

pub fn enable_shared_access(vault_path: &str) -> DotLockResult<bool> {
    let mut metadata = load_vault_metadata(vault_path)?;
    let changed = metadata.access_mode != AccessMode::Shared;
    metadata.access_mode = AccessMode::Shared;
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
    let mut metadata = load_vault_metadata(vault_path)?;
    metadata.access_mode = AccessMode::Shared;

    let fingerprint = fingerprint_public_key(public_key_pem)?;
    let public_key_b64 = encode_public_key_b64(public_key_pem)?;
    let wrapped_dek_b64 = wrap_dek_for_public_key(dek, public_key_pem)?;

    if let Some(existing) = metadata
        .recipients
        .iter_mut()
        .find(|recipient| recipient.public_key_fingerprint == fingerprint)
    {
        existing.label = label.to_string();
        existing.public_key_b64 = public_key_b64;
        existing.wrapped_dek_b64 = wrapped_dek_b64;
        existing.alg = RECIPIENT_ALG.to_string();
        let recipient = existing.clone();
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
    };
    metadata.recipients.push(recipient.clone());
    save_vault_metadata(vault_path, &metadata)?;

    Ok(recipient)
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

pub fn rewrap_recipients(metadata: &mut VaultKeyMetadata, dek: &[u8; 32]) -> DotLockResult<()> {
    for recipient in &mut metadata.recipients {
        recipient.wrapped_dek_b64 = wrap_dek_for_public_key_b64(dek, &recipient.public_key_b64)?;
        recipient.alg = RECIPIENT_ALG.to_string();
    }
    Ok(())
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
        crypto::{AccessMode, VaultKeyMetadata, share::generate_identity},
        storage::vault_file::{load_vault_metadata, save_vault_metadata},
    };

    use super::{grant_recipient, list_recipients, revoke_recipient_in_memory};

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
            wrapped_dek_nonce_b64: "nonce".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            access_mode: AccessMode::MasterPassword,
            recipients: Vec::new(),
            secrets_hash_nonce_b64: "hash_nonce".to_string(),
            secrets_hash_b64: "hash".to_string(),
        }
    }

    #[test]
    fn grant_and_revoke_update_recipients() {
        let path = temp_file("shared-access");
        save_vault_metadata(&path, &metadata()).expect("save metadata");
        let identity = generate_identity("hunter2").expect("identity");

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
}
