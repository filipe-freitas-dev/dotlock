use std::{collections::HashMap, path::Path};

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
    storage::vault_file::{load_vault_metadata, record_vault_write, save_vault_metadata},
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
        crypto::{
            AccessMode, VaultConfig, VaultKeyMetadata,
            share::{IdentityProtection, generate_identity},
        },
        storage::vault_file::{load_vault_metadata, save_vault_metadata},
    };

    use super::{
        grant_recipient, grant_recipient_with_secret_ids, list_recipients,
        revoke_recipient_in_memory,
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
