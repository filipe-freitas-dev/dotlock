use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    crypto::{
        AccessMode,
        integrity::{build_encrypted_hash_fields, file_sha256_b64},
        sdk,
        secret_cipher::{decryption_process, encryption_process},
        share::{unwrap_dek_with_private_key, wrap_dek_for_public_key_b64},
    },
    domain::{
        error::DotLockError,
        model::{Alg, DataEncrypted, DotLockResult},
    },
    storage::{
        identity::{load_local_identity, load_local_identity_metadata},
        project::SECRETS_FILE,
        secure_fs,
        vault_file::{load_vault_metadata, record_vault_write, save_vault_metadata},
    },
};

pub const DEFAULT_SECRET_ALG: &str = "xchacha20-poly1305";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsFile {
    pub version: u32,
    #[serde(default)]
    pub secrets: Vec<SecretRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    pub data: String,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub kind: SecretKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretKind {
    #[default]
    Static,
    Dynamic {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<Value>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        bootstrap: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DynamicSecretMetadata {
    pub provider: String,
    pub config: Value,
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_sha256: Option<String>,
}

impl Default for SecretsFile {
    fn default() -> Self {
        Self {
            version: 2,
            secrets: Vec::new(),
        }
    }
}

pub fn load_secrets_file<P: AsRef<Path>>(path: P) -> DotLockResult<SecretsFile> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(SecretsFile::default());
    }

    let content = secure_fs::read_to_string(path)?;

    if content.trim().is_empty() {
        return Ok(SecretsFile::default());
    }

    let file =
        toml::from_str::<SecretsFile>(&content).map_err(|_| DotLockError::LegacyVaultFormat)?;
    Ok(file)
}

pub fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn migrate_legacy_secret_timestamps(file: &mut SecretsFile) {
    let now = current_unix_timestamp();
    for secret in &mut file.secrets {
        if secret.updated_at == 0 {
            secret.updated_at = now;
        }
    }
}

fn migrate_legacy_secret_algorithms(file: &mut SecretsFile) -> DotLockResult<()> {
    file.version = file.version.max(2);
    for secret in &mut file.secrets {
        let Some(alg) = secret.alg.as_deref() else {
            continue;
        };
        crate::utils::parse_alg(alg)?;
        if alg == DEFAULT_SECRET_ALG {
            secret.alg = None;
        }
    }
    Ok(())
}

fn write_secrets_file<P: AsRef<Path>>(path: P, file: &SecretsFile) -> DotLockResult<()> {
    let path = path.as_ref();

    let content = toml::to_string_pretty(file).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(path, &content, 0o700, 0o600)
}

pub fn save_secrets_file<P: AsRef<Path>>(
    path: P,
    file: &SecretsFile,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<()> {
    let mut file = file.clone();
    migrate_legacy_secret_timestamps(&mut file);
    migrate_legacy_secret_algorithms(&mut file)?;
    write_secrets_file(path.as_ref(), &file)?;
    refresh_vault_hash(path.as_ref(), dek, vault_path)
}

pub fn refresh_vault_hash(
    secrets_path: &Path,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<()> {
    let mut metadata = load_vault_metadata(vault_path)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(secrets_path, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(secrets_path)?;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)
}

#[allow(dead_code)]
pub fn upsert_secret<P: AsRef<Path>>(
    path: P,
    encrypted: DataEncrypted<'_>,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<()> {
    let path = path.as_ref();
    let mut file = load_secrets_file(path)?;

    let data_str =
        String::from_utf8(encrypted.data).map_err(|e| DotLockError::Crypto(e.to_string()))?;

    if let Some(existing) = file
        .secrets
        .iter_mut()
        .find(|secret| secret.name == encrypted.name)
    {
        existing.alg = None;
        existing.data = data_str;
        existing.updated_at = current_unix_timestamp();
        existing.kind = SecretKind::Static;
    } else {
        file.secrets.push(SecretRecord {
            id: Uuid::new_v4().to_string(),
            name: encrypted.name,
            alg: None,
            data: data_str,
            updated_at: current_unix_timestamp(),
            kind: SecretKind::Static,
        });
    }

    save_secrets_file(path, &file, dek, vault_path)
}

pub fn upsert_plain_secret<P: AsRef<Path>>(
    path: P,
    name: String,
    value: String,
    alg: Alg,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<SecretRecord> {
    let path = path.as_ref();
    let mut file = load_secrets_file(path)?;
    let mut metadata = load_vault_metadata(vault_path)?;
    metadata.version = metadata.version.max(5);
    reject_limited_identity_write(&metadata)?;

    let now = current_unix_timestamp();
    let (record_id, sdk) = if let Some(existing) =
        file.secrets.iter().find(|secret| secret.name == name)
    {
        let sdk = secret_sdk_from_project_key(&metadata, existing, dek)?.unwrap_or_else(|| *dek);
        (existing.id.clone(), sdk)
    } else {
        (Uuid::new_v4().to_string(), sdk::generate_sdk()?)
    };

    let encrypted = encryption_process(name.clone(), value, alg, &sdk)?;
    let data =
        String::from_utf8(encrypted.data).map_err(|err| DotLockError::Crypto(err.to_string()))?;

    let record = if let Some(existing) = file.secrets.iter_mut().find(|secret| secret.name == name)
    {
        existing.alg = None;
        existing.data = data;
        existing.updated_at = now;
        existing.kind = SecretKind::Static;
        existing.clone()
    } else {
        let record = SecretRecord {
            id: record_id,
            name: encrypted.name,
            alg: None,
            data,
            updated_at: now,
            kind: SecretKind::Static,
        };
        file.secrets.push(record.clone());
        record
    };

    metadata
        .wrapped_sdks_under_kek
        .insert(record.id.clone(), sdk::wrap_sdk_for_project_key(&sdk, dek)?);
    for recipient in &mut metadata.recipients {
        if recipient.full_access {
            recipient.wrapped_sdks.insert(
                record.id.clone(),
                wrap_dek_for_public_key_b64(&sdk, &recipient.public_key_b64)?,
            );
        }
    }

    migrate_legacy_secret_timestamps(&mut file);
    migrate_legacy_secret_algorithms(&mut file)?;
    write_secrets_file(path, &file)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(path, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(path)?;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)?;

    Ok(record)
}

fn reject_limited_identity_write(metadata: &crate::crypto::VaultKeyMetadata) -> DotLockResult<()> {
    if metadata.access_mode != AccessMode::Shared {
        return Ok(());
    }
    let Ok(identity_meta) = load_local_identity_metadata() else {
        return Ok(());
    };
    reject_limited_identity_write_for_fingerprint(metadata, &identity_meta.fingerprint)
}

fn reject_limited_identity_write_for_fingerprint(
    metadata: &crate::crypto::VaultKeyMetadata,
    fingerprint: &str,
) -> DotLockResult<()> {
    if metadata.access_mode != AccessMode::Shared {
        return Ok(());
    }
    let Some(recipient) = metadata
        .recipients
        .iter()
        .find(|recipient| recipient.public_key_fingerprint == fingerprint)
    else {
        return Ok(());
    };
    if recipient.wrapped_dek_b64.is_empty() {
        return Err(DotLockError::AccessDenied {
            secret: "write requires full-access recipient or master password".to_string(),
        });
    }
    Ok(())
}

pub fn migrate_all_secrets_to_envelope(dek: &[u8; 32], vault_path: &str) -> DotLockResult<()> {
    let mut file = load_secrets_file(SECRETS_FILE)?;
    let mut metadata = load_vault_metadata(vault_path)?;
    let mut changed = false;

    for secret in &mut file.secrets {
        if metadata.wrapped_sdks_under_kek.contains_key(&secret.id) {
            continue;
        }
        let value = decryption_process(secret.data.clone(), secret_algorithm(secret)?, dek)?;
        let sdk = sdk::generate_sdk()?;
        let encrypted =
            encryption_process(secret.name.clone(), value, secret_algorithm(secret)?, &sdk)?;
        secret.data = String::from_utf8(encrypted.data)
            .map_err(|err| DotLockError::Crypto(err.to_string()))?;
        secret.alg = None;
        secret.updated_at = current_unix_timestamp();
        metadata
            .wrapped_sdks_under_kek
            .insert(secret.id.clone(), sdk::wrap_sdk_for_project_key(&sdk, dek)?);
        for recipient in &mut metadata.recipients {
            if recipient.full_access {
                recipient.wrapped_sdks.insert(
                    secret.id.clone(),
                    wrap_dek_for_public_key_b64(&sdk, &recipient.public_key_b64)?,
                );
            }
        }
        changed = true;
    }

    if !changed {
        return Ok(());
    }

    metadata.version = metadata.version.max(5);
    migrate_legacy_secret_algorithms(&mut file)?;
    write_secrets_file(SECRETS_FILE, &file)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(SECRETS_FILE, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(SECRETS_FILE)?;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)
}

pub fn rotate_secret_sdks_after_acl_removal(
    secret_ids: &[String],
    removed_recipient_query: &str,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<()> {
    let mut file = load_secrets_file(SECRETS_FILE)?;
    let mut metadata = load_vault_metadata(vault_path)?;
    let removed_index = metadata
        .recipients
        .iter()
        .position(|recipient| {
            recipient.id == removed_recipient_query
                || recipient.label == removed_recipient_query
                || recipient.public_key_fingerprint == removed_recipient_query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: removed_recipient_query.to_string(),
        })?;

    for secret_id in secret_ids {
        let Some(secret) = file
            .secrets
            .iter_mut()
            .find(|secret| &secret.id == secret_id)
        else {
            continue;
        };
        if !metadata.recipients[removed_index]
            .wrapped_sdks
            .contains_key(secret_id)
        {
            continue;
        }

        let old_sdk = secret_sdk_from_project_key(&metadata, secret, dek)?.unwrap_or(*dek);
        let value = decryption_process(secret.data.clone(), secret_algorithm(secret)?, &old_sdk)?;
        let new_sdk = sdk::generate_sdk()?;
        let encrypted = encryption_process(
            secret.name.clone(),
            value,
            secret_algorithm(secret)?,
            &new_sdk,
        )?;
        secret.data = String::from_utf8(encrypted.data)
            .map_err(|err| DotLockError::Crypto(err.to_string()))?;
        secret.alg = None;
        secret.updated_at = current_unix_timestamp();
        metadata.wrapped_sdks_under_kek.insert(
            secret.id.clone(),
            sdk::wrap_sdk_for_project_key(&new_sdk, dek)?,
        );

        for (index, recipient) in metadata.recipients.iter_mut().enumerate() {
            if index == removed_index {
                recipient.wrapped_sdks.remove(secret_id);
                recipient.full_access = false;
                continue;
            }
            if recipient.full_access || recipient.wrapped_sdks.contains_key(secret_id) {
                recipient.wrapped_sdks.insert(
                    secret.id.clone(),
                    wrap_dek_for_public_key_b64(&new_sdk, &recipient.public_key_b64)?,
                );
            }
        }
    }

    migrate_legacy_secret_algorithms(&mut file)?;
    write_secrets_file(SECRETS_FILE, &file)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(SECRETS_FILE, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(SECRETS_FILE)?;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)
}

pub fn decrypt_secret_value(secret: &SecretRecord, dek: &[u8; 32]) -> DotLockResult<String> {
    let metadata = load_vault_metadata(crate::storage::project::VAULT_FILE)?;
    let key = if metadata.access_mode == AccessMode::Shared {
        match secret_sdk_from_local_identity(&metadata, secret)? {
            Some(sdk) => sdk,
            None if metadata.recipients.is_empty() => {
                secret_sdk_from_project_key(&metadata, secret, dek)?.unwrap_or(*dek)
            }
            None => {
                return Err(DotLockError::AccessDenied {
                    secret: secret.name.clone(),
                });
            }
        }
    } else {
        secret_sdk_from_project_key(&metadata, secret, dek)?.unwrap_or(*dek)
    };

    decryption_process(secret.data.clone(), secret_algorithm(secret)?, &key)
}

pub fn secret_algorithm(secret: &SecretRecord) -> DotLockResult<Alg> {
    crate::utils::parse_alg(secret.alg.as_deref().unwrap_or(DEFAULT_SECRET_ALG))
}

fn secret_sdk_from_project_key(
    metadata: &crate::crypto::VaultKeyMetadata,
    secret: &SecretRecord,
    dek: &[u8; 32],
) -> DotLockResult<Option<[u8; 32]>> {
    metadata
        .wrapped_sdks_under_kek
        .get(&secret.id)
        .map(|wrapped| sdk::unwrap_sdk_with_project_key(wrapped, dek))
        .transpose()
}

fn secret_sdk_from_local_identity(
    metadata: &crate::crypto::VaultKeyMetadata,
    secret: &SecretRecord,
) -> DotLockResult<Option<[u8; 32]>> {
    let Ok(identity_meta) = load_local_identity_metadata() else {
        return Ok(None);
    };
    let Some(recipient) = metadata
        .recipients
        .iter()
        .find(|recipient| recipient.public_key_fingerprint == identity_meta.fingerprint)
    else {
        return Ok(None);
    };
    let Some(wrapped_sdk) = recipient.wrapped_sdks.get(&secret.id) else {
        return Ok(None);
    };
    let identity = load_local_identity()?;
    unwrap_dek_with_private_key(wrapped_sdk, &identity.private_key_pem).map(Some)
}

pub fn find_secret_by_name(name: &str) -> DotLockResult<SecretRecord> {
    let file = load_secrets_file(SECRETS_FILE)?;
    file.secrets
        .into_iter()
        .find(|secret| secret.name == name)
        .ok_or_else(|| DotLockError::SecretNotFound {
            name: name.to_string(),
        })
}

pub fn list_secrets() -> DotLockResult<Vec<SecretRecord>> {
    let file = load_secrets_file(SECRETS_FILE)?;
    Ok(file.secrets)
}

pub struct PlainSecretEntry {
    pub name: String,
    pub value: String,
    pub alg: Alg,
}

pub struct UpsertSummary {
    pub created: usize,
    pub updated: usize,
}

pub fn upsert_many<P: AsRef<Path>>(
    path: P,
    entries: Vec<PlainSecretEntry>,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<UpsertSummary> {
    let path = path.as_ref();
    let mut file = load_secrets_file(path)?;
    let mut metadata = load_vault_metadata(vault_path)?;
    metadata.version = metadata.version.max(5);
    reject_limited_identity_write(&metadata)?;
    let mut summary = UpsertSummary {
        created: 0,
        updated: 0,
    };

    for entry in entries {
        let existing_index = file
            .secrets
            .iter()
            .position(|secret| secret.name == entry.name);
        let (record_id, sdk) = if let Some(index) = existing_index {
            let existing = &file.secrets[index];
            let sdk =
                secret_sdk_from_project_key(&metadata, existing, dek)?.unwrap_or_else(|| *dek);
            (existing.id.clone(), sdk)
        } else {
            (Uuid::new_v4().to_string(), sdk::generate_sdk()?)
        };
        let encrypted = encryption_process(entry.name.clone(), entry.value, entry.alg, &sdk)?;
        let data = String::from_utf8(encrypted.data)
            .map_err(|err| DotLockError::Crypto(err.to_string()))?;
        let now = current_unix_timestamp();

        let record = if let Some(index) = existing_index {
            let existing = &mut file.secrets[index];
            existing.alg = None;
            existing.data = data;
            existing.updated_at = now;
            existing.kind = SecretKind::Static;
            summary.updated += 1;
            existing.clone()
        } else {
            let record = SecretRecord {
                id: record_id,
                name: encrypted.name,
                alg: None,
                data,
                updated_at: now,
                kind: SecretKind::Static,
            };
            file.secrets.push(record.clone());
            summary.created += 1;
            record
        };

        metadata
            .wrapped_sdks_under_kek
            .insert(record.id.clone(), sdk::wrap_sdk_for_project_key(&sdk, dek)?);
        for recipient in &mut metadata.recipients {
            if recipient.full_access {
                recipient.wrapped_sdks.insert(
                    record.id.clone(),
                    wrap_dek_for_public_key_b64(&sdk, &recipient.public_key_b64)?,
                );
            }
        }
    }

    migrate_legacy_secret_timestamps(&mut file);
    migrate_legacy_secret_algorithms(&mut file)?;
    write_secrets_file(path, &file)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(path, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(path)?;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)?;

    Ok(summary)
}

pub fn upsert_dynamic_secret<P: AsRef<Path>>(
    path: P,
    name: String,
    dynamic: DynamicSecretMetadata,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<SecretRecord> {
    let path = path.as_ref();
    let mut file = load_secrets_file(path)?;
    let mut metadata = load_vault_metadata(vault_path)?;
    metadata.version = metadata.version.max(5);
    reject_limited_identity_write(&metadata)?;

    let now = current_unix_timestamp();
    let (record_id, sdk) = if let Some(existing) =
        file.secrets.iter().find(|secret| secret.name == name)
    {
        let sdk = secret_sdk_from_project_key(&metadata, existing, dek)?.unwrap_or_else(|| *dek);
        (existing.id.clone(), sdk)
    } else {
        (Uuid::new_v4().to_string(), sdk::generate_sdk()?)
    };

    let dynamic_json =
        serde_json::to_string(&dynamic).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    let encrypted = encryption_process(name.clone(), dynamic_json, Alg::XChaCha20Poly1305, &sdk)?;
    let data =
        String::from_utf8(encrypted.data).map_err(|err| DotLockError::Crypto(err.to_string()))?;

    let kind = SecretKind::Dynamic {
        provider: None,
        config: None,
        bootstrap: Vec::new(),
    };
    let record = if let Some(existing) = file.secrets.iter_mut().find(|secret| secret.name == name)
    {
        existing.alg = None;
        existing.data = data;
        existing.updated_at = now;
        existing.kind = kind;
        existing.clone()
    } else {
        let record = SecretRecord {
            id: record_id,
            name: encrypted.name,
            alg: None,
            data,
            updated_at: now,
            kind,
        };
        file.secrets.push(record.clone());
        record
    };

    metadata
        .wrapped_sdks_under_kek
        .insert(record.id.clone(), sdk::wrap_sdk_for_project_key(&sdk, dek)?);
    for recipient in &mut metadata.recipients {
        if recipient.full_access {
            recipient.wrapped_sdks.insert(
                record.id.clone(),
                wrap_dek_for_public_key_b64(&sdk, &recipient.public_key_b64)?,
            );
        }
    }

    migrate_legacy_secret_timestamps(&mut file);
    migrate_legacy_secret_algorithms(&mut file)?;
    write_secrets_file(path, &file)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(path, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(path)?;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)?;

    Ok(record)
}

pub fn decrypt_dynamic_metadata(
    secret: &SecretRecord,
    dek: &[u8; 32],
) -> DotLockResult<DynamicSecretMetadata> {
    let plaintext = decrypt_secret_value(secret, dek)?;
    if !plaintext.trim().is_empty() {
        return serde_json::from_str::<DynamicSecretMetadata>(&plaintext).map_err(|err| {
            DotLockError::Crypto(format!("invalid dynamic secret metadata: {err}"))
        });
    }

    match &secret.kind {
        SecretKind::Dynamic {
            provider: Some(provider),
            config,
            bootstrap,
        } => Ok(DynamicSecretMetadata {
            provider: provider.clone(),
            config: config.clone().unwrap_or_else(|| serde_json::json!({})),
            bootstrap: bootstrap.clone(),
            provider_path: None,
            provider_sha256: None,
        }),
        SecretKind::Dynamic { .. } => Err(DotLockError::Crypto(
            "dynamic secret metadata is missing".to_string(),
        )),
        SecretKind::Static => Err(DotLockError::Crypto(
            "static secret has no dynamic metadata".to_string(),
        )),
    }
}

pub fn remove_secret_by_name(name: &str, dek: &[u8; 32], vault_path: &str) -> DotLockResult<()> {
    let mut file = load_secrets_file(SECRETS_FILE)?;
    let removed_ids = file
        .secrets
        .iter()
        .filter(|secret| secret.name == name)
        .map(|secret| secret.id.clone())
        .collect::<Vec<_>>();
    let before = file.secrets.len();
    file.secrets.retain(|secret| secret.name != name);

    if file.secrets.len() == before {
        return Err(DotLockError::SecretNotFound {
            name: name.to_string(),
        });
    }

    let mut metadata = load_vault_metadata(vault_path)?;
    for id in &removed_ids {
        metadata.wrapped_sdks_under_kek.remove(id);
        for recipient in &mut metadata.recipients {
            recipient.wrapped_sdks.remove(id);
        }
    }

    migrate_legacy_secret_algorithms(&mut file)?;
    write_secrets_file(SECRETS_FILE, &file)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(SECRETS_FILE, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(SECRETS_FILE)?;
    record_vault_write(&mut metadata);
    save_vault_metadata(vault_path, &metadata)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        crypto::{
            AccessMode, VaultConfig, VaultKeyMetadata, VaultRecipient,
            secret_cipher::decryption_process,
        },
        domain::model::Alg,
        storage::{
            secrets_lock::{
                PlainSecretEntry, SecretRecord, load_secrets_file, upsert_many, upsert_plain_secret,
            },
            vault_file::{load_vault_metadata, save_vault_metadata},
        },
    };

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    fn metadata() -> VaultKeyMetadata {
        VaultKeyMetadata {
            version: 2,
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
    fn upsert_plain_secret_encrypts_with_per_secret_sdk() {
        let dir = temp_dir("envelope");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let dek = [8u8; 32];
        save_vault_metadata(&vault_path, &metadata()).expect("save vault");

        let record = upsert_plain_secret(
            &secrets_path,
            "FOO".to_string(),
            "bar".to_string(),
            Alg::XChaCha20Poly1305,
            &dek,
            vault_path.to_str().expect("vault path"),
        )
        .expect("upsert");
        let file = load_secrets_file(&secrets_path).expect("load secrets");
        let metadata = load_vault_metadata(&vault_path).expect("load metadata");

        assert_eq!(metadata.version, 5);
        assert_eq!(record.alg, None);
        assert_eq!(file.secrets[0].alg, None);
        let serialized = fs::read_to_string(&secrets_path).expect("read secrets");
        assert!(!serialized.contains("alg ="));
        assert!(metadata.wrapped_sdks_under_kek.contains_key(&record.id));
        assert!(
            decryption_process(file.secrets[0].data.clone(), Alg::XChaCha20Poly1305, &dek).is_err()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn upsert_many_encrypts_with_per_secret_sdks_and_updates_full_access_recipients() {
        let dir = temp_dir("batch-envelope");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let dek = [8u8; 32];
        let identity = crate::crypto::share::generate_identity(
            crate::crypto::share::IdentityProtection::Plain,
        )
        .expect("identity");
        let mut metadata = metadata();
        metadata.access_mode = AccessMode::Shared;
        metadata.recipients.push(VaultRecipient {
            id: "alice-id".to_string(),
            label: "alice".to_string(),
            alg: crate::crypto::share::RECIPIENT_ALG.to_string(),
            public_key_fingerprint: identity.fingerprint,
            public_key_b64: crate::crypto::share::encode_public_key_b64(&identity.public_key_pem)
                .expect("public key b64"),
            wrapped_dek_b64: crate::crypto::share::wrap_dek_for_public_key(
                &dek,
                &identity.public_key_pem,
            )
            .expect("wrap project key"),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: true,
        });
        save_vault_metadata(&vault_path, &metadata).expect("save vault");

        upsert_many(
            &secrets_path,
            vec![PlainSecretEntry {
                name: "FOO".to_string(),
                value: "bar".to_string(),
                alg: Alg::XChaCha20Poly1305,
            }],
            &dek,
            vault_path.to_str().expect("vault path"),
        )
        .expect("upsert many");

        let file = load_secrets_file(&secrets_path).expect("load secrets");
        let metadata = load_vault_metadata(&vault_path).expect("load metadata");
        let record = &file.secrets[0];
        assert_eq!(record.alg, None);
        assert!(metadata.wrapped_sdks_under_kek.contains_key(&record.id));
        assert!(metadata.recipients[0].wrapped_sdks.contains_key(&record.id));
        assert!(decryption_process(record.data.clone(), Alg::XChaCha20Poly1305, &dek).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn limited_identity_cannot_write_without_project_key() {
        let mut metadata = metadata();
        metadata.access_mode = AccessMode::Shared;
        metadata.recipients.push(VaultRecipient {
            id: "alice-id".to_string(),
            label: "alice".to_string(),
            alg: "rsa-oaep-sha256".to_string(),
            public_key_fingerprint: "alice-fp".to_string(),
            public_key_b64: "public".to_string(),
            wrapped_dek_b64: String::new(),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: false,
        });
        let result = super::reject_limited_identity_write_for_fingerprint(&metadata, "alice-fp");

        assert!(matches!(
            result,
            Err(crate::domain::error::DotLockError::AccessDenied { .. })
        ));
    }

    #[test]
    fn legacy_secret_records_default_to_static_kind() {
        let record = toml::from_str::<SecretRecord>(
            r#"
id = "secret-id"
name = "FOO"
alg = "xchacha20-poly1305"
data = "ciphertext"
updated_at = 1
"#,
        )
        .expect("record");

        assert!(matches!(record.kind, super::SecretKind::Static));
        assert_eq!(record.alg.as_deref(), Some(super::DEFAULT_SECRET_ALG));
    }

    #[test]
    fn upsert_dynamic_secret_encrypts_provider_metadata_in_data() {
        let dir = temp_dir("dynamic-envelope");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let dek = [8u8; 32];
        save_vault_metadata(&vault_path, &metadata()).expect("save vault");

        let record = super::upsert_dynamic_secret(
            &secrets_path,
            "DATABASE_URL".to_string(),
            super::DynamicSecretMetadata {
                provider: "echo".to_string(),
                config: serde_json::json!({"value": "minted"}),
                bootstrap: vec!["AWS_KEY".to_string()],
                provider_path: Some("/usr/bin/dotlock-provider-echo".to_string()),
                provider_sha256: Some("sha256:test".to_string()),
            },
            &dek,
            vault_path.to_str().expect("vault path"),
        )
        .expect("upsert dynamic");

        assert!(matches!(record.kind, super::SecretKind::Dynamic { .. }));
        assert!(!record.data.contains("echo"));
        assert!(!record.data.contains("AWS_KEY"));

        let vault_metadata = load_vault_metadata(&vault_path).expect("load vault");
        let wrapped_sdk = vault_metadata
            .wrapped_sdks_under_kek
            .get(&record.id)
            .expect("wrapped sdk");
        let sdk =
            crate::crypto::sdk::unwrap_sdk_with_project_key(wrapped_sdk, &dek).expect("unwrap sdk");
        let plaintext = decryption_process(record.data.clone(), Alg::XChaCha20Poly1305, &sdk)
            .expect("decrypt data");
        let metadata =
            serde_json::from_str::<super::DynamicSecretMetadata>(&plaintext).expect("metadata");
        assert_eq!(metadata.provider, "echo");
        assert_eq!(metadata.bootstrap, vec!["AWS_KEY"]);

        let _ = fs::remove_dir_all(dir);
    }
}
