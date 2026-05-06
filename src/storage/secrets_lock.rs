use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    crypto::integrity::build_encrypted_hash_fields,
    domain::{error::DotLockError, model::DataEncrypted, model::DotLockResult},
    storage::{
        project::SECRETS_FILE,
        secure_fs,
        vault_file::{load_vault_metadata, save_vault_metadata},
    },
};

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
    pub alg: String,
    pub data: String,
}

impl Default for SecretsFile {
    fn default() -> Self {
        Self {
            version: 1,
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

    let file = toml::from_str::<SecretsFile>(&content).map_err(|_| DotLockError::LegacyVaultFormat)?;
    Ok(file)
}

fn write_secrets_file<P: AsRef<Path>>(path: P, file: &SecretsFile) -> DotLockResult<()> {
    let path = path.as_ref();

    let content =
        toml::to_string_pretty(file).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(path, &content, 0o700, 0o600)
}

pub fn save_secrets_file<P: AsRef<Path>>(
    path: P,
    file: &SecretsFile,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<()> {
    write_secrets_file(path.as_ref(), file)?;
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
    save_vault_metadata(vault_path, &metadata)
}

pub fn upsert_secret<P: AsRef<Path>>(
    path: P,
    encrypted: DataEncrypted<'_>,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<()> {
    let path = path.as_ref();
    let mut file = load_secrets_file(path)?;

    let data_str = String::from_utf8(encrypted.data).map_err(|e| DotLockError::Crypto(e.to_string()))?;

    if let Some(existing) = file
        .secrets
        .iter_mut()
        .find(|secret| secret.name == encrypted.name)
    {
        existing.alg = encrypted.alg.to_string();
        existing.data = data_str;
    } else {
        file.secrets.push(SecretRecord {
            id: Uuid::new_v4().to_string(),
            name: encrypted.name,
            alg: encrypted.alg.to_string(),
            data: data_str,
        });
    }

    save_secrets_file(path, &file, dek, vault_path)
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

pub struct EncryptedEntry {
    pub name: String,
    pub alg: String,
    pub data: String,
}

pub struct UpsertSummary {
    pub created: usize,
    pub updated: usize,
}

pub fn upsert_many<P: AsRef<Path>>(
    path: P,
    entries: Vec<EncryptedEntry>,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<UpsertSummary> {
    let path = path.as_ref();
    let mut file = load_secrets_file(path)?;
    let mut summary = UpsertSummary {
        created: 0,
        updated: 0,
    };

    for entry in entries {
        if let Some(existing) = file.secrets.iter_mut().find(|s| s.name == entry.name) {
            existing.alg = entry.alg;
            existing.data = entry.data;
            summary.updated += 1;
        } else {
            file.secrets.push(SecretRecord {
                id: Uuid::new_v4().to_string(),
                name: entry.name,
                alg: entry.alg,
                data: entry.data,
            });
            summary.created += 1;
        }
    }

    save_secrets_file(path, &file, dek, vault_path)?;
    Ok(summary)
}

pub fn remove_secret_by_name(
    name: &str,
    dek: &[u8; 32],
    vault_path: &str,
) -> DotLockResult<()> {
    let mut file = load_secrets_file(SECRETS_FILE)?;
    let before = file.secrets.len();
    file.secrets.retain(|secret| secret.name != name);

    if file.secrets.len() == before {
        return Err(DotLockError::SecretNotFound {
            name: name.to_string(),
        });
    }

    save_secrets_file(SECRETS_FILE, &file, dek, vault_path)
}
