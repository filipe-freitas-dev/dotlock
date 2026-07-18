//! Secret-record domain entities (A2). These are the real domain types behind
//! `secrets.lock`; `storage::secrets_lock` only (de)serializes and persists
//! them. Serde attributes here define the on-disk TOML format and MUST stay
//! compatible with existing vaults.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_SECRET_ALG: &str = "xchacha20-poly1305";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsFile {
    pub version: u32,
    #[serde(default)]
    pub secrets: Vec<SecretRecord>,
}

impl Default for SecretsFile {
    fn default() -> Self {
        Self {
            version: 2,
            secrets: Vec::new(),
        }
    }
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
    /// Monotonic per-secret write counter (H2). `0` marks a legacy record
    /// encrypted without AAD; every write through `upsert_record` (or a
    /// re-encryption) sets `version >= 1` and binds
    /// `id`/`name`/`updated_at`/`version` into the ciphertext's AEAD
    /// associated data, so plaintext ordering metadata can no longer be forged
    /// without failing authentication.
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub kind: SecretKind,
}

impl SecretRecord {
    /// Canonical AEAD associated data for this record; see
    /// [`secret_record_aad`].
    pub fn aad(&self) -> Vec<u8> {
        secret_record_aad(&self.id, &self.name, self.updated_at, self.version)
    }
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

/// Canonical AEAD associated data for a secret record (H2 + M4): binds the
/// record's identity (`id`, `name`) and ordering metadata (`updated_at`,
/// monotonic `version`) into the ciphertext's authentication tag.
/// Length-prefixed encoding, so no field combination is ambiguous.
pub fn secret_record_aad(id: &str, name: &str, updated_at: i64, version: u64) -> Vec<u8> {
    const DOMAIN: &[u8] = b"dotlock/secret-record-aad/v1";
    let mut aad = Vec::with_capacity(DOMAIN.len() + id.len() + name.len() + 40);
    for part in [DOMAIN, id.as_bytes(), name.as_bytes()] {
        aad.extend_from_slice(&(part.len() as u64).to_le_bytes());
        aad.extend_from_slice(part);
    }
    aad.extend_from_slice(&updated_at.to_le_bytes());
    aad.extend_from_slice(&version.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_SECRET_ALG, SecretKind, SecretRecord};

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

        assert!(matches!(record.kind, SecretKind::Static));
        assert_eq!(record.alg.as_deref(), Some(DEFAULT_SECRET_ALG));
    }
}
