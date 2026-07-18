//! Vault metadata domain entities (A2). These are the real domain types
//! behind `vault.toml`; storage modules only (de)serialize and persist them.
//! Serde attributes here define the on-disk TOML format and MUST stay
//! compatible with existing v5/v6 vaults.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::domain::{error::DotLockError, model::DotLockResult};

fn default_access_mode() -> AccessMode {
    AccessMode::MasterPassword
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    MasterPassword,
    Shared,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecipient {
    pub id: String,
    pub label: String,
    pub alg: String,
    pub public_key_fingerprint: String,
    pub public_key_b64: String,
    #[serde(default)]
    pub wrapped_dek_b64: String,
    #[serde(default)]
    pub wrapped_sdks: HashMap<String, String>,
    #[serde(default)]
    pub full_access: bool,
    /// RSA-PSS signature over the grant payload (project_uuid + this
    /// recipient's pubkey/fingerprint + the granting signer's fingerprint),
    /// produced by `dl share grant`. Empty on vaults that predate signed
    /// grants; such recipients are never absorbed from an untrusted merge
    /// side and are skipped by rotation once the vault has authorized signers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub grant_signature_b64: String,
    /// Fingerprint of the authorized signer whose key produced
    /// `grant_signature_b64`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub grant_signer_fingerprint: String,
}

/// An identity allowed to authorize recipient grants. Established locally by
/// operations that already proved master-password/full-key authority (`dl
/// share grant`); never absorbed from the untrusted side of a merge except as
/// a one-time bootstrap when the local side predates signed grants entirely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedSigner {
    pub fingerprint: String,
    pub public_key_b64: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct VaultConfig {
    #[serde(default)]
    pub auto_fetch_on_run: bool,
    #[serde(default)]
    pub auto_fetch_timeout_secs: Option<u64>,
    #[serde(default)]
    pub auto_fetch_remote: Option<String>,
    #[serde(default)]
    pub auto_ratchet_after_writes: Option<u32>,
    #[serde(default)]
    pub dynamic_resolve_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyMetadata {
    pub version: u32,
    pub project_uuid: String,
    pub project: String,
    pub environment: String,

    pub kdf: String,
    pub salt_b64: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,

    pub kek_version: u32,
    #[serde(default)]
    pub kek_writes_since_rotate: u32,

    pub wrapped_dek_nonce_b64: String,
    pub wrapped_dek_b64: String,
    /// Per-secret SDKs wrapped under the project key (DEK). The serialized
    /// field name says "under_kek" for historical reasons — the KEK only ever
    /// wraps the DEK itself — and is kept via `serde(rename)` so existing
    /// v5/v6 vault.toml files stay readable and byte-compatible (A9).
    #[serde(default, rename = "wrapped_sdks_under_kek")]
    pub wrapped_sdks_under_dek: HashMap<String, String>,

    #[serde(default = "default_access_mode")]
    pub access_mode: AccessMode,
    #[serde(default)]
    pub recipients: Vec<VaultRecipient>,
    /// Identities whose signatures authorize recipient grants (H3). Empty on
    /// vaults that predate signed grants; populated on the first `dl share
    /// grant` executed with the new binary.
    #[serde(default)]
    pub authorized_signers: Vec<AuthorizedSigner>,
    #[serde(default)]
    pub config: VaultConfig,

    pub secrets_hash_nonce_b64: String,
    pub secrets_hash_b64: String,
    #[serde(default)]
    pub secrets_hash_sha256_b64: String,
}

impl VaultKeyMetadata {
    /// Pure business rule: on a shared vault, a limited recipient (one with
    /// no `wrapped_dek_b64`, i.e. no project key) must never write. Callers
    /// resolve the local identity's fingerprint; this decides.
    pub fn reject_limited_identity_write_for_fingerprint(
        &self,
        fingerprint: &str,
    ) -> DotLockResult<()> {
        if self.access_mode != AccessMode::Shared {
            return Ok(());
        }
        let Some(recipient) = self
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
}

#[cfg(test)]
mod tests {
    use super::VaultKeyMetadata;

    #[test]
    fn vault_metadata_defaults_missing_config() {
        let metadata = toml::from_str::<VaultKeyMetadata>(
            r#"
version = 2
project_uuid = "project"
project = "dotlock"
environment = "dev"
kdf = "argon2id"
salt_b64 = "salt"
memory_kib = 1
iterations = 1
parallelism = 1
kek_version = 1
wrapped_dek_nonce_b64 = "nonce"
wrapped_dek_b64 = "wrapped"
secrets_hash_nonce_b64 = "hash_nonce"
secrets_hash_b64 = "hash"
"#,
        )
        .expect("metadata");

        assert!(!metadata.config.auto_fetch_on_run);
        assert_eq!(metadata.config.auto_fetch_timeout_secs, None);
        assert_eq!(metadata.config.auto_fetch_remote, None);
        assert_eq!(metadata.config.auto_ratchet_after_writes, None);
        assert_eq!(metadata.config.dynamic_resolve_timeout_secs, None);
        assert_eq!(metadata.kek_writes_since_rotate, 0);
        // Pre-signed-grant vaults (no authorized_signers, recipients without
        // grant fields) must keep parsing so they still unlock (H3 migration).
        assert!(metadata.authorized_signers.is_empty());
    }

    /// A9 on-disk compatibility proof: the Rust field is named
    /// `wrapped_sdks_under_dek`, but the serialized TOML field MUST remain
    /// `wrapped_sdks_under_kek` — an existing v5/v6 vault.toml parses, and
    /// re-serialization emits the identical historical field name (never the
    /// new Rust identifier).
    #[test]
    fn vault_toml_round_trips_with_historical_wrapped_sdks_field_name() {
        let existing_vault_toml = r#"
version = 5
project_uuid = "project"
project = "dotlock"
environment = "dev"
kdf = "argon2id"
salt_b64 = "salt"
memory_kib = 1
iterations = 1
parallelism = 1
kek_version = 1
wrapped_dek_nonce_b64 = "nonce"
wrapped_dek_b64 = "wrapped"
secrets_hash_nonce_b64 = "hash_nonce"
secrets_hash_b64 = "hash"

[wrapped_sdks_under_kek]
secret-id = "wrapped-sdk-b64"
"#;
        let metadata =
            toml::from_str::<VaultKeyMetadata>(existing_vault_toml).expect("pre-existing vault");
        assert_eq!(
            metadata
                .wrapped_sdks_under_dek
                .get("secret-id")
                .map(String::as_str),
            Some("wrapped-sdk-b64"),
            "old on-disk field must populate the renamed Rust field"
        );

        let serialized = toml::to_string_pretty(&metadata).expect("serialize");
        assert!(
            serialized.contains("wrapped_sdks_under_kek"),
            "serialized TOML must keep the historical field name:\n{serialized}"
        );
        assert!(
            !serialized.contains("wrapped_sdks_under_dek"),
            "the Rust-side rename must never leak into the on-disk format:\n{serialized}"
        );

        // Full round-trip: parse -> serialize -> parse yields the same data.
        let reparsed = toml::from_str::<VaultKeyMetadata>(&serialized).expect("reparse");
        assert_eq!(
            reparsed.wrapped_sdks_under_dek,
            metadata.wrapped_sdks_under_dek
        );
        assert_eq!(reparsed.version, metadata.version);
    }

    #[test]
    fn limited_identity_write_rule_is_pure_on_the_domain_type() {
        use super::{AccessMode, VaultRecipient};
        use crate::domain::error::DotLockError;

        let mut metadata = toml::from_str::<VaultKeyMetadata>(
            r#"
version = 5
project_uuid = "project"
project = "dotlock"
environment = "dev"
kdf = "argon2id"
salt_b64 = "salt"
memory_kib = 1
iterations = 1
parallelism = 1
kek_version = 1
wrapped_dek_nonce_b64 = "nonce"
wrapped_dek_b64 = "wrapped"
secrets_hash_nonce_b64 = "hash_nonce"
secrets_hash_b64 = "hash"
"#,
        )
        .expect("metadata");
        metadata.access_mode = AccessMode::Shared;
        metadata.recipients.push(VaultRecipient {
            id: "alice-id".to_string(),
            label: "alice".to_string(),
            alg: "rsa-oaep-sha256".to_string(),
            public_key_fingerprint: "alice-fp".to_string(),
            public_key_b64: "public".to_string(),
            wrapped_dek_b64: String::new(),
            wrapped_sdks: std::collections::HashMap::new(),
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
            full_access: false,
        });

        // Limited recipient (no wrapped project key): write denied.
        assert!(matches!(
            metadata.reject_limited_identity_write_for_fingerprint("alice-fp"),
            Err(DotLockError::AccessDenied { .. })
        ));
        // Unknown fingerprint (master-password holder): allowed.
        assert!(
            metadata
                .reject_limited_identity_write_for_fingerprint("other-fp")
                .is_ok()
        );
    }
}
