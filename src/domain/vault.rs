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
    /// FG5 scheduled-rotation policy: `dl rotate --if-due` rotates the
    /// project key when more than this many days passed since
    /// `last_rotated_at`. Complements (does not replace) the write-count
    /// ratchet `auto_ratchet_after_writes`. MAC-covered when set (see
    /// [`VaultKeyMetadata::canonical_mac_input`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_max_age_days: Option<u64>,
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

    /// Unix timestamp of the last project-key rotation (FG5). `0` means "no
    /// rotation recorded" (pre-FG5 vault or never rotated with a policy) and
    /// is never serialized, keeping older vault.toml files byte-stable.
    /// MAC-covered when set (see [`Self::canonical_mac_input`]).
    #[serde(default, skip_serializing_if = "i64_is_zero")]
    pub last_rotated_at: i64,

    /// Monotonic write counter (M3): bumped by every sealed metadata write.
    /// Covered by `metadata_mac_b64`; unlock refuses to move backward past the
    /// newest epoch persisted in the per-user anchor outside the repo.
    #[serde(default)]
    pub vault_epoch: u64,
    /// HMAC-SHA256 over [`VaultKeyMetadata::canonical_mac_input`] under a
    /// subkey derived from the project key (M2). Empty on pre-v7 vaults —
    /// tolerated on unlock (legacy) and set on the first full-access write. A
    /// PRESENT-but-wrong MAC hard-fails with `MetadataTampered`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub metadata_mac_b64: String,
}

fn i64_is_zero(value: &i64) -> bool {
    *value == 0
}

fn push_part(buf: &mut Vec<u8>, part: &[u8]) {
    buf.extend_from_slice(&(part.len() as u64).to_le_bytes());
    buf.extend_from_slice(part);
}

fn push_str(buf: &mut Vec<u8>, value: &str) {
    push_part(buf, value.as_bytes());
}

fn push_u64(buf: &mut Vec<u8>, value: u64) {
    push_str(buf, &value.to_string());
}

fn push_bool(buf: &mut Vec<u8>, value: bool) {
    push_str(buf, if value { "1" } else { "0" });
}

fn push_opt_u64(buf: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            push_str(buf, "1");
            push_u64(buf, value);
        }
        None => push_str(buf, "0"),
    }
}

fn push_opt_str(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            push_str(buf, "1");
            push_str(buf, value);
        }
        None => push_str(buf, "0"),
    }
}

fn push_sorted_map(buf: &mut Vec<u8>, map: &HashMap<String, String>) {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    push_u64(buf, keys.len() as u64);
    for key in keys {
        push_str(buf, key);
        push_str(buf, &map[key]);
    }
}

impl VaultKeyMetadata {
    /// Canonical byte encoding of every security-relevant metadata field (M2)
    /// — everything persisted in `vault.toml` EXCEPT `metadata_mac_b64`
    /// itself. Length-prefixed (like `recipient_grant_payload`) so no field
    /// combination is ambiguous; maps are emitted sorted by key so the
    /// encoding is independent of `HashMap` iteration order. The field order
    /// below is part of the on-disk format and MUST stay stable:
    ///
    /// domain, version, project_uuid, project, environment, kdf, salt_b64,
    /// memory_kib, iterations, parallelism, kek_version,
    /// kek_writes_since_rotate, vault_epoch, wrapped_dek_nonce_b64,
    /// wrapped_dek_b64, wrapped_sdks_under_dek (count + sorted pairs),
    /// access_mode, recipients (count + each: id, label, alg, fingerprint,
    /// public_key_b64, wrapped_dek_b64, wrapped_sdks, full_access,
    /// grant_signature_b64, grant_signer_fingerprint), authorized_signers
    /// (count + each: fingerprint, public_key_b64, label), config (5 fields),
    /// secrets_hash_nonce_b64, secrets_hash_b64, secrets_hash_sha256_b64.
    pub fn canonical_mac_input(&self) -> Vec<u8> {
        const DOMAIN: &[u8] = b"dotlock/metadata-mac/v1";
        let mut buf = Vec::new();
        push_part(&mut buf, DOMAIN);
        push_u64(&mut buf, u64::from(self.version));
        push_str(&mut buf, &self.project_uuid);
        push_str(&mut buf, &self.project);
        push_str(&mut buf, &self.environment);
        push_str(&mut buf, &self.kdf);
        push_str(&mut buf, &self.salt_b64);
        push_u64(&mut buf, u64::from(self.memory_kib));
        push_u64(&mut buf, u64::from(self.iterations));
        push_u64(&mut buf, u64::from(self.parallelism));
        push_u64(&mut buf, u64::from(self.kek_version));
        push_u64(&mut buf, u64::from(self.kek_writes_since_rotate));
        push_u64(&mut buf, self.vault_epoch);
        push_str(&mut buf, &self.wrapped_dek_nonce_b64);
        push_str(&mut buf, &self.wrapped_dek_b64);
        push_sorted_map(&mut buf, &self.wrapped_sdks_under_dek);
        push_str(
            &mut buf,
            match self.access_mode {
                AccessMode::MasterPassword => "master_password",
                AccessMode::Shared => "shared",
            },
        );
        push_u64(&mut buf, self.recipients.len() as u64);
        for recipient in &self.recipients {
            push_str(&mut buf, &recipient.id);
            push_str(&mut buf, &recipient.label);
            push_str(&mut buf, &recipient.alg);
            push_str(&mut buf, &recipient.public_key_fingerprint);
            push_str(&mut buf, &recipient.public_key_b64);
            push_str(&mut buf, &recipient.wrapped_dek_b64);
            push_sorted_map(&mut buf, &recipient.wrapped_sdks);
            push_bool(&mut buf, recipient.full_access);
            push_str(&mut buf, &recipient.grant_signature_b64);
            push_str(&mut buf, &recipient.grant_signer_fingerprint);
        }
        push_u64(&mut buf, self.authorized_signers.len() as u64);
        for signer in &self.authorized_signers {
            push_str(&mut buf, &signer.fingerprint);
            push_str(&mut buf, &signer.public_key_b64);
            push_str(&mut buf, &signer.label);
        }
        push_bool(&mut buf, self.config.auto_fetch_on_run);
        push_opt_u64(&mut buf, self.config.auto_fetch_timeout_secs);
        push_opt_str(&mut buf, self.config.auto_fetch_remote.as_deref());
        push_opt_u64(
            &mut buf,
            self.config.auto_ratchet_after_writes.map(u64::from),
        );
        push_opt_u64(&mut buf, self.config.dynamic_resolve_timeout_secs);
        push_str(&mut buf, &self.secrets_hash_nonce_b64);
        push_str(&mut buf, &self.secrets_hash_b64);
        push_str(&mut buf, &self.secrets_hash_sha256_b64);
        // FG5 rotation-policy block: appended ONLY when a policy field is in
        // use, so vaults sealed before FG5 keep verifying with a byte-identical
        // input. Once either field is set the block is covered by the MAC —
        // stripping the fields (reverting to the legacy input) or altering
        // them without resealing fails authentication.
        if self.config.rotate_max_age_days.is_some() || self.last_rotated_at != 0 {
            push_str(&mut buf, "rotation-policy/v1");
            push_opt_u64(&mut buf, self.config.rotate_max_age_days);
            push_str(&mut buf, &self.last_rotated_at.to_string());
        }
        buf
    }

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

    /// M2/M3 compatibility proof: a pre-v7 vault.toml (no `vault_epoch`, no
    /// `metadata_mac_b64`) parses with safe defaults, still round-trips, and
    /// the empty MAC is never written to disk — so an old vault keeps
    /// unlocking (legacy) and only gains the new fields when a full-access
    /// write seals it.
    #[test]
    fn pre_m2_m3_vault_fixture_round_trips_with_default_epoch_and_no_mac() {
        let pre_m2_m3_vault_toml = r#"
version = 6
project_uuid = "project"
project = "dotlock"
environment = "dev"
kdf = "argon2id"
salt_b64 = "salt"
memory_kib = 1
iterations = 1
parallelism = 1
kek_version = 2
kek_writes_since_rotate = 4
wrapped_dek_nonce_b64 = "nonce"
wrapped_dek_b64 = "wrapped"
secrets_hash_nonce_b64 = "hash_nonce"
secrets_hash_b64 = "hash"
secrets_hash_sha256_b64 = "hash_plain"

[wrapped_sdks_under_kek]
secret-id = "wrapped-sdk-b64"
"#;
        let metadata =
            toml::from_str::<VaultKeyMetadata>(pre_m2_m3_vault_toml).expect("pre-M2/M3 vault");
        assert_eq!(metadata.vault_epoch, 0);
        assert!(metadata.metadata_mac_b64.is_empty());

        let serialized = toml::to_string_pretty(&metadata).expect("serialize");
        assert!(
            !serialized.contains("metadata_mac_b64"),
            "an empty MAC must never be written:\n{serialized}"
        );

        let reparsed = toml::from_str::<VaultKeyMetadata>(&serialized).expect("reparse");
        assert_eq!(reparsed.version, metadata.version);
        assert_eq!(reparsed.kek_version, metadata.kek_version);
        assert_eq!(reparsed.vault_epoch, 0);
        assert!(reparsed.metadata_mac_b64.is_empty());
        assert_eq!(
            reparsed.wrapped_sdks_under_dek,
            metadata.wrapped_sdks_under_dek
        );
    }

    /// The canonical MAC input must change whenever a covered field changes
    /// (otherwise the MAC would not detect that tampering).
    #[test]
    fn canonical_mac_input_covers_security_relevant_fields() {
        let base = toml::from_str::<VaultKeyMetadata>(
            r#"
version = 7
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
secrets_hash_sha256_b64 = "hash_plain"
"#,
        )
        .expect("metadata");
        let reference = base.canonical_mac_input();

        let mut changed = base.clone();
        changed.access_mode = super::AccessMode::Shared;
        assert_ne!(changed.canonical_mac_input(), reference);

        let mut changed = base.clone();
        changed.kek_version = 9;
        assert_ne!(changed.canonical_mac_input(), reference);

        let mut changed = base.clone();
        changed.vault_epoch = 9;
        assert_ne!(changed.canonical_mac_input(), reference);

        let mut changed = base.clone();
        changed.secrets_hash_sha256_b64 = "forged".to_string();
        assert_ne!(changed.canonical_mac_input(), reference);

        // The MAC field itself is NOT covered (it cannot authenticate itself).
        let mut changed = base.clone();
        changed.metadata_mac_b64 = "whatever".to_string();
        assert_eq!(changed.canonical_mac_input(), reference);
    }

    /// FG5 MAC compatibility: the rotation-policy block is appended to the
    /// canonical input ONLY when one of its fields is in use, so vaults
    /// sealed before FG5 keep verifying byte-for-byte; once a field is set,
    /// both fields are covered (stripping or altering them breaks the MAC).
    #[test]
    fn rotation_policy_fields_are_mac_covered_only_when_set() {
        let base = toml::from_str::<VaultKeyMetadata>(
            r#"
version = 7
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
secrets_hash_sha256_b64 = "hash_plain"
"#,
        )
        .expect("metadata");
        let legacy_input = base.canonical_mac_input();

        // Defaults: input ends exactly where the pre-FG5 input ended.
        let mut with_defaults = base.clone();
        with_defaults.last_rotated_at = 0;
        with_defaults.config.rotate_max_age_days = None;
        assert_eq!(with_defaults.canonical_mac_input(), legacy_input);

        // Either field in use extends (and thus covers) the input.
        let mut with_policy = base.clone();
        with_policy.config.rotate_max_age_days = Some(30);
        assert_ne!(with_policy.canonical_mac_input(), legacy_input);

        let mut with_timestamp = base.clone();
        with_timestamp.last_rotated_at = 1_700_000_000;
        assert_ne!(with_timestamp.canonical_mac_input(), legacy_input);

        // And the two fields are distinguishable from each other.
        let mut both = with_policy.clone();
        both.last_rotated_at = 1_700_000_000;
        assert_ne!(
            both.canonical_mac_input(),
            with_policy.canonical_mac_input()
        );

        // `last_rotated_at == 0` is never serialized: an old vault.toml stays
        // byte-stable until a rotation actually records a timestamp.
        let serialized = toml::to_string_pretty(&base).expect("serialize");
        assert!(!serialized.contains("last_rotated_at"));
        assert!(!serialized.contains("rotate_max_age_days"));
        let mut rotated = base.clone();
        rotated.last_rotated_at = 1_700_000_000;
        let serialized = toml::to_string_pretty(&rotated).expect("serialize");
        assert!(serialized.contains("last_rotated_at = 1700000000"));
        let reparsed = toml::from_str::<VaultKeyMetadata>(&serialized).expect("reparse");
        assert_eq!(reparsed.last_rotated_at, 1_700_000_000);
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
