use base64::{Engine, engine::general_purpose};
use colored::Colorize;
use zeroize::Zeroize;

use crate::{
    audit::record_unlock,
    crypto::{
        AccessMode,
        dek::{WrappedDek, unwrap_dek},
        integrity::{verify_metadata_mac, verify_public_secrets_hash, verify_secrets_integrity},
        kdf::{KdfParams, derive_master_key},
        kek::derive_kek,
        prompt_unlock_password,
        share::unwrap_dek_with_private_key,
    },
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    storage::{
        cache::{invalidate_cache, read_cached_dek_for, write_cached_dek_for},
        epoch_anchor,
        identity::{
            LocalIdentity, load_legacy_identity, load_legacy_identity_metadata,
            load_local_identity, load_local_identity_metadata,
        },
        pending_merge::ensure_no_pending_merge,
        project::secrets_file,
        vault_file::load_vault_metadata,
        vault_txn::recover_pending,
    },
    utils::render_table,
};

/// Result of unlocking the vault. Write paths must call [`UnlockAccess::require_full`]
/// so a limited (read-only) identity can never hand "a DEK" to a mutator; the
/// legacy all-zero placeholder survives only inside [`UnlockAccess::into_read_key`]
/// and is additionally rejected by every integrity-hash writer.
pub enum UnlockAccess {
    /// Full access: the real project key (DEK) was recovered.
    Full(ProjectKey),
    /// Limited recipient: only per-secret SDKs from the recipient's
    /// `wrapped_sdks` are available; no project key exists for this identity.
    Limited,
}

impl UnlockAccess {
    /// Returns the project key, or a permission error for limited identities.
    /// Every mutating path must obtain its key through here.
    pub fn require_full(self) -> DotLockResult<ProjectKey> {
        match self {
            UnlockAccess::Full(dek) => Ok(dek),
            UnlockAccess::Limited => Err(DotLockError::AccessDenied {
                secret: "write requires full-access recipient or master password".to_string(),
            }),
        }
    }

    /// Key handed to read-only decryption paths. Limited identities get an
    /// all-zero placeholder that can never act as a project key: their
    /// per-secret SDKs are resolved from the recipient's `wrapped_sdks`, and
    /// every write/integrity path rejects the all-zero key.
    pub fn into_read_key(self) -> ProjectKey {
        match self {
            UnlockAccess::Full(dek) => dek,
            UnlockAccess::Limited => ProjectKey::read_only_placeholder(),
        }
    }
}

/// Recipient entry matching one of the local identities: the current one
/// first, then the archived legacy (RSA) identity that `dl cert migrate`
/// keeps around until every project has been rekeyed. Returns the matching
/// recipient and whether it resolved through the legacy identity.
fn find_local_recipient(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> Option<(&crate::crypto::VaultRecipient, bool)> {
    if let Ok(identity_meta) = load_local_identity_metadata()
        && let Some(recipient) = metadata
            .recipients
            .iter()
            .find(|recipient| recipient.public_key_fingerprint == identity_meta.fingerprint)
    {
        return Some((recipient, false));
    }
    if let Ok(legacy_meta) = load_legacy_identity_metadata()
        && let Some(recipient) = metadata
            .recipients
            .iter()
            .find(|recipient| recipient.public_key_fingerprint == legacy_meta.fingerprint)
    {
        return Some((recipient, true));
    }
    None
}

/// Loads the identity selected by [`find_local_recipient`], nudging legacy
/// unlocks toward `dl cert migrate` (the RSA-decryption exit, ADR 0001).
fn load_matched_identity(legacy: bool) -> DotLockResult<LocalIdentity> {
    if legacy {
        eprintln!(
            "{} unlocking with the archived legacy (RSA) identity; run {} in this project to finish the migration",
            "warn:".yellow().bold(),
            "dl cert migrate".bold()
        );
        return load_legacy_identity();
    }
    load_local_identity()
}

/// Resolves any interrupted vault-pair transaction before the vault is read,
/// and refuses to proceed while a pending-merge marker exists: merged content
/// was never signed by a key holder, so every unlock (interactive or CI) must
/// fail with a clear "run `dl reconcile`" error instead of a false
/// `TamperedSecretsFile`.
fn recover_pending_before_access(vault_path: &str) -> DotLockResult<()> {
    let vault = std::path::Path::new(vault_path);
    recover_pending(vault, std::path::Path::new(&secrets_file()))?;
    let lock_dir = match vault.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    ensure_no_pending_merge(lock_dir)
}

/// Runs the pending-transaction recovery + reconcile gate, then loads the
/// vault metadata exactly once (A6). Every unlock in a command flows from this
/// single read; the `*_prepared` unlock variants below never touch the file
/// again.
pub fn prepare_vault_access(path: &str) -> DotLockResult<crate::crypto::VaultKeyMetadata> {
    recover_pending_before_access(path)?;
    load_vault_metadata(path)
}

/// Unlock used exclusively by `dl reconcile`: obtains the real project key
/// WITHOUT the integrity check (after a merge the stored hash is stale by
/// construction) and WITHOUT the metadata-MAC/epoch checks (merged metadata
/// was assembled by the merge driver, not by a key holder — the pending-merge
/// marker plus per-record AEAD checks gate it instead, and the reconcile
/// rewrite reseals the MAC and bumps the epoch). The caller must verify the
/// pending-merge marker against the files first. Key correctness is still
/// guaranteed: both the identity unwrap and the password unwrap fail on wrong
/// credentials.
pub fn unlock_full_for_reconcile(path: &str) -> DotLockResult<ProjectKey> {
    recover_pending(
        std::path::Path::new(path),
        std::path::Path::new(&secrets_file()),
    )?;
    let metadata = load_vault_metadata(path)?;

    if metadata.access_mode == AccessMode::Shared
        && let Some((recipient, legacy)) = find_local_recipient(&metadata)
        && !recipient.wrapped_dek_b64.is_empty()
        && let Ok(identity) = load_matched_identity(legacy)
    {
        let dek = ProjectKey::new(unwrap_dek_with_private_key(
            &recipient.wrapped_dek_b64,
            &identity.private_key_pem,
        )?);
        record_unlock_best_effort("identity", &metadata);
        return Ok(dek);
    }

    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(&metadata, &passphrase)?;
    record_unlock_best_effort("password", &metadata);
    Ok(dek)
}

/// Unlock used exclusively by `dl repair` (FG6): recovers the real project
/// key against already-loaded metadata WITHOUT the secrets integrity check —
/// a hash-stale vault is exactly what repair exists to fix — but WITH the
/// metadata MAC check: repair recovers hash↔content desync, it never blesses
/// a `vault.toml` someone rewrote outside DotLock. Key correctness is still
/// proven (identity unwrap or password unwrap both fail on wrong
/// credentials), so no DEK means no repair. The session cache is neither
/// consulted nor refreshed: repairing always demands a fresh proof.
pub fn unlock_full_for_repair(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<ProjectKey> {
    if metadata.access_mode == AccessMode::Shared
        && let Some((recipient, legacy)) = find_local_recipient(metadata)
        && !recipient.wrapped_dek_b64.is_empty()
        && let Ok(identity) = load_matched_identity(legacy)
    {
        let dek = ProjectKey::new(unwrap_dek_with_private_key(
            &recipient.wrapped_dek_b64,
            &identity.private_key_pem,
        )?);
        verify_metadata_mac(metadata, &dek)?;
        record_unlock_best_effort("identity", metadata);
        return Ok(dek);
    }

    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(metadata, &passphrase)?;
    verify_metadata_mac(metadata, &dek)?;
    record_unlock_best_effort("password", metadata);
    Ok(dek)
}

/// RSA-exit unlock used exclusively by `dl cert migrate`: recovers the
/// project key through the ARCHIVED legacy identity's recipient entry — the
/// one deliberate, final RSA decryption for this project — and runs the full
/// M2+M3 trust chain (metadata MAC, rollback anchor, secrets integrity)
/// before the caller rewrites the recipient entry under the new key.
pub fn unlock_full_with_legacy_identity(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<ProjectKey> {
    let legacy_meta = load_legacy_identity_metadata()?;
    let recipient = metadata
        .recipients
        .iter()
        .find(|recipient| recipient.public_key_fingerprint == legacy_meta.fingerprint)
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: legacy_meta.fingerprint.clone(),
        })?;
    if recipient.wrapped_dek_b64.is_empty() {
        return Err(DotLockError::AccessDenied {
            secret: "a limited recipient cannot rekey their own entry; ask an owner to re-grant your new public key".to_string(),
        });
    }
    let identity = load_legacy_identity()?;
    let dek = ProjectKey::new(unwrap_dek_with_private_key(
        &recipient.wrapped_dek_b64,
        &identity.private_key_pem,
    )?);
    verify_metadata_and_secrets(metadata, &dek)?;
    record_unlock_best_effort("identity", metadata);
    Ok(dek)
}

fn unwrap_dek_with_passphrase(
    metadata: &crate::crypto::VaultKeyMetadata,
    passphrase: &str,
) -> DotLockResult<ProjectKey> {
    let salt = general_purpose::STANDARD
        .decode(&metadata.salt_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let params = KdfParams {
        memory_kib: metadata.memory_kib,
        iterations: metadata.iterations,
        parallelism: metadata.parallelism,
    };

    let mut master_key = derive_master_key(passphrase, &salt, params)?;

    let mut kek = derive_kek(
        &master_key,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )?;

    master_key.zeroize();

    let nonce = general_purpose::STANDARD
        .decode(&metadata.wrapped_dek_nonce_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let wrapped_dek = general_purpose::STANDARD
        .decode(&metadata.wrapped_dek_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let wrapped = WrappedDek {
        nonce,
        ciphertext: wrapped_dek,
    };

    let dek = unwrap_dek(
        &kek,
        &wrapped,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )
    .map_err(|_| DotLockError::InvalidMasterPassword)?;

    kek.zeroize();
    Ok(dek)
}

/// M3 rollback gate: refuses a vault whose monotonic epoch is older than the
/// newest one this machine has already seen (anchor kept OUTSIDE the repo),
/// then advances the anchor. `DOTLOCK_ALLOW_VAULT_ROLLBACK=1` lets the USER
/// explicitly accept a checkout of an older revision; an attacker with mere
/// repo write access cannot set the victim's environment. Runs even for
/// legacy vaults without a MAC, so stripping the MAC/epoch fields cannot
/// bypass it once a newer epoch was anchored.
fn enforce_epoch_anchor(metadata: &crate::crypto::VaultKeyMetadata) -> DotLockResult<()> {
    if let Some(last_seen) = epoch_anchor::last_seen_epoch(&metadata.project_uuid)
        && metadata.vault_epoch < last_seen
    {
        let user_accepted = std::env::var("DOTLOCK_ALLOW_VAULT_ROLLBACK")
            .map(|value| value == "1")
            .unwrap_or(false);
        if !user_accepted {
            return Err(DotLockError::VaultRolledBack {
                found: metadata.vault_epoch,
                last_seen,
            });
        }
        eprintln!(
            "{} accepting vault epoch {} older than last seen {} (DOTLOCK_ALLOW_VAULT_ROLLBACK=1)",
            "warn:".yellow().bold(),
            metadata.vault_epoch,
            last_seen
        );
        return Ok(());
    }
    // Best-effort: the anchor lives in per-user state; its absence (e.g. no
    // HOME) must not block an otherwise valid unlock.
    let _ = epoch_anchor::advance_epoch(&metadata.project_uuid, metadata.vault_epoch);
    Ok(())
}

/// Full-access trust chain (M2+M3), in order: authenticate the metadata MAC
/// (covers every scalar field, the recipient set and the epoch), enforce the
/// rollback anchor, then verify the secrets integrity hash.
fn verify_metadata_and_secrets(
    metadata: &crate::crypto::VaultKeyMetadata,
    dek: &ProjectKey,
) -> DotLockResult<()> {
    verify_metadata_mac(metadata, dek)?;
    enforce_epoch_anchor(metadata)?;
    verify_secrets_integrity(secrets_file(), metadata, dek)
}

fn unlock_vault_with_dek(
    metadata: &crate::crypto::VaultKeyMetadata,
    dek: ProjectKey,
) -> DotLockResult<ProjectKey> {
    verify_metadata_and_secrets(metadata, &dek)?;
    write_cached_dek_for(metadata, &dek)?;
    Ok(dek)
}

/// Master-password unlock against already-loaded metadata: prompts (or takes
/// the FG2 non-interactive source), unwraps the DEK, verifies integrity,
/// refreshes the session cache, and records the audit entry — without
/// re-reading `vault.toml`.
pub fn unlock_vault_with_master_password_prepared(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<(ProjectKey, zeroize::Zeroizing<String>)> {
    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(metadata, &passphrase)?;
    let dek = unlock_vault_with_dek(metadata, dek)?;
    record_unlock_best_effort("password", metadata);
    Ok((dek, passphrase))
}

fn try_unlock_vault_with_local_identity(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<UnlockAccess> {
    let (recipient, legacy) = find_local_recipient(metadata).ok_or_else(|| {
        let query = load_local_identity_metadata()
            .map(|identity_meta| identity_meta.fingerprint)
            .unwrap_or_default();
        DotLockError::RecipientNotFound { query }
    })?;
    let identity = load_matched_identity(legacy)?;
    if recipient.wrapped_dek_b64.is_empty() && !recipient.wrapped_sdks.is_empty() {
        verify_public_secrets_hash(secrets_file(), metadata)?;
        record_unlock_best_effort("identity", metadata);
        return Ok(UnlockAccess::Limited);
    }
    let dek = ProjectKey::new(unwrap_dek_with_private_key(
        &recipient.wrapped_dek_b64,
        &identity.private_key_pem,
    )?);
    let dek = unlock_vault_with_dek(metadata, dek)?;
    record_unlock_best_effort("identity", metadata);
    Ok(UnlockAccess::Full(dek))
}

fn print_shared_recipients(metadata: &crate::crypto::VaultKeyMetadata) {
    if metadata.recipients.is_empty() {
        return;
    }

    let mut recipients = metadata.recipients.clone();
    recipients.sort_by(|a, b| a.label.cmp(&b.label));

    let rows: Vec<Vec<String>> = recipients
        .iter()
        .map(|recipient| {
            vec![
                recipient.label.clone(),
                recipient.public_key_fingerprint.clone(),
            ]
        })
        .collect();

    println!();
    println!(
        "  {}",
        "shared recipients available for certificate unlock:"
            .cyan()
            .bold()
    );
    render_table(
        &["LABEL", "FINGERPRINT"],
        &rows,
        &[|s| s.bold(), |s| s.yellow()],
    );
    println!();
}

/// Test-only convenience wrapper; command code goes through
/// [`prepare_vault_access`] + [`unlock_vault_prepared`] so the metadata read
/// happens exactly once per command (A6).
#[cfg(test)]
pub fn unlock_vault(path: &str) -> DotLockResult<UnlockAccess> {
    let metadata = prepare_vault_access(path)?;
    unlock_vault_prepared(&metadata)
}

/// Full unlock flow (cache -> shared identity -> master password) against
/// already-loaded metadata. Callers must have gone through
/// [`prepare_vault_access`] first so the reconcile gate has run.
pub fn unlock_vault_prepared(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<UnlockAccess> {
    if let Some(dek) = read_cached_dek_for(metadata) {
        match verify_metadata_and_secrets(metadata, &dek) {
            Ok(()) => {
                write_cached_dek_for(metadata, &dek)?;
                record_unlock_best_effort("cache", metadata);
                return Ok(UnlockAccess::Full(dek));
            }
            Err(err @ (DotLockError::TamperedSecretsFile | DotLockError::MetadataTampered)) => {
                let _ = invalidate_cache();
                return Err(err);
            }
            // A rollback refusal is not a key problem: the cached project key
            // is still correct, and the user may legitimately accept the
            // older state (DOTLOCK_ALLOW_VAULT_ROLLBACK=1) on the next run.
            Err(err @ DotLockError::VaultRolledBack { .. }) => {
                return Err(err);
            }
            Err(_) => {
                let _ = invalidate_cache();
            }
        }
    }

    if metadata.access_mode == AccessMode::Shared {
        match try_unlock_vault_with_local_identity(metadata) {
            Ok(access) => return Ok(access),
            Err(
                err @ (DotLockError::TamperedSecretsFile
                | DotLockError::MetadataTampered
                | DotLockError::VaultRolledBack { .. }),
            ) => {
                return Err(err);
            }
            Err(_) => {}
        }

        print_shared_recipients(metadata);
    }

    unlock_vault_with_master_password_prepared(metadata).map(|(dek, _)| UnlockAccess::Full(dek))
}

fn record_unlock_best_effort(method: &str, metadata: &crate::crypto::VaultKeyMetadata) {
    let access_mode = match metadata.access_mode {
        AccessMode::MasterPassword => "master",
        AccessMode::Shared => "shared",
    };
    if let Err(err) = record_unlock(method, access_mode) {
        eprintln!(
            "{} audit log write failed: {}",
            "warn:".yellow().bold(),
            err
        );
    }
}

#[cfg(test)]
mod tests {
    use super::UnlockAccess;
    use crate::domain::{error::DotLockError, keys::ProjectKey};

    #[test]
    fn limited_access_never_yields_a_project_key_for_writes() {
        let result = UnlockAccess::Limited.require_full();
        assert!(matches!(result, Err(DotLockError::AccessDenied { .. })));
    }

    #[test]
    fn full_access_yields_the_project_key() {
        let dek = UnlockAccess::Full(ProjectKey::new([8u8; 32]))
            .require_full()
            .expect("full access");
        assert_eq!(dek.as_bytes(), &[8u8; 32]);
    }

    #[test]
    fn limited_read_key_is_the_all_zero_placeholder() {
        assert!(
            UnlockAccess::Limited
                .into_read_key()
                .is_read_only_placeholder()
        );
    }

    /// Legacy-identity fallback (ADR 0001): after `dl cert migrate`, a vault
    /// that still references the OLD (RSA) fingerprint resolves through the
    /// archived legacy identity; a vault already rekeyed to the new
    /// fingerprint resolves through the current identity.
    #[test]
    fn find_local_recipient_falls_back_to_the_archived_legacy_identity() {
        use crate::storage::{identity::test_identity_env_lock, secure_fs};

        let _guard = test_identity_env_lock().lock().expect("lock");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-unlock-legacy-{unique}"));
        std::fs::create_dir_all(&dir).expect("create dir");
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
        }
        let write = |name: &str, content: &str| {
            secure_fs::write_string_atomic(&dir.join(name), content, 0o700, 0o600)
                .expect("write identity file");
        };
        write(
            "identity.toml",
            "fingerprint = \"new-fp\"\nencrypted = false\nalg = \"ed25519\"\n",
        );
        write(
            "identity.legacy.toml",
            "fingerprint = \"old-fp\"\nencrypted = false\n",
        );

        let mut metadata = toml::from_str::<crate::crypto::VaultKeyMetadata>(
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
        let recipient_with = |fingerprint: &str| crate::crypto::VaultRecipient {
            id: fingerprint.to_string(),
            label: fingerprint.to_string(),
            alg: "rsa-oaep-sha256".to_string(),
            public_key_fingerprint: fingerprint.to_string(),
            public_key_b64: "cHVi".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: true,
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
        };

        // Pre-migration vault: only the legacy fingerprint matches.
        metadata.recipients = vec![recipient_with("old-fp")];
        let (recipient, legacy) =
            super::find_local_recipient(&metadata).expect("legacy fallback match");
        assert!(legacy);
        assert_eq!(recipient.public_key_fingerprint, "old-fp");

        // Rekeyed vault: the current identity wins (no legacy fallback).
        metadata.recipients = vec![recipient_with("new-fp"), recipient_with("old-fp")];
        let (recipient, legacy) =
            super::find_local_recipient(&metadata).expect("current identity match");
        assert!(!legacy);
        assert_eq!(recipient.public_key_fingerprint, "new-fp");

        // No matching recipient at all: no identity unlock is attempted.
        metadata.recipients = vec![recipient_with("someone-else")];
        assert!(super::find_local_recipient(&metadata).is_none());

        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_DIR");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
