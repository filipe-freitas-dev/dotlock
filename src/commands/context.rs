use colored::Colorize;

use crate::{
    audit::record_ratchet,
    cli::present::print_ratchet_summary,
    crypto::{VaultKeyMetadata, dek::generate_dek, update_master_password_metadata},
    domain::{keys::ProjectKey, model::DotLockResult},
    storage::{
        cache::invalidate_cache,
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        unlock_file::{
            UnlockAccess, prepare_vault_access, unlock_vault_prepared,
            unlock_vault_with_master_password_prepared,
        },
        vault_file::{
            RatchetSummary, rotate_project_key_wrapping, should_auto_ratchet_for_next_write,
        },
        vault_txn::{VaultPairWrite, commit_vault_pair},
    },
};

/// Per-command vault context (A6): one pending-transaction recovery, one
/// reconcile-gate check, one `vault.toml` read, and one unlock — threaded by
/// reference into every helper that previously re-read the vault on its own.
pub struct VaultContext {
    pub metadata: VaultKeyMetadata,
    pub access: UnlockAccess,
}

impl VaultContext {
    /// Standard unlock (cache -> shared identity -> master password), exactly
    /// like the old per-helper flow but with a single metadata load.
    pub fn unlock() -> DotLockResult<Self> {
        ensure_project_initialized()?;
        let metadata = prepare_vault_access(VAULT_FILE)?;
        let access = unlock_vault_prepared(&metadata)?;
        Ok(Self { metadata, access })
    }

    /// Master-password-only unlock used by `share`/`rotate`: always prompts,
    /// and returns the proven passphrase alongside the context.
    pub fn unlock_with_master_password() -> DotLockResult<(Self, String)> {
        ensure_project_initialized()?;
        let metadata = prepare_vault_access(VAULT_FILE)?;
        let (dek, passphrase) = unlock_vault_with_master_password_prepared(&metadata)?;
        Ok((
            Self {
                metadata,
                access: UnlockAccess::Full(dek),
            },
            passphrase,
        ))
    }

    /// Read path: hands out the metadata with the read key (all-zero
    /// placeholder for limited identities, as before).
    pub fn into_read(self) -> (VaultKeyMetadata, ProjectKey) {
        (self.metadata, self.access.into_read_key())
    }

    /// Write gate: requires full access and applies the auto-ratchet policy
    /// (re-proving the master password and rotating the project key when the
    /// write counter crosses the configured threshold), without re-reading
    /// `vault.toml`.
    pub fn into_write(self) -> DotLockResult<(VaultKeyMetadata, ProjectKey)> {
        let Self {
            mut metadata,
            access,
        } = self;
        let current_dek = access.require_full()?;
        if !should_auto_ratchet_for_next_write(&metadata) {
            return Ok((metadata, current_dek));
        }

        let (verified_dek, passphrase) = unlock_vault_with_master_password_prepared(&metadata)?;
        let (new_dek, summary) = rotate_project_key(&mut metadata, &verified_dek, &passphrase)?;
        print_ratchet_summary(&summary);
        Ok((metadata, new_dek))
    }
}

pub fn rotate_project_key(
    metadata: &mut VaultKeyMetadata,
    current_dek: &ProjectKey,
    passphrase: &str,
) -> DotLockResult<(ProjectKey, RatchetSummary)> {
    let new_dek = generate_dek()?;
    // rotate_project_key_wrapping rewraps the SDKs/recipient wrappings AND
    // re-encrypts `secrets_hash_*` under the new DEK in the same metadata
    // object; one transactional commit makes the whole rotation atomic
    // (secrets.lock is unchanged by rotation). `dl rotate` rotates the DEK.
    let summary = rotate_project_key_wrapping(metadata, current_dek, &new_dek)?;
    update_master_password_metadata(metadata, &new_dek, passphrase)?;
    commit_vault_pair(
        std::path::Path::new(VAULT_FILE),
        std::path::Path::new(SECRETS_FILE),
        VaultPairWrite {
            metadata,
            secrets_lock_bytes: None,
        },
    )?;
    record_ratchet_best_effort(&summary);
    invalidate_cache()?;
    Ok((new_dek, summary))
}

pub fn record_ratchet_best_effort(summary: &RatchetSummary) {
    if let Err(err) = record_ratchet(
        summary.old_kek_version,
        summary.new_kek_version,
        summary.secrets_rewrapped,
        summary.recipients_rewrapped,
    ) {
        eprintln!(
            "{} audit log write failed: {}",
            "warn:".yellow().bold(),
            err
        );
    }
}
