use colored::Colorize;

use crate::{
    audit::record_ratchet,
    cli::present::print_ratchet_summary,
    crypto::{dek::generate_dek, update_master_password_metadata},
    domain::{keys::ProjectKey, model::DotLockResult},
    storage::{
        cache::invalidate_cache,
        project::{SECRETS_FILE, VAULT_FILE},
        unlock_file::{UnlockAccess, unlock_vault_with_master_password_and_passphrase},
        vault_file::{
            RatchetSummary, load_vault_metadata, rotate_project_key_wrapping,
            should_auto_ratchet_for_next_write,
        },
        vault_txn::{VaultPairWrite, commit_vault_pair},
    },
};

pub fn prepare_project_key_for_write(access: UnlockAccess) -> DotLockResult<ProjectKey> {
    let current_dek = access.require_full()?;
    let metadata = load_vault_metadata(VAULT_FILE)?;
    if !should_auto_ratchet_for_next_write(&metadata) {
        return Ok(current_dek);
    }

    let (verified_dek, passphrase) = unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
    let (new_dek, summary) = rotate_project_key(&verified_dek, &passphrase)?;
    print_ratchet_summary(&summary);
    Ok(new_dek)
}

pub fn rotate_project_key(
    current_dek: &ProjectKey,
    passphrase: &str,
) -> DotLockResult<(ProjectKey, RatchetSummary)> {
    let mut metadata = load_vault_metadata(VAULT_FILE)?;
    let new_dek = generate_dek()?;
    // rotate_project_key_wrapping rewraps the SDKs/recipient wrappings AND
    // re-encrypts `secrets_hash_*` under the new DEK in the same metadata
    // object; one transactional commit makes the whole rotation atomic
    // (secrets.lock is unchanged by rotation). `dl rotate` rotates the DEK.
    let summary = rotate_project_key_wrapping(&mut metadata, current_dek, &new_dek)?;
    update_master_password_metadata(&mut metadata, &new_dek, passphrase)?;
    commit_vault_pair(
        std::path::Path::new(VAULT_FILE),
        std::path::Path::new(SECRETS_FILE),
        VaultPairWrite {
            metadata: &metadata,
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
