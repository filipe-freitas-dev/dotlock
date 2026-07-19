use colored::Colorize;

use crate::{
    cli::{
        args::{RotateArgs, RotateCommand},
        confirm::confirm_destructive,
        present::print_ratchet_summary,
    },
    commands::context::{VaultContext, rotate_project_key},
    crypto::{
        ask_master_password, integrity::seal_vault_metadata, update_master_password_metadata,
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        project::{ensure_project_initialized, secrets_file, vault_file},
        secrets_lock::current_unix_timestamp,
        vault_file::{load_vault_metadata, record_vault_write, rotation_due},
        vault_txn::{VaultPairWrite, commit_vault_pair},
    },
};

pub fn run(args: RotateArgs) -> DotLockResult<()> {
    if args.if_due {
        return run_if_due();
    }
    let Some(command) = args.command else {
        return Err(DotLockError::Io(
            "specify what to rotate (`kek`, `project-key`, `master-password`) or pass `--if-due`"
                .to_string(),
        ));
    };
    // L5: rotations are irreversible (the old wrapping material is gone once
    // committed) — gate on --yes / TTY confirmation BEFORE any unlock prompt.
    // `--if-due` is exempt: it exists for cron/CI, where the policy check
    // itself is the operator's standing consent.
    ensure_project_initialized()?;
    match command {
        RotateCommand::MasterPassword { yes } => {
            confirm_destructive(
                "rotate the master password (the current password will stop unlocking this vault)",
                yes,
            )?;
            let (ctx, _passphrase) = VaultContext::unlock_with_master_password()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            let passphrase = ask_master_password()?;
            update_master_password_metadata(&mut metadata, &dek, &passphrase)?;
            record_vault_write(&mut metadata);
            seal_vault_metadata(&mut metadata, &dek)?;
            commit_vault_pair(
                std::path::Path::new(&vault_file()),
                std::path::Path::new(&secrets_file()),
                VaultPairWrite {
                    metadata: &metadata,
                    secrets_lock_bytes: None,
                },
            )?;
            println!("{} master password rotated", "ok:".green().bold());
            Ok(())
        }
        RotateCommand::Kek { yes } => {
            confirm_destructive(
                "rotate the project key (DEK) and rewrap every secret data key",
                yes,
            )?;
            let (ctx, passphrase) = VaultContext::unlock_with_master_password()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            let (_new_dek, summary) = rotate_project_key(&mut metadata, &dek, &passphrase)?;
            print_ratchet_summary(&summary);
            Ok(())
        }
        RotateCommand::ProjectKey { yes } => {
            confirm_destructive(
                "rotate the project key (DEK) and rewrap every secret data key",
                yes,
            )?;
            let (ctx, passphrase) = VaultContext::unlock_with_master_password()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            let (_new_dek, _) = rotate_project_key(&mut metadata, &dek, &passphrase)?;
            println!("{} project key rotated", "ok:".green().bold());
            Ok(())
        }
    }
}

/// FG5 scheduled rotation: rotates the project key ONLY when the configured
/// policy says a rotation is due. The due-check reads the (unauthenticated at
/// this point) metadata without unlocking, so a cron job that finds nothing
/// due exits 0 without ever prompting for the master password.
fn run_if_due() -> DotLockResult<()> {
    ensure_project_initialized()?;
    let metadata = load_vault_metadata(vault_file())?;
    let Some(reason) = rotation_due(&metadata, current_unix_timestamp()) else {
        println!(
            "{} rotation not due (policies: rotate_max_age_days = {}, auto_ratchet_after_writes = {})",
            "ok:".green().bold(),
            metadata
                .config
                .rotate_max_age_days
                .map(|days| days.to_string())
                .unwrap_or_else(|| "off".to_string()),
            metadata
                .config
                .auto_ratchet_after_writes
                .map(|writes| writes.to_string())
                .unwrap_or_else(|| "off".to_string()),
        );
        return Ok(());
    };

    println!("{} rotation due: {reason}", "info:".cyan().bold());
    // The unlock re-runs pending-transaction recovery, the reconcile gate and
    // the MAC/epoch checks against a fresh metadata read — the pre-check
    // above only decided whether to bother the operator for a password.
    let (ctx, passphrase) = VaultContext::unlock_with_master_password()?;
    let VaultContext {
        mut metadata,
        access,
    } = ctx;
    let dek = access.require_full()?;
    let (_new_dek, summary) = rotate_project_key(&mut metadata, &dek, &passphrase)?;
    print_ratchet_summary(&summary);
    Ok(())
}
