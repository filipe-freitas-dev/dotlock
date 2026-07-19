use colored::Colorize;

use crate::{
    cli::{args::RotateCommand, present::print_ratchet_summary},
    commands::context::{VaultContext, rotate_project_key},
    crypto::{
        ask_master_password, integrity::seal_vault_metadata, update_master_password_metadata,
    },
    domain::model::DotLockResult,
    storage::{
        project::{SECRETS_FILE, VAULT_FILE},
        vault_file::record_vault_write,
        vault_txn::{VaultPairWrite, commit_vault_pair},
    },
};

pub fn run(command: RotateCommand) -> DotLockResult<()> {
    match command {
        RotateCommand::MasterPassword => {
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
                std::path::Path::new(VAULT_FILE),
                std::path::Path::new(SECRETS_FILE),
                VaultPairWrite {
                    metadata: &metadata,
                    secrets_lock_bytes: None,
                },
            )?;
            println!("{} master password rotated", "ok:".green().bold());
            Ok(())
        }
        RotateCommand::Kek => {
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
        RotateCommand::ProjectKey => {
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
