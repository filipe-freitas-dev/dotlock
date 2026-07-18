use colored::Colorize;

use crate::{
    cli::{args::RotateCommand, present::print_ratchet_summary},
    commands::context::{VaultContext, rotate_project_key},
    crypto::{ask_master_password, update_master_password_metadata},
    domain::model::DotLockResult,
    storage::{
        project::VAULT_FILE,
        vault_file::{record_vault_write, save_vault_metadata},
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
            save_vault_metadata(VAULT_FILE, &metadata)?;
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
