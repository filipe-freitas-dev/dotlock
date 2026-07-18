use colored::Colorize;

use crate::{
    cli::{args::RotateCommand, present::print_ratchet_summary},
    commands::context::rotate_project_key,
    crypto::{ask_master_password, update_master_password_metadata},
    domain::model::DotLockResult,
    storage::{
        project::{VAULT_FILE, ensure_project_initialized},
        unlock_file::{
            unlock_vault_with_master_password, unlock_vault_with_master_password_and_passphrase,
        },
        vault_file::{load_vault_metadata, record_vault_write, save_vault_metadata},
    },
};

pub fn run(command: RotateCommand) -> DotLockResult<()> {
    match command {
        RotateCommand::MasterPassword => {
            ensure_project_initialized()?;
            let dek = unlock_vault_with_master_password(VAULT_FILE)?;
            let mut metadata = load_vault_metadata(VAULT_FILE)?;
            let passphrase = ask_master_password()?;
            update_master_password_metadata(&mut metadata, &dek, &passphrase)?;
            record_vault_write(&mut metadata);
            save_vault_metadata(VAULT_FILE, &metadata)?;
            println!("{} master password rotated", "ok:".green().bold());
            Ok(())
        }
        RotateCommand::Kek => {
            ensure_project_initialized()?;
            let (dek, passphrase) = unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
            let (_new_dek, summary) = rotate_project_key(&dek, &passphrase)?;
            print_ratchet_summary(&summary);
            Ok(())
        }
        RotateCommand::ProjectKey => {
            ensure_project_initialized()?;
            let (dek, passphrase) = unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
            let (_new_dek, _) = rotate_project_key(&dek, &passphrase)?;
            println!("{} project key rotated", "ok:".green().bold());
            Ok(())
        }
    }
}
