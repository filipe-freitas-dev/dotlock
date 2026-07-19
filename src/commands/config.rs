use colored::Colorize;

use crate::{
    cli::args::ConfigCommand,
    commands::context::VaultContext,
    domain::model::DotLockResult,
    storage::{
        config::{config_lines, set_config_value, unset_config_value},
        project::{ensure_project_initialized, vault_file},
        vault_file::load_vault_metadata,
    },
};

pub fn run(command: ConfigCommand) -> DotLockResult<()> {
    ensure_project_initialized()?;
    match command {
        ConfigCommand::Show => {
            let metadata = load_vault_metadata(vault_file())?;
            for line in config_lines(&metadata.config) {
                println!("{line}");
            }
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            // Config fields are covered by the metadata MAC (M2), so writing
            // them requires full access and reseals the vault.
            let ctx = VaultContext::unlock()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            set_config_value(
                std::path::Path::new(&vault_file()),
                &mut metadata,
                &key,
                &value,
                &dek,
            )?;
            println!("{} config {} updated", "ok:".green().bold(), key.bold());
            Ok(())
        }
        ConfigCommand::Unset { key } => {
            let ctx = VaultContext::unlock()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            unset_config_value(
                std::path::Path::new(&vault_file()),
                &mut metadata,
                &key,
                &dek,
            )?;
            println!("{} config {} reset", "ok:".green().bold(), key.bold());
            Ok(())
        }
    }
}
