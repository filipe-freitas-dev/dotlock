use colored::Colorize;

use crate::{
    cli::args::ConfigCommand,
    domain::model::DotLockResult,
    storage::{
        config::{config_lines, set_config_value, unset_config_value},
        project::{VAULT_FILE, ensure_project_initialized},
        vault_file::load_vault_metadata,
    },
};

pub fn run(command: ConfigCommand) -> DotLockResult<()> {
    ensure_project_initialized()?;
    match command {
        ConfigCommand::Show => {
            let metadata = load_vault_metadata(VAULT_FILE)?;
            for line in config_lines(&metadata.config) {
                println!("{line}");
            }
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            set_config_value(std::path::Path::new(VAULT_FILE), &key, &value)?;
            println!("{} config {} updated", "ok:".green().bold(), key.bold());
            Ok(())
        }
        ConfigCommand::Unset { key } => {
            unset_config_value(std::path::Path::new(VAULT_FILE), &key)?;
            println!("{} config {} reset", "ok:".green().bold(), key.bold());
            Ok(())
        }
    }
}
