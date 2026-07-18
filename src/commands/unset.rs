use colored::Colorize;

use crate::{
    cli::args::UnsetArgs,
    commands::context::prepare_project_key_for_write,
    domain::model::DotLockResult,
    storage::{
        project::{VAULT_FILE, ensure_project_initialized},
        secrets_lock::remove_secret_by_name,
        unlock_file::unlock_vault,
    },
    utils::normalize_var_name,
};

pub fn run(args: UnsetArgs) -> DotLockResult<()> {
    let name = normalize_var_name(&args.name)?;
    ensure_project_initialized()?;
    let dek = prepare_project_key_for_write(unlock_vault(VAULT_FILE)?)?;

    remove_secret_by_name(&name, &dek, VAULT_FILE)?;

    println!("{} secret {} removed", "ok:".green().bold(), name.bold());
    Ok(())
}
