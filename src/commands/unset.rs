use colored::Colorize;

use crate::{
    cli::{args::UnsetArgs, confirm::confirm_destructive},
    commands::context::VaultContext,
    domain::model::DotLockResult,
    storage::{
        project::{ensure_project_initialized, vault_file},
        secrets_lock::{find_secret_by_name, remove_secret_by_name},
    },
    utils::normalize_var_name,
};

pub fn run(args: UnsetArgs) -> DotLockResult<()> {
    ensure_project_initialized()?;
    let name = normalize_var_name(&args.name)?;
    // Fail on a missing secret BEFORE bothering the user with a confirmation
    // or a password prompt.
    find_secret_by_name(&name)?;
    // L5: destructive and irreversible — gate on --yes / TTY confirmation
    // before anything unlocks or mutates.
    confirm_destructive(&format!("permanently remove secret {name}"), args.yes)?;

    let (mut metadata, dek) = VaultContext::unlock()?.into_write()?;

    remove_secret_by_name(&name, &dek, &vault_file(), &mut metadata)?;

    println!("{} secret {} removed", "ok:".green().bold(), name.bold());
    Ok(())
}
