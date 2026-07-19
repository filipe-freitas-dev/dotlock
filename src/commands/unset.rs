use colored::Colorize;

use crate::{
    cli::args::UnsetArgs,
    commands::context::VaultContext,
    domain::model::DotLockResult,
    storage::{project::vault_file, secrets_lock::remove_secret_by_name},
    utils::normalize_var_name,
};

pub fn run(args: UnsetArgs) -> DotLockResult<()> {
    let name = normalize_var_name(&args.name)?;
    let (mut metadata, dek) = VaultContext::unlock()?.into_write()?;

    remove_secret_by_name(&name, &dek, &vault_file(), &mut metadata)?;

    println!("{} secret {} removed", "ok:".green().bold(), name.bold());
    Ok(())
}
