use crate::{
    cli::args::RunArgs,
    commands::context::VaultContext,
    domain::model::DotLockResult,
    git::fetch::auto_fetch_if_enabled,
    runtime::{load_env_file_vars, run_with_secrets},
    storage::project::{ensure_project_initialized, vault_file},
};

pub fn run(args: RunArgs) -> DotLockResult<()> {
    ensure_project_initialized()?;
    // The fetch may fast-forward the vault files, so the context (and its
    // single metadata read) is only built afterwards.
    auto_fetch_if_enabled(&vault_file())?;
    let extra_env = match args.env_file.as_deref() {
        Some(path) => load_env_file_vars(path)?,
        None => Vec::new(),
    };
    let (metadata, dek) = VaultContext::unlock()?.into_read();
    run_with_secrets(args.command, extra_env, &dek, &metadata)
}
