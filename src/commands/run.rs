use crate::{
    cli::args::RunArgs,
    commands::context::VaultContext,
    domain::model::DotLockResult,
    git::fetch::auto_fetch_if_enabled,
    runtime::run_with_secrets,
    storage::project::{VAULT_FILE, ensure_project_initialized},
};

pub fn run(args: RunArgs) -> DotLockResult<()> {
    ensure_project_initialized()?;
    // The fetch may fast-forward the vault files, so the context (and its
    // single metadata read) is only built afterwards.
    auto_fetch_if_enabled(VAULT_FILE)?;
    let (metadata, dek) = VaultContext::unlock()?.into_read();
    run_with_secrets(args.command, &dek, &metadata)
}
