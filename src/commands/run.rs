use crate::{
    cli::args::RunArgs,
    domain::model::DotLockResult,
    git::fetch::auto_fetch_if_enabled,
    runtime::run_with_secrets,
    storage::{
        project::{VAULT_FILE, ensure_project_initialized},
        unlock_file::unlock_vault,
    },
};

pub fn run(args: RunArgs) -> DotLockResult<()> {
    ensure_project_initialized()?;
    auto_fetch_if_enabled(VAULT_FILE)?;
    let dek = unlock_vault(VAULT_FILE)?.into_read_key();
    run_with_secrets(args.command, &dek)
}
