//! `dl exec` (FG4): shell-form counterpart of `dl run`. The user-provided
//! command line is executed via `sh -c`, so `&&`, pipes and variable
//! expansion work. Secrets are injected exclusively as ENVIRONMENT variables
//! of the child shell — they are never interpolated into the command string,
//! so secret values cannot alter what gets executed. `dl run -- cmd args`
//! (argv form, no shell) remains the safe default; `dl exec` is the explicit
//! opt-in convenience for migration from `.env`-era scripts.

use crate::{
    cli::args::ExecArgs,
    commands::context::VaultContext,
    domain::model::DotLockResult,
    git::fetch::auto_fetch_if_enabled,
    runtime::{load_env_file_vars, run_with_secrets},
    storage::project::{VAULT_FILE, ensure_project_initialized},
};

pub fn run(args: ExecArgs) -> DotLockResult<()> {
    ensure_project_initialized()?;
    auto_fetch_if_enabled(VAULT_FILE)?;
    let extra_env = match args.env_file.as_deref() {
        Some(path) => load_env_file_vars(path)?,
        None => Vec::new(),
    };
    let (metadata, dek) = VaultContext::unlock()?.into_read();
    // Join the (possibly unquoted) words back into one shell command line.
    // This is the user's OWN string — exactly what they would type after
    // `sh -c` themselves; no vault data ever becomes part of it.
    let command_line = args.command.join(" ");
    let command = vec!["sh".to_string(), "-c".to_string(), command_line];
    run_with_secrets(command, extra_env, &dek, &metadata)
}
