use colored::Colorize;

use crate::{
    domain::model::DotLockResult,
    git::sync::{SyncStatus, sync_with_remote},
    storage::project::{ensure_project_initialized, vault_file},
};

pub fn run() -> DotLockResult<()> {
    ensure_project_initialized()?;
    let summary = sync_with_remote(&vault_file())?;
    match summary.status {
        SyncStatus::UpToDate => println!(
            "{} vault already synced with {}/{}",
            "ok:".green().bold(),
            summary.remote,
            summary.branch
        ),
        SyncStatus::FastForwarded => println!(
            "{} vault synced from {}/{}",
            "ok:".green().bold(),
            summary.remote,
            summary.branch
        ),
        SyncStatus::LocalAhead => println!(
            "{} local branch is ahead of {}/{}; no pull needed",
            "info:".cyan().bold(),
            summary.remote,
            summary.branch
        ),
    }
    Ok(())
}
