use colored::Colorize;

use crate::{
    domain::model::DotLockResult,
    git::sync::{SyncStatus, sync_with_remote},
    storage::project::{VAULT_FILE, ensure_project_initialized},
};

pub fn run() -> DotLockResult<()> {
    ensure_project_initialized()?;
    let summary = sync_with_remote(VAULT_FILE)?;
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
