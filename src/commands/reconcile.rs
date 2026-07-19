use colored::Colorize;

use crate::{
    cli::present::print_merge_diff,
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        self,
        pending_merge::{
            confirmation_is_yes, load_marker, reconcile_pending_merge, verify_marker_matches_files,
        },
        project::{ensure_project_initialized, env_lock_dir, secrets_file, vault_file},
        unlock_file::unlock_full_for_reconcile,
        vault_txn::recover_pending,
    },
};

pub fn run() -> DotLockResult<()> {
    ensure_project_initialized()?;
    let vault_file = vault_file();
    let secrets_file = secrets_file();
    let env_lock_dir = env_lock_dir();
    let vault_path = std::path::Path::new(&vault_file);
    let secrets_path = std::path::Path::new(&secrets_file);
    let lock_dir = std::path::Path::new(&env_lock_dir);
    recover_pending(vault_path, secrets_path)?;

    let Some(marker) = load_marker(lock_dir)? else {
        println!("{} no pending merge to reconcile", "info:".cyan().bold());
        return Ok(());
    };
    // Anti-laundering: refuse before even prompting if the merged
    // files were edited after the merge driver produced them.
    verify_marker_matches_files(&marker, vault_path, secrets_path)?;

    print_merge_diff(&marker);
    print!("re-sign and accept the merged vault? [y/N] ");
    use std::io::Write as _;
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(DotLockError::from)?;
    if !confirmation_is_yes(&answer) {
        println!(
            "{} merge left unreconciled; resolve manually with `git checkout --ours -- .lock/` (or `--theirs`) and redo the merge, or run {} again to accept",
            "info:".cyan().bold(),
            "dl reconcile".bold()
        );
        return Err(DotLockError::Aborted);
    }

    let dek = unlock_full_for_reconcile(&vault_file)?;
    reconcile_pending_merge(vault_path, secrets_path, lock_dir, &dek)?;
    storage::cache::write_cached_dek(&dek)?;
    println!(
        "{} merged vault reconciled and re-signed",
        "ok:".green().bold()
    );
    Ok(())
}
