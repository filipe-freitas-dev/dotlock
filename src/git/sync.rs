use std::{
    io,
    process::{Command, Stdio},
};

use crate::{
    crypto::VaultConfig,
    domain::{error::DotLockError, model::DotLockResult},
    git::validate_git_ref_component,
    storage::vault_file::load_vault_metadata,
};

const DEFAULT_REMOTE: &str = "origin";
const VAULT_PATHS: [&str; 2] = [".lock/vault.toml", ".lock/secrets.lock"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    UpToDate,
    FastForwarded,
    LocalAhead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSummary {
    pub remote: String,
    pub branch: String,
    pub status: SyncStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefState {
    Equal,
    Behind,
    Ahead,
    Diverged,
}

pub fn sync_with_remote(vault_path: &str) -> DotLockResult<SyncSummary> {
    let metadata = load_vault_metadata(vault_path)?;
    let remote = sync_remote(&metadata.config)?;

    ensure_git_work_tree()?;
    ensure_vault_clean()?;

    let branch = current_branch()?;
    validate_git_ref_component("branch", &branch)?;
    // `--` ends option parsing so a hostile remote/branch value can never be
    // interpreted by git as an option such as `--upload-pack=<cmd>` (H1).
    run_git(["fetch", "--", &remote, &branch])?;

    let local = git_output(["rev-parse", "HEAD"])?
        .ok_or_else(|| DotLockError::Io("could not resolve local Git HEAD for sync".to_string()))?;
    let remote_ref = format!("refs/remotes/{remote}/{branch}");
    let remote_head = git_output(["rev-parse", "--verify", &remote_ref])?.ok_or_else(|| {
        DotLockError::Io(format!(
            "remote branch `{remote}/{branch}` was not found after fetch"
        ))
    })?;

    match classify_refs(
        local.trim() == remote_head.trim(),
        is_ancestor(local.trim(), remote_head.trim())?,
        is_ancestor(remote_head.trim(), local.trim())?,
    ) {
        RefState::Equal => Ok(SyncSummary {
            remote,
            branch,
            status: SyncStatus::UpToDate,
        }),
        RefState::Behind => {
            run_git(["pull", "--ff-only", "--no-rebase", "--", &remote, &branch])?;
            Ok(SyncSummary {
                remote,
                branch,
                status: SyncStatus::FastForwarded,
            })
        }
        RefState::Ahead => Ok(SyncSummary {
            remote,
            branch,
            status: SyncStatus::LocalAhead,
        }),
        RefState::Diverged => Err(DotLockError::Io(format!(
            "local branch and `{remote}/{branch}` have diverged; merge manually and run `dl git install-merge-driver` if DotLock files conflict"
        ))),
    }
}

pub fn classify_refs(equal: bool, local_is_ancestor: bool, remote_is_ancestor: bool) -> RefState {
    if equal {
        RefState::Equal
    } else if local_is_ancestor {
        RefState::Behind
    } else if remote_is_ancestor {
        RefState::Ahead
    } else {
        RefState::Diverged
    }
}

fn sync_remote(config: &VaultConfig) -> DotLockResult<String> {
    let remote = config
        .auto_fetch_remote
        .as_deref()
        .unwrap_or(DEFAULT_REMOTE);
    // `auto_fetch_remote` lives in the committed `vault.toml` and is
    // attacker-controlled by anyone with write access to the repo; reject
    // option-shaped values before they ever reach a git invocation (H1).
    validate_git_ref_component("auto_fetch_remote", remote)?;
    Ok(remote.to_string())
}

fn ensure_git_work_tree() -> DotLockResult<()> {
    let inside = git_output(["rev-parse", "--is-inside-work-tree"])?;
    if inside
        .as_deref()
        .is_some_and(|value| value.trim() == "true")
    {
        return Ok(());
    }
    Err(DotLockError::Io(
        "`dl sync` must be run inside a Git work tree".to_string(),
    ))
}

fn ensure_vault_clean() -> DotLockResult<()> {
    let mut args = vec!["status", "--porcelain", "--"];
    args.extend(VAULT_PATHS);
    let status = git_output_dynamic(&args)?.unwrap_or_default();
    if status.trim().is_empty() {
        return Ok(());
    }
    Err(DotLockError::Io(
        "local `.lock/` changes are present; commit or stash them before `dl sync`".to_string(),
    ))
}

fn current_branch() -> DotLockResult<String> {
    let branch = git_output(["branch", "--show-current"])?.ok_or_else(|| {
        DotLockError::Io("could not determine the current Git branch".to_string())
    })?;
    let branch = branch.trim();
    if branch.is_empty() {
        return Err(DotLockError::Io(
            "`dl sync` requires a named Git branch".to_string(),
        ));
    }
    Ok(branch.to_string())
}

fn is_ancestor(ancestor: &str, descendant: &str) -> DotLockResult<bool> {
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(map_git_spawn)?;

    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(DotLockError::Io(
            "git merge-base failed while checking sync state".to_string(),
        )),
    }
}

fn git_output<const N: usize>(args: [&str; N]) -> DotLockResult<Option<String>> {
    git_output_dynamic(&args)
}

fn git_output_dynamic(args: &[&str]) -> DotLockResult<Option<String>> {
    let output = Command::new("git")
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map_err(map_git_spawn)?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

fn run_git<const N: usize>(args: [&str; N]) -> DotLockResult<()> {
    let output = Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(map_git_spawn)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr.trim();
    if message.is_empty() {
        return Err(DotLockError::Io("git command failed".to_string()));
    }
    Err(DotLockError::Io(message.to_string()))
}

fn map_git_spawn(err: io::Error) -> DotLockError {
    if err.kind() == io::ErrorKind::NotFound {
        DotLockError::Io("git was not found on PATH".to_string())
    } else {
        DotLockError::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{RefState, classify_refs};

    #[test]
    fn classifies_equal_refs() {
        assert_eq!(classify_refs(true, true, true), RefState::Equal);
    }

    #[test]
    fn classifies_local_behind_remote() {
        assert_eq!(classify_refs(false, true, false), RefState::Behind);
    }

    #[test]
    fn classifies_local_ahead_of_remote() {
        assert_eq!(classify_refs(false, false, true), RefState::Ahead);
    }

    #[test]
    fn classifies_diverged_refs() {
        assert_eq!(classify_refs(false, false, false), RefState::Diverged);
    }
}
