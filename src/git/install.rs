use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::Command,
};

use crate::domain::{error::DotLockError, model::DotLockResult};

const ATTRIBUTES: &[&str] = &[
    ".lock/secrets.lock merge=dotlock",
    ".lock/vault.toml merge=dotlock",
];

pub fn install_merge_driver_if_in_git_repo() -> DotLockResult<bool> {
    if !is_git_repo()? {
        return Ok(false);
    }

    install_gitattributes()?;
    configure_merge_driver()?;
    Ok(true)
}

fn is_git_repo() -> DotLockResult<bool> {
    let output = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map_err(|err| DotLockError::Io(err.to_string()))?;

    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true")
}

fn install_gitattributes() -> DotLockResult<()> {
    let path = Path::new(".gitattributes");
    let existing = if path.exists() {
        fs::read_to_string(path).map_err(DotLockError::from)?
    } else {
        String::new()
    };

    let missing: Vec<&str> = ATTRIBUTES
        .iter()
        .copied()
        .filter(|line| !existing.lines().any(|existing| existing.trim() == *line))
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(DotLockError::from)?;

    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file).map_err(DotLockError::from)?;
    }

    for line in missing {
        writeln!(file, "{line}").map_err(DotLockError::from)?;
    }

    Ok(())
}

fn configure_merge_driver() -> DotLockResult<()> {
    run_git_config(["merge.dotlock.driver", "dl _git-merge %A %B %O"])?;
    run_git_config(["merge.dotlock.name", "DotLock vault merge driver"])
}

fn run_git_config(args: [&str; 2]) -> DotLockResult<()> {
    let status = Command::new("git")
        .args(["config", args[0], args[1]])
        .status()
        .map_err(|err| DotLockError::Io(err.to_string()))?;

    if !status.success() {
        return Err(DotLockError::Io(format!(
            "git config failed for {}",
            args[0]
        )));
    }

    Ok(())
}
