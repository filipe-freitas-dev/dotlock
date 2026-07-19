use std::{
    io,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use colored::Colorize;

use crate::{
    crypto::VaultConfig,
    domain::{error::DotLockError, model::DotLockResult},
    git::validate_git_ref_component,
    storage::vault_file::load_vault_metadata,
};

const DEFAULT_TIMEOUT_SECS: u64 = 3;
const DEFAULT_REMOTE: &str = "origin";

pub fn auto_fetch_if_enabled(vault_path: &str) -> DotLockResult<()> {
    let metadata = load_vault_metadata(vault_path)?;
    let env_override = std::env::var("DOTLOCK_AUTO_FETCH").ok();
    if !auto_fetch_enabled(&metadata.config, env_override.as_deref()) {
        return Ok(());
    }

    if !git_output(["rev-parse", "--is-inside-work-tree"])?
        .is_some_and(|output| output.trim() == "true")
    {
        return Ok(());
    }

    let Some(branch) = git_output(["branch", "--show-current"])? else {
        return Ok(());
    };
    let branch = branch.trim();
    if branch.is_empty() {
        return Ok(());
    }

    let remote = resolve_remote(&metadata.config)?;
    validate_git_ref_component("branch", branch)?;
    let timeout = Duration::from_secs(timeout_secs(&metadata.config));

    // `--` ends option parsing so a hostile remote/branch value can never be
    // interpreted by git as an option such as `--upload-pack=<cmd>` (H1).
    let pulled = run_git_with_timeout(
        &["pull", "--ff-only", "--no-rebase", "--", &remote, branch],
        timeout,
    )?;
    if pulled {
        return Ok(());
    }

    let _ = run_git_with_timeout(&["fetch", "--", &remote, branch], timeout);
    eprintln!(
        "{} auto-fetch failed; using local vault",
        "info:".cyan().bold()
    );
    Ok(())
}

pub fn auto_fetch_enabled(config: &VaultConfig, env_override: Option<&str>) -> bool {
    if env_override.is_some_and(is_disable_value) {
        return false;
    }
    config.auto_fetch_on_run
}

/// Resolves and validates the configured auto-fetch remote. The value comes
/// from the committed `vault.toml` (attacker-controlled by anyone with write
/// access to the repo), so option-shaped values are rejected here even if a
/// tampered vault bypassed the `dl config set` validation (H1).
pub fn resolve_remote(config: &VaultConfig) -> DotLockResult<String> {
    let remote = config
        .auto_fetch_remote
        .as_deref()
        .unwrap_or(DEFAULT_REMOTE);
    validate_git_ref_component("auto_fetch_remote", remote)?;
    Ok(remote.to_string())
}

pub fn timeout_secs(config: &VaultConfig) -> u64 {
    config
        .auto_fetch_timeout_secs
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

fn is_disable_value(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn git_output<const N: usize>(args: [&str; N]) -> DotLockResult<Option<String>> {
    let output = match Command::new("git")
        .args(args)
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(DotLockError::Io(err.to_string())),
    };
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

fn run_git_with_timeout(args: &[&str], timeout: Duration) -> DotLockResult<bool> {
    let mut child = match Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(DotLockError::Io(err.to_string())),
    };

    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(DotLockError::from)? {
            return Ok(status.success());
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::VaultConfig,
        git::fetch::{auto_fetch_enabled, resolve_remote, timeout_secs},
    };

    #[test]
    fn auto_fetch_is_enabled_only_by_config_and_can_be_disabled_by_env() {
        let config = VaultConfig {
            auto_fetch_on_run: true,
            auto_fetch_timeout_secs: None,
            auto_fetch_remote: None,
            auto_ratchet_after_writes: None,
            dynamic_resolve_timeout_secs: None,
            rotate_max_age_days: None,
        };

        assert!(auto_fetch_enabled(&config, None));
        assert!(!auto_fetch_enabled(&config, Some("0")));
        assert!(!auto_fetch_enabled(&config, Some("false")));
        assert!(!auto_fetch_enabled(&VaultConfig::default(), None));
    }

    #[test]
    fn option_shaped_remote_is_neutralized_before_any_git_invocation() {
        let config = VaultConfig {
            auto_fetch_remote: Some("--upload-pack=/tmp/evil".to_string()),
            ..VaultConfig::default()
        };

        assert!(resolve_remote(&config).is_err());
        assert!(
            resolve_remote(&VaultConfig {
                auto_fetch_remote: Some("-r".to_string()),
                ..VaultConfig::default()
            })
            .is_err()
        );
        assert_eq!(
            resolve_remote(&VaultConfig::default()).expect("default remote"),
            "origin"
        );
    }

    #[test]
    fn timeout_defaults_to_three_seconds() {
        assert_eq!(timeout_secs(&VaultConfig::default()), 3);
        assert_eq!(
            timeout_secs(&VaultConfig {
                auto_fetch_timeout_secs: Some(1),
                ..VaultConfig::default()
            }),
            1
        );
    }
}
