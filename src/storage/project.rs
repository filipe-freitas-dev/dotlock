//! Project layout and environment-aware path resolution (FG3).
//!
//! A project holds one vault pair per environment. The DEFAULT environment is
//! the pre-FG3 layout — `.lock/vault.toml` + `.lock/secrets.lock` — so every
//! existing project keeps working with zero file moves. Additional
//! environments live under `.lock/envs/<name>/` with the same pair layout,
//! each cryptographically independent (own Argon2id salt, own KEK derivation
//! via the MAC-covered `environment` metadata field, own DEK).
//!
//! Selection precedence: `--env <name>` (CLI, recorded once in `main`) >
//! `DOTLOCK_ENV` > the persisted default in `.lock/env` (plain, NON-secret) >
//! the default environment. The literal name `default` always means the
//! legacy pair, so `--env default` can override a persisted selection.

use std::{path::PathBuf, sync::OnceLock};

use crate::domain::{error::DotLockError, model::DotLockResult};

pub const DOTLOCK_DIR: &str = ".lock";
/// Directory holding the non-default environments' vault pairs.
pub const ENVS_DIR: &str = ".lock/envs";
/// Reserved name for the legacy single-environment pair in `.lock/`.
pub const DEFAULT_ENV_NAME: &str = "default";
/// Plain-text, NON-secret project-local file holding the persisted default
/// environment selection (`dl env use`). It only contains an environment
/// name — never key material — and is validated on every read.
pub const ENV_SELECTION_FILE: &str = ".lock/env";

const DEFAULT_VAULT_FILE: &str = ".lock/vault.toml";
const DEFAULT_SECRETS_FILE: &str = ".lock/secrets.lock";

/// Environment resolved once in `main` from `--env`/`DOTLOCK_ENV`/`.lock/env`
/// (`None` = default environment). Unset in lib tests, where the lazy
/// fallback below resolves per call so path helpers still honor the sources.
static SELECTED_ENV: OnceLock<Option<String>> = OnceLock::new();

/// Resolves and validates the environment selection exactly once, from the
/// CLI flag, `DOTLOCK_ENV`, or the persisted `.lock/env` file (in that
/// order). Called from `main` before any command runs so an invalid name
/// fails fast instead of silently routing to wrong paths.
pub fn init_env_selection(cli_env: Option<String>) -> DotLockResult<()> {
    let resolved = resolve_env_selection(cli_env)?;
    let _ = SELECTED_ENV.set(resolved);
    Ok(())
}

fn resolve_env_selection(cli_env: Option<String>) -> DotLockResult<Option<String>> {
    // An explicit source (flag or env var) always wins over the persisted
    // default, including the literal `default` used to force the legacy pair.
    let explicit = cli_env.or_else(|| {
        std::env::var("DOTLOCK_ENV")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    if let Some(name) = explicit {
        validate_env_name(&name)?;
        return Ok(normalize_default(name));
    }
    match persisted_default_env() {
        Some(name) => {
            validate_env_name(&name)?;
            Ok(normalize_default(name))
        }
        None => Ok(None),
    }
}

fn normalize_default(name: String) -> Option<String> {
    (name != DEFAULT_ENV_NAME).then_some(name)
}

/// The environment every command operates on. `None` = default environment
/// (the legacy `.lock/` pair).
pub fn active_env() -> Option<String> {
    if let Some(selected) = SELECTED_ENV.get() {
        return selected.clone();
    }
    // Lib-test / library path: `main` never ran, resolve lazily and ignore
    // invalid names (path helpers are infallible; `main` is where invalid
    // selections become hard errors).
    resolve_env_selection(None).ok().flatten()
}

/// Human-facing name of the active environment.
pub fn active_env_name() -> String {
    active_env().unwrap_or_else(|| DEFAULT_ENV_NAME.to_string())
}

/// Environment names are path components: short, ASCII alphanumeric plus
/// `-`/`_`, so a selection can never traverse outside `.lock/envs/`.
pub fn validate_env_name(name: &str) -> DotLockResult<()> {
    let valid = !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && name.starts_with(|c: char| c.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        Err(DotLockError::InvalidEnvironmentName {
            name: name.to_string(),
        })
    }
}

/// Vault/secrets/marker paths for a given environment (`None` = default).
pub fn env_lock_dir_for(env: Option<&str>) -> String {
    match env {
        Some(name) => format!("{ENVS_DIR}/{name}"),
        None => DOTLOCK_DIR.to_string(),
    }
}

pub fn vault_file_for(env: Option<&str>) -> String {
    match env {
        Some(name) => format!("{ENVS_DIR}/{name}/vault.toml"),
        None => DEFAULT_VAULT_FILE.to_string(),
    }
}

pub fn secrets_file_for(env: Option<&str>) -> String {
    match env {
        Some(name) => format!("{ENVS_DIR}/{name}/secrets.lock"),
        None => DEFAULT_SECRETS_FILE.to_string(),
    }
}

/// `vault.toml` path of the ACTIVE environment.
pub fn vault_file() -> String {
    vault_file_for(active_env().as_deref())
}

/// `secrets.lock` path of the ACTIVE environment.
pub fn secrets_file() -> String {
    secrets_file_for(active_env().as_deref())
}

/// Directory holding the active environment's vault pair (and its
/// pending-merge marker / transaction journal).
pub fn env_lock_dir() -> String {
    env_lock_dir_for(active_env().as_deref())
}

/// Environments present on disk: `default` first (when the legacy pair
/// exists), then the `.lock/envs/*` entries that contain a `vault.toml`.
pub fn list_environments() -> Vec<String> {
    let mut envs = Vec::new();
    if PathBuf::from(DEFAULT_VAULT_FILE).exists() {
        envs.push(DEFAULT_ENV_NAME.to_string());
    }
    let mut named: Vec<String> = std::fs::read_dir(ENVS_DIR)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| validate_env_name(name).is_ok())
                .filter(|name| PathBuf::from(vault_file_for(Some(name))).exists())
                .collect()
        })
        .unwrap_or_default();
    named.sort();
    envs.extend(named);
    envs
}

/// The persisted default selection from `.lock/env`, if any (raw name;
/// callers validate).
pub fn persisted_default_env() -> Option<String> {
    let content = std::fs::read_to_string(ENV_SELECTION_FILE).ok()?;
    let name = content.trim().to_string();
    (!name.is_empty()).then_some(name)
}

pub fn is_project_initialized() -> bool {
    PathBuf::from(vault_file()).exists()
}

pub fn ensure_project_initialized() -> DotLockResult<()> {
    if is_project_initialized() {
        return Ok(());
    }
    // Distinguish "no project at all" from "project exists but this
    // environment was never created" for an actionable error.
    if let Some(env) = active_env()
        && PathBuf::from(DEFAULT_VAULT_FILE).exists()
    {
        return Err(DotLockError::EnvironmentNotInitialized { name: env });
    }
    Err(DotLockError::ProjectNotInitialized)
}

pub fn ensure_project_not_initialized() -> DotLockResult<()> {
    if is_project_initialized() {
        return Err(DotLockError::ProjectAlreadyInitialized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_names_are_validated_as_safe_path_components() {
        for good in ["dev", "staging", "prod-eu", "qa_2", "a", "default"] {
            assert!(validate_env_name(good).is_ok(), "{good} must be valid");
        }
        for bad in [
            "",
            "../etc",
            "a/b",
            ".hidden",
            "-lead",
            "_lead",
            "name with space",
            "über",
            "x".repeat(33).as_str(),
        ] {
            assert!(
                matches!(
                    validate_env_name(bad),
                    Err(DotLockError::InvalidEnvironmentName { .. })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn default_env_keeps_the_legacy_paths_and_named_envs_are_scoped() {
        assert_eq!(vault_file_for(None), ".lock/vault.toml");
        assert_eq!(secrets_file_for(None), ".lock/secrets.lock");
        assert_eq!(env_lock_dir_for(None), ".lock");
        assert_eq!(
            vault_file_for(Some("staging")),
            ".lock/envs/staging/vault.toml"
        );
        assert_eq!(
            secrets_file_for(Some("staging")),
            ".lock/envs/staging/secrets.lock"
        );
        assert_eq!(env_lock_dir_for(Some("staging")), ".lock/envs/staging");
    }

    #[test]
    fn explicit_default_name_resolves_to_the_legacy_environment() {
        // `--env default` / `DOTLOCK_ENV=default` must force the legacy pair
        // even when `.lock/env` persists another selection.
        assert_eq!(
            resolve_env_selection(Some("default".to_string())).expect("resolve"),
            None
        );
        assert_eq!(
            resolve_env_selection(Some("staging".to_string())).expect("resolve"),
            Some("staging".to_string())
        );
        assert!(matches!(
            resolve_env_selection(Some("../evil".to_string())),
            Err(DotLockError::InvalidEnvironmentName { .. })
        ));
    }
}
