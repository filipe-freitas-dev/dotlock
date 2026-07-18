use std::path::PathBuf;

use crate::domain::{error::DotLockError, model::DotLockResult};

const APP_DIR: &str = ".lock";

/// Root directory for per-user DotLock state (identities, key caches, audit
/// logs). Resolution order: `DOTLOCK_HOME`, then the platform home/config
/// directory (`HOME` on Unix, `LOCALAPPDATA` on Windows).
///
/// This NEVER falls back to the current working directory: private keys and
/// cached project keys must not land in a committable `./.lock`. When no
/// directory resolves (cron, containers, systemd units without a login
/// environment) callers get [`DotLockError::HomeDirUnavailable`] instead.
pub fn dotlock_data_root() -> DotLockResult<PathBuf> {
    resolve_data_root(
        non_empty_env("DOTLOCK_HOME"),
        non_empty_env(platform_home_var()),
    )
}

const fn platform_home_var() -> &'static str {
    #[cfg(not(windows))]
    {
        "HOME"
    }
    #[cfg(windows)]
    {
        "LOCALAPPDATA"
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn resolve_data_root(
    dotlock_home: Option<String>,
    platform_home: Option<String>,
) -> DotLockResult<PathBuf> {
    if let Some(dir) = dotlock_home {
        return Ok(PathBuf::from(dir));
    }
    if let Some(home) = platform_home {
        #[cfg(not(windows))]
        {
            return Ok(PathBuf::from(home).join(APP_DIR));
        }
        #[cfg(windows)]
        {
            return Ok(PathBuf::from(home).join("dotlock"));
        }
    }
    Err(DotLockError::HomeDirUnavailable)
}

#[cfg(test)]
mod tests {
    use super::resolve_data_root;
    use crate::domain::error::DotLockError;
    use std::path::Path;

    #[test]
    fn resolution_fails_hard_without_home_instead_of_using_cwd() {
        let result = resolve_data_root(None, None);
        assert!(matches!(result, Err(DotLockError::HomeDirUnavailable)));
    }

    #[test]
    fn dotlock_home_wins_over_platform_home() {
        let root = resolve_data_root(
            Some("/custom/dotlock".to_string()),
            Some("/home/user".to_string()),
        )
        .expect("resolve");
        assert_eq!(root, Path::new("/custom/dotlock"));
    }

    #[cfg(not(windows))]
    #[test]
    fn platform_home_appends_app_dir() {
        let root = resolve_data_root(None, Some("/home/user".to_string())).expect("resolve");
        assert_eq!(root, Path::new("/home/user/.lock"));
    }
}
