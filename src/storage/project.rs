use std::path::Path;

use crate::domain::{error::DotLockError, model::DotLockResult};

pub const DOTLOCK_DIR: &str = ".lock";
pub const VAULT_FILE: &str = ".lock/vault.toml";
pub const SECRETS_FILE: &str = ".lock/secrets.lock";

pub fn is_project_initialized() -> bool {
    Path::new(VAULT_FILE).exists()
}

pub fn ensure_project_initialized() -> DotLockResult<()> {
    if !is_project_initialized() {
        return Err(DotLockError::ProjectNotInitialized);
    }
    Ok(())
}

pub fn ensure_project_not_initialized() -> DotLockResult<()> {
    if is_project_initialized() {
        return Err(DotLockError::ProjectAlreadyInitialized);
    }
    Ok(())
}
