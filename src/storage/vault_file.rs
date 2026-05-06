use std::path::Path;

use crate::{
    crypto::VaultKeyMetadata,
    domain::{error::DotLockError, model::DotLockResult},
    storage::secure_fs,
};

pub fn save_vault_metadata<P: AsRef<Path>>(
    path: P,
    metadata: &VaultKeyMetadata,
) -> DotLockResult<()> {
    let path = path.as_ref();

    let content =
        toml::to_string_pretty(metadata).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(path, &content, 0o700, 0o600)
}

pub fn load_vault_metadata<P: AsRef<Path>>(path: P) -> DotLockResult<VaultKeyMetadata> {
    let content = secure_fs::read_to_string(path.as_ref())?;
    let metadata =
        toml::from_str::<VaultKeyMetadata>(&content).map_err(|_| DotLockError::LegacyVaultFormat)?;

    Ok(metadata)
}
