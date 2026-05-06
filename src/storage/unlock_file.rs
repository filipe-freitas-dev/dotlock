use base64::{Engine, engine::general_purpose};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        dek::{WrappedDek, unwrap_dek},
        integrity::verify_secrets_integrity,
        kdf::{KdfParams, derive_master_key},
        kek::derive_kek,
        prompt_unlock_password,
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        cache::{invalidate_cache, read_cached_dek, write_cached_dek},
        project::SECRETS_FILE,
        vault_file::load_vault_metadata,
    },
};

pub fn unlock_vault(path: &str) -> DotLockResult<Zeroizing<[u8; 32]>> {
    let metadata = load_vault_metadata(path)?;

    if let Some(dek) = read_cached_dek() {
        match verify_secrets_integrity(SECRETS_FILE, &metadata, &dek) {
            Ok(()) => {
                write_cached_dek(&dek)?;
                return Ok(dek);
            }
            Err(DotLockError::TamperedSecretsFile) => {
                let _ = invalidate_cache();
                return Err(DotLockError::TamperedSecretsFile);
            }
            Err(_) => {
                let _ = invalidate_cache();
            }
        }
    }

    let passphrase = prompt_unlock_password()?;

    let salt = general_purpose::STANDARD
        .decode(&metadata.salt_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let params = KdfParams {
        memory_kib: metadata.memory_kib,
        iterations: metadata.iterations,
        parallelism: metadata.parallelism,
    };

    let mut master_key = derive_master_key(&passphrase, &salt, params)
        .map_err(|e| DotLockError::Crypto(e.to_string()))?;

    let mut kek = derive_kek(
        &master_key,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )
    .map_err(|e| DotLockError::Crypto(e.to_string()))?;

    master_key.zeroize();

    let nonce = general_purpose::STANDARD
        .decode(&metadata.wrapped_dek_nonce_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let wrapped_dek = general_purpose::STANDARD
        .decode(&metadata.wrapped_dek_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let wrapped = WrappedDek {
        nonce,
        ciphertext: wrapped_dek,
    };

    let dek = unwrap_dek(&kek, &wrapped, &metadata.project, &metadata.environment)
        .map_err(|_| DotLockError::InvalidMasterPassword)?;

    kek.zeroize();

    verify_secrets_integrity(SECRETS_FILE, &metadata, &dek)?;

    write_cached_dek(&dek)?;

    Ok(Zeroizing::new(dek))
}
