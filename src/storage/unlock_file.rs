use base64::{Engine, engine::general_purpose};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        AccessMode,
        dek::{WrappedDek, unwrap_dek},
        integrity::verify_secrets_integrity,
        kdf::{KdfParams, derive_master_key},
        kek::derive_kek,
        prompt_unlock_password,
        share::unwrap_dek_with_private_key,
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        cache::{invalidate_cache, read_cached_dek, write_cached_dek},
        identity::load_local_identity,
        project::SECRETS_FILE,
        vault_file::load_vault_metadata,
    },
};

fn unwrap_dek_with_passphrase(
    metadata: &crate::crypto::VaultKeyMetadata,
    passphrase: &str,
) -> DotLockResult<[u8; 32]> {
    let salt = general_purpose::STANDARD
        .decode(&metadata.salt_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let params = KdfParams {
        memory_kib: metadata.memory_kib,
        iterations: metadata.iterations,
        parallelism: metadata.parallelism,
    };

    let mut master_key = derive_master_key(passphrase, &salt, params)
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
    Ok(dek)
}

fn unlock_vault_with_dek(
    metadata: &crate::crypto::VaultKeyMetadata,
    dek: [u8; 32],
) -> DotLockResult<Zeroizing<[u8; 32]>> {
    verify_secrets_integrity(SECRETS_FILE, metadata, &dek)?;
    write_cached_dek(&dek)?;
    Ok(Zeroizing::new(dek))
}

pub fn unlock_vault_with_master_password(path: &str) -> DotLockResult<Zeroizing<[u8; 32]>> {
    let metadata = load_vault_metadata(path)?;
    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(&metadata, &passphrase)?;
    unlock_vault_with_dek(&metadata, dek)
}

pub fn unlock_vault_with_master_password_and_passphrase(
    path: &str,
) -> DotLockResult<(Zeroizing<[u8; 32]>, String)> {
    let metadata = load_vault_metadata(path)?;
    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(&metadata, &passphrase)?;
    let dek = unlock_vault_with_dek(&metadata, dek)?;
    Ok((dek, passphrase))
}

fn try_unlock_vault_with_local_identity(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<Zeroizing<[u8; 32]>> {
    let identity = load_local_identity()?;
    let recipient = metadata
        .recipients
        .iter()
        .find(|recipient| recipient.public_key_fingerprint == identity.fingerprint)
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: identity.fingerprint.clone(),
        })?;
    let dek = unwrap_dek_with_private_key(&recipient.wrapped_dek_b64, &identity.private_key_pem)?;
    unlock_vault_with_dek(metadata, dek)
}

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

    if metadata.access_mode == AccessMode::Shared {
        match try_unlock_vault_with_local_identity(&metadata) {
            Ok(dek) => return Ok(dek),
            Err(DotLockError::TamperedSecretsFile) => {
                return Err(DotLockError::TamperedSecretsFile);
            }
            Err(_) => {}
        }
    }

    unlock_vault_with_master_password(path)
}
