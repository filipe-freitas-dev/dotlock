use std::path::Path;

use base64::{Engine, engine::general_purpose};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};

use crate::{
    crypto::VaultKeyMetadata,
    domain::{error::DotLockError, model::DotLockResult},
    storage::secure_fs,
};

const HASH_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const HASH_AAD: &[u8] = b"dotlock:v1:secrets-hash";

pub fn compute_file_sha256<P: AsRef<Path>>(path: P) -> DotLockResult<[u8; HASH_LEN]> {
    let path = path.as_ref();
    secure_fs::reject_symlink(path)?;

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(DotLockError::from(err)),
    };

    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub struct EncryptedHash {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_hash(hash: &[u8; HASH_LEN], dek: &[u8; 32]) -> DotLockResult<EncryptedHash> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| DotLockError::Crypto(e.to_string()))?;

    let cipher = XChaCha20Poly1305::new(dek.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: hash,
                aad: HASH_AAD,
            },
        )
        .map_err(|e| DotLockError::Crypto(e.to_string()))?;

    Ok(EncryptedHash { nonce, ciphertext })
}

pub fn decrypt_hash(
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    dek: &[u8; 32],
) -> DotLockResult<[u8; HASH_LEN]> {
    let cipher = XChaCha20Poly1305::new(dek.into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: HASH_AAD,
            },
        )
        .map_err(|_| DotLockError::TamperedSecretsFile)?;

    let hash: [u8; HASH_LEN] = plaintext
        .try_into()
        .map_err(|_| DotLockError::TamperedSecretsFile)?;
    Ok(hash)
}

pub fn verify_secrets_integrity<P: AsRef<Path>>(
    secrets_path: P,
    metadata: &VaultKeyMetadata,
    dek: &[u8; 32],
) -> DotLockResult<()> {
    if metadata.secrets_hash_b64.is_empty() || metadata.secrets_hash_nonce_b64.is_empty() {
        return Err(DotLockError::LegacyVaultFormat);
    }

    let nonce_bytes = general_purpose::STANDARD
        .decode(&metadata.secrets_hash_nonce_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let ciphertext = general_purpose::STANDARD
        .decode(&metadata.secrets_hash_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let stored = decrypt_hash(&nonce, &ciphertext, dek)?;
    let current = compute_file_sha256(secrets_path)?;

    if stored != current {
        return Err(DotLockError::TamperedSecretsFile);
    }
    Ok(())
}

pub fn verify_public_secrets_hash<P: AsRef<Path>>(
    secrets_path: P,
    metadata: &VaultKeyMetadata,
) -> DotLockResult<()> {
    if metadata.secrets_hash_sha256_b64.is_empty() {
        return Err(DotLockError::LegacyVaultFormat);
    }
    let stored = general_purpose::STANDARD
        .decode(&metadata.secrets_hash_sha256_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;
    let stored: [u8; HASH_LEN] = stored
        .try_into()
        .map_err(|_| DotLockError::LegacyVaultFormat)?;
    let current = compute_file_sha256(secrets_path)?;
    if stored != current {
        return Err(DotLockError::TamperedSecretsFile);
    }
    Ok(())
}

pub fn file_sha256_b64(secrets_path: impl AsRef<Path>) -> DotLockResult<String> {
    Ok(general_purpose::STANDARD.encode(compute_file_sha256(secrets_path)?))
}

pub fn compute_bytes_sha256(bytes: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

pub fn bytes_sha256_b64(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(compute_bytes_sha256(bytes))
}

/// Builds the encrypted integrity hash fields for in-memory `secrets.lock`
/// content, so mutators can finalize metadata before any file is written.
pub fn build_encrypted_hash_fields_from_bytes(
    bytes: &[u8],
    dek: &[u8; 32],
) -> DotLockResult<(String, String)> {
    let hash = compute_bytes_sha256(bytes);
    let encrypted = encrypt_hash(&hash, dek)?;
    Ok((
        general_purpose::STANDARD.encode(encrypted.nonce),
        general_purpose::STANDARD.encode(encrypted.ciphertext),
    ))
}

pub fn build_encrypted_hash_fields(
    secrets_path: impl AsRef<Path>,
    dek: &[u8; 32],
) -> DotLockResult<(String, String)> {
    let hash = compute_file_sha256(secrets_path)?;
    let encrypted = encrypt_hash(&hash, dek)?;
    Ok((
        general_purpose::STANDARD.encode(encrypted.nonce),
        general_purpose::STANDARD.encode(encrypted.ciphertext),
    ))
}
