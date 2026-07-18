use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::domain::{error::DotLockError, model::DotLockResult};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub struct WrappedDek {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn generate_dek() -> DotLockResult<[u8; KEY_LEN]> {
    let mut dek = [0u8; KEY_LEN];

    getrandom::fill(&mut dek)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate DEK: {e}")))?;

    Ok(dek)
}

pub fn wrap_dek(
    kek: &[u8; KEY_LEN],
    dek: &[u8; KEY_LEN],
    project: &str,
    environment: &str,
) -> DotLockResult<WrappedDek> {
    let mut nonce = [0u8; NONCE_LEN];

    getrandom::fill(&mut nonce)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate nonce: {e}")))?;

    let aad = format!("dotlock:v1:wrapped-dek:project={project}:env={environment}");

    let cipher = XChaCha20Poly1305::new(kek.into());

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: dek,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| DotLockError::Crypto("failed to wrap DEK".to_string()))?;

    Ok(WrappedDek { nonce, ciphertext })
}

pub fn unwrap_dek(
    kek: &[u8; KEY_LEN],
    wrapped: &WrappedDek,
    project: &str,
    environment: &str,
) -> DotLockResult<[u8; KEY_LEN]> {
    let aad = format!("dotlock:v1:wrapped-dek:project={project}:env={environment}");

    let cipher = XChaCha20Poly1305::new(kek.into());

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            Payload {
                msg: wrapped.ciphertext.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| DotLockError::Crypto("failed to unwrap DEK".to_string()))?;

    let dek: [u8; KEY_LEN] = plaintext
        .try_into()
        .map_err(|_| DotLockError::Crypto("invalid DEK length".to_string()))?;

    Ok(dek)
}
