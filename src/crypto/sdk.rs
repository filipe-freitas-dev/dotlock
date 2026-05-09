use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::domain::{error::DotLockError, model::DotLockResult};

const SDK_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SDK_AAD: &[u8] = b"dotlock:v3:sdk-wrap";

pub fn generate_sdk() -> DotLockResult<[u8; SDK_LEN]> {
    let mut sdk = [0u8; SDK_LEN];
    getrandom::fill(&mut sdk).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    Ok(sdk)
}

pub fn wrap_sdk_for_project_key(
    sdk: &[u8; SDK_LEN],
    project_key: &[u8; 32],
) -> DotLockResult<String> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|err| DotLockError::Crypto(err.to_string()))?;

    let cipher = XChaCha20Poly1305::new(project_key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: sdk,
                aad: SDK_AAD,
            },
        )
        .map_err(|_| DotLockError::Crypto("failed to wrap secret key".to_string()))?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(general_purpose::STANDARD.encode(output))
}

pub fn unwrap_sdk_with_project_key(
    wrapped_sdk_b64: &str,
    project_key: &[u8; 32],
) -> DotLockResult<[u8; SDK_LEN]> {
    let data = general_purpose::STANDARD
        .decode(wrapped_sdk_b64)
        .map_err(|err| {
            DotLockError::Crypto(format!("failed to decode wrapped secret key: {err}"))
        })?;
    if data.len() < NONCE_LEN {
        return Err(DotLockError::Crypto(
            "invalid wrapped secret key".to_string(),
        ));
    }

    let cipher = XChaCha20Poly1305::new(project_key.into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&data[..NONCE_LEN]),
            Payload {
                msg: &data[NONCE_LEN..],
                aad: SDK_AAD,
            },
        )
        .map_err(|_| DotLockError::Crypto("failed to unwrap secret key".to_string()))?;

    plaintext
        .try_into()
        .map_err(|_| DotLockError::Crypto("invalid secret key size".to_string()))
}
