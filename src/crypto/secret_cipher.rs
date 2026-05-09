use base64::{Engine, engine::general_purpose};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use crate::domain::{
    error::DotLockError,
    model::{Alg, DataEncrypted, DotLockResult},
};

pub fn encryption_process<'a>(
    name: String,
    value: String,
    alg: Alg,
    dek: &[u8; 32],
) -> DotLockResult<DataEncrypted<'a>> {
    match alg {
        Alg::XChaCha20Poly1305 => {
            let encrypted = encrypt_xchacha20poly1305(value, dek)?;
            Ok(DataEncrypted {
                alg: "xchacha20-poly1305",
                name,
                data: encrypted.into_bytes(),
            })
        }
    }
}

fn encrypt_xchacha20poly1305(plaintext: String, key: &[u8; 32]) -> DotLockResult<String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|err| DotLockError::Crypto(err.to_string()))?;

    let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(output))
}

pub fn decryption_process(
    encrypted_data: String,
    alg: Alg,
    dek: &[u8; 32],
) -> DotLockResult<String> {
    match alg {
        Alg::XChaCha20Poly1305 => decrypt_xchacha20poly1305(encrypted_data, dek),
    }
}

fn decrypt_xchacha20poly1305(encrypted_data: String, key: &[u8; 32]) -> DotLockResult<String> {
    let data = general_purpose::STANDARD
        .decode(encrypted_data)
        .map_err(|err| DotLockError::Crypto(err.to_string()))?;

    if data.len() < 24 {
        return Err(DotLockError::Crypto("invalid encrypted data".to_string()));
    }

    let nonce = &data[..24];
    let ciphertext = &data[24..];

    let cipher = XChaCha20Poly1305::new(key.into());

    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|err| DotLockError::Crypto(err.to_string()))?;

    String::from_utf8(plaintext).map_err(|err| DotLockError::Crypto(err.to_string()))
}
