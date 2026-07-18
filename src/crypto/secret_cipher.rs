use base64::{Engine, engine::general_purpose};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};

use crate::domain::{
    error::DotLockError,
    keys::SecretKey,
    model::{Alg, DataEncrypted, DotLockResult},
};

/// Encrypts a secret value, binding `aad` (the record's identity/ordering
/// metadata, see `secret_record_aad`) into the AEAD tag. An empty `aad` is
/// bit-compatible with the legacy pre-AAD format.
pub fn encryption_process_with_aad<'a>(
    name: String,
    value: String,
    alg: Alg,
    key: &SecretKey,
    aad: &[u8],
) -> DotLockResult<DataEncrypted<'a>> {
    match alg {
        Alg::XChaCha20Poly1305 => {
            let encrypted = encrypt_xchacha20poly1305(value, key, aad)?;
            Ok(DataEncrypted {
                alg: "xchacha20-poly1305",
                name,
                data: encrypted.into_bytes(),
            })
        }
    }
}

fn encrypt_xchacha20poly1305(
    plaintext: String,
    key: &SecretKey,
    aad: &[u8],
) -> DotLockResult<String> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|err| DotLockError::Crypto(err.to_string()))?;

    let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(output))
}

/// Legacy entry point: decrypts with no associated data (empty AAD is
/// bit-compatible with the pre-AAD format).
pub fn decryption_process(
    encrypted_data: String,
    alg: Alg,
    key: &SecretKey,
) -> DotLockResult<String> {
    decryption_process_with_aad(encrypted_data, alg, key, &[])
}

pub fn decryption_process_with_aad(
    encrypted_data: String,
    alg: Alg,
    key: &SecretKey,
    aad: &[u8],
) -> DotLockResult<String> {
    match alg {
        Alg::XChaCha20Poly1305 => decrypt_xchacha20poly1305(encrypted_data, key, aad),
    }
}

fn decrypt_xchacha20poly1305(
    encrypted_data: String,
    key: &SecretKey,
    aad: &[u8],
) -> DotLockResult<String> {
    let data = general_purpose::STANDARD
        .decode(encrypted_data)
        .map_err(|err| DotLockError::Crypto(err.to_string()))?;

    if data.len() < 24 {
        return Err(DotLockError::Crypto("invalid encrypted data".to_string()));
    }

    let nonce = &data[..24];
    let ciphertext = &data[24..];

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let plaintext = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|err| DotLockError::Crypto(err.to_string()))?;

    String::from_utf8(plaintext).map_err(|err| DotLockError::Crypto(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{decryption_process_with_aad, encryption_process_with_aad};
    use crate::domain::{keys::SecretKey, model::Alg};

    #[test]
    fn aad_binds_ciphertext_to_its_metadata() {
        let key = SecretKey::new([5u8; 32]);
        let encrypted = encryption_process_with_aad(
            "FOO".to_string(),
            "value".to_string(),
            Alg::XChaCha20Poly1305,
            &key,
            b"aad-v1",
        )
        .expect("encrypt");
        let data = String::from_utf8(encrypted.data).expect("utf8");

        // Correct AAD decrypts...
        assert_eq!(
            decryption_process_with_aad(data.clone(), Alg::XChaCha20Poly1305, &key, b"aad-v1")
                .expect("decrypt"),
            "value"
        );
        // ...any other AAD (including none) fails authentication.
        assert!(
            decryption_process_with_aad(data.clone(), Alg::XChaCha20Poly1305, &key, b"forged")
                .is_err()
        );
        assert!(decryption_process_with_aad(data, Alg::XChaCha20Poly1305, &key, &[]).is_err());
    }
}
