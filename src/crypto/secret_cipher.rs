use base64::{Engine, engine::general_purpose};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use zeroize::Zeroizing;

use crate::domain::{
    error::DotLockError,
    keys::SecretKey,
    model::{Alg, DataEncrypted, DotLockResult},
};

/// Encrypts a secret value, binding `aad` (the record's identity/ordering
/// metadata, see `secret_record_aad`) into the AEAD tag. An empty `aad` is
/// bit-compatible with the legacy pre-AAD format. The plaintext is borrowed
/// (L1) so callers keep it in their own `Zeroizing` buffer — no unzeroized
/// copy is made here.
pub fn encryption_process_with_aad<'a>(
    name: String,
    value: &str,
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
    plaintext: &str,
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
/// bit-compatible with the pre-AAD format). The plaintext comes back in a
/// `Zeroizing` buffer (L1) so decrypted secret values never linger in freed
/// heap after use.
pub fn decryption_process(
    encrypted_data: &str,
    alg: Alg,
    key: &SecretKey,
) -> DotLockResult<Zeroizing<String>> {
    decryption_process_with_aad(encrypted_data, alg, key, &[])
}

pub fn decryption_process_with_aad(
    encrypted_data: &str,
    alg: Alg,
    key: &SecretKey,
    aad: &[u8],
) -> DotLockResult<Zeroizing<String>> {
    match alg {
        Alg::XChaCha20Poly1305 => decrypt_xchacha20poly1305(encrypted_data, key, aad),
    }
}

fn decrypt_xchacha20poly1305(
    encrypted_data: &str,
    key: &SecretKey,
    aad: &[u8],
) -> DotLockResult<Zeroizing<String>> {
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

    // `from_utf8` moves the buffer (no copy); the error path zeroizes the
    // rejected bytes and reports only the generic utf-8 failure, never the
    // decrypted content itself.
    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|err| {
            let mut bytes = err.into_bytes();
            zeroize::Zeroize::zeroize(&mut bytes);
            DotLockError::Crypto("decrypted secret is not valid utf-8".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::{decryption_process, decryption_process_with_aad, encryption_process_with_aad};
    use crate::domain::{keys::SecretKey, model::Alg};

    /// L1: decrypted plaintext comes back in a `Zeroizing` buffer (wiped on
    /// drop) and stays fully usable before then.
    #[test]
    fn decrypted_plaintext_is_returned_in_a_zeroizing_buffer() {
        let key = SecretKey::new([7u8; 32]);
        let encrypted =
            encryption_process_with_aad("FOO".to_string(), "s3cret", Alg::XChaCha20Poly1305, &key, &[])
                .expect("encrypt");
        let data = String::from_utf8(encrypted.data).expect("utf8");

        let plaintext: zeroize::Zeroizing<String> =
            decryption_process(&data, Alg::XChaCha20Poly1305, &key).expect("decrypt");
        assert_eq!(plaintext.as_str(), "s3cret");
    }

    /// L1/L3: a decrypt that yields non-utf8 bytes reports a generic error —
    /// the rejected (decrypted) bytes never appear in the message.
    #[test]
    fn non_utf8_plaintext_error_does_not_echo_decrypted_bytes() {
        let key = SecretKey::new([7u8; 32]);
        // Encrypt raw non-utf8 bytes by driving the cipher directly.
        use chacha20poly1305::{
            XChaCha20Poly1305,
            aead::{Aead, AeadCore, KeyInit, OsRng},
        };
        use base64::{Engine, engine::general_purpose};
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, &[0xff, 0xfe, 0x80][..]).expect("encrypt");
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        let data = general_purpose::STANDARD.encode(blob);

        let err = decryption_process(&data, Alg::XChaCha20Poly1305, &key)
            .expect_err("non-utf8 must fail");
        assert_eq!(
            err.to_string(),
            "crypto failure: decrypted secret is not valid utf-8"
        );
    }

    #[test]
    fn aad_binds_ciphertext_to_its_metadata() {
        let key = SecretKey::new([5u8; 32]);
        let encrypted = encryption_process_with_aad(
            "FOO".to_string(),
            "value",
            Alg::XChaCha20Poly1305,
            &key,
            b"aad-v1",
        )
        .expect("encrypt");
        let data = String::from_utf8(encrypted.data).expect("utf8");

        // Correct AAD decrypts...
        assert_eq!(
            decryption_process_with_aad(&data, Alg::XChaCha20Poly1305, &key, b"aad-v1")
                .expect("decrypt")
                .as_str(),
            "value"
        );
        // ...any other AAD (including none) fails authentication.
        assert!(
            decryption_process_with_aad(&data, Alg::XChaCha20Poly1305, &key, b"forged").is_err()
        );
        assert!(decryption_process_with_aad(&data, Alg::XChaCha20Poly1305, &key, &[]).is_err());
    }
}
