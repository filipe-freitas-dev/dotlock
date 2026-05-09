use base64::{Engine as _, engine::general_purpose};
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    pss::{BlindedSigningKey, Signature as RsaPssSignature, VerifyingKey},
    rand_core::OsRng,
    sha2::{Digest, Sha256},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
};

use crate::domain::{error::DotLockError, model::DotLockResult};

pub const RECIPIENT_ALG: &str = "rsa-oaep-sha256";

pub struct GeneratedIdentity {
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProtection<'a> {
    Encrypted(&'a str),
    Plain,
}

fn parse_private_key(private_key_pem: &str) -> DotLockResult<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| DotLockError::Crypto(format!("failed to parse private key: {e}")))
}

fn parse_public_key(public_key_pem: &str) -> DotLockResult<RsaPublicKey> {
    RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| DotLockError::Crypto(format!("failed to parse public key: {e}")))
}

pub fn generate_identity(protection: IdentityProtection<'_>) -> DotLockResult<GeneratedIdentity> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 3072)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate identity key: {e}")))?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = match protection {
        IdentityProtection::Encrypted(passphrase) => private_key
            .to_pkcs8_encrypted_pem(&mut rng, passphrase, LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))?
            .to_string(),
        IdentityProtection::Plain => private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))?
            .to_string(),
    };
    let public_key_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}")))?;
    let fingerprint = fingerprint_public_key(&public_key_pem)?;

    Ok(GeneratedIdentity {
        private_key_pem,
        public_key_pem,
        fingerprint,
    })
}

pub fn decrypt_private_key_pem(
    encrypted_private_key_pem: &str,
    passphrase: &str,
) -> DotLockResult<String> {
    let private_key =
        RsaPrivateKey::from_pkcs8_encrypted_pem(encrypted_private_key_pem, passphrase)
            .map_err(|_| DotLockError::InvalidIdentityPassphrase)?;
    private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))
        .map(|pem| pem.to_string())
}

pub fn fingerprint_public_key(public_key_pem: &str) -> DotLockResult<String> {
    let public_key = parse_public_key(public_key_pem)?;
    let der = public_key
        .to_public_key_der()
        .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}")))?;
    let digest = Sha256::digest(der.as_ref());
    Ok(hex_lower(&digest[..16]))
}

pub fn encode_public_key_b64(public_key_pem: &str) -> DotLockResult<String> {
    let public_key = parse_public_key(public_key_pem)?;
    let der = public_key
        .to_public_key_der()
        .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}")))?;
    Ok(general_purpose::STANDARD.encode(der.as_ref()))
}

pub fn decode_public_key_b64(public_key_b64: &str) -> DotLockResult<RsaPublicKey> {
    let der = general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| DotLockError::Crypto(format!("failed to decode public key: {e}")))?;
    RsaPublicKey::from_public_key_der(&der)
        .map_err(|e| DotLockError::Crypto(format!("failed to parse public key: {e}")))
}

pub fn wrap_dek_for_public_key(dek: &[u8; 32], public_key_pem: &str) -> DotLockResult<String> {
    let mut rng = OsRng;
    let public_key = parse_public_key(public_key_pem)?;
    let encrypted = public_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), dek)
        .map_err(|e| DotLockError::Crypto(format!("failed to wrap project key: {e}")))?;
    Ok(general_purpose::STANDARD.encode(encrypted))
}

pub fn wrap_dek_for_public_key_b64(dek: &[u8; 32], public_key_b64: &str) -> DotLockResult<String> {
    let public_key = decode_public_key_b64(public_key_b64)?;
    let pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}")))?;
    wrap_dek_for_public_key(dek, &pem)
}

pub fn unwrap_dek_with_private_key(
    wrapped_dek_b64: &str,
    private_key_pem: &str,
) -> DotLockResult<[u8; 32]> {
    let private_key = parse_private_key(private_key_pem)?;
    let wrapped = general_purpose::STANDARD
        .decode(wrapped_dek_b64)
        .map_err(|e| DotLockError::Crypto(format!("failed to decode wrapped project key: {e}")))?;
    let decrypted = private_key
        .decrypt(Oaep::new::<Sha256>(), &wrapped)
        .map_err(|e| DotLockError::Crypto(format!("failed to unwrap project key: {e}")))?;

    decrypted
        .try_into()
        .map_err(|_| DotLockError::Crypto("invalid project key size".to_string()))
}

pub fn sign_audit_entry_hash(entry_hash: &str, private_key_pem: &str) -> DotLockResult<String> {
    let private_key = parse_private_key(private_key_pem)?;
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    let mut rng = OsRng;
    let signature = signing_key.sign_with_rng(&mut rng, entry_hash.as_bytes());
    Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
}

pub fn verify_audit_entry_hash_signature(
    entry_hash: &str,
    signature_b64: &str,
    public_key_pem: &str,
) -> DotLockResult<()> {
    let public_key = parse_public_key(public_key_pem)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature = general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| DotLockError::Crypto(format!("failed to decode audit signature: {e}")))?;
    let signature = RsaPssSignature::try_from(signature.as_slice())
        .map_err(|e| DotLockError::Crypto(format!("failed to parse audit signature: {e}")))?;
    verifying_key
        .verify(entry_hash.as_bytes(), &signature)
        .map_err(|_| DotLockError::Crypto("audit signature invalid".to_string()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        IdentityProtection, RECIPIENT_ALG, decrypt_private_key_pem, encode_public_key_b64,
        generate_identity, sign_audit_entry_hash, unwrap_dek_with_private_key,
        verify_audit_entry_hash_signature, wrap_dek_for_public_key, wrap_dek_for_public_key_b64,
    };

    #[test]
    fn generated_identity_wraps_and_unwraps_project_key() {
        let identity =
            generate_identity(IdentityProtection::Encrypted("hunter2")).expect("identity");
        let dek = [7u8; 32];
        let private_key_pem =
            decrypt_private_key_pem(&identity.private_key_pem, "hunter2").expect("decrypt pem");

        let wrapped = wrap_dek_for_public_key(&dek, &identity.public_key_pem).expect("wrap");
        let unwrapped = unwrap_dek_with_private_key(&wrapped, &private_key_pem).expect("unwrap");

        assert_eq!(RECIPIENT_ALG, "rsa-oaep-sha256");
        assert_eq!(unwrapped, dek);
        assert!(identity.private_key_pem.contains("ENCRYPTED PRIVATE KEY"));
    }

    #[test]
    fn public_key_b64_roundtrip_wraps_project_key() {
        let identity =
            generate_identity(IdentityProtection::Encrypted("hunter2")).expect("identity");
        let dek = [9u8; 32];
        let public_key_b64 = encode_public_key_b64(&identity.public_key_pem).expect("encode");
        let private_key_pem =
            decrypt_private_key_pem(&identity.private_key_pem, "hunter2").expect("decrypt pem");

        let wrapped = wrap_dek_for_public_key_b64(&dek, &public_key_b64).expect("wrap");
        let unwrapped = unwrap_dek_with_private_key(&wrapped, &private_key_pem).expect("unwrap");

        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn plain_identity_generates_unencrypted_private_key() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");

        assert!(identity.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!identity.private_key_pem.contains("ENCRYPTED PRIVATE KEY"));
    }

    #[test]
    fn audit_signature_roundtrip() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");
        let signature =
            sign_audit_entry_hash("sha256:test", &identity.private_key_pem).expect("sign");

        verify_audit_entry_hash_signature("sha256:test", &signature, &identity.public_key_pem)
            .expect("verify");
    }
}
