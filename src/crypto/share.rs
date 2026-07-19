//! Identity crypto for shared vaults: key wrapping (project DEK / per-secret
//! SDKs to a recipient) and signatures (recipient grants, audit entries).
//!
//! Two algorithm families coexist (ADR 0001):
//! - **Modern (default):** Ed25519 identities. Signatures are Ed25519; key
//!   wrapping is an X25519 sealed box (libsodium-compatible `crypto_box`
//!   seal: ephemeral X25519 + XSalsa20-Poly1305), with the recipient's X25519
//!   key derived from their Ed25519 key via the standard birational map — the
//!   same construction libsodium (`crypto_sign_ed25519_*_to_curve25519`) and
//!   age's ssh-ed25519 recipients use, proven jointly secure in
//!   <https://eprint.iacr.org/2021/509>.
//! - **Legacy (read/interop only):** RSA-3072 identities (OAEP-SHA256
//!   wrapping, RSA-PSS signatures). New identities are never RSA; the RSA
//!   private-key decryption path (RUSTSEC-2023-0071 "Marvin") survives only
//!   to unlock not-yet-migrated vaults and to run `dl cert migrate`.
//!
//! Every public function here dispatches on the key material itself (PKCS#8 /
//! SPKI algorithm OID), so mixed vaults — some recipients RSA, some Ed25519 —
//! resolve the right primitive per recipient with no extra bookkeeping.

use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
    pkcs8::{
        DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
    },
};
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{BlindedSigningKey, Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey},
    rand_core::OsRng as LegacyOsRng,
    sha2::{Digest, Sha256},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
};

use crate::domain::{error::DotLockError, model::DotLockResult};

/// Legacy recipient-wrapping algorithm tag (RSA-OAEP). Still readable and
/// still valid as a wrap TARGET (encryption is a public-key operation and is
/// not Marvin-affected), but never produced for new identities.
pub const RECIPIENT_ALG: &str = "rsa-oaep-sha256";
/// Modern recipient-wrapping algorithm tag: X25519 sealed box
/// (libsodium-compatible), recipient key derived from the Ed25519 identity.
pub const RECIPIENT_ALG_X25519: &str = "x25519-sealedbox";

/// Modern identity algorithm tag (identity.toml `alg`).
pub const IDENTITY_ALG_ED25519: &str = "ed25519";
/// Legacy identity algorithm tag; also the serde default for identity.toml
/// files that predate the `alg` field.
pub const IDENTITY_ALG_RSA: &str = "rsa-3072";

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

/// A parsed identity private key, dispatched by PKCS#8 algorithm OID.
enum PrivateIdentityKey {
    Ed25519(Box<SigningKey>),
    Rsa(Box<RsaPrivateKey>),
}

/// A parsed identity public key, dispatched by SPKI algorithm OID.
enum PublicIdentityKey {
    Ed25519(Box<VerifyingKey>),
    Rsa(Box<RsaPublicKey>),
}

fn parse_private_key(private_key_pem: &str) -> DotLockResult<PrivateIdentityKey> {
    if let Ok(signing_key) = SigningKey::from_pkcs8_pem(private_key_pem) {
        return Ok(PrivateIdentityKey::Ed25519(Box::new(signing_key)));
    }
    RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map(|key| PrivateIdentityKey::Rsa(Box::new(key)))
        .map_err(|e| DotLockError::Crypto(format!("failed to parse private key: {e}")))
}

fn parse_public_key_pem(public_key_pem: &str) -> DotLockResult<PublicIdentityKey> {
    if let Ok(verifying_key) = VerifyingKey::from_public_key_pem(public_key_pem) {
        return Ok(PublicIdentityKey::Ed25519(Box::new(verifying_key)));
    }
    RsaPublicKey::from_public_key_pem(public_key_pem)
        .map(|key| PublicIdentityKey::Rsa(Box::new(key)))
        .map_err(|e| DotLockError::Crypto(format!("failed to parse public key: {e}")))
}

fn parse_public_key_der(der: &[u8]) -> DotLockResult<PublicIdentityKey> {
    if let Ok(verifying_key) = VerifyingKey::from_public_key_der(der) {
        return Ok(PublicIdentityKey::Ed25519(Box::new(verifying_key)));
    }
    RsaPublicKey::from_public_key_der(der)
        .map(|key| PublicIdentityKey::Rsa(Box::new(key)))
        .map_err(|e| DotLockError::Crypto(format!("failed to parse public key: {e}")))
}

fn parse_public_key_b64(public_key_b64: &str) -> DotLockResult<PublicIdentityKey> {
    let der = general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| DotLockError::Crypto(format!("failed to decode public key: {e}")))?;
    parse_public_key_der(&der)
}

impl PublicIdentityKey {
    fn to_der(&self) -> DotLockResult<Vec<u8>> {
        match self {
            PublicIdentityKey::Ed25519(key) => key
                .to_public_key_der()
                .map(|der| der.as_ref().to_vec())
                .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}"))),
            PublicIdentityKey::Rsa(key) => key
                .to_public_key_der()
                .map(|der| der.as_ref().to_vec())
                .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}"))),
        }
    }

    fn recipient_alg(&self) -> &'static str {
        match self {
            PublicIdentityKey::Ed25519(_) => RECIPIENT_ALG_X25519,
            PublicIdentityKey::Rsa(_) => RECIPIENT_ALG,
        }
    }
}

/// Generates a MODERN (Ed25519) identity. Legacy RSA identities are never
/// generated anymore — only read (see module docs).
pub fn generate_identity(protection: IdentityProtection<'_>) -> DotLockResult<GeneratedIdentity> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut())
        .map_err(|e| DotLockError::Crypto(format!("failed to generate identity key: {e}")))?;
    let signing_key = SigningKey::from_bytes(&seed);

    let private_key_pem = match protection {
        IdentityProtection::Encrypted(passphrase) => signing_key
            .to_pkcs8_encrypted_pem(passphrase, pkcs8::LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))?
            .to_string(),
        IdentityProtection::Plain => signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))?
            .to_string(),
    };
    let public_key_pem = signing_key
        .verifying_key()
        .to_public_key_pem(pkcs8::LineEnding::LF)
        .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}")))?;
    let fingerprint = fingerprint_public_key(&public_key_pem)?;

    Ok(GeneratedIdentity {
        private_key_pem,
        public_key_pem,
        fingerprint,
    })
}

/// Test-only legacy generator: exercises the RSA read/verify/migrate paths
/// against material shaped exactly like pre-migration identities.
#[cfg(test)]
pub(crate) fn generate_legacy_rsa_identity(
    protection: IdentityProtection<'_>,
) -> DotLockResult<GeneratedIdentity> {
    let mut rng = LegacyOsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate identity key: {e}")))?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = match protection {
        IdentityProtection::Encrypted(passphrase) => private_key
            .to_pkcs8_encrypted_pem(&mut rng, passphrase, rsa::pkcs8::LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))?
            .to_string(),
        IdentityProtection::Plain => private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))?
            .to_string(),
    };
    let public_key_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| DotLockError::Crypto(format!("failed to encode public key: {e}")))?;
    let fingerprint = fingerprint_public_key(&public_key_pem)?;

    Ok(GeneratedIdentity {
        private_key_pem,
        public_key_pem,
        fingerprint,
    })
}

/// Decrypts a passphrase-protected PKCS#8 private key (Ed25519 or legacy RSA)
/// back to an unencrypted PKCS#8 PEM.
pub fn decrypt_private_key_pem(
    encrypted_private_key_pem: &str,
    passphrase: &str,
) -> DotLockResult<String> {
    if let Ok(signing_key) =
        SigningKey::from_pkcs8_encrypted_pem(encrypted_private_key_pem, passphrase)
    {
        return signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))
            .map(|pem| pem.to_string());
    }
    let private_key =
        RsaPrivateKey::from_pkcs8_encrypted_pem(encrypted_private_key_pem, passphrase)
            .map_err(|_| DotLockError::InvalidIdentityPassphrase)?;
    private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| DotLockError::Crypto(format!("failed to encode private key: {e}")))
        .map(|pem| pem.to_string())
}

/// Re-encrypts an (already decrypted) PKCS#8 private-key PEM under a NEW
/// passphrase, preserving the key material exactly — the counterpart of
/// [`decrypt_private_key_pem`] used by `dl cert passwd`. Never generates a
/// key: the input key pair (and thus the identity fingerprint) is unchanged.
pub fn encrypt_private_key_pem(private_key_pem: &str, passphrase: &str) -> DotLockResult<String> {
    match parse_private_key(private_key_pem)? {
        PrivateIdentityKey::Ed25519(signing_key) => signing_key
            .to_pkcs8_encrypted_pem(passphrase, pkcs8::LineEnding::LF)
            .map_err(|e| DotLockError::Crypto(format!("failed to encrypt private key: {e}")))
            .map(|pem| pem.to_string()),
        PrivateIdentityKey::Rsa(private_key) => {
            let mut rng = LegacyOsRng;
            private_key
                .to_pkcs8_encrypted_pem(&mut rng, passphrase, rsa::pkcs8::LineEnding::LF)
                .map_err(|e| DotLockError::Crypto(format!("failed to encrypt private key: {e}")))
                .map(|pem| pem.to_string())
        }
    }
}

/// Fingerprint of the public key that corresponds to a (decrypted) identity
/// private key. `dl cert passwd` uses it to PROVE the key being re-encoded is
/// the same key pair recorded in `identity.toml` before touching disk.
pub fn fingerprint_for_private_key(private_key_pem: &str) -> DotLockResult<String> {
    let public_key = match parse_private_key(private_key_pem)? {
        PrivateIdentityKey::Ed25519(signing_key) => {
            PublicIdentityKey::Ed25519(Box::new(signing_key.verifying_key()))
        }
        PrivateIdentityKey::Rsa(private_key) => {
            PublicIdentityKey::Rsa(Box::new(RsaPublicKey::from(&*private_key)))
        }
    };
    let der = public_key.to_der()?;
    let digest = Sha256::digest(&der);
    Ok(hex_lower(&digest[..16]))
}

/// Identity algorithm tag for a private key PEM (Ed25519 or legacy RSA).
/// Production code reads the tag from `identity.toml` instead (so `dl cert
/// show` never has to decrypt the key); tests use this to assert the on-disk
/// key material really matches the recorded algorithm.
#[cfg_attr(not(test), allow(dead_code))]
pub fn identity_alg_for_private_key(private_key_pem: &str) -> DotLockResult<&'static str> {
    Ok(match parse_private_key(private_key_pem)? {
        PrivateIdentityKey::Ed25519(_) => IDENTITY_ALG_ED25519,
        PrivateIdentityKey::Rsa(_) => IDENTITY_ALG_RSA,
    })
}

/// Recipient-wrapping algorithm tag for a public key PEM.
pub fn recipient_alg_for_public_key(public_key_pem: &str) -> DotLockResult<&'static str> {
    Ok(parse_public_key_pem(public_key_pem)?.recipient_alg())
}

/// Recipient-wrapping algorithm tag for a base64-DER public key (as stored in
/// `VaultRecipient::public_key_b64`).
pub fn recipient_alg_for_public_key_b64(public_key_b64: &str) -> DotLockResult<&'static str> {
    Ok(parse_public_key_b64(public_key_b64)?.recipient_alg())
}

pub fn fingerprint_public_key(public_key_pem: &str) -> DotLockResult<String> {
    let der = parse_public_key_pem(public_key_pem)?.to_der()?;
    let digest = Sha256::digest(&der);
    Ok(hex_lower(&digest[..16]))
}

pub fn encode_public_key_b64(public_key_pem: &str) -> DotLockResult<String> {
    let der = parse_public_key_pem(public_key_pem)?.to_der()?;
    Ok(general_purpose::STANDARD.encode(der))
}

fn wrap_for_parsed_key(data: &[u8; 32], public_key: &PublicIdentityKey) -> DotLockResult<String> {
    match public_key {
        PublicIdentityKey::Ed25519(verifying_key) => {
            let curve_public =
                crypto_box::PublicKey::from(verifying_key.to_montgomery().to_bytes());
            let sealed = curve_public
                .seal(&mut rand_core::OsRng, data)
                .map_err(|_| DotLockError::Crypto("failed to wrap project key".to_string()))?;
            Ok(general_purpose::STANDARD.encode(sealed))
        }
        PublicIdentityKey::Rsa(rsa_public) => {
            // Legacy interop target: encrypting TO an RSA recipient is a
            // public-key operation (not Marvin-affected) and keeps
            // not-yet-migrated teammates working during rotation.
            let mut rng = LegacyOsRng;
            let encrypted = rsa_public
                .encrypt(&mut rng, Oaep::new::<Sha256>(), data)
                .map_err(|e| DotLockError::Crypto(format!("failed to wrap project key: {e}")))?;
            Ok(general_purpose::STANDARD.encode(encrypted))
        }
    }
}

/// Wraps 32 bytes of key material (project DEK or per-secret SDK) for the
/// identity public key in `public_key_pem`, dispatching on its algorithm.
pub fn wrap_dek_for_public_key(dek: &[u8; 32], public_key_pem: &str) -> DotLockResult<String> {
    wrap_for_parsed_key(dek, &parse_public_key_pem(public_key_pem)?)
}

/// Same as [`wrap_dek_for_public_key`] for a base64-DER public key (as stored
/// in `VaultRecipient::public_key_b64`).
pub fn wrap_dek_for_public_key_b64(dek: &[u8; 32], public_key_b64: &str) -> DotLockResult<String> {
    wrap_for_parsed_key(dek, &parse_public_key_b64(public_key_b64)?)
}

/// Unwraps key material with the identity private key, dispatching on its
/// algorithm: X25519 sealed-box open for Ed25519 identities, RSA-OAEP
/// decryption ONLY for legacy RSA identities (the Marvin-affected path —
/// reachable exclusively through not-yet-migrated identities).
pub fn unwrap_dek_with_private_key(
    wrapped_dek_b64: &str,
    private_key_pem: &str,
) -> DotLockResult<[u8; 32]> {
    let wrapped = general_purpose::STANDARD
        .decode(wrapped_dek_b64)
        .map_err(|e| DotLockError::Crypto(format!("failed to decode wrapped project key: {e}")))?;
    let decrypted = match parse_private_key(private_key_pem)? {
        PrivateIdentityKey::Ed25519(signing_key) => {
            let curve_secret = crypto_box::SecretKey::from(signing_key.to_scalar_bytes());
            curve_secret
                .unseal(&wrapped)
                .map_err(|_| DotLockError::Crypto("failed to unwrap project key".to_string()))?
        }
        PrivateIdentityKey::Rsa(private_key) => private_key
            .decrypt(Oaep::new::<Sha256>(), &wrapped)
            .map_err(|e| DotLockError::Crypto(format!("failed to unwrap project key: {e}")))?,
    };

    decrypted
        .try_into()
        .map_err(|_| DotLockError::Crypto("invalid project key size".to_string()))
}

fn sign_payload(payload: &[u8], private_key_pem: &str) -> DotLockResult<String> {
    match parse_private_key(private_key_pem)? {
        PrivateIdentityKey::Ed25519(signing_key) => {
            let signature = signing_key.sign(payload);
            Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
        }
        PrivateIdentityKey::Rsa(private_key) => {
            // Legacy path: signing is not Marvin-affected, but new identities
            // are Ed25519, so this only runs for not-yet-migrated identities.
            let signing_key = BlindedSigningKey::<Sha256>::new(*private_key);
            let mut rng = LegacyOsRng;
            let signature = signing_key.sign_with_rng(&mut rng, payload);
            Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
        }
    }
}

fn verify_payload(
    payload: &[u8],
    signature_b64: &str,
    public_key: &PublicIdentityKey,
    what: &str,
) -> DotLockResult<()> {
    let signature = general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| DotLockError::Crypto(format!("failed to decode {what} signature: {e}")))?;
    match public_key {
        PublicIdentityKey::Ed25519(verifying_key) => {
            let signature = Ed25519Signature::from_slice(&signature).map_err(|e| {
                DotLockError::Crypto(format!("failed to parse {what} signature: {e}"))
            })?;
            verifying_key
                .verify(payload, &signature)
                .map_err(|_| DotLockError::Crypto(format!("{what} signature invalid")))
        }
        PublicIdentityKey::Rsa(rsa_public) => {
            let verifying_key = RsaPssVerifyingKey::<Sha256>::new((**rsa_public).clone());
            let signature = RsaPssSignature::try_from(signature.as_slice()).map_err(|e| {
                DotLockError::Crypto(format!("failed to parse {what} signature: {e}"))
            })?;
            verifying_key
                .verify(payload, &signature)
                .map_err(|_| DotLockError::Crypto(format!("{what} signature invalid")))
        }
    }
}

pub fn sign_audit_entry_hash(entry_hash: &str, private_key_pem: &str) -> DotLockResult<String> {
    sign_payload(entry_hash.as_bytes(), private_key_pem)
}

pub fn verify_audit_entry_hash_signature(
    entry_hash: &str,
    signature_b64: &str,
    public_key_pem: &str,
) -> DotLockResult<()> {
    verify_payload(
        entry_hash.as_bytes(),
        signature_b64,
        &parse_public_key_pem(public_key_pem)?,
        "audit",
    )
}

/// Signs a recipient-grant payload (see
/// `storage::shared_access::recipient_grant_payload`) with the granting
/// signer's private key (Ed25519, or RSA-PSS for legacy identities).
pub fn sign_recipient_grant(payload: &[u8], private_key_pem: &str) -> DotLockResult<String> {
    sign_payload(payload, private_key_pem)
}

/// Verifies a recipient-grant signature against an authorized signer's public
/// key (base64 DER, as stored in `authorized_signers`), dispatching on the
/// signer's key algorithm.
pub fn verify_recipient_grant(
    payload: &[u8],
    signature_b64: &str,
    public_key_b64: &str,
) -> DotLockResult<()> {
    verify_payload(
        payload,
        signature_b64,
        &parse_public_key_b64(public_key_b64)?,
        "recipient grant",
    )
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
        IDENTITY_ALG_ED25519, IDENTITY_ALG_RSA, IdentityProtection, RECIPIENT_ALG,
        RECIPIENT_ALG_X25519, decrypt_private_key_pem, encode_public_key_b64, generate_identity,
        generate_legacy_rsa_identity, identity_alg_for_private_key, recipient_alg_for_public_key,
        recipient_alg_for_public_key_b64, sign_audit_entry_hash, sign_recipient_grant,
        unwrap_dek_with_private_key, verify_audit_entry_hash_signature, verify_recipient_grant,
        wrap_dek_for_public_key, wrap_dek_for_public_key_b64,
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

        assert_eq!(unwrapped, dek);
        assert!(identity.private_key_pem.contains("ENCRYPTED PRIVATE KEY"));
    }

    /// A freshly generated identity is Ed25519/X25519 end to end — no RSA on
    /// any modern path (RUSTSEC-2023-0071 exit).
    #[test]
    fn new_identities_are_ed25519_never_rsa() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");

        assert_eq!(
            identity_alg_for_private_key(&identity.private_key_pem).expect("alg"),
            IDENTITY_ALG_ED25519
        );
        assert_eq!(
            recipient_alg_for_public_key(&identity.public_key_pem).expect("alg"),
            RECIPIENT_ALG_X25519
        );
        // Ed25519 keys are tiny; an RSA-3072 PEM would be ~30x this size.
        assert!(identity.private_key_pem.len() < 400);
        let wrapped = wrap_dek_for_public_key(&[7u8; 32], &identity.public_key_pem).expect("wrap");
        // Sealed box: 32-byte ephemeral pk + 16-byte tag + 32-byte payload.
        use base64::Engine as _;
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(&wrapped)
            .expect("b64");
        assert_eq!(sealed.len(), 32 + 16 + 32);
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
        assert_eq!(
            recipient_alg_for_public_key_b64(&public_key_b64).expect("alg"),
            RECIPIENT_ALG_X25519
        );
    }

    /// `dl cert passwd` core property: re-encrypting a decrypted private key
    /// under a new passphrase (and decrypting it again) preserves the key
    /// material exactly — same fingerprint, same wrap/unwrap capability — and
    /// the OLD passphrase no longer opens the new encoding. Also covers the
    /// footgun input: a PEM "encrypted" under an EMPTY passphrase decrypts
    /// with `""` and re-encodes to the same key.
    #[test]
    fn encrypt_private_key_pem_preserves_the_key_pair() {
        use super::{encrypt_private_key_pem, fingerprint_for_private_key};

        let identity = generate_identity(IdentityProtection::Encrypted("")).expect("identity");
        let plain_pem = decrypt_private_key_pem(&identity.private_key_pem, "").expect("decrypt");
        assert_eq!(
            fingerprint_for_private_key(&plain_pem).expect("fingerprint"),
            identity.fingerprint
        );

        let reencrypted = encrypt_private_key_pem(&plain_pem, "N3w-Pass!").expect("encrypt");
        assert!(reencrypted.contains("ENCRYPTED PRIVATE KEY"));
        assert!(decrypt_private_key_pem(&reencrypted, "").is_err());
        let roundtrip = decrypt_private_key_pem(&reencrypted, "N3w-Pass!").expect("decrypt new");
        assert_eq!(roundtrip, plain_pem);
        assert_eq!(
            fingerprint_for_private_key(&roundtrip).expect("fingerprint"),
            identity.fingerprint
        );

        // The re-encoded key is still the SAME key pair operationally: it
        // unwraps material sealed to the original public key.
        let dek = [4u8; 32];
        let wrapped = wrap_dek_for_public_key(&dek, &identity.public_key_pem).expect("wrap");
        assert_eq!(
            unwrap_dek_with_private_key(&wrapped, &roundtrip).expect("unwrap"),
            dek
        );
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
        // Ed25519 signatures are 64 bytes.
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&signature)
            .expect("b64");
        assert_eq!(raw.len(), 64);
    }

    /// Legacy interop: RSA identities (pre-migration) still wrap/unwrap,
    /// sign/verify, and decrypt their passphrase-protected PEM — through the
    /// exact same dispatching entry points the rest of the codebase calls.
    #[test]
    fn legacy_rsa_identity_still_works_through_the_same_api() {
        let identity = generate_legacy_rsa_identity(IdentityProtection::Encrypted("hunter2"))
            .expect("legacy identity");
        let private_key_pem =
            decrypt_private_key_pem(&identity.private_key_pem, "hunter2").expect("decrypt pem");

        assert_eq!(
            identity_alg_for_private_key(&private_key_pem).expect("alg"),
            IDENTITY_ALG_RSA
        );
        assert_eq!(
            recipient_alg_for_public_key(&identity.public_key_pem).expect("alg"),
            RECIPIENT_ALG
        );

        let dek = [3u8; 32];
        let wrapped = wrap_dek_for_public_key(&dek, &identity.public_key_pem).expect("wrap");
        assert_eq!(
            unwrap_dek_with_private_key(&wrapped, &private_key_pem).expect("unwrap"),
            dek
        );

        let signature = sign_audit_entry_hash("sha256:test", &private_key_pem).expect("sign");
        verify_audit_entry_hash_signature("sha256:test", &signature, &identity.public_key_pem)
            .expect("verify");
    }

    /// Mixed-recipient resolution: the same payload wrapped for an Ed25519
    /// recipient and an RSA recipient unwraps correctly on each side, and a
    /// grant signed by either identity type verifies via base64-DER dispatch.
    #[test]
    fn mixed_rsa_and_ed25519_recipients_resolve_per_key() {
        let modern = generate_identity(IdentityProtection::Plain).expect("modern");
        let legacy =
            generate_legacy_rsa_identity(IdentityProtection::Plain).expect("legacy identity");
        let dek = [5u8; 32];

        let for_modern = wrap_dek_for_public_key(&dek, &modern.public_key_pem).expect("wrap");
        let for_legacy = wrap_dek_for_public_key(&dek, &legacy.public_key_pem).expect("wrap");
        assert_eq!(
            unwrap_dek_with_private_key(&for_modern, &modern.private_key_pem).expect("unwrap"),
            dek
        );
        assert_eq!(
            unwrap_dek_with_private_key(&for_legacy, &legacy.private_key_pem).expect("unwrap"),
            dek
        );
        // Cross-unwrapping must fail: each wrap is bound to its key.
        assert!(unwrap_dek_with_private_key(&for_modern, &legacy.private_key_pem).is_err());
        assert!(unwrap_dek_with_private_key(&for_legacy, &modern.private_key_pem).is_err());

        for identity in [&modern, &legacy] {
            let public_key_b64 =
                encode_public_key_b64(&identity.public_key_pem).expect("encode public key");
            let signature =
                sign_recipient_grant(b"payload", &identity.private_key_pem).expect("sign");
            verify_recipient_grant(b"payload", &signature, &public_key_b64).expect("verify");
            assert!(verify_recipient_grant(b"tampered", &signature, &public_key_b64).is_err());
        }
    }
}
