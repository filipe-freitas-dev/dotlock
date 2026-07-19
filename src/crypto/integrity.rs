use std::path::Path;

use base64::{Engine, engine::general_purpose};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    crypto::VaultKeyMetadata,
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    storage::secure_fs,
};

type HmacSha256 = Hmac<Sha256>;

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

pub fn encrypt_hash(hash: &[u8; HASH_LEN], dek: &ProjectKey) -> DotLockResult<EncryptedHash> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| DotLockError::Crypto(e.to_string()))?;

    let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
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
    dek: &ProjectKey,
) -> DotLockResult<[u8; HASH_LEN]> {
    let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
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
    dek: &ProjectKey,
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

/// Rejects the all-zero key. A zeroed array is the placeholder handed to
/// read-only (limited-identity) unlocks; encrypting the integrity hash under
/// it would brick the vault for every full-access user on the next unlock.
fn reject_all_zero_key(dek: &ProjectKey) -> DotLockResult<()> {
    if dek.is_read_only_placeholder() {
        return Err(DotLockError::Crypto(
            "refusing to encrypt the integrity hash with an all-zero key (read-only unlock cannot sign the vault)".to_string(),
        ));
    }
    Ok(())
}

/// Builds the encrypted integrity hash fields for in-memory `secrets.lock`
/// content, so mutators can finalize metadata before any file is written.
pub fn build_encrypted_hash_fields_from_bytes(
    bytes: &[u8],
    dek: &ProjectKey,
) -> DotLockResult<(String, String)> {
    reject_all_zero_key(dek)?;
    let hash = compute_bytes_sha256(bytes);
    let encrypted = encrypt_hash(&hash, dek)?;
    Ok((
        general_purpose::STANDARD.encode(encrypted.nonce),
        general_purpose::STANDARD.encode(encrypted.ciphertext),
    ))
}

/// MAC subkey for `vault.toml` metadata (M2), derived from the PROJECT KEY
/// (DEK) — not the KEK — because every full-access unlock (master password,
/// shared identity, session cache) holds the DEK, while the KEK is only
/// derivable on password unlocks. Domain-separated from every other HKDF use
/// (`kek.rs` uses salt `dotlock:v1:hkdf` + a `kek:` info string).
fn derive_metadata_mac_key(
    metadata: &VaultKeyMetadata,
    dek: &ProjectKey,
) -> DotLockResult<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"dotlock:v1:metadata-mac"), dek.as_bytes());
    let info = format!(
        "dotlock:v1:metadata-mac:project_uuid={}",
        metadata.project_uuid
    );
    let mut key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut key)
        .map_err(|_| DotLockError::Crypto("failed to derive metadata MAC key".to_string()))?;
    Ok(key)
}

/// HMAC-SHA256 tag (base64) over the canonical encoding of every
/// security-relevant metadata field (everything except the MAC itself).
pub fn compute_metadata_mac_b64(
    metadata: &VaultKeyMetadata,
    dek: &ProjectKey,
) -> DotLockResult<String> {
    let mut key = derive_metadata_mac_key(metadata, dek)?;
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&key)
        .map_err(|_| DotLockError::Crypto("failed to key the metadata MAC".to_string()))?;
    key.zeroize();
    mac.update(&metadata.canonical_mac_input());
    Ok(general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

/// Verifies `metadata_mac_b64` against the metadata (M2). An EMPTY MAC is
/// tolerated: it marks a pre-v7 vault, which is upgraded (sealed) on its first
/// full-access write. A present-but-wrong MAC means someone rewrote
/// `vault.toml` outside DotLock and hard-fails. Limited recipients cannot run
/// this check (no project key); they keep relying on the public secrets hash.
pub fn verify_metadata_mac(metadata: &VaultKeyMetadata, dek: &ProjectKey) -> DotLockResult<()> {
    if metadata.metadata_mac_b64.is_empty() {
        return Ok(());
    }
    let stored = general_purpose::STANDARD
        .decode(&metadata.metadata_mac_b64)
        .map_err(|_| DotLockError::MetadataTampered)?;
    let mut key = derive_metadata_mac_key(metadata, dek)?;
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&key)
        .map_err(|_| DotLockError::Crypto("failed to key the metadata MAC".to_string()))?;
    key.zeroize();
    mac.update(&metadata.canonical_mac_input());
    mac.verify_slice(&stored)
        .map_err(|_| DotLockError::MetadataTampered)
}

/// Finalizes metadata for persistence (M2+M3): bumps the vault format to v7,
/// advances the monotonic `vault_epoch`, and (re)computes `metadata_mac_b64`
/// over the final field values. Every write path with a project key MUST call
/// this immediately before its transactional commit — after every other field
/// mutation — so the stored MAC always covers what lands on disk.
pub fn seal_vault_metadata(metadata: &mut VaultKeyMetadata, dek: &ProjectKey) -> DotLockResult<()> {
    reject_all_zero_key(dek)?;
    metadata.version = metadata.version.max(7);
    metadata.vault_epoch = metadata.vault_epoch.saturating_add(1);
    metadata.metadata_mac_b64 = compute_metadata_mac_b64(metadata, dek)?;
    Ok(())
}

pub fn build_encrypted_hash_fields(
    secrets_path: impl AsRef<Path>,
    dek: &ProjectKey,
) -> DotLockResult<(String, String)> {
    reject_all_zero_key(dek)?;
    let hash = compute_file_sha256(secrets_path)?;
    let encrypted = encrypt_hash(&hash, dek)?;
    Ok((
        general_purpose::STANDARD.encode(encrypted.nonce),
        general_purpose::STANDARD.encode(encrypted.ciphertext),
    ))
}

#[cfg(test)]
mod tests {
    use super::{build_encrypted_hash_fields, build_encrypted_hash_fields_from_bytes};
    use crate::domain::{error::DotLockError, keys::ProjectKey};

    #[test]
    fn build_encrypted_hash_fields_from_bytes_rejects_all_zero_key() {
        let result = build_encrypted_hash_fields_from_bytes(
            b"content",
            &ProjectKey::read_only_placeholder(),
        );
        assert!(matches!(result, Err(DotLockError::Crypto(_))));
    }

    #[test]
    fn build_encrypted_hash_fields_rejects_all_zero_key() {
        let path = std::env::temp_dir().join("dotlock-zero-key-hash-test");
        std::fs::write(&path, b"content").expect("write");
        let result = build_encrypted_hash_fields(&path, &ProjectKey::read_only_placeholder());
        assert!(matches!(result, Err(DotLockError::Crypto(_))));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn build_encrypted_hash_fields_accepts_non_zero_key() {
        let (nonce_b64, hash_b64) =
            build_encrypted_hash_fields_from_bytes(b"content", &ProjectKey::new([8u8; 32]))
                .expect("build");
        assert!(!nonce_b64.is_empty());
        assert!(!hash_b64.is_empty());
    }

    // ---- metadata MAC (M2) + epoch (M3) ----

    fn dek() -> ProjectKey {
        ProjectKey::new([8u8; 32])
    }

    fn unsealed_metadata() -> crate::crypto::VaultKeyMetadata {
        toml::from_str(
            r#"
version = 6
project_uuid = "project"
project = "dotlock"
environment = "dev"
kdf = "argon2id"
salt_b64 = "salt"
memory_kib = 1
iterations = 1
parallelism = 1
kek_version = 1
wrapped_dek_nonce_b64 = "nonce"
wrapped_dek_b64 = "wrapped"
secrets_hash_nonce_b64 = "hash_nonce"
secrets_hash_b64 = "hash"
secrets_hash_sha256_b64 = "hash_plain"
"#,
        )
        .expect("metadata")
    }

    fn sealed_metadata() -> crate::crypto::VaultKeyMetadata {
        let mut metadata = unsealed_metadata();
        super::seal_vault_metadata(&mut metadata, &dek()).expect("seal");
        metadata
    }

    #[test]
    fn seal_bumps_version_and_epoch_and_produces_a_verifying_mac() {
        let metadata = sealed_metadata();
        assert_eq!(metadata.version, 7);
        assert_eq!(metadata.vault_epoch, 1);
        assert!(!metadata.metadata_mac_b64.is_empty());
        super::verify_metadata_mac(&metadata, &dek()).expect("verify");
    }

    #[test]
    fn legacy_vault_without_mac_is_tolerated() {
        // Pre-v7 vault: no MAC field. Unlock must not hard-fail (migration);
        // the first full-access write seals it.
        super::verify_metadata_mac(&unsealed_metadata(), &dek()).expect("legacy tolerated");
    }

    #[test]
    fn tampering_access_mode_without_resealing_fails_authentication() {
        let mut metadata = sealed_metadata();
        metadata.access_mode = crate::crypto::AccessMode::Shared;
        assert!(matches!(
            super::verify_metadata_mac(&metadata, &dek()),
            Err(DotLockError::MetadataTampered)
        ));
    }

    #[test]
    fn tampering_public_secrets_hash_without_resealing_fails_authentication() {
        // The exact M2 attack: limited recipients trust the PLAINTEXT
        // `secrets_hash_sha256_b64`; rewriting it must break the MAC that
        // full-access users verify.
        let mut metadata = sealed_metadata();
        metadata.secrets_hash_sha256_b64 = "forged".to_string();
        assert!(matches!(
            super::verify_metadata_mac(&metadata, &dek()),
            Err(DotLockError::MetadataTampered)
        ));
    }

    #[test]
    fn injecting_a_recipient_without_resealing_fails_authentication() {
        let mut metadata = sealed_metadata();
        metadata.recipients.push(crate::crypto::VaultRecipient {
            id: "evil-id".to_string(),
            label: "evil".to_string(),
            alg: "rsa-oaep-sha256".to_string(),
            public_key_fingerprint: "evil-fp".to_string(),
            public_key_b64: "ZXZpbA==".to_string(),
            wrapped_dek_b64: "ZXZpbA==".to_string(),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: true,
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
        });
        assert!(matches!(
            super::verify_metadata_mac(&metadata, &dek()),
            Err(DotLockError::MetadataTampered)
        ));
    }

    #[test]
    fn rolling_the_epoch_backward_without_resealing_fails_authentication() {
        let mut metadata = sealed_metadata();
        super::seal_vault_metadata(&mut metadata, &dek()).expect("second seal");
        assert_eq!(metadata.vault_epoch, 2);
        metadata.vault_epoch = 1;
        assert!(matches!(
            super::verify_metadata_mac(&metadata, &dek()),
            Err(DotLockError::MetadataTampered)
        ));
    }

    #[test]
    fn legit_change_resealed_through_the_write_path_verifies() {
        let mut metadata = sealed_metadata();
        metadata.access_mode = crate::crypto::AccessMode::Shared;
        metadata.config.auto_ratchet_after_writes = Some(10);
        super::seal_vault_metadata(&mut metadata, &dek()).expect("reseal");
        assert_eq!(metadata.vault_epoch, 2);
        super::verify_metadata_mac(&metadata, &dek()).expect("verify after reseal");
    }

    #[test]
    fn corrupted_mac_encoding_fails_authentication_not_crypto() {
        let mut metadata = sealed_metadata();
        metadata.metadata_mac_b64 = "not-base64!!".to_string();
        assert!(matches!(
            super::verify_metadata_mac(&metadata, &dek()),
            Err(DotLockError::MetadataTampered)
        ));
    }

    #[test]
    fn seal_refuses_the_read_only_placeholder_key() {
        let mut metadata = unsealed_metadata();
        let result =
            super::seal_vault_metadata(&mut metadata, &ProjectKey::read_only_placeholder());
        assert!(matches!(result, Err(DotLockError::Crypto(_))));
    }

    /// M3: rotation reseals under the NEW project key — the MAC verifies with
    /// the new key, never with the revoked one, and the epoch advances.
    #[test]
    fn rotation_reseal_verifies_under_the_new_key_only() {
        let old_dek = dek();
        let new_dek = ProjectKey::new([9u8; 32]);
        let mut metadata = sealed_metadata();
        // Simulate the rotate write path: kek_version bump + reseal(new key).
        metadata.kek_version += 1;
        super::seal_vault_metadata(&mut metadata, &new_dek).expect("reseal after rotation");
        assert_eq!(metadata.vault_epoch, 2);
        super::verify_metadata_mac(&metadata, &new_dek).expect("verify with new key");
        assert!(matches!(
            super::verify_metadata_mac(&metadata, &old_dek),
            Err(DotLockError::MetadataTampered)
        ));
    }
}
