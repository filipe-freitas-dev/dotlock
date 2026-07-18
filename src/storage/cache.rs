use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    crypto::{AccessMode, VaultKeyMetadata},
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    storage::{paths::dotlock_data_root, secure_fs, vault_file::load_vault_metadata},
};

const CACHE_DIR_NAME: &str = "run";
const CACHE_SCOPE_DIR: &str = "sessions";
const CACHE_FILE_NAME: &str = "sessions.toml";
const LEGACY_CACHE_FILE_NAME: &str = "sessions.lock";
const WRAP_KEY_FILE: &str = "session.key";
/// Short exposure window for the on-disk session cache (H5). The previous
/// default was 30s with a 3600s cap; the cap is now 300s so `DOTLOCK_CACHE_TTL`
/// can never keep a cached project key around for an hour.
const DEFAULT_TTL_SECS: u64 = 15;
const MAX_TTL_SECS: u64 = 300;
const VAULT_FILE: &str = ".lock/vault.toml";
const WRAP_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// On-disk session cache entry. The project key is never stored raw: it is
/// wrapped under a key derived (HKDF-SHA256) from a separate per-user random
/// key file (`~/.lock/run/session.key`, 0600), so a bare read of
/// `sessions.toml` alone is not enough to recover the DEK (H5).
#[derive(Debug, Serialize, Deserialize)]
struct SessionCache {
    expires_at: u64,
    nonce_b64: String,
    wrapped_dek_b64: String,
}

fn ttl_secs() -> u64 {
    std::env::var("DOTLOCK_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|ttl| ttl.min(MAX_TTL_SECS))
        .unwrap_or(DEFAULT_TTL_SECS)
}

fn shared_cache_enabled() -> bool {
    std::env::var("DOTLOCK_SHARED_CACHE")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

/// Test-only convenience: resolves the cache path from the on-disk vault the
/// way the legacy single-shot callers did.
#[cfg(test)]
pub fn cache_path() -> DotLockResult<PathBuf> {
    cache_path_for_session(&session_name(load_metadata_best_effort().as_ref()))
}

fn cache_path_for_session(session: &str) -> DotLockResult<PathBuf> {
    Ok(cache_dir(session)?.join(CACHE_FILE_NAME))
}

fn legacy_cache_path_for_session(session: &str) -> DotLockResult<PathBuf> {
    Ok(cache_dir(session)?.join(LEGACY_CACHE_FILE_NAME))
}

/// Cache root resolution hard-fails when no home/config directory resolves:
/// a cached project key must never be written into a committable `./.lock`
/// in the current directory (H6).
fn cache_root() -> DotLockResult<PathBuf> {
    if let Ok(dir) = std::env::var("DOTLOCK_CACHE_DIR")
        && !dir.trim().is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    dotlock_data_root()
}

fn cache_dir(session: &str) -> DotLockResult<PathBuf> {
    Ok(cache_root()?
        .join(CACHE_DIR_NAME)
        .join(CACHE_SCOPE_DIR)
        .join(session))
}

fn wrap_key_path() -> DotLockResult<PathBuf> {
    Ok(cache_root()?.join(CACHE_DIR_NAME).join(WRAP_KEY_FILE))
}

/// Legacy entry point for callers without an already-loaded vault: resolves
/// the metadata best-effort ONCE (an unreadable vault keeps the historical
/// "unknown" session / non-shared defaults).
fn load_metadata_best_effort() -> Option<VaultKeyMetadata> {
    load_vault_metadata(VAULT_FILE).ok()
}

fn session_name(metadata: Option<&VaultKeyMetadata>) -> String {
    metadata
        .map(|metadata| short_uuid(&metadata.project_uuid))
        .unwrap_or_else(|| "unknown".to_string())
}

fn shared_mode_active(metadata: Option<&VaultKeyMetadata>) -> bool {
    metadata
        .map(|metadata| metadata.access_mode == AccessMode::Shared)
        .unwrap_or(false)
}

fn short_uuid(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort overwrite of the file contents with zeros before unlinking,
/// so an expired session cache does not leave the wrapped key material
/// recoverable from the (still allocated) blocks after a plain unlink (H5).
fn shred_and_remove(path: &Path) {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() {
            return;
        }
        let len = metadata.len() as usize;
        if len > 0
            && let Ok(mut file) = OpenOptions::new().write(true).open(path)
        {
            let _ = file.write_all(&vec![0u8; len]);
            let _ = file.sync_all();
        }
    }
    let _ = fs::remove_file(path);
}

/// Loads (or creates on first use) the per-user random key that wraps every
/// cached DEK. Stored 0600 outside the session directory, so reading
/// `sessions.toml` alone is insufficient to recover the project key.
fn load_or_create_wrap_key() -> DotLockResult<Zeroizing<[u8; WRAP_KEY_LEN]>> {
    let path = wrap_key_path()?;
    if path.exists() {
        let content = secure_fs::read_to_string(&path)?;
        let bytes = Zeroizing::new(
            general_purpose::STANDARD
                .decode(content.trim())
                .map_err(|_| DotLockError::Crypto("invalid session wrap key file".to_string()))?,
        );
        let key: [u8; WRAP_KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| DotLockError::Crypto("invalid session wrap key size".to_string()))?;
        return Ok(Zeroizing::new(key));
    }

    let mut key = Zeroizing::new([0u8; WRAP_KEY_LEN]);
    getrandom::fill(key.as_mut())
        .map_err(|e| DotLockError::Crypto(format!("failed to generate session wrap key: {e}")))?;
    let encoded = general_purpose::STANDARD.encode(key.as_ref());
    secure_fs::write_string_atomic(&path, &encoded, 0o700, 0o600)?;
    Ok(key)
}

fn derive_session_key(
    wrap_key: &[u8; WRAP_KEY_LEN],
    session: &str,
) -> DotLockResult<Zeroizing<[u8; WRAP_KEY_LEN]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"dotlock:v1:session-cache-hkdf"), wrap_key);
    let context = format!("dotlock:v1:session-cache:session={session}");
    let mut key = Zeroizing::new([0u8; WRAP_KEY_LEN]);
    hkdf.expand(context.as_bytes(), key.as_mut())
        .map_err(|_| DotLockError::Crypto("failed to derive session cache key".to_string()))?;
    Ok(key)
}

fn cache_aad(session: &str, expires_at: u64) -> String {
    format!("dotlock:v1:session-cache:session={session}:expires_at={expires_at}")
}

/// Test-only legacy entry point; production callers hold the metadata and use
/// [`read_cached_dek_for`].
#[cfg(test)]
pub fn read_cached_dek() -> Option<ProjectKey> {
    read_cached_dek_inner(load_metadata_best_effort().as_ref())
}

/// Cache read for callers that already hold the vault metadata (A6): avoids
/// re-reading `vault.toml` for the shared-mode check and the session name.
pub fn read_cached_dek_for(metadata: &VaultKeyMetadata) -> Option<ProjectKey> {
    read_cached_dek_inner(Some(metadata))
}

fn read_cached_dek_inner(metadata: Option<&VaultKeyMetadata>) -> Option<ProjectKey> {
    if shared_mode_active(metadata) && !shared_cache_enabled() {
        let _ = invalidate_cache_inner(metadata);
        return None;
    }

    let session = session_name(metadata);
    let path = cache_path_for_session(&session).ok()?;
    let legacy_path = legacy_cache_path_for_session(&session).ok()?;
    // Legacy plaintext caches are shredded on sight instead of honored.
    if legacy_path.exists() {
        shred_and_remove(&legacy_path);
    }
    if !path.exists() {
        return None;
    }

    let content = secure_fs::read_to_string(&path).ok()?;
    let Ok(cache) = toml::from_str::<SessionCache>(&content) else {
        // Stale/pre-wrapping format: remove eagerly rather than leave it.
        shred_and_remove(&path);
        return None;
    };

    if cache.expires_at <= now_secs() {
        shred_and_remove(&path);
        return None;
    }

    let wrap_key = load_or_create_wrap_key().ok()?;
    let key = derive_session_key(&wrap_key, &session).ok()?;
    let nonce = general_purpose::STANDARD.decode(&cache.nonce_b64).ok()?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let ciphertext = general_purpose::STANDARD
        .decode(&cache.wrapped_dek_b64)
        .ok()?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let aad = cache_aad(&session, cache.expires_at);
    let plaintext = match cipher.decrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: ciphertext.as_ref(),
            aad: aad.as_bytes(),
        },
    ) {
        Ok(plaintext) => Zeroizing::new(plaintext),
        Err(_) => {
            shred_and_remove(&path);
            return None;
        }
    };

    let dek: [u8; 32] = plaintext.as_slice().try_into().ok()?;
    Some(ProjectKey::new(dek))
}

pub fn write_cached_dek(dek: &ProjectKey) -> DotLockResult<()> {
    write_cached_dek_inner(load_metadata_best_effort().as_ref(), dek)
}

/// Cache write for callers that already hold the vault metadata (A6).
pub fn write_cached_dek_for(metadata: &VaultKeyMetadata, dek: &ProjectKey) -> DotLockResult<()> {
    write_cached_dek_inner(Some(metadata), dek)
}

fn write_cached_dek_inner(metadata: Option<&VaultKeyMetadata>, dek: &ProjectKey) -> DotLockResult<()> {
    if shared_mode_active(metadata) && !shared_cache_enabled() {
        let _ = invalidate_cache_inner(metadata);
        return Ok(());
    }

    let session = session_name(metadata);
    let path = cache_path_for_session(&session)?;
    let expires_at = now_secs().saturating_add(ttl_secs());

    let wrap_key = load_or_create_wrap_key()?;
    let key = derive_session_key(&wrap_key, &session)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate cache nonce: {e}")))?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let aad = cache_aad(&session, expires_at);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: dek.as_bytes().as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| DotLockError::Crypto("failed to wrap cached project key".to_string()))?;

    let cache = SessionCache {
        expires_at,
        nonce_b64: general_purpose::STANDARD.encode(nonce),
        wrapped_dek_b64: general_purpose::STANDARD.encode(ciphertext),
    };

    let content = toml::to_string(&cache).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(&path, &content, 0o700, 0o600)?;

    let legacy_path = legacy_cache_path_for_session(&session)?;
    if legacy_path != path {
        shred_and_remove(&legacy_path);
    }

    Ok(())
}

pub fn invalidate_cache() -> DotLockResult<bool> {
    invalidate_cache_inner(load_metadata_best_effort().as_ref())
}

fn invalidate_cache_inner(metadata: Option<&VaultKeyMetadata>) -> DotLockResult<bool> {
    let session = session_name(metadata);
    let paths = match (
        cache_path_for_session(&session),
        legacy_cache_path_for_session(&session),
    ) {
        (Ok(current), Ok(legacy)) => [current, legacy],
        // No resolvable cache directory means nothing was ever cached.
        _ => return Ok(false),
    };

    let mut removed = false;
    for path in paths {
        if path.exists() {
            shred_and_remove(&path);
            removed = !path.exists();
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::{read_cached_dek, shared_cache_enabled, write_cached_dek};
    use crate::{
        crypto::{AccessMode, VaultConfig, VaultKeyMetadata},
        domain::keys::ProjectKey,
        storage::vault_file::save_vault_metadata,
    };
    use base64::{Engine, engine::general_purpose};
    use std::{
        fs,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    /// Serializes tests that mutate `DOTLOCK_CACHE_DIR`/`DOTLOCK_CACHE_TTL`
    /// and the process working directory.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    fn metadata_with_mode(access_mode: AccessMode) -> VaultKeyMetadata {
        VaultKeyMetadata {
            version: 1,
            project_uuid: "project".to_string(),
            project: "dotlock".to_string(),
            environment: "dev".to_string(),
            kdf: "argon2id".to_string(),
            salt_b64: "salt".to_string(),
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
            kek_version: 1,
            kek_writes_since_rotate: 0,
            wrapped_dek_nonce_b64: "nonce".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks_under_dek: std::collections::HashMap::new(),
            access_mode,
            recipients: Vec::new(),
            authorized_signers: Vec::new(),
            config: VaultConfig::default(),
            secrets_hash_nonce_b64: "hash_nonce".to_string(),
            secrets_hash_b64: "hash".to_string(),
            secrets_hash_sha256_b64: "hash_plain".to_string(),
        }
    }

    struct CacheTestEnv {
        dir: std::path::PathBuf,
        cwd: std::path::PathBuf,
    }

    impl CacheTestEnv {
        fn new(name: &str, access_mode: AccessMode) -> Self {
            let dir = temp_dir(name);
            let project_dir = dir.join("project");
            fs::create_dir_all(project_dir.join(".lock")).expect("project dir");
            let cache_dir = dir.join("cache");
            unsafe {
                std::env::set_var("DOTLOCK_CACHE_DIR", &cache_dir);
                std::env::set_var("DOTLOCK_SHARED_CACHE", "false");
            }
            save_vault_metadata(
                project_dir.join(".lock/vault.toml"),
                &metadata_with_mode(access_mode),
            )
            .expect("save vault");
            let cwd = std::env::current_dir().expect("cwd");
            std::env::set_current_dir(&project_dir).expect("chdir");
            Self { dir, cwd }
        }

        fn cache_file(&self) -> std::path::PathBuf {
            super::cache_path().expect("cache path")
        }
    }

    impl Drop for CacheTestEnv {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.cwd);
            let _ = fs::remove_dir_all(&self.dir);
            unsafe {
                std::env::remove_var("DOTLOCK_CACHE_DIR");
                std::env::remove_var("DOTLOCK_SHARED_CACHE");
                std::env::remove_var("DOTLOCK_CACHE_TTL");
            }
        }
    }

    #[test]
    fn shared_mode_does_not_cache_by_default() {
        let _guard = env_lock().lock().expect("lock");
        let env = CacheTestEnv::new("cache", AccessMode::Shared);

        assert!(!shared_cache_enabled());
        write_cached_dek(&ProjectKey::new([5u8; 32])).expect("write cache");
        assert!(read_cached_dek().is_none());

        drop(env);
    }

    #[test]
    fn cached_dek_roundtrips_and_is_wrapped_on_disk() {
        let _guard = env_lock().lock().expect("lock");
        let env = CacheTestEnv::new("cache-wrap", AccessMode::MasterPassword);
        let dek = ProjectKey::new([7u8; 32]);

        write_cached_dek(&dek).expect("write cache");
        let content = fs::read_to_string(env.cache_file()).expect("read cache file");
        let raw_b64 = general_purpose::STANDARD.encode(dek.as_bytes());
        assert!(
            !content.contains(&raw_b64),
            "on-disk cache must not contain the raw base64 DEK"
        );
        assert!(content.contains("wrapped_dek_b64"));

        let cached = read_cached_dek().expect("read cached dek");
        assert_eq!(cached.as_bytes(), dek.as_bytes());

        drop(env);
    }

    #[test]
    fn expired_entry_is_removed_eagerly_on_read() {
        let _guard = env_lock().lock().expect("lock");
        let env = CacheTestEnv::new("cache-expiry", AccessMode::MasterPassword);
        unsafe {
            std::env::set_var("DOTLOCK_CACHE_TTL", "0");
        }

        write_cached_dek(&ProjectKey::new([9u8; 32])).expect("write cache");
        assert!(env.cache_file().exists());
        assert!(read_cached_dek().is_none());
        assert!(
            !env.cache_file().exists(),
            "expired session file must be shredded and removed on read"
        );

        drop(env);
    }

    #[test]
    fn tampered_wrapped_blob_is_rejected_and_removed() {
        let _guard = env_lock().lock().expect("lock");
        let env = CacheTestEnv::new("cache-tamper", AccessMode::MasterPassword);

        write_cached_dek(&ProjectKey::new([3u8; 32])).expect("write cache");
        let path = env.cache_file();
        let content = fs::read_to_string(&path).expect("read cache file");
        let tampered = content.replace("expires_at = ", "expires_at = 9");
        fs::write(&path, tampered).expect("tamper cache file");

        assert!(
            read_cached_dek().is_none(),
            "extending expires_at must break AEAD decryption"
        );
        assert!(!path.exists());

        drop(env);
    }
}
