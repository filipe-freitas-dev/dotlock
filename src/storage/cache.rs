use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::VaultKeyMetadata,
    domain::{error::DotLockError, model::DotLockResult},
    storage::{secure_fs, vault_file::load_vault_metadata},
};

const CACHE_DIR_NAME: &str = "run";
const CACHE_SCOPE_DIR: &str = "sessions";
const CACHE_FILE_NAME: &str = "sessions.toml";
const LEGACY_CACHE_FILE_NAME: &str = "sessions.lock";
const APP_CACHE_DIR: &str = ".lock";
const DEFAULT_TTL_SECS: u64 = 30;
const VAULT_FILE: &str = ".lock/vault.toml";

#[derive(Debug, Serialize, Deserialize)]
struct SessionCache {
    expires_at: u64,
    dek_b64: String,
}

fn ttl_secs() -> u64 {
    std::env::var("DOTLOCK_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_SECS)
}

pub fn cache_path() -> PathBuf {
    cache_dir().join(CACHE_FILE_NAME)
}

fn legacy_cache_path() -> PathBuf {
    cache_dir().join(LEGACY_CACHE_FILE_NAME)
}

fn cache_root() -> PathBuf {
    if let Ok(dir) = std::env::var("DOTLOCK_CACHE_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return Path::new(&home).join(APP_CACHE_DIR);
        }
    }

    #[cfg(windows)]
    {
        if let Ok(dir) = std::env::var("LOCALAPPDATA") {
            return Path::new(&dir).join("dotlock");
        }
    }

    PathBuf::from(".").join(APP_CACHE_DIR)
}

fn cache_dir() -> PathBuf {
    cache_root()
        .join(CACHE_DIR_NAME)
        .join(CACHE_SCOPE_DIR)
        .join(project_cache_dir_name())
}

fn project_cache_dir_name() -> String {
    read_project_uuid()
        .map(|uuid| short_uuid(&uuid))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn read_project_uuid() -> DotLockResult<String> {
    let metadata: VaultKeyMetadata = load_vault_metadata(VAULT_FILE)?;
    Ok(metadata.project_uuid)
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

pub fn read_cached_dek() -> Option<Zeroizing<[u8; 32]>> {
    let path = cache_path();
    let legacy_path = legacy_cache_path();
    let path = if path.exists() {
        path
    } else if legacy_path.exists() {
        legacy_path
    } else {
        return None;
    };

    let content = secure_fs::read_to_string(&path).ok()?;
    let cache: SessionCache = toml::from_str(&content).ok()?;

    if cache.expires_at <= now_secs() {
        let _ = fs::remove_file(&path);
        return None;
    }

    let bytes = general_purpose::STANDARD.decode(&cache.dek_b64).ok()?;
    let dek: [u8; 32] = bytes.try_into().ok()?;
    Some(Zeroizing::new(dek))
}

pub fn write_cached_dek(dek: &[u8; 32]) -> DotLockResult<()> {
    let path = cache_path();

    let cache = SessionCache {
        expires_at: now_secs().saturating_add(ttl_secs()),
        dek_b64: general_purpose::STANDARD.encode(dek),
    };

    let content = toml::to_string(&cache).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(&path, &content, 0o700, 0o600)?;

    let legacy_path = legacy_cache_path();
    if legacy_path != path {
        let _ = fs::remove_file(legacy_path);
    }

    Ok(())
}

pub fn invalidate_cache() -> DotLockResult<bool> {
    let mut removed = false;

    for path in [cache_path(), legacy_cache_path()] {
        match fs::remove_file(&path) {
            Ok(()) => removed = true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(DotLockError::from(err)),
        }
    }

    Ok(removed)
}
