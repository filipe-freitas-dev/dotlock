use std::{
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use inquire::{Password, PasswordDisplayMode};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::share::{
        GeneratedIdentity, IdentityProtection, decrypt_private_key_pem, generate_identity,
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::{paths::dotlock_data_root, secure_fs},
};

const IDENTITY_DIR: &str = "identity";
const PRIVATE_KEY_FILE: &str = "identity.pem";
const PUBLIC_KEY_FILE: &str = "identity.pub.pem";
const META_FILE: &str = "identity.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIdentityMetadata {
    pub fingerprint: String,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct LocalIdentity {
    pub fingerprint: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
}

/// Directory holding the local identity key pair. Hard-fails with
/// [`DotLockError::HomeDirUnavailable`] when no home/config directory
/// resolves: the private key must never be written into a committable CWD.
pub fn identity_dir() -> DotLockResult<PathBuf> {
    if let Ok(dir) = std::env::var("DOTLOCK_IDENTITY_DIR")
        && !dir.trim().is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    Ok(dotlock_data_root()?.join(IDENTITY_DIR))
}

pub fn private_key_path() -> DotLockResult<PathBuf> {
    Ok(identity_dir()?.join(PRIVATE_KEY_FILE))
}

pub fn public_key_path() -> DotLockResult<PathBuf> {
    Ok(identity_dir()?.join(PUBLIC_KEY_FILE))
}

fn metadata_path() -> DotLockResult<PathBuf> {
    Ok(identity_dir()?.join(META_FILE))
}

/// Process-wide signer registered whenever a local identity is successfully
/// loaded (and, for passphrase-encrypted identities, decrypted). Lets audit
/// entries written later in the same command be signed without re-prompting,
/// so encrypted identities no longer fall back to anonymous entries.
fn session_signer_slot() -> &'static Mutex<Option<LocalIdentity>> {
    static SLOT: OnceLock<Mutex<Option<LocalIdentity>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

pub fn register_session_signer(identity: &LocalIdentity) {
    if let Ok(mut slot) = session_signer_slot().lock() {
        *slot = Some(identity.clone());
    }
}

pub fn session_signer() -> Option<LocalIdentity> {
    session_signer_slot()
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
}

#[cfg(test)]
pub(crate) fn clear_session_signer() {
    if let Ok(mut slot) = session_signer_slot().lock() {
        *slot = None;
    }
}

fn prompt_identity_passphrase() -> DotLockResult<String> {
    Password::new("Local identity passphrase:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_help_message("used to decrypt your local shared-access key")
        .without_confirmation()
        .prompt()
        .map_err(|err| match err {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => DotLockError::Aborted,
            other => DotLockError::Io(other.to_string()),
        })
}

fn prompt_new_identity_passphrase() -> DotLockResult<String> {
    Password::new("Choose a passphrase for the local identity:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_help_message("this protects your local private key on disk")
        .with_custom_confirmation_message("Confirm local identity passphrase:")
        .with_custom_confirmation_error_message("the passphrases don't match")
        .prompt()
        .map_err(|err| match err {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => DotLockError::Aborted,
            other => DotLockError::Io(other.to_string()),
        })
}

pub fn initialize_local_identity(force: bool) -> DotLockResult<LocalIdentityMetadata> {
    initialize_local_identity_with_options(force, false)
}

pub fn initialize_local_identity_with_options(
    force: bool,
    plain: bool,
) -> DotLockResult<LocalIdentityMetadata> {
    let private_path = private_key_path()?;
    let public_path = public_key_path()?;
    let meta_path = metadata_path()?;

    if !force && (private_path.exists() || public_path.exists() || meta_path.exists()) {
        return Err(DotLockError::LocalIdentityAlreadyInitialized);
    }

    let GeneratedIdentity {
        private_key_pem,
        public_key_pem,
        fingerprint,
    } = if plain {
        generate_identity(IdentityProtection::Plain)?
    } else {
        let passphrase = prompt_new_identity_passphrase()?;
        generate_identity(IdentityProtection::Encrypted(&passphrase))?
    };

    secure_fs::write_string_atomic(&private_path, &private_key_pem, 0o700, 0o600)?;
    secure_fs::write_string_atomic(&public_path, &public_key_pem, 0o700, 0o644)?;
    let meta = LocalIdentityMetadata {
        fingerprint: fingerprint.clone(),
        encrypted: !plain,
    };
    let content = toml::to_string_pretty(&meta).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(&meta_path, &content, 0o700, 0o600)?;

    Ok(meta)
}

pub fn load_local_identity_metadata() -> DotLockResult<LocalIdentityMetadata> {
    let meta_path = metadata_path()?;

    if !meta_path.exists() {
        return Err(DotLockError::LocalIdentityNotInitialized);
    }

    let meta_content = secure_fs::read_to_string(&meta_path)?;
    toml::from_str::<LocalIdentityMetadata>(&meta_content)
        .map_err(|e| DotLockError::Crypto(format!("failed to parse identity metadata: {e}")))
}

pub fn load_local_identity() -> DotLockResult<LocalIdentity> {
    let private_path = private_key_path()?;
    let public_path = public_key_path()?;

    if !private_path.exists() || !public_path.exists() {
        return Err(DotLockError::LocalIdentityNotInitialized);
    }

    let metadata = load_local_identity_metadata()?;

    let encrypted_private_key_pem = secure_fs::read_to_string(&private_path)?;
    let private_key_pem = if metadata.encrypted {
        let passphrase = prompt_identity_passphrase()?;
        decrypt_private_key_pem(&encrypted_private_key_pem, &passphrase)?
    } else {
        encrypted_private_key_pem
    };

    let identity = LocalIdentity {
        fingerprint: metadata.fingerprint,
        private_key_pem,
        public_key_pem: secure_fs::read_to_string(&public_path)?,
    };
    // Keep the (already decrypted) signing key available for audit writes
    // made later in this command, so passphrase-encrypted identities still
    // produce signed audit entries instead of anonymous ones.
    register_session_signer(&identity);
    Ok(identity)
}

/// Serializes tests that mutate `DOTLOCK_IDENTITY_DIR`, across all modules.
#[cfg(test)]
pub(crate) fn test_identity_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::{
        LocalIdentityMetadata, initialize_local_identity_with_options, load_local_identity,
        load_local_identity_metadata, test_identity_env_lock,
    };
    use crate::storage::secure_fs;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn env_lock() -> &'static std::sync::Mutex<()> {
        test_identity_env_lock()
    }

    fn temp_dir() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-test-identity-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn initializes_and_loads_local_identity() {
        let _guard = env_lock().lock().expect("lock");
        let dir = temp_dir();
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
        }
        let meta = LocalIdentityMetadata {
            fingerprint: "abc".to_string(),
            encrypted: false,
        };
        let private = "-----BEGIN PRIVATE KEY-----\nvalue\n-----END PRIVATE KEY-----\n";
        let public = "-----BEGIN PUBLIC KEY-----\nvalue\n-----END PUBLIC KEY-----\n";
        let content = toml::to_string_pretty(&meta).expect("meta");
        secure_fs::write_string_atomic(
            &super::metadata_path().expect("meta path"),
            &content,
            0o700,
            0o600,
        )
        .expect("write meta");
        secure_fs::write_string_atomic(
            &super::private_key_path().expect("private path"),
            private,
            0o700,
            0o600,
        )
        .expect("write private");
        secure_fs::write_string_atomic(
            &super::public_key_path().expect("public path"),
            public,
            0o700,
            0o644,
        )
        .expect("write public");

        let loaded = load_local_identity().expect("load identity");
        let loaded_meta = load_local_identity_metadata().expect("load identity metadata");

        assert_eq!(loaded.fingerprint, "abc");
        assert_eq!(loaded.private_key_pem, private);
        assert_eq!(loaded.public_key_pem, public);
        assert_eq!(loaded_meta.fingerprint, "abc");
        assert!(!loaded_meta.encrypted);

        let _ = fs::remove_dir_all(&dir);
        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_DIR");
        }
    }

    #[test]
    fn initializes_plain_identity_without_passphrase() {
        let _guard = env_lock().lock().expect("lock");
        let dir = temp_dir();
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
        }

        let meta = initialize_local_identity_with_options(false, true).expect("init identity");
        super::clear_session_signer();
        let loaded = load_local_identity().expect("load identity");

        assert!(!meta.encrypted);
        assert_eq!(loaded.fingerprint, meta.fingerprint);
        assert!(loaded.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!loaded.private_key_pem.contains("ENCRYPTED PRIVATE KEY"));

        // Loading an identity must register the in-memory session signer so
        // later audit writes in the same command are signed (H4).
        let signer = super::session_signer().expect("session signer registered");
        assert_eq!(signer.fingerprint, meta.fingerprint);
        super::clear_session_signer();

        let _ = fs::remove_dir_all(&dir);
        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_DIR");
        }
    }

    #[test]
    fn identity_paths_hard_fail_without_home_or_overrides() {
        let _guard = env_lock().lock().expect("lock");
        let vars = [
            "HOME",
            "LOCALAPPDATA",
            "DOTLOCK_IDENTITY_DIR",
            "DOTLOCK_HOME",
        ];
        let saved: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect();
        unsafe {
            for name in vars {
                std::env::remove_var(name);
            }
        }

        let result = super::identity_dir();

        unsafe {
            for (name, value) in saved {
                if let Some(value) = value {
                    std::env::set_var(name, value);
                }
            }
        }

        assert!(matches!(
            result,
            Err(crate::domain::error::DotLockError::HomeDirUnavailable)
        ));
    }
}
