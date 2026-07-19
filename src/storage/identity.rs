use std::{
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use inquire::{Password, PasswordDisplayMode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::share::{
        GeneratedIdentity, IDENTITY_ALG_ED25519, IDENTITY_ALG_RSA, IdentityProtection,
        decrypt_private_key_pem, generate_identity,
    },
    domain::{error::DotLockError, model::DotLockResult},
    storage::{paths::dotlock_data_root, secure_fs},
};

const IDENTITY_DIR: &str = "identity";
const PRIVATE_KEY_FILE: &str = "identity.pem";
const PUBLIC_KEY_FILE: &str = "identity.pub.pem";
const META_FILE: &str = "identity.toml";
// `dl cert migrate` archives the pre-migration RSA identity under these names
// so not-yet-rekeyed vaults (and old audit signatures) stay
// readable/verifiable until every project has been migrated.
const LEGACY_PRIVATE_KEY_FILE: &str = "identity.legacy.pem";
const LEGACY_PUBLIC_KEY_FILE: &str = "identity.legacy.pub.pem";
const LEGACY_META_FILE: &str = "identity.legacy.toml";

fn default_identity_alg() -> String {
    // identity.toml files that predate the `alg` field are always RSA.
    IDENTITY_ALG_RSA.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIdentityMetadata {
    pub fingerprint: String,
    #[serde(default)]
    pub encrypted: bool,
    /// Identity key algorithm: `ed25519` (modern) or `rsa-3072` (legacy).
    /// Defaults to the legacy value so pre-existing identity.toml files parse.
    #[serde(default = "default_identity_alg")]
    pub alg: String,
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

fn legacy_private_key_path() -> DotLockResult<PathBuf> {
    Ok(identity_dir()?.join(LEGACY_PRIVATE_KEY_FILE))
}

pub fn legacy_public_key_path() -> DotLockResult<PathBuf> {
    Ok(identity_dir()?.join(LEGACY_PUBLIC_KEY_FILE))
}

fn legacy_metadata_path() -> DotLockResult<PathBuf> {
    Ok(identity_dir()?.join(LEGACY_META_FILE))
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

/// Existing-passphrase entry point (every load of a passphrase-encrypted
/// identity). The FG2 non-interactive sources satisfy this prompt too —
/// `DOTLOCK_IDENTITY_PASSPHRASE` first, then `--password-stdin` /
/// `--password-file` / `DOTLOCK_MASTER_PASSWORD` — so shared-vault unlocks
/// work in CI. A wrong non-interactive passphrase still fails the PKCS#8
/// decrypt; there is no weaker path. Only called for `encrypted = true`
/// identities: a plain identity never reaches any passphrase prompt.
fn prompt_identity_passphrase() -> DotLockResult<Zeroizing<String>> {
    if let Some(passphrase) = crate::crypto::non_interactive_identity_passphrase()? {
        return Ok(passphrase);
    }
    crate::crypto::ensure_tty_for_prompt()?;
    Password::new("Local identity passphrase:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_help_message("used to decrypt your local shared-access key")
        .without_confirmation()
        .prompt()
        .map(Zeroizing::new)
        .map_err(|err| match err {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => DotLockError::Aborted,
            other => DotLockError::Io(other.to_string()),
        })
}

/// New-passphrase entry point (`dl cert init` / `dl cert migrate` without
/// `--plain`). Accepts the same non-interactive sources as
/// [`prompt_identity_passphrase`], so a passphrase-protected identity can be
/// created in CI; otherwise a TTY is required for the confirmed prompt.
fn prompt_new_identity_passphrase() -> DotLockResult<Zeroizing<String>> {
    if let Some(passphrase) = crate::crypto::non_interactive_identity_passphrase()? {
        return Ok(passphrase);
    }
    crate::crypto::ensure_tty_for_prompt()?;
    Password::new("Choose a passphrase for the local identity:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_help_message("this protects your local private key on disk")
        .with_custom_confirmation_message("Confirm local identity passphrase:")
        .with_custom_confirmation_error_message("the passphrases don't match")
        .prompt()
        .map(Zeroizing::new)
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
        alg: IDENTITY_ALG_ED25519.to_string(),
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

    // A passphrase-encrypted identity is decrypted at most ONCE per command:
    // the first load registers the decrypted key as the session signer, and
    // every later load in the same process (e.g. the per-secret SDK
    // resolution after the unlock already decrypted it) reuses it instead of
    // prompting for the passphrase again. The fingerprint check ensures a
    // signer for a different identity is never handed out.
    if metadata.encrypted
        && let Some(identity) = session_signer()
        && identity.fingerprint == metadata.fingerprint
    {
        return Ok(identity);
    }

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

/// True when a `dl cert migrate` run archived a pre-migration RSA identity
/// next to the current one.
pub fn has_legacy_identity() -> DotLockResult<bool> {
    Ok(legacy_metadata_path()?.exists())
}

/// Metadata of the archived pre-migration identity, if any.
pub fn load_legacy_identity_metadata() -> DotLockResult<LocalIdentityMetadata> {
    let meta_path = legacy_metadata_path()?;
    if !meta_path.exists() {
        return Err(DotLockError::LocalIdentityNotInitialized);
    }
    let meta_content = secure_fs::read_to_string(&meta_path)?;
    toml::from_str::<LocalIdentityMetadata>(&meta_content)
        .map_err(|e| DotLockError::Crypto(format!("failed to parse legacy identity metadata: {e}")))
}

/// Loads the archived pre-migration (RSA) identity — the ONLY remaining
/// consumer of RSA private-key material: unlocking vaults whose recipient
/// entry still references the legacy fingerprint, until `dl cert migrate`
/// rekeys them. Never registered as the session signer: new audit entries
/// must be signed by the modern identity.
pub fn load_legacy_identity() -> DotLockResult<LocalIdentity> {
    let private_path = legacy_private_key_path()?;
    let public_path = legacy_public_key_path()?;
    if !private_path.exists() || !public_path.exists() {
        return Err(DotLockError::LocalIdentityNotInitialized);
    }
    let metadata = load_legacy_identity_metadata()?;
    let encrypted_private_key_pem = secure_fs::read_to_string(&private_path)?;
    let private_key_pem = if metadata.encrypted {
        let passphrase = prompt_identity_passphrase()?;
        decrypt_private_key_pem(&encrypted_private_key_pem, &passphrase)?
    } else {
        encrypted_private_key_pem
    };
    Ok(LocalIdentity {
        fingerprint: metadata.fingerprint,
        private_key_pem,
        public_key_pem: secure_fs::read_to_string(&public_path)?,
    })
}

/// Migrates the local identity to the modern algorithm (Ed25519): archives
/// the current RSA files under the `identity.legacy.*` names and generates a
/// fresh identity in their place. The caller (the `dl cert migrate` command)
/// then rekeys per-project vault recipients; the legacy key stays available
/// for projects that were not rekeyed yet.
pub fn migrate_local_identity(
    plain: bool,
) -> DotLockResult<(LocalIdentityMetadata, LocalIdentity)> {
    let current = load_local_identity_metadata()?;
    if current.alg == IDENTITY_ALG_ED25519 {
        return Err(DotLockError::Crypto(
            "local identity already uses ed25519; nothing to migrate".to_string(),
        ));
    }
    if has_legacy_identity()? {
        return Err(DotLockError::Crypto(
            "a legacy identity archive already exists; refusing to overwrite it".to_string(),
        ));
    }

    let (
        GeneratedIdentity {
            private_key_pem,
            public_key_pem,
            fingerprint,
        },
        decrypted_private_key_pem,
    ) = if plain {
        let generated = generate_identity(IdentityProtection::Plain)?;
        let decrypted = generated.private_key_pem.clone();
        (generated, decrypted)
    } else {
        let passphrase = prompt_new_identity_passphrase()?;
        let generated = generate_identity(IdentityProtection::Encrypted(&passphrase))?;
        // Keep the decrypted key in memory for this command (grant re-sign +
        // audit signature) so the user is not immediately re-prompted.
        let decrypted = decrypt_private_key_pem(&generated.private_key_pem, &passphrase)?;
        (generated, decrypted)
    };

    // Archive the RSA identity FIRST (its files must never be lost), then
    // write the new one into the primary slots.
    std::fs::rename(private_key_path()?, legacy_private_key_path()?).map_err(DotLockError::from)?;
    std::fs::rename(public_key_path()?, legacy_public_key_path()?).map_err(DotLockError::from)?;
    std::fs::rename(metadata_path()?, legacy_metadata_path()?).map_err(DotLockError::from)?;

    secure_fs::write_string_atomic(&private_key_path()?, &private_key_pem, 0o700, 0o600)?;
    secure_fs::write_string_atomic(&public_key_path()?, &public_key_pem, 0o700, 0o644)?;
    let meta = LocalIdentityMetadata {
        fingerprint: fingerprint.clone(),
        encrypted: !plain,
        alg: IDENTITY_ALG_ED25519.to_string(),
    };
    let content = toml::to_string_pretty(&meta).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(&metadata_path()?, &content, 0o700, 0o600)?;

    let identity = LocalIdentity {
        fingerprint,
        private_key_pem: decrypted_private_key_pem,
        public_key_pem,
    };
    // New audit entries written later in this command are signed by the NEW
    // identity.
    register_session_signer(&identity);
    Ok((meta, identity))
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
            alg: crate::crypto::share::IDENTITY_ALG_ED25519.to_string(),
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

    /// Regression (double passphrase prompt): once a passphrase-encrypted
    /// identity has been decrypted in this process (session signer
    /// registered), a later `load_local_identity` in the same command must
    /// reuse the decrypted key instead of prompting again — `dl get` on a
    /// shared vault loads the identity once for the unlock and once for
    /// per-secret SDK resolution, and used to prompt for the passphrase
    /// twice. There is no TTY here, so any prompt attempt fails the load.
    #[test]
    fn encrypted_identity_reuses_session_signer_instead_of_reprompting() {
        use crate::crypto::share::{IdentityProtection, generate_identity};

        let _guard = env_lock().lock().expect("lock");
        let dir = temp_dir();
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
        }

        let generated = generate_identity(IdentityProtection::Plain).expect("identity");
        let meta = LocalIdentityMetadata {
            fingerprint: generated.fingerprint.clone(),
            encrypted: true,
            alg: crate::crypto::share::IDENTITY_ALG_ED25519.to_string(),
        };
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
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque\n-----END ENCRYPTED PRIVATE KEY-----\n",
            0o700,
            0o600,
        )
        .expect("write private");
        secure_fs::write_string_atomic(
            &super::public_key_path().expect("public path"),
            &generated.public_key_pem,
            0o700,
            0o644,
        )
        .expect("write public");

        // Simulate the first load of the command (the unlock path), which
        // decrypts the identity and registers the session signer.
        super::clear_session_signer();
        super::register_session_signer(&super::LocalIdentity {
            fingerprint: generated.fingerprint.clone(),
            private_key_pem: generated.private_key_pem.clone(),
            public_key_pem: generated.public_key_pem.clone(),
        });

        // The second load (e.g. per-secret SDK resolution) must reuse it.
        let loaded = load_local_identity().expect("second load must reuse the session signer");
        assert_eq!(loaded.fingerprint, generated.fingerprint);
        assert_eq!(loaded.private_key_pem, generated.private_key_pem);

        // A signer for a DIFFERENT identity must never be handed out: the
        // load falls through to the real decrypt path (which fails here,
        // since prompting is impossible without a TTY).
        super::register_session_signer(&super::LocalIdentity {
            fingerprint: "some-other-fp".to_string(),
            private_key_pem: generated.private_key_pem.clone(),
            public_key_pem: generated.public_key_pem.clone(),
        });
        load_local_identity().expect_err("mismatched session signer must not be reused");

        super::clear_session_signer();
        let _ = fs::remove_dir_all(&dir);
        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_DIR");
        }
    }

    /// Issue #1 regression: a PLAIN identity (`encrypted = false`) must NEVER
    /// reach a passphrase prompt. There is no TTY and no non-interactive
    /// source here, so any prompt attempt would fail the load — a successful
    /// load PROVES no prompt fired.
    #[test]
    fn plain_identity_never_prompts_for_a_passphrase() {
        let _guard = env_lock().lock().expect("lock");
        let dir = temp_dir();
        let saved_master = std::env::var("DOTLOCK_MASTER_PASSWORD").ok();
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
            std::env::remove_var("DOTLOCK_IDENTITY_PASSPHRASE");
            std::env::remove_var("DOTLOCK_MASTER_PASSWORD");
        }
        crate::crypto::clear_resolved_password_for_tests();
        super::clear_session_signer();

        let meta = initialize_local_identity_with_options(false, true).expect("init identity");
        assert!(
            !meta.encrypted,
            "--plain identity must record encrypted = false"
        );
        super::clear_session_signer();

        let loaded = load_local_identity()
            .expect("a plain identity must load without any passphrase prompt");
        assert_eq!(loaded.fingerprint, meta.fingerprint);

        super::clear_session_signer();
        let _ = fs::remove_dir_all(&dir);
        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_DIR");
            if let Some(value) = saved_master {
                std::env::set_var("DOTLOCK_MASTER_PASSWORD", value);
            }
        }
    }

    /// Issue #2: the non-interactive sources satisfy the identity passphrase.
    /// `DOTLOCK_IDENTITY_PASSPHRASE` (dedicated) and the shared FG2 fallback
    /// (`DOTLOCK_MASTER_PASSWORD` here) both decrypt the identity with no TTY;
    /// a wrong value fails the decrypt; and with no source at all the load
    /// fails with the actionable `NoTtyForPassword` error, not a raw inquire
    /// failure.
    #[test]
    fn encrypted_identity_honors_non_interactive_passphrase_sources() {
        use crate::crypto::share::{IdentityProtection, generate_identity};
        use crate::domain::error::DotLockError;

        let _guard = env_lock().lock().expect("lock");
        let dir = temp_dir();
        let saved_master = std::env::var("DOTLOCK_MASTER_PASSWORD").ok();
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
            std::env::remove_var("DOTLOCK_IDENTITY_PASSPHRASE");
            std::env::remove_var("DOTLOCK_MASTER_PASSWORD");
        }
        crate::crypto::clear_resolved_password_for_tests();
        super::clear_session_signer();

        let passphrase = "Corr3ct-Horse!";
        let generated =
            generate_identity(IdentityProtection::Encrypted(passphrase)).expect("identity");
        let meta = LocalIdentityMetadata {
            fingerprint: generated.fingerprint.clone(),
            encrypted: true,
            alg: crate::crypto::share::IDENTITY_ALG_ED25519.to_string(),
        };
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
            &generated.private_key_pem,
            0o700,
            0o600,
        )
        .expect("write private");
        secure_fs::write_string_atomic(
            &super::public_key_path().expect("public path"),
            &generated.public_key_pem,
            0o700,
            0o644,
        )
        .expect("write public");

        // No TTY (cargo test) + no non-interactive source: the clear,
        // actionable error — never a raw inquire "not a TTY" failure.
        let err = load_local_identity().expect_err("no source and no TTY must fail");
        assert!(
            matches!(err, DotLockError::NoTtyForPassword),
            "expected NoTtyForPassword, got: {err:?}"
        );

        // The dedicated env var decrypts the identity non-interactively.
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_PASSPHRASE", passphrase);
        }
        let loaded = load_local_identity().expect("env passphrase must decrypt the identity");
        assert_eq!(loaded.fingerprint, generated.fingerprint);
        assert!(loaded.private_key_pem.contains("BEGIN PRIVATE KEY"));

        // A wrong non-interactive passphrase must FAIL the decrypt, never
        // silently proceed (session signer cleared so the cached decrypt
        // cannot mask the failure).
        super::clear_session_signer();
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_PASSPHRASE", "wrong-passphrase");
        }
        load_local_identity().expect_err("a wrong non-interactive passphrase must fail");

        // The shared FG2 sources are the fallback: with no dedicated var set,
        // DOTLOCK_MASTER_PASSWORD feeds the identity prompt (one credential
        // per unlock).
        super::clear_session_signer();
        crate::crypto::clear_resolved_password_for_tests();
        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_PASSPHRASE");
            std::env::set_var("DOTLOCK_MASTER_PASSWORD", passphrase);
        }
        let loaded =
            load_local_identity().expect("shared FG2 source must decrypt the identity too");
        assert_eq!(loaded.fingerprint, generated.fingerprint);

        super::clear_session_signer();
        crate::crypto::clear_resolved_password_for_tests();
        let _ = fs::remove_dir_all(&dir);
        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_PASSPHRASE");
            std::env::remove_var("DOTLOCK_MASTER_PASSWORD");
            std::env::remove_var("DOTLOCK_IDENTITY_DIR");
            if let Some(value) = saved_master {
                std::env::set_var("DOTLOCK_MASTER_PASSWORD", value);
            }
        }
    }

    /// RSA-exit migration (ADR 0001): `migrate_local_identity` archives the
    /// RSA identity under the legacy slots and installs a fresh Ed25519
    /// identity — the legacy key stays loadable for not-yet-rekeyed vaults,
    /// and the new identity is registered as the session signer.
    #[test]
    fn migrate_local_identity_archives_rsa_and_installs_ed25519() {
        use crate::crypto::share::{
            IDENTITY_ALG_ED25519, IDENTITY_ALG_RSA, IdentityProtection,
            generate_legacy_rsa_identity, identity_alg_for_private_key,
        };

        let _guard = env_lock().lock().expect("lock");
        let dir = temp_dir();
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
        }

        // Seed an on-disk RSA identity exactly as a pre-migration setup: a
        // plain PKCS#8 PEM plus an identity.toml WITHOUT the `alg` field.
        let legacy = generate_legacy_rsa_identity(IdentityProtection::Plain).expect("legacy");
        secure_fs::write_string_atomic(
            &super::private_key_path().expect("private path"),
            &legacy.private_key_pem,
            0o700,
            0o600,
        )
        .expect("write private");
        secure_fs::write_string_atomic(
            &super::public_key_path().expect("public path"),
            &legacy.public_key_pem,
            0o700,
            0o644,
        )
        .expect("write public");
        let legacy_toml = format!(
            "fingerprint = \"{}\"\nencrypted = false\n",
            legacy.fingerprint
        );
        secure_fs::write_string_atomic(
            &super::metadata_path().expect("meta path"),
            &legacy_toml,
            0o700,
            0o600,
        )
        .expect("write meta");

        // The pre-`alg` identity.toml parses and defaults to the RSA tag.
        let before = load_local_identity_metadata().expect("pre-migration metadata");
        assert_eq!(before.alg, IDENTITY_ALG_RSA);
        assert!(!super::has_legacy_identity().expect("legacy check"));

        let (new_meta, new_identity) =
            super::migrate_local_identity(true).expect("migrate identity");

        assert_eq!(new_meta.alg, IDENTITY_ALG_ED25519);
        assert_ne!(new_meta.fingerprint, legacy.fingerprint);
        assert_eq!(new_identity.fingerprint, new_meta.fingerprint);
        assert_eq!(
            identity_alg_for_private_key(&new_identity.private_key_pem).expect("alg"),
            IDENTITY_ALG_ED25519
        );
        // The archived RSA identity stays loadable for not-yet-rekeyed vaults.
        assert!(super::has_legacy_identity().expect("legacy check"));
        let archived = super::load_legacy_identity().expect("load legacy");
        assert_eq!(archived.fingerprint, legacy.fingerprint);
        assert_eq!(archived.private_key_pem, legacy.private_key_pem);
        // The current identity is now the Ed25519 one, and it signs this
        // command's audit entries.
        let current = load_local_identity().expect("load current");
        assert_eq!(current.fingerprint, new_meta.fingerprint);
        let signer = super::session_signer().expect("session signer");
        assert_eq!(signer.fingerprint, new_meta.fingerprint);
        super::clear_session_signer();

        // Re-running refuses: nothing left to migrate.
        assert!(super::migrate_local_identity(true).is_err());

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
