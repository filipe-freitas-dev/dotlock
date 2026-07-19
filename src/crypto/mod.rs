pub mod dek;
pub mod integrity;
pub mod kdf;
pub mod kek;
pub mod passgen;
pub mod sdk;
pub mod secret_cipher;
pub mod share;

use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use base64::{Engine as _, engine::general_purpose};
use colored::Colorize;
use inquire::{Confirm, Password, PasswordDisplayMode, Select, validator::Validation};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        dek::{generate_dek, wrap_dek},
        kdf::{KdfParams, derive_master_key, generate_salt},
        kek::derive_kek,
        passgen::{generate_password, validate_password_strength},
    },
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
};

// Vault metadata entities live in the domain layer (A2); re-exported here so
// crypto-centric call sites keep their historical import paths.
pub use crate::domain::vault::{
    AccessMode, AuthorizedSigner, VaultConfig, VaultKeyMetadata, VaultRecipient,
};

const GENERATED_PASSWORD_LEN: usize = 32;

pub struct InitializedVault {
    pub dek: ProjectKey,
    pub metadata: VaultKeyMetadata,
}

pub fn update_master_password_metadata(
    metadata: &mut VaultKeyMetadata,
    dek: &ProjectKey,
    passphrase: &str,
) -> DotLockResult<()> {
    let params = KdfParams::default();
    let salt = generate_salt()?;

    let mut master_key = derive_master_key(passphrase, &salt, params)?;
    let mut kek = derive_kek(
        &master_key,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )?;

    master_key.zeroize();

    let wrapped = wrap_dek(
        &kek,
        dek,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )?;

    kek.zeroize();

    metadata.kdf = "argon2id".to_string();
    metadata.salt_b64 = general_purpose::STANDARD.encode(salt);
    metadata.memory_kib = params.memory_kib;
    metadata.iterations = params.iterations;
    metadata.parallelism = params.parallelism;
    metadata.wrapped_dek_nonce_b64 = general_purpose::STANDARD.encode(wrapped.nonce);
    metadata.wrapped_dek_b64 = general_purpose::STANDARD.encode(wrapped.ciphertext);

    Ok(())
}

/// Explicit non-interactive master-password source selected on the command
/// line (FG2). Precedence: explicit flag > `DOTLOCK_MASTER_PASSWORD` env var
/// > interactive prompt (TTY only).
#[derive(Clone, Debug)]
pub enum PasswordFlagSource {
    /// `--password-stdin`: the first line of stdin is the master password
    /// (only the first line, so `dl set NAME --stdin` can still read the
    /// secret value from the remainder of the pipe).
    Stdin,
    /// `--password-file FILE`: the first line of FILE is the master password.
    File(PathBuf),
}

static PASSWORD_FLAG_SOURCE: OnceLock<Option<PasswordFlagSource>> = OnceLock::new();

/// Memoized non-interactive password so a command that needs it twice (e.g.
/// the auto-ratchet re-proof during a write) never re-consumes stdin. Held in
/// a `Zeroizing` buffer; like the session key cache it lives for the (short)
/// process lifetime only.
static RESOLVED_PASSWORD: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

/// Records the `--password-stdin`/`--password-file` selection; called exactly
/// once from `main` before any command runs.
pub fn set_password_flag_source(source: Option<PasswordFlagSource>) {
    let _ = PASSWORD_FLAG_SOURCE.set(source);
}

/// Drops the memoized non-interactive password so tests that set
/// `DOTLOCK_MASTER_PASSWORD` never leak a cached value into later tests in
/// the same process.
#[cfg(test)]
pub(crate) fn clear_resolved_password_for_tests() {
    if let Ok(mut cached) = RESOLVED_PASSWORD.lock() {
        *cached = None;
    }
}

fn read_password_from_stdin() -> DotLockResult<Zeroizing<String>> {
    use std::io::BufRead;
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(DotLockError::from)?;
    while line.ends_with(['\r', '\n']) {
        line.pop();
    }
    if line.is_empty() {
        return Err(DotLockError::Io(
            "no master password received on stdin (--password-stdin)".to_string(),
        ));
    }
    Ok(line)
}

fn read_password_from_file(path: &Path) -> DotLockResult<Zeroizing<String>> {
    // Symlink-safe open (M5), and the full file buffer is zeroized: only the
    // first line is the password, but the rest must not linger either.
    let content = Zeroizing::new(crate::storage::secure_fs::read_to_string(path)?);
    let password = Zeroizing::new(content.lines().next().unwrap_or("").to_string());
    if password.is_empty() {
        return Err(DotLockError::Io(format!(
            "no master password found on the first line of {}",
            path.display()
        )));
    }
    Ok(password)
}

fn password_from_env() -> Option<Zeroizing<String>> {
    match std::env::var("DOTLOCK_MASTER_PASSWORD") {
        Ok(value) if !value.is_empty() => Some(Zeroizing::new(value)),
        _ => None,
    }
}

/// Resolves the non-interactive master password, if any source is configured
/// (FG2). Returns `Ok(None)` when the interactive prompt should run instead.
fn non_interactive_password() -> DotLockResult<Option<Zeroizing<String>>> {
    let mut cached = RESOLVED_PASSWORD
        .lock()
        .map_err(|_| DotLockError::Io("password source lock poisoned".to_string()))?;
    if let Some(password) = cached.as_ref() {
        return Ok(Some(password.clone()));
    }
    let resolved = match PASSWORD_FLAG_SOURCE.get().and_then(Option::as_ref) {
        Some(PasswordFlagSource::Stdin) => Some(read_password_from_stdin()?),
        Some(PasswordFlagSource::File(path)) => Some(read_password_from_file(path)?),
        None => password_from_env(),
    };
    if let Some(password) = resolved.as_ref() {
        *cached = Some(password.clone());
    }
    Ok(resolved)
}

/// Non-interactive source for the LOCAL IDENTITY passphrase. Only one
/// credential is needed per unlock (identity passphrase in shared mode,
/// master password in master-password mode), so the FG2 sources feed
/// whichever prompt actually fires. Precedence: `DOTLOCK_IDENTITY_PASSPHRASE`
/// (dedicated, for environments that must carry BOTH credentials at once) >
/// the shared FG2 sources (`--password-stdin` > `--password-file` >
/// `DOTLOCK_MASTER_PASSWORD`). The shared sources stay memoized, so
/// `--password-stdin` still consumes only the first line of stdin, once.
pub(crate) fn non_interactive_identity_passphrase() -> DotLockResult<Option<Zeroizing<String>>> {
    match std::env::var("DOTLOCK_IDENTITY_PASSPHRASE") {
        Ok(value) if !value.is_empty() => Ok(Some(Zeroizing::new(value))),
        _ => non_interactive_password(),
    }
}

/// Gate for the interactive prompts: without a TTY the raw `inquire` failure
/// is replaced by an actionable error pointing at the FG2 sources.
pub(crate) fn ensure_tty_for_prompt() -> DotLockResult<()> {
    if std::io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(DotLockError::NoTtyForPassword)
    }
}

fn map_inquire(err: inquire::InquireError) -> DotLockError {
    use inquire::InquireError::*;
    match err {
        OperationCanceled | OperationInterrupted => DotLockError::Aborted,
        other => DotLockError::Io(other.to_string()),
    }
}

fn prompt_typed_password() -> DotLockResult<Zeroizing<String>> {
    let validator = |input: &str| match validate_password_strength(input) {
        Ok(()) => Ok(Validation::Valid),
        Err(DotLockError::WeakPassword { missing }) => {
            Ok(Validation::Invalid(format!("missing {missing}").into()))
        }
        Err(other) => Err(Box::new(other) as Box<dyn std::error::Error + Send + Sync>),
    };

    Password::new("Choose a master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(validator)
        .with_help_message("min 12 chars; mix lower, upper, digit and symbol")
        .with_custom_confirmation_message("Confirm master password:")
        .with_custom_confirmation_error_message("the passwords don't match")
        .prompt()
        .map(Zeroizing::new)
        .map_err(map_inquire)
}

fn prompt_generated_password() -> DotLockResult<Zeroizing<String>> {
    let pwd = generate_password(GENERATED_PASSWORD_LEN)?;

    println!();
    println!(
        "  {} a master password was generated for you:",
        "info:".cyan().bold()
    );
    println!();
    println!("    {}", pwd.bold().yellow());
    println!();
    println!(
        "  {} {}",
        "warn:".yellow().bold(),
        "store this password in a safe place; it will NOT be shown again".bold()
    );
    println!();

    let confirmed = Confirm::new("I have saved the password and want to continue")
        .with_default(false)
        .prompt()
        .map_err(map_inquire)?;

    if !confirmed {
        return Err(DotLockError::Aborted);
    }
    Ok(Zeroizing::new(pwd))
}

/// New-password entry point (`dl init`, `dl rotate master-password`). A
/// non-interactive source (FG2) bypasses the picker but still goes through
/// the strength gate; otherwise a TTY is required.
pub fn ask_master_password() -> DotLockResult<Zeroizing<String>> {
    if let Some(password) = non_interactive_password()? {
        validate_password_strength(&password)?;
        return Ok(password);
    }
    ensure_tty_for_prompt()?;

    let mode = Select::new(
        "How do you want to set the master password?",
        vec!["Generate a strong random one", "Type my own"],
    )
    .prompt()
    .map_err(map_inquire)?;

    if mode.starts_with("Generate") {
        prompt_generated_password()
    } else {
        prompt_typed_password()
    }
}

pub fn initialize_vault_keys(project: &str, environment: &str) -> DotLockResult<InitializedVault> {
    let passphrase = ask_master_password()?;

    let dek = generate_dek()?;

    let mut metadata = VaultKeyMetadata {
        version: 2,
        project_uuid: Uuid::new_v4().to_string(),
        project: project.to_string(),
        environment: environment.to_string(),

        kdf: String::new(),
        salt_b64: String::new(),
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,

        kek_version: 1,
        kek_writes_since_rotate: 0,

        wrapped_dek_nonce_b64: String::new(),
        wrapped_dek_b64: String::new(),
        wrapped_sdks_under_dek: std::collections::HashMap::new(),

        access_mode: AccessMode::MasterPassword,
        recipients: Vec::new(),
        authorized_signers: Vec::new(),
        config: VaultConfig::default(),

        secrets_hash_nonce_b64: String::new(),
        secrets_hash_b64: String::new(),
        secrets_hash_sha256_b64: String::new(),

        last_rotated_at: 0,
        vault_epoch: 0,
        metadata_mac_b64: String::new(),
    };
    update_master_password_metadata(&mut metadata, &dek, &passphrase)?;

    Ok(InitializedVault { dek, metadata })
}

/// Existing-password entry point (every unlock). The FG2 non-interactive
/// sources feed the exact same KDF/unwrap/MAC path as the prompt; there is no
/// weaker unlock.
pub fn prompt_unlock_password() -> DotLockResult<Zeroizing<String>> {
    if let Some(password) = non_interactive_password()? {
        return Ok(password);
    }
    ensure_tty_for_prompt()?;

    Password::new("Master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map(Zeroizing::new)
        .map_err(map_inquire)
}

#[cfg(test)]
mod password_source_tests {
    use super::read_password_from_file;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str, content: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("dotlock-pwfile-{name}-{unique}"));
        std::fs::write(&path, content).expect("write password file");
        path
    }

    #[test]
    fn password_file_uses_only_the_first_line() {
        let path = temp_file("first-line", "S3cret-Line!\ntrailing garbage\n");
        let password = read_password_from_file(&path).expect("read password");
        assert_eq!(password.as_str(), "S3cret-Line!");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn password_file_strips_crlf_and_rejects_empty() {
        let path = temp_file("crlf", "S3cret-Line!\r\n");
        let password = read_password_from_file(&path).expect("read password");
        assert_eq!(password.as_str(), "S3cret-Line!");
        let _ = std::fs::remove_file(&path);

        let empty = temp_file("empty", "\n");
        assert!(read_password_from_file(&empty).is_err());
        let _ = std::fs::remove_file(&empty);
    }
}
