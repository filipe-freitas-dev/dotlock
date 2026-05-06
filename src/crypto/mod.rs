pub mod dek;
pub mod integrity;
pub mod kdf;
pub mod kek;
pub mod passgen;
pub mod share;

use base64::{Engine as _, engine::general_purpose};
use colored::Colorize;
use inquire::{Confirm, Password, PasswordDisplayMode, Select, validator::Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        dek::{generate_dek, wrap_dek},
        kdf::{KdfParams, derive_master_key, generate_salt},
        kek::derive_kek,
        passgen::{generate_password, validate_password_strength},
    },
    domain::{error::DotLockError, model::DotLockResult},
};

const KEY_LEN: usize = 32;
const GENERATED_PASSWORD_LEN: usize = 32;

fn default_access_mode() -> AccessMode {
    AccessMode::MasterPassword
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    MasterPassword,
    Shared,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecipient {
    pub id: String,
    pub label: String,
    pub alg: String,
    pub public_key_fingerprint: String,
    pub public_key_b64: String,
    pub wrapped_dek_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyMetadata {
    pub version: u32,
    pub project_uuid: String,
    pub project: String,
    pub environment: String,

    pub kdf: String,
    pub salt_b64: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,

    pub kek_version: u32,

    pub wrapped_dek_nonce_b64: String,
    pub wrapped_dek_b64: String,

    #[serde(default = "default_access_mode")]
    pub access_mode: AccessMode,
    #[serde(default)]
    pub recipients: Vec<VaultRecipient>,

    pub secrets_hash_nonce_b64: String,
    pub secrets_hash_b64: String,
}

pub struct InitializedVault {
    pub dek: Zeroizing<[u8; KEY_LEN]>,
    pub metadata: VaultKeyMetadata,
}

pub fn update_master_password_metadata(
    metadata: &mut VaultKeyMetadata,
    dek: &[u8; KEY_LEN],
    passphrase: &str,
) -> DotLockResult<()> {
    let params = KdfParams::default();
    let salt = generate_salt().map_err(|e| DotLockError::Crypto(e.to_string()))?;

    let mut master_key = derive_master_key(passphrase, &salt, params)
        .map_err(|e| DotLockError::Crypto(e.to_string()))?;
    let mut kek = derive_kek(
        &master_key,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )
    .map_err(|e| DotLockError::Crypto(e.to_string()))?;

    master_key.zeroize();

    let wrapped = wrap_dek(&kek, dek, &metadata.project, &metadata.environment)
        .map_err(|e| DotLockError::Crypto(e.to_string()))?;

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

fn map_inquire(err: inquire::InquireError) -> DotLockError {
    use inquire::InquireError::*;
    match err {
        OperationCanceled | OperationInterrupted => DotLockError::Aborted,
        other => DotLockError::Io(other.to_string()),
    }
}

fn prompt_typed_password() -> DotLockResult<String> {
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
        .map_err(map_inquire)
}

fn prompt_generated_password() -> DotLockResult<String> {
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
    Ok(pwd)
}

pub fn ask_master_password() -> DotLockResult<String> {
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

    let dek = generate_dek().map_err(|e| DotLockError::Crypto(e.to_string()))?;

    let mut metadata = VaultKeyMetadata {
        version: 1,
        project_uuid: Uuid::new_v4().to_string(),
        project: project.to_string(),
        environment: environment.to_string(),

        kdf: String::new(),
        salt_b64: String::new(),
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,

        kek_version: 1,

        wrapped_dek_nonce_b64: String::new(),
        wrapped_dek_b64: String::new(),

        access_mode: AccessMode::MasterPassword,
        recipients: Vec::new(),

        secrets_hash_nonce_b64: String::new(),
        secrets_hash_b64: String::new(),
    };
    update_master_password_metadata(&mut metadata, &dek, &passphrase)?;

    Ok(InitializedVault {
        dek: Zeroizing::new(dek),
        metadata,
    })
}

pub fn prompt_unlock_password() -> DotLockResult<String> {
    Password::new("Master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|err| match err {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => DotLockError::Aborted,
            other => DotLockError::Io(other.to_string()),
        })
}
