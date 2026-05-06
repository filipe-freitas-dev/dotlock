use thiserror::Error;

#[derive(Error, Debug)]
pub enum DotLockError {
    #[error("invalid master password")]
    InvalidMasterPassword,

    #[error("master password is weak: missing {missing}")]
    WeakPassword { missing: String },

    #[error("DotLock is not initialized in this directory")]
    ProjectNotInitialized,

    #[error("a DotLock vault already exists in `.lock/`")]
    ProjectAlreadyInitialized,

    #[error(
        "vault is in a legacy format (missing vault UUID, secret UUIDs, or the integrity hash)"
    )]
    LegacyVaultFormat,

    #[error("secret `{name}` not found")]
    SecretNotFound { name: String },

    #[error("`.lock/secrets.lock` was modified outside of DotLock")]
    TamperedSecretsFile,

    #[error("variable name `{name}` is invalid")]
    InvalidVariableName { name: String },

    #[error("could not parse `{path}` at line {line}: {message}")]
    EnvParseError {
        path: String,
        line: usize,
        message: String,
    },

    #[error("algorithm `{alg}` is not supported")]
    UnsupportedAlgorithm { alg: String },

    #[error("no command was provided to `dotlock run`")]
    MissingCommand,

    #[error("the command exited with status {status}")]
    CommandFailed { status: String },

    #[error("local identity is not initialized")]
    LocalIdentityNotInitialized,

    #[error("local identity already exists")]
    LocalIdentityAlreadyInitialized,

    #[error("shared recipient `{query}` not found")]
    RecipientNotFound { query: String },

    #[error("invalid identity passphrase")]
    InvalidIdentityPassphrase,

    #[error("crypto failure: {0}")]
    Crypto(String),

    #[error("I/O failure: {0}")]
    Io(String),

    #[error("aborted by user")]
    Aborted,
}

impl DotLockError {
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            DotLockError::InvalidMasterPassword => {
                Some("check caps lock and your keyboard layout, then try again")
            }
            DotLockError::WeakPassword { .. } => {
                Some("use at least 12 characters with lowercase, uppercase, a digit and a symbol")
            }
            DotLockError::ProjectNotInitialized => {
                Some("run `dotlock init` in this directory before using other commands")
            }
            DotLockError::ProjectAlreadyInitialized => {
                Some("use `set/get/list/unset`, or remove `.lock/` to start over")
            }
            DotLockError::LegacyVaultFormat => {
                Some("delete the `.lock/` directory and run `dotlock init` to create a fresh vault")
            }
            DotLockError::SecretNotFound { .. } => {
                Some("list available secrets with `dotlock list`")
            }
            DotLockError::TamperedSecretsFile => Some(
                "someone modified `.lock/secrets.lock` outside DotLock; restore from a trusted backup or start over with `dotlock init`",
            ),
            DotLockError::InvalidVariableName { .. } => {
                Some("use only letters, digits and underscores; the name cannot start with a digit")
            }
            DotLockError::EnvParseError { .. } => Some(
                "each line must look like `KEY=VALUE` (quotes and `export` prefix are allowed)",
            ),
            DotLockError::UnsupportedAlgorithm { .. } => {
                Some("supported algorithms: xchacha20-poly1305")
            }
            DotLockError::MissingCommand => {
                Some("pass the command after `--`, e.g. `dotlock run -- node app.js`")
            }
            DotLockError::LocalIdentityNotInitialized => Some(
                "run `dotlock cert init` to create your local key pair before using shared access",
            ),
            DotLockError::LocalIdentityAlreadyInitialized => Some(
                "use `dotlock cert show` to inspect the existing identity, or delete it manually before reinitializing",
            ),
            DotLockError::RecipientNotFound { .. } => {
                Some("list current recipients with `dotlock share list`")
            }
            DotLockError::InvalidIdentityPassphrase => Some(
                "enter the passphrase used when `dotlock cert init` created this local identity",
            ),
            DotLockError::Aborted => None,
            DotLockError::CommandFailed { .. } => None,
            DotLockError::Crypto(_) | DotLockError::Io(_) => None,
        }
    }
}

impl From<std::io::Error> for DotLockError {
    fn from(err: std::io::Error) -> Self {
        DotLockError::Io(err.to_string())
    }
}
