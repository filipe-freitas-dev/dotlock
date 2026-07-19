use thiserror::Error;

#[derive(Error, Debug)]
pub enum DotLockError {
    #[error("invalid master password")]
    InvalidMasterPassword,

    #[error("no TTY available to prompt for the master password")]
    NoTtyForPassword,

    #[error("master password is weak: missing {missing}")]
    WeakPassword { missing: String },

    #[error("DotLock is not initialized in this directory")]
    ProjectNotInitialized,

    #[error("a DotLock vault already exists in `.lock/`")]
    ProjectAlreadyInitialized,

    #[error("environment `{name}` is not initialized in this project")]
    EnvironmentNotInitialized { name: String },

    #[error("environment `{name}` already exists")]
    EnvironmentAlreadyExists { name: String },

    #[error(
        "environment name `{name}` is invalid (use up to 32 ASCII letters, digits, `-` or `_`, starting with a letter or digit)"
    )]
    InvalidEnvironmentName { name: String },

    #[error(
        "vault is in a legacy format (missing vault UUID, secret UUIDs, or the integrity hash)"
    )]
    LegacyVaultFormat,

    #[error("secret `{name}` not found")]
    SecretNotFound { name: String },

    #[error("`.lock/secrets.lock` was modified outside of DotLock")]
    TamperedSecretsFile,

    #[error("`.lock/vault.toml` metadata failed authentication (modified outside of DotLock)")]
    MetadataTampered,

    #[error(
        "vault epoch {found} is older than the newest state seen on this machine ({last_seen}); refusing a potential rollback"
    )]
    VaultRolledBack { found: u64, last_seen: u64 },

    #[error("secret `{id}` has no key wrapping in `vault.toml` (`wrapped_sdks_under_kek`)")]
    MissingSecretKeyWrapping { id: String },

    #[error("vault has an unreconciled merge; run `dl reconcile`")]
    UnreconciledMerge,

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

    #[error("no command was provided to `dl run`")]
    MissingCommand,

    #[error("the command exited with status {status}")]
    CommandFailed { status: String },

    #[error("local identity is not initialized")]
    LocalIdentityNotInitialized,

    #[error("local identity already exists")]
    LocalIdentityAlreadyInitialized,

    #[error("shared recipient `{query}` not found")]
    RecipientNotFound { query: String },

    #[error("access denied to secret `{secret}`")]
    AccessDenied { secret: String },

    #[error("invalid identity passphrase")]
    InvalidIdentityPassphrase,

    #[error("cannot resolve the home/config directory; set HOME or DOTLOCK_HOME")]
    HomeDirUnavailable,

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
            DotLockError::NoTtyForPassword => Some(
                "set DOTLOCK_MASTER_PASSWORD, or pass --password-stdin / --password-file <path> (preferred: env vars can leak in CI logs and process listings)",
            ),
            DotLockError::WeakPassword { .. } => {
                Some("use at least 12 characters with lowercase, uppercase, a digit and a symbol")
            }
            DotLockError::ProjectNotInitialized => {
                Some("run `dl init` in this directory before using other commands")
            }
            DotLockError::ProjectAlreadyInitialized => {
                Some("use `set/get/list/unset`, or remove `.lock/` to start over")
            }
            DotLockError::EnvironmentNotInitialized { .. } => {
                Some("create it with `dl env add <name>`, or list existing ones with `dl env list`")
            }
            DotLockError::EnvironmentAlreadyExists { .. } => {
                Some("select it with `--env <name>` or `dl env use <name>`")
            }
            DotLockError::InvalidEnvironmentName { .. } => {
                Some("environment names become directory names under `.lock/envs/`")
            }
            DotLockError::LegacyVaultFormat => {
                Some("delete the `.lock/` directory and run `dl init` to create a fresh vault")
            }
            DotLockError::SecretNotFound { .. } => Some("list available secrets with `dl list`"),
            DotLockError::MetadataTampered => Some(
                "someone modified `.lock/vault.toml` outside DotLock; restore `.lock/` from a trusted backup or git revision",
            ),
            DotLockError::VaultRolledBack { .. } => Some(
                "the repo holds an older vault state than this machine has already seen; if this checkout of an older revision is intentional, re-run with DOTLOCK_ALLOW_VAULT_ROLLBACK=1",
            ),
            DotLockError::TamperedSecretsFile => Some(
                "someone modified `.lock/secrets.lock` outside DotLock; restore from a trusted backup or start over with `dl init`",
            ),
            DotLockError::MissingSecretKeyWrapping { .. } => Some(
                "the vault metadata and secrets file are out of sync; restore `.lock/` from a trusted git revision (e.g. `git checkout <rev> -- .lock/`) or re-set the secret with `dl set`",
            ),
            DotLockError::UnreconciledMerge => Some(
                "a git merge combined the vault files without re-signing them; run `dl reconcile` interactively to review and approve the merged content",
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
                Some("pass the command after `--`, e.g. `dl run -- node app.js`")
            }
            DotLockError::LocalIdentityNotInitialized => {
                Some("run `dl cert init` to create your local key pair before using shared access")
            }
            DotLockError::LocalIdentityAlreadyInitialized => Some(
                "use `dl cert show` to inspect the existing identity, or delete it manually before reinitializing",
            ),
            DotLockError::RecipientNotFound { .. } => {
                Some("list current recipients with `dl share list`")
            }
            DotLockError::AccessDenied { .. } => {
                Some("ask the vault owner to grant access to this secret")
            }
            DotLockError::InvalidIdentityPassphrase => {
                Some("enter the passphrase used when `dl cert init` created this local identity")
            }
            DotLockError::HomeDirUnavailable => Some(
                "DotLock refuses to write identities, key caches or audit logs into the current directory; export HOME (or DOTLOCK_HOME) pointing at a per-user directory",
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
