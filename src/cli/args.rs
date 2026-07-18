use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::domain::model::Alg;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "DotLock encrypts your project's environment variables."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Set a variable
    #[command(alias = "s")]
    #[command(alias = "add")]
    Set(SetArgs),
    /// Get a variable
    #[command(alias = "g")]
    Get(GetArgs),
    /// Remove a variable
    #[command(alias = "rm")]
    #[command(alias = "remove")]
    #[command(alias = "u")]
    #[command(alias = "d")]
    #[command(alias = "del")]
    #[command(alias = "delete")]
    Unset(UnsetArgs),
    /// List variables
    #[command(alias = "l")]
    List,
    /// Initialize DotLock in the current directory
    #[command(alias = "i")]
    Init,
    /// Run a command with decrypted variables in its environment
    #[command(alias = "r")]
    Run(RunArgs),
    /// Drop the cached master password (sudo-style logout)
    #[command(alias = "k")]
    #[command(alias = "logout")]
    Lock,
    /// Import variables from a .env file
    #[command(alias = "m")]
    #[command(alias = "import")]
    Migrate(MigrateArgs),
    /// Export variables to a .env file
    #[command(alias = "x")]
    Export(ExportArgs),
    /// Manage the local identity used for shared access
    #[command(alias = "crt")]
    Cert(CertArgs),
    /// Manage shared project access
    #[command(alias = "shr")]
    Share(ShareArgs),
    /// Rotate project access material
    #[command(alias = "rot")]
    Rotate(RotateArgs),
    /// Show and verify the local audit log
    #[command(alias = "a")]
    Audit(AuditArgs),
    /// Manage Git integration
    #[command(alias = "gt")]
    Git(GitArgs),
    /// Manage project configuration
    #[command(alias = "c")]
    Config(ConfigArgs),
    /// Discover dynamic secret providers
    #[command(alias = "p")]
    Provider(ProviderArgs),
    /// Synchronize the local vault with the configured Git remote
    #[command(alias = "sy")]
    Sync,
    /// Review and re-sign a vault combined by the Git merge driver
    #[command(alias = "rec")]
    Reconcile,
    /// Git merge-driver entrypoint
    #[command(name = "_git-merge", hide = true)]
    GitMerge(GitMergeArgs),
}

#[derive(Args, Debug)]
pub struct SetArgs {
    pub name: String,
    pub value: Option<String>,
    #[arg(short, long, value_enum, default_value_t = Alg::XChaCha20Poly1305)]
    pub alg: Alg,
    #[arg(long)]
    pub provider: Option<String>,
    #[arg(long)]
    pub config: Option<String>,
    #[arg(long)]
    pub bootstrap: Option<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    pub name: String,
}

#[derive(Args, Debug)]
pub struct UnsetArgs {
    pub name: String,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// Path to the .env file to import
    #[arg(default_value = ".env")]
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Path to the .env file to export
    #[arg(default_value = ".env")]
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct CertArgs {
    #[command(subcommand)]
    pub command: CertCommand,
}

#[derive(Subcommand, Debug)]
pub enum CertCommand {
    /// Generate a local key pair for shared access
    #[command(alias = "i")]
    Init {
        #[arg(long, short)]
        force: bool,
        #[arg(long, short = 'p')]
        plain: bool,
    },
    /// Show the local identity fingerprint and paths
    #[command(alias = "sh")]
    Show,
    /// Print or save the local public key
    #[command(alias = "x")]
    ExportPub { path: Option<PathBuf> },
}

#[derive(Args, Debug)]
pub struct ShareArgs {
    #[command(subcommand)]
    pub command: ShareCommand,
}

#[derive(Subcommand, Debug)]
pub enum ShareCommand {
    /// Turn the current project into shared mode
    #[command(alias = "en")]
    Enable,
    /// Grant project access to a public key
    #[command(alias = "gr")]
    Grant {
        #[arg(long, short)]
        pubkey: PathBuf,
        #[arg(long, short)]
        label: String,
        #[arg(long)]
        allow: Option<String>,
    },
    /// Revoke project access from a recipient
    #[command(alias = "rev")]
    Revoke { query: String },
    /// Manage a recipient's per-secret access list
    #[command(alias = "al")]
    Allow {
        query: String,
        #[arg(long)]
        add: Option<String>,
        #[arg(long)]
        remove: Option<String>,
        #[arg(long)]
        list: bool,
    },
    /// List current recipients
    #[command(alias = "l")]
    List,
}

#[derive(Args, Debug)]
pub struct RotateArgs {
    #[command(subcommand)]
    pub command: RotateCommand,
}

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// List audit log entries
    #[command(alias = "s")]
    Show {
        #[arg(long)]
        verbose: bool,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        action: Option<String>,
    },
    /// Verify audit hash-chain and signatures (strict by default: anonymous
    /// entries and an unsigned high-water mark fail verification)
    #[command(alias = "v")]
    Verify {
        /// Accept anonymous/unsigned entries and an unsigned high-water mark
        #[arg(long)]
        lax: bool,
        /// Deprecated: strict verification is now the default
        #[arg(long, hide = true)]
        strict: bool,
    },
    /// Print the current audit log path
    #[command(alias = "p")]
    Path,
    /// Rotate the current audit log
    #[command(alias = "r")]
    Rotate,
}

#[derive(Args, Debug)]
pub struct GitArgs {
    #[command(subcommand)]
    pub command: GitCommand,
}

#[derive(Subcommand, Debug)]
pub enum GitCommand {
    /// Install the DotLock merge driver in this Git clone
    #[command(alias = "i")]
    InstallMergeDriver,
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Args, Debug)]
pub struct ProviderArgs {
    #[command(subcommand)]
    pub command: ProviderCommand,
}

#[derive(Subcommand, Debug)]
pub enum ProviderCommand {
    /// List dotlock-provider-* binaries on PATH
    #[command(alias = "l")]
    List,
    /// Show provider describe output
    #[command(alias = "i")]
    Info { name: String },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Show project configuration
    #[command(alias = "sh")]
    Show,
    /// Set a project configuration value
    #[command(alias = "s")]
    Set { key: String, value: String },
    /// Reset a project configuration value to its default
    #[command(alias = "u")]
    Unset { key: String },
}

#[derive(Args, Debug)]
pub struct GitMergeArgs {
    pub ours: PathBuf,
    pub theirs: PathBuf,
    pub base: PathBuf,
}

#[derive(Subcommand, Debug)]
pub enum RotateCommand {
    /// Rotate the project key (DEK) and rewrap the secret data keys
    /// (historical name; does the same as `project-key` — the KEK only ever
    /// wraps the DEK and is re-derived from the master password)
    #[command(alias = "k")]
    Kek,
    /// Change the master password wrapping the project key
    #[command(alias = "mp")]
    MasterPassword,
    /// Generate a new project key (DEK) and rewrap the secret data keys
    /// (secret ciphertexts are unchanged; only their wrappings move)
    #[command(alias = "pk")]
    ProjectKey,
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use super::{
        AuditArgs, AuditCommand, CertArgs, CertCommand, Cli, Commands, ConfigArgs, ConfigCommand,
        GitArgs, GitCommand, ProviderArgs, ProviderCommand, RotateArgs, RotateCommand, ShareArgs,
        ShareCommand,
    };

    #[test]
    fn parses_top_level_canonical_aliases() {
        assert!(matches!(
            Cli::try_parse_from(["dl", "sy"])
                .expect("sync alias")
                .command,
            Commands::Sync
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "k"])
                .expect("lock alias")
                .command,
            Commands::Lock
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "rot", "k"])
                .expect("rotate alias")
                .command,
            Commands::Rotate(RotateArgs {
                command: RotateCommand::Kek
            })
        ));
    }

    #[test]
    fn parses_nested_canonical_aliases() {
        assert!(matches!(
            Cli::try_parse_from(["dl", "crt", "sh"])
                .expect("cert alias")
                .command,
            Commands::Cert(CertArgs {
                command: CertCommand::Show
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "shr", "al", "alice", "--list"])
                .expect("share alias")
                .command,
            Commands::Share(ShareArgs {
                command: ShareCommand::Allow { .. }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "a", "p"])
                .expect("audit alias")
                .command,
            Commands::Audit(AuditArgs {
                command: AuditCommand::Path
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "gt", "i"])
                .expect("git alias")
                .command,
            Commands::Git(GitArgs {
                command: GitCommand::InstallMergeDriver
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "c", "sh"])
                .expect("config alias")
                .command,
            Commands::Config(ConfigArgs {
                command: ConfigCommand::Show
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "p", "l"])
                .expect("provider alias")
                .command,
            Commands::Provider(ProviderArgs {
                command: ProviderCommand::List
            })
        ));
    }
}
