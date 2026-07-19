use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::domain::model::Alg;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "DotLock encrypts your project's environment variables."
)]
pub struct Cli {
    /// Read the master password from the first line of stdin (FG2). Preferred
    /// for CI over DOTLOCK_MASTER_PASSWORD, which can leak through process
    /// listings and CI log captures of the environment.
    #[arg(long, global = true, conflicts_with = "password_file")]
    pub password_stdin: bool,
    /// Read the master password from the first line of FILE (FG2). The file
    /// is opened with the same symlink-safe reader used for vault files.
    #[arg(long, global = true, value_name = "FILE")]
    pub password_file: Option<PathBuf>,
    /// Emit machine-readable JSON on stdout instead of human-formatted output
    /// (supported by `list`, `get`, `share list`, `audit show`,
    /// `provider list`) (FG1).
    #[arg(long, global = true)]
    pub json: bool,
    /// Operate on this environment's vault (FG3). Each environment is an
    /// independent vault pair: the default one lives in `.lock/`, named ones
    /// under `.lock/envs/<NAME>/` (create with `dl env add`). Falls back to
    /// DOTLOCK_ENV, then to the selection persisted by `dl env use`;
    /// `--env default` always forces the default environment.
    #[arg(long, global = true, value_name = "NAME")]
    pub env: Option<String>,
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
    /// Run a shell command line with decrypted variables in its environment
    /// (FG4). The string is executed via `sh -c`; secrets are injected as
    /// environment variables only and are never interpolated into the command
    /// string. Prefer `dl run -- cmd args` (no shell) when you do not need
    /// shell syntax.
    #[command(alias = "e")]
    Exec(ExecArgs),
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
    /// Manage project environments (dev/staging/prod) (FG3)
    #[command(alias = "ev")]
    Env(EnvArgs),
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
    /// Diagnose and recover a vault whose integrity hash is out of sync
    /// (FG6). Requires a valid full-access unlock — repair is a recovery
    /// path, never a tamper bypass.
    #[command(alias = "rep")]
    Repair(RepairArgs),
    /// Git merge-driver entrypoint
    #[command(name = "_git-merge", hide = true)]
    GitMerge(GitMergeArgs),
}

#[derive(Args, Debug)]
pub struct SetArgs {
    pub name: String,
    /// Secret value. Prefer omitting it: with no VALUE, `dl set` reads the
    /// secret from a hidden prompt (or from stdin with `--stdin`), keeping it
    /// out of `ps`, `/proc/<pid>/cmdline` and shell history (M8).
    pub value: Option<String>,
    /// Read the secret value from stdin (for pipes/scripts) instead of the
    /// interactive hidden prompt.
    #[arg(long)]
    pub stdin: bool,
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
    /// Load additional PLAINTEXT variables from a .env file (FG4 migration
    /// aid). Vault secrets always win on name collision; env-file values are
    /// not encrypted and not covered by the vault's integrity checks.
    #[arg(long, value_name = "FILE")]
    pub env_file: Option<PathBuf>,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ExecArgs {
    /// Load additional PLAINTEXT variables from a .env file (FG4 migration
    /// aid). Vault secrets always win on name collision; env-file values are
    /// not encrypted and not covered by the vault's integrity checks.
    #[arg(long, value_name = "FILE")]
    pub env_file: Option<PathBuf>,
    /// Shell command line, executed as `sh -c "<command>"`. Multiple words
    /// are joined with spaces, so both `dl exec "npm start && node x.js"`
    /// and `dl exec npm start` work.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RepairArgs {
    /// Print the diagnosis only; never modify anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Skip the interactive confirmation (for scripted recovery).
    #[arg(long, short)]
    pub yes: bool,
    /// Remove records that are irrecoverable (missing SDK wrapping or failed
    /// AEAD) and reseal the rest. Data loss is explicit and enumerated —
    /// without this flag, repair only reports them and exits non-zero.
    #[arg(long)]
    pub prune: bool,
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
#[command(args_conflicts_with_subcommands = true)]
pub struct RotateArgs {
    /// Rotate the project key only when a rotation is due per the configured
    /// policy (FG5): `rotate_max_age_days` (age since last rotation) or
    /// `auto_ratchet_after_writes` (write count). Exits 0 without rotating
    /// (and without prompting for the password) when nothing is due —
    /// cron/CI friendly.
    #[arg(long)]
    pub if_due: bool,
    #[command(subcommand)]
    pub command: Option<RotateCommand>,
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
    /// Worktree pathname of the merge result (`%P`), used to route
    /// env-scoped vault pairs (FG3). Optional so clones configured by older
    /// DotLock versions (3-arg driver) keep merging the default environment.
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct EnvArgs {
    #[command(subcommand)]
    pub command: EnvCommand,
}

#[derive(Subcommand, Debug)]
pub enum EnvCommand {
    /// List this project's environments
    #[command(alias = "l")]
    List,
    /// Create a new environment with its own independent vault pair
    /// (fresh salt/KEK/DEK; prompts for that environment's master password)
    #[command(alias = "a")]
    Add { name: String },
    /// Persist NAME as this checkout's default environment (in the
    /// non-secret `.lock/env` file); `dl env use default` reverts
    #[command(alias = "u")]
    Use { name: String },
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
    fn parses_global_json_and_password_flags_in_any_position() {
        // Global flags are accepted before or after the subcommand.
        let cli = Cli::try_parse_from(["dl", "list", "--json"]).expect("list --json");
        assert!(cli.json);
        assert!(matches!(cli.command, Commands::List));

        let cli = Cli::try_parse_from(["dl", "--json", "get", "FOO"]).expect("--json get");
        assert!(cli.json);

        let cli =
            Cli::try_parse_from(["dl", "get", "FOO", "--password-stdin"]).expect("password-stdin");
        assert!(cli.password_stdin);
        assert!(cli.password_file.is_none());

        let cli = Cli::try_parse_from(["dl", "init", "--password-file", "/tmp/pw"])
            .expect("password-file");
        assert_eq!(
            cli.password_file.as_deref(),
            Some(std::path::Path::new("/tmp/pw"))
        );

        // The two explicit sources are mutually exclusive.
        assert!(
            Cli::try_parse_from([
                "dl",
                "list",
                "--password-stdin",
                "--password-file",
                "/tmp/pw"
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_global_env_flag_and_env_subcommand() {
        use super::{EnvArgs, EnvCommand};

        // FG3: --env is global (before or after the subcommand).
        let cli = Cli::try_parse_from(["dl", "--env", "staging", "get", "FOO"]).expect("--env get");
        assert_eq!(cli.env.as_deref(), Some("staging"));
        let cli = Cli::try_parse_from(["dl", "list", "--env", "prod"]).expect("list --env");
        assert_eq!(cli.env.as_deref(), Some("prod"));
        let cli = Cli::try_parse_from(["dl", "list"]).expect("list");
        assert!(cli.env.is_none());

        // `dl env` management subcommands and aliases.
        assert!(matches!(
            Cli::try_parse_from(["dl", "env", "add", "staging"])
                .expect("env add")
                .command,
            Commands::Env(EnvArgs {
                command: EnvCommand::Add { ref name }
            }) if name == "staging"
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "ev", "l"])
                .expect("env list alias")
                .command,
            Commands::Env(EnvArgs {
                command: EnvCommand::List
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["dl", "ev", "u", "default"])
                .expect("env use alias")
                .command,
            Commands::Env(EnvArgs {
                command: EnvCommand::Use { ref name }
            }) if name == "default"
        ));

        // The hidden merge driver accepts the optional 4th `%P` argument
        // (and still parses without it for pre-FG3 clone configs).
        let cli = Cli::try_parse_from(["dl", "_git-merge", "a", "b", "o"]).expect("3-arg merge");
        assert!(matches!(cli.command, Commands::GitMerge(ref args) if args.path.is_none()));
        let cli = Cli::try_parse_from([
            "dl",
            "_git-merge",
            "a",
            "b",
            "o",
            ".lock/envs/staging/vault.toml",
        ])
        .expect("4-arg merge");
        assert!(matches!(
            cli.command,
            Commands::GitMerge(ref args)
                if args.path.as_deref()
                    == Some(std::path::Path::new(".lock/envs/staging/vault.toml"))
        ));
    }

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
                command: Some(RotateCommand::Kek),
                if_due: false
            })
        ));
    }

    #[test]
    fn parses_rotate_if_due_and_rejects_it_with_a_subcommand() {
        // FG5: `dl rotate --if-due` needs no subcommand...
        assert!(matches!(
            Cli::try_parse_from(["dl", "rotate", "--if-due"])
                .expect("rotate --if-due")
                .command,
            Commands::Rotate(RotateArgs {
                command: None,
                if_due: true
            })
        ));
        // ...and conflicts with an explicit rotation subcommand.
        assert!(Cli::try_parse_from(["dl", "rotate", "--if-due", "project-key"]).is_err());
    }

    #[test]
    fn parses_exec_shell_form_and_repair_flags() {
        // FG4: shell-form command line with hyphenated words.
        let cli = Cli::try_parse_from(["dl", "exec", "--env-file", ".env", "npm start --watch"])
            .expect("exec");
        let Commands::Exec(args) = cli.command else {
            panic!("expected exec");
        };
        assert_eq!(args.command, vec!["npm start --watch"]);
        assert_eq!(args.env_file.as_deref(), Some(std::path::Path::new(".env")));

        // FG6: repair flags.
        let cli = Cli::try_parse_from(["dl", "repair", "--dry-run"]).expect("repair dry-run");
        let Commands::Repair(args) = cli.command else {
            panic!("expected repair");
        };
        assert!(args.dry_run && !args.yes && !args.prune);
        let cli = Cli::try_parse_from(["dl", "repair", "--prune", "--yes"]).expect("repair prune");
        let Commands::Repair(args) = cli.command else {
            panic!("expected repair");
        };
        assert!(!args.dry_run && args.yes && args.prune);
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
