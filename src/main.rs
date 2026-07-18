use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use colored::Colorize;

use crate::{
    audit::{audit_log_path, record_ratchet, rotate_current_log, show_entries, verify_log},
    crypto::{ask_master_password, dek::generate_dek, update_master_password_metadata},
    domain::{
        error::DotLockError,
        keys::ProjectKey,
        model::{Alg, DotLockResult},
    },
    git::{
        fetch::auto_fetch_if_enabled,
        install::install_merge_driver_if_in_git_repo,
        merge::run_merge_driver,
        sync::{SyncStatus, sync_with_remote},
    },
    providers::{attest_provider, describe_provider, list_providers},
    runtime::{run_with_secrets, secret_value_for_runtime},
    storage::{
        cache::invalidate_cache,
        config::{config_lines, set_config_value, unset_config_value},
        env_file::{EnvEntry, merge_exported_env_content, parse_env_file, write_env_file},
        identity::{
            initialize_local_identity, initialize_local_identity_with_options, load_local_identity,
            private_key_path, public_key_path,
        },
        init_project::init_project,
        pending_merge::{
            PendingMergeMarker, confirmation_is_yes, load_marker, reconcile_pending_merge,
            verify_marker_matches_files,
        },
        project::{DOTLOCK_DIR, SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{
            DynamicSecretMetadata, PlainSecretEntry, SecretKind, decrypt_secret_value,
            find_secret_by_name, list_secrets, load_secrets_file, migrate_all_secrets_to_envelope,
            remove_secret_by_name, rotate_secret_sdks_after_acl_removal, upsert_dynamic_secret,
            upsert_many, upsert_plain_secret,
        },
        shared_access::{
            self, add_recipient_secret_ids, enable_shared_access, list_recipient_acl,
            list_recipients, load_public_key_from_file, revoke_recipient_and_rotate,
        },
        unlock_file::{
            UnlockAccess, unlock_full_for_reconcile, unlock_vault,
            unlock_vault_with_master_password, unlock_vault_with_master_password_and_passphrase,
        },
        vault_file::{
            RatchetSummary, load_vault_metadata, record_vault_write, rotate_project_key_wrapping,
            save_vault_metadata, should_auto_ratchet_for_next_write,
        },
        vault_txn::{VaultPairWrite, commit_vault_pair, recover_pending},
    },
    utils::{
        normalize_var_name, print_get_result, print_secrets_table, render_table, report_error,
    },
};

mod audit;
mod crypto;
mod domain;
mod git;
mod providers;
mod runtime;
mod storage;
mod utils;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "DotLock encrypts your project's environment variables."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
struct SetArgs {
    name: String,
    value: Option<String>,
    #[arg(short, long, value_enum, default_value_t = Alg::XChaCha20Poly1305)]
    alg: Alg,
    #[arg(long)]
    provider: Option<String>,
    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    bootstrap: Option<String>,
}

#[derive(Args, Debug)]
struct GetArgs {
    name: String,
}

#[derive(Args, Debug)]
struct UnsetArgs {
    name: String,
}

#[derive(Args, Debug)]
struct RunArgs {
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Args, Debug)]
struct MigrateArgs {
    /// Path to the .env file to import
    #[arg(default_value = ".env")]
    path: PathBuf,
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Path to the .env file to export
    #[arg(default_value = ".env")]
    path: PathBuf,
}

#[derive(Args, Debug)]
struct CertArgs {
    #[command(subcommand)]
    command: CertCommand,
}

#[derive(Subcommand, Debug)]
enum CertCommand {
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
struct ShareArgs {
    #[command(subcommand)]
    command: ShareCommand,
}

#[derive(Subcommand, Debug)]
enum ShareCommand {
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
struct RotateArgs {
    #[command(subcommand)]
    command: RotateCommand,
}

#[derive(Args, Debug)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
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
struct GitArgs {
    #[command(subcommand)]
    command: GitCommand,
}

#[derive(Subcommand, Debug)]
enum GitCommand {
    /// Install the DotLock merge driver in this Git clone
    #[command(alias = "i")]
    InstallMergeDriver,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Args, Debug)]
struct ProviderArgs {
    #[command(subcommand)]
    command: ProviderCommand,
}

#[derive(Subcommand, Debug)]
enum ProviderCommand {
    /// List dotlock-provider-* binaries on PATH
    #[command(alias = "l")]
    List,
    /// Show provider describe output
    #[command(alias = "i")]
    Info { name: String },
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
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
struct GitMergeArgs {
    ours: PathBuf,
    theirs: PathBuf,
    base: PathBuf,
}

#[derive(Subcommand, Debug)]
enum RotateCommand {
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(DotLockError::Aborted) => ExitCode::from(130),
        Err(err) => {
            report_error(&err);
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> DotLockResult<()> {
    match cli.command {
        Commands::Init => init_project(),

        Commands::Sync => {
            ensure_project_initialized()?;
            let summary = sync_with_remote(VAULT_FILE)?;
            match summary.status {
                SyncStatus::UpToDate => println!(
                    "{} vault already synced with {}/{}",
                    "ok:".green().bold(),
                    summary.remote,
                    summary.branch
                ),
                SyncStatus::FastForwarded => println!(
                    "{} vault synced from {}/{}",
                    "ok:".green().bold(),
                    summary.remote,
                    summary.branch
                ),
                SyncStatus::LocalAhead => println!(
                    "{} local branch is ahead of {}/{}; no pull needed",
                    "info:".cyan().bold(),
                    summary.remote,
                    summary.branch
                ),
            }
            Ok(())
        }

        Commands::Reconcile => {
            ensure_project_initialized()?;
            let vault_path = std::path::Path::new(VAULT_FILE);
            let secrets_path = std::path::Path::new(SECRETS_FILE);
            let lock_dir = std::path::Path::new(DOTLOCK_DIR);
            recover_pending(vault_path, secrets_path)?;

            let Some(marker) = load_marker(lock_dir)? else {
                println!("{} no pending merge to reconcile", "info:".cyan().bold());
                return Ok(());
            };
            // Anti-laundering: refuse before even prompting if the merged
            // files were edited after the merge driver produced them.
            verify_marker_matches_files(&marker, vault_path, secrets_path)?;

            print_merge_diff(&marker);
            print!("re-sign and accept the merged vault? [y/N] ");
            use std::io::Write as _;
            std::io::stdout().flush().ok();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(DotLockError::from)?;
            if !confirmation_is_yes(&answer) {
                println!(
                    "{} merge left unreconciled; resolve manually with `git checkout --ours -- .lock/` (or `--theirs`) and redo the merge, or run {} again to accept",
                    "info:".cyan().bold(),
                    "dl reconcile".bold()
                );
                return Err(DotLockError::Aborted);
            }

            let dek = unlock_full_for_reconcile(VAULT_FILE)?;
            reconcile_pending_merge(vault_path, secrets_path, lock_dir, &dek)?;
            storage::cache::write_cached_dek(&dek)?;
            println!(
                "{} merged vault reconciled and re-signed",
                "ok:".green().bold()
            );
            Ok(())
        }

        Commands::Git(GitArgs { command }) => match command {
            GitCommand::InstallMergeDriver => {
                if install_merge_driver_if_in_git_repo()? {
                    println!("{} Git merge driver installed", "ok:".green().bold());
                } else {
                    println!("{} not inside a Git work tree", "info:".cyan().bold());
                }
                Ok(())
            }
        },

        Commands::GitMerge(GitMergeArgs { ours, theirs, base }) => {
            run_merge_driver(&ours, &theirs, &base)
        }

        Commands::Config(ConfigArgs { command }) => {
            ensure_project_initialized()?;
            match command {
                ConfigCommand::Show => {
                    let metadata = load_vault_metadata(VAULT_FILE)?;
                    for line in config_lines(&metadata.config) {
                        println!("{line}");
                    }
                    Ok(())
                }
                ConfigCommand::Set { key, value } => {
                    set_config_value(std::path::Path::new(VAULT_FILE), &key, &value)?;
                    println!("{} config {} updated", "ok:".green().bold(), key.bold());
                    Ok(())
                }
                ConfigCommand::Unset { key } => {
                    unset_config_value(std::path::Path::new(VAULT_FILE), &key)?;
                    println!("{} config {} reset", "ok:".green().bold(), key.bold());
                    Ok(())
                }
            }
        }

        Commands::Provider(ProviderArgs { command }) => match command {
            ProviderCommand::List => {
                for provider in list_providers(None)? {
                    println!("{provider}");
                }
                Ok(())
            }
            ProviderCommand::Info { name } => {
                print!("{}", describe_provider(&name, None)?);
                Ok(())
            }
        },

        Commands::Audit(AuditArgs { command }) => match command {
            AuditCommand::Show {
                verbose,
                since,
                action,
            } => show_entries(verbose, since.as_deref(), action.as_deref()),
            AuditCommand::Verify { lax, strict: _ } => verify_log(!lax),
            AuditCommand::Path => {
                println!("{}", audit_log_path()?.display());
                Ok(())
            }
            AuditCommand::Rotate => {
                let path = audit_log_path()?;
                match rotate_current_log(&path)? {
                    Some(rotated) => println!("{}", rotated.display()),
                    None => println!("{} no audit log to rotate", "info:".cyan().bold()),
                }
                Ok(())
            }
        },

        Commands::Lock => {
            let removed = invalidate_cache()?;
            if removed {
                println!("{} session locked", "ok:".green().bold());
            } else {
                println!("{} no active session", "info:".cyan().bold());
            }
            Ok(())
        }

        Commands::Set(SetArgs {
            name,
            value,
            alg,
            provider,
            config,
            bootstrap,
        }) => {
            let name = normalize_var_name(&name)?;
            ensure_project_initialized()?;
            let dek = prepare_project_key_for_write(unlock_vault(VAULT_FILE)?)?;

            let secret = if let Some(provider) = provider {
                let _ = describe_provider(&provider, None)?;
                let attestation = attest_provider(&provider, None)?;
                let config = config
                    .as_deref()
                    .map(serde_json::from_str::<serde_json::Value>)
                    .transpose()
                    .map_err(|err| {
                        DotLockError::Io(format!("invalid provider config JSON: {err}"))
                    })?
                    .unwrap_or_else(|| serde_json::json!({}));
                let bootstrap = parse_csv_list(bootstrap.as_deref().unwrap_or(""));
                upsert_dynamic_secret(
                    SECRETS_FILE,
                    name,
                    DynamicSecretMetadata {
                        provider,
                        config,
                        bootstrap,
                        provider_path: Some(attestation.path.display().to_string()),
                        provider_sha256: Some(attestation.sha256),
                    },
                    &dek,
                    VAULT_FILE,
                )?
            } else {
                let value = value.ok_or_else(|| {
                    DotLockError::Io("static secrets require a VALUE argument".to_string())
                })?;
                upsert_plain_secret(SECRETS_FILE, name, value, alg, &dek, VAULT_FILE)?
            };

            println!(
                "{} secret {} saved",
                "ok:".green().bold(),
                secret.name.bold()
            );
            Ok(())
        }

        Commands::Get(GetArgs { name }) => {
            let name = normalize_var_name(&name)?;
            ensure_project_initialized()?;
            let dek = unlock_vault(VAULT_FILE)?.into_read_key();

            let secret = find_secret_by_name(&name)?;
            let all_secrets = load_secrets_file(SECRETS_FILE)?.secrets;
            let value =
                secret_value_for_runtime(&secret, &dek, &all_secrets)?.ok_or_else(|| {
                    DotLockError::AccessDenied {
                        secret: secret.name.clone(),
                    }
                })?;

            print_get_result(&secret.name, &secret.id, &value);
            Ok(())
        }

        Commands::List => {
            ensure_project_initialized()?;
            // Unlock (full or limited) is only an access gate for listing;
            // the key material is dropped (and zeroized) immediately.
            let _ = unlock_vault(VAULT_FILE)?;

            let mut entries = list_secrets()?;
            entries.sort_by(|a, b| a.name.cmp(&b.name));

            print_secrets_table(&entries);
            Ok(())
        }

        Commands::Unset(UnsetArgs { name }) => {
            let name = normalize_var_name(&name)?;
            ensure_project_initialized()?;
            let dek = prepare_project_key_for_write(unlock_vault(VAULT_FILE)?)?;

            remove_secret_by_name(&name, &dek, VAULT_FILE)?;

            println!("{} secret {} removed", "ok:".green().bold(), name.bold());
            Ok(())
        }

        Commands::Run(RunArgs { command }) => {
            ensure_project_initialized()?;
            auto_fetch_if_enabled(VAULT_FILE)?;
            let dek = unlock_vault(VAULT_FILE)?.into_read_key();
            run_with_secrets(command, &dek)
        }

        Commands::Migrate(MigrateArgs { path }) => {
            if !path.exists() {
                return Err(DotLockError::Io(format!(
                    "env file not found: {}",
                    path.display()
                )));
            }

            let raw_entries = parse_env_file(&path)?;
            if raw_entries.is_empty() {
                println!(
                    "{} no variables found in {}",
                    "info:".cyan().bold(),
                    path.display().to_string().bold()
                );
                return Ok(());
            }

            ensure_project_initialized()?;
            let dek = prepare_project_key_for_write(unlock_vault(VAULT_FILE)?)?;

            let mut prepared = Vec::with_capacity(raw_entries.len());
            for entry in raw_entries {
                let name = normalize_var_name(&entry.key)?;
                prepared.push(PlainSecretEntry {
                    name,
                    value: entry.value,
                    alg: Alg::XChaCha20Poly1305,
                });
            }

            let total = prepared.len();
            let summary = upsert_many(SECRETS_FILE, prepared, &dek, VAULT_FILE)?;

            println!(
                "{} imported {} from {}",
                "ok:".green().bold(),
                format!("{} secret{}", total, if total == 1 { "" } else { "s" }).bold(),
                path.display().to_string().bold()
            );
            println!(
                "     {} {} created, {} updated",
                "info:".cyan().bold(),
                summary.created.to_string().bold(),
                summary.updated.to_string().bold()
            );
            Ok(())
        }

        Commands::Export(ExportArgs { path }) => {
            ensure_project_initialized()?;
            let dek = unlock_vault(VAULT_FILE)?.into_read_key();
            let mut entries = decrypted_env_entries(&dek)?;
            entries.sort_by(|a, b| a.key.cmp(&b.key));

            let existing_content = if path.exists() {
                Some(storage::secure_fs::read_to_string(&path)?)
            } else {
                None
            };

            let merged = merge_exported_env_content(existing_content.as_deref(), &entries)?;
            if merged.added == 0 {
                println!(
                    "{} no missing variables to export into {}",
                    "info:".cyan().bold(),
                    path.display().to_string().bold()
                );
                return Ok(());
            }

            write_env_file(&path, &merged.content)?;
            println!(
                "{} exported {} to {}",
                "ok:".green().bold(),
                format!(
                    "{} variable{}",
                    merged.added,
                    if merged.added == 1 { "" } else { "s" }
                )
                .bold(),
                path.display().to_string().bold()
            );
            println!(
                "     {} {} already existed",
                "info:".cyan().bold(),
                merged.skipped.to_string().bold()
            );
            Ok(())
        }

        Commands::Cert(CertArgs { command }) => match command {
            CertCommand::Init { force, plain } => {
                let identity = if plain {
                    initialize_local_identity_with_options(force, true)?
                } else {
                    initialize_local_identity(force)?
                };
                if plain {
                    println!(
                        "{} local identity ready without passphrase ({})",
                        "ok:".green().bold(),
                        identity.fingerprint.bold()
                    );
                } else {
                    println!(
                        "{} local identity ready ({})",
                        "ok:".green().bold(),
                        identity.fingerprint.bold()
                    );
                }
                println!(
                    "     {} {}",
                    "private".dimmed(),
                    private_key_path()?.display()
                );
                println!(
                    "     {} {}",
                    "public".dimmed(),
                    public_key_path()?.display()
                );
                Ok(())
            }
            CertCommand::Show => {
                let identity = load_local_identity()?;
                println!(
                    "{} {}",
                    "fingerprint:".cyan().bold(),
                    identity.fingerprint.bold()
                );
                println!(
                    "{} {}",
                    "private:".cyan().bold(),
                    private_key_path()?.display()
                );
                println!(
                    "{} {}",
                    "public:".cyan().bold(),
                    public_key_path()?.display()
                );
                Ok(())
            }
            CertCommand::ExportPub { path } => {
                let identity = load_local_identity()?;
                if let Some(path) = path {
                    storage::secure_fs::write_string_atomic(
                        &path,
                        &identity.public_key_pem,
                        0o700,
                        0o644,
                    )?;
                    println!(
                        "{} public key exported to {}",
                        "ok:".green().bold(),
                        path.display().to_string().bold()
                    );
                } else {
                    print!("{}", identity.public_key_pem);
                }
                Ok(())
            }
        },

        Commands::Share(ShareArgs { command }) => match command {
            ShareCommand::Enable => {
                ensure_project_initialized()?;
                let changed = enable_shared_access(VAULT_FILE)?;
                if changed {
                    println!("{} shared access enabled", "ok:".green().bold());
                } else {
                    println!("{} shared access already enabled", "info:".cyan().bold());
                }
                Ok(())
            }
            ShareCommand::Grant {
                pubkey,
                label,
                allow,
            } => {
                ensure_project_initialized()?;
                let dek = unlock_vault_with_master_password(VAULT_FILE)?;
                migrate_all_secrets_to_envelope(&dek, VAULT_FILE)?;
                let public_key_pem = load_public_key_from_file(&pubkey)?;
                let allowed_ids = allow.as_deref().map(resolve_secret_ids_csv).transpose()?;
                // Grants must be signed by an authorized signer (H3): the
                // granting user just proved master-password authority, so
                // their local identity signs the grant (and blesses any
                // legacy unsigned recipients on pre-signed-grant vaults).
                let signer = storage::identity::load_local_identity()?;
                let recipient = shared_access::grant_recipient_with_secret_ids(
                    VAULT_FILE,
                    &public_key_pem,
                    &label,
                    &dek,
                    allowed_ids.as_deref(),
                    Some(&signer),
                )?;
                println!(
                    "{} access granted to {} ({})",
                    "ok:".green().bold(),
                    recipient.label.bold(),
                    recipient.public_key_fingerprint.yellow()
                );
                Ok(())
            }
            ShareCommand::Revoke { query } => {
                ensure_project_initialized()?;
                let (dek, passphrase) =
                    unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
                let outcome = revoke_recipient_and_rotate(
                    VAULT_FILE,
                    SECRETS_FILE,
                    &query,
                    &dek,
                    &passphrase,
                )?;
                invalidate_cache()?;
                println!(
                    "{} access revoked for {} ({}); project key rotated",
                    "ok:".green().bold(),
                    outcome.removed.label.bold(),
                    outcome.removed.public_key_fingerprint.yellow()
                );
                print_ratchet_summary(&outcome.summary);
                println!(
                    "     {} the revoked identity may still hold previously fetched ciphertexts (e.g. from git history); rotate sensitive values with {}",
                    "info:".cyan().bold(),
                    "dl set".bold()
                );
                Ok(())
            }
            ShareCommand::Allow {
                query,
                add,
                remove,
                list,
            } => {
                ensure_project_initialized()?;
                if list {
                    let ids = list_recipient_acl(VAULT_FILE, &query)?;
                    for name in secret_names_for_ids(&ids)? {
                        println!("{name}");
                    }
                    return Ok(());
                }

                let dek = unlock_vault_with_master_password(VAULT_FILE)?;
                migrate_all_secrets_to_envelope(&dek, VAULT_FILE)?;

                if let Some(add) = add {
                    let ids = resolve_secret_ids_csv(&add)?;
                    let added = add_recipient_secret_ids(VAULT_FILE, &query, &ids, &dek)?;
                    println!(
                        "{} added {} secret{} to {}",
                        "ok:".green().bold(),
                        added.to_string().bold(),
                        if added == 1 { "" } else { "s" },
                        query.bold()
                    );
                    return Ok(());
                }

                if let Some(remove) = remove {
                    let ids = resolve_secret_ids_csv(&remove)?;
                    rotate_secret_sdks_after_acl_removal(&ids, &query, &dek, VAULT_FILE)?;
                    println!(
                        "{} removed {} secret{} from {}",
                        "ok:".green().bold(),
                        ids.len().to_string().bold(),
                        if ids.len() == 1 { "" } else { "s" },
                        query.bold()
                    );
                    return Ok(());
                }

                Err(DotLockError::Io(
                    "pass --list, --add SECRET[,SECRET], or --remove SECRET[,SECRET]".to_string(),
                ))
            }
            ShareCommand::List => {
                ensure_project_initialized()?;
                let mut recipients = list_recipients(VAULT_FILE)?;
                recipients.sort_by(|a, b| a.label.cmp(&b.label));
                print_recipients_table(&recipients);
                Ok(())
            }
        },

        Commands::Rotate(RotateArgs { command }) => match command {
            RotateCommand::MasterPassword => {
                ensure_project_initialized()?;
                let dek = unlock_vault_with_master_password(VAULT_FILE)?;
                let mut metadata = load_vault_metadata(VAULT_FILE)?;
                let passphrase = ask_master_password()?;
                update_master_password_metadata(&mut metadata, &dek, &passphrase)?;
                record_vault_write(&mut metadata);
                save_vault_metadata(VAULT_FILE, &metadata)?;
                println!("{} master password rotated", "ok:".green().bold());
                Ok(())
            }
            RotateCommand::Kek => {
                ensure_project_initialized()?;
                let (dek, passphrase) =
                    unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
                let (_new_dek, summary) = rotate_project_key(&dek, &passphrase)?;
                print_ratchet_summary(&summary);
                Ok(())
            }
            RotateCommand::ProjectKey => {
                ensure_project_initialized()?;
                let (dek, passphrase) =
                    unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
                let (_new_dek, _) = rotate_project_key(&dek, &passphrase)?;
                println!("{} project key rotated", "ok:".green().bold());
                Ok(())
            }
        },
    }
}

/// Human-readable summary of what a merge changed — secret names only, never
/// values.
fn print_merge_diff(marker: &PendingMergeMarker) {
    println!(
        "{} a git merge combined the vault files; the integrity hash must be re-signed",
        "info:".cyan().bold()
    );
    if marker.added.is_empty() && marker.changed.is_empty() && marker.removed.is_empty() {
        println!(
            "     {} vault metadata merged (no secret changes)",
            "info:".cyan().bold()
        );
    }
    for name in &marker.added {
        println!("     {} {}", "added".green().bold(), name.bold());
    }
    for name in &marker.changed {
        println!("     {} {}", "changed".yellow().bold(), name.bold());
    }
    for name in &marker.removed {
        println!("     {} {}", "removed".red().bold(), name.bold());
    }
    for entry in &marker.rejected_recipients {
        println!(
            "     {} recipient {} (no valid grant signature; not absorbed)",
            "rejected".red().bold(),
            entry.bold()
        );
    }
    for entry in &marker.rejected_signers {
        println!(
            "     {} authorized signer {} (unknown to this side; not absorbed)",
            "rejected".red().bold(),
            entry.bold()
        );
    }
}

fn prepare_project_key_for_write(access: UnlockAccess) -> DotLockResult<ProjectKey> {
    let current_dek = access.require_full()?;
    let metadata = load_vault_metadata(VAULT_FILE)?;
    if !should_auto_ratchet_for_next_write(&metadata) {
        return Ok(current_dek);
    }

    let (verified_dek, passphrase) = unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
    let (new_dek, summary) = rotate_project_key(&verified_dek, &passphrase)?;
    print_ratchet_summary(&summary);
    Ok(new_dek)
}

fn rotate_project_key(
    current_dek: &ProjectKey,
    passphrase: &str,
) -> DotLockResult<(ProjectKey, RatchetSummary)> {
    let mut metadata = load_vault_metadata(VAULT_FILE)?;
    let new_dek = generate_dek()?;
    // rotate_project_key_wrapping rewraps the SDKs/recipient wrappings AND
    // re-encrypts `secrets_hash_*` under the new DEK in the same metadata
    // object; one transactional commit makes the whole rotation atomic
    // (secrets.lock is unchanged by rotation). `dl rotate` rotates the DEK.
    let summary = rotate_project_key_wrapping(&mut metadata, current_dek, &new_dek)?;
    update_master_password_metadata(&mut metadata, &new_dek, passphrase)?;
    commit_vault_pair(
        std::path::Path::new(VAULT_FILE),
        std::path::Path::new(SECRETS_FILE),
        VaultPairWrite {
            metadata: &metadata,
            secrets_lock_bytes: None,
        },
    )?;
    record_ratchet_best_effort(&summary);
    invalidate_cache()?;
    Ok((new_dek, summary))
}

fn record_ratchet_best_effort(summary: &RatchetSummary) {
    if let Err(err) = record_ratchet(
        summary.old_kek_version,
        summary.new_kek_version,
        summary.secrets_rewrapped,
        summary.recipients_rewrapped,
    ) {
        eprintln!(
            "{} audit log write failed: {}",
            "warn:".yellow().bold(),
            err
        );
    }
}

fn print_ratchet_summary(summary: &RatchetSummary) {
    println!(
        "{} key wrapping rotated (kek_version {} -> {}, {} SDK{}, {} recipient{})",
        "ok:".green().bold(),
        summary.old_kek_version,
        summary.new_kek_version,
        summary.secrets_rewrapped.to_string().bold(),
        if summary.secrets_rewrapped == 1 {
            ""
        } else {
            "s"
        },
        summary.recipients_rewrapped.to_string().bold(),
        if summary.recipients_rewrapped == 1 {
            ""
        } else {
            "s"
        }
    );
    if summary.recipients_skipped > 0 {
        println!(
            "{} {} recipient{} skipped: grant signature did not verify against an authorized signer (re-grant with `dl share grant` or revoke)",
            "warn:".yellow().bold(),
            summary.recipients_skipped.to_string().bold(),
            if summary.recipients_skipped == 1 {
                ""
            } else {
                "s"
            }
        );
    }
}

fn decrypted_env_entries(dek: &ProjectKey) -> DotLockResult<Vec<EnvEntry>> {
    let mut secrets = load_secrets_file(SECRETS_FILE)?.secrets;
    secrets.sort_by(|a, b| a.name.cmp(&b.name));

    let mut entries = Vec::with_capacity(secrets.len());
    for secret in secrets {
        if !matches!(secret.kind, SecretKind::Static) {
            continue;
        }
        let value = decrypt_secret_value(&secret, dek)?;
        entries.push(EnvEntry {
            key: secret.name,
            value,
        });
    }

    Ok(entries)
}

fn resolve_secret_ids_csv(value: &str) -> DotLockResult<Vec<String>> {
    let file = load_secrets_file(SECRETS_FILE)?;
    value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            file.secrets
                .iter()
                .find(|secret| secret.name == name)
                .map(|secret| secret.id.clone())
                .ok_or_else(|| DotLockError::SecretNotFound {
                    name: name.to_string(),
                })
        })
        .collect()
}

fn parse_csv_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn secret_names_for_ids(ids: &[String]) -> DotLockResult<Vec<String>> {
    let file = load_secrets_file(SECRETS_FILE)?;
    let mut names = ids
        .iter()
        .filter_map(|id| {
            file.secrets
                .iter()
                .find(|secret| &secret.id == id)
                .map(|secret| secret.name.clone())
        })
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn print_recipients_table(recipients: &[crypto::VaultRecipient]) {
    if recipients.is_empty() {
        println!("{} no shared recipients", "info:".cyan().bold());
        return;
    }

    let rows: Vec<Vec<String>> = recipients
        .iter()
        .map(|recipient| {
            let access = if recipient.full_access {
                "*".to_string()
            } else {
                recipient.wrapped_sdks.len().to_string()
            };
            vec![
                recipient.label.clone(),
                recipient.public_key_fingerprint.clone(),
                access,
            ]
        })
        .collect();

    println!();
    render_table(
        &["LABEL", "FINGERPRINT", "ACCESS"],
        &rows,
        &[|s| s.bold(), |s| s.yellow()],
    );
    println!();
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
