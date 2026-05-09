use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    audit::{audit_log_path, record_ratchet, rotate_current_log, show_entries, verify_log},
    crypto::{
        ask_master_password,
        dek::generate_dek,
        secret_cipher::{decryption_process, encryption_process},
        update_master_password_metadata,
    },
    domain::{
        error::DotLockError,
        model::{Alg, DotLockResult},
    },
    git::{
        fetch::auto_fetch_if_enabled, install::install_merge_driver_if_in_git_repo,
        merge::run_merge_driver,
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
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{
            DynamicSecretMetadata, PlainSecretEntry, SecretKind, SecretRecord,
            decrypt_secret_value, find_secret_by_name, list_secrets, load_secrets_file,
            migrate_all_secrets_to_envelope, remove_secret_by_name,
            rotate_secret_sdks_after_acl_removal, save_secrets_file, upsert_dynamic_secret,
            upsert_many, upsert_plain_secret,
        },
        shared_access::{
            self, add_recipient_secret_ids, enable_shared_access, grant_recipient,
            list_recipient_acl, list_recipients, load_public_key_from_file,
            revoke_recipient_in_memory, rewrap_recipients,
        },
        unlock_file::{
            unlock_vault, unlock_vault_with_master_password,
            unlock_vault_with_master_password_and_passphrase,
        },
        vault_file::{
            RatchetSummary, load_vault_metadata, record_vault_write, rotate_kek_wrapping,
            save_vault_metadata, should_auto_ratchet_for_next_write,
        },
    },
    utils::{normalize_var_name, parse_alg, print_get_result, print_secrets_table, report_error},
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
    Rotate(RotateArgs),
    /// Show and verify the local audit log
    #[command(alias = "a")]
    Audit(AuditArgs),
    /// Manage Git integration
    Git(GitArgs),
    /// Manage project configuration
    #[command(alias = "c")]
    Config(ConfigArgs),
    /// Discover dynamic secret providers
    #[command(alias = "p")]
    Provider(ProviderArgs),
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
    /// Verify audit hash-chain and signatures
    #[command(alias = "v")]
    Verify {
        #[arg(long)]
        strict: bool,
    },
    /// Print the current audit log path
    Path,
    /// Rotate the current audit log
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
    List,
    /// Show provider describe output
    Info { name: String },
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Show project configuration
    Show,
    /// Set a project configuration value
    Set { key: String, value: String },
    /// Reset a project configuration value to its default
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
    /// Rotate only the key wrapping secret data keys
    Kek,
    /// Change the master password wrapping the project key
    #[command(alias = "mp")]
    MasterPassword,
    /// Generate a new project key and re-encrypt the secrets
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
            AuditCommand::Verify { strict } => verify_log(strict),
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
            let dek = unlock_vault(VAULT_FILE)?;

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
            let mut dek = unlock_vault(VAULT_FILE)?;
            dek.zeroize();

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
            let dek = unlock_vault(VAULT_FILE)?;
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
            let dek = unlock_vault(VAULT_FILE)?;
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
                    private_key_path().display()
                );
                println!("     {} {}", "public".dimmed(), public_key_path().display());
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
                    private_key_path().display()
                );
                println!(
                    "{} {}",
                    "public:".cyan().bold(),
                    public_key_path().display()
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
                let recipient = if let Some(ids) = allowed_ids.as_ref() {
                    shared_access::grant_recipient_with_secret_ids(
                        VAULT_FILE,
                        &public_key_pem,
                        &label,
                        &dek,
                        Some(ids),
                    )?
                } else {
                    grant_recipient(VAULT_FILE, &public_key_pem, &label, &dek)?
                };
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
                let mut metadata = load_vault_metadata(VAULT_FILE)?;
                let mut secrets_file = load_secrets_file(SECRETS_FILE)?;
                let removed = revoke_recipient_in_memory(&mut metadata, &query)?;
                let new_dek = generate_dek().map_err(|e| DotLockError::Crypto(e.to_string()))?;

                for secret in &mut secrets_file.secrets {
                    reencrypt_secret(secret, &dek, &new_dek)?;
                }

                update_master_password_metadata(&mut metadata, &new_dek, &passphrase)?;
                rewrap_recipients(&mut metadata, &new_dek)?;
                save_vault_metadata(VAULT_FILE, &metadata)?;
                save_secrets_file(SECRETS_FILE, &secrets_file, &new_dek, VAULT_FILE)?;
                invalidate_cache()?;
                println!(
                    "{} access revoked for {} ({}); project key rotated",
                    "ok:".green().bold(),
                    removed.label.bold(),
                    removed.public_key_fingerprint.yellow()
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
                let (new_dek, summary) = rotate_project_key_wrapping(&dek, &passphrase)?;
                save_rotated_project_key(&new_dek)?;
                print_ratchet_summary(&summary);
                Ok(())
            }
            RotateCommand::ProjectKey => {
                ensure_project_initialized()?;
                let (dek, passphrase) =
                    unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
                let (new_dek, _) = rotate_project_key_wrapping(&dek, &passphrase)?;
                save_rotated_project_key(&new_dek)?;
                println!("{} project key rotated", "ok:".green().bold());
                Ok(())
            }
        },
    }
}

fn prepare_project_key_for_write(
    current_dek: Zeroizing<[u8; 32]>,
) -> DotLockResult<Zeroizing<[u8; 32]>> {
    let metadata = load_vault_metadata(VAULT_FILE)?;
    if !should_auto_ratchet_for_next_write(&metadata) {
        return Ok(current_dek);
    }

    let (verified_dek, passphrase) = unlock_vault_with_master_password_and_passphrase(VAULT_FILE)?;
    let (new_dek, summary) = rotate_project_key_wrapping(&verified_dek, &passphrase)?;
    save_rotated_project_key(&new_dek)?;
    print_ratchet_summary(&summary);
    Ok(new_dek)
}

fn rotate_project_key_wrapping(
    current_dek: &[u8; 32],
    passphrase: &str,
) -> DotLockResult<(Zeroizing<[u8; 32]>, RatchetSummary)> {
    let mut metadata = load_vault_metadata(VAULT_FILE)?;
    let new_dek = Zeroizing::new(generate_dek().map_err(|e| DotLockError::Crypto(e.to_string()))?);
    let summary = rotate_kek_wrapping(&mut metadata, current_dek, &new_dek)?;
    update_master_password_metadata(&mut metadata, &new_dek, passphrase)?;
    save_vault_metadata(VAULT_FILE, &metadata)?;
    record_ratchet_best_effort(&summary);
    invalidate_cache()?;
    Ok((new_dek, summary))
}

fn save_rotated_project_key(dek: &[u8; 32]) -> DotLockResult<()> {
    let secrets_file = load_secrets_file(SECRETS_FILE)?;
    save_secrets_file(SECRETS_FILE, &secrets_file, dek, VAULT_FILE)?;
    let mut metadata = load_vault_metadata(VAULT_FILE)?;
    metadata.kek_writes_since_rotate = 0;
    save_vault_metadata(VAULT_FILE, &metadata)
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
}

fn reencrypt_secret(
    secret: &mut SecretRecord,
    old_dek: &[u8; 32],
    new_dek: &[u8; 32],
) -> DotLockResult<()> {
    let alg = parse_alg(&secret.alg)?;
    let value = decryption_process(secret.data.clone(), alg.clone(), old_dek)?;
    let encrypted = encryption_process(secret.name.clone(), value, alg, new_dek)?;
    secret.data =
        String::from_utf8(encrypted.data).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    Ok(())
}

fn decrypted_env_entries(dek: &[u8; 32]) -> DotLockResult<Vec<EnvEntry>> {
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

    let label_w = recipients
        .iter()
        .map(|entry| entry.label.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let fp_w = recipients
        .iter()
        .map(|entry| entry.public_key_fingerprint.len())
        .max()
        .unwrap_or(11)
        .max(11);

    println!();
    println!(
        "  {:label_w$}  {:fp_w$}  ACCESS",
        "LABEL".dimmed().bold(),
        "FINGERPRINT".dimmed().bold(),
        label_w = label_w,
        fp_w = fp_w
    );
    println!(
        "  {}  {}  {}",
        "─".repeat(label_w).dimmed(),
        "─".repeat(fp_w).dimmed(),
        "─".repeat(6).dimmed()
    );
    for recipient in recipients {
        let access = if recipient.full_access {
            "*".to_string()
        } else {
            recipient.wrapped_sdks.len().to_string()
        };
        println!(
            "  {:label_w$}  {:fp_w$}  {}",
            recipient.label.as_str().bold(),
            recipient.public_key_fingerprint.as_str().yellow(),
            access,
            label_w = label_w,
            fp_w = fp_w
        );
    }
    println!();
}
