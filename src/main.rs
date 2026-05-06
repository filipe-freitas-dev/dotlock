use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use zeroize::Zeroize;

use crate::{
    crypto::{ask_master_password, dek::generate_dek, update_master_password_metadata},
    domain::{
        error::DotLockError,
        model::{Alg, DotLockResult},
    },
    runtime::{decryption_process, encryption_process, run_with_secrets},
    storage::{
        cache::invalidate_cache,
        env_file::parse_env_file,
        identity::{
            initialize_local_identity, load_local_identity, private_key_path, public_key_path,
        },
        init_project::init_project,
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{
            EncryptedEntry, SecretRecord, find_secret_by_name, list_secrets, load_secrets_file,
            remove_secret_by_name, save_secrets_file, upsert_many, upsert_secret,
        },
        shared_access::{
            enable_shared_access, grant_recipient, list_recipients, load_public_key_from_file,
            revoke_recipient_in_memory, rewrap_recipients,
        },
        unlock_file::{
            unlock_vault, unlock_vault_with_master_password,
            unlock_vault_with_master_password_and_passphrase,
        },
        vault_file::{load_vault_metadata, save_vault_metadata},
    },
    utils::{normalize_var_name, parse_alg, print_get_result, print_secrets_table, report_error},
};

mod crypto;
mod domain;
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
    /// Manage the local identity used for shared access
    Cert(CertArgs),
    /// Manage shared project access
    Share(ShareArgs),
    /// Rotate project access material
    Rotate(RotateArgs),
}

#[derive(Args, Debug)]
struct SetArgs {
    name: String,
    value: String,
    #[arg(short, long, value_enum, default_value_t = Alg::XChaCha20Poly1305)]
    alg: Alg,
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
struct CertArgs {
    #[command(subcommand)]
    command: CertCommand,
}

#[derive(Subcommand, Debug)]
enum CertCommand {
    /// Generate a local key pair for shared access
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Show the local identity fingerprint and paths
    Show,
    /// Print or save the local public key
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
    Enable,
    /// Grant project access to a public key
    Grant {
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// Revoke project access from a recipient
    Revoke { query: String },
    /// List current recipients
    List,
}

#[derive(Args, Debug)]
struct RotateArgs {
    #[command(subcommand)]
    command: RotateCommand,
}

#[derive(Subcommand, Debug)]
enum RotateCommand {
    /// Change the master password wrapping the project key
    MasterPassword,
    /// Generate a new project key and re-encrypt the secrets
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

        Commands::Lock => {
            let removed = invalidate_cache()?;
            if removed {
                println!("{} session locked", "ok:".green().bold());
            } else {
                println!("{} no active session", "info:".cyan().bold());
            }
            Ok(())
        }

        Commands::Set(SetArgs { name, value, alg }) => {
            let name = normalize_var_name(&name)?;
            ensure_project_initialized()?;
            let dek = unlock_vault(VAULT_FILE)?;

            let encrypted_data = encryption_process(name, value, alg, &dek)?;
            let secret_name = encrypted_data.name.clone();

            upsert_secret(SECRETS_FILE, encrypted_data, &dek, VAULT_FILE)?;

            println!(
                "{} secret {} saved",
                "ok:".green().bold(),
                secret_name.bold()
            );
            Ok(())
        }

        Commands::Get(GetArgs { name }) => {
            let name = normalize_var_name(&name)?;
            ensure_project_initialized()?;
            let dek = unlock_vault(VAULT_FILE)?;

            let secret = find_secret_by_name(&name)?;
            let alg = parse_alg(&secret.alg)?;
            let value = decryption_process(secret.data.clone(), alg, &dek)?;

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
            let dek = unlock_vault(VAULT_FILE)?;

            remove_secret_by_name(&name, &dek, VAULT_FILE)?;

            println!("{} secret {} removed", "ok:".green().bold(), name.bold());
            Ok(())
        }

        Commands::Run(RunArgs { command }) => {
            ensure_project_initialized()?;
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
            let dek = unlock_vault(VAULT_FILE)?;

            let mut prepared = Vec::with_capacity(raw_entries.len());
            for entry in raw_entries {
                let name = normalize_var_name(&entry.key)?;
                let encrypted =
                    encryption_process(name, entry.value, Alg::XChaCha20Poly1305, &dek)?;
                let data = String::from_utf8(encrypted.data)
                    .map_err(|e| DotLockError::Crypto(e.to_string()))?;
                prepared.push(EncryptedEntry {
                    name: encrypted.name,
                    alg: encrypted.alg.to_string(),
                    data,
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

        Commands::Cert(CertArgs { command }) => match command {
            CertCommand::Init { force } => {
                let identity = initialize_local_identity(force)?;
                println!(
                    "{} local identity ready ({})",
                    "ok:".green().bold(),
                    identity.fingerprint.bold()
                );
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
            ShareCommand::Grant { pubkey, label } => {
                ensure_project_initialized()?;
                let dek = unlock_vault_with_master_password(VAULT_FILE)?;
                let public_key_pem = load_public_key_from_file(&pubkey)?;
                let recipient = grant_recipient(VAULT_FILE, &public_key_pem, &label, &dek)?;
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
                save_vault_metadata(VAULT_FILE, &metadata)?;
                println!("{} master password rotated", "ok:".green().bold());
                Ok(())
            }
            RotateCommand::ProjectKey => {
                ensure_project_initialized()?;
                let dek = unlock_vault_with_master_password(VAULT_FILE)?;
                let mut metadata = load_vault_metadata(VAULT_FILE)?;
                let mut secrets_file = load_secrets_file(SECRETS_FILE)?;
                let new_dek = generate_dek().map_err(|e| DotLockError::Crypto(e.to_string()))?;

                for secret in &mut secrets_file.secrets {
                    reencrypt_secret(secret, &dek, &new_dek)?;
                }

                let passphrase = ask_master_password()?;
                update_master_password_metadata(&mut metadata, &new_dek, &passphrase)?;
                rewrap_recipients(&mut metadata, &new_dek)?;
                save_vault_metadata(VAULT_FILE, &metadata)?;
                save_secrets_file(SECRETS_FILE, &secrets_file, &new_dek, VAULT_FILE)?;
                println!("{} project key rotated", "ok:".green().bold());
                Ok(())
            }
        },
    }
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
        "  {:label_w$}  {:fp_w$}",
        "LABEL".dimmed().bold(),
        "FINGERPRINT".dimmed().bold(),
        label_w = label_w,
        fp_w = fp_w
    );
    println!(
        "  {}  {}",
        "─".repeat(label_w).dimmed(),
        "─".repeat(fp_w).dimmed()
    );
    for recipient in recipients {
        println!(
            "  {:label_w$}  {:fp_w$}",
            recipient.label.as_str().bold(),
            recipient.public_key_fingerprint.as_str().yellow(),
            label_w = label_w,
            fp_w = fp_w
        );
    }
    println!();
}
