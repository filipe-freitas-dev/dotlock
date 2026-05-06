use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use zeroize::Zeroize;

use crate::{
    domain::{error::DotLockError, model::Alg, model::DotLockResult},
    runtime::{decryption_process, encryption_process, run_with_secrets},
    storage::{
        cache::invalidate_cache,
        env_file::parse_env_file,
        init_project::init_project,
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{
            EncryptedEntry, find_secret_by_name, list_secrets, remove_secret_by_name,
            upsert_many, upsert_secret,
        },
        unlock_file::unlock_vault,
    },
    utils::{normalize_var_name, parse_alg},
};

mod crypto;
mod domain;
mod runtime;
mod storage;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about = "DotLock encrypts your project's environment variables.")]
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
    }
}

fn print_get_result(name: &str, id: &str, value: &str) {
    if !std::io::stdout().is_terminal() {
        println!("{}", value);
        return;
    }

    let short = short_uuid(id);
    let title = name.to_string();
    let id_line = format!("id: {}", short);
    let value_lines: Vec<&str> = if value.is_empty() {
        vec![""]
    } else {
        value.lines().collect()
    };

    let center = |s: &str, w: usize| {
        let len = s.chars().count();
        if len >= w {
            s.to_string()
        } else {
            let total = w - len;
            let left = total / 2;
            let right = total - left;
            format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
        }
    };
    let content_w = title
        .chars()
        .count()
        .max(id_line.chars().count())
        .max(value_lines.iter().map(|line| line.chars().count()).max().unwrap_or(0));
    let inner_w = content_w + 2;

    println!();
    println!(
        "  {}{}{}",
        "┌".dimmed(),
        "─".repeat(inner_w).dimmed(),
        "┐".dimmed()
    );
    println!(
        "  {}{}{}",
        "│ ".dimmed(),
        center(&title, content_w).bold(),
        " │".dimmed()
    );
    println!(
        "  {}{}{}",
        "│ ".dimmed(),
        center(&id_line, content_w).yellow(),
        " │".dimmed()
    );
    println!("  {}{}{}", "│ ".dimmed(), " ".repeat(content_w), " │".dimmed());
    for line in value_lines {
        println!(
            "  {}{}{}",
            "│ ".dimmed(),
            center(line, content_w),
            " │".dimmed()
        );
    }
    println!(
        "  {}{}{}",
        "└".dimmed(),
        "─".repeat(content_w + 2).dimmed(),
        "┘".dimmed()
    );
    println!();
    println!(
        "  {} pipe to a command to read the value (e.g. `dotlock get {} | pbcopy`)",
        "hint:".cyan().bold(),
        name
    );
    println!();
}

fn print_secrets_table(entries: &[storage::secrets_lock::SecretRecord]) {
    if entries.is_empty() {
        println!("{} no secrets stored", "info:".cyan().bold());
        return;
    }

    let id_header = "ID";
    let name_header = "NAME";

    let id_w = id_header.len().max(8);
    let name_w = entries
        .iter()
        .map(|e| e.name.chars().count())
        .max()
        .unwrap_or(0)
        .max(name_header.len());

    let pad = |s: &str, w: usize| {
        let len = s.chars().count();
        if len >= w {
            s.to_string()
        } else {
            format!("{}{}", s, " ".repeat(w - len))
        }
    };

    println!();
    println!(
        "  {}  {}",
        pad(id_header, id_w).dimmed().bold(),
        pad(name_header, name_w).dimmed().bold()
    );
    println!(
        "  {}  {}",
        "─".repeat(id_w).dimmed(),
        "─".repeat(name_w).dimmed()
    );
    for entry in entries {
        let short = short_uuid(&entry.id);
        println!(
            "  {}  {}",
            pad(&short, id_w).yellow(),
            pad(&entry.name, name_w).bold()
        );
    }
    println!();
    println!(
        "  {} {}",
        "total:".cyan().bold(),
        format!(
            "{} secret{}",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        )
        .bold()
    );
    println!();
}

fn short_uuid(id: &str) -> String {
    id.chars().take(8).collect()
}

fn report_error(err: &DotLockError) {
    eprintln!("{} {}", "error:".red().bold(), err);
    if let Some(hint) = err.hint() {
        eprintln!("{} {}", "hint: ".cyan().bold(), hint);
    }
}
