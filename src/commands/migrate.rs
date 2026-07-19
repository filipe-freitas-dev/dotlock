use colored::Colorize;

use crate::{
    cli::args::MigrateArgs,
    commands::context::VaultContext,
    domain::{
        error::DotLockError,
        model::{Alg, DotLockResult},
    },
    storage::{
        env_file::parse_env_file,
        project::{secrets_file, vault_file},
        secrets_lock::{PlainSecretEntry, upsert_many},
    },
    utils::normalize_var_name,
};

pub fn run(args: MigrateArgs) -> DotLockResult<()> {
    let path = args.path;
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

    let (mut metadata, dek) = VaultContext::unlock()?.into_write()?;

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
    let summary = upsert_many(secrets_file(), prepared, &dek, &vault_file(), &mut metadata)?;

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
