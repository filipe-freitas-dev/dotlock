use colored::Colorize;

use crate::{
    cli::args::ExportArgs,
    domain::{keys::ProjectKey, model::DotLockResult},
    storage::{
        self,
        env_file::{EnvEntry, merge_exported_env_content, write_env_file},
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{SecretKind, decrypt_secret_value, load_secrets_file},
        unlock_file::unlock_vault,
    },
};

pub fn run(args: ExportArgs) -> DotLockResult<()> {
    let path = args.path;
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
