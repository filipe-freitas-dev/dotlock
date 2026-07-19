use colored::Colorize;

use crate::{
    cli::args::ExportArgs,
    commands::context::VaultContext,
    crypto::VaultKeyMetadata,
    domain::{keys::ProjectKey, model::DotLockResult},
    storage::{
        self,
        env_file::{EnvEntry, merge_exported_env_content, write_env_file},
        project::secrets_file,
        secrets_lock::{SecretKind, decrypt_secret_value, load_secrets_file},
    },
};

pub fn run(args: ExportArgs) -> DotLockResult<()> {
    let path = args.path;
    let (metadata, dek) = VaultContext::unlock()?.into_read();
    let mut entries = decrypted_env_entries(&dek, &metadata)?;
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

fn decrypted_env_entries(
    dek: &ProjectKey,
    metadata: &VaultKeyMetadata,
) -> DotLockResult<Vec<EnvEntry>> {
    let mut secrets = load_secrets_file(secrets_file())?.secrets;
    secrets.sort_by(|a, b| a.name.cmp(&b.name));

    let mut entries = Vec::with_capacity(secrets.len());
    for secret in secrets {
        if !matches!(secret.kind, SecretKind::Static) {
            continue;
        }
        // The exported value intentionally ends up in a plaintext `.env`
        // file; `mem::take` moves it out of the `Zeroizing` buffer without
        // an extra unzeroized heap copy.
        let mut value = decrypt_secret_value(&secret, dek, metadata)?;
        entries.push(EnvEntry {
            key: secret.name,
            value: std::mem::take(&mut *value),
        });
    }

    Ok(entries)
}
