use std::{path::Path, process::Command, time::Instant};

use zeroize::Zeroizing;

use crate::{
    audit::{record_dynamic_resolve, record_run},
    crypto::VaultKeyMetadata,
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    providers::resolve_provider,
    storage::{
        env_file::parse_env_file,
        project::secrets_file,
        secrets_lock::{SecretKind, decrypt_secret_value, load_secrets_file},
    },
};

/// Loads extra PLAINTEXT variables from a `.env` file for `--env-file` (FG4).
/// The file is read through the symlink-safe reader; its values come from
/// disk in the clear — they are NOT vault secrets and get no integrity
/// protection. Precedence is decided in [`run_with_secrets`]: vault secrets
/// always override env-file entries of the same name.
pub fn load_env_file_vars(path: &Path) -> DotLockResult<Vec<(String, String)>> {
    Ok(parse_env_file(path)?
        .into_iter()
        .map(|entry| (entry.key, entry.value))
        .collect())
}

pub fn run_with_secrets(
    command: Vec<String>,
    extra_env: Vec<(String, String)>,
    dek: &ProjectKey,
    metadata: &VaultKeyMetadata,
) -> DotLockResult<()> {
    if command.is_empty() {
        return Err(DotLockError::MissingCommand);
    }

    let file = load_secrets_file(secrets_file())?;

    // `--env-file` entries first, vault secrets afterwards: with
    // `Command::envs` the LAST occurrence of a name wins, so a vault secret
    // always overrides a plaintext env-file value of the same name. Values
    // live in `Zeroizing` buffers (L1) that are wiped when this function
    // returns; the child process receives its own copy of the environment.
    let mut envs: Vec<(String, Zeroizing<String>)> = extra_env
        .into_iter()
        .map(|(name, value)| (name, Zeroizing::new(value)))
        .collect();
    let extra_count = envs.len();

    for secret in &file.secrets {
        let value = match secret_value_for_runtime(secret, dek, &file.secrets, metadata) {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(err) => return Err(err),
        };
        envs.push((secret.name.clone(), value));
    }

    // Only vault secret names are audited; env-file variables are plaintext
    // input the user already controls.
    let secrets_consumed = envs[extra_count..]
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    if let Err(err) = record_run(&command, &secrets_consumed) {
        eprintln!("warn: audit log write failed: {err}");
    }

    let program = &command[0];
    let args = &command[1..];

    let status = Command::new(program)
        .args(args)
        .envs(envs.iter().map(|(name, value)| (name.as_str(), value.as_str())))
        .status()
        .map_err(|e| DotLockError::Io(e.to_string()))?;

    if !status.success() {
        return Err(DotLockError::CommandFailed {
            status: status.to_string(),
        });
    }

    Ok(())
}

pub fn secret_value_for_runtime(
    secret: &crate::storage::secrets_lock::SecretRecord,
    dek: &ProjectKey,
    all_secrets: &[crate::storage::secrets_lock::SecretRecord],
    metadata: &VaultKeyMetadata,
) -> DotLockResult<Option<Zeroizing<String>>> {
    match &secret.kind {
        SecretKind::Static => match decrypt_secret_value(secret, dek, metadata) {
            Ok(value) => Ok(Some(value)),
            Err(DotLockError::AccessDenied { .. }) => Ok(None),
            Err(err) => Err(err),
        },
        SecretKind::Dynamic {
            provider: _,
            config: _,
            bootstrap: _,
        } => {
            let dynamic =
                crate::storage::secrets_lock::decrypt_dynamic_metadata(secret, dek, metadata)?;
            let value = resolve_dynamic_secret(&secret.name, &dynamic, dek, all_secrets, metadata)?;
            Ok(Some(value))
        }
    }
}

pub fn resolve_dynamic_secret(
    secret_name: &str,
    dynamic: &crate::storage::secrets_lock::DynamicSecretMetadata,
    dek: &ProjectKey,
    all_secrets: &[crate::storage::secrets_lock::SecretRecord],
    metadata: &VaultKeyMetadata,
) -> DotLockResult<Zeroizing<String>> {
    let mut bootstrap_values = serde_json::Map::new();
    for bootstrap_name in &dynamic.bootstrap {
        let bootstrap_secret = all_secrets
            .iter()
            .find(|secret| &secret.name == bootstrap_name)
            .ok_or_else(|| DotLockError::SecretNotFound {
                name: bootstrap_name.clone(),
            })?;
        if !matches!(bootstrap_secret.kind, SecretKind::Static) {
            return Err(DotLockError::Io(format!(
                "bootstrap secret `{bootstrap_name}` must be static"
            )));
        }
        // The bootstrap plaintext has to live inside the JSON payload handed
        // to the provider; `mem::take` moves it out of the `Zeroizing` buffer
        // without an extra unzeroized copy.
        let mut value = decrypt_secret_value(bootstrap_secret, dek, metadata)?;
        bootstrap_values.insert(
            bootstrap_name.clone(),
            serde_json::Value::String(std::mem::take(&mut *value)),
        );
    }

    let timeout = metadata.config.dynamic_resolve_timeout_secs.unwrap_or(10);
    let started = Instant::now();
    let provider_dir = dynamic
        .provider_path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).parent());
    let resolved = resolve_provider(
        &dynamic.provider,
        &dynamic.config,
        &bootstrap_values,
        dynamic.provider_sha256.as_deref(),
        provider_dir,
        timeout,
    );
    let duration_ms = started.elapsed().as_millis();
    if let Err(err) = record_dynamic_resolve(
        &dynamic.provider,
        secret_name,
        duration_ms,
        resolved.is_ok(),
    ) {
        eprintln!("warn: audit log write failed: {err}");
    }
    // Minted values are secrets too (L1): keep them in a Zeroizing buffer.
    resolved.map(Zeroizing::new)
}
