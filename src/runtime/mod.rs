use std::{process::Command, time::Instant};

use crate::{
    audit::{record_dynamic_resolve, record_run},
    domain::{error::DotLockError, model::DotLockResult},
    providers::resolve_provider,
    storage::{
        project::SECRETS_FILE,
        secrets_lock::{SecretKind, decrypt_secret_value, load_secrets_file},
        vault_file::load_vault_metadata,
    },
};

pub fn run_with_secrets(command: Vec<String>, dek: &[u8; 32]) -> DotLockResult<()> {
    if command.is_empty() {
        return Err(DotLockError::MissingCommand);
    }

    let file = load_secrets_file(SECRETS_FILE)?;

    let mut envs = Vec::new();

    for secret in &file.secrets {
        let value = match secret_value_for_runtime(&secret, dek, &file.secrets) {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(err) => return Err(err),
        };
        envs.push((secret.name.clone(), value));
    }

    let secrets_consumed = envs
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
        .envs(envs)
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
    dek: &[u8; 32],
    all_secrets: &[crate::storage::secrets_lock::SecretRecord],
) -> DotLockResult<Option<String>> {
    match &secret.kind {
        SecretKind::Static => match decrypt_secret_value(secret, dek) {
            Ok(value) => Ok(Some(value)),
            Err(DotLockError::AccessDenied { .. }) => Ok(None),
            Err(err) => Err(err),
        },
        SecretKind::Dynamic {
            provider: _,
            config: _,
            bootstrap: _,
        } => {
            let dynamic = crate::storage::secrets_lock::decrypt_dynamic_metadata(secret, dek)?;
            let value = resolve_dynamic_secret(&secret.name, &dynamic, dek, all_secrets)?;
            Ok(Some(value))
        }
    }
}

pub fn resolve_dynamic_secret(
    secret_name: &str,
    dynamic: &crate::storage::secrets_lock::DynamicSecretMetadata,
    dek: &[u8; 32],
    all_secrets: &[crate::storage::secrets_lock::SecretRecord],
) -> DotLockResult<String> {
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
        bootstrap_values.insert(
            bootstrap_name.clone(),
            serde_json::Value::String(decrypt_secret_value(bootstrap_secret, dek)?),
        );
    }

    let timeout = load_vault_metadata(crate::storage::project::VAULT_FILE)
        .map(|metadata| metadata.config.dynamic_resolve_timeout_secs.unwrap_or(10))
        .unwrap_or(10);
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
    resolved
}
