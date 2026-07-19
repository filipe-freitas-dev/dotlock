use colored::Colorize;

use crate::{
    cli::args::SetArgs,
    commands::context::VaultContext,
    domain::{error::DotLockError, model::DotLockResult},
    providers::{attest_provider, describe_provider},
    storage::{
        project::{SECRETS_FILE, VAULT_FILE},
        secrets_lock::{DynamicSecretMetadata, upsert_dynamic_secret, upsert_plain_secret},
    },
    utils::normalize_var_name,
};

pub fn run(args: SetArgs) -> DotLockResult<()> {
    let SetArgs {
        name,
        value,
        stdin,
        alg,
        provider,
        config,
        bootstrap,
    } = args;
    let name = normalize_var_name(&name)?;
    let (mut metadata, dek) = VaultContext::unlock()?.into_write()?;

    let secret = if let Some(provider) = provider {
        let _ = describe_provider(&provider, None)?;
        let attestation = attest_provider(&provider, None)?;
        let config = config
            .as_deref()
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose()
            .map_err(|err| DotLockError::Io(format!("invalid provider config JSON: {err}")))?
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
            &mut metadata,
        )?
    } else {
        // M8: the value in argv is visible in `ps`/`/proc`/shell history, so
        // the positional form is compat-only; the recommended paths are the
        // hidden prompt (default when VALUE is omitted) or `--stdin`.
        let value = match value {
            Some(value) => value,
            None if stdin => read_value_from_stdin()?,
            None => prompt_secret_value(&name)?,
        };
        upsert_plain_secret(
            SECRETS_FILE,
            name,
            value,
            alg,
            &dek,
            VAULT_FILE,
            &mut metadata,
        )?
    };

    println!(
        "{} secret {} saved",
        "ok:".green().bold(),
        secret.name.bold()
    );
    Ok(())
}

fn read_value_from_stdin() -> DotLockResult<String> {
    use std::io::Read;
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .map_err(DotLockError::from)?;
    let value = value.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        return Err(DotLockError::Io(
            "no secret value received on stdin".to_string(),
        ));
    }
    Ok(value)
}

fn prompt_secret_value(name: &str) -> DotLockResult<String> {
    use inquire::{Password, PasswordDisplayMode};
    let value = Password::new(&format!("Value for {name}:"))
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|err| match err {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => DotLockError::Aborted,
            other => DotLockError::Io(other.to_string()),
        })?;
    if value.is_empty() {
        return Err(DotLockError::Io("empty secret value".to_string()));
    }
    Ok(value)
}

fn parse_csv_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_csv_list;

    #[test]
    fn parse_csv_list_trims_and_drops_empty_entries() {
        assert_eq!(
            parse_csv_list(" AWS_KEY , ,DB_URL,"),
            vec!["AWS_KEY".to_string(), "DB_URL".to_string()]
        );
        assert!(parse_csv_list("").is_empty());
        assert!(parse_csv_list(" , ").is_empty());
    }
}
