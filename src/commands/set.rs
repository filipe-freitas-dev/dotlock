use colored::Colorize;

use crate::{
    cli::args::SetArgs,
    commands::context::prepare_project_key_for_write,
    domain::{error::DotLockError, model::DotLockResult},
    providers::{attest_provider, describe_provider},
    storage::{
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{DynamicSecretMetadata, upsert_dynamic_secret, upsert_plain_secret},
        unlock_file::unlock_vault,
    },
    utils::normalize_var_name,
};

pub fn run(args: SetArgs) -> DotLockResult<()> {
    let SetArgs {
        name,
        value,
        alg,
        provider,
        config,
        bootstrap,
    } = args;
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
