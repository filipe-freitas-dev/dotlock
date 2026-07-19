use crate::{
    cli::{args::GetArgs, global::json_output},
    commands::context::VaultContext,
    domain::{error::DotLockError, model::DotLockResult},
    runtime::secret_value_for_runtime,
    storage::{
        project::secrets_file,
        secrets_lock::{find_secret_by_name, load_secrets_file},
    },
    utils::{normalize_var_name, print_get_result},
};

pub fn run(args: GetArgs) -> DotLockResult<()> {
    let name = normalize_var_name(&args.name)?;
    let (metadata, dek) = VaultContext::unlock()?.into_read();

    let secret = find_secret_by_name(&name)?;
    let all_secrets = load_secrets_file(secrets_file())?.secrets;
    let value =
        secret_value_for_runtime(&secret, &dek, &all_secrets, &metadata)?.ok_or_else(|| {
            DotLockError::AccessDenied {
                secret: secret.name.clone(),
            }
        })?;

    if json_output() {
        // FG1 schema: `{"name": "<NAME>", "id": "<uuid>", "value": "<value>"}`.
        // The value is only emitted because the user explicitly requested this
        // exact secret — same exposure as the default piped output.
        println!(
            "{}",
            serde_json::json!({
                "name": secret.name,
                "id": secret.id,
                "value": value.as_str(),
            })
        );
        return Ok(());
    }

    print_get_result(&secret.name, &secret.id, &value);
    Ok(())
}
