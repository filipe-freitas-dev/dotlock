use crate::{
    cli::args::GetArgs,
    domain::{error::DotLockError, model::DotLockResult},
    runtime::secret_value_for_runtime,
    storage::{
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{find_secret_by_name, load_secrets_file},
        unlock_file::unlock_vault,
    },
    utils::{normalize_var_name, print_get_result},
};

pub fn run(args: GetArgs) -> DotLockResult<()> {
    let name = normalize_var_name(&args.name)?;
    ensure_project_initialized()?;
    let dek = unlock_vault(VAULT_FILE)?.into_read_key();

    let secret = find_secret_by_name(&name)?;
    let all_secrets = load_secrets_file(SECRETS_FILE)?.secrets;
    let value =
        secret_value_for_runtime(&secret, &dek, &all_secrets)?.ok_or_else(|| {
            DotLockError::AccessDenied {
                secret: secret.name.clone(),
            }
        })?;

    print_get_result(&secret.name, &secret.id, &value);
    Ok(())
}
