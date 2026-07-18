use crate::{
    domain::model::DotLockResult,
    storage::{
        project::{VAULT_FILE, ensure_project_initialized},
        secrets_lock::list_secrets,
        unlock_file::unlock_vault,
    },
    utils::print_secrets_table,
};

pub fn run() -> DotLockResult<()> {
    ensure_project_initialized()?;
    // Unlock (full or limited) is only an access gate for listing;
    // the key material is dropped (and zeroized) immediately.
    let _ = unlock_vault(VAULT_FILE)?;

    let mut entries = list_secrets()?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    print_secrets_table(&entries);
    Ok(())
}
