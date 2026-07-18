use crate::{
    commands::context::VaultContext, domain::model::DotLockResult,
    storage::secrets_lock::list_secrets, utils::print_secrets_table,
};

pub fn run() -> DotLockResult<()> {
    // Unlock (full or limited) is only an access gate for listing;
    // the key material is dropped (and zeroized) immediately.
    let _ = VaultContext::unlock()?;

    let mut entries = list_secrets()?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    print_secrets_table(&entries);
    Ok(())
}
