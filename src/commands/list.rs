use crate::{
    cli::global::json_output, commands::context::VaultContext, domain::model::DotLockResult,
    storage::secrets_lock::list_secrets, utils::print_secrets_table,
};

pub fn run() -> DotLockResult<()> {
    // Unlock (full or limited) is only an access gate for listing;
    // the key material is dropped (and zeroized) immediately.
    let _ = VaultContext::unlock()?;

    let mut entries = list_secrets()?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    if json_output() {
        // FG1 schema: `[{"id": "<uuid>", "name": "<NAME>"}]` — names and ids
        // only, never values.
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| serde_json::json!({ "id": entry.id, "name": entry.name }))
            .collect();
        println!("{}", serde_json::Value::Array(items));
        return Ok(());
    }

    print_secrets_table(&entries);
    Ok(())
}
