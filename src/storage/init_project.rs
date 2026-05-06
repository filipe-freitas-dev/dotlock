use colored::Colorize;

use crate::{
    crypto::{initialize_vault_keys, integrity::build_encrypted_hash_fields},
    domain::model::DotLockResult,
    storage::{
        cache::write_cached_dek,
        project::{DOTLOCK_DIR, SECRETS_FILE, VAULT_FILE, ensure_project_not_initialized},
        secure_fs,
        vault_file::save_vault_metadata,
    },
};

pub fn init_project() -> DotLockResult<()> {
    ensure_project_not_initialized()?;

    secure_fs::ensure_dir(std::path::Path::new(DOTLOCK_DIR), 0o700)?;

    let mut vault = initialize_vault_keys("dotlock", "dev")?;

    if !std::path::Path::new(SECRETS_FILE).exists() {
        secure_fs::write_string_atomic(std::path::Path::new(SECRETS_FILE), "", 0o700, 0o600)?;
    }

    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(SECRETS_FILE, &vault.dek)?;
    vault.metadata.secrets_hash_nonce_b64 = nonce_b64;
    vault.metadata.secrets_hash_b64 = hash_b64;

    save_vault_metadata(VAULT_FILE, &vault.metadata)?;

    write_cached_dek(&vault.dek)?;

    println!(
        "{} initialized DotLock project at {}",
        "ok:".green().bold(),
        DOTLOCK_DIR.bold()
    );
    println!("     {} {}", "created".dimmed(), VAULT_FILE.bold());
    println!("     {} {}", "created".dimmed(), SECRETS_FILE.bold());

    Ok(())
}
