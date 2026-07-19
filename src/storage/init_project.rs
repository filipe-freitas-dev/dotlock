use colored::Colorize;

use crate::{
    crypto::{
        initialize_vault_keys,
        integrity::{build_encrypted_hash_fields, file_sha256_b64, seal_vault_metadata},
    },
    domain::{error::DotLockError, model::DotLockResult},
    git::install::install_merge_driver_if_in_git_repo,
    storage::{
        cache::write_cached_dek_for,
        project::{self, DOTLOCK_DIR, ensure_project_not_initialized},
        secure_fs,
        vault_file::save_vault_metadata,
    },
};

pub fn init_project() -> DotLockResult<()> {
    // `dl init` always creates the DEFAULT environment; named environments
    // get their own vault pair through `dl env add <name>` (FG3).
    if let Some(env) = project::active_env() {
        return Err(DotLockError::EnvironmentNotInitialized { name: env });
    }
    ensure_project_not_initialized()?;

    init_vault_pair(None)?;

    println!(
        "{} initialized DotLock project at {}",
        "ok:".green().bold(),
        DOTLOCK_DIR.bold()
    );
    println!(
        "     {} {}",
        "created".dimmed(),
        project::vault_file_for(None).bold()
    );
    println!(
        "     {} {}",
        "created".dimmed(),
        project::secrets_file_for(None).bold()
    );

    let _ = install_merge_driver_if_in_git_repo()?;

    Ok(())
}

/// Creates one environment's vault pair from scratch: fresh Argon2id salt,
/// fresh DEK, KEK derived from (project, environment, kek_version) — so every
/// environment is cryptographically independent — sealed (MAC + epoch 1) at
/// birth. `env = None` is the default environment (`.lock/`, MAC-covered
/// `environment` field kept at the historical `dev`); `Some(name)` creates
/// `.lock/envs/<name>/` with `environment = name`.
pub fn init_vault_pair(env: Option<&str>) -> DotLockResult<()> {
    let lock_dir = project::env_lock_dir_for(env);
    let vault_file = project::vault_file_for(env);
    let secrets_file = project::secrets_file_for(env);
    // The `environment` field feeds `derive_kek` and is covered by the
    // metadata MAC; for named environments it must equal the env name.
    let environment = env.unwrap_or("dev");

    secure_fs::ensure_dir(std::path::Path::new(&lock_dir), 0o700)?;

    let mut vault = initialize_vault_keys("dotlock", environment)?;

    if !std::path::Path::new(&secrets_file).exists() {
        secure_fs::write_string_atomic(std::path::Path::new(&secrets_file), "", 0o700, 0o600)?;
    }

    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(&secrets_file, &vault.dek)?;
    vault.metadata.secrets_hash_nonce_b64 = nonce_b64;
    vault.metadata.secrets_hash_b64 = hash_b64;
    vault.metadata.secrets_hash_sha256_b64 = file_sha256_b64(&secrets_file)?;
    // Fresh vaults are born sealed: v7 format, epoch 1, metadata MAC set.
    seal_vault_metadata(&mut vault.metadata, &vault.dek)?;

    save_vault_metadata(&vault_file, &vault.metadata)?;

    // Session cache keyed by the vault's own project_uuid, so each
    // environment caches independently.
    write_cached_dek_for(&vault.metadata, &vault.dek)?;

    Ok(())
}
