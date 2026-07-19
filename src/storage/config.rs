use std::path::Path;

use crate::{
    crypto::{VaultConfig, VaultKeyMetadata, integrity::seal_vault_metadata},
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    git::validate_git_ref_component,
    storage::{
        vault_file::record_vault_write,
        vault_txn::{VaultPairWrite, commit_vault_pair},
    },
};

/// Config fields are covered by the metadata MAC (M2) — e.g.
/// `auto_ratchet_after_writes` and `auto_fetch_remote` are security-relevant —
/// so config writes now require a proven project key and reseal + commit
/// through the transactional funnel.
fn seal_and_commit(
    path: &Path,
    metadata: &mut VaultKeyMetadata,
    dek: &ProjectKey,
) -> DotLockResult<()> {
    record_vault_write(metadata);
    seal_vault_metadata(metadata, dek)?;
    let secrets = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join("secrets.lock"))
        .unwrap_or_else(|| std::path::PathBuf::from("secrets.lock"));
    commit_vault_pair(
        path,
        &secrets,
        VaultPairWrite {
            metadata,
            secrets_lock_bytes: None,
        },
    )
}

pub fn set_config_value(
    path: &Path,
    metadata: &mut VaultKeyMetadata,
    key: &str,
    value: &str,
    dek: &ProjectKey,
) -> DotLockResult<()> {
    set_config_field(&mut metadata.config, key, value)?;
    seal_and_commit(path, metadata, dek)
}

pub fn unset_config_value(
    path: &Path,
    metadata: &mut VaultKeyMetadata,
    key: &str,
    dek: &ProjectKey,
) -> DotLockResult<()> {
    unset_config_field(&mut metadata.config, key)?;
    seal_and_commit(path, metadata, dek)
}

pub fn config_lines(config: &VaultConfig) -> Vec<String> {
    vec![
        format!("auto_fetch_on_run = {}", config.auto_fetch_on_run),
        format!(
            "auto_fetch_timeout_secs = {}",
            config
                .auto_fetch_timeout_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "default(3)".to_string())
        ),
        format!(
            "auto_fetch_remote = {}",
            config
                .auto_fetch_remote
                .as_deref()
                .unwrap_or("default(origin)")
        ),
        format!(
            "auto_ratchet_after_writes = {}",
            config
                .auto_ratchet_after_writes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "off".to_string())
        ),
        format!(
            "dynamic_resolve_timeout_secs = {}",
            config
                .dynamic_resolve_timeout_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "default(10)".to_string())
        ),
    ]
}

fn set_config_field(config: &mut VaultConfig, key: &str, value: &str) -> DotLockResult<()> {
    match key {
        "auto_fetch_on_run" => {
            config.auto_fetch_on_run = parse_bool(value)?;
            Ok(())
        }
        "auto_fetch_timeout_secs" => {
            let seconds = value.parse::<u64>().map_err(|_| {
                DotLockError::Io("auto_fetch_timeout_secs must be a positive integer".to_string())
            })?;
            if seconds == 0 {
                return Err(DotLockError::Io(
                    "auto_fetch_timeout_secs must be greater than zero".to_string(),
                ));
            }
            config.auto_fetch_timeout_secs = Some(seconds);
            Ok(())
        }
        "auto_fetch_remote" => {
            // Reject option-shaped values (e.g. `--upload-pack=<cmd>`) at
            // config-set time; the git invocation sites validate again in
            // case a tampered vault.toml bypassed this path (H1).
            validate_git_ref_component("auto_fetch_remote", value.trim())?;
            config.auto_fetch_remote = Some(value.trim().to_string());
            Ok(())
        }
        "auto_ratchet_after_writes" => {
            let writes = value.parse::<u32>().map_err(|_| {
                DotLockError::Io(
                    "auto_ratchet_after_writes must be a non-negative integer".to_string(),
                )
            })?;
            config.auto_ratchet_after_writes = (writes > 0).then_some(writes);
            Ok(())
        }
        "dynamic_resolve_timeout_secs" => {
            let seconds = value.parse::<u64>().map_err(|_| {
                DotLockError::Io(
                    "dynamic_resolve_timeout_secs must be a positive integer".to_string(),
                )
            })?;
            if seconds == 0 {
                return Err(DotLockError::Io(
                    "dynamic_resolve_timeout_secs must be greater than zero".to_string(),
                ));
            }
            config.dynamic_resolve_timeout_secs = Some(seconds);
            Ok(())
        }
        other => Err(DotLockError::Io(format!("unknown config key `{other}`"))),
    }
}

fn unset_config_field(config: &mut VaultConfig, key: &str) -> DotLockResult<()> {
    match key {
        "auto_fetch_on_run" => {
            config.auto_fetch_on_run = false;
            Ok(())
        }
        "auto_fetch_timeout_secs" => {
            config.auto_fetch_timeout_secs = None;
            Ok(())
        }
        "auto_fetch_remote" => {
            config.auto_fetch_remote = None;
            Ok(())
        }
        "auto_ratchet_after_writes" => {
            config.auto_ratchet_after_writes = None;
            Ok(())
        }
        "dynamic_resolve_timeout_secs" => {
            config.dynamic_resolve_timeout_secs = None;
            Ok(())
        }
        other => Err(DotLockError::Io(format!("unknown config key `{other}`"))),
    }
}

fn parse_bool(value: &str) -> DotLockResult<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(DotLockError::Io(
            "boolean config values must be true or false".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        crypto::{AccessMode, VaultConfig, VaultKeyMetadata},
        domain::keys::ProjectKey,
        storage::{
            config::{set_config_value, unset_config_value},
            vault_file::{load_vault_metadata, save_vault_metadata},
        },
    };

    /// Per-test directory so the transactional journal written by
    /// `commit_vault_pair` never collides across parallel tests.
    fn temp_vault(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir.join("vault.toml")
    }

    fn dek() -> ProjectKey {
        ProjectKey::new([8u8; 32])
    }

    fn metadata() -> VaultKeyMetadata {
        VaultKeyMetadata {
            version: 2,
            project_uuid: "project".to_string(),
            project: "dotlock".to_string(),
            environment: "dev".to_string(),
            kdf: "argon2id".to_string(),
            salt_b64: "salt".to_string(),
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
            kek_version: 1,
            kek_writes_since_rotate: 0,
            wrapped_dek_nonce_b64: "nonce".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks_under_dek: std::collections::HashMap::new(),
            access_mode: AccessMode::MasterPassword,
            recipients: Vec::new(),
            authorized_signers: Vec::new(),
            config: VaultConfig::default(),
            secrets_hash_nonce_b64: "hash_nonce".to_string(),
            secrets_hash_b64: "hash".to_string(),
            secrets_hash_sha256_b64: "hash_plain".to_string(),
            vault_epoch: 0,
            metadata_mac_b64: String::new(),
        }
    }

    #[test]
    fn sets_and_unsets_auto_fetch_config_values() {
        let path = temp_vault("config");
        save_vault_metadata(&path, &metadata()).expect("save metadata");

        let mut meta = load_vault_metadata(&path).expect("load");
        set_config_value(&path, &mut meta, "auto_fetch_on_run", "true", &dek())
            .expect("set enabled");
        set_config_value(&path, &mut meta, "auto_fetch_timeout_secs", "1", &dek())
            .expect("set timeout");
        set_config_value(&path, &mut meta, "auto_fetch_remote", "upstream", &dek())
            .expect("set remote");
        let metadata = load_vault_metadata(&path).expect("load metadata");

        assert!(metadata.config.auto_fetch_on_run);
        assert_eq!(metadata.config.auto_fetch_timeout_secs, Some(1));
        assert_eq!(
            metadata.config.auto_fetch_remote.as_deref(),
            Some("upstream")
        );
        // Config writes are sealed: MAC present and epoch advanced (M2+M3).
        assert!(!metadata.metadata_mac_b64.is_empty());
        assert_eq!(metadata.vault_epoch, 3);

        let mut meta = load_vault_metadata(&path).expect("load");
        unset_config_value(&path, &mut meta, "auto_fetch_remote", &dek()).expect("unset remote");
        let metadata = load_vault_metadata(&path).expect("load metadata again");

        assert_eq!(metadata.config.auto_fetch_remote, None);

        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn rejects_option_injection_in_auto_fetch_remote() {
        let path = temp_vault("remote-injection");
        save_vault_metadata(&path, &metadata()).expect("save metadata");

        let mut meta = load_vault_metadata(&path).expect("load");
        for value in ["--upload-pack=/tmp/evil", "-r", "ext::sh -c id", ""] {
            assert!(
                set_config_value(&path, &mut meta, "auto_fetch_remote", value, &dek()).is_err(),
                "should reject `{value}`"
            );
        }
        let metadata = load_vault_metadata(&path).expect("load metadata");
        assert_eq!(metadata.config.auto_fetch_remote, None);

        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn sets_and_unsets_auto_ratchet_threshold() {
        let path = temp_vault("ratchet-config");
        save_vault_metadata(&path, &metadata()).expect("save metadata");

        let mut meta = load_vault_metadata(&path).expect("load");
        set_config_value(&path, &mut meta, "auto_ratchet_after_writes", "100", &dek())
            .expect("set threshold");
        let metadata = load_vault_metadata(&path).expect("load metadata");
        assert_eq!(metadata.config.auto_ratchet_after_writes, Some(100));

        let mut meta = load_vault_metadata(&path).expect("load");
        unset_config_value(&path, &mut meta, "auto_ratchet_after_writes", &dek())
            .expect("unset threshold");
        let metadata = load_vault_metadata(&path).expect("load metadata");
        assert_eq!(metadata.config.auto_ratchet_after_writes, None);

        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }
}
