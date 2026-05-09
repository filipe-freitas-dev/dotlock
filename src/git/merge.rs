use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use crate::{
    crypto::VaultKeyMetadata,
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        cache::read_cached_dek,
        project::{SECRETS_FILE, VAULT_FILE},
        secrets_lock::{SecretRecord, SecretsFile, load_secrets_file, refresh_vault_hash},
        secure_fs,
        unlock_file::unlock_vault,
        vault_file::load_vault_metadata,
    },
};

pub fn run_merge_driver(ours: &Path, theirs: &Path, base: &Path) -> DotLockResult<()> {
    match merge_target(ours) {
        MergeTarget::Secrets => merge_secrets_lock(ours, theirs, base),
        MergeTarget::Vault => merge_vault_metadata(ours, theirs, base),
    }
}

enum MergeTarget {
    Secrets,
    Vault,
}

fn merge_target(path: &Path) -> MergeTarget {
    if path.file_name().and_then(|name| name.to_str()) == Some("vault.toml") {
        MergeTarget::Vault
    } else {
        MergeTarget::Secrets
    }
}

fn merge_secrets_lock(ours: &Path, theirs: &Path, base: &Path) -> DotLockResult<()> {
    let ours_file = load_secrets_file(ours)?;
    let theirs_file = load_secrets_file(theirs)?;
    let base_file = load_secrets_file(base).unwrap_or_default();
    let merged = merge_secrets(ours_file, theirs_file, base_file)?;

    let content =
        toml::to_string_pretty(&merged).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    secure_fs::write_string_atomic(ours, &content, 0o700, 0o600)?;

    let dek = read_cached_dek().or_else(|| unlock_vault(VAULT_FILE).ok());
    if let Some(dek) = dek {
        refresh_vault_hash(Path::new(SECRETS_FILE), &dek, VAULT_FILE)?;
    }

    Ok(())
}

pub fn merge_secrets(
    ours: SecretsFile,
    theirs: SecretsFile,
    base: SecretsFile,
) -> DotLockResult<SecretsFile> {
    let version = ours.version.max(theirs.version);
    let ours_by_name: HashMap<String, SecretRecord> = ours
        .secrets
        .into_iter()
        .map(|secret| (secret.name.clone(), secret))
        .collect();
    let theirs_by_name: HashMap<String, SecretRecord> = theirs
        .secrets
        .into_iter()
        .map(|secret| (secret.name.clone(), secret))
        .collect();
    let base_by_name: HashMap<String, SecretRecord> = base
        .secrets
        .into_iter()
        .map(|secret| (secret.name.clone(), secret))
        .collect();

    let mut names = BTreeSet::new();
    names.extend(ours_by_name.keys().cloned());
    names.extend(theirs_by_name.keys().cloned());
    names.extend(base_by_name.keys().cloned());

    let mut secrets = Vec::new();
    for name in names {
        if let Some(secret) = choose_secret(
            &name,
            ours_by_name.get(&name),
            theirs_by_name.get(&name),
            base_by_name.get(&name),
        )? {
            secrets.push(secret.clone());
        }
    }

    Ok(SecretsFile { version, secrets })
}

fn choose_secret<'a>(
    name: &str,
    ours: Option<&'a SecretRecord>,
    theirs: Option<&'a SecretRecord>,
    base: Option<&SecretRecord>,
) -> DotLockResult<Option<&'a SecretRecord>> {
    match (ours, theirs, base) {
        (Some(ours), Some(theirs), _) => choose_latest(name, ours, theirs).map(Some),
        (Some(ours), None, Some(base)) => {
            if same_secret_revision(ours, base) {
                Ok(None)
            } else {
                Ok(Some(ours))
            }
        }
        (None, Some(theirs), Some(base)) => {
            if same_secret_revision(theirs, base) {
                Ok(None)
            } else {
                Ok(Some(theirs))
            }
        }
        (Some(ours), None, None) => Ok(Some(ours)),
        (None, Some(theirs), None) => Ok(Some(theirs)),
        (None, None, _) => Ok(None),
    }
}

fn choose_latest<'a>(
    name: &str,
    ours: &'a SecretRecord,
    theirs: &'a SecretRecord,
) -> DotLockResult<&'a SecretRecord> {
    if ours.updated_at > theirs.updated_at {
        return Ok(ours);
    }
    if theirs.updated_at > ours.updated_at {
        return Ok(theirs);
    }
    if ours.data != theirs.data {
        return Err(DotLockError::Io(format!(
            "manual merge required for secret `{name}`; both sides changed it at the same timestamp"
        )));
    }
    Ok(ours)
}

fn same_secret_revision(left: &SecretRecord, right: &SecretRecord) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.alg == right.alg
        && left.data == right.data
        && left.updated_at == right.updated_at
}

fn merge_vault_metadata(ours: &Path, theirs: &Path, base: &Path) -> DotLockResult<()> {
    let ours_metadata = load_vault_metadata(ours)?;
    let theirs_metadata = load_vault_metadata(theirs)?;
    let base_metadata = load_vault_metadata(base).ok();
    let merged = merge_metadata(ours_metadata, theirs_metadata, base_metadata)?;
    let content =
        toml::to_string_pretty(&merged).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    secure_fs::write_string_atomic(ours, &content, 0o700, 0o600)
}

pub fn merge_metadata(
    mut ours: VaultKeyMetadata,
    theirs: VaultKeyMetadata,
    base: Option<VaultKeyMetadata>,
) -> DotLockResult<VaultKeyMetadata> {
    if ours.project_uuid != theirs.project_uuid {
        return Err(DotLockError::Io(
            "manual merge required for vault.toml; project_uuid differs".to_string(),
        ));
    }

    if ours.kek_version != theirs.kek_version {
        return Err(DotLockError::Io(
            "manual merge required for vault.toml; kek_version differs".to_string(),
        ));
    }

    ours.version = ours.version.max(theirs.version).max(2);
    merge_recipients(&mut ours, theirs, base);
    Ok(ours)
}

fn merge_recipients(
    ours: &mut VaultKeyMetadata,
    theirs: VaultKeyMetadata,
    base: Option<VaultKeyMetadata>,
) {
    let base_fingerprints: Vec<String> = base
        .map(|metadata| {
            metadata
                .recipients
                .into_iter()
                .map(|recipient| recipient.public_key_fingerprint)
                .collect()
        })
        .unwrap_or_default();

    for recipient in theirs.recipients {
        let exists = ours
            .recipients
            .iter()
            .any(|existing| existing.public_key_fingerprint == recipient.public_key_fingerprint);
        if exists {
            continue;
        }

        let was_in_base = base_fingerprints
            .iter()
            .any(|fingerprint| fingerprint == &recipient.public_key_fingerprint);
        if !was_in_base {
            ours.recipients.push(recipient);
        }
    }

    ours.recipients
        .sort_by(|a, b| a.public_key_fingerprint.cmp(&b.public_key_fingerprint));
}

#[cfg(test)]
mod tests {
    use crate::storage::secrets_lock::{SecretKind, SecretRecord, SecretsFile};

    use super::merge_secrets;

    fn secret(name: &str, data: &str, updated_at: i64) -> SecretRecord {
        SecretRecord {
            id: name.to_string(),
            name: name.to_string(),
            alg: "xchacha20-poly1305".to_string(),
            data: data.to_string(),
            updated_at,
            kind: SecretKind::Static,
        }
    }

    fn file(secrets: Vec<SecretRecord>) -> SecretsFile {
        SecretsFile {
            version: 1,
            secrets,
        }
    }

    #[test]
    fn merges_different_secret_changes() {
        let merged = merge_secrets(
            file(vec![secret("A", "ours", 10)]),
            file(vec![secret("B", "theirs", 11)]),
            file(Vec::new()),
        )
        .expect("merge");

        assert_eq!(merged.secrets.len(), 2);
        assert_eq!(merged.secrets[0].name, "A");
        assert_eq!(merged.secrets[1].name, "B");
    }

    #[test]
    fn latest_timestamp_wins_for_same_secret() {
        let merged = merge_secrets(
            file(vec![secret("A", "old", 10)]),
            file(vec![secret("A", "new", 20)]),
            file(Vec::new()),
        )
        .expect("merge");

        assert_eq!(merged.secrets[0].data, "new");
    }

    #[test]
    fn same_timestamp_conflict_requires_manual_merge() {
        let result = merge_secrets(
            file(vec![secret("A", "ours", 10)]),
            file(vec![secret("A", "theirs", 10)]),
            file(Vec::new()),
        );

        assert!(result.is_err());
    }

    #[test]
    fn deletion_wins_when_other_side_did_not_change_secret() {
        let base = secret("A", "base", 10);
        let merged = merge_secrets(file(Vec::new()), file(vec![base.clone()]), file(vec![base]))
            .expect("merge");

        assert!(merged.secrets.is_empty());
    }

    #[test]
    fn update_wins_when_other_side_deleted_older_base_secret() {
        let merged = merge_secrets(
            file(Vec::new()),
            file(vec![secret("A", "updated", 20)]),
            file(vec![secret("A", "base", 10)]),
        )
        .expect("merge");

        assert_eq!(merged.secrets[0].data, "updated");
    }
}
