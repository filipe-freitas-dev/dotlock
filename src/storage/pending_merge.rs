//! The `pending-merge` marker: tamper-evident handoff between the git merge
//! driver and the interactive `dl reconcile` step.
//!
//! The merge driver never holds the project key, so it can never re-sign the
//! integrity hash of merged content. Instead, when it produces a content-valid
//! merge it records the public SHA-256 of the merged files in this marker.
//! Every unlock refuses to proceed while the marker exists; `dl reconcile`
//! verifies the merged files still match the marker (no post-merge tampering),
//! shows the merge diff, and only re-signs the hash under the DEK after
//! explicit user confirmation.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{integrity::file_sha256_b64, sdk},
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    storage::{
        secrets_lock::{current_unix_timestamp, load_secrets_file, refresh_vault_hash},
        secure_fs,
        vault_file::load_vault_metadata,
    },
};

pub const PENDING_MERGE_FILE: &str = "pending-merge";
const MARKER_VERSION: u32 = 1;

/// Entries that must never be committed from `.lock/`: transactional scratch
/// files and the pending-merge marker (it describes local, unreconciled state).
const LOCK_GITIGNORE_ENTRIES: &[&str] = &[
    "pending-merge",
    "txn.journal",
    ".txn.lock",
    "*.txn-tmp",
    ".gitignore",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMergeMarker {
    pub version: u32,
    pub created_at: i64,
    /// Public SHA-256 of the merged `secrets.lock` produced by the driver;
    /// `None` when only `vault.toml` was merged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_sha256_b64: Option<String>,
    /// Public SHA-256 of the merged `vault.toml` produced by the driver;
    /// `None` when only `secrets.lock` was merged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_sha256_b64: Option<String>,
    /// Every secret id present in the merged `secrets.lock` (used to enforce
    /// the SDK-wrapping invariant during the coordinated vault merge).
    #[serde(default)]
    pub merged_ids: Vec<String>,
    /// Ids where both sides changed the record and `theirs` won: their SDK
    /// wrapping must win too, so wrapping and ciphertext never diverge.
    #[serde(default)]
    pub theirs_won: Vec<String>,
    /// Merge diff relative to the local (`ours`) side — names only, never values.
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub changed: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
    /// Recipients from `theirs` rejected because their grant signature did not
    /// verify against a known authorized signer (H3) — `label (fingerprint)`.
    #[serde(default)]
    pub rejected_recipients: Vec<String>,
    /// Authorized-signer entries from `theirs` rejected for the same reason.
    #[serde(default)]
    pub rejected_signers: Vec<String>,
}

impl PendingMergeMarker {
    pub fn new() -> Self {
        Self {
            version: MARKER_VERSION,
            created_at: current_unix_timestamp(),
            secrets_sha256_b64: None,
            vault_sha256_b64: None,
            merged_ids: Vec::new(),
            theirs_won: Vec::new(),
            added: Vec::new(),
            changed: Vec::new(),
            removed: Vec::new(),
            rejected_recipients: Vec::new(),
            rejected_signers: Vec::new(),
        }
    }
}

impl Default for PendingMergeMarker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn marker_path(lock_dir: &Path) -> PathBuf {
    lock_dir.join(PENDING_MERGE_FILE)
}

pub fn load_marker(lock_dir: &Path) -> DotLockResult<Option<PendingMergeMarker>> {
    let path = marker_path(lock_dir);
    if !path.exists() {
        return Ok(None);
    }
    let content = secure_fs::read_to_string(&path)?;
    let marker = toml::from_str::<PendingMergeMarker>(&content).map_err(|err| {
        DotLockError::Io(format!(
            "unreadable pending-merge marker at {}: {err}",
            path.display()
        ))
    })?;
    Ok(Some(marker))
}

pub fn save_marker(lock_dir: &Path, marker: &PendingMergeMarker) -> DotLockResult<()> {
    let content =
        toml::to_string_pretty(marker).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    secure_fs::write_string_atomic(&marker_path(lock_dir), &content, 0o700, 0o600)?;
    ensure_lock_gitignore(lock_dir)
}

pub fn remove_marker(lock_dir: &Path) -> DotLockResult<()> {
    match std::fs::remove_file(marker_path(lock_dir)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(DotLockError::from(err)),
    }
}

/// Fails with [`DotLockError::UnreconciledMerge`] while a pending-merge marker
/// exists. Called on every unlock so no command (interactive or CI) can read
/// or write merged-but-unblessed content.
pub fn ensure_no_pending_merge(lock_dir: &Path) -> DotLockResult<()> {
    if load_marker(lock_dir)?.is_some() {
        return Err(DotLockError::UnreconciledMerge);
    }
    Ok(())
}

/// Anti-laundering check: the files on disk must still be exactly what the
/// merge driver produced. Any divergence means someone edited the merged
/// content after the merge, and reconcile must refuse to bless it.
pub fn verify_marker_matches_files(
    marker: &PendingMergeMarker,
    vault_path: &Path,
    secrets_path: &Path,
) -> DotLockResult<()> {
    if let Some(expected) = &marker.secrets_sha256_b64
        && &file_sha256_b64(secrets_path)? != expected
    {
        return Err(DotLockError::Io(
            "`.lock/secrets.lock` no longer matches the merge driver output recorded in the \
             pending-merge marker; refusing to re-sign tampered content"
                .to_string(),
        ));
    }
    if let Some(expected) = &marker.vault_sha256_b64
        && &file_sha256_b64(vault_path)? != expected
    {
        return Err(DotLockError::Io(
            "`.lock/vault.toml` no longer matches the merge driver output recorded in the \
             pending-merge marker; refusing to re-sign tampered content"
                .to_string(),
        ));
    }
    Ok(())
}

/// Core of `dl reconcile`: after the caller verified the marker against the
/// files and obtained explicit user confirmation plus a full-access DEK, this
/// enforces the SDK invariant, re-signs the integrity hash under the DEK
/// (committed via the transactional vault-pair write) and removes the marker.
pub fn reconcile_pending_merge(
    vault_path: &Path,
    secrets_path: &Path,
    lock_dir: &Path,
    dek: &ProjectKey,
) -> DotLockResult<()> {
    let marker = load_marker(lock_dir)?
        .ok_or_else(|| DotLockError::Io("no pending merge to reconcile".to_string()))?;
    verify_marker_matches_files(&marker, vault_path, secrets_path)?;

    let metadata = load_vault_metadata(vault_path)?;
    let file = load_secrets_file(secrets_path)?;
    if metadata.version >= 5 {
        // Post-merge invariant: every merged secret keeps a wrapping that the
        // project key can open. A violation means the merge orphaned a secret
        // and the vault must be repaired instead of blessed.
        for secret in &file.secrets {
            let wrapped = metadata
                .wrapped_sdks_under_dek
                .get(&secret.id)
                .ok_or_else(|| DotLockError::MissingSecretKeyWrapping {
                    id: secret.id.clone(),
                })?;
            let secret_key = sdk::unwrap_sdk_with_project_key(wrapped, dek)?;
            // H2: authenticate the record against its claimed
            // id/name/updated_at/version before blessing. A replayed old
            // ciphertext carrying forged ordering metadata (which is how a
            // rollback wins `choose_latest`) fails its AEAD check here, so
            // the merge stays unreconciled instead of being silently signed.
            crate::storage::secrets_lock::decrypt_record_with_key(secret, &secret_key)?;
        }
    }

    let vault_path_str = vault_path
        .to_str()
        .ok_or_else(|| DotLockError::Io("vault path is not valid UTF-8".to_string()))?;
    refresh_vault_hash(secrets_path, dek, vault_path_str)?;
    remove_marker(lock_dir)
}

fn ensure_lock_gitignore(lock_dir: &Path) -> DotLockResult<()> {
    let path = lock_dir.join(".gitignore");
    let existing = if path.exists() {
        secure_fs::read_to_string(&path)?
    } else {
        String::new()
    };

    let missing: Vec<&str> = LOCK_GITIGNORE_ENTRIES
        .iter()
        .copied()
        .filter(|entry| !existing.lines().any(|line| line.trim() == *entry))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    for entry in missing {
        content.push_str(entry);
        content.push('\n');
    }
    secure_fs::write_string_atomic(&path, &content, 0o700, 0o600)
}

/// Parses the interactive confirmation answer for `dl reconcile`.
pub fn confirmation_is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-marker-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    #[test]
    fn marker_roundtrip_and_gitignore() {
        let dir = temp_dir("roundtrip");
        let mut marker = PendingMergeMarker::new();
        marker.secrets_sha256_b64 = Some("hash".to_string());
        marker.merged_ids = vec!["id-a".to_string()];
        save_marker(&dir, &marker).expect("save");

        let loaded = load_marker(&dir).expect("load").expect("present");
        assert_eq!(loaded.secrets_sha256_b64.as_deref(), Some("hash"));
        assert_eq!(loaded.merged_ids, vec!["id-a".to_string()]);

        let gitignore = fs::read_to_string(dir.join(".gitignore")).expect("gitignore");
        assert!(gitignore.lines().any(|line| line == "pending-merge"));
        assert!(gitignore.lines().any(|line| line == "txn.journal"));

        assert!(matches!(
            ensure_no_pending_merge(&dir),
            Err(DotLockError::UnreconciledMerge)
        ));
        remove_marker(&dir).expect("remove");
        ensure_no_pending_merge(&dir).expect("clean after removal");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn confirmation_parsing() {
        assert!(confirmation_is_yes("y"));
        assert!(confirmation_is_yes(" YES \n"));
        assert!(!confirmation_is_yes(""));
        assert!(!confirmation_is_yes("n"));
        assert!(!confirmation_is_yes("nope"));
    }
}
