//! Per-user rollback anchor for the vault's monotonic epoch (M3).
//!
//! The `vault_epoch` counter inside `vault.toml` is authenticated by the
//! metadata MAC, but an attacker with repo write access can restore an ENTIRE
//! older vault pair, which is internally self-consistent. The only defense is
//! an anchor OUTSIDE the repo: the newest epoch this machine has ever seen,
//! persisted under the per-user DotLock data root (never the project's
//! committable `.lock/`). Unlock refuses to move backward past it.
//!
//! Limits (documented, not silently ignored): the anchor is per-machine, so a
//! rollback pushed to a remote is only caught on machines that already saw the
//! newer epoch; and a legitimate checkout of an older revision looks exactly
//! like a rollback — `DOTLOCK_ALLOW_VAULT_ROLLBACK=1` lets the user accept it
//! explicitly (an attacker with mere repo write access cannot set the victim's
//! environment).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    domain::{error::DotLockError, model::DotLockResult},
    storage::{paths::dotlock_data_root, secure_fs},
};

const EPOCH_DIR: &str = "epoch";

#[derive(Debug, Serialize, Deserialize)]
struct EpochAnchor {
    epoch: u64,
}

/// Anchor file path for a project under `root`. The uuid comes from
/// attacker-writable repo metadata, so it is hashed instead of being used as
/// a path component.
fn anchor_path_in(root: &Path, project_uuid: &str) -> PathBuf {
    let digest = Sha256::digest(project_uuid.as_bytes());
    let mut name = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    root.join(EPOCH_DIR).join(format!("{name}.toml"))
}

fn last_seen_epoch_in(root: &Path, project_uuid: &str) -> Option<u64> {
    let path = anchor_path_in(root, project_uuid);
    if !path.exists() {
        return None;
    }
    let content = secure_fs::read_to_string(&path).ok()?;
    toml::from_str::<EpochAnchor>(&content)
        .ok()
        .map(|anchor| anchor.epoch)
}

fn advance_epoch_in(root: &Path, project_uuid: &str, epoch: u64) -> DotLockResult<()> {
    if last_seen_epoch_in(root, project_uuid).is_some_and(|stored| stored >= epoch) {
        return Ok(());
    }
    let path = anchor_path_in(root, project_uuid);
    let content =
        toml::to_string(&EpochAnchor { epoch }).map_err(|e| DotLockError::Io(e.to_string()))?;
    secure_fs::write_string_atomic(&path, &content, 0o700, 0o600)
}

/// Newest epoch ever seen on this machine for the project, if any.
pub fn last_seen_epoch(project_uuid: &str) -> Option<u64> {
    let root = dotlock_data_root().ok()?;
    last_seen_epoch_in(&root, project_uuid)
}

/// Advances the anchor to `epoch` if it is newer than what is stored. Never
/// moves backward.
pub fn advance_epoch(project_uuid: &str, epoch: u64) -> DotLockResult<()> {
    advance_epoch_in(&dotlock_data_root()?, project_uuid, epoch)
}

#[cfg(test)]
mod tests {
    use super::{advance_epoch_in, last_seen_epoch_in};

    #[test]
    fn anchor_advances_monotonically_and_never_moves_backward() {
        let dir = std::env::temp_dir().join(format!(
            "dotlock-epoch-anchor-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create dir");
        let uuid = "test-uuid";

        assert_eq!(last_seen_epoch_in(&dir, uuid), None);
        advance_epoch_in(&dir, uuid, 3).expect("advance to 3");
        assert_eq!(last_seen_epoch_in(&dir, uuid), Some(3));
        advance_epoch_in(&dir, uuid, 2).expect("no-op backward");
        assert_eq!(last_seen_epoch_in(&dir, uuid), Some(3));
        advance_epoch_in(&dir, uuid, 5).expect("advance to 5");
        assert_eq!(last_seen_epoch_in(&dir, uuid), Some(5));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
