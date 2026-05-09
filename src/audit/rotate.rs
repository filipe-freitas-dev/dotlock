use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::domain::{error::DotLockError, model::DotLockResult};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const MAX_LOG_AGE_SECS: u64 = 90 * 24 * 60 * 60;

pub fn rotate_if_needed(path: &Path) -> DotLockResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::metadata(path).map_err(DotLockError::from)?;
    let too_large = metadata.len() >= MAX_LOG_BYTES;
    let too_old = metadata
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age.as_secs() >= MAX_LOG_AGE_SECS);

    if too_large || too_old {
        rotate_current_log_at(path, now_secs())?;
    }
    Ok(())
}

pub fn rotate_current_log(path: &Path) -> DotLockResult<Option<std::path::PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    rotate_current_log_at(path, now_secs()).map(Some)
}

fn rotate_current_log_at(path: &Path, ts: u64) -> DotLockResult<std::path::PathBuf> {
    let rotated = path.with_file_name(format!("audit.log.{ts}"));
    fs::rename(path, &rotated).map_err(DotLockError::from)?;
    let status = Command::new("gzip")
        .args(["-f", rotated.to_str().unwrap_or_default()])
        .status()
        .map_err(|err| DotLockError::Io(format!("failed to run gzip: {err}")))?;
    if !status.success() {
        return Err(DotLockError::Io(
            "gzip failed while rotating audit log".to_string(),
        ));
    }
    Ok(rotated.with_extension(format!(
        "{}gz",
        rotated
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    )))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
