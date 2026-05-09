use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Cursor, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    audit::rotate::rotate_if_needed,
    crypto::share::sign_audit_entry_hash,
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        identity::{load_local_identity, load_local_identity_metadata},
        secure_fs,
        vault_file::load_vault_metadata,
    },
};

const AUDIT_DIR: &str = "audit";
const AUDIT_FILE: &str = "audit.log";
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub v: u32,
    pub ts: u64,
    pub action: String,
    pub payload: Value,
    pub prev_hash: String,
    pub entry_hash: String,
    pub signer_fingerprint: String,
    pub signature: String,
}

#[derive(Serialize)]
struct HashMaterial<'a> {
    v: u32,
    ts: u64,
    action: &'a str,
    payload: &'a Value,
    prev_hash: &'a str,
}

pub fn audit_log_path() -> DotLockResult<PathBuf> {
    let metadata = load_vault_metadata(".lock/vault.toml")?;
    Ok(audit_root().join(metadata.project_uuid).join(AUDIT_FILE))
}

pub fn append_entry(action: &str, payload: Value) -> DotLockResult<()> {
    let path = audit_log_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| DotLockError::Io(format!("invalid audit path: {}", path.display())))?;
    secure_fs::ensure_dir(parent, 0o700)?;
    let _lock = AuditLock::acquire(parent)?;
    rotate_if_needed(&path)?;
    secure_fs::reject_symlink(&path)?;

    let prev_hash = last_entry_hash_across_logs(&path)?.unwrap_or_else(|| ZERO_HASH.to_string());
    let ts = now_secs();
    let entry_hash = compute_entry_hash(ts, action, &payload, &prev_hash)?;
    let (signer_fingerprint, signature) = sign_entry_best_effort(&entry_hash);
    let entry = AuditEntry {
        v: 1,
        ts,
        action: action.to_string(),
        payload,
        prev_hash,
        entry_hash,
        signer_fingerprint,
        signature,
    };

    let line = serde_json::to_string(&entry).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(DotLockError::from)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{line}").map_err(DotLockError::from)?;
    Ok(())
}

struct AuditLock {
    path: PathBuf,
}

impl AuditLock {
    fn acquire(parent: &Path) -> DotLockResult<Self> {
        let path = parent.join(".audit.log.lock");
        let started = SystemTime::now();
        loop {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    writeln!(file, "{}", now_secs()).map_err(DotLockError::from)?;
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if started
                        .elapsed()
                        .map(|elapsed| elapsed.as_secs())
                        .unwrap_or(0)
                        >= 10
                    {
                        return Err(DotLockError::Io(format!(
                            "timed out waiting for audit lock: {}",
                            path.display()
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(err) => return Err(DotLockError::from(err)),
            }
        }
    }
}

impl Drop for AuditLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn read_entries(path: &Path) -> DotLockResult<Vec<AuditEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    secure_fs::reject_symlink(path)?;
    read_entries_from_reader(path, open_log_reader(path)?)
}

pub fn read_all_entries(path: &Path) -> DotLockResult<Vec<AuditEntry>> {
    let mut entries = Vec::new();
    for log_path in audit_log_paths(path)? {
        entries.extend(read_entries(&log_path)?);
    }
    Ok(entries)
}

fn read_entries_from_reader<R: Read>(path: &Path, reader: R) -> DotLockResult<Vec<AuditEntry>> {
    let reader = BufReader::new(reader);
    let mut entries = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(DotLockError::from)?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<AuditEntry>(&line).map_err(|e| {
            DotLockError::Crypto(format!(
                "failed to parse audit line {} in {}: {e}",
                index + 1,
                path.display()
            ))
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

pub fn show_entries(verbose: bool, since: Option<&str>, action: Option<&str>) -> DotLockResult<()> {
    let path = audit_log_path()?;
    let since_ts = since.map(parse_since_date).transpose()?;
    let entries = read_all_entries(&path)?;

    for entry in entries {
        if since_ts.is_some_and(|since| entry.ts < since) {
            continue;
        }
        if action.is_some_and(|wanted| entry.action != wanted) {
            continue;
        }

        if verbose {
            println!(
                "{} {} {} {}",
                entry.ts,
                entry.action,
                entry.signer_fingerprint,
                serde_json::to_string(&entry.payload)
                    .map_err(|e| DotLockError::Crypto(e.to_string()))?
            );
            println!("  prev_hash: {}", entry.prev_hash);
            println!("  entry_hash: {}", entry.entry_hash);
            println!("  signature: {}", entry.signature);
        } else {
            println!(
                "{} {:<8} {}",
                entry.ts,
                entry.action,
                summarize_payload(&entry.payload)
            );
        }
    }

    Ok(())
}

pub fn compute_entry_hash(
    ts: u64,
    action: &str,
    payload: &Value,
    prev_hash: &str,
) -> DotLockResult<String> {
    let material = HashMaterial {
        v: 1,
        ts,
        action,
        payload,
        prev_hash,
    };
    let bytes = serde_json::to_vec(&material).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    Ok(format!("sha256:{}", hex_lower(&Sha256::digest(bytes))))
}

fn last_entry_hash_across_logs(path: &Path) -> DotLockResult<Option<String>> {
    let entries = read_all_entries(path)?;
    Ok(entries.last().map(|entry| entry.entry_hash.clone()))
}

fn audit_log_paths(path: &Path) -> DotLockResult<Vec<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(Vec::new());
    };
    if !parent.exists() {
        return Ok(Vec::new());
    }

    let current_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let rotated_prefix = format!("{current_name}.");
    let mut paths = Vec::new();

    for entry in fs::read_dir(parent).map_err(DotLockError::from)? {
        let entry = entry.map_err(DotLockError::from)?;
        let entry_path = entry.path();
        let Some(name) = entry_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == current_name || name.starts_with(&rotated_prefix) {
            paths.push(entry_path);
        }
    }

    paths.sort_by(|left, right| log_sort_key(left).cmp(&log_sort_key(right)));
    Ok(paths)
}

fn log_sort_key(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if name == AUDIT_FILE {
        return format!("{AUDIT_FILE}.~current");
    }
    name.to_string()
}

fn open_log_reader(path: &Path) -> DotLockResult<Box<dyn Read>> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("gz") {
        return fs::File::open(path)
            .map(|file| Box::new(file) as Box<dyn Read>)
            .map_err(DotLockError::from);
    }

    let output = Command::new("gzip")
        .args(["-cd", path.to_str().unwrap_or_default()])
        .output()
        .map_err(|err| DotLockError::Io(format!("failed to run gzip: {err}")))?;
    if !output.status.success() {
        return Err(DotLockError::Io(format!(
            "gzip failed while reading rotated audit log {}",
            path.display()
        )));
    }
    Ok(Box::new(Cursor::new(output.stdout)))
}

fn sign_entry_best_effort(entry_hash: &str) -> (String, String) {
    let Ok(metadata) = load_local_identity_metadata() else {
        return ("anonymous".to_string(), String::new());
    };
    if metadata.encrypted {
        return ("anonymous".to_string(), String::new());
    }
    let Ok(identity) = load_local_identity() else {
        return ("anonymous".to_string(), String::new());
    };
    match sign_audit_entry_hash(entry_hash, &identity.private_key_pem) {
        Ok(signature) => (identity.fingerprint, signature),
        Err(_) => ("anonymous".to_string(), String::new()),
    }
}

fn audit_root() -> PathBuf {
    if let Ok(dir) = std::env::var("DOTLOCK_AUDIT_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return Path::new(&home).join(".lock").join(AUDIT_DIR);
        }
    }

    #[cfg(windows)]
    {
        if let Ok(dir) = std::env::var("LOCALAPPDATA") {
            return Path::new(&dir).join("dotlock").join(AUDIT_DIR);
        }
    }

    PathBuf::from(".").join(".lock").join(AUDIT_DIR)
}

fn summarize_payload(payload: &Value) -> String {
    if let Some(cmd) = payload.get("cmd").and_then(|value| value.as_array()) {
        let cmd = cmd
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        return format!("cmd={cmd}");
    }
    if let Some(method) = payload.get("method").and_then(|value| value.as_str()) {
        let mode = payload
            .get("access_mode")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        return format!("method={method} access_mode={mode}");
    }
    payload.to_string()
}

fn parse_since_date(value: &str) -> DotLockResult<u64> {
    let mut parts = value.split('-');
    let year = parts
        .next()
        .and_then(|part| part.parse::<i32>().ok())
        .ok_or_else(|| DotLockError::Io("expected --since YYYY-MM-DD".to_string()))?;
    let month = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .ok_or_else(|| DotLockError::Io("expected --since YYYY-MM-DD".to_string()))?;
    let day = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .ok_or_else(|| DotLockError::Io("expected --since YYYY-MM-DD".to_string()))?;
    if parts.next().is_some() {
        return Err(DotLockError::Io("expected --since YYYY-MM-DD".to_string()));
    }
    Ok(days_from_civil(year, month, day)? * 86_400)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> DotLockResult<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(DotLockError::Io("invalid --since date".to_string()));
    }
    let month = month as i64;
    let day = day as i64;
    let year = year as i64 - (month <= 2) as i64;
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146097 + doe as i64 - 719468;
    if days < 0 {
        return Err(DotLockError::Io("invalid --since date".to_string()));
    }
    Ok(days as u64)
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::compute_entry_hash;

    #[test]
    fn entry_hash_changes_when_payload_changes() {
        let first = compute_entry_hash(1, "run", &json!({"cmd":["a"]}), "sha256:0").expect("hash");
        let second = compute_entry_hash(1, "run", &json!({"cmd":["b"]}), "sha256:0").expect("hash");

        assert_ne!(first, second);
    }

    #[test]
    fn entry_hash_changes_when_previous_hash_changes() {
        let first = compute_entry_hash(1, "run", &json!({"cmd":["a"]}), "sha256:0").expect("hash");
        let second = compute_entry_hash(1, "run", &json!({"cmd":["a"]}), "sha256:1").expect("hash");

        assert_ne!(first, second);
    }
}
