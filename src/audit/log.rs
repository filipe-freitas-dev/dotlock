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
        identity::{load_local_identity, load_local_identity_metadata, session_signer},
        paths::dotlock_data_root,
        secure_fs,
        vault_file::load_vault_metadata,
    },
};

const AUDIT_DIR: &str = "audit";
const AUDIT_FILE: &str = "audit.log";
const HWM_FILE: &str = "hwm.toml";
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

/// Signed monotonic high-water mark for the audit log: total entry count
/// (across rotated logs) plus the hash of the newest entry. Deleting the last
/// N entries leaves a log shorter than the recorded count, which `dl audit
/// verify` rejects (tail-truncation detection, H4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHighWaterMark {
    pub count: u64,
    pub head_hash: String,
    #[serde(default)]
    pub signer_fingerprint: String,
    #[serde(default)]
    pub signature: String,
}

pub fn hwm_material(count: u64, head_hash: &str) -> String {
    format!("dotlock:v1:audit-hwm:count={count}:head={head_hash}")
}

pub fn load_high_water_mark(log_path: &Path) -> DotLockResult<Option<AuditHighWaterMark>> {
    let Some(parent) = log_path.parent() else {
        return Ok(None);
    };
    let path = parent.join(HWM_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let content = secure_fs::read_to_string(&path)?;
    let hwm = toml::from_str::<AuditHighWaterMark>(&content)
        .map_err(|e| DotLockError::Crypto(format!("failed to parse audit high-water mark: {e}")))?;
    Ok(Some(hwm))
}

fn store_high_water_mark(log_path: &Path, count: u64, head_hash: &str) -> DotLockResult<()> {
    let Some(parent) = log_path.parent() else {
        return Ok(());
    };
    let (signer_fingerprint, signature) = sign_entry_best_effort(&hwm_material(count, head_hash));
    let hwm = AuditHighWaterMark {
        count,
        head_hash: head_hash.to_string(),
        signer_fingerprint,
        signature,
    };
    let content = toml::to_string(&hwm).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    secure_fs::write_string_atomic(&parent.join(HWM_FILE), &content, 0o700, 0o600)
}

pub fn audit_log_path() -> DotLockResult<PathBuf> {
    // Env-aware (FG3): each environment's vault has its own project_uuid, so
    // every environment gets its own audit log directory.
    let metadata = load_vault_metadata(crate::storage::project::vault_file())?;
    Ok(audit_root()?.join(metadata.project_uuid).join(AUDIT_FILE))
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

    let existing = read_all_entries(&path)?;
    let prev_hash = existing
        .last()
        .map(|entry| entry.entry_hash.clone())
        .unwrap_or_else(|| ZERO_HASH.to_string());
    let count = existing.len() as u64 + 1;
    if let Some(hwm) = load_high_water_mark(&path)?
        && hwm.count > count
    {
        return Err(DotLockError::Crypto(format!(
            "audit log has fewer entries ({}) than the recorded high-water mark ({}); the log tail was truncated",
            count - 1,
            hwm.count
        )));
    }
    let ts = now_secs();
    let entry_hash = compute_entry_hash(ts, action, &payload, &prev_hash)?;
    let (signer_fingerprint, signature) = sign_entry_best_effort(&entry_hash);
    let entry = AuditEntry {
        v: 1,
        ts,
        action: action.to_string(),
        payload,
        prev_hash,
        entry_hash: entry_hash.clone(),
        signer_fingerprint,
        signature,
    };

    let line = serde_json::to_string(&entry).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    // M9 (documented gap): on Windows there is no 0600 equivalent here; the
    // log inherits the parent directory's default ACLs. Restrictive DACL
    // support is tracked in README "Security Notes > Windows".
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
    // L4: fsync the appended entry so a crash right after the write cannot
    // lose (or leave torn on some filesystems) the last audit line.
    file.sync_all().map_err(DotLockError::from)?;
    store_high_water_mark(&path, count, &entry_hash)?;
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

/// Parses the JSONL audit log with tail-resilience (L4): a malformed FINAL
/// line is treated as an interrupted append (crash mid-write) — it is dropped
/// with a warning and every prior valid entry is returned, so one torn line
/// can never make the whole log (and further appends, which need
/// `read_all_entries`) unreadable. A malformed line in the MIDDLE of the file
/// is real corruption/tampering and stays a hard error; the hash-chain verify
/// distinguishes honest truncation from splicing.
fn read_entries_from_reader<R: Read>(path: &Path, reader: R) -> DotLockResult<Vec<AuditEntry>> {
    let reader = BufReader::new(reader);
    let mut lines = Vec::new();
    for line in reader.lines() {
        lines.push(line.map_err(DotLockError::from)?);
    }
    let last_content_index = lines.iter().rposition(|line| !line.trim().is_empty());

    let mut entries = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(_) if Some(index) == last_content_index => {
                eprintln!(
                    "warn: dropping malformed final audit line {} in {} (interrupted write)",
                    index + 1,
                    path.display()
                );
            }
            Err(e) => {
                return Err(DotLockError::Crypto(format!(
                    "failed to parse audit line {} in {}: {e}",
                    index + 1,
                    path.display()
                )));
            }
        }
    }
    Ok(entries)
}

pub fn show_entries(
    verbose: bool,
    since: Option<&str>,
    action: Option<&str>,
    json: bool,
) -> DotLockResult<()> {
    let path = audit_log_path()?;
    let since_ts = since.map(parse_since_date).transpose()?;
    let entries = read_all_entries(&path)?;
    let entries = entries.into_iter().filter(|entry| {
        !since_ts.is_some_and(|since| entry.ts < since)
            && !action.is_some_and(|wanted| entry.action != wanted)
    });

    if json {
        // FG1 schema: a JSON array of full audit entries (the same shape as
        // the on-disk JSONL lines: ts/action/payload/hash-chain/signature).
        let entries: Vec<AuditEntry> = entries.collect();
        println!(
            "{}",
            serde_json::to_string(&entries).map_err(|e| DotLockError::Crypto(e.to_string()))?
        );
        return Ok(());
    }

    for entry in entries {
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

    paths.sort_by_key(|path| log_sort_key(path));
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

pub(crate) fn sign_entry_best_effort(entry_hash: &str) -> (String, String) {
    // Prefer the in-memory session signer: it is populated whenever a local
    // identity is loaded (and decrypted, for passphrase-encrypted ones), so
    // encrypted identities sign audit entries instead of writing anonymous
    // ones (H4).
    if let Some(identity) = session_signer()
        && let Ok(signature) = sign_audit_entry_hash(entry_hash, &identity.private_key_pem)
    {
        return (identity.fingerprint, signature);
    }
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

/// Audit-root resolution hard-fails when no home/config directory resolves:
/// audit logs must never be written into a committable `./.lock` (H6).
fn audit_root() -> DotLockResult<PathBuf> {
    if let Ok(dir) = std::env::var("DOTLOCK_AUDIT_DIR")
        && !dir.trim().is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    Ok(dotlock_data_root()?.join(AUDIT_DIR))
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
    let days = era * 146097 + doe - 719468;
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

    use super::{compute_entry_hash, sign_entry_best_effort};
    use crate::{
        crypto::share::{IdentityProtection, generate_identity, verify_audit_entry_hash_signature},
        storage::{
            identity::{
                LocalIdentity, LocalIdentityMetadata, clear_session_signer,
                register_session_signer, test_identity_env_lock,
            },
            secure_fs,
        },
    };

    fn sample_entry_line(ts: u64, prev_hash: &str) -> (String, String) {
        let payload = json!({"cmd":["step"]});
        let entry_hash = compute_entry_hash(ts, "run", &payload, prev_hash).expect("hash");
        let entry = super::AuditEntry {
            v: 1,
            ts,
            action: "run".to_string(),
            payload,
            prev_hash: prev_hash.to_string(),
            entry_hash: entry_hash.clone(),
            signer_fingerprint: "anonymous".to_string(),
            signature: String::new(),
        };
        (serde_json::to_string(&entry).expect("json"), entry_hash)
    }

    /// L4: a torn trailing line (crash mid-append) must not make the whole
    /// log unreadable — prior entries stay readable, so appends can continue.
    #[test]
    fn torn_trailing_line_is_dropped_and_prior_entries_survive() {
        let (first, first_hash) = sample_entry_line(1000, super::ZERO_HASH);
        let (second, _) = sample_entry_line(1001, &first_hash);
        let torn = &second[..second.len() / 2];
        let content = format!("{first}\n{torn}");

        let entries = super::read_entries_from_reader(
            std::path::Path::new("torn.log"),
            std::io::Cursor::new(content.into_bytes()),
        )
        .expect("tail-torn log must stay readable");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ts, 1000);
    }

    /// L4: a malformed line in the MIDDLE is real corruption/tampering and
    /// must stay a hard error, never be silently dropped.
    #[test]
    fn corrupted_middle_line_is_a_hard_error() {
        let (first, first_hash) = sample_entry_line(1000, super::ZERO_HASH);
        let (second, _) = sample_entry_line(1001, &first_hash);
        let content = format!("{first}\nnot-json-at-all\n{second}\n");

        let err = super::read_entries_from_reader(
            std::path::Path::new("corrupt.log"),
            std::io::Cursor::new(content.into_bytes()),
        )
        .expect_err("mid-file corruption must fail");
        assert!(err.to_string().contains("failed to parse audit line 2"));
    }

    /// L4: a torn line that is also the ONLY line yields an empty (readable)
    /// log rather than an error.
    #[test]
    fn torn_only_line_yields_empty_log() {
        let entries = super::read_entries_from_reader(
            std::path::Path::new("only-torn.log"),
            std::io::Cursor::new(b"{\"v\":1,\"ts\":10".to_vec()),
        )
        .expect("single torn line tolerated");
        assert!(entries.is_empty());
    }

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

    #[test]
    fn session_signer_signs_entries_even_when_disk_identity_is_encrypted() {
        let _guard = test_identity_env_lock().lock().expect("lock");
        // Simulate the default setup: the on-disk identity is passphrase
        // encrypted (which previously always produced anonymous entries).
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-audit-signer-{unique}"));
        std::fs::create_dir_all(&dir).expect("create dir");
        let meta = LocalIdentityMetadata {
            fingerprint: "encrypted-fp".to_string(),
            encrypted: true,
            alg: crate::crypto::share::IDENTITY_ALG_ED25519.to_string(),
        };
        let content = toml::to_string_pretty(&meta).expect("meta");
        secure_fs::write_string_atomic(&dir.join("identity.toml"), &content, 0o700, 0o600)
            .expect("write meta");
        unsafe {
            std::env::set_var("DOTLOCK_IDENTITY_DIR", &dir);
        }

        clear_session_signer();
        // Without an unlocked signer in memory, encrypted identities fall
        // back to anonymous entries.
        let (fingerprint, signature) = sign_entry_best_effort("sha256:test");
        assert_eq!(fingerprint, "anonymous");
        assert!(signature.is_empty());

        // Once the identity is unlocked during the command, its decrypted
        // key signs audit entries in memory.
        let generated = generate_identity(IdentityProtection::Plain).expect("identity");
        register_session_signer(&LocalIdentity {
            fingerprint: generated.fingerprint.clone(),
            private_key_pem: generated.private_key_pem.clone(),
            public_key_pem: generated.public_key_pem.clone(),
        });
        let (fingerprint, signature) = sign_entry_best_effort("sha256:test");
        assert_eq!(fingerprint, generated.fingerprint);
        verify_audit_entry_hash_signature("sha256:test", &signature, &generated.public_key_pem)
            .expect("signature verifies");

        clear_session_signer();
        unsafe {
            std::env::remove_var("DOTLOCK_IDENTITY_DIR");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
