use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::domain::{error::DotLockError, model::DotLockResult};

const PROVIDER_PREFIX: &str = "dotlock-provider-";
const MAX_PROVIDER_STDOUT: usize = 64 * 1024;
const MAX_PROVIDER_STDERR: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAttestation {
    pub path: PathBuf,
    pub sha256: String,
}

pub fn resolve_provider(
    provider: &str,
    config: &Value,
    bootstrap: &Map<String, Value>,
    expected_sha256: Option<&str>,
    path_override: Option<&Path>,
    timeout_secs: u64,
) -> DotLockResult<String> {
    let binary = find_provider_binary(provider, path_override)?.ok_or_else(|| {
        DotLockError::Io(format!(
            "provider '{provider}' not found; install {PROVIDER_PREFIX}{provider}"
        ))
    })?;
    // M7a: open once and hash from the open descriptor; the exec below runs
    // the SAME open file (via /proc/self/fd on Linux), so the hashed bytes
    // are the executed bytes — no hash->exec swap window.
    let binary_file = std::fs::File::open(&binary).map_err(DotLockError::from)?;
    let actual_sha256 = sha256_hex_of_reader(&binary_file)?;
    if let Some(expected_sha256) = expected_sha256.filter(|expected| *expected != actual_sha256) {
        return Err(DotLockError::Io(format!(
            "provider '{provider}' hash mismatch; expected {expected_sha256}, got {actual_sha256}"
        )));
    }
    if let Some(warning) = unpinned_provider_warning(provider, expected_sha256) {
        eprintln!("{warning}");
    }
    let input = json!({
        "config": config,
        "bootstrap": bootstrap,
    });
    run_provider(&binary, binary_file, &input, timeout_secs)
}

/// M7d: a dynamic secret whose provider has no pinned sha256 executes whatever
/// binary currently shadows the name — warn loudly. Re-run `dl set --provider`
/// to attest and pin the binary.
fn unpinned_provider_warning(provider: &str, expected_sha256: Option<&str>) -> Option<String> {
    if expected_sha256.is_some() {
        return None;
    }
    Some(format!(
        "warn: provider '{provider}' is NOT sha256-pinned; any binary named \
         {PROVIDER_PREFIX}{provider} on PATH will be executed. \
         Re-run `dl set <NAME> --provider {provider}` to pin it."
    ))
}

pub fn attest_provider(
    provider: &str,
    path_override: Option<&Path>,
) -> DotLockResult<ProviderAttestation> {
    let path = find_provider_binary(provider, path_override)?.ok_or_else(|| {
        DotLockError::Io(format!(
            "provider '{provider}' not found; install {PROVIDER_PREFIX}{provider}"
        ))
    })?;
    let sha256 = file_sha256_hex(&path)?;
    Ok(ProviderAttestation { path, sha256 })
}

pub fn describe_provider(provider: &str, path_override: Option<&Path>) -> DotLockResult<String> {
    let binary = find_provider_binary(provider, path_override)?.ok_or_else(|| {
        DotLockError::Io(format!(
            "provider '{provider}' not found; install {PROVIDER_PREFIX}{provider}"
        ))
    })?;
    let output = Command::new(binary)
        .arg("--describe")
        .output()
        .map_err(|err| DotLockError::Io(format!("failed to run provider '{provider}': {err}")))?;
    if !output.status.success() {
        return Err(DotLockError::Io(format!(
            "provider '{provider}' describe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout).map_err(|err| DotLockError::Crypto(err.to_string()))
}

pub fn list_providers(path_override: Option<&Path>) -> DotLockResult<Vec<String>> {
    let mut providers = BTreeSet::new();
    for dir in provider_search_dirs(path_override) {
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&dir).map_err(DotLockError::from)? {
            let entry = entry.map_err(DotLockError::from)?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if let Some(provider) = name.strip_prefix(PROVIDER_PREFIX) {
                providers.insert(provider.to_string());
            }
        }
    }
    Ok(providers.into_iter().collect())
}

/// On Linux, a non-close-on-exec dup of the hashed descriptor so the child can
/// be exec'd through `/proc/self/fd/<n>` — the same open file description that
/// was hashed. Closed on drop.
#[cfg(target_os = "linux")]
struct ExecFd(std::os::fd::RawFd);

#[cfg(target_os = "linux")]
impl ExecFd {
    fn dup_from(file: &std::fs::File) -> DotLockResult<Self> {
        use std::os::fd::AsRawFd;
        // F_DUPFD (not F_DUPFD_CLOEXEC): the fd must survive into the child so
        // `/proc/self/fd/<n>` resolves there, including for `#!` interpreters
        // that re-open the script path after exec.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 3) };
        if fd < 0 {
            return Err(DotLockError::Io(format!(
                "failed to duplicate provider descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self(fd))
    }
}

#[cfg(target_os = "linux")]
impl Drop for ExecFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

fn run_provider(
    binary: &Path,
    binary_file: std::fs::File,
    input: &Value,
    timeout_secs: u64,
) -> DotLockResult<String> {
    // M7a: execute the exact file that was hashed. On Linux we exec the open
    // descriptor itself (fexecve-style via /proc/self/fd); elsewhere we hold
    // the descriptor open — which pins the inode we hashed — and exec by
    // path, accepting the residual path-swap window on those platforms.
    #[cfg(target_os = "linux")]
    let exec_fd = ExecFd::dup_from(&binary_file)?;
    #[cfg(target_os = "linux")]
    let program = std::path::PathBuf::from(format!("/proc/self/fd/{}", exec_fd.0));
    #[cfg(not(target_os = "linux"))]
    let program = binary.to_path_buf();
    #[cfg(target_os = "linux")]
    let _ = binary;

    let mut child = Command::new(&program)
        .arg("--resolve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| DotLockError::Io(format!("failed to run provider: {err}")))?;
    // The hashed descriptor may be dropped once the child is spawned.
    drop(binary_file);
    #[cfg(target_os = "linux")]
    drop(exec_fd);

    if let Some(mut stdin) = child.stdin.take() {
        let payload =
            serde_json::to_vec(input).map_err(|err| DotLockError::Crypto(err.to_string()))?;
        stdin.write_all(&payload).map_err(DotLockError::from)?;
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| DotLockError::Io("provider stdout unavailable".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| DotLockError::Io("provider stderr unavailable".to_string()))?;
    let stdout_reader = thread::spawn(move || read_limited(stdout, MAX_PROVIDER_STDOUT));
    let stderr_reader = thread::spawn(move || read_limited(stderr, MAX_PROVIDER_STDERR));

    let started = Instant::now();
    let timeout = Duration::from_secs(timeout_secs.max(1));
    loop {
        if child.try_wait().map_err(DotLockError::from)?.is_some() {
            let status = child.wait().map_err(DotLockError::from)?;
            let stdout = stdout_reader
                .join()
                .map_err(|_| DotLockError::Io("provider stdout reader panicked".to_string()))??;
            let stderr = stderr_reader
                .join()
                .map_err(|_| DotLockError::Io("provider stderr reader panicked".to_string()))??;
            if stdout.truncated {
                return Err(DotLockError::Io(
                    "provider output exceeded 65536 bytes".to_string(),
                ));
            }
            if stderr.truncated {
                return Err(DotLockError::Io(
                    "provider stderr exceeded 16384 bytes".to_string(),
                ));
            }
            if !status.success() {
                return Err(DotLockError::Io(format!(
                    "provider failed: {}",
                    String::from_utf8_lossy(&stderr.bytes).trim()
                )));
            }
            let value = String::from_utf8(stdout.bytes)
                .map_err(|err| DotLockError::Crypto(err.to_string()))?;
            return Ok(value.trim_end_matches(['\r', '\n']).to_string());
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(DotLockError::Io("provider timed out".to_string()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct LimitedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> DotLockResult<LimitedOutput> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer).map_err(DotLockError::from)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        if remaining == 0 {
            truncated = true;
            continue;
        }
        let keep = remaining.min(read);
        bytes.extend_from_slice(&buffer[..keep]);
        if keep < read {
            truncated = true;
        }
    }
    Ok(LimitedOutput { bytes, truncated })
}

/// M7b: provider names participate in binary resolution
/// (`{PROVIDER_PREFIX}{name}` joined onto PATH entries), so anything outside
/// `^[a-z0-9][a-z0-9_-]*$` — separators, dots, uppercase — is rejected before
/// it can traverse into arbitrary paths (e.g. `../bin/sh`).
fn validate_provider_name(provider: &str) -> DotLockResult<()> {
    let mut chars = provider.chars();
    let valid = match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() => {
            chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DotLockError::Io(format!(
            "invalid provider name '{provider}': must match ^[a-z0-9][a-z0-9_-]*$"
        )))
    }
}

fn find_provider_binary(
    provider: &str,
    path_override: Option<&Path>,
) -> DotLockResult<Option<PathBuf>> {
    validate_provider_name(provider)?;
    let binary_name = format!("{PROVIDER_PREFIX}{provider}");
    for dir in provider_search_dirs(path_override) {
        reject_insecure_provider_dir(&dir)?;
        let candidate = dir.join(&binary_name);
        if candidate.is_file() {
            reject_insecure_provider_binary(&candidate)?;
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn provider_search_dirs(path_override: Option<&Path>) -> Vec<PathBuf> {
    if let Some(dir) = path_override {
        return vec![dir.to_path_buf()];
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).collect())
        .unwrap_or_default()
}

fn file_sha256_hex(path: &Path) -> DotLockResult<String> {
    let file = std::fs::File::open(path).map_err(DotLockError::from)?;
    sha256_hex_of_reader(&file)
}

fn sha256_hex_of_reader(mut reader: impl Read) -> DotLockResult<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(DotLockError::from)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex_lower(&hasher.finalize())))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// M7c: a provider directory (or the binary inside it) that another
/// non-root user can rewrite is an arbitrary-code-execution primitive.
/// Reject group/world-writable paths and paths not owned by us or root.
#[cfg(unix)]
fn reject_insecure_unix_path(
    metadata: &std::fs::Metadata,
    what: &str,
    path: &Path,
) -> DotLockResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(DotLockError::Io(format!(
            "refusing provider {what} writable by group or others: {}",
            path.display()
        )));
    }
    let owner = metadata.uid();
    let me = unsafe { libc::geteuid() };
    if owner != me && owner != 0 {
        return Err(DotLockError::Io(format!(
            "refusing provider {what} owned by another user (uid {owner}): {}",
            path.display()
        )));
    }
    Ok(())
}

fn reject_insecure_provider_dir(dir: &Path) -> DotLockResult<()> {
    #[cfg(unix)]
    {
        let Ok(metadata) = std::fs::metadata(dir) else {
            return Ok(());
        };
        reject_insecure_unix_path(&metadata, "directory", dir)?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn reject_insecure_provider_binary(binary: &Path) -> DotLockResult<()> {
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(binary).map_err(DotLockError::from)?;
        reject_insecure_unix_path(&metadata, "binary", binary)?;
    }
    #[cfg(not(unix))]
    let _ = binary;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;

    use crate::providers::resolve_provider;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-provider-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        // Umask-independent baseline; individual tests loosen this on purpose.
        #[cfg(unix)]
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        dir
    }

    fn write_executable(path: &Path, content: &str) {
        let mut file = fs::File::create(path).expect("create provider");
        file.write_all(content.as_bytes()).expect("write provider");
        #[cfg(unix)]
        {
            let mut permissions = file.metadata().expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("chmod");
        }
    }

    #[test]
    fn resolves_provider_with_json_stdin_protocol() {
        let dir = temp_dir("resolve");
        let provider_path = dir.join("dotlock-provider-echo");
        write_executable(
            &provider_path,
            r#"#!/bin/sh
if [ "$1" = "--describe" ]; then
  echo '{"name":"echo","version":"0.0.1","config_schema":{},"bootstrap_required":[]}'
  exit 0
fi
python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["config"]["value"])'
"#,
        );

        let value = resolve_provider(
            "echo",
            &json!({"value": "minted"}),
            &serde_json::Map::new(),
            None,
            Some(&dir),
            5,
        )
        .expect("resolve");

        assert_eq!(value, "minted");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_provider_names_with_path_traversal() {
        for name in ["../bin/sh", "a/b", "UPPER", "-leading", "", "dot.dot"] {
            let err = resolve_provider(
                name,
                &json!({}),
                &serde_json::Map::new(),
                None,
                Some(Path::new("/nonexistent")),
                1,
            )
            .expect_err("traversal name must be rejected");
            assert!(
                err.to_string().contains("invalid provider name"),
                "unexpected error for {name:?}: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_writable_provider_directory() {
        let dir = temp_dir("group-writable");
        let provider_path = dir.join("dotlock-provider-echo");
        write_executable(&provider_path, "#!/bin/sh\necho hi\n");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).expect("chmod dir");

        let err = resolve_provider(
            "echo",
            &json!({}),
            &serde_json::Map::new(),
            None,
            Some(&dir),
            1,
        )
        .expect_err("group-writable dir must be rejected");
        assert!(
            err.to_string().contains("writable by group or others"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_writable_provider_binary() {
        let dir = temp_dir("gw-binary");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let provider_path = dir.join("dotlock-provider-echo");
        write_executable(&provider_path, "#!/bin/sh\necho hi\n");
        fs::set_permissions(&provider_path, fs::Permissions::from_mode(0o775)).expect("chmod bin");

        let err = resolve_provider(
            "echo",
            &json!({}),
            &serde_json::Map::new(),
            None,
            Some(&dir),
            1,
        )
        .expect_err("group-writable binary must be rejected");
        assert!(
            err.to_string()
                .contains("provider binary writable by group or others"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unpinned_provider_warns_and_pinned_does_not() {
        let warning =
            super::unpinned_provider_warning("vaultmint", None).expect("unpinned must warn");
        assert!(warning.contains("NOT sha256-pinned"));
        assert!(warning.contains("vaultmint"));
        assert!(super::unpinned_provider_warning("vaultmint", Some("sha256:abc")).is_none());
    }
}
