//! Transactional writes for the vault pair (`vault.toml` + `secrets.lock`).
//!
//! Every mutation of the pair goes through [`commit_vault_pair`], which uses a
//! journal plus double temp-rename so that a crash at any point leaves the pair
//! recoverable: either both files show the new state, or both show the old one.
//! [`recover_pending`] is called at the start of every vault access and resolves
//! any interrupted transaction (roll-forward or rollback) before reads happen.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{VaultKeyMetadata, integrity::compute_file_sha256},
    domain::{error::DotLockError, model::DotLockResult},
    storage::secure_fs,
};

const JOURNAL_FILE: &str = "txn.journal";
const LOCK_FILE: &str = ".txn.lock";
const TMP_SUFFIX: &str = ".txn-tmp";
const JOURNAL_VERSION: u32 = 1;

/// Final state of a vault pair mutation, built entirely in memory by the caller.
pub struct VaultPairWrite<'a> {
    /// Complete final metadata (SDK wrappings and `secrets_hash_*` already recomputed).
    pub metadata: &'a VaultKeyMetadata,
    /// New `secrets.lock` bytes; `None` means the secrets file is unchanged
    /// (e.g. a key rotation that only rewraps metadata).
    pub secrets_lock_bytes: Option<&'a [u8]>,
}

/// What [`recover_pending`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No interrupted transaction was found.
    Clean,
    /// The transaction had fully completed; only the journal was cleaned up.
    Completed,
    /// The crash happened mid-commit; the remaining rename was completed.
    RolledForward,
    /// The crash happened before any rename; temp files were discarded.
    RolledBack,
}

/// Points inside the commit protocol where a crash can be injected in tests.
/// The `After` prefix is intentional: each variant names the protocol step
/// that has just completed when the simulated crash fires.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    AfterTemps,
    AfterJournal,
    AfterVaultRename,
    AfterSecretsRename,
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::Cell;

    use super::CrashPoint;

    thread_local! {
        static CRASH_AFTER: Cell<Option<CrashPoint>> = const { Cell::new(None) };
    }

    pub fn set_crash_after(point: Option<CrashPoint>) {
        CRASH_AFTER.with(|cell| cell.set(point));
    }

    pub fn take_if_matches(point: CrashPoint) -> bool {
        CRASH_AFTER.with(|cell| {
            if cell.get() == Some(point) {
                cell.set(None);
                true
            } else {
                false
            }
        })
    }
}

fn crash_if_requested(point: CrashPoint) -> DotLockResult<()> {
    #[cfg(test)]
    {
        if test_hooks::take_if_matches(point) {
            return Err(DotLockError::Io(format!(
                "simulated crash at {point:?} (test hook)"
            )));
        }
    }

    // Subprocess fault injection: only honored in debug builds so release
    // binaries cannot be aborted mid-commit via the environment.
    if cfg!(debug_assertions)
        && let Ok(value) = std::env::var("DOTLOCK_TEST_CRASH_AFTER")
    {
        let requested = match value.as_str() {
            "temps" => Some(CrashPoint::AfterTemps),
            "journal" => Some(CrashPoint::AfterJournal),
            "vault_rename" | "first_rename" => Some(CrashPoint::AfterVaultRename),
            "secrets_rename" | "second_rename" => Some(CrashPoint::AfterSecretsRename),
            _ => None,
        };
        if requested == Some(point) {
            std::process::abort();
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct TxnJournal {
    version: u32,
    created_at: i64,
    vault_old_sha256_b64: String,
    vault_new_sha256_b64: String,
    secrets_changed: bool,
    secrets_old_sha256_b64: String,
    secrets_new_sha256_b64: String,
}

/// Inter-process guard over the transaction journal. Uses `flock` on Unix so a
/// crashed writer never leaves a stale lock behind.
struct TxnLock {
    _file: fs::File,
}

impl TxnLock {
    fn acquire(dir: &Path) -> DotLockResult<Self> {
        let path = dir.join(LOCK_FILE);
        secure_fs::ensure_dir(dir, 0o700)?;
        secure_fs::reject_symlink(&path)?;

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(DotLockError::Io(format!(
                    "failed to lock vault transaction journal: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        Ok(Self { _file: file })
    }
}

fn journal_dir(vault_path: &Path) -> PathBuf {
    match vault_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dotlock");
    journal_dir(path).join(format!("{name}{TMP_SUFFIX}"))
}

fn fsync_dir(dir: &Path) -> DotLockResult<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn write_bytes_excl(path: &Path, bytes: &[u8], file_mode: u32) -> DotLockResult<()> {
    secure_fs::reject_symlink(path)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(file_mode);
    }
    #[cfg(not(unix))]
    {
        let _ = file_mode;
    }

    let result = (|| -> DotLockResult<()> {
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn sha256_b64_of(path: &Path) -> DotLockResult<String> {
    use base64::{Engine, engine::general_purpose};
    Ok(general_purpose::STANDARD.encode(compute_file_sha256(path)?))
}

fn remove_if_exists(path: &Path) -> DotLockResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(DotLockError::from(err)),
    }
}

fn repair_error(context: &str) -> DotLockError {
    DotLockError::Io(format!(
        "interrupted vault transaction could not be resolved automatically ({context}); \
         restore `.lock/` from a trusted backup or git history"
    ))
}

/// Commits the two writes as one transaction: either both become visible or neither.
///
/// Steps: write temps (fsync) -> write journal (fsync file + dir) ->
/// rename `vault.toml` (fsync dir) -> rename `secrets.lock` (fsync dir) ->
/// remove journal (fsync dir). Because the metadata (with new SDK wrappings and
/// hash) always lands before the new `secrets.lock`, no intermediate state ever
/// contains a ciphertext without its SDK.
pub fn commit_vault_pair(
    vault_path: &Path,
    secrets_path: &Path,
    write: VaultPairWrite<'_>,
) -> DotLockResult<()> {
    let dir = journal_dir(vault_path);
    let journal_path = dir.join(JOURNAL_FILE);
    let _lock = TxnLock::acquire(&dir)?;

    // Resolve any interrupted transaction from a previous writer first.
    if journal_path.exists() {
        recover_pending_locked(vault_path, secrets_path, &journal_path)?;
    }

    let vault_tmp = tmp_path(vault_path);
    let secrets_tmp = tmp_path(secrets_path);
    // Without a journal, leftover temps are garbage from a pre-journal crash.
    remove_if_exists(&vault_tmp)?;
    remove_if_exists(&secrets_tmp)?;

    let mut metadata = write.metadata.clone();
    metadata.version = metadata.version.max(2);
    let vault_content =
        toml::to_string_pretty(&metadata).map_err(|e| DotLockError::Crypto(e.to_string()))?;

    // Step 1: temps, fsynced.
    write_bytes_excl(&vault_tmp, vault_content.as_bytes(), 0o600)?;
    if let Some(bytes) = write.secrets_lock_bytes {
        write_bytes_excl(&secrets_tmp, bytes, 0o600)?;
    }
    crash_if_requested(CrashPoint::AfterTemps)?;

    // Step 2: journal with old and new digests, fsynced along with the directory.
    let journal = TxnJournal {
        version: JOURNAL_VERSION,
        created_at: crate::storage::secrets_lock::current_unix_timestamp(),
        vault_old_sha256_b64: sha256_b64_of(vault_path)?,
        vault_new_sha256_b64: sha256_b64_of(&vault_tmp)?,
        secrets_changed: write.secrets_lock_bytes.is_some(),
        secrets_old_sha256_b64: sha256_b64_of(secrets_path)?,
        secrets_new_sha256_b64: if write.secrets_lock_bytes.is_some() {
            sha256_b64_of(&secrets_tmp)?
        } else {
            sha256_b64_of(secrets_path)?
        },
    };
    let journal_content =
        toml::to_string_pretty(&journal).map_err(|e| DotLockError::Crypto(e.to_string()))?;
    write_bytes_excl(&journal_path, journal_content.as_bytes(), 0o600)?;
    fsync_dir(&dir)?;
    crash_if_requested(CrashPoint::AfterJournal)?;

    // Step 3: metadata becomes visible first (new SDKs + hash).
    secure_fs::reject_symlink(vault_path)?;
    fs::rename(&vault_tmp, vault_path)?;
    fsync_dir(&dir)?;
    crash_if_requested(CrashPoint::AfterVaultRename)?;

    // Step 4: secrets.lock becomes visible.
    if write.secrets_lock_bytes.is_some() {
        secure_fs::reject_symlink(secrets_path)?;
        fs::rename(&secrets_tmp, secrets_path)?;
        fsync_dir(&journal_dir(secrets_path))?;
    }
    crash_if_requested(CrashPoint::AfterSecretsRename)?;

    // Step 5: transaction complete; drop the journal.
    remove_if_exists(&journal_path)?;
    fsync_dir(&dir)?;

    // M3: the committed epoch is now the newest state this machine produced;
    // anchor it (best effort — per-user state may be unavailable, e.g. no
    // HOME, and that must never fail an already-durable commit).
    let _ =
        crate::storage::epoch_anchor::advance_epoch(&metadata.project_uuid, metadata.vault_epoch);
    Ok(())
}

/// Resolves an interrupted transaction, if any. Called at the start of every
/// vault access (unlock/read) so a crashed writer never leaves the pair in a
/// mixed state observable by readers.
pub fn recover_pending(vault_path: &Path, secrets_path: &Path) -> DotLockResult<RecoveryOutcome> {
    let dir = journal_dir(vault_path);
    let journal_path = dir.join(JOURNAL_FILE);
    if !journal_path.exists() {
        return Ok(RecoveryOutcome::Clean);
    }

    let _lock = TxnLock::acquire(&dir)?;
    if !journal_path.exists() {
        // Another process finished recovery while we waited for the lock.
        return Ok(RecoveryOutcome::Clean);
    }
    recover_pending_locked(vault_path, secrets_path, &journal_path)
}

fn recover_pending_locked(
    vault_path: &Path,
    secrets_path: &Path,
    journal_path: &Path,
) -> DotLockResult<RecoveryOutcome> {
    let dir = journal_dir(vault_path);
    let vault_tmp = tmp_path(vault_path);
    let secrets_tmp = tmp_path(secrets_path);

    let journal = secure_fs::read_to_string(journal_path)
        .ok()
        .and_then(|content| toml::from_str::<TxnJournal>(&content).ok());

    let Some(journal) = journal else {
        // Unreadable/truncated journal: the journal is written before any
        // rename, so if the vault temp is still present nothing was renamed
        // yet and a clean rollback is safe.
        if vault_tmp.exists() {
            remove_if_exists(&vault_tmp)?;
            remove_if_exists(&secrets_tmp)?;
            remove_if_exists(journal_path)?;
            fsync_dir(&dir)?;
            return Ok(RecoveryOutcome::RolledBack);
        }
        return Err(repair_error("journal unreadable and temp files missing"));
    };

    let vault_now = sha256_b64_of(vault_path)?;
    let secrets_now = sha256_b64_of(secrets_path)?;
    let vault_is_new = vault_now == journal.vault_new_sha256_b64;
    let vault_is_old = vault_now == journal.vault_old_sha256_b64;
    let secrets_is_new = !journal.secrets_changed || secrets_now == journal.secrets_new_sha256_b64;
    let secrets_is_old = !journal.secrets_changed || secrets_now == journal.secrets_old_sha256_b64;

    if vault_is_new && secrets_is_new {
        // Transaction completed; only the journal removal was interrupted.
        remove_if_exists(&vault_tmp)?;
        remove_if_exists(&secrets_tmp)?;
        remove_if_exists(journal_path)?;
        fsync_dir(&dir)?;
        return Ok(RecoveryOutcome::Completed);
    }

    if vault_is_old && secrets_is_old {
        // Crash before the first rename: discard temps, keep the old pair.
        remove_if_exists(&vault_tmp)?;
        remove_if_exists(&secrets_tmp)?;
        remove_if_exists(journal_path)?;
        fsync_dir(&dir)?;
        return Ok(RecoveryOutcome::RolledBack);
    }

    if vault_is_new && journal.secrets_changed && secrets_now == journal.secrets_old_sha256_b64 {
        // Mixed state: vault renamed, secrets not yet. Roll forward using the
        // surviving secrets temp.
        if secrets_tmp.exists() && sha256_b64_of(&secrets_tmp)? == journal.secrets_new_sha256_b64 {
            secure_fs::reject_symlink(secrets_path)?;
            fs::rename(&secrets_tmp, secrets_path)?;
            fsync_dir(&journal_dir(secrets_path))?;
            remove_if_exists(&vault_tmp)?;
            remove_if_exists(journal_path)?;
            fsync_dir(&dir)?;
            return Ok(RecoveryOutcome::RolledForward);
        }
        return Err(repair_error(
            "secrets temp file for an interrupted transaction is missing or altered",
        ));
    }

    Err(repair_error(
        "vault pair does not match either side of the interrupted transaction",
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        crypto::{AccessMode, VaultConfig, VaultKeyMetadata},
        storage::vault_file::{load_vault_metadata, save_vault_metadata},
    };

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-txn-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    fn metadata(marker: &str) -> VaultKeyMetadata {
        VaultKeyMetadata {
            version: 5,
            project_uuid: "project".to_string(),
            project: marker.to_string(),
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

    struct Paths {
        vault: PathBuf,
        secrets: PathBuf,
        dir: PathBuf,
    }

    fn setup(name: &str) -> Paths {
        let dir = temp_dir(name);
        let vault = dir.join("vault.toml");
        let secrets = dir.join("secrets.lock");
        save_vault_metadata(&vault, &metadata("old")).expect("save vault");
        fs::write(&secrets, b"old-secrets").expect("write secrets");
        Paths {
            vault,
            secrets,
            dir,
        }
    }

    fn commit_new(paths: &Paths, crash: Option<CrashPoint>) -> DotLockResult<()> {
        test_hooks::set_crash_after(crash);
        let result = commit_vault_pair(
            &paths.vault,
            &paths.secrets,
            VaultPairWrite {
                metadata: &metadata("new"),
                secrets_lock_bytes: Some(b"new-secrets"),
            },
        );
        test_hooks::set_crash_after(None);
        result
    }

    fn assert_consistent_pair(paths: &Paths, expect_new: bool) {
        let meta = load_vault_metadata(&paths.vault).expect("load vault");
        let secrets = fs::read(&paths.secrets).expect("read secrets");
        if expect_new {
            assert_eq!(meta.project, "new");
            assert_eq!(secrets, b"new-secrets");
        } else {
            assert_eq!(meta.project, "old");
            assert_eq!(secrets, b"old-secrets");
        }
        assert!(!paths.dir.join(JOURNAL_FILE).exists());
        assert!(!tmp_path(&paths.vault).exists());
        assert!(!tmp_path(&paths.secrets).exists());
    }

    #[test]
    fn commit_vault_pair_writes_both_files_and_removes_journal() {
        let paths = setup("commit");
        commit_new(&paths, None).expect("commit");
        assert_consistent_pair(&paths, true);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn commit_vault_pair_supports_metadata_only_writes() {
        let paths = setup("meta-only");
        commit_vault_pair(
            &paths.vault,
            &paths.secrets,
            VaultPairWrite {
                metadata: &metadata("new"),
                secrets_lock_bytes: None,
            },
        )
        .expect("commit");
        let meta = load_vault_metadata(&paths.vault).expect("load vault");
        assert_eq!(meta.project, "new");
        assert_eq!(fs::read(&paths.secrets).expect("secrets"), b"old-secrets");
        assert!(!paths.dir.join(JOURNAL_FILE).exists());
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn crash_after_temps_rolls_back_cleanly() {
        let paths = setup("crash-temps");
        assert!(commit_new(&paths, Some(CrashPoint::AfterTemps)).is_err());
        let outcome = recover_pending(&paths.vault, &paths.secrets).expect("recover");
        // No journal was written yet, so nothing pending; stale temps are
        // cleaned by the next commit.
        assert_eq!(outcome, RecoveryOutcome::Clean);
        commit_new(&paths, None).expect("retry commit");
        assert_consistent_pair(&paths, true);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn crash_after_journal_rolls_back_to_old_pair() {
        let paths = setup("crash-journal");
        assert!(commit_new(&paths, Some(CrashPoint::AfterJournal)).is_err());
        assert!(paths.dir.join(JOURNAL_FILE).exists());
        let outcome = recover_pending(&paths.vault, &paths.secrets).expect("recover");
        assert_eq!(outcome, RecoveryOutcome::RolledBack);
        assert_consistent_pair(&paths, false);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn crash_between_renames_rolls_forward_to_new_pair() {
        let paths = setup("crash-mid");
        assert!(commit_new(&paths, Some(CrashPoint::AfterVaultRename)).is_err());
        let outcome = recover_pending(&paths.vault, &paths.secrets).expect("recover");
        assert_eq!(outcome, RecoveryOutcome::RolledForward);
        assert_consistent_pair(&paths, true);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn crash_after_both_renames_completes_on_recovery() {
        let paths = setup("crash-late");
        assert!(commit_new(&paths, Some(CrashPoint::AfterSecretsRename)).is_err());
        assert!(paths.dir.join(JOURNAL_FILE).exists());
        let outcome = recover_pending(&paths.vault, &paths.secrets).expect("recover");
        assert_eq!(outcome, RecoveryOutcome::Completed);
        assert_consistent_pair(&paths, true);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn recovery_is_noop_without_journal() {
        let paths = setup("noop");
        let outcome = recover_pending(&paths.vault, &paths.secrets).expect("recover");
        assert_eq!(outcome, RecoveryOutcome::Clean);
        assert_consistent_pair(&paths, false);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn unreadable_journal_with_temps_rolls_back() {
        let paths = setup("bad-journal");
        assert!(commit_new(&paths, Some(CrashPoint::AfterJournal)).is_err());
        fs::write(paths.dir.join(JOURNAL_FILE), b"garbage").expect("corrupt journal");
        let outcome = recover_pending(&paths.vault, &paths.secrets).expect("recover");
        assert_eq!(outcome, RecoveryOutcome::RolledBack);
        assert_consistent_pair(&paths, false);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn tampered_pair_after_crash_reports_repair_error() {
        let paths = setup("tampered");
        assert!(commit_new(&paths, Some(CrashPoint::AfterVaultRename)).is_err());
        // Tamper with the surviving secrets temp so roll-forward must refuse.
        fs::write(tmp_path(&paths.secrets), b"evil").expect("tamper");
        let err = recover_pending(&paths.vault, &paths.secrets).expect_err("must refuse");
        assert!(err.to_string().contains("interrupted vault transaction"));
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn crash_never_yields_mixed_state_for_any_crash_point() {
        for point in [
            CrashPoint::AfterTemps,
            CrashPoint::AfterJournal,
            CrashPoint::AfterVaultRename,
            CrashPoint::AfterSecretsRename,
        ] {
            let paths = setup("matrix");
            assert!(commit_new(&paths, Some(point)).is_err());
            recover_pending(&paths.vault, &paths.secrets).expect("recover");
            let meta = load_vault_metadata(&paths.vault).expect("load vault");
            let secrets = fs::read(&paths.secrets).expect("read secrets");
            let pair = (meta.project.as_str(), secrets.as_slice());
            assert!(
                pair == ("old", b"old-secrets".as_slice())
                    || pair == ("new", b"new-secrets".as_slice()),
                "mixed state after crash at {point:?}: {:?}",
                pair.0
            );
            let _ = fs::remove_dir_all(&paths.dir);
        }
    }
}
