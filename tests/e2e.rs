//! End-to-end tests driving the real `dl` binary in isolated temp
//! directories. Every test gets its own project dir and its own
//! `DOTLOCK_HOME`/`HOME`, so nothing touches the developer's real state.
//!
//! Master-password bootstrap (FG2): `dl init --password-stdin` reads the
//! password from the first line of stdin, so no pseudo-terminal is needed.
//! After init the session key cache under `DOTLOCK_HOME` keeps subsequent
//! commands non-interactive; tests that drop the cache re-unlock via
//! `DOTLOCK_MASTER_PASSWORD` or `--password-file`.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const MASTER_PASSWORD: &str = "Str0ng!Passw0rd!";

/// Isolated environment: a project directory plus a private DOTLOCK_HOME.
struct TestEnv {
    _root: TempDir,
    project: PathBuf,
    home: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let root = TempDir::new().expect("create temp dir");
        // `secure_fs` refuses `..` components and symlinked ancestors, so the
        // paths handed to the binary must be canonical.
        let canonical = root.path().canonicalize().expect("canonicalize temp dir");
        let project = canonical.join("project");
        let home = canonical.join("home");
        fs::create_dir(&project).expect("create project dir");
        fs::create_dir(&home).expect("create home dir");
        Self {
            _root: root,
            project,
            home,
        }
    }

    /// A `dl` command scoped to this environment.
    fn dl(&self) -> Command {
        self.dl_as(&self.home)
    }

    /// A `dl` command running in the same project but with an explicit
    /// DOTLOCK_HOME — a separate home means a separate identity and a
    /// separate session cache, i.e. a different teammate's machine.
    fn dl_as(&self, home: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dl"));
        cmd.current_dir(&self.project)
            .env("DOTLOCK_HOME", home)
            .env("HOME", home)
            .env("NO_COLOR", "1");
        cmd
    }

    /// Initializes the vault non-interactively (FG2): the master password is
    /// fed through `--password-stdin`, so no pty helper is needed.
    fn init_vault(&self) {
        self.dl()
            .args(["init", "--password-stdin"])
            .write_stdin(format!("{MASTER_PASSWORD}\n"))
            .assert()
            .success();

        assert!(
            self.project.join(".lock/vault.toml").exists(),
            "`dl init` must create .lock/vault.toml"
        );
        assert!(
            self.project.join(".lock/secrets.lock").exists(),
            "`dl init` must create .lock/secrets.lock"
        );
    }

    fn lock_path(&self, name: &str) -> PathBuf {
        self.project.join(".lock").join(name)
    }
}

#[test]
fn version_flag_reports_package_version() {
    let env = TestEnv::new();
    env.dl()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn commands_fail_cleanly_before_init() {
    let env = TestEnv::new();
    for args in [
        vec!["list"],
        vec!["get", "FOO"],
        vec!["set", "FOO", "bar"],
        vec!["unset", "FOO"],
        vec!["export", ".env.out"],
        vec!["run", "--", "true"],
        vec!["reconcile"],
    ] {
        env.dl()
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("not initialized"))
            .stderr(predicate::str::contains("dl init"));
    }
    assert!(
        !env.project.join(".env.out").exists(),
        "export must not write a file before init"
    );
}

#[test]
fn init_without_a_tty_fails_with_actionable_error() {
    let env = TestEnv::new();
    // FG2: with no TTY and no non-interactive source, the failure must be a
    // clean, actionable error (not the raw inquire "not a TTY" failure) that
    // points at DOTLOCK_MASTER_PASSWORD / --password-stdin and leaves no
    // usable vault behind.
    env.dl()
        .arg("init")
        .write_stdin(format!("{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no TTY"))
        .stderr(predicate::str::contains("DOTLOCK_MASTER_PASSWORD"))
        .stderr(predicate::str::contains("--password-stdin"))
        .stderr(predicate::str::contains("panicked").not());
    assert!(!env.project.join(".lock/vault.toml").exists());
}

/// FG2: non-interactive unlock. The env var and `--password-file` feed the
/// same Argon2id -> DEK-unwrap -> MAC/epoch path as the interactive prompt,
/// so a wrong password is rejected identically.
#[test]
fn non_interactive_unlock_via_env_var_and_password_file() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // Drop the session cache so the next command must actually unlock.
    env.dl().arg("lock").assert().success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");

    // A wrong password goes through the same KDF/unwrap path and fails.
    env.dl().arg("lock").assert().success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", "Wr0ng!Passw0rd!!")
        .args(["get", "FOO"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid master password"));

    // --password-file: only the first line is the password.
    let password_file = env.home.join("master.pw");
    fs::write(&password_file, format!("{MASTER_PASSWORD}\n")).expect("write password file");
    env.dl().arg("lock").assert().success();
    env.dl()
        .args(["get", "FOO", "--password-file"])
        .arg(&password_file)
        .assert()
        .success()
        .stdout("bar-value\n");

    // --password-stdin unlocks reads too (first line only).
    env.dl().arg("lock").assert().success();
    env.dl()
        .args(["get", "FOO", "--password-stdin"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .assert()
        .success()
        .stdout("bar-value\n");
}

/// FG1: `--json` emits valid machine-readable JSON for read commands.
#[test]
fn json_output_for_list_get_share_and_provider() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // list --json: array of {id, name}, no values.
    let out = env
        .dl()
        .args(["list", "--json"])
        .output()
        .expect("run list");
    assert!(out.status.success());
    let listed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("list --json must be valid JSON");
    let items = listed.as_array().expect("list --json must be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "FOO");
    assert!(items[0]["id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(items[0].get("value").is_none(), "list must not leak values");

    // get --json: {name, id, value}.
    let out = env
        .dl()
        .args(["get", "FOO", "--json"])
        .output()
        .expect("run get");
    assert!(out.status.success());
    let got: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("get --json must be valid JSON");
    assert_eq!(got["name"], "FOO");
    assert_eq!(got["value"], "bar-value");
    assert_eq!(got["id"], items[0]["id"]);

    // share list --json: no recipients yet -> empty array.
    let out = env
        .dl()
        .args(["share", "list", "--json"])
        .output()
        .expect("run share list");
    assert!(out.status.success());
    let recipients: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("share list --json must be valid JSON");
    assert_eq!(recipients, serde_json::json!([]));

    // provider list --json: array of provider names (none on this PATH).
    let out = env
        .dl()
        .args(["provider", "list", "--json"])
        .output()
        .expect("run provider list");
    assert!(out.status.success());
    let providers: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("provider list --json must be valid JSON");
    assert!(providers.is_array());
}

#[test]
fn secret_lifecycle_set_get_list_export_run_unset() {
    let env = TestEnv::new();
    env.init_vault();

    // set: value round-trips through the encrypted vault.
    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret FOO saved"));

    // get: piped stdout prints the raw value only.
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");

    // list: the table shows the secret name and the count.
    env.dl()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("FOO"))
        .stdout(predicate::str::contains("total:"))
        .stdout(predicate::str::contains("1 secret"));

    // run: the decrypted secret reaches the child process environment and
    // never leaks onto dl's own stdout apart from the child's output.
    env.dl()
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "printf 'child sees %s\\n' \"$FOO\"",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("child sees bar-value"));

    // export: plaintext .env file is written on request.
    env.dl()
        .args(["export", ".env.out"])
        .assert()
        .success()
        .stdout(predicate::str::contains("exported 1 variable"));
    let exported = fs::read_to_string(env.project.join(".env.out")).expect("read exported env");
    assert!(
        exported.contains("FOO=bar-value"),
        "exported file must contain the secret: {exported}"
    );

    // unset: the secret disappears (`--yes` skips the L5 confirmation, which
    // otherwise fails fast without a TTY — covered by its own test below).
    env.dl()
        .args(["unset", "--yes", "FOO"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret FOO removed"));
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
    env.dl()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("no secrets stored"));
}

/// M8: `dl set NAME --stdin` reads the value from stdin so it never appears
/// in argv (`ps`/`/proc`/shell history).
#[test]
fn set_reads_secret_value_from_stdin() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "PIPED", "--stdin"])
        .write_stdin("piped-value\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("secret PIPED saved"));

    env.dl()
        .args(["get", "PIPED"])
        .assert()
        .success()
        .stdout("piped-value\n");

    // Empty stdin is a clean error, not an empty secret.
    env.dl()
        .args(["set", "EMPTY", "--stdin"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no secret value received"));
}

/// Phase 0/1 guarantee: while a pending-merge marker exists every access is
/// refused with a clear "run `dl reconcile`" error, and `dl reconcile` only
/// re-signs after explicit confirmation (declining aborts and keeps the
/// marker).
#[test]
fn pending_merge_marker_blocks_access_until_reconciled() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // Simulate the merge driver's handoff: a marker without file hashes
    // (metadata-only merge).
    let marker = env.lock_path("pending-merge");
    fs::write(&marker, "version = 1\ncreated_at = 0\n").expect("write pending-merge marker");

    // Every unlock is refused while the marker exists.
    for args in [vec!["list"], vec!["get", "FOO"], vec!["run", "--", "true"]] {
        env.dl()
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("unreconciled merge"))
            .stderr(predicate::str::contains("dl reconcile"));
    }

    // Declining the reconcile prompt aborts (exit 130) and keeps the marker.
    env.dl()
        .arg("reconcile")
        .write_stdin("n\n")
        .assert()
        .code(130)
        .stdout(predicate::str::contains("merge left unreconciled"));
    assert!(marker.exists(), "declined reconcile must keep the marker");

    // Once the marker is gone, access works again.
    fs::remove_file(&marker).expect("remove marker");
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");
}

/// Phase 0/1 guarantee: out-of-band modification of `.lock/secrets.lock`
/// must never decrypt silently — the session cache is invalidated and the
/// command fails.
#[test]
fn tampered_vault_metadata_is_refused() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // M2: rewrite a MAC-covered scalar field without resealing. The write
    // counter is chosen because it does not alter cache/session resolution,
    // so the failure is unambiguously the metadata authentication check.
    let vault = env.lock_path("vault.toml");
    let content = fs::read_to_string(&vault).expect("read vault.toml");
    let tampered = content.replace("kek_writes_since_rotate = 1", "kek_writes_since_rotate = 9");
    assert_ne!(content, tampered, "fixture must actually change the field");
    fs::write(&vault, &tampered).expect("write tampered vault.toml");

    env.dl()
        .args(["get", "FOO"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("bar-value").not())
        .stderr(predicate::str::contains("failed authentication"));
}

#[test]
fn restored_older_vault_pair_is_refused_as_rollback() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "old-value"])
        .assert()
        .success();

    // Snapshot a legitimate (MAC-valid) older vault state...
    let vault = env.lock_path("vault.toml");
    let secrets = env.lock_path("secrets.lock");
    let old_vault = fs::read(&vault).expect("read vault.toml");
    let old_secrets = fs::read(&secrets).expect("read secrets.lock");

    env.dl()
        .args(["set", "FOO", "new-value"])
        .assert()
        .success();

    // ...then restore it wholesale, as a rollback attacker would.
    fs::write(&vault, &old_vault).expect("restore vault.toml");
    fs::write(&secrets, &old_secrets).expect("restore secrets.lock");

    // M3: the per-user epoch anchor has already seen the newer epoch.
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("old-value").not())
        .stderr(predicate::str::contains("rollback"));

    // The user (not a repo-writing attacker) can accept it explicitly.
    env.dl()
        .env("DOTLOCK_ALLOW_VAULT_ROLLBACK", "1")
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout(predicate::str::contains("old-value"));
}

/// FG4: `dl exec` runs a shell-form command line via `sh -c` with secrets
/// injected as ENVIRONMENT variables only (never interpolated into the
/// command string), and `--env-file` merges plaintext variables with vault
/// secrets winning on name collision.
#[test]
fn exec_shell_form_and_env_file_fallback() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "MY_SECRET", "vault-value"])
        .assert()
        .success();

    // Shell-form: expansion happens in the child shell, where the secret
    // exists only as an environment variable.
    env.dl()
        .args(["exec", r#"printf 'exec sees %s\n' "$MY_SECRET""#])
        .assert()
        .success()
        .stdout(predicate::str::contains("exec sees vault-value"));

    // Shell syntax (&&) works — the whole point of the shell form.
    env.dl()
        .args(["exec", r#"true && printf 'chained %s\n' "$MY_SECRET""#])
        .assert()
        .success()
        .stdout(predicate::str::contains("chained vault-value"));

    // --env-file: plaintext extras are injected, but a vault secret with the
    // same name ALWAYS wins over the env-file value.
    let env_file = env.project.join(".env.extra");
    fs::write(
        &env_file,
        "EXTRA_VAR=from-env-file\nMY_SECRET=plaintext-should-lose\n",
    )
    .expect("write env file");
    env.dl()
        .args(["exec", "--env-file", ".env.extra"])
        .arg(r#"printf '%s %s\n' "$EXTRA_VAR" "$MY_SECRET""#)
        .assert()
        .success()
        .stdout(predicate::str::contains("from-env-file vault-value"))
        .stdout(predicate::str::contains("plaintext-should-lose").not());

    // `dl run --env-file` (argv form) gets the same merge semantics.
    env.dl()
        .args([
            "run",
            "--env-file",
            ".env.extra",
            "--",
            "sh",
            "-c",
            r#"printf 'run %s %s\n' "$EXTRA_VAR" "$MY_SECRET""#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("run from-env-file vault-value"));
}

/// FG5: `dl rotate --if-due` is cron-friendly — exit 0 with no rotation (and
/// no password prompt) when nothing is due, rotates when the policy says so,
/// and the recorded `last_rotated_at` keeps the MAC-sealed vault healthy.
#[test]
fn rotate_if_due_noops_when_not_due_and_rotates_when_due() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // No policy configured: not due, exit 0, no password required at all.
    env.dl().arg("lock").assert().success();
    env.dl()
        .args(["rotate", "--if-due"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotation not due"));

    // Configure the age policy. The vault has never recorded a rotation
    // (last_rotated_at = 0), so the first scheduled run is due and rotates.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["config", "set", "rotate_max_age_days", "30"])
        .assert()
        .success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["rotate", "--if-due"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotation due"))
        .stdout(predicate::str::contains("rotated"));

    // Immediately afterwards nothing is due: the rotation stamped
    // last_rotated_at, which is now well within the 30-day budget.
    env.dl()
        .args(["rotate", "--if-due"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotation not due"));

    // The vault stays fully usable: MAC/epoch verify and the secret decrypts
    // under the rotated project key.
    env.dl().arg("lock").assert().success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");
}

/// FG6: `dl repair` recovers a hash-stale vault — dry-run diagnoses without
/// touching anything, the real run recomputes + reseals, and the repair is
/// audit-logged.
#[test]
fn repair_recovers_hash_stale_vault() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // Desynchronize hash and content the way partial restores do.
    let secrets = env.lock_path("secrets.lock");
    let mut content = fs::read_to_string(&secrets).expect("read secrets.lock");
    content.push_str("# restored from a partial backup\n");
    fs::write(&secrets, &content).expect("write stale secrets.lock");

    env.dl()
        .args(["get", "FOO"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("modified outside"));

    // Dry-run: prints the diagnosis, changes nothing.
    let vault_before = fs::read(env.lock_path("vault.toml")).expect("vault bytes");
    let secrets_before = fs::read(&secrets).expect("secrets bytes");
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["repair", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("STALE"))
        .stdout(predicate::str::contains("dry run"));
    assert_eq!(
        fs::read(env.lock_path("vault.toml")).expect("vault bytes"),
        vault_before
    );
    assert_eq!(fs::read(&secrets).expect("secrets bytes"), secrets_before);

    // Real repair: recompute + reseal, then the vault works again.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["repair", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("integrity hash recomputed"));
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");

    // The repair is an auditable security event.
    env.dl()
        .args(["audit", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("repair"));
}

/// FG6: a record whose SDK wrapping is gone is IRRECOVERABLE — repair lists
/// it, refuses to touch it without `--prune`, and `--prune --yes` removes
/// exactly that record while the rest stays intact and integrity-valid.
#[test]
fn repair_prunes_only_irrecoverable_records() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "KEEP", "keep-value"])
        .assert()
        .success();
    env.dl()
        .args(["set", "DOOMED", "doomed-value"])
        .assert()
        .success();

    // Find DOOMED's record id via the machine-readable listing.
    let out = env.dl().args(["list", "--json"]).output().expect("list");
    let listed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let doomed_id = listed
        .as_array()
        .expect("array")
        .iter()
        .find(|item| item["name"] == "DOOMED")
        .expect("doomed listed")["id"]
        .as_str()
        .expect("id")
        .to_string();

    // Emulate the historical merge-bug state: DOOMED's SDK wrapping vanished
    // from a vault.toml that predates the metadata MAC (legacy, no MAC line),
    // so the record's ciphertext is permanently orphaned.
    let vault = env.lock_path("vault.toml");
    let content = fs::read_to_string(&vault).expect("read vault.toml");
    let filtered: String = content
        .lines()
        .filter(|line| !line.contains(&doomed_id) && !line.starts_with("metadata_mac_b64"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_ne!(content, filtered, "fixture must drop the SDK wrapping");
    fs::write(&vault, &filtered).expect("write orphaned vault.toml");

    // Dry-run names the irrecoverable record.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["repair", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("IRRECOVERABLE"))
        .stdout(predicate::str::contains(&doomed_id));

    // Without --prune: report and exit non-zero, never silent data loss.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["repair", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("irrecoverable"))
        .stderr(predicate::str::contains("--prune"));

    // --prune --yes removes ONLY the orphaned record and reseals the rest.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["repair", "--prune", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed 1 irrecoverable record"))
        .stdout(predicate::str::contains("DOOMED"));

    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["get", "KEEP"])
        .assert()
        .success()
        .stdout("keep-value\n");
    env.dl()
        .args(["get", "DOOMED"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

/// FG6: repair is not a tamper bypass — without a valid master password it
/// fails before modifying anything.
#[test]
fn repair_without_valid_password_changes_nothing() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    let secrets = env.lock_path("secrets.lock");
    let mut content = fs::read_to_string(&secrets).expect("read secrets.lock");
    content.push_str("# out-of-band edit\n");
    fs::write(&secrets, &content).expect("write stale secrets.lock");

    let vault_before = fs::read(env.lock_path("vault.toml")).expect("vault bytes");
    let secrets_before = fs::read(&secrets).expect("secrets bytes");

    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", "Wr0ng!Passw0rd!!")
        .args(["repair", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid master password"));

    assert_eq!(
        fs::read(env.lock_path("vault.toml")).expect("vault bytes"),
        vault_before
    );
    assert_eq!(fs::read(&secrets).expect("secrets bytes"), secrets_before);
}

#[test]
fn tampered_secrets_file_is_refused() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    let secrets = env.lock_path("secrets.lock");
    let mut content = fs::read_to_string(&secrets).expect("read secrets.lock");
    content.push_str("# tampered outside dotlock\n");
    fs::write(&secrets, &content).expect("write tampered secrets.lock");

    env.dl()
        .args(["get", "FOO"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("bar-value").not())
        .stderr(predicate::str::contains("error:"));
}

/// FG3: multi-environment support. `dl env add` creates an INDEPENDENT
/// vault pair under `.lock/envs/<name>/` (own salt/KEK/DEK, own master
/// password), `--env`/`DOTLOCK_ENV`/`dl env use` select which pair every
/// command operates on, and the pre-FG3 files in `.lock/` remain the default
/// environment untouched — a secret set in staging is invisible to the
/// default env and undecryptable with the default env's password.
#[test]
fn environments_are_isolated_and_selectable() {
    const STAGING_PASSWORD: &str = "Sta9ing!Passw0rd";
    let env = TestEnv::new();
    env.init_vault();

    // A secret that must stay visible only in the default environment.
    env.dl()
        .args(["set", "ONLY_DEFAULT", "default-value"])
        .assert()
        .success();

    // Create staging with its OWN master password (FG2 stdin bootstrap).
    env.dl()
        .args(["env", "add", "staging", "--password-stdin"])
        .write_stdin(format!("{STAGING_PASSWORD}\n"))
        .assert()
        .success();
    assert!(env.project.join(".lock/envs/staging/vault.toml").exists());
    assert!(env.project.join(".lock/envs/staging/secrets.lock").exists());
    // Backward compat: the default pair stays exactly where it was.
    assert!(env.lock_path("vault.toml").exists());
    assert!(env.lock_path("secrets.lock").exists());

    // Adding the same environment twice fails cleanly.
    env.dl()
        .args(["env", "add", "staging"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    // Env names are path components; traversal-looking names are rejected.
    env.dl()
        .args(["env", "add", "../evil"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));

    // Write into staging via the global --env flag (FG2 env var unlock, so
    // the test never depends on the 15s session cache).
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", STAGING_PASSWORD)
        .args(["--env", "staging", "set", "API_KEY", "staging-value"])
        .assert()
        .success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", STAGING_PASSWORD)
        .args(["--env", "staging", "get", "API_KEY"])
        .assert()
        .success()
        .stdout("staging-value\n");

    // Isolation both ways: the default env cannot see staging's secret...
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
    // ...and staging cannot see the default env's secret.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", STAGING_PASSWORD)
        .args(["--env", "staging", "get", "ONLY_DEFAULT"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));

    // Crypto isolation: the default env's master password cannot unlock
    // staging's vault (independent salt + KEK derivation + DEK).
    env.dl()
        .args(["--env", "staging", "lock"])
        .assert()
        .success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["--env", "staging", "get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid master password"));

    // DOTLOCK_ENV selects the environment without the flag.
    env.dl()
        .env("DOTLOCK_ENV", "staging")
        .env("DOTLOCK_MASTER_PASSWORD", STAGING_PASSWORD)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("staging-value\n");

    // `dl env list --json` (FG1) reports both, default active by default.
    let out = env
        .dl()
        .args(["env", "list", "--json"])
        .output()
        .expect("run env list");
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("env list emits valid JSON");
    let names: Vec<&str> = parsed
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, vec!["default", "staging"]);
    assert_eq!(parsed[0]["active"], serde_json::json!(true));
    assert_eq!(parsed[1]["active"], serde_json::json!(false));

    // `dl env use staging` persists the selection in the non-secret
    // `.lock/env` file; plain commands now hit staging, and `--env default`
    // still forces the legacy pair.
    env.dl().args(["env", "use", "staging"]).assert().success();
    assert_eq!(
        fs::read_to_string(env.lock_path("env"))
            .expect("selection file")
            .trim(),
        "staging"
    );
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", STAGING_PASSWORD)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("staging-value\n");
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["--env", "default", "get", "ONLY_DEFAULT"])
        .assert()
        .success()
        .stdout("default-value\n");

    // Selecting an environment that was never created fails actionably.
    env.dl()
        .args(["--env", "missing", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not initialized"))
        .stderr(predicate::str::contains("dl env add"));

    // `dl env use default` reverts the persisted selection.
    env.dl().args(["env", "use", "default"]).assert().success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["get", "ONLY_DEFAULT"])
        .assert()
        .success()
        .stdout("default-value\n");
}

/// L5: destructive operations require an explicit confirmation. Without a
/// TTY and without `--yes` they must FAIL FAST with an actionable error (not
/// hang waiting for input), and nothing may have been modified.
#[test]
fn destructive_ops_require_yes_without_a_tty() {
    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // unset without --yes: refuses, names the flag, leaves the secret intact.
    env.dl()
        .args(["unset", "FOO"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("confirmation required"))
        .stderr(predicate::str::contains("--yes"));
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");

    // rotate (explicit subcommands) without --yes: same refusal, BEFORE any
    // password prompt (no DOTLOCK_MASTER_PASSWORD is needed to see it fail).
    for rotate in ["project-key", "kek", "master-password"] {
        env.dl()
            .args(["rotate", rotate])
            .assert()
            .failure()
            .stderr(predicate::str::contains("confirmation required"))
            .stderr(predicate::str::contains("--yes"));
    }

    // share revoke without --yes: refused as well (before recipient lookup).
    env.dl()
        .args(["share", "revoke", "anyone"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("confirmation required"));

    // With --yes the same operations proceed: rotate really rotates and the
    // secret stays readable under the new project key.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["rotate", "project-key", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotated"));
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");
    env.dl()
        .args(["unset", "--yes", "FOO"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret FOO removed"));

    // `rotate --if-due` stays exempt (cron/CI is its whole purpose): with
    // nothing due it exits 0 without --yes and without prompting.
    env.dl()
        .args(["rotate", "--if-due"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotation not due"));
}

/// L5 (FG3 follow-up): `dl env remove` permanently deletes a named
/// environment's vault pair, refuses the default environment, and is gated
/// by the same --yes / TTY confirmation as the other destructive commands.
#[test]
fn env_remove_deletes_named_environment_and_refuses_default() {
    let env = TestEnv::new();
    env.init_vault();

    env.dl()
        .args(["env", "add", "staging", "--password-stdin"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .assert()
        .success();
    let staging_dir = env.lock_path("envs").join("staging");
    assert!(staging_dir.join("vault.toml").exists());

    // Without --yes and without a TTY: fail fast, environment untouched.
    env.dl()
        .args(["env", "remove", "staging"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("confirmation required"))
        .stderr(predicate::str::contains("--yes"));
    assert!(staging_dir.join("vault.toml").exists());

    // The default environment can never be removed, even with --yes.
    env.dl()
        .args(["env", "remove", "default", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "default environment cannot be removed",
        ));
    assert!(env.lock_path("vault.toml").exists());

    // Removing a non-existent environment fails actionably.
    env.dl()
        .args(["env", "remove", "missing", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not initialized"));

    // With --yes: the warning names the environment and the pair is gone.
    env.dl()
        .args(["env", "remove", "staging", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "permanently deletes environment staging",
        ))
        .stdout(predicate::str::contains("environment staging removed"));
    assert!(!staging_dir.exists());
    env.dl()
        .args(["env", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("staging").not());
}

/// L5: removing the persisted-selected environment resets the selection file
/// so later commands fall back to `default` instead of erroring.
#[test]
fn env_remove_resets_persisted_selection() {
    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["env", "add", "staging", "--password-stdin"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .assert()
        .success();
    env.dl().args(["env", "use", "staging"]).assert().success();
    assert!(env.lock_path("env").exists());

    env.dl()
        .args(["env", "remove", "staging", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("selection reset"));
    assert!(
        !env.lock_path("env").exists(),
        "the dangling selection file must be removed"
    );
    env.dl()
        .args(["env", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("default"));
}

/// L6: `dl export` writes plaintext secrets, so it must say so — and inside
/// a git repo it must warn loudly when the exported file is not gitignored
/// (without a TTY it never blocks on the append-to-gitignore offer).
#[test]
fn export_warns_about_plaintext_and_missing_gitignore_coverage() {
    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // Outside a git repo: the plaintext note appears, but no gitignore talk.
    env.dl()
        .args(["export", ".env.plain"])
        .assert()
        .success()
        .stderr(predicate::str::contains("PLAINTEXT secrets"))
        .stderr(predicate::str::contains("gitignore").not());

    // Inside a git repo with no coverage: loud warning + non-TTY hint, and
    // .gitignore is NOT modified behind the user's back.
    let git_init = std::process::Command::new("git")
        .arg("init")
        .current_dir(&env.project)
        .output()
        .expect("git init");
    assert!(git_init.status.success());
    env.dl()
        .args(["export", ".env.out"])
        .assert()
        .success()
        .stderr(predicate::str::contains("PLAINTEXT secrets"))
        .stderr(predicate::str::contains("NOT covered by .gitignore"))
        .stderr(predicate::str::contains(
            "add `.env.out` to your .gitignore",
        ));
    assert!(
        !env.project.join(".gitignore").exists(),
        "export must not silently create/modify .gitignore without a TTY confirmation"
    );

    // Once the file IS gitignored, only the generic plaintext note remains.
    fs::write(env.project.join(".gitignore"), ".env.covered\n").expect("write .gitignore");
    env.dl()
        .args(["export", ".env.covered"])
        .assert()
        .success()
        .stderr(predicate::str::contains("PLAINTEXT secrets"))
        .stderr(predicate::str::contains("NOT covered").not());
}

/// L7: piped `dl get` output is EXACTLY the bare value (load-bearing for
/// `dl get X | pbcopy`) — with and without `--reveal`, which only affects an
/// interactive terminal.
#[test]
fn get_piped_output_stays_bare_with_and_without_reveal() {
    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    env.dl()
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");
    env.dl()
        .args(["get", "FOO", "--reveal"])
        .assert()
        .success()
        .stdout("bar-value\n");
}

/// RSA-exit (ADR 0001): a fresh setup — `dl cert init` identity plus a shared
/// grant — is Ed25519/X25519 end to end: the identity reports `ed25519`, the
/// vault records an `x25519-sealedbox` recipient (never the legacy RSA alg),
/// and after dropping the session cache the vault unlocks via the modern
/// identity with no password and zero RSA operations.
#[test]
fn fresh_shared_setup_uses_modern_crypto_with_zero_rsa() {
    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // New identities are Ed25519 (no passphrase so the test stays
    // non-interactive; passphrase protection is orthogonal to the algorithm).
    env.dl()
        .args(["cert", "init", "--plain"])
        .assert()
        .success();
    env.dl()
        .args(["cert", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ed25519"))
        // Discoverability: `cert show` states whether the private key is
        // passphrase-protected, so "why am I being prompted?" has an answer.
        .stdout(predicate::str::contains("passphrase: no"));

    let pubkey = env.project.join("me.pub.pem");
    env.dl()
        .args(["cert", "export-pub"])
        .arg(&pubkey)
        .assert()
        .success();

    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["share", "grant", "--pubkey"])
        .arg(&pubkey)
        .args(["--label", "me"])
        .assert()
        .success();

    // The vault records the modern wrapping algorithm — and no RSA one.
    let vault = fs::read_to_string(env.lock_path("vault.toml")).expect("read vault.toml");
    assert!(
        vault.contains("x25519-sealedbox"),
        "recipient must be wrapped with the X25519 sealed box:\n{vault}"
    );
    assert!(
        !vault.contains("rsa-oaep-sha256"),
        "a fresh setup must contain zero RSA material:\n{vault}"
    );

    // Drop the session cache: the next read unlocks through the Ed25519
    // identity (sealed-box open), with no master password available.
    env.dl().arg("lock").assert().success();
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");
}

/// Non-interactive identity passphrase (CI): the FG2 sources satisfy the
/// certificate passphrase too. A passphrase-protected identity is created via
/// `cert init --password-stdin` (no PTY), granted shared access, and then —
/// with the session cache dropped and no master password anywhere — the vault
/// unlocks through the encrypted identity with the passphrase fed by
/// `--password-stdin` and by `DOTLOCK_IDENTITY_PASSPHRASE`. A wrong
/// passphrase fails, and no source + no TTY fails with the actionable error.
#[test]
fn shared_vault_with_encrypted_identity_unlocks_non_interactively() {
    const IDENTITY_PASSPHRASE: &str = "1d3ntity-Pass!";

    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // Passphrase-protected identity created WITHOUT a PTY: the new-passphrase
    // prompt accepts the same non-interactive sources.
    env.dl()
        .args(["cert", "init", "--password-stdin"])
        .write_stdin(format!("{IDENTITY_PASSPHRASE}\n"))
        .assert()
        .success();

    // `cert show` reveals the protection state without decrypting the key —
    // it must succeed with no TTY and no passphrase source.
    env.dl()
        .args(["cert", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("passphrase: yes"));

    // Grant shared access to this identity. This single command needs BOTH
    // credentials (master password to unlock, identity passphrase to sign the
    // grant), which is exactly what the dedicated env var disambiguates.
    let pubkey = env.project.join("me.pub.pem");
    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", IDENTITY_PASSPHRASE)
        .args(["cert", "export-pub"])
        .arg(&pubkey)
        .assert()
        .success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .env("DOTLOCK_IDENTITY_PASSPHRASE", IDENTITY_PASSPHRASE)
        .args(["share", "grant", "--pubkey"])
        .arg(&pubkey)
        .args(["--label", "me"])
        .assert()
        .success();

    // Drop the session cache: every unlock below goes through the encrypted
    // identity, with NO master password available anywhere.
    env.dl().arg("lock").assert().success();

    // No TTY + no source: the clear FG2 error, not a raw prompt failure.
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--password-stdin"));

    // --password-stdin feeds the identity passphrase (CI unlock).
    env.dl()
        .args(["get", "FOO", "--password-stdin"])
        .write_stdin(format!("{IDENTITY_PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout("bar-value\n");

    // The dedicated env var works too.
    env.dl().arg("lock").assert().success();
    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", IDENTITY_PASSPHRASE)
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");

    // A wrong non-interactive passphrase must fail the identity decrypt.
    env.dl().arg("lock").assert().success();
    env.dl()
        .args(["get", "FOO", "--password-stdin"])
        .write_stdin("wrong-passphrase\n")
        .assert()
        .failure();
}

/// `dl cert passwd`: changes/removes the identity passphrase IN PLACE — the
/// key pair and fingerprint are unchanged, so the existing recipient entry
/// keeps working. Flow: encrypted identity is a shared-vault recipient;
/// `cert passwd --remove` (current passphrase supplied non-interactively)
/// flips it to plain; `cert show` reports `passphrase: no`; the fingerprint
/// is IDENTICAL; and `dl get` then unlocks with ZERO prompts and ZERO
/// passphrase sources. Setting a NEW passphrase re-encrypts the same key and
/// the vault unlocks with it.
#[test]
fn cert_passwd_removes_and_changes_passphrase_preserving_shared_access() {
    const IDENTITY_PASSPHRASE: &str = "0ld-Pass!";
    const NEW_PASSPHRASE: &str = "N3w-Pass!";

    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["set", "FOO", "bar-value"])
        .assert()
        .success();

    // Passphrase-protected identity, granted shared access.
    env.dl()
        .args(["cert", "init", "--password-stdin"])
        .write_stdin(format!("{IDENTITY_PASSPHRASE}\n"))
        .assert()
        .success();
    let pubkey = env.project.join("me.pub.pem");
    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", IDENTITY_PASSPHRASE)
        .args(["cert", "export-pub"])
        .arg(&pubkey)
        .assert()
        .success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .env("DOTLOCK_IDENTITY_PASSPHRASE", IDENTITY_PASSPHRASE)
        .args(["share", "grant", "--pubkey"])
        .arg(&pubkey)
        .args(["--label", "me"])
        .assert()
        .success();

    // Record the fingerprint the recipient entry is keyed on.
    let out = env
        .dl()
        .args(["share", "list", "--json"])
        .output()
        .expect("run share list");
    let recipients: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("share list --json must be valid JSON");
    let fingerprint = recipients.as_array().expect("recipients")[0]["fingerprint"]
        .as_str()
        .expect("fingerprint string")
        .to_string();

    // The friction being fixed: with the encrypted identity, no session
    // cache and no passphrase source, every unlock wants the passphrase.
    env.dl().arg("lock").assert().success();
    env.dl().args(["get", "FOO"]).assert().failure();

    // `cert passwd --remove`, current passphrase fed non-interactively.
    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", IDENTITY_PASSPHRASE)
        .args(["cert", "passwd", "--remove"])
        .assert()
        .success()
        .stdout(predicate::str::contains("identity passphrase removed"))
        .stdout(predicate::str::contains("fingerprint unchanged"))
        .stdout(predicate::str::contains(&fingerprint));

    // Now plain — and the SAME identity: fingerprint unchanged, recipient
    // entry untouched.
    env.dl()
        .args(["cert", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("passphrase: no"))
        .stdout(predicate::str::contains(&fingerprint));
    let vault = fs::read_to_string(env.lock_path("vault.toml")).expect("read vault.toml");
    assert!(
        vault.contains(&fingerprint),
        "the recipient entry must still match the (unchanged) fingerprint:\n{vault}"
    );

    // ZERO prompts, ZERO sources: identity unlock alone returns the secret.
    env.dl().arg("lock").assert().success();
    env.dl()
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");
    env.dl().args(["run", "--", "true"]).assert().success();

    // Set a NEW passphrase (fed via --password-stdin; the identity is plain,
    // so only the new-passphrase prompt consumes it) — same key pair again.
    env.dl()
        .args(["cert", "passwd", "--password-stdin"])
        .write_stdin(format!("{NEW_PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("identity passphrase updated"))
        .stdout(predicate::str::contains(&fingerprint));
    env.dl()
        .args(["cert", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("passphrase: yes"))
        .stdout(predicate::str::contains(&fingerprint));

    // Unlocking with the new passphrase works; without a source it prompts
    // (fails here) — and the OLD passphrase no longer decrypts the identity.
    env.dl().arg("lock").assert().success();
    env.dl().args(["get", "FOO"]).assert().failure();
    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", IDENTITY_PASSPHRASE)
        .args(["get", "FOO"])
        .assert()
        .failure();
    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", NEW_PASSPHRASE)
        .args(["get", "FOO"])
        .assert()
        .success()
        .stdout("bar-value\n");
}

/// Fix for the empty-passphrase footgun at the source: `dl cert init`
/// without `--plain` REJECTS an empty passphrase (here via the set-but-empty
/// non-interactive source) with an actionable error pointing at `--plain`,
/// and leaves no identity behind; `--plain` remains the supported
/// no-passphrase path.
#[test]
fn cert_init_rejects_an_empty_identity_passphrase() {
    let env = TestEnv::new();

    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", "")
        .args(["cert", "init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty identity passphrase"))
        .stderr(predicate::str::contains("--plain"))
        .stderr(predicate::str::contains("panicked").not());

    // Nothing half-created: there is no identity to show.
    env.dl()
        .args(["cert", "show"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not initialized"));

    // --plain still works, even with the empty var in the environment.
    env.dl()
        .env("DOTLOCK_IDENTITY_PASSPHRASE", "")
        .args(["cert", "init", "--plain"])
        .assert()
        .success();
    env.dl()
        .args(["cert", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("passphrase: no"));
}

/// Full grant -> revoke cycle on an envelope (v5+) vault, driven end to end
/// through the binary with two distinct identities (two DOTLOCK_HOMEs sharing
/// one project, like two teammates' machines):
///
/// 1. the peer identity, once granted, reads secrets with no master password
///    and no session cache — pure identity unlock;
/// 2. `dl share revoke` succeeds and rotates the project key;
/// 3. the OWNER still reads every secret afterwards via their own (rewrapped)
///    identity — the rotation must not brick the vault;
/// 4. the revoked peer can no longer unlock: its identity read fails and its
///    wrapped key material is gone from `vault.toml`.
#[test]
fn share_revoke_cycle_locks_out_revoked_recipient_end_to_end() {
    let env = TestEnv::new();
    env.init_vault();
    env.dl()
        .args(["set", "API_KEY", "owner-secret-1"])
        .assert()
        .success();
    env.dl()
        .args(["set", "DB_URL", "postgres://owner"])
        .assert()
        .success();

    // Owner identity: signs grants (H3) and, once granted itself, proves the
    // vault stays readable after the revoke rotation without any password.
    env.dl()
        .args(["cert", "init", "--plain"])
        .assert()
        .success();
    let owner_pub = env.project.join("owner.pub.pem");
    env.dl()
        .args(["cert", "export-pub"])
        .arg(&owner_pub)
        .assert()
        .success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["share", "grant", "--pubkey"])
        .arg(&owner_pub)
        .args(["--label", "owner"])
        .assert()
        .success();

    // Peer identity: a second DOTLOCK_HOME with its own identity.pem and its
    // own (empty) session cache.
    let peer_home = env.home.parent().expect("temp root").join("peer-home");
    fs::create_dir(&peer_home).expect("create peer home");
    env.dl_as(&peer_home)
        .args(["cert", "init", "--plain"])
        .assert()
        .success();
    let peer_pub = env.project.join("peer.pub.pem");
    env.dl_as(&peer_home)
        .args(["cert", "export-pub"])
        .arg(&peer_pub)
        .assert()
        .success();
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["share", "grant", "--pubkey"])
        .arg(&peer_pub)
        .args(["--label", "peer"])
        .assert()
        .success();

    // The grant migrated the vault to the envelope layout and recorded both
    // modern recipients; remember the peer's fingerprint so its removal can
    // be asserted precisely after the revoke.
    let out = env
        .dl()
        .args(["share", "list", "--json"])
        .output()
        .expect("run share list");
    let recipients: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("share list --json must be valid JSON");
    let peer_fingerprint = recipients
        .as_array()
        .expect("array of recipients")
        .iter()
        .find(|item| item["label"] == "peer")
        .expect("peer recipient listed")["fingerprint"]
        .as_str()
        .expect("fingerprint string")
        .to_string();
    let vault = fs::read_to_string(env.lock_path("vault.toml")).expect("read vault.toml");
    assert!(
        vault.contains(&peer_fingerprint),
        "peer's wrapped material must be recorded before the revoke:\n{vault}"
    );

    // The peer reads secrets through the binary with no master password and
    // no cached session key: identity unlock alone grants access.
    env.dl_as(&peer_home)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("owner-secret-1\n");

    // Revoke the peer through the binary; the project key is rotated.
    env.dl()
        .env("DOTLOCK_MASTER_PASSWORD", MASTER_PASSWORD)
        .args(["share", "revoke", "peer", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("project key rotated"));

    // The peer's wrapped key material is genuinely gone from vault.toml;
    // the owner's rewrapped grant remains.
    let vault = fs::read_to_string(env.lock_path("vault.toml")).expect("read vault.toml");
    assert!(
        !vault.contains(&peer_fingerprint),
        "revoke must remove every trace of the peer's wrapped material:\n{vault}"
    );
    assert!(
        vault.contains("label = \"owner\""),
        "the owner recipient must survive the revoke:\n{vault}"
    );

    // Vault not bricked: with the session cache invalidated by the revoke and
    // no password in the environment, the owner still reads both secrets via
    // their own identity, whose DEK wrapping was rotated to the new key.
    env.dl().arg("lock").assert().success();
    env.dl()
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("owner-secret-1\n");
    env.dl()
        .args(["get", "DB_URL"])
        .assert()
        .success()
        .stdout("postgres://owner\n");

    // The revoked peer is locked out: with its session cache dropped, its
    // identity can no longer unwrap the rotated project key.
    env.dl_as(&peer_home).arg("lock").assert().success();
    env.dl_as(&peer_home)
        .args(["get", "API_KEY"])
        .assert()
        .failure();
}
