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
use std::path::PathBuf;

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
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dl"));
        cmd.current_dir(&self.project)
            .env("DOTLOCK_HOME", &self.home)
            .env("HOME", &self.home)
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

    env.dl().args(["set", "FOO", "bar-value"]).assert().success();

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

    env.dl().args(["set", "FOO", "bar-value"]).assert().success();

    // list --json: array of {id, name}, no values.
    let out = env.dl().args(["list", "--json"]).output().expect("run list");
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

    // unset: the secret disappears.
    env.dl()
        .args(["unset", "FOO"])
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
