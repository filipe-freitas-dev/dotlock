//! End-to-end tests driving the real `dl` binary in isolated temp
//! directories. Every test gets its own project dir and its own
//! `DOTLOCK_HOME`/`HOME`, so nothing touches the developer's real state.
//!
//! Master-password bootstrap: `dl` has no non-interactive unlock yet
//! (`inquire` requires a TTY; Phase 4 FG2 will add
//! `DOTLOCK_MASTER_PASSWORD`/`--password-stdin`). Until then `dl init` is
//! driven through a pseudo-terminal via util-linux `script(1)`; after init the
//! session key cache under `DOTLOCK_HOME` keeps every subsequent command
//! non-interactive. Tests that need an initialized vault are skipped (with a
//! message) when `script` is unavailable.

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

    /// Initializes the vault by driving `dl init` through a pty (`script`).
    /// Returns `false` (test should skip) when no pty helper is available.
    fn init_vault(&self) -> bool {
        if !script_available() {
            eprintln!("skipping: util-linux `script` not available for pty-driven `dl init`");
            return false;
        }

        // Keystrokes: arrow-down + Enter selects "Type my own" in the
        // password-mode picker, then the password is typed and confirmed.
        let keystrokes = format!("\x1b[B\r{MASTER_PASSWORD}\r{MASTER_PASSWORD}\r");

        let mut cmd = Command::new("script");
        cmd.current_dir(&self.project)
            .env("DOTLOCK_HOME", &self.home)
            .env("HOME", &self.home)
            .arg("-qec")
            .arg(format!("{} init", env!("CARGO_BIN_EXE_dl")))
            .arg("/dev/null")
            .write_stdin(keystrokes);
        cmd.assert().success();

        assert!(
            self.project.join(".lock/vault.toml").exists(),
            "`dl init` must create .lock/vault.toml"
        );
        assert!(
            self.project.join(".lock/secrets.lock").exists(),
            "`dl init` must create .lock/secrets.lock"
        );
        true
    }

    fn lock_path(&self, name: &str) -> PathBuf {
        self.project.join(".lock").join(name)
    }
}

fn script_available() -> bool {
    std::process::Command::new("script")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .is_ok_and(|ok| ok)
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
fn init_without_a_tty_fails_gracefully() {
    let env = TestEnv::new();
    // No pty: the interactive prompt cannot run, and the failure must be a
    // clean error (no panic) that leaves no usable vault behind.
    env.dl()
        .arg("init")
        .write_stdin(format!("{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"))
        .stderr(predicate::str::contains("panicked").not());
    assert!(!env.project.join(".lock/vault.toml").exists());
}

#[test]
fn secret_lifecycle_set_get_list_export_run_unset() {
    let env = TestEnv::new();
    if !env.init_vault() {
        return;
    }

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

/// Phase 0/1 guarantee: while a pending-merge marker exists every access is
/// refused with a clear "run `dl reconcile`" error, and `dl reconcile` only
/// re-signs after explicit confirmation (declining aborts and keeps the
/// marker).
#[test]
fn pending_merge_marker_blocks_access_until_reconciled() {
    let env = TestEnv::new();
    if !env.init_vault() {
        return;
    }

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
fn tampered_secrets_file_is_refused() {
    let env = TestEnv::new();
    if !env.init_vault() {
        return;
    }

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
