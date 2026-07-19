# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-07-19

### Added

- `dl cert passwd` (alias `dl crt pw`) — change or remove the local identity's
  passphrase in place. The key pair and fingerprint are preserved, so access to
  shared vaults is kept. Use `--remove` to drop the passphrase (for example, to
  fix an identity accidentally created with a blank passphrase), or run it
  without the flag to set a new one.

### Changed

- `dl cert init` and `dl cert migrate` now reject an empty identity passphrase
  (use `--plain` for an unencrypted identity). This prevents accidentally
  creating a passphrase-encrypted identity with a blank passphrase that then
  prompts on every unlock.

## [1.1.0] - 2026-07-19

### Added

- **Non-interactive unlock for shared vaults.** The certificate (identity)
  passphrase prompt now honors the same non-interactive sources as the master
  password: `--password-stdin`, `--password-file`,
  `DOTLOCK_MASTER_PASSWORD`, and the new dedicated
  `DOTLOCK_IDENTITY_PASSPHRASE` environment variable (precedence:
  `DOTLOCK_IDENTITY_PASSPHRASE` > `--password-stdin` > `--password-file` >
  `DOTLOCK_MASTER_PASSWORD`). Shared-vault `dl get` and `dl run` with a
  passphrase-protected identity now work in CI. Without a TTY and without any
  source, commands fail with the actionable no-TTY error instead of hanging.
- `dl cert init` and `dl cert migrate` can now create a passphrase-encrypted
  identity non-interactively using the same sources.
- `dl cert show` now reports whether the identity's private key is
  passphrase-encrypted (`passphrase: yes/no`), without prompting.

## [1.0.1] - 2026-07-19

### Fixed

- Passphrase-encrypted local identities are now decrypted once per command and
  reused for per-secret key resolution and audit signing, instead of
  re-prompting for the identity passphrase on every secret. `dl get`, `dl run`,
  and `dl exec` in shared vaults no longer prompt multiple times. The crypto
  path is unchanged.

## [1.0.0] - 2026-07-19

First stable release. The on-disk vault format, the CLI surface, and the
security model are now considered stable. Vaults created with recent `0.1.x`
releases keep working unchanged.

### Security

- **Modern identity cryptography.** New identities use Ed25519 signatures and
  X25519 sealed-box key wrapping (libsodium-compatible) instead of RSA. All
  new setups are RSA-free; `dl cert migrate` moves an existing RSA identity to
  the new scheme and rekeys the current project's recipient entry so unlocking
  never touches RSA again.
- **Whole-vault tamper detection.** Vault metadata (`vault.toml`) now carries
  an HMAC-SHA256 metadata MAC keyed from the project key, and `secrets.lock`
  is covered by an integrity hash encrypted under the project key. Editing
  either file outside DotLock — swapping ciphertexts, resurrecting deleted
  secrets, or adding a recipient by hand — aborts commands with a tamper
  error.
- **Rollback/downgrade protection.** The vault carries a monotonic,
  MAC-covered epoch counter, and each machine remembers the newest epoch it
  has seen (`~/.lock/epoch/`). Force-pushing an older-but-self-consistent
  vault (for example one from before a revocation) is detected;
  `DOTLOCK_ALLOW_VAULT_ROLLBACK=1` exists for legitimate checkouts of old
  revisions.
- **Signed sharing grants.** Recipient grants are Ed25519 signatures by an
  authorized identity, not plain list entries — the recipient list cannot be
  silently extended by anyone able to write the vault file (including through
  a Git merge).
- **Hardened audit log.** Entries are hash-chained and signed when an identity
  is available; a signed high-water mark (entry count plus head hash) is
  written alongside the log so truncating the tail of an otherwise-valid chain
  is detected. `dl audit verify` is strict by default.
- **Hardened session cache.** The briefly cached project key is never stored
  raw: it is XChaCha20-Poly1305-encrypted under a separate per-user key file,
  with the expiry timestamp authenticated. Expired or tampered entries are
  shredded on sight; `dl lock` shreds them on demand.
- **Owner-only file permissions on Windows.** Sensitive files and directories
  (vault files, identities, session cache, audit log) receive a restrictive
  DACL granting access to the current user only, with inheritance severed —
  complementing the existing Unix `0700`/`0600` modes, `O_NOFOLLOW` opens and
  atomic writes.
- **Atomic, crash-safe vault writes.** The `vault.toml` + `secrets.lock` pair
  is written through a single transactional primitive with a journal, so a
  crash mid-write can no longer strand a secret's key or leave the vault
  reporting tampering; interrupted transactions are finished or rolled back.
- **Input hygiene.** Secret values can be supplied via hidden prompt or
  `--stdin` (keeping them out of argv, `ps` and shell history), `dl get`
  masks values on a terminal, and diagnostics avoid echoing secret material.
- **Refusal to degrade.** When no per-user state directory can be resolved
  (no `HOME`, no `DOTLOCK_HOME`), commands that would write identities,
  cached keys or audit logs fail with a clear error instead of dropping key
  material into a committable `./.lock`.

### Added

- **Multiple environments** — `dl env add/list/use/remove` and a global
  `--env NAME` flag (or `DOTLOCK_ENV`). Each environment (`dev`, `staging`,
  `prod`, …) has its own cryptographically isolated vault pair with its own
  salt, keys and master password; the default environment is the existing
  vault, so current projects keep working unchanged. The Git merge driver is
  environment-aware.
- **Non-interactive / CI unlock** — global `--password-stdin` and
  `--password-file FILE` flags, plus the `DOTLOCK_MASTER_PASSWORD`
  environment variable. All three feed the exact same unlock path as the
  interactive prompt; they work with every command, including `dl init`.
- **Machine-readable output** — a global `--json` flag for `dl list`,
  `dl get`, `dl share list`, `dl audit show` and `dl provider list`.
- **`dl exec`** — shell-form sibling of `dl run` (`sh -c`), so pipes and
  `&&` work; secrets are still injected as environment variables only, never
  spliced into the command string.
- **`--env-file FILE`** on `dl run` and `dl exec` — merge additional
  plaintext variables from a `.env` file as a migration aid (vault secrets
  win on collisions).
- **Scheduled rotation** — `dl rotate --if-due` rotates the project key only
  when a rotation is due per policy (`rotate_max_age_days` and/or
  `auto_ratchet_after_writes`) and exits 0 without prompting otherwise —
  cron/CI friendly.
- **`dl repair`** — diagnose and recover a vault whose integrity hash is out
  of sync (interrupted transactions, restored backups). Supports `--dry-run`
  and, with `--prune`, explicit removal of genuinely irrecoverable records.
  Requires a valid full-access unlock — it is a recovery path, never a
  tamper bypass.
- **`dl reconcile`** — review, re-sign and accept a vault combined by the Git
  merge driver; merged vaults are intentionally left pending until a human
  approves them.
- **`dl cert migrate`** — migrate a legacy RSA identity to Ed25519/X25519 and
  rekey the current project's recipient entry.

### Changed

- `dl audit verify` is **strict by default**: anonymous (unsigned) entries and
  an unsigned high-water mark fail with a non-zero exit; `--lax` downgrades
  them to warnings.
- `dl get` **masks the value by default when stdout is a terminal**; pass
  `--reveal` to show it. Piped output is unchanged (always the bare value).
- Destructive operations (`dl unset`, `dl rotate *`, `dl share revoke`,
  `dl env remove`, `dl repair`) now ask for confirmation and accept
  `-y`/`--yes` for scripts; without a TTY and without `--yes` they fail fast
  instead of hanging.

### Known issues / notes

- The `rsa` crate is retained **only to read legacy material** (RSA-wrapped
  recipient entries and old RSA-signed grants/audit lines). RUSTSEC-2023-0071
  ("Marvin") is tracked and accepted for that legacy-read path; no new-setup
  code path executes RSA. Run `dl cert migrate` to leave RSA behind entirely.
  Rationale and assessment: [ADR 0001](./docs/adr/0001-crypto-dependencies.md).
- The audit log, session cache and rollback anchor are per-machine local
  state; see the README's [security model](./README.md#security-model) for
  what DotLock does and does not protect against.

[1.0.0]: https://github.com/filipe-freitas-dev/dotlock/releases/tag/v1.0.0
