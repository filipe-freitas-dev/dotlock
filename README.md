<div align="center">

```
    ██████╗   ██████╗  ████████╗ ██╗       ██████╗   ██████╗ ██╗  ██╗
    ██╔══██╗ ██╔═══██╗ ╚══██╔══╝ ██║      ██╔═══██╗ ██╔════╝ ██║ ██╔╝
    ██║  ██║ ██║   ██║    ██║    ██║      ██║   ██║ ██║      █████╔╝
    ██║  ██║ ██║   ██║    ██║    ██║      ██║   ██║ ██║      ██╔═██╗
    ██████╔╝ ╚██████╔╝    ██║    ███████╗ ╚██████╔╝ ╚██████╗ ██║  ██╗
    ╚═════╝   ╚═════╝     ╚═╝    ╚══════╝  ╚═════╝   ╚═════╝ ╚═╝  ╚═╝
```

### Encrypt your `.env`. Share by key, not by password.

[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Cipher](https://img.shields.io/badge/Cipher-XChaCha20--Poly1305-FF1744?style=for-the-badge)](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-7C4DFF?style=for-the-badge)](https://en.wikipedia.org/wiki/Argon2)
[![Sharing](https://img.shields.io/badge/Sharing-Ed25519%20%2B%20X25519-00BFA5?style=for-the-badge)](https://en.wikipedia.org/wiki/Curve25519)
[![Version](https://img.shields.io/badge/Version-1.2.0-4CAF50?style=for-the-badge)](./CHANGELOG.md)

</div>

---

## What is DotLock?

DotLock is a local, file-based secrets manager for project environment variables. It stores secrets encrypted in a `.lock/` vault next to your code — safe to commit to git — and injects decrypted values only into child processes launched with `dl run` or `dl exec`.

Use DotLock when you want:

- to keep `.env` values encrypted **inside the repository**, instead of passing plaintext files around;
- to run local commands with decrypted variables without ever writing plaintext back to disk;
- separate, cryptographically isolated vaults per environment (`dev`/`staging`/`prod`) in the same checkout;
- to share project secrets with teammates through **public keys** instead of a shared password;
- a lightweight, tamper-evident audit log of unlocks, runs, key rotations and provider resolutions.

DotLock is not a hosted production secret manager. For large production systems, prefer a dedicated service such as AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault or your platform's native secret store.

**Contents:** [Install](#installation) · [Quick start](#quick-start) · [Core workflow](#core-workflow) · [Environments](#multiple-environments) · [CI usage](#non-interactive--ci-usage) · [Rotation](#rotation-and-ratcheting) · [Recovery](#vault-recovery-dl-repair) · [Sharing](#team-sharing) · [Providers](#dynamic-secret-providers) · [Git](#git-integration) · [Audit](#audit-log) · [Security model](#security-model) · [Configuration](#configuration) · [Command reference](#command-reference)

## Status

DotLock is at `1.2.0`: the on-disk vault format, the CLI surface and the security model are stable, and vaults created with recent `0.1.x` releases keep working unchanged. It remains a local, file-based tool — see the [security model](#security-model) for what it does and does not protect against, and keep backups of `.lock/` as ordinary operational hygiene. Release history: [CHANGELOG.md](./CHANGELOG.md).

## Installation

### From crates.io

```bash
cargo install dotlock-bin
```

The crate is named `dotlock-bin`; the installed binary is named `dl`.

### From source

```bash
cargo build --release
install -m 0755 target/release/dl ~/.local/bin/dl
```

DotLock uses Rust edition 2024.

## Quick Start

```bash
cd my-project
dl init                 # create the vault (choose or generate a master password)
dl migrate .env         # import an existing .env file
dl run npm start        # run with decrypted secrets in the child environment
```

What happens:

1. `dl init` creates `.lock/vault.toml` and `.lock/secrets.lock` (both safe to commit).
2. `dl migrate .env` imports variables from an existing `.env` file into the encrypted vault.
3. `dl run npm start` starts `npm start` with decrypted secrets in the child process environment — nothing plaintext touches disk.

After migration, remove the plaintext `.env` only when you have verified the imported values:

```bash
dl list
dl get DATABASE_URL
rm .env
```

## Core Workflow

### Initialize a project — `dl init`

Creates the project vault in the current directory:

```bash
dl init
```

You choose whether DotLock generates a strong master password or lets you type one (typed passwords must pass a strength check). Vault metadata goes into `.lock/vault.toml`; encrypted secret records go into `.lock/secrets.lock`. Run once per project.

### Add or update a secret — `dl set`

`dl set NAME [VALUE]` stores a secret under a normalized environment-variable name:

```bash
dl set DATABASE_URL                                   # preferred: hidden interactive prompt
printf '%s' "$TOKEN" | dl set API_TOKEN --stdin       # preferred for pipes/scripts
dl set DATABASE_URL "postgres://localhost/app_dev"    # discouraged: value lands in shell history and `ps`
```

**Prefer omitting the value.** With no `VALUE`, `dl set` reads the secret from a hidden prompt; `--stdin` reads it from standard input instead. Both keep the secret out of `ps`, `/proc/<pid>/cmdline` and shell history, where an argv value is visible to other processes.

Names must use letters, digits and underscores, cannot start with a digit, and are normalized to uppercase. `--alg`/`-a` selects the encryption algorithm; the current supported value is `xcha` (XChaCha20-Poly1305). Aliases: `dl s`, `dl add`.

### Read a secret — `dl get`

```bash
dl get DATABASE_URL             # masked on a terminal
dl get DATABASE_URL --reveal    # show the value on a terminal
dl get DATABASE_URL | pbcopy    # piped: always the bare value
```

When stdout is a terminal, the value is **masked by default** to keep it out of the scrollback — pass `--reveal` to show it. When stdout is piped, `dl get` always prints the raw value (no flag needed). Use it sparingly for copying or debugging; prefer `dl run` for normal execution.

### List secrets — `dl list`

```bash
dl list      # names and short ids only — never plaintext values
```

### Remove a secret — `dl unset`

```bash
dl unset OLD_FEATURE_FLAG        # asks for confirmation
dl unset OLD_FEATURE_FLAG -y     # scripted: skip the confirmation
```

Aliases: `rm`, `remove`, `del`, `delete`, `u`, `d`.

### Run a command with secrets — `dl run`

`dl run [--env-file FILE] -- CMD [args...]` decrypts accessible secrets and starts a child process with those values in its environment. The command runs **directly (argv form, no shell)**; secrets are injected as environment variables only and are **never interpolated into the command string**.

```bash
dl run npm start
dl run -- python manage.py runserver --noreload   # `--` needed when the command has flags
```

This is the normal way to consume secrets locally or in scripts.

### Run a shell command line — `dl exec`

`dl exec [--env-file FILE] COMMAND...` is the shell-form sibling of `dl run`: the command line runs via `sh -c`, so pipes, `&&` and other shell syntax work. Secrets are still injected as environment variables only — never spliced into the string.

```bash
dl exec "npm run build && npm start"
dl exec "node migrate.js | tee migrate.log"
```

Multiple words are joined with spaces, so `dl exec npm start` also works. Prefer `dl run -- cmd args` (no shell) when you don't need shell syntax.

### Merge extra variables from a plain `.env` file — `--env-file`

Both `dl run` and `dl exec` accept `--env-file FILE` to load additional **plaintext** variables alongside the vault. It is a migration aid: vault secrets always win on a name collision, and env-file values are neither encrypted nor covered by the vault's integrity checks.

```bash
dl run --env-file .env.defaults -- npm start
dl exec --env-file .env.local "npm run dev"
```

### Lock the session — `dl lock`

```bash
dl lock      # shred the cached project key for this project (alias: dl logout)
```

Use after a sensitive session, before handing off a machine, or at the end of CI/scripted workflows.

### Safety defaults

Every destructive command (`dl unset`, `dl rotate *`, `dl share revoke`, `dl env remove`, `dl repair`) asks for interactive confirmation and takes `-y`/`--yes` for scripts. Without a TTY and without `--yes`, they fail fast instead of hanging. After a git merge that touched `.lock/` files, run [`dl reconcile`](#reconcile-after-a-merge--dl-reconcile).

## Multiple Environments

A project can hold several environments — `dev`, `staging`, `prod` — each with its **own independent vault pair**: fresh salt, key-encryption key, project key and its own master password. Environments are cryptographically isolated: knowing the `dev` password gives no access to `prod`, and rotating or corrupting one environment never touches another.

**Backward compatibility:** the default environment *is* the vault DotLock has always used (`.lock/vault.toml` + `.lock/secrets.lock`), so existing projects keep working unchanged. Named environments live under `.lock/envs/<NAME>/` with the same pair layout.

### Manage environments

```bash
dl env add staging       # create a new environment (prompts for its master password)
dl env list              # show all environments and which one is active
dl env use staging       # persist staging as this checkout's default (.lock/env, non-secret)
dl env use default       # revert to the default environment
dl env remove staging    # PERMANENTLY delete .lock/envs/staging/ (confirms; --yes skips)
```

`dl env remove` destroys every secret in that environment and cannot remove the default environment.

### Select the environment per command

Every command accepts the global `--env NAME` flag. Selection precedence:

1. `--env NAME` on the command line;
2. the `DOTLOCK_ENV` environment variable;
3. the selection persisted by `dl env use` (in `.lock/env`);
4. the default environment.

`--env default` (or `DOTLOCK_ENV=default`) always forces the default environment.

```bash
dl set DATABASE_URL --env staging
dl run --env prod -- ./deploy.sh
DOTLOCK_ENV=staging dl list
```

The Git merge driver is environment-aware: merges of `.lock/envs/<NAME>/` files are routed to the right vault pair automatically.

## Non-Interactive / CI Usage

### Supply the master password without a prompt

In headless environments (CI, scripts) the interactive password prompt cannot run. DotLock accepts the master password from three non-interactive sources, in this precedence order:

1. `--password-stdin` — reads the password from the **first line of stdin** (so `dl set NAME --stdin --password-stdin` can still read the secret value from the rest of the pipe);
2. `--password-file FILE` — reads the password from the first line of `FILE`, opened with the same symlink-safe reader used for vault files;
3. `DOTLOCK_MASTER_PASSWORD` — environment variable, used when neither flag is passed.

When a TTY is available and no source is set, the interactive prompt runs as usual. When there is no TTY and no source, the command fails with a clear error. Both flags are global and work with every command, including `dl init` (where the password must still pass the strength check).

```bash
# CI unlock (preferred): the password never enters the process environment.
printf '%s\n' "$MASTER_PASSWORD" | dl run --password-stdin -- ./deploy.sh
dl get API_KEY --password-file /run/secrets/dotlock-password

# Env var (simplest, but weaker: environment variables are inherited by child
# processes, readable in /proc/<pid>/environ, and commonly echoed by CI debug logs).
DOTLOCK_MASTER_PASSWORD="$MASTER_PASSWORD" dl get API_KEY

# Non-interactive init for ephemeral test environments.
printf '%s\n' "$MASTER_PASSWORD" | dl init --password-stdin
```

A minimal CI job (GitHub Actions):

```yaml
- name: Run tests with vault secrets
  run: printf '%s\n' "$DL_PASSWORD" | dl run --password-stdin -- npm test
  env:
    DL_PASSWORD: ${{ secrets.DOTLOCK_MASTER_PASSWORD }}
```

**Security tradeoff:** every non-interactive source feeds the exact same unlock path as the prompt (Argon2id key derivation, project-key unwrap, metadata MAC and rollback-epoch verification) — there is no weaker CI unlock. Prefer `--password-stdin` or `--password-file` over the env var. The password buffer is zeroized in memory in all cases.

### Certificate (identity) passphrase in CI

Shared-vault unlocks don't use the master password — they decrypt your **local identity** (see [Team Sharing](#team-sharing)), which asks for the identity passphrase when the private key is passphrase-protected. Only one credential is ever needed per unlock, so the same non-interactive sources satisfy whichever prompt fires: with a shared vault, `--password-stdin` / `--password-file` / `DOTLOCK_MASTER_PASSWORD` supply the **identity passphrase** instead.

```bash
# CI unlock of a shared vault with a passphrase-protected identity.
printf '%s\n' "$IDENTITY_PASSPHRASE" | dl run --password-stdin -- ./deploy.sh
```

For environments that need **both** credentials in the same command (e.g. `dl share grant`, which unlocks with the master password *and* signs with your identity), the dedicated `DOTLOCK_IDENTITY_PASSPHRASE` environment variable feeds only the identity prompt and takes precedence over the shared sources for it:

```bash
DOTLOCK_IDENTITY_PASSPHRASE="$ID_PASS" \
  dl share grant --pubkey peer.pub --label peer --password-file /run/secrets/master
```

A wrong non-interactive passphrase fails the identity decrypt exactly like a mistyped one; a **plain** identity (`dl cert init --plain`) never asks for a passphrase at all — `dl cert show` tells you which kind you have.

### Machine-readable output — `--json`

The global `--json` flag switches read commands to structured JSON on stdout (human output stays the default). Exit codes are unchanged.

| Command | JSON shape |
|---|---|
| `dl list --json` | `[{"id": "<uuid>", "name": "<NAME>"}]` (never values) |
| `dl get NAME --json` | `{"name": "<NAME>", "id": "<uuid>", "value": "<value>"}` |
| `dl share list --json` | `[{"label", "fingerprint", "full_access", "allowed_secret_count"}]` |
| `dl audit show --json` | array of full audit entries (same shape as the on-disk JSONL lines) |
| `dl provider list --json` | `["<name>", ...]` |

```bash
dl list --json | jq -r '.[].name'
dl get API_KEY --json | jq -r '.value'
dl audit show --json --since 2026-01-01 | jq 'length'
```

`dl get --json` emits the secret value only because the user explicitly asked for that exact secret — the same exposure as the default piped output.

## Rotation and Ratcheting

### Rotate the master password — `dl rotate master-password`

Changes the password used to unlock the project key. Fast, because only the wrapping changes — see the [key hierarchy](#layer-1--design-why-the-keys-are-layered) for why.

```bash
dl rotate master-password      # alias: dl rotate mp
```

Use when a password may have been exposed but the vault itself does not need a full project-key rotation.

### Rotate the project key — `dl rotate project-key` / `dl rotate kek`

Generates a new project key (DEK) and rewraps every secret data key under it; secret ciphertexts stay unchanged, only their wrappings move.

```bash
dl rotate project-key          # alias: dl rotate pk
dl rotate kek                  # historical name; does the same thing
```

(`kek` is the historical command name — the KEK itself is always re-derived from the master password, so what actually rotates is the project key and the SDK wrappings.) Use after a suspected project-key exposure, after major access changes, or as periodic hygiene.

### Policy-driven rotation — `dl rotate --if-due`

Rotates the project key **only when a rotation is due** per the configured policy, and exits `0` without rotating (and without prompting for a password) when nothing is due — cron/CI friendly. Two policies can make a rotation due:

- `rotate_max_age_days` — age since the last rotation;
- `auto_ratchet_after_writes` — number of vault writes since the last rotation.

```bash
dl config set rotate_max_age_days 30
dl rotate --if-due                                   # in a cron job or scheduled CI step
printf '%s\n' "$PW" | dl rotate --if-due --password-stdin
```

`--if-due` conflicts with an explicit rotation subcommand — it decides *whether* to rotate, not *what*. Schedule it so key rotation happens on a policy instead of on memory.

### Automatic write-count ratchet

Independently of `--if-due`, setting `auto_ratchet_after_writes` makes DotLock rotate key wrapping automatically after that many vault writes, inline as part of a normal write command; `0` disables it. Use `--if-due` for a schedule you control; use the auto-ratchet to rotate without any scheduled job.

## Vault Recovery (`dl repair`)

`dl repair` diagnoses and recovers a vault whose integrity hash is out of sync with `secrets.lock` — the state DotLock otherwise reports as tampering. Legitimate causes include lost transaction journals, partial backup restores and historical merge bugs. Repair can:

- finish or roll back an interrupted vault transaction;
- recompute and reseal a stale or undecryptable integrity hash — after verifying that every record still decrypts;
- with `--prune`, remove records that are genuinely irrecoverable (missing key wrapping or failed decryption) and reseal the rest. The data loss is explicit and enumerated; without `--prune`, repair only reports those records and exits non-zero.

```bash
dl repair --dry-run    # print the diagnosis only; never modifies anything
dl repair              # repair what is recoverable (asks for confirmation)
dl repair --prune -y   # scripted recovery, dropping irrecoverable records
```

Repair requires a valid full-access unlock — it is a recovery path for people who hold the master password, **never** a tamper bypass. Without the correct password there is no project key and no repair. Every executed repair is recorded in the audit log.

Use it when a command aborts with a vault-integrity error and you know the cause is operational (interrupted write, restored backup) rather than an attack.

## Import and Export `.env` Files

### Import — `dl migrate [PATH]`

```bash
dl migrate                  # defaults to .env
dl migrate .env.local
dl import .env.production   # alias
```

The parser accepts `KEY=VALUE`, `export KEY=VALUE`, single-quoted values, double-quoted values with escapes (`\n`, `\r`, `\t`, `\\`, `\"`), comments and blank lines.

### Export — `dl export [PATH]`

Writes missing static secrets into a `.env` file:

```bash
dl export
dl export .env.local
```

Existing keys are never overwritten. Dynamic secrets are skipped because their values are resolved at runtime. `dl export` warns when the exported file is not covered by `.gitignore` inside a git repository and offers to add it.

## Team Sharing

DotLock supports shared access through a local key-pair identity: the project owner keeps the master password, and recipients unlock with their own private key. New identities use **Ed25519** for signing and **X25519 sealed boxes** for key wrapping; legacy RSA identities are still read for backward compatibility (see [`dl cert migrate`](#migrate-a-legacy-rsa-identity--dl-cert-migrate) and [ADR 0001](./docs/adr/0001-crypto-dependencies.md)). Grants are **cryptographically signed** by an authorized signer's identity, so a recipient list cannot be silently extended by editing the vault file.

### Create a local identity — `dl cert init`

```bash
dl cert init            # passphrase-protected Ed25519 key pair
dl cert init --plain    # unencrypted private key (controlled automation only)
dl cert init --force    # replace an existing identity
```

Each developer or CI environment does this once before requesting shared access. The passphrase prompt accepts the [non-interactive sources](#certificate-identity-passphrase-in-ci) too, so a passphrase-protected identity can be created in CI: `printf '%s\n' "$ID_PASS" | dl cert init --password-stdin`.

An **empty passphrase is rejected** (interactively and from the non-interactive sources): `encrypted` under `""` protects nothing and turns every unlock into a pointless prompt. Use `--plain` if you genuinely want no passphrase — and if you already have an empty-passphrase identity from an older version, [`dl cert passwd --remove`](#change-or-remove-the-identity-passphrase--dl-cert-passwd) repairs it without prompting.

### Show or export the public key — `dl cert show` / `dl cert export-pub`

```bash
dl cert show                  # fingerprint, algorithm, passphrase state and paths
dl cert export-pub alice.pub  # write the public key to a file
dl cert export-pub            # print it
```

`cert show` reports `passphrase: yes/no` — whether the private key on disk is passphrase-encrypted (i.e. whether unlocks will ask for a passphrase) — without decrypting it, so it never prompts.

Use `export-pub` when sending your public key to a vault owner.

### Change or remove the identity passphrase — `dl cert passwd`

```bash
dl cert passwd            # set a new passphrase (prompts for the current one first)
dl cert passwd --remove   # store the private key unencrypted (no more prompts)
```

Re-encodes the existing private key **in place** — the key pair is never regenerated, so the **fingerprint is unchanged** and every shared vault that lists you as a recipient keeps working; no re-grant is needed. Only the on-disk PKCS#8 encoding of `identity.pem` (and the `encrypted` flag in `identity.toml`) changes.

Both the *current* and the *new* passphrase accept the [non-interactive sources](#certificate-identity-passphrase-in-ci), so the command works in CI too. An identity accidentally "encrypted" under an **empty** passphrase (older versions accepted pressing Enter at `cert init`) is detected and unlocked silently — `dl cert passwd --remove` fixes that state with zero prompts. Setting a new *empty* passphrase is rejected, same as at `cert init`. Alias: `dl crt pw`; `--plain` is accepted as an alias for `--remove`.

### Migrate a legacy RSA identity — `dl cert migrate`

Moves an existing RSA identity to the modern Ed25519/X25519 scheme and rekeys the current project's recipient entry so unlocking it never touches RSA again:

```bash
dl cert migrate
dl cert migrate --plain   # unencrypted new private key (controlled automation only)
```

The old RSA key is archived next to the new identity — it is still needed to rekey *other* shared projects you belong to; run `dl cert migrate` once inside each of them, then the archived key can be retired. If the identity is already Ed25519 but the project still holds an RSA wrapping, the command performs one final RSA unwrap and rewraps the entry as an X25519 sealed box. Run once per machine if you created your identity before the Ed25519 migration, then once per shared project. Rationale and details: [ADR 0001](./docs/adr/0001-crypto-dependencies.md).

### Enable shared mode — `dl share enable`

```bash
dl share enable
```

Run before granting access to teammates or CI.

### Grant access — `dl share grant`

```bash
dl share grant --pubkey alice.pub --label alice                       # full access
dl share grant --pubkey ci.pub --label ci --allow DATABASE_URL,REDIS_URL  # per-secret access
```

Without `--allow`, the recipient gets full access. With `--allow`, the recipient can decrypt only the listed secrets — use it for least-privilege CI identities.

### Manage a recipient's ACL — `dl share allow`

```bash
dl share allow ci --list
dl share allow ci --add STRIPE_KEY
dl share allow ci --remove REDIS_URL
```

The recipient query can be the recipient id, label or public key fingerprint; `--add`/`--remove` take comma-separated lists. Removing a secret from a recipient rotates that secret's data key, so the old recipient wrapping cannot decrypt future values.

### List or revoke recipients — `dl share list` / `dl share revoke`

```bash
dl share list
dl share revoke alice        # confirms; --yes skips — and rotates the project key
```

Revocation rotates project access material so the revoked identity cannot unlock **future** vault states. It cannot un-read the past: values the recipient could already decrypt from old git history should be rotated at the source (new API keys, new passwords) — see [what DotLock does not protect against](#what-dotlock-does-not-protect-against).

## Dynamic Secret Providers

Dynamic secrets are resolved by external executables instead of storing a fixed value. Provider binaries must be named `dotlock-provider-NAME` and be available on `PATH`.

### Discover providers

```bash
dl provider list       # provider binaries found on PATH
dl provider info aws   # run the provider's --describe
```

### Store a dynamic secret

```bash
dl set DATABASE_URL --provider aws --config '{"name":"prod/db/url"}'
dl set API_TOKEN --provider vault --config '{"path":"secret/api"}' --bootstrap VAULT_TOKEN
```

`--config` must be valid JSON. `--bootstrap` is a comma-separated list of existing static secrets that DotLock decrypts and passes to the provider at resolve time.

### Provider protocol

Providers run as child processes:

- `dotlock-provider-NAME --describe` prints human-readable provider information;
- `dotlock-provider-NAME --resolve` reads JSON on stdin and prints the resolved secret value on stdout.

The resolve input has this shape:

```json
{
  "config": {},
  "bootstrap": {
    "VAULT_TOKEN": "decrypted bootstrap value"
  }
}
```

DotLock records the provider path and SHA-256 digest when the dynamic secret is created, and verifies the digest before running the provider on later resolutions. Provider stdout is limited to 64 KiB and stderr to 16 KiB. Providers are executable code — install them only from trusted sources. DotLock refuses provider directories/binaries that are group- or world-writable or owned by another non-root user, and warns loudly when a dynamic secret's provider is not sha256-pinned (re-run `dl set <NAME> --provider <name>` to pin it).

## Git Integration

### Install the merge driver — `dl git install-merge-driver`

Configures Git to use DotLock's merge driver for `.lock/secrets.lock` and `.lock/vault.toml`:

```bash
dl git install-merge-driver
```

`dl init` also attempts to install it when the project is inside a Git work tree. The driver is environment-aware: merges of `.lock/envs/<NAME>/` files are routed to the right vault pair.

### Reconcile after a merge — `dl reconcile`

When the merge driver combines two vault histories, the result is intentionally left **pending**: DotLock records a marker and refuses normal operations until a human reviews it. `dl reconcile` shows what the merge changed, then re-signs and accepts the merged vault after your confirmation:

```bash
git merge feature-branch   # merge driver combines .lock files, leaves a pending marker
dl reconcile               # review the merge diff, then re-sign and accept
```

Reconcile requires a full-access unlock and refuses to proceed if the merged files were edited after the merge driver produced them. Run once after any Git merge that touched `.lock/` files.

### Sync from remote — `dl sync`

Fetches the configured remote and updates the current branch only when Git can fast-forward safely:

```bash
dl sync
```

It uses `auto_fetch_remote` from project config (default `origin`), aborts when `.lock/vault.toml` or `.lock/secrets.lock` has local staged, unstaged or untracked changes, or when the branches diverged. It never runs a hard reset and never discards local vault data.

### Auto-fetch before run

When enabled, `dl run` tries a short `git pull --ff-only --no-rebase REMOTE BRANCH` before unlocking:

```bash
dl config set auto_fetch_on_run true
dl config set auto_fetch_timeout_secs 3
dl config set auto_fetch_remote origin

DOTLOCK_AUTO_FETCH=0 dl run npm test    # disable for one command
```

If pull fails, DotLock tries `git fetch` and then continues with the local vault.

## Audit Log

DotLock keeps a local audit log outside the project by default. Entries are hash-chained; if a local plain identity is available they are signed, otherwise they are anonymous.

### Show entries — `dl audit show`

```bash
dl audit show
dl audit show --verbose
dl audit show --since 2026-05-01
dl audit show --action run
```

### Verify, rotate, locate — `dl audit verify` / `rotate` / `path`

```bash
dl audit verify          # strict by default
dl audit verify --lax    # accept anonymous entries and an unsigned high-water mark
dl audit path            # print the current log path
dl audit rotate          # gzip the current log
```

Verification is **strict by default**: anonymous (unsigned) entries and an unsigned high-water mark fail with a non-zero exit code; `--lax` downgrades those to warnings. Each audit write also records a signed high-water mark (entry count plus head hash) next to the log, so deleting the last N entries is detected even though each remaining line still chains correctly. Logs rotate automatically when they reach 10 MiB or are older than 90 days.

Audit logs are local by default — useful for local accountability and incident review, not a centralized compliance system.

## Security Model

**Threat model in one line:** the primary adversary is someone with write access to the repository (a teammate, CI, or anyone who obtains `.lock/`), or a local process running as your user — not a remote network attacker, because DotLock is not a network service.

This section has two layers: first the design and *why* it is shaped this way, then the exact cryptography for readers who want to check the details.

### Layer 1 — Design: why the keys are layered

DotLock uses an envelope (key-wrapping) hierarchy. No key in the chain ever touches disk unencrypted:

```text
master password
  └─ Argon2id ──► master key            (in memory only, zeroized after use)
       └─ HKDF ──► KEK                  (key-encryption key; re-derived, never stored)
            └─ wraps ──► project key    (DEK; random, stored only in wrapped form)
                 └─ wraps ──► per-secret keys (SDKs; one random key per secret)
                      └─ encrypts ──► each secret value / provider metadata
```

Each layer exists for a reason:

- **Cheap password changes.** `dl rotate master-password` only re-wraps the project key — one small blob — instead of re-encrypting every secret.
- **Blast-radius limiting.** Rotating the project key (`dl rotate project-key`) rewraps the per-secret keys but leaves secret ciphertexts untouched; compromising one secret's key (SDK) exposes one secret, not the vault.
- **Per-secret sharing.** Because every secret has its own key, a recipient can be granted exactly the secrets they need (`dl share grant --allow`): they receive wrapped SDKs for those secrets and nothing else.

#### What lives where (committed vs. local)

| File | Committed to git? | Contents |
|---|---|---|
| `.lock/vault.toml` | yes | vault metadata: salt, wrapped project key, recipients and signed grants, encrypted integrity hash, metadata MAC, epoch counter, project config |
| `.lock/secrets.lock` | yes | encrypted secret records: name, id, ciphertext, wrapped per-secret keys |
| `.lock/env` | yes (optional) | plain, non-secret persisted environment selection from `dl env use` |
| `.lock/envs/<NAME>/` | yes | one `vault.toml` + `secrets.lock` pair per named environment |
| `~/.lock/identity/` | **never** | your private identity key (`identity.pem`), public key, metadata |
| `~/.lock/run/` | **never** | wrapped session cache + its wrapping key |
| `~/.lock/audit/<project>/` | **never** | hash-chained audit log + signed high-water mark |
| `~/.lock/epoch/` | **never** | per-machine rollback anchor (newest vault epoch seen) |

Everything committed is either public metadata or ciphertext. An attacker who obtains the repository sees variable *names* and ciphertexts — nothing decryptable without the master password or a granted private key. Secret records deliberately do not carry a per-secret algorithm tag next to the name (the cipher is a storage-version policy), so the vault leaks no name-to-algorithm pairing an attacker could use to prioritize offline guessing.

DotLock refuses to fall back to the current directory for local state: when neither `HOME` (or `%LOCALAPPDATA%` on Windows) nor `DOTLOCK_HOME` resolves — cron jobs, containers, systemd units without a login environment — commands that would write identities, cached keys or audit logs fail with a clear error instead of dropping key material into a committable `./.lock`.

#### The protections and why each exists

- **Confidentiality.** Every secret is encrypted with an authenticated cipher under its own key; the password is stretched with a memory-hard KDF so offline brute-force of a stolen `.lock/` is expensive.
- **Tamper detection.** Vault metadata carries a MAC and `secrets.lock` is covered by an encrypted hash, both keyed from material only a legitimate unlock produces. Editing either file outside DotLock aborts commands with a tamper error — an attacker with repo write access cannot silently swap ciphertexts, resurrect deleted secrets, or add themselves as a recipient.
- **Rollback protection.** The vault carries a monotonic epoch, and each machine remembers the newest epoch it has seen. Force-pushing an older-but-self-consistent vault (e.g. one from before a revocation) is detected on any machine that already saw the newer state.
- **Signed sharing.** Recipient grants are signatures, not just list entries — the recipient list is not editable by anyone who can write the file.
- **Audit trail.** Unlocks, runs, rotations, repairs and provider resolutions are appended to a hash-chained, signed-when-possible local log with a signed high-water mark, so both middle-of-log edits and tail truncation are detectable.

#### What DotLock does NOT protect against

Being honest about limits matters more in a security tool than anywhere else:

- **An attacker who owns your machine while a vault is unlocked.** Code running as your user (or root) during the session-cache TTL can read the cache and its wrapping key, or simply read your process memory. No local tool survives that; `dl lock` and `DOTLOCK_CACHE_TTL=0` narrow the window, they do not close it.
- **Revoked users reading the past.** `dl share revoke` rotates keys so the recipient cannot unlock *future* vault states — but every value they could decrypt before revocation is still decryptable by them from old git history they already have. Treat revocation as "rotate the sensitive values themselves" (new API keys, new database passwords), not as un-sharing.
- **Rollback when the attacker controls both the repo and your local anchor.** The epoch anchor is per-machine local state; someone who can rewrite the repository *and* delete or rewind `~/.lock/epoch/` on your machine (i.e. same-user local access) can serve you an old vault. A fresh clone on a brand-new machine has no anchor yet, so its first unlock accepts whatever epoch it sees.
- **A malicious provider binary.** Dynamic providers execute as your user. Digest pinning detects replacement, not malice at install time.
- **Weak master passwords.** Argon2id slows brute force; it cannot rescue a guessable password.

### Layer 2 — The actual cryptography

Exact primitives and parameters, for verification against the source. Nothing here is bespoke crypto — every construction is a standard composition of well-reviewed primitives (RustCrypto crates and `crypto_box`).

**Password → master key.** Argon2id v1.3 with 64 MiB memory (`m = 65536` KiB), `t = 3` iterations, `p = 1` lane, over a random 16-byte per-vault salt, producing a 32-byte master key. The master key exists only in memory and is zeroized after use.

**Master key → KEK (domain separation).** HKDF-SHA256 with salt `dotlock:v1:hkdf` and info string `dotlock:v1:kek:project=<uuid>:env=<name>:version=<n>`. Binding the project UUID, environment name and key version into the derivation is what makes environments cryptographically isolated: the same password would still derive different KEKs per environment, and a wrapped blob from one environment or key version cannot be replayed in another.

**All encryption and wrapping: XChaCha20-Poly1305 AEAD.** Every encryption in the system — secret values, wrapped project key, wrapped per-secret keys, the integrity hash, the session cache — uses XChaCha20-Poly1305 with a fresh random 192-bit (24-byte) nonce per operation (the extended nonce makes random generation safe without counters) and context-binding *additional authenticated data*:

- each secret record's AEAD is bound to a length-prefixed encoding of `id | name | updated_at | version` — so a valid ciphertext cannot be swapped under another variable name, and an old version of a secret cannot be replayed as the current one;
- the wrapped project key's AAD binds `project`, `environment` and `kek_version` (with a one-shot fallback that still authenticates pre-versioning vaults).

**Integrity of `secrets.lock`.** After every write, DotLock stores the SHA-256 of `secrets.lock` *encrypted under the project key* (AAD `dotlock:v1:secrets-hash`) in `vault.toml`; on unlock it recomputes the file hash and compares in constant time. Because the stored hash is itself an AEAD ciphertext under the DEK, an attacker without the password cannot recompute a matching value after modifying the file.

**Integrity of `vault.toml`.** A metadata MAC: HMAC-SHA256 over a canonical encoding of the vault metadata, keyed by HKDF-SHA256 from the project key (salt `dotlock:v1:metadata-mac`, info bound to the project UUID — domain-separated from the KEK derivation). Verified in constant time on unlock. This covers the recipient list, epoch and key metadata, so none of it can be edited undetected.

**Rollback protection.** The MAC-covered vault epoch is a monotonic counter bumped on rotations and other security-relevant writes. Each machine persists the newest epoch it has seen per project under `~/.lock/epoch/` (outside the repo); an unlock that presents an older epoch than the anchor fails unless explicitly accepted with `DOTLOCK_ALLOW_VAULT_ROLLBACK=1` (for legitimate checkouts of old revisions).

**Sharing.** Identities are Ed25519 (PKCS#8 PEM, optionally scrypt-encrypted). Grants, audit entries and the audit high-water mark are Ed25519 signatures. Key wrapping to a recipient is an X25519 sealed box (`crypto_box`, libsodium-compatible `seal`); the recipient's X25519 key is derived from their Ed25519 key via the standard Edwards→Montgomery map — the same construction libsodium and age use. RSA-3072 (OAEP/PSS) is kept **only to read legacy material** — existing RSA-wrapped entries and old RSA-signed grants/audit lines; no fresh setup ever executes RSA code, and `dl cert migrate` moves an identity and project off it entirely. Rationale, the RUSTSEC-2023-0071 ("Marvin") assessment and the migration design are in [ADR 0001](./docs/adr/0001-crypto-dependencies.md).

**Audit log.** JSONL entries, each carrying the SHA-256 hash of its predecessor (hash chain) and an Ed25519 signature when a usable identity is present. A signed high-water mark (`count` + head hash) is written alongside, so truncating the tail of an otherwise-valid chain is detected. `dl audit verify` is strict by default (unsigned entries fail); `--lax` downgrades them to warnings.

**Session cache.** After a successful unlock, the project key may be cached briefly so consecutive commands do not re-prompt (default TTL 15 s via `DOTLOCK_CACHE_TTL`, capped at 300; disabled in shared mode unless `DOTLOCK_SHARED_CACHE` is set). The cached key is never stored raw: it is XChaCha20-Poly1305-encrypted under a key derived from a separate per-user random key file (`~/.lock/run/session.key`, mode `0600`), with the expiry timestamp bound as AAD. Expired or tampered entries are overwritten with zeros and deleted on sight; `dl lock` shreds them on demand. **Honest residual:** the wrapped cache and its wrapping key live on the same filesystem — a same-uid process within the TTL can recover the project key; the wrapping defeats single-file exposure (a backed-up `sessions.toml`, a log shipper), not a same-user attacker. Filesystem snapshots, swap and copy-on-write storage may also defeat best-effort shredding. On multi-tenant machines, set `DOTLOCK_CACHE_TTL=0` or run `dl lock` after sensitive sessions.

**File permissions.** On Unix: private directories `0700`, secret/private files `0600` (mode applied at open/mkdir time), public key files `0644`, `O_NOFOLLOW` symlink-safe opens, and atomic temp-file-and-rename writes. Windows is covered below.

### Windows

File-permission hardening is implemented on both families. On Windows, DotLock applies a restrictive DACL to every sensitive file and directory it creates (vault/secrets files, identities, session cache, audit log): a single access-control entry granting full control to the current user only, with inheritance from the parent severed (`PROTECTED_DACL_SECURITY_INFORMATION`), so no other account — including other members of local groups — retains access through inherited ACEs. Private directories get an inheritable owner-only ACE so files born inside them (e.g. transaction journals) start owner-only. If applying the DACL fails, the operation errors out rather than silently leaving a permissive file behind.

Honest residual differences on Windows: there is no `O_NOFOLLOW` equivalent in the portable open path, so symlink rejection falls back to a check-then-open pattern — a narrow race window that requires a local attacker who can already write inside your protected directories. Files that existed before this hardening keep whatever ACLs they had until rewritten, and Administrators can always take ownership of any file; that is inherent to the platform.

### Operational notes

- Commit `.lock/vault.toml` and `.lock/secrets.lock` (and `.lock/envs/`) if your team shares the encrypted vault through Git; never commit plaintext `.env` files after migrating.
- Prefer `dl set NAME` (hidden prompt) or `--stdin` over passing values in argv; prefer `dl run` over `dl get` for consumption.
- Keep local identity private keys protected; use `dl cert init --plain` only for controlled automation or ephemeral environments.
- Known dependency advisories (RSA "Marvin" RUSTSEC-2023-0071 and monitored transitive crates) are documented in [ADR 0001](./docs/adr/0001-crypto-dependencies.md); CI enforces `cargo audit`/`cargo deny` so only the documented advisories are accepted. Since the Ed25519/X25519 migration the RSA paths run only when reading legacy material — run `dl cert migrate` to leave them behind entirely.

## Configuration

### Project configuration

Stored in `.lock/vault.toml`, managed with `dl config`:

```bash
dl config show
dl config set rotate_max_age_days 30
dl config set auto_ratchet_after_writes 50
dl config unset auto_fetch_remote
```

| Key | Default | Accepted values | Effect |
|---|---:|---|---|
| `auto_fetch_on_run` | `false` | `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` | Enables Git auto-fetch before `dl run` |
| `auto_fetch_timeout_secs` | `3` | positive integer | Timeout for Git auto-fetch operations |
| `auto_fetch_remote` | `origin` | non-empty string | Remote used by auto-fetch and `dl sync` |
| `auto_ratchet_after_writes` | off | non-negative integer | Rotates key wrapping automatically after this many vault writes; `0` disables (also a `dl rotate --if-due` policy) |
| `rotate_max_age_days` | off | non-negative integer | Marks a project-key rotation as due for `dl rotate --if-due` after this many days; `0` disables |
| `dynamic_resolve_timeout_secs` | `10` | positive integer | Timeout for dynamic provider resolution |

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `DOTLOCK_ENV` | unset | Selects the environment vault; overridden by `--env`, overrides the `dl env use` selection |
| `DOTLOCK_MASTER_PASSWORD` | unset | Non-interactive master password; overridden by `--password-stdin` / `--password-file` (preferred — env vars can leak in CI logs and process listings). In shared mode the same sources feed the identity passphrase instead |
| `DOTLOCK_IDENTITY_PASSPHRASE` | unset | Non-interactive **identity** passphrase; takes precedence over the shared sources for the identity prompt only — use it when one command needs both credentials (e.g. `dl share grant`) |
| `DOTLOCK_CACHE_TTL` | `15` | Cached project key lifetime in seconds, capped at 300; `0` makes entries expire immediately (effectively disabling the cache) |
| `DOTLOCK_CACHE_DIR` | `$HOME/.lock` on Unix, `%LOCALAPPDATA%\dotlock` on Windows | Overrides the session cache root |
| `DOTLOCK_SHARED_CACHE` | off | Set to `1`, `true`, `TRUE`, `yes` or `YES` to enable caching in shared mode |
| `DOTLOCK_IDENTITY_DIR` | `$HOME/.lock/identity` | Overrides local identity storage |
| `DOTLOCK_HOME` | unset | Overrides the per-user state root (`$HOME/.lock` / `%LOCALAPPDATA%\dotlock`); required in environments without `HOME` |
| `DOTLOCK_AUDIT_DIR` | `$HOME/.lock/audit` on Unix, `%LOCALAPPDATA%\dotlock\audit` on Windows | Overrides audit log storage |
| `DOTLOCK_AUTO_FETCH` | unset | Set to `0`, `false`, `no` or `off` to disable auto-fetch for one command |
| `DOTLOCK_ALLOW_VAULT_ROLLBACK` | unset | Set to `1` to accept a vault whose epoch is older than the newest one this machine has seen (e.g. a legitimate checkout of an older revision) |

## Command Reference

| Command | Aliases | Purpose |
|---|---|---|
| `dl init` | `i` | Initialize `.lock/` in the current project |
| `dl set [--alg xcha] NAME [VALUE] [--stdin]` | `s`, `add` | Store or update a static secret (hidden prompt when VALUE is omitted) |
| `dl set NAME --provider PROVIDER [--config JSON] [--bootstrap A,B]` | `s` | Store a dynamic secret definition |
| `dl get NAME [--reveal]` | `g` | Print a secret (masked on a TTY unless `--reveal`; piped output is always the bare value) |
| `dl unset NAME [--yes]` | `u`, `rm`, `remove`, `d`, `del`, `delete` | Remove a secret (confirms; `--yes`/`-y` skips) |
| `dl list` | `l` | List stored secrets without plaintext |
| `dl run [--env-file FILE] -- CMD [args...]` | `r` | Run a command (argv form, no shell) with decrypted secrets in its environment |
| `dl exec [--env-file FILE] COMMAND...` | `e` | Run a shell command line (`sh -c`) with decrypted secrets in its environment |
| `dl lock` | `k`, `logout` | Shred the cached project key |
| `dl migrate [PATH]` | `m`, `import` | Import variables from `.env` |
| `dl export [PATH]` | `x` | Append missing static secrets to `.env` |
| `dl sync` | `sy` | Fast-forward from the configured Git remote when safe |
| `dl cert init [--force] [--plain]` | `crt i` | Create a local Ed25519 identity |
| `dl cert show` | `crt sh` | Show local identity information |
| `dl cert passwd [--remove]` | `crt pw` | Change or remove the identity passphrase in place (key pair and fingerprint unchanged) |
| `dl cert migrate [--plain]` | `crt m` | Migrate a legacy RSA identity to Ed25519/X25519 and rekey this project's recipient entry |
| `dl cert export-pub [PATH]` | `crt x` | Print or write the public key |
| `dl share enable` | `shr en` | Enable shared mode |
| `dl share grant --pubkey FILE --label LABEL [--allow A,B]` | `shr gr` | Grant recipient access (signed) |
| `dl share allow QUERY [--list] [--add A,B] [--remove A,B]` | `shr al` | Inspect or edit a recipient's per-secret ACL (removal rotates affected keys) |
| `dl share revoke QUERY [--yes]` | `shr rev` | Revoke a recipient and rotate the project key (confirms; `--yes` skips) |
| `dl share list` | `shr l` | List recipients |
| `dl rotate kek [--yes]` | `rot k` | Rotate the project key and rewrap secret keys (historical name for `project-key`) |
| `dl rotate master-password [--yes]` | `rot mp` | Change the master password (confirms; `--yes` skips) |
| `dl rotate project-key [--yes]` | `rot pk` | Rotate the project key (confirms; `--yes` skips) |
| `dl rotate --if-due` | `rot --if-due` | Rotate only when due per `rotate_max_age_days` / `auto_ratchet_after_writes`; exits 0 when nothing is due |
| `dl env list` | `ev l` | List this project's environments |
| `dl env add NAME` | `ev a` | Create an environment with its own vault pair |
| `dl env use NAME` | `ev u` | Persist NAME as this checkout's default environment |
| `dl env remove NAME [--yes]` | `ev rm` | PERMANENTLY delete an environment's vault pair (confirms; `--yes` skips) |
| `dl audit show [--verbose] [--since YYYY-MM-DD] [--action ACTION]` | `a s` | Show audit entries |
| `dl audit verify [--lax]` | `a v` | Verify audit hash chain and signatures (strict by default) |
| `dl audit path` | `a p` | Print the audit log path |
| `dl audit rotate` | `a r` | Rotate and gzip the current audit log |
| `dl git install-merge-driver` | `gt i` | Configure the Git merge driver |
| `dl config show` | `c sh` | Show project config |
| `dl config set KEY VALUE` | `c s` | Set a project config value |
| `dl config unset KEY` | `c u` | Reset a project config value |
| `dl provider list` | `p l` | List provider binaries on `PATH` |
| `dl provider info NAME` | `p i` | Show provider description |
| `dl reconcile` | `rec` | Review and re-sign a vault combined by the Git merge driver |
| `dl repair [--dry-run] [--prune] [--yes]` | `rep` | Diagnose and recover a vault whose integrity hash is out of sync |

Global flags, accepted by every command: `--json` (machine-readable output for `list`, `get`, `share list`, `audit show`, `provider list`), `--password-stdin` / `--password-file FILE` (non-interactive master password — or identity passphrase in shared mode; see [CI usage](#non-interactive--ci-usage)), and `--env NAME` (operate on a named environment's vault; see [Multiple Environments](#multiple-environments)).

## License

Dual-licensed under your choice of:

- MIT: [LICENSE-MIT](./LICENSE-MIT)
- Apache 2.0: [LICENSE-APACHE](./LICENSE-APACHE)
