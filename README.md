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
[![Sharing](https://img.shields.io/badge/Sharing-RSA--OAEP-00BFA5?style=for-the-badge)](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
[![Status](https://img.shields.io/badge/Status-Alpha-FF9800?style=for-the-badge)](#status)

</div>

---

## Description

DotLock is a local, file-based secrets manager for project environment variables. It stores secrets in a `.lock/` vault next to your code and injects decrypted values only into child processes launched with `dl run`.

Use DotLock when you want:

- to keep `.env` values encrypted in a repository;
- to run local commands with decrypted variables without writing plaintext back to disk;
- to share project secrets with teammates through public keys instead of a shared password;
- to keep a lightweight audit log of unlocks, runs, key ratchets and dynamic provider resolutions.

DotLock is not a hosted production secret manager. For large production systems, prefer a dedicated service such as AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault or your platform's native secret store.

## Status

DotLock is alpha software. The cryptographic building blocks are conservative, but the on-disk format and CLI surface may still change before `1.0`. Keep backups of `.lock/` and review changes before upgrading across `0.1.x` releases.

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
dl init
dl migrate .env
dl run npm start
```

What happens:

1. `dl init` creates `.lock/vault.toml` and `.lock/secrets.lock`.
2. `dl migrate .env` imports variables from an existing `.env` file.
3. `dl run npm start` starts `npm start` with decrypted secrets in the child process environment.

After migration, remove the plaintext `.env` only when you have verified the imported values:

```bash
dl list
dl get DATABASE_URL
rm .env
```

## Core Workflow

### Initialize a project

**What:** `dl init` creates the project vault in the current directory.

**How:**

```bash
dl init
```

You will choose whether DotLock generates a strong master password or lets you type one. The vault metadata goes into `.lock/vault.toml`; encrypted secret records go into `.lock/secrets.lock`.

**When:** Run once per project before using any other project command.

### Add or update a static secret

**What:** `dl set NAME VALUE` stores a secret value under a normalized environment variable name.

**How:**

```bash
dl set DATABASE_URL "postgres://localhost/app_dev"
dl set STRIPE_KEY "sk_live_..."
dl set API_KEY "secret" --alg xcha
```

Aliases:

```bash
dl s DATABASE_URL "postgres://localhost/app_dev"
dl add DATABASE_URL "postgres://localhost/app_dev"
```

Names must use letters, digits and underscores, and cannot start with a digit. DotLock normalizes names to uppercase.

`--alg` (short `-a`) selects the encryption algorithm for static secrets. The current supported value is `xcha`, which maps to XChaCha20-Poly1305.

**When:** Use this when adding a new secret or replacing an existing value.

### Read a secret

**What:** `dl get NAME` decrypts one secret and prints it.

**How:**

```bash
dl get DATABASE_URL
dl get DATABASE_URL | pbcopy
```

When stdout is a terminal, DotLock renders a boxed display with the secret name and short id. When stdout is piped, it prints the raw value.

**When:** Use sparingly for copying or debugging a single value. Prefer `dl run` for normal command execution.

### List secrets

**What:** `dl list` shows stored secret names and short ids without plaintext values.

**How:**

```bash
dl list
dl l
```

**When:** Use before `get`, `unset`, ACL changes or audits to confirm what is stored.

### Remove a secret

**What:** `dl unset NAME` removes a secret and its access wrapping metadata.

**How:**

```bash
dl unset OLD_FEATURE_FLAG
dl rm OLD_FEATURE_FLAG
```

Other aliases: `remove`, `u`, `d`, `del`, `delete`.

**When:** Use when a variable is no longer needed or should no longer be available to `dl run`.

### Run a command with secrets

**What:** `dl run CMD [args...]` decrypts accessible secrets and starts a child process with those values in its environment.

**How:**

```bash
dl run npm start
dl run python manage.py runserver
dl r cargo test
```

The `--` separator is important when the command has its own flags.

**When:** Use this as the normal way to consume secrets locally or in scripts.

### Lock the session

**What:** `dl lock` deletes the cached project key for the current project.

**How:**

```bash
dl lock
dl logout
```

**When:** Use after a sensitive session, before handing off a machine, or at the end of CI/scripted workflows.

## Import and Export `.env` Files

### Import from `.env`

**What:** `dl migrate [PATH]` imports variables from a `.env` file into the encrypted vault.

**How:**

```bash
dl migrate
dl migrate .env.local
dl import .env.production
```

The parser accepts:

- `KEY=VALUE`;
- `export KEY=VALUE`;
- single-quoted values;
- double-quoted values with escapes such as `\n`, `\r`, `\t`, `\\` and `\"`;
- comments and blank lines.

**When:** Use when adopting DotLock in an existing project or bulk-loading variables.

### Export to `.env`

**What:** `dl export [PATH]` writes missing static secrets into a `.env` file.

**How:**

```bash
dl export
dl export .env.local
```

Existing keys are never overwritten. Dynamic secrets are skipped because their values are resolved at runtime.

**When:** Use for tools that still require a `.env` file, or when bridging DotLock with legacy local workflows.

## Team Sharing

DotLock supports shared access through a local RSA identity. The project owner keeps the master password; recipients unlock with their own private key.

### Create a local identity

**What:** `dl cert init` creates a local RSA key pair.

**How:**

```bash
dl cert init
dl cert init --plain
dl cert init --force
```

Aliases:

```bash
dl crt init
dl crt i
```

By default, the private key is passphrase-protected. `--plain` creates an unencrypted private key. `--force` replaces an existing identity.

**When:** Each developer or CI environment should do this once before requesting shared access.

### Show or export the public key

**What:** `dl cert show` prints the local identity fingerprint and paths. `dl cert export-pub [PATH]` prints or writes the public key.

**How:**

```bash
dl cert show
dl cert export-pub alice.pub
dl cert export-pub
```

Aliases: `dl crt sh`, `dl crt x`.

**When:** Use `show` to confirm which identity is active. Use `export-pub` when sending a public key to a vault owner.

### Enable shared mode

**What:** `dl share enable` marks the vault as shared.

**How:**

```bash
dl share enable
dl shr en
```

**When:** Use before granting access to teammates or CI.

### Grant access

**What:** `dl share grant` adds or updates a recipient.

**How:**

```bash
dl share grant --pubkey alice.pub --label alice
dl share grant --pubkey ci.pub --label ci --allow DATABASE_URL,REDIS_URL
```

Aliases: `dl shr gr`.

Without `--allow`, the recipient gets full access. With `--allow`, the recipient can decrypt only the listed secrets.

**When:** Use when onboarding a developer, adding a CI identity, or changing a recipient's access scope.

### Manage a recipient ACL

**What:** `dl share allow` lists, adds or removes per-secret access for a recipient.

**How:**

```bash
dl share allow ci --list
dl share allow ci --add STRIPE_KEY
dl share allow ci --remove REDIS_URL
```

The recipient query can be the recipient id, label or public key fingerprint. Removing a secret from a recipient rotates that secret's SDK so the old recipient wrapping cannot decrypt future values.

**When:** Use for least-privilege access, especially for CI identities.

### List or revoke recipients

**What:** `dl share list` shows recipients. `dl share revoke QUERY` removes a recipient and rotates project access material.

**How:**

```bash
dl share list
dl share revoke alice
```

Aliases: `dl shr l`, `dl shr rev`.

**When:** Use `list` before access reviews. Use `revoke` when someone leaves the project or an identity is compromised.

## Rotation and Ratcheting

### Rotate the master password

**What:** `dl rotate master-password` changes the password used to unlock the project key.

**How:**

```bash
dl rotate master-password
dl rotate mp
```

**When:** Use when a password may have been exposed but the encrypted vault itself does not need a full project-key rotation.

### Rotate key wrapping material

**What:** `dl rotate kek` rotates the project key (DEK) and rewraps secret SDKs and full-access recipient wrappings (historical command name; the KEK itself is always re-derived from the master password).

**How:**

```bash
dl rotate kek
```

**When:** Use as hygiene after many writes, or let DotLock trigger it automatically with `auto_ratchet_after_writes`.

### Rotate the project key

**What:** `dl rotate project-key` generates a new project key (DEK) and rewraps every secret data key under it; secret ciphertexts stay unchanged.

**How:**

```bash
dl rotate project-key
dl rotate pk
```

**When:** Use after a suspected project-key exposure or after major access changes that justify a heavier rotation.

## Dynamic Secret Providers

Dynamic secrets are resolved by external executables instead of storing a fixed plaintext value. Provider binaries must be named `dotlock-provider-NAME` and be available on `PATH`.

### Discover providers

**What:** `dl provider list` lists provider binaries found on `PATH`. `dl provider info NAME` runs a provider's `--describe` command.

**How:**

```bash
dl provider list
dl provider info aws
dl p list
dl p info aws
```

**When:** Use before creating a dynamic secret, or when debugging provider installation.

### Store a dynamic secret

**What:** `dl set NAME --provider PROVIDER` stores encrypted provider metadata instead of a static value.

**How:**

```bash
dl set DATABASE_URL --provider aws --config '{"name":"prod/db/url"}'
dl set API_TOKEN --provider vault --config '{"path":"secret/api"}' --bootstrap VAULT_TOKEN
```

`--config` must be valid JSON. `--bootstrap` is a comma-separated list of existing static secrets that DotLock decrypts and passes to the provider at resolve time.

**When:** Use when the value should be minted or fetched just-in-time from another local provider, while DotLock still controls bootstrap material and runtime injection.

### Provider protocol

Providers are executed as child processes:

- `dotlock-provider-NAME --describe` prints human-readable provider information.
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

DotLock records the provider path and SHA-256 digest when the dynamic secret is created. Later resolutions verify the digest before running the provider. Provider stdout is limited to 64 KiB and stderr to 16 KiB.

## Git Integration

### Install the merge driver

**What:** `dl git install-merge-driver` configures Git to use DotLock's merge driver for `.lock/secrets.lock` and `.lock/vault.toml`.

**How:**

```bash
dl git install-merge-driver
```

`dl init` also attempts to install the merge driver when the project is inside a Git work tree.

**When:** Use in repositories where multiple branches or teammates may edit the vault.

### Sync from remote

**What:** `dl sync` fetches the configured remote and updates the current branch only when Git can fast-forward safely.

**How:**

```bash
dl sync
dl sy
```

`dl sync` uses `auto_fetch_remote` from project config, defaulting to `origin`. It aborts when `.lock/vault.toml` or `.lock/secrets.lock` has local staged, unstaged, or untracked changes, or when the local and remote branches diverged. It never runs a hard reset and never discards local vault data.

**When:** Use before reading, exporting, or rotating secrets when you want to force a remote refresh without enabling auto-fetch for every `dl run`.

### Auto-fetch before run

**What:** when enabled, `dl run` tries a short `git pull --ff-only --no-rebase REMOTE BRANCH` before unlocking.

**How:**

```bash
dl config set auto_fetch_on_run true
dl config set auto_fetch_timeout_secs 3
dl config set auto_fetch_remote origin

DOTLOCK_AUTO_FETCH=0 dl run npm test
```

If pull fails, DotLock tries `git fetch` and then continues with the local vault.

**When:** Use when teams commit `.lock/` changes frequently and want `dl run` to pick up fast-forward updates automatically.

## Audit Log

DotLock keeps a local audit log outside the project by default. Entries are hash-chained. If a local plain identity is available, entries are signed; otherwise they are anonymous.

### Show audit entries

**What:** `dl audit show` prints audit entries.

**How:**

```bash
dl audit show
dl audit show --verbose
dl audit show --since 2026-05-01
dl audit show --action run
```

Aliases: `dl audit s`, `dl a show`.

**When:** Use during local review, debugging or incident response.

### Verify or rotate logs

**What:** `dl audit verify` checks the hash chain and signatures. `dl audit rotate` compresses the current log with `gzip`. `dl audit path` prints the current log path.

**How:**

```bash
dl audit verify
dl audit verify --lax
dl audit path
dl audit rotate
```

Verification is strict by default: anonymous (unsigned) entries and an unsigned high-water mark fail with a non-zero exit code. `--lax` downgrades those to warnings. Each audit write also records a signed high-water mark (entry count plus head hash) next to the log, so deleting the last N entries is detected even though each remaining line still chains correctly. Logs rotate automatically when they reach 10 MiB or are older than 90 days.

**When:** Use `verify` before trusting audit history. Use `rotate` for manual cleanup or archival.

## Configuration

### Project configuration

Project configuration is stored in `.lock/vault.toml`.

```bash
dl config show
dl config set auto_fetch_on_run true
dl config set auto_fetch_timeout_secs 3
dl config set auto_fetch_remote origin
dl config set auto_ratchet_after_writes 50
dl config set dynamic_resolve_timeout_secs 10
dl config unset auto_fetch_remote
```

Aliases: `dl c show`, `dl c set`, `dl c unset`.

| Key | Default | Accepted values | Effect |
|---|---:|---|---|
| `auto_fetch_on_run` | `false` | `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` | Enables Git auto-fetch before `dl run` |
| `auto_fetch_timeout_secs` | `3` | positive integer | Timeout for Git auto-fetch operations |
| `auto_fetch_remote` | `origin` | non-empty string | Remote used by auto-fetch |
| `auto_ratchet_after_writes` | off | non-negative integer | Automatically rotates key wrapping after this many vault writes; `0` disables it |
| `dynamic_resolve_timeout_secs` | `10` | positive integer | Timeout for dynamic provider resolution |

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `DOTLOCK_CACHE_TTL` | `15` | Cached project key lifetime in seconds, capped at 300 |
| `DOTLOCK_CACHE_DIR` | `$HOME/.lock` on Unix, `%LOCALAPPDATA%\dotlock` on Windows | Overrides the session cache root |
| `DOTLOCK_SHARED_CACHE` | off | Set to `1`, `true`, `TRUE`, `yes` or `YES` to enable caching in shared mode |
| `DOTLOCK_IDENTITY_DIR` | `$HOME/.lock/identity` | Overrides local identity storage |
| `DOTLOCK_HOME` | unset | Overrides the per-user state root (`$HOME/.lock` / `%LOCALAPPDATA%\dotlock`); required in environments without `HOME` |
| `DOTLOCK_AUDIT_DIR` | `$HOME/.lock/audit` on Unix, `%LOCALAPPDATA%\dotlock\audit` on Windows | Overrides audit log storage |
| `DOTLOCK_AUTO_FETCH` | unset | Set to `0`, `false`, `no` or `off` to disable auto-fetch for one command |

## Command Reference

| Command | Aliases | Purpose |
|---|---|---|
| `dl init` | `i` | Initialize `.lock/` in the current project |
| `dl set [--alg xcha] NAME VALUE` | `s` | Store or update a static secret |
| `dl set NAME --provider PROVIDER [--config JSON] [--bootstrap A,B]` | `s` | Store a dynamic secret definition |
| `dl get NAME` | `g` | Print a secret value |
| `dl unset NAME` | `u` | Remove a secret |
| `dl list` | `l` | List stored secrets without plaintext |
| `dl run CMD [args...]` | `r` | Run a command with decrypted secrets in its environment |
| `dl lock` | `k` | Drop the cached project key |
| `dl migrate [PATH]` | `m` | Import variables from `.env` |
| `dl export [PATH]` | `x` | Append missing static secrets to `.env` |
| `dl sync` | `sy` | Fast-forward from the configured Git remote when safe |
| `dl cert init [--force] [--plain]` | `crt init`, `crt i` | Create a local RSA identity |
| `dl cert show` | `crt show`, `crt sh` | Show local identity information |
| `dl cert export-pub [PATH]` | `crt export-pub`, `crt x` | Print or write the public key |
| `dl share enable` | `shr enable`, `shr en` | Enable shared mode |
| `dl share grant --pubkey FILE --label LABEL [--allow A,B]` | `shr grant`, `shr gr` | Grant recipient access |
| `dl share allow QUERY --list` | `shr allow`, `shr al` | List recipient ACL |
| `dl share allow QUERY --add A,B` | `shr allow`, `shr al` | Add secrets to recipient ACL |
| `dl share allow QUERY --remove A,B` | `shr allow`, `shr al` | Remove secrets from recipient ACL and rotate affected SDKs |
| `dl share revoke QUERY` | `shr revoke`, `shr rev` | Revoke a recipient |
| `dl share list` | `shr list`, `shr l` | List recipients |
| `dl rotate kek` | `rot kek`, `rot k` | Rotate key wrapping material |
| `dl rotate master-password` | `rot master-password`, `rot mp` | Change master password |
| `dl rotate project-key` | `rot project-key`, `rot pk` | Rotate project key |
| `dl audit show [--verbose] [--since YYYY-MM-DD] [--action ACTION]` | `a show`, `audit s` | Show audit entries |
| `dl audit verify [--lax]` | `a verify`, `audit v` | Verify audit log (strict by default) |
| `dl audit path` | `a path`, `audit p` | Print audit log path |
| `dl audit rotate` | `a rotate`, `audit r` | Rotate and gzip current audit log |
| `dl git install-merge-driver` | `gt install-merge-driver`, `gt i` | Configure Git merge support |
| `dl config show` | `c show`, `config sh` | Show project config |
| `dl config set KEY VALUE` | `c set`, `config s` | Set project config |
| `dl config unset KEY` | `c unset`, `config u` | Reset project config |
| `dl provider list` | `p list`, `provider l` | List provider binaries on `PATH` |
| `dl provider info NAME` | `p info`, `provider i` | Show provider description |

Compatibility aliases such as `add`, `rm`, `remove`, `del`, `delete`, `logout`, and `import` remain available, but the table above is the canonical long/short command set.

## How It Works

### Files on disk

Project vault:

```text
.lock/
├── vault.toml
└── secrets.lock
```

Local user state:

```text
~/.lock/
├── identity/
│   ├── identity.pem
│   ├── identity.pub.pem
│   └── identity.toml
├── run/
│   ├── session.key
│   └── sessions/<project>/
│       └── sessions.toml
└── audit/<project-uuid>/
    ├── audit.log
    └── hwm.toml
```

DotLock refuses to fall back to the current directory for any of this state. When neither `HOME` (or `%LOCALAPPDATA%` on Windows) nor `DOTLOCK_HOME` resolves — cron jobs, containers, systemd units without a login environment — commands that would write identities, cached keys or audit logs fail with a clear error instead of dropping key material into a committable `./.lock`.

On Unix, private directories are created with `0700`, secret/private files with `0600`, and public key files with `0644`. Writes use an atomic temp-file-and-rename flow.

### Secret metadata

New `secrets.lock` records store the secret `id`, variable `name`, ciphertext `data`, update timestamp, and kind. They do not store the data encryption algorithm next to the variable name. DotLock uses the storage-version cipher policy, currently XChaCha20-Poly1305, and still reads older records that contain `alg = "xchacha20-poly1305"`.

Keeping the algorithm out of each visible secret record removes a per-secret cryptographic hint from the Git-tracked vault. An attacker who obtains `.lock/` can still see variable names and ciphertexts, but cannot use a name-to-algorithm pairing to classify records, prioritize guesses, or tune offline brute-force workflows per secret. Algorithm agility remains a vault/storage-version concern rather than secret metadata.

### Key hierarchy

```text
master password
  -> Argon2id derives master key
    -> HKDF derives KEK
      -> KEK wraps project key
        -> project key wraps per-secret SDKs
          -> SDK encrypts each secret value or dynamic provider metadata
```

Terms:

- Master password: typed or generated during `dl init`.
- Master key: derived from the password and salt; held briefly and zeroized.
- KEK: key-encryption key derived for wrapping the project key.
- Project key: random 32-byte key stored only in wrapped form.
- SDK: per-secret data key used to encrypt one secret's stored data.

This is why changing a master password is fast, while project-key and ACL rotations touch more vault metadata.

### Integrity

Every write to `secrets.lock` updates an authenticated hash in `vault.toml`. On unlock, DotLock verifies the hash before decrypting secrets. If `secrets.lock` was modified outside DotLock, the command aborts with a tamper error.

### Session cache

After successful unlock, DotLock may cache the project key for a short time so consecutive commands do not re-prompt. The default TTL is 15 seconds (`DOTLOCK_CACHE_TTL`, capped at 300). Shared mode disables caching unless `DOTLOCK_SHARED_CACHE` is enabled.

The cached key is never stored raw: it is encrypted (XChaCha20-Poly1305) under a key derived from a separate per-user random key file (`~/.lock/run/session.key`, mode `0600`), with the expiry timestamp bound as authenticated data. Expired or tampered entries are overwritten with zeros and deleted as soon as they are seen, and `dl lock` shreds them on demand.

**Residual threat model:** both the wrapped session file and the wrapping key file live on the same filesystem with `0600` permissions. A process running as the same user (or root) within the TTL window can read both files and recover the project key; the wrapping defeats casual single-file exposure (backups or snapshots of `sessions.toml` alone, log shippers), not a same-uid attacker. Filesystem snapshots, swap and copy-on-write storage may also defeat the best-effort shredding. Moving the cache into the OS keyring or a memory-only agent is a planned follow-up; until then, set `DOTLOCK_CACHE_TTL=0` or run `dl lock` after sensitive sessions on multi-tenant machines.

### Shared mode and ACLs

Full-access recipients receive wrapped access to the project key and per-secret SDKs. Limited recipients receive only wrapped SDKs for allowed secrets. Removing a secret from a recipient ACL rotates the affected SDKs.

## Security Notes

- `dl get` prints plaintext. Prefer `dl run` when a command can consume secrets directly.
- Do not commit plaintext `.env` files after migrating to DotLock.
- Commit `.lock/vault.toml` and `.lock/secrets.lock` if your team shares the encrypted vault through Git.
- Use `dl sync` to refresh the vault safely from Git. It aborts on local vault changes or branch divergence instead of discarding data.
- Keep local identity private keys protected. Use `dl cert init --plain` only for controlled automation or ephemeral environments.
- Dynamic providers are executable code. Install them from trusted sources. DotLock refuses provider directories/binaries that are group- or world-writable or owned by another non-root user, and warns loudly when a dynamic secret's provider is not sha256-pinned — re-run `dl set <NAME> --provider <name>` to pin it.
- Prefer `dl set NAME` (hidden prompt) or `dl set NAME --stdin` over `dl set NAME value`: a value passed as an argument is visible in `ps`, `/proc/<pid>/cmdline`, and shell history.
- Audit logs are local by default. They are useful for local accountability and debugging, not a centralized compliance system.

### Windows

File-permission hardening (0600 key/vault files, 0700 private directories, `O_NOFOLLOW` symlink-safe opens) is implemented for Unix only. On Windows, files created by DotLock inherit the parent directory's default ACLs and symlink checks fall back to a check-then-open pattern; restrictive owner-only DACLs are not yet applied. Until that lands, treat the profile directory (`%USERPROFILE%\.dotlock`) and project `.lock/` directories as protected only by your account's default ACLs, and avoid shared/multi-user Windows machines for sensitive vaults.

## License

Dual-licensed under your choice of:

- MIT: [LICENSE-MIT](./LICENSE-MIT)
- Apache 2.0: [LICENSE-APACHE](./LICENSE-APACHE)
