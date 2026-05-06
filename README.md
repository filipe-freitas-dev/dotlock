# DotLock

DotLock is a small Rust CLI that encrypts a project's environment variables and lets you run commands with the decrypted values injected into the process environment — without ever writing plaintext secrets to disk.

It is designed to replace ad‑hoc `.env` files for local development and small teams: secrets stay encrypted at rest, are decrypted only in memory, and can be shared between developers using public‑key cryptography instead of shipping a shared password around.

---

## Features

- **Per‑project encrypted vault** stored under `.lock/` next to your code.
- **XChaCha20‑Poly1305** authenticated encryption for individual secrets.
- **Argon2id** key derivation from the master password, with HKDF on top to derive a key‑encryption key.
- **DEK / KEK split**: a random 32‑byte Data Encryption Key (DEK) encrypts the secrets, and is itself wrapped by a Key Encryption Key (KEK) derived from your password — so rotating the password does not re‑encrypt every secret.
- **Short‑lived session cache** (`sudo`‑style): after the first unlock the DEK is cached for 30 seconds in your user directory, so you don't retype the master password on every command.
- **Shared access mode** (`dotlock share`): each recipient gets the DEK wrapped with their own RSA public key, so a project can be unlocked by any authorized identity without a shared password.
- **Local identity** (`dotlock cert`): generates a passphrase‑protected RSA key pair under `~/.lock/identity/` for use as a recipient.
- **Run with secrets** (`dotlock run -- <cmd>`): decrypts in memory and spawns the child process with the variables injected as environment.
- **Rotation primitives**: rotate the master password or generate a brand‑new project key (re‑encrypting every secret).
- **`.env` import** (`dotlock migrate`): bulk‑import an existing `.env` file in one step.
- **Integrity check**: the vault metadata stores an authenticated hash of the secrets file so tampering is detected on unlock.
- **Defensive memory handling**: keys and passwords are wiped with `zeroize` after use.

---

## Installation

Build from source with Cargo (Rust edition 2024 toolchain required):

```bash
cargo build --release
# binary will be at ./target/release/dotlock
```

Drop the binary somewhere on your `PATH`, e.g.:

```bash
install -m 0755 target/release/dotlock ~/.local/bin/dotlock
```

---

## Quick start

```bash
# 1. Initialize a project — creates .lock/vault.toml and .lock/secrets.lock
dotlock init

# 2. Add a few secrets
dotlock set DATABASE_URL "postgres://localhost/app"
dotlock set API_KEY     "sk_live_..."

# 3. List what's stored (names only — never plaintext)
dotlock list

# 4. Run a command with the secrets injected into its environment
dotlock run -- node server.js

# 5. Drop the cached master password (sudo-style logout)
dotlock lock
```

---

## Command reference

All commands accept short aliases — for example `dotlock s` is `set`, `dotlock g` is `get`, `dotlock l` is `list`, `dotlock rm` / `dotlock del` is `unset`.

### Project lifecycle

| Command | Purpose |
|---|---|
| `dotlock init` | Initialize the current directory as a DotLock project. Prompts for a master password (or generates a strong one), creates `.lock/vault.toml` and `.lock/secrets.lock`. |
| `dotlock lock` (alias `logout`) | Invalidate the cached DEK so the next operation re‑prompts for the master password. |

### Secrets

| Command | Purpose |
|---|---|
| `dotlock set <NAME> <VALUE>` | Store or overwrite a variable. Default algorithm is `xchacha20-poly1305`. |
| `dotlock get <NAME>` | Show the metadata of a variable. The plaintext is **not** printed by default — use `dotlock run` to consume it. |
| `dotlock unset <NAME>` | Remove a variable. |
| `dotlock list` | List variable names (no plaintext). |
| `dotlock migrate [path]` | Import every variable from a `.env` file (defaults to `./.env`) in a single transaction. |
| `dotlock run -- <cmd> [args...]` | Decrypt every secret in memory and spawn `<cmd>` with them as environment variables. |

### Local identity (for shared mode)

| Command | Purpose |
|---|---|
| `dotlock cert init [--force]` | Generate a passphrase‑encrypted RSA key pair under `~/.lock/identity/`. |
| `dotlock cert show` | Print the fingerprint and key paths of the local identity. |
| `dotlock cert export-pub [path]` | Print the local public key, or write it to `path` so it can be shared. |

### Shared project access

| Command | Purpose |
|---|---|
| `dotlock share enable` | Switch the project from master‑password mode to shared mode. |
| `dotlock share grant --pubkey <PATH> --label <NAME>` | Wrap the project DEK for the given public key and add it as a recipient. |
| `dotlock share revoke <ID|LABEL|FINGERPRINT>` | Remove a recipient and **rotate** the project key, re‑encrypting every secret and re‑wrapping for the remaining recipients. |
| `dotlock share list` | Show every recipient with label and fingerprint. |

### Rotation

| Command | Purpose |
|---|---|
| `dotlock rotate master-password` | Change the master password without re‑encrypting secrets — only the wrapping of the DEK changes. |
| `dotlock rotate project-key` | Generate a brand‑new project DEK and re‑encrypt every secret. Recipients are re‑wrapped automatically. |

---

## How it works

### Files on disk

```
<project>/
└── .lock/
    ├── vault.toml      # public metadata: KDF params, salt, wrapped DEK, recipients, integrity hash
    └── secrets.lock    # encrypted secret records (one per variable)

~/.lock/
├── identity/           # local RSA key pair (passphrase-encrypted)
│   ├── identity.pem
│   ├── identity.pub.pem
│   └── identity.toml
└── run/sessions/<project-uuid-prefix>/
    └── sessions.toml   # short-lived cached DEK (default 30s TTL)
```

The `.lock/` directory is created with `0700` permissions; secret and key files use `0600`.

### Key hierarchy

```
master password
  └── Argon2id (salt, m=64MiB, t=3, p=1) ──► master_key (32 B)
        └── HKDF-SHA256 (project, environment, kek_version) ──► KEK (32 B)
              └── XChaCha20-Poly1305 wrap ──► DEK (32 B, random)
                    └── XChaCha20-Poly1305 ──► each secret value
```

- The **master password** never leaves the prompt — only the derived key material is kept (and zeroized as soon as it's consumed).
- The **DEK** is what actually encrypts secrets. It is generated once at `init` and only ever changes during `rotate project-key` or `share revoke`.
- The **KEK** is ephemeral: it is re‑derived from the master password on every unlock and discarded.
- Rotating the master password therefore only rewraps the DEK; rotating the project key re‑encrypts every secret in `secrets.lock`.

### Integrity

Every time the secrets file is written, the vault metadata stores a fresh nonce and authenticated hash of its contents (encrypted under the DEK). On unlock, this is verified — if `secrets.lock` was edited or replaced out‑of‑band, the operation aborts.

### Session cache

After the first successful unlock, the DEK is base64‑encoded and written to `~/.lock/run/sessions/<short-uuid>/sessions.toml` with an expiry timestamp. Subsequent commands within the TTL skip the password prompt entirely.

- Default TTL is **30 seconds**. Override with the `DOTLOCK_CACHE_TTL` environment variable (in seconds).
- The cache is **per project**, keyed by the project's UUID stored in `vault.toml`.
- In shared mode the cache is **disabled by default** — set `DOTLOCK_SHARED_CACHE=1` to opt in.
- `dotlock lock` deletes the cache file immediately.

### Shared mode

When you run `dotlock share enable` and grant access to one or more public keys, the vault metadata gains a `recipients` table. Each recipient stores its label, fingerprint, and the project DEK wrapped with that recipient's RSA public key (RSA‑OAEP). A user that holds the matching private key (managed via `dotlock cert`) can unlock the project without ever knowing the master password.

Revocation is destructive on purpose: `dotlock share revoke` removes the recipient, generates a new DEK, re‑encrypts every secret with it, and re‑wraps the new DEK for every remaining recipient. The revoked party cannot decrypt anything written after the revocation, even if they kept a copy of the old vault.

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DOTLOCK_CACHE_TTL` | `30` | Lifetime in seconds of the cached DEK. |
| `DOTLOCK_CACHE_DIR` | `$HOME/.lock` | Override the root for the session cache. |
| `DOTLOCK_SHARED_CACHE` | `false` | Set to `1`/`true` to enable session caching while in shared mode. |
| `DOTLOCK_IDENTITY_DIR` | `$HOME/.lock/identity` | Override where the local RSA identity is stored. |

---

## Project layout

```
src/
├── main.rs              # CLI surface (clap)
├── runtime/             # encrypt / decrypt / `run` orchestration
├── crypto/              # KDF, KEK, DEK, integrity hash, RSA share, password generator
├── storage/             # vault file, secrets file, identity, cache, .env parser, atomic FS helpers
├── domain/              # error types and shared model definitions
└── utils.rs             # small helpers (variable name normalization, pretty printing)
```

---

## Security notes

- Master passwords are validated for length and character mix, or you can let DotLock generate a 32‑character random one (printed once, never stored).
- All secret files are written **atomically** with restricted permissions (`0600`).
- Sensitive byte buffers are wrapped in `Zeroizing<…>` and explicitly zeroed when no longer needed.
- The local identity's private key is stored encrypted under a separate passphrase, distinct from any project's master password.
- `dotlock get` deliberately does **not** print the plaintext value — use `dotlock run` to consume secrets, so values stay out of shell history and terminal scrollback.

---

## License

See repository for license information.
