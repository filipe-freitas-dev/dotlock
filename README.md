<div align="center">

```
    ██████╗   ██████╗  ████████╗ ██╗       ██████╗   ██████╗ ██╗  ██╗
    ██╔══██╗ ██╔═══██╗ ╚══██╔══╝ ██║      ██╔═══██╗ ██╔════╝ ██║ ██╔╝
    ██║  ██║ ██║   ██║    ██║    ██║      ██║   ██║ ██║      █████╔╝
    ██║  ██║ ██║   ██║    ██║    ██║      ██║   ██║ ██║      ██╔═██╗
    ██████╔╝ ╚██████╔╝    ██║    ███████╗ ╚██████╔╝ ╚██████╗ ██║  ██╗
    ╚═════╝   ╚═════╝     ╚═╝    ╚══════╝  ╚═════╝   ╚═════╝ ╚═╝  ╚═╝
```

### **Encrypt your `.env`. Share by key, not by password.**

[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Cipher](https://img.shields.io/badge/Cipher-XChaCha20--Poly1305-FF1744?style=for-the-badge)](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-7C4DFF?style=for-the-badge)](https://en.wikipedia.org/wiki/Argon2)
[![Sharing](https://img.shields.io/badge/Sharing-RSA--OAEP-00BFA5?style=for-the-badge)](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-2962FF?style=for-the-badge&logo=linux&logoColor=white)](#)
[![Status](https://img.shields.io/badge/Status-Alpha-FF9800?style=for-the-badge)](#)

</div>

---

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
- **Run with secrets** (`dotlock run <cmd>`): decrypts in memory and spawns the child process with the variables injected as environment.
- **Rotation primitives**: rotate the master password or generate a brand‑new project key (re‑encrypting every secret).
- **`.env` import** (`dotlock migrate`): bulk‑import an existing `.env` file in one step.
- **Integrity check**: the vault metadata stores an authenticated hash of the secrets file so tampering is detected on unlock.
- **Defensive memory handling**: keys and passwords are wiped with `zeroize` after use.

---

## Installation

The crate is `dotlock-bin` (the name `dotlock` was already taken on crates.io by an unrelated lockfile crate). The installed binary is named **`dl`** — short and quick to type.

### From crates.io

```bash
cargo install dotlock-bin
# binary `dl` will be at ~/.cargo/bin/dl
```

### From source

Rust edition 2024 toolchain required:

```bash
cargo build --release
# binary will be at ./target/release/dl
```

Drop the binary somewhere on your `PATH`, e.g.:

```bash
install -m 0755 target/release/dl ~/.local/bin/dl
```

---

## Usage examples

### 1. Solo developer — replace your `.env`

```bash
cd ~/code/my-app

# Initialize the vault (prompts for a master password, or generates one for you)
dl init 

# Pull in everything from your existing .env in one shot
dl migrate .env

# Verify what's stored — names only, never plaintext
dl list

# (optional) once you trust the vault, delete the plaintext .env
rm .env
```

Now run your app with the secrets injected only into the child process:

```bash
dl run npm start
dl run python manage.py runserver
dl run cargo test
```

Need to add or update one variable on the fly:

```bash
dl set STRIPE_KEY "sk_live_..."
dl set DATABASE_URL "postgres://localhost/app_dev"
dl unset OLD_FEATURE_FLAG
```

### 2. Daily workflow with the session cache

The first command of the day prompts for the master password. Subsequent commands within **30 seconds** (default TTL) reuse the cached key — `sudo`‑style:

```bash
dl set API_KEY "abc"        # ← prompts for master password
dl set ANOTHER_KEY "xyz"    # ← no prompt, uses cached key
dl run npm test          # ← still no prompt

# Done for the day — drop the cached key:
dl lock
```

Want the cache to last longer? Bump the TTL in your shell rc:

```bash
export DOTLOCK_CACHE_TTL=900   # 15 minutes
```

### 3. Team workflow — shared access by public key

Every developer keeps a personal RSA identity once, then projects grant access to their public key.

**One‑time, on each developer's machine:**

```bash
dl cert init                   # creates ~/.lock/identity/{identity.pem,identity.pub.pem}
dl cert show                   # show fingerprint + paths
dl cert export-pub alice.pub   # share this file with the project owner
```

**On the project (the owner does this once per teammate):**

```bash
dl share enable                                    # switch the project to shared mode
dl share grant --pubkey alice.pub --label alice    # wrap the project key for Alice
dl share grant --pubkey bob.pub   --label bob
dl share list                                      # who has access?
```

Commit `.lock/vault.toml` and `.lock/secrets.lock` to your repo. From now on, **anyone listed as a recipient can unlock the project with their identity passphrase** — no shared master password ever leaves a developer's laptop.

When someone leaves the team:

```bash
dl share revoke alice
# DotLock automatically:
#   1. removes Alice from the recipients list
#   2. generates a new project DEK
#   3. re-encrypts every secret with the new DEK
#   4. re-wraps the new DEK for the remaining recipients
```

### 4. Rotating credentials

```bash
# Change the master password (keeps existing secrets, only re-wraps the DEK):
dl rotate master-password

# Roll the project key (re-encrypts every secret — do this if you suspect leakage):
dl rotate project-key
```

### 5. CI / scripted use

For non‑interactive contexts, the typical pattern is to export `DOTLOCK_CACHE_TTL` to something workflow‑sized, unlock once, then run several commands:

```bash
export DOTLOCK_CACHE_TTL=600
dl list > /dev/null            # primes the session cache
dl run ./scripts/migrate.sh
dl run ./scripts/seed.sh
dl run npm test
dl lock                        # explicit cleanup at the end
```

---

## Command reference

All commands accept short aliases — for example `dl s` is `set`, `dl g` is `get`, `dl l` is `list`, `dl rm` / `dl del` is `unset`.

### Project lifecycle

| Command | Purpose |
|---|---|
| `dl init` | Initialize the current directory as a DotLock project. Prompts for a master password (or generates a strong one), creates `.lock/vault.toml` and `.lock/secrets.lock`. |
| `dl lock` (alias `logout`) | Invalidate the cached DEK so the next operation re‑prompts for the master password. |

### Secrets

| Command | Purpose |
|---|---|
| `dl set <NAME> <VALUE>` | Store or overwrite a variable. Default algorithm is `xchacha20-poly1305`. |
| `dl get <NAME>` | Show the metadata of a variable. The plaintext is **not** printed by default — use `dl run` to consume it. |
| `dl unset <NAME>` | Remove a variable. |
| `dl list` | List variable names (no plaintext). |
| `dl migrate [path]` | Import every variable from a `.env` file (defaults to `./.env`) in a single transaction. |
| `dl run <cmd> [args...]` | Decrypt every secret in memory and spawn `<cmd>` with them as environment variables. |

### Local identity (for shared mode)

| Command | Purpose |
|---|---|
| `dl cert init [--force]` | Generate a passphrase‑encrypted RSA key pair under `~/.lock/identity/`. |
| `dl cert show` | Print the fingerprint and key paths of the local identity. |
| `dl cert export-pub [path]` | Print the local public key, or write it to `path` so it can be shared. |

### Shared project access

| Command | Purpose |
|---|---|
| `dl share enable` | Switch the project from master‑password mode to shared mode. |
| `dl share grant --pubkey <PATH> --label <NAME>` | Wrap the project DEK for the given public key and add it as a recipient. |
| `dl share revoke <ID\|LABEL\|FINGERPRINT>` | Remove a recipient and **rotate** the project key, re‑encrypting every secret and re‑wrapping for the remaining recipients. |
| `dl share list` | Show every recipient with label and fingerprint. |

### Rotation

| Command | Purpose |
|---|---|
| `dl rotate master-password` | Change the master password without re‑encrypting secrets — only the wrapping of the DEK changes. |
| `dl rotate project-key` | Generate a brand‑new project DEK and re‑encrypt every secret. Recipients are re‑wrapped automatically. |

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
- `dl lock` deletes the cache file immediately.

### Shared mode

When you run `dl share enable` and grant access to one or more public keys, the vault metadata gains a `recipients` table. Each recipient stores its label, fingerprint, and the project DEK wrapped with that recipient's RSA public key (RSA‑OAEP). A user that holds the matching private key (managed via `dl cert`) can unlock the project without ever knowing the master password.

Revocation is destructive on purpose: `dl share revoke` removes the recipient, generates a new DEK, re‑encrypts every secret with it, and re‑wraps the new DEK for every remaining recipient. The revoked party cannot decrypt anything written after the revocation, even if they kept a copy of the old vault.

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
- `dl get` deliberately does **not** print the plaintext value — use `dl run` to consume secrets, so values stay out of shell history and terminal scrollback.

---

## License

Dual‑licensed under either:

- **MIT** license ([LICENSE-MIT](./LICENSE-MIT) or <https://opensource.org/licenses/MIT>)
- **Apache License, Version 2.0** ([LICENSE-APACHE](./LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)

at your option.
