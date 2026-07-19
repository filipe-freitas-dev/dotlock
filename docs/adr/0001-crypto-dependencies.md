# ADR 0001 — Crypto dependency advisories: keep RSA (for now), plan the X25519 migration

- **Status:** accepted — **superseded in part**: the X25519/Ed25519 migration
  planned below has SHIPPED (see the addendum at the end). RSA remains only
  as a legacy-interop read path.
- **Date:** 2026-07-18 (addendum 2026-07-19)
- **Context:** Phase 5 dependency hygiene (REVIEW.md "Dependências", ROADMAP Fase 5)

## Context

`cargo audit` / `cargo deny` report the following against DotLock's dependency
tree. This ADR records why each one is accepted (with mitigation) instead of
fixed immediately, so CI can stay green while the risk remains tracked.

### 1. `rsa` 0.9.x — RUSTSEC-2023-0071 "Marvin" timing side-channel (CVSS 5.9, no upstream fix)

**Where it is used.** RSA-3072 is DotLock's *identity* algorithm for shared
vaults only:

- `unwrap_dek_with_private_key` — OAEP-SHA256 **decryption** of the project
  key (DEK) wrapped to a recipient's public key (`dl share grant` /
  recipient unlock);
- RSA-PSS signatures over recipient grants and audit-log entries.

The vulnerable primitive is the private-key decryption path (OAEP unwrap):
the Marvin attack recovers plaintext by measuring many decryption timings of
attacker-chosen ciphertexts.

**Residual risk assessment.** Accepted as LOW for DotLock's threat model:

- Decryption runs in a short-lived local CLI process, never in a network
  service. There is no remote timing oracle: an attacker cannot submit
  ciphertexts and time responses at scale.
- A local attacker with the same uid can already read the session key cache
  and the identity file — timing attacks would be the hard way in.
- The number of decryptions is tiny (one unwrap per unlock), far below the
  millions of samples Marvin-class attacks require.

**Decision.** Keep `rsa` 0.9.x, acknowledge RUSTSEC-2023-0071 explicitly in
`deny.toml` (so *new* advisories still fail CI) and pass
`--ignore RUSTSEC-2023-0071` to `cargo audit` in CI.

**Planned exit.** Migrate identity key-wrapping to X25519 (age-style, e.g.
`crypto_box`: X25519 + XSalsa20/XChaCha20-Poly1305), eliminating RSA and the
advisory entirely, plus smaller/faster keys. This is intentionally NOT part of
Phase 5: existing vaults hold RSA-wrapped DEKs and RSA-signed grants, so the
migration is a compatibility-breaking milestone of its own requiring a
double-write period (new grants wrapped to both key types until every
recipient re-keys), fingerprint/format versioning, and a re-grant flow.
Revisit this ADR when that milestone starts.

### 2. `fxhash` (transitive, via `inquire`) — unmaintained (RUSTSEC-2025-0057)

Pulled in transitively (not a direct dependency). Unmaintained ≠ vulnerable;
no advisory beyond maintenance status, and it cannot be replaced without
forking `inquire`. **Decision:** monitor. `deny.toml` sets
`unmaintained = "workspace"` so transitive unmaintained crates warn while a
DIRECT unmaintained dependency still fails CI; replace the parent dependency
if a real vulnerability ever lands.

### 3. `spin` 0.9.8 (transitive) — yanked release

A transitive dependency pins a release that was later yanked from crates.io.
Yanked ≠ vulnerable; the pinned build still resolves via `Cargo.lock`.
**Decision:** monitor; `deny.toml` sets `yanked = "warn"` (not `deny`) until
the parent crates move off it, at which point flip it to `deny`.

### 4. `anyhow` — RUSTSEC-2026-0190 (`downcast_mut` unsound)

`anyhow` was removed as a *direct* dependency in Phase 2 (A4); it remained in
the tree transitively. Bumped past the advisory via `cargo update -p anyhow`
(1.0.102 → 1.0.104). No decision needed; recorded for completeness.

## Consequences

- CI (`.github/workflows/ci.yml`) runs `cargo audit --ignore RUSTSEC-2023-0071`
  and `cargo deny check advisories licenses`: the *known, documented* risk is
  accepted; any **new** advisory fails the build.
- The RSA→X25519 migration is deferred to its own milestone with double-write
  compatibility; until then, share-mode identity operations keep using
  RSA-3072 OAEP/PSS (never PKCS#1 v1.5).

## Addendum (2026-07-19) — the X25519/Ed25519 migration shipped

The "planned exit" above is implemented. The identity subsystem now uses:

- **Identities:** Ed25519 (`ed25519-dalek`), PKCS#8 PEM on disk (optionally
  scrypt-encrypted PKCS#8, same as before). `dl cert init` only generates
  Ed25519; identity.toml carries `alg = "ed25519"` (missing `alg` ⇒ legacy
  RSA, so old files keep parsing).
- **Signatures** (recipient grants H3, audit entries + high-water mark H4):
  Ed25519. RSA-PSS signatures on EXISTING vaults/logs still verify.
- **Key wrapping** (project DEK / per-secret SDKs to a recipient): X25519
  sealed box (`crypto_box`, libsodium-compatible `seal`), recipient alg tag
  `x25519-sealedbox`. The recipient's X25519 key is derived from their
  Ed25519 key via the standard Edwards→Montgomery map — the construction
  libsodium (`crypto_sign_ed25519_*_to_curve25519`) and age's ssh-ed25519
  recipients use, with joint Ed25519+X25519-KEM security proven in
  <https://eprint.iacr.org/2021/509>.
- **Dispatch:** every wrap/unwrap/sign/verify entry point dispatches on the
  key material's algorithm OID, so vaults with MIXED recipients (some RSA,
  some X25519) work throughout a team's transition window. Rewrapping a
  rotation for a still-RSA recipient uses RSA **encryption** only (a
  public-key operation, not Marvin-affected).
- **Migration:** `dl cert migrate` — generates the Ed25519 identity, archives
  the RSA key as `identity.legacy.*` (kept for not-yet-migrated projects and
  for verifying old audit signatures), then per project performs ONE final
  RSA unwrap of the DEK, rewraps it as a sealed box, re-signs the user's
  grant under Ed25519, reseals the metadata MAC (M2) and bumps the epoch
  (M3), committed transactionally. Vault `version` ≥ 8 marks x25519
  recipients. Limited (per-secret) recipients cannot rekey their own entry —
  they get re-granted by an owner (`dl cert export-pub` + `dl share grant`).

**Why `rsa` is still in the tree.** Reading is forever: existing vaults hold
RSA-wrapped DEKs, RSA-signed grants and RSA-signed audit entries, and the
migration itself needs one final RSA decryption per project. The crate is now
reachable ONLY from that legacy/migration path — no fresh `dl init` +
`dl cert init` setup ever executes RSA code. RUSTSEC-2023-0071 therefore
stays acknowledged in `deny.toml`/CI, with this reduced scope recorded there.
Remove `rsa` (and the ignore) once legacy-identity support is dropped in a
future major release.
