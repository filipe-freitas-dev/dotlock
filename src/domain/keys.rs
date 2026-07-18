//! Newtypes for the two kinds of 32-byte symmetric key material (A7).
//!
//! The vault's envelope model has exactly two symmetric key roles that used to
//! travel as indistinguishable raw `[u8; 32]` values:
//!
//! - [`ProjectKey`] — the per-project DEK. Unwrapped on unlock (from the
//!   master-password KEK or a recipient's `wrapped_dek_b64`), it protects the
//!   per-secret SDK wrappings and the encrypted integrity hash. It never
//!   encrypts secret values directly on v5+ vaults.
//! - [`SecretKey`] — a per-secret data key (SDK). Minted per record, it is the
//!   only key that encrypts/decrypts a secret's value, and it is stored
//!   wrapped under the [`ProjectKey`] (and per-recipient public keys).
//!
//! Handing a DEK where an SDK is expected (or vice versa) was the root cause
//! of K1; with these newtypes that mixup is a compile error. Both types keep
//! their bytes inside [`Zeroizing`], so key material is wiped on drop exactly
//! as before.

use zeroize::Zeroizing;

/// The project key (DEK). See the module docs for its exact role.
#[derive(Clone)]
pub struct ProjectKey(Zeroizing<[u8; 32]>);

impl ProjectKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The all-zero placeholder handed to read-only (limited-identity)
    /// unlocks. It can never act as a real project key: every write and
    /// integrity-hash path rejects it explicitly.
    pub fn read_only_placeholder() -> Self {
        Self::new([0u8; 32])
    }

    /// True for the read-only placeholder; used by the integrity writers to
    /// refuse signing the vault with a key that no full-access user holds.
    pub fn is_read_only_placeholder(&self) -> bool {
        *self.0 == [0u8; 32]
    }
}

impl std::fmt::Debug for ProjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProjectKey(<redacted>)")
    }
}

/// A per-secret data key (SDK). See the module docs for its exact role.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Legacy bridge for pre-v5 vaults, where secret values were encrypted
    /// directly under the project key (no per-secret SDK existed). This is
    /// the ONLY sanctioned DEK-as-SDK conversion; every call site is a
    /// documented legacy/migration path.
    pub fn from_legacy_project_key(project_key: &ProjectKey) -> Self {
        Self::new(*project_key.as_bytes())
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}
