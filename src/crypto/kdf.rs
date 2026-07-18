use argon2::{Algorithm, Argon2, Params, Version};

use crate::domain::{error::DotLockError, model::DotLockResult};

const MASTER_KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

pub fn generate_salt() -> DotLockResult<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate salt: {e}")))?;
    Ok(salt)
}

pub fn derive_master_key(
    passphrase: &str,
    salt: &[u8],
    params: KdfParams,
) -> DotLockResult<[u8; MASTER_KEY_LEN]> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(MASTER_KEY_LEN),
    )
    .map_err(|e| DotLockError::Crypto(format!("invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut master_key = [0u8; MASTER_KEY_LEN];

    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut master_key)
        .map_err(|e| {
            DotLockError::Crypto(format!("failed to derive master key with Argon2id: {e}"))
        })?;

    Ok(master_key)
}
