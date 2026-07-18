use hkdf::Hkdf;
use sha2::Sha256;

use crate::domain::{error::DotLockError, model::DotLockResult};

const KEY_LEN: usize = 32;

pub fn derive_kek(
    master_key: &[u8; KEY_LEN],
    project: &str,
    environment: &str,
    version: u32,
) -> DotLockResult<[u8; KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"dotlock:v1:hkdf"), master_key);

    let context = format!("dotlock:v1:kek:project={project}:env={environment}:version={version}");

    let mut kek = [0u8; KEY_LEN];

    hkdf.expand(context.as_bytes(), &mut kek)
        .map_err(|_| DotLockError::Crypto("failed to derive KEK with HKDF".to_string()))?;

    Ok(kek)
}
