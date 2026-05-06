use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use sha2::Sha256;

const KEY_LEN: usize = 32;

pub fn derive_kek(
    master_key: &[u8; KEY_LEN],
    project: &str,
    environment: &str,
    version: u32,
) -> Result<[u8; KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"dotlock:v1:hkdf"), master_key);

    let context = format!("dotlock:v1:kek:project={project}:env={environment}:version={version}");

    let mut kek = [0u8; KEY_LEN];

    hkdf.expand(context.as_bytes(), &mut kek)
        .map_err(|_| anyhow!("failed to derive KEK with HKDF"))?;

    Ok(kek)
}
