use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub struct WrappedDek {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn generate_dek() -> DotLockResult<ProjectKey> {
    let mut dek = [0u8; KEY_LEN];

    getrandom::fill(&mut dek)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate DEK: {e}")))?;

    Ok(ProjectKey::new(dek))
}

/// Current wrapped-DEK AAD (M3): binds `kek_version` so a wrapped blob can
/// never be replayed under a different claimed KEK version — the AEAD tag
/// fails before the plaintext DEK ever materializes.
fn wrapped_dek_aad(project: &str, environment: &str, kek_version: u32) -> String {
    format!("dotlock:v2:wrapped-dek:project={project}:env={environment}:kek_version={kek_version}")
}

/// Pre-M3 AAD, accepted only as an unwrap fallback for vaults whose DEK was
/// wrapped before the v2 format. Rewrapping (init, master-password rotation,
/// key ratchet) always emits the v2 AAD.
fn legacy_wrapped_dek_aad(project: &str, environment: &str) -> String {
    format!("dotlock:v1:wrapped-dek:project={project}:env={environment}")
}

pub fn wrap_dek(
    kek: &[u8; KEY_LEN],
    dek: &ProjectKey,
    project: &str,
    environment: &str,
    kek_version: u32,
) -> DotLockResult<WrappedDek> {
    let mut nonce = [0u8; NONCE_LEN];

    getrandom::fill(&mut nonce)
        .map_err(|e| DotLockError::Crypto(format!("failed to generate nonce: {e}")))?;

    let aad = wrapped_dek_aad(project, environment, kek_version);

    let cipher = XChaCha20Poly1305::new(kek.into());

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: dek.as_bytes().as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| DotLockError::Crypto("failed to wrap DEK".to_string()))?;

    Ok(WrappedDek { nonce, ciphertext })
}

pub fn unwrap_dek(
    kek: &[u8; KEY_LEN],
    wrapped: &WrappedDek,
    project: &str,
    environment: &str,
    kek_version: u32,
) -> DotLockResult<ProjectKey> {
    let cipher = XChaCha20Poly1305::new(kek.into());

    let current_aad = wrapped_dek_aad(project, environment, kek_version);
    let plaintext = match cipher.decrypt(
        XNonce::from_slice(&wrapped.nonce),
        Payload {
            msg: wrapped.ciphertext.as_ref(),
            aad: current_aad.as_bytes(),
        },
    ) {
        Ok(plaintext) => plaintext,
        // Legacy fallback: a genuinely pre-v2 wrap authenticates only under
        // the v1 AAD. A v2 blob replayed with a doctored `kek_version` fails
        // BOTH attempts (its tag was computed over the v2 AAD), and on sealed
        // vaults the wrap fields are additionally covered by the metadata MAC.
        Err(_) => {
            let legacy_aad = legacy_wrapped_dek_aad(project, environment);
            cipher
                .decrypt(
                    XNonce::from_slice(&wrapped.nonce),
                    Payload {
                        msg: wrapped.ciphertext.as_ref(),
                        aad: legacy_aad.as_bytes(),
                    },
                )
                .map_err(|_| DotLockError::Crypto("failed to unwrap DEK".to_string()))?
        }
    };

    let dek: [u8; KEY_LEN] = plaintext
        .try_into()
        .map_err(|_| DotLockError::Crypto("invalid DEK length".to_string()))?;

    Ok(ProjectKey::new(dek))
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };

    use super::{WrappedDek, unwrap_dek, wrap_dek};
    use crate::domain::keys::ProjectKey;

    const KEK: [u8; 32] = [7u8; 32];

    #[test]
    fn wrap_unwrap_round_trips_with_kek_version_in_aad() {
        let dek = ProjectKey::new([3u8; 32]);
        let wrapped = wrap_dek(&KEK, &dek, "dotlock", "dev", 3).expect("wrap");
        let unwrapped = unwrap_dek(&KEK, &wrapped, "dotlock", "dev", 3).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }

    /// M3: a v2-wrapped DEK replayed under a downgraded `kek_version` fails
    /// the AEAD check — on BOTH the current and the legacy AAD attempt.
    #[test]
    fn unwrap_fails_when_kek_version_is_downgraded() {
        let dek = ProjectKey::new([3u8; 32]);
        let wrapped = wrap_dek(&KEK, &dek, "dotlock", "dev", 3).expect("wrap");
        assert!(unwrap_dek(&KEK, &wrapped, "dotlock", "dev", 2).is_err());
    }

    /// Pre-M3 vaults wrapped the DEK with the v1 AAD (no `kek_version`); the
    /// unwrap fallback must keep them unlockable.
    #[test]
    fn legacy_v1_wrapped_dek_unwraps_via_fallback() {
        let dek = ProjectKey::new([3u8; 32]);
        let nonce = [5u8; 24];
        let legacy_aad = "dotlock:v1:wrapped-dek:project=dotlock:env=dev";
        let cipher = XChaCha20Poly1305::new((&KEK).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: dek.as_bytes().as_slice(),
                    aad: legacy_aad.as_bytes(),
                },
            )
            .expect("legacy wrap");
        let wrapped = WrappedDek { nonce, ciphertext };
        let unwrapped = unwrap_dek(&KEK, &wrapped, "dotlock", "dev", 1).expect("legacy unwrap");
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }
}
