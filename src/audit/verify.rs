use std::fs;

use crate::{
    audit::log::{audit_log_path, compute_entry_hash, read_all_entries},
    crypto::share::verify_audit_entry_hash_signature,
    domain::{error::DotLockError, model::DotLockResult},
    storage::identity::{load_local_identity_metadata, public_key_path},
};

const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub fn verify_log(strict: bool) -> DotLockResult<()> {
    let path = audit_log_path()?;
    let entries = read_all_entries(&path)?;
    let local_identity = load_local_identity_metadata().ok();
    let local_public_key = fs::read_to_string(public_key_path()).ok();
    let mut prev_hash = ZERO_HASH.to_string();
    let mut anonymous = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        let line = index + 1;
        if entry.prev_hash != prev_hash {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed at line {line}: prev_hash mismatch"
            )));
        }

        let expected =
            compute_entry_hash(entry.ts, &entry.action, &entry.payload, &entry.prev_hash)?;
        if entry.entry_hash != expected {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed at line {line}: hash mismatch"
            )));
        }

        if entry.signer_fingerprint == "anonymous" || entry.signature.is_empty() {
            anonymous += 1;
            if strict {
                return Err(DotLockError::Crypto(format!(
                    "audit verify failed at line {line}: anonymous entry rejected by --strict"
                )));
            }
        } else if let (Some(identity), Some(public_key)) = (&local_identity, &local_public_key) {
            if identity.fingerprint != entry.signer_fingerprint {
                return Err(DotLockError::Crypto(format!(
                    "audit verify failed at line {line}: signer fingerprint is not the local identity"
                )));
            }
            verify_audit_entry_hash_signature(&entry.entry_hash, &entry.signature, public_key)
                .map_err(|_| {
                    DotLockError::Crypto(format!(
                        "audit verify failed at line {line}: signature invalid"
                    ))
                })?;
        } else {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed at line {line}: signer identity is unavailable"
            )));
        }

        prev_hash = entry.entry_hash.clone();
    }

    if anonymous > 0 {
        eprintln!("warn: {anonymous} anonymous audit entrie(s) had no signature");
    }
    println!("ok: audit log verified ({} entrie(s))", entries.len());
    Ok(())
}
