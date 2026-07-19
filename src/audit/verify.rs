use std::fs;

use subtle::ConstantTimeEq;

use crate::{
    audit::log::{
        AuditEntry, AuditHighWaterMark, audit_log_path, compute_entry_hash, hwm_material,
        load_high_water_mark, read_all_entries,
    },
    crypto::share::verify_audit_entry_hash_signature,
    domain::{error::DotLockError, model::DotLockResult},
    storage::identity::{
        legacy_public_key_path, load_legacy_identity_metadata, load_local_identity_metadata,
        public_key_path,
    },
};

const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// L8: constant-time string-hash comparison. The compared values are public
/// (non-secret) chain hashes, so there is no real timing oracle; this is
/// defense-in-depth rigor per REVIEW. `ct_eq` on differing lengths is an
/// immediate (public) mismatch, which leaks only the length — also public.
fn hashes_match(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// A signer this machine trusts for audit-log verification: the current local
/// identity plus, after `dl cert migrate`, the archived legacy (RSA) identity
/// — entries written before the migration keep verifying under the old key.
pub struct TrustedSigner {
    pub fingerprint: String,
    pub public_key_pem: String,
}

pub struct VerifyContext<'a> {
    /// Strict is the DEFAULT: anonymous/unsigned entries (and an unsigned
    /// high-water mark) fail verification. `dl audit verify --lax` opts out.
    pub strict: bool,
    pub signers: &'a [TrustedSigner],
    pub hwm: Option<&'a AuditHighWaterMark>,
}

impl VerifyContext<'_> {
    fn signer(&self, fingerprint: &str) -> Option<&TrustedSigner> {
        self.signers
            .iter()
            .find(|signer| signer.fingerprint == fingerprint)
    }
}

/// Core verification over an in-memory entry list; returns the number of
/// anonymous entries encountered (only ever non-zero in lax mode).
pub fn verify_entries(entries: &[AuditEntry], ctx: &VerifyContext<'_>) -> DotLockResult<usize> {
    let mut prev_hash = ZERO_HASH.to_string();
    let mut anonymous = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        let line = index + 1;
        if !hashes_match(&entry.prev_hash, &prev_hash) {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed at line {line}: prev_hash mismatch"
            )));
        }

        let expected =
            compute_entry_hash(entry.ts, &entry.action, &entry.payload, &entry.prev_hash)?;
        if !hashes_match(&entry.entry_hash, &expected) {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed at line {line}: hash mismatch"
            )));
        }

        if entry.signer_fingerprint == "anonymous" || entry.signature.is_empty() {
            anonymous += 1;
            if ctx.strict {
                return Err(DotLockError::Crypto(format!(
                    "audit verify failed at line {line}: anonymous entry rejected (run with --lax to allow unsigned entries)"
                )));
            }
        } else if let Some(signer) = ctx.signer(&entry.signer_fingerprint) {
            verify_audit_entry_hash_signature(
                &entry.entry_hash,
                &entry.signature,
                &signer.public_key_pem,
            )
            .map_err(|_| {
                DotLockError::Crypto(format!(
                    "audit verify failed at line {line}: signature invalid"
                ))
            })?;
        } else if ctx.signers.is_empty() {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed at line {line}: signer identity is unavailable"
            )));
        } else {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed at line {line}: signer fingerprint is not the local identity"
            )));
        }

        prev_hash = entry.entry_hash.clone();
    }

    verify_high_water_mark(entries, ctx)?;

    Ok(anonymous)
}

/// Tail-truncation detection (H4): the recorded high-water mark commits to a
/// minimum entry count and the entry hash at that position. These checks run
/// in BOTH strict and lax mode — truncation is tampering, not a signature
/// policy question. Only the "unsigned mark" rejection is strict-only.
fn verify_high_water_mark(entries: &[AuditEntry], ctx: &VerifyContext<'_>) -> DotLockResult<()> {
    let Some(hwm) = ctx.hwm else {
        return Ok(());
    };

    if (entries.len() as u64) < hwm.count {
        return Err(DotLockError::Crypto(format!(
            "audit verify failed: log has {} entrie(s) but the signed high-water mark records {}; the log tail was truncated",
            entries.len(),
            hwm.count
        )));
    }

    if hwm.count > 0 {
        let at_mark = &entries[hwm.count as usize - 1];
        if !hashes_match(&at_mark.entry_hash, &hwm.head_hash) {
            return Err(DotLockError::Crypto(format!(
                "audit verify failed: entry {} does not match the recorded high-water mark head hash",
                hwm.count
            )));
        }
    }

    if hwm.signer_fingerprint == "anonymous"
        || hwm.signer_fingerprint.is_empty()
        || hwm.signature.is_empty()
    {
        if ctx.strict {
            return Err(DotLockError::Crypto(
                "audit verify failed: the high-water mark is unsigned (run with --lax to allow it)"
                    .to_string(),
            ));
        }
        return Ok(());
    }

    let Some(signer) = ctx.signer(&hwm.signer_fingerprint) else {
        if ctx.signers.is_empty() {
            return Err(DotLockError::Crypto(
                "audit verify failed: signer identity is unavailable for the high-water mark"
                    .to_string(),
            ));
        }
        return Err(DotLockError::Crypto(
            "audit verify failed: high-water mark signer is not the local identity".to_string(),
        ));
    };
    verify_audit_entry_hash_signature(
        &hwm_material(hwm.count, &hwm.head_hash),
        &hwm.signature,
        &signer.public_key_pem,
    )
    .map_err(|_| {
        DotLockError::Crypto("audit verify failed: high-water mark signature invalid".to_string())
    })
}

pub fn verify_log(strict: bool) -> DotLockResult<()> {
    let path = audit_log_path()?;
    let entries = read_all_entries(&path)?;
    let mut signers = Vec::new();
    if let Ok(identity_meta) = load_local_identity_metadata()
        && let Some(public_key_pem) = public_key_path()
            .ok()
            .and_then(|path| fs::read_to_string(path).ok())
    {
        signers.push(TrustedSigner {
            fingerprint: identity_meta.fingerprint,
            public_key_pem,
        });
    }
    // Entries signed before `dl cert migrate` verify under the archived
    // legacy identity.
    if let Ok(legacy_meta) = load_legacy_identity_metadata()
        && let Some(public_key_pem) = legacy_public_key_path()
            .ok()
            .and_then(|path| fs::read_to_string(path).ok())
    {
        signers.push(TrustedSigner {
            fingerprint: legacy_meta.fingerprint,
            public_key_pem,
        });
    }
    let hwm = load_high_water_mark(&path)?;

    let ctx = VerifyContext {
        strict,
        signers: &signers,
        hwm: hwm.as_ref(),
    };
    let anonymous = verify_entries(&entries, &ctx)?;

    if anonymous > 0 {
        eprintln!("warn: {anonymous} anonymous audit entrie(s) had no signature");
    }
    if hwm.is_none() && !entries.is_empty() {
        eprintln!(
            "warn: no high-water mark recorded yet; tail truncation cannot be detected until the next audit write"
        );
    }
    println!("ok: audit log verified ({} entrie(s))", entries.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{TrustedSigner, VerifyContext, verify_entries};
    use crate::{
        audit::log::{AuditEntry, AuditHighWaterMark, compute_entry_hash, hwm_material},
        crypto::share::{
            GeneratedIdentity, IdentityProtection, generate_identity, sign_audit_entry_hash,
        },
    };

    const ZERO_HASH: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn signed_chain(identity: &GeneratedIdentity, len: usize) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        let mut prev_hash = ZERO_HASH.to_string();
        for index in 0..len {
            let ts = 1000 + index as u64;
            let payload = json!({"cmd": [format!("step-{index}")]});
            let entry_hash = compute_entry_hash(ts, "run", &payload, &prev_hash).expect("hash");
            let signature =
                sign_audit_entry_hash(&entry_hash, &identity.private_key_pem).expect("sign");
            entries.push(AuditEntry {
                v: 1,
                ts,
                action: "run".to_string(),
                payload,
                prev_hash: prev_hash.clone(),
                entry_hash: entry_hash.clone(),
                signer_fingerprint: identity.fingerprint.clone(),
                signature,
            });
            prev_hash = entry_hash;
        }
        entries
    }

    fn signed_hwm(identity: &GeneratedIdentity, entries: &[AuditEntry]) -> AuditHighWaterMark {
        let count = entries.len() as u64;
        let head_hash = entries
            .last()
            .map(|entry| entry.entry_hash.clone())
            .unwrap_or_else(|| ZERO_HASH.to_string());
        let signature =
            sign_audit_entry_hash(&hwm_material(count, &head_hash), &identity.private_key_pem)
                .expect("sign hwm");
        AuditHighWaterMark {
            count,
            head_hash,
            signer_fingerprint: identity.fingerprint.clone(),
            signature,
        }
    }

    fn ctx<'a>(
        strict: bool,
        signers: &'a [TrustedSigner],
        hwm: Option<&'a AuditHighWaterMark>,
    ) -> VerifyContext<'a> {
        VerifyContext {
            strict,
            signers,
            hwm,
        }
    }

    fn signers_for(identity: &GeneratedIdentity) -> Vec<TrustedSigner> {
        vec![TrustedSigner {
            fingerprint: identity.fingerprint.clone(),
            public_key_pem: identity.public_key_pem.clone(),
        }]
    }

    #[test]
    fn signed_chain_with_matching_hwm_verifies_in_strict_mode() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");
        let entries = signed_chain(&identity, 3);
        let hwm = signed_hwm(&identity, &entries);
        let signers = signers_for(&identity);

        let anonymous = verify_entries(&entries, &ctx(true, &signers, Some(&hwm))).expect("verify");
        assert_eq!(anonymous, 0);
    }

    #[test]
    fn anonymous_entry_fails_strict_verify_but_passes_lax() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");
        let mut entries = signed_chain(&identity, 2);
        entries[1].signer_fingerprint = "anonymous".to_string();
        entries[1].signature = String::new();
        let signers = signers_for(&identity);

        let strict = verify_entries(&entries, &ctx(true, &signers, None));
        assert!(
            strict.is_err(),
            "strict (default) must reject anonymous entries"
        );

        let anonymous = verify_entries(&entries, &ctx(false, &signers, None)).expect("lax verify");
        assert_eq!(anonymous, 1);
    }

    /// Migration boundary (ADR 0001): a log whose older entries were signed
    /// by the pre-migration RSA identity and newer ones by the Ed25519
    /// identity verifies strictly when BOTH are trusted signers — and fails
    /// when the legacy signer is not in the trusted set.
    #[test]
    fn mixed_rsa_and_ed25519_signed_chain_verifies_with_both_signers() {
        use crate::crypto::share::generate_legacy_rsa_identity;

        let legacy =
            generate_legacy_rsa_identity(IdentityProtection::Plain).expect("legacy identity");
        let modern = generate_identity(IdentityProtection::Plain).expect("modern identity");

        // Two entries signed by the RSA identity, then two by Ed25519.
        let mut entries = signed_chain(&legacy, 2);
        let mut prev_hash = entries.last().expect("entries").entry_hash.clone();
        for index in 0..2u64 {
            let ts = 2000 + index;
            let payload = json!({"cmd": [format!("modern-{index}")]});
            let entry_hash = compute_entry_hash(ts, "run", &payload, &prev_hash).expect("hash");
            let signature =
                sign_audit_entry_hash(&entry_hash, &modern.private_key_pem).expect("sign");
            entries.push(AuditEntry {
                v: 1,
                ts,
                action: "run".to_string(),
                payload,
                prev_hash: prev_hash.clone(),
                entry_hash: entry_hash.clone(),
                signer_fingerprint: modern.fingerprint.clone(),
                signature,
            });
            prev_hash = entry_hash;
        }
        let hwm = signed_hwm(&modern, &entries);

        let both = [
            TrustedSigner {
                fingerprint: modern.fingerprint.clone(),
                public_key_pem: modern.public_key_pem.clone(),
            },
            TrustedSigner {
                fingerprint: legacy.fingerprint.clone(),
                public_key_pem: legacy.public_key_pem.clone(),
            },
        ];
        let anonymous =
            verify_entries(&entries, &ctx(true, &both, Some(&hwm))).expect("mixed chain verifies");
        assert_eq!(anonymous, 0);

        // Without the archived legacy signer, the RSA-signed prefix fails.
        let modern_only = [TrustedSigner {
            fingerprint: modern.fingerprint.clone(),
            public_key_pem: modern.public_key_pem.clone(),
        }];
        assert!(verify_entries(&entries, &ctx(true, &modern_only, Some(&hwm))).is_err());
    }

    #[test]
    fn tail_truncation_is_detected_even_in_lax_mode() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");
        let entries = signed_chain(&identity, 3);
        let hwm = signed_hwm(&identity, &entries);
        let truncated = &entries[..2];
        let signers = signers_for(&identity);

        for strict in [true, false] {
            let result = verify_entries(truncated, &ctx(strict, &signers, Some(&hwm)));
            assert!(
                result.is_err(),
                "truncated tail must fail (strict={strict})"
            );
        }
    }

    #[test]
    fn hwm_head_hash_mismatch_is_rejected() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");
        let entries = signed_chain(&identity, 2);
        let mut hwm = signed_hwm(&identity, &entries);
        hwm.head_hash = "sha256:deadbeef".to_string();
        let signers = signers_for(&identity);

        let result = verify_entries(&entries, &ctx(false, &signers, Some(&hwm)));
        assert!(result.is_err());
    }

    #[test]
    fn unsigned_hwm_is_rejected_in_strict_mode_only() {
        let identity = generate_identity(IdentityProtection::Plain).expect("identity");
        let entries = signed_chain(&identity, 2);
        let mut hwm = signed_hwm(&identity, &entries);
        hwm.signer_fingerprint = "anonymous".to_string();
        hwm.signature = String::new();
        let signers = signers_for(&identity);

        assert!(verify_entries(&entries, &ctx(true, &signers, Some(&hwm)),).is_err());
        verify_entries(&entries, &ctx(false, &signers, Some(&hwm)))
            .expect("lax verify accepts unsigned hwm");
    }
}
