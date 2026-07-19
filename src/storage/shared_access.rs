use std::{collections::HashMap, path::Path};

use uuid::Uuid;

use crate::{
    crypto::{
        AccessMode, AuthorizedSigner, VaultKeyMetadata, VaultRecipient,
        dek::generate_dek,
        integrity::seal_vault_metadata,
        share::{
            RECIPIENT_ALG, encode_public_key_b64, fingerprint_public_key, sign_recipient_grant,
            verify_recipient_grant, wrap_dek_for_public_key, wrap_dek_for_public_key_b64,
        },
        update_master_password_metadata,
    },
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    storage::{
        identity::LocalIdentity,
        vault_file::{
            RatchetSummary, load_vault_metadata, record_vault_write, rotate_project_key_wrapping,
        },
        vault_txn::{VaultPairWrite, commit_vault_pair},
    },
};

/// Metadata-only write funnel for shared-access mutations: records the write,
/// reseals the metadata MAC/epoch under `dek` (M2+M3), and commits through
/// the same transactional path as every other vault mutation.
fn seal_and_commit_metadata(
    vault_path: &str,
    metadata: &mut VaultKeyMetadata,
    dek: &ProjectKey,
) -> DotLockResult<()> {
    record_vault_write(metadata);
    seal_vault_metadata(metadata, dek)?;
    let vault = Path::new(vault_path);
    let secrets = vault
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join("secrets.lock"))
        .unwrap_or_else(|| std::path::PathBuf::from("secrets.lock"));
    commit_vault_pair(
        vault,
        &secrets,
        VaultPairWrite {
            metadata,
            secrets_lock_bytes: None,
        },
    )
}

/// Canonical payload signed by an authorized signer to authorize a recipient
/// grant (H3): binds the recipient's identity to this project and to the
/// granting authority. Wrapped key material is intentionally excluded — it is
/// rewrapped on every rotation without changing WHO is authorized.
/// Length-prefixed encoding, so no field combination is ambiguous.
pub fn recipient_grant_payload(
    project_uuid: &str,
    public_key_fingerprint: &str,
    public_key_b64: &str,
    signer_fingerprint: &str,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"dotlock/recipient-grant/v1";
    let mut payload = Vec::new();
    for part in [
        DOMAIN,
        project_uuid.as_bytes(),
        public_key_fingerprint.as_bytes(),
        public_key_b64.as_bytes(),
        signer_fingerprint.as_bytes(),
    ] {
        payload.extend_from_slice(&(part.len() as u64).to_le_bytes());
        payload.extend_from_slice(part);
    }
    payload
}

/// True when `recipient` carries a grant signature that verifies against one
/// of the vault's authorized signers. Unsigned recipients (legacy or
/// injected) never validate.
pub fn recipient_grant_is_valid(
    project_uuid: &str,
    signers: &[AuthorizedSigner],
    recipient: &VaultRecipient,
) -> bool {
    if recipient.grant_signature_b64.is_empty() || recipient.grant_signer_fingerprint.is_empty() {
        return false;
    }
    let Some(signer) = signers
        .iter()
        .find(|signer| signer.fingerprint == recipient.grant_signer_fingerprint)
    else {
        return false;
    };
    let payload = recipient_grant_payload(
        project_uuid,
        &recipient.public_key_fingerprint,
        &recipient.public_key_b64,
        &signer.fingerprint,
    );
    verify_recipient_grant(
        &payload,
        &recipient.grant_signature_b64,
        &signer.public_key_b64,
    )
    .is_ok()
}

/// Registers `signer` as an authorized grant signer. Only reachable from code
/// paths that already proved master-password/full-project-key authority.
fn ensure_authorized_signer(
    metadata: &mut VaultKeyMetadata,
    signer: &LocalIdentity,
) -> DotLockResult<()> {
    if metadata
        .authorized_signers
        .iter()
        .any(|existing| existing.fingerprint == signer.fingerprint)
    {
        return Ok(());
    }
    metadata.authorized_signers.push(AuthorizedSigner {
        fingerprint: signer.fingerprint.clone(),
        public_key_b64: encode_public_key_b64(&signer.public_key_pem)?,
        label: String::new(),
    });
    Ok(())
}

/// Migration/bless path: re-signs every recipient whose grant does not verify
/// (vaults that predate signed grants) under `signer`, registering `signer`
/// as an authorized signer. Callers must have proven master-password/full-key
/// authority. Returns how many recipients were blessed.
pub fn bless_recipient_grants(
    metadata: &mut VaultKeyMetadata,
    signer: &LocalIdentity,
) -> DotLockResult<usize> {
    ensure_authorized_signer(metadata, signer)?;
    let project_uuid = metadata.project_uuid.clone();
    let signers = metadata.authorized_signers.clone();
    let mut blessed = 0usize;
    for recipient in &mut metadata.recipients {
        if recipient_grant_is_valid(&project_uuid, &signers, recipient) {
            continue;
        }
        let payload = recipient_grant_payload(
            &project_uuid,
            &recipient.public_key_fingerprint,
            &recipient.public_key_b64,
            &signer.fingerprint,
        );
        recipient.grant_signature_b64 = sign_recipient_grant(&payload, &signer.private_key_pem)?;
        recipient.grant_signer_fingerprint = signer.fingerprint.clone();
        blessed += 1;
    }
    Ok(blessed)
}

/// Flips the vault into shared mode. `access_mode` is covered by the metadata
/// MAC (M2), so this now requires a proven project key: callers must unlock
/// with full access first.
pub fn enable_shared_access(
    vault_path: &str,
    metadata: &mut VaultKeyMetadata,
    dek: &ProjectKey,
) -> DotLockResult<bool> {
    let changed = metadata.access_mode != AccessMode::Shared;
    metadata.access_mode = AccessMode::Shared;
    seal_and_commit_metadata(vault_path, metadata, dek)?;
    Ok(changed)
}

pub fn list_recipients(vault_path: &str) -> DotLockResult<Vec<VaultRecipient>> {
    let metadata = load_vault_metadata(vault_path)?;
    Ok(metadata.recipients)
}

/// Legacy unsigned grant, kept for tests exercising pre-signed-grant vaults;
/// the CLI always grants through `grant_recipient_with_secret_ids` with a
/// signing identity (H3).
#[cfg(test)]
pub fn grant_recipient(
    vault_path: &str,
    public_key_pem: &str,
    label: &str,
    dek: &ProjectKey,
) -> DotLockResult<VaultRecipient> {
    let mut metadata = load_vault_metadata(vault_path)?;
    grant_recipient_with_secret_ids(
        vault_path,
        &mut metadata,
        public_key_pem,
        label,
        dek,
        None,
        None,
    )
}

pub fn grant_recipient_with_secret_ids(
    vault_path: &str,
    metadata: &mut VaultKeyMetadata,
    public_key_pem: &str,
    label: &str,
    dek: &ProjectKey,
    allowed_secret_ids: Option<&[String]>,
    signer: Option<&LocalIdentity>,
) -> DotLockResult<VaultRecipient> {
    metadata.access_mode = AccessMode::Shared;

    let fingerprint = fingerprint_public_key(public_key_pem)?;
    let public_key_b64 = encode_public_key_b64(public_key_pem)?;
    let full_access = allowed_secret_ids.is_none();
    let wrapped_dek_b64 = if full_access {
        wrap_dek_for_public_key(dek.as_bytes(), public_key_pem)?
    } else {
        String::new()
    };
    let wrapped_sdks = wrap_allowed_sdks(metadata, public_key_pem, dek, allowed_secret_ids)?;

    // Signed-grant path (H3): the granting identity — which just proved
    // master-password authority to obtain `dek` — becomes an authorized
    // signer, signs this grant, and blesses any legacy unsigned recipients so
    // pre-signed-grant vaults migrate on their first grant.
    let (grant_signature_b64, grant_signer_fingerprint) = match signer {
        Some(signer) => {
            ensure_authorized_signer(metadata, signer)?;
            metadata.version = metadata.version.max(6);
            let payload = recipient_grant_payload(
                &metadata.project_uuid,
                &fingerprint,
                &public_key_b64,
                &signer.fingerprint,
            );
            (
                sign_recipient_grant(&payload, &signer.private_key_pem)?,
                signer.fingerprint.clone(),
            )
        }
        None => (String::new(), String::new()),
    };

    if let Some(existing) = metadata
        .recipients
        .iter_mut()
        .find(|recipient| recipient.public_key_fingerprint == fingerprint)
    {
        existing.label = label.to_string();
        existing.public_key_b64 = public_key_b64;
        existing.wrapped_dek_b64 = wrapped_dek_b64;
        existing.wrapped_sdks = wrapped_sdks;
        existing.full_access = full_access;
        existing.alg = RECIPIENT_ALG.to_string();
        existing.grant_signature_b64 = grant_signature_b64;
        existing.grant_signer_fingerprint = grant_signer_fingerprint;
        let recipient = existing.clone();
        if let Some(signer) = signer {
            bless_recipient_grants(metadata, signer)?;
        }
        seal_and_commit_metadata(vault_path, metadata, dek)?;
        return Ok(recipient);
    }

    let recipient = VaultRecipient {
        id: Uuid::new_v4().to_string(),
        label: label.to_string(),
        alg: RECIPIENT_ALG.to_string(),
        public_key_fingerprint: fingerprint,
        public_key_b64,
        wrapped_dek_b64,
        wrapped_sdks,
        full_access,
        grant_signature_b64,
        grant_signer_fingerprint,
    };
    metadata.recipients.push(recipient.clone());
    if let Some(signer) = signer {
        bless_recipient_grants(metadata, signer)?;
    }
    seal_and_commit_metadata(vault_path, metadata, dek)?;

    Ok(recipient)
}

fn wrap_allowed_sdks(
    metadata: &VaultKeyMetadata,
    public_key_pem: &str,
    dek: &ProjectKey,
    allowed_secret_ids: Option<&[String]>,
) -> DotLockResult<HashMap<String, String>> {
    let ids: Vec<String> = match allowed_secret_ids {
        Some(ids) => ids.to_vec(),
        None => metadata.wrapped_sdks_under_dek.keys().cloned().collect(),
    };
    let mut wrapped = HashMap::new();
    for secret_id in ids {
        let Some(project_wrapped_sdk) = metadata.wrapped_sdks_under_dek.get(&secret_id) else {
            continue;
        };
        let sdk = crate::crypto::sdk::unwrap_sdk_with_project_key(project_wrapped_sdk, dek)?;
        wrapped.insert(
            secret_id,
            wrap_dek_for_public_key(sdk.as_bytes(), public_key_pem)?,
        );
    }
    Ok(wrapped)
}

pub fn revoke_recipient_in_memory(
    metadata: &mut VaultKeyMetadata,
    query: &str,
) -> DotLockResult<VaultRecipient> {
    let index = metadata
        .recipients
        .iter()
        .position(|recipient| {
            recipient.id == query
                || recipient.label == query
                || recipient.public_key_fingerprint == query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: query.to_string(),
        })?;
    Ok(metadata.recipients.remove(index))
}

/// Outcome of [`revoke_recipient_and_rotate`].
pub struct RevokeOutcome {
    pub removed: VaultRecipient,
    /// The freshly rotated project key. The CLI invalidates the session cache
    /// instead of reusing it; tests use it to verify the vault stays readable.
    #[allow(dead_code)]
    pub new_dek: ProjectKey,
    pub summary: RatchetSummary,
}

/// Revokes a recipient and rotates the project key (DEK) in one transaction.
///
/// The ciphertexts in `secrets.lock` stay under their per-secret SDKs and are
/// untouched; what changes ownership is the *wrapping*: every SDK is unwrapped
/// under the old DEK and rewrapped under a fresh one, the remaining full-access
/// recipients get the fresh DEK wrapped for their public keys, the master
/// password wrapping is refreshed, and the integrity hash is re-encrypted
/// under the fresh DEK — all committed atomically via `commit_vault_pair`.
///
/// Note: revocation cannot remove access to ciphertexts the revoked identity
/// already obtained (e.g. from git history); rotating sensitive values is the
/// only remedy for that.
pub fn revoke_recipient_and_rotate(
    vault_path: &str,
    secrets_path: &str,
    metadata: &mut VaultKeyMetadata,
    query: &str,
    current_dek: &ProjectKey,
    passphrase: &str,
) -> DotLockResult<RevokeOutcome> {
    let removed = revoke_recipient_in_memory(metadata, query)?;

    let new_dek = generate_dek()?;
    // Rewraps every per-secret SDK and every remaining recipient's DEK under
    // the new project key, and re-encrypts `secrets_hash_*` under it, in the
    // same metadata object.
    let summary = rotate_project_key_wrapping(metadata, current_dek, &new_dek)?;
    update_master_password_metadata(metadata, &new_dek, passphrase)?;
    // Reseal under the NEW project key so the MAC and the bumped epoch land
    // in the same transactional commit as the rewrap (M2+M3).
    seal_vault_metadata(metadata, &new_dek)?;

    commit_vault_pair(
        Path::new(vault_path),
        Path::new(secrets_path),
        VaultPairWrite {
            metadata,
            secrets_lock_bytes: None,
        },
    )?;

    Ok(RevokeOutcome {
        removed,
        new_dek,
        summary,
    })
}

pub fn list_recipient_acl(vault_path: &str, query: &str) -> DotLockResult<Vec<String>> {
    let metadata = load_vault_metadata(vault_path)?;
    let recipient = metadata
        .recipients
        .iter()
        .find(|recipient| {
            recipient.id == query
                || recipient.label == query
                || recipient.public_key_fingerprint == query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: query.to_string(),
        })?;
    let mut ids = recipient.wrapped_sdks.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    Ok(ids)
}

pub fn add_recipient_secret_ids(
    vault_path: &str,
    metadata: &mut VaultKeyMetadata,
    query: &str,
    secret_ids: &[String],
    dek: &ProjectKey,
) -> DotLockResult<usize> {
    let recipient = metadata
        .recipients
        .iter_mut()
        .find(|recipient| {
            recipient.id == query
                || recipient.label == query
                || recipient.public_key_fingerprint == query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: query.to_string(),
        })?;

    let mut added = 0usize;
    for secret_id in secret_ids {
        if recipient.wrapped_sdks.contains_key(secret_id) {
            continue;
        }
        let Some(project_wrapped_sdk) = metadata.wrapped_sdks_under_dek.get(secret_id) else {
            continue;
        };
        let sdk = crate::crypto::sdk::unwrap_sdk_with_project_key(project_wrapped_sdk, dek)?;
        recipient.wrapped_sdks.insert(
            secret_id.clone(),
            wrap_dek_for_public_key_b64(sdk.as_bytes(), &recipient.public_key_b64)?,
        );
        added += 1;
    }
    recipient.full_access = false;
    seal_and_commit_metadata(vault_path, metadata, dek)?;
    Ok(added)
}

pub fn load_public_key_from_file(path: &Path) -> DotLockResult<String> {
    std::fs::read_to_string(path).map_err(DotLockError::from)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        crypto::{
            AccessMode, VaultConfig, VaultKeyMetadata,
            share::{IdentityProtection, generate_identity},
        },
        domain::keys::ProjectKey,
        storage::vault_file::{load_vault_metadata, save_vault_metadata},
    };

    use super::{
        grant_recipient, grant_recipient_with_secret_ids, list_recipients,
        revoke_recipient_and_rotate, revoke_recipient_in_memory,
    };

    fn temp_file(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("dotlock-{name}-{unique}.toml"))
    }

    fn metadata() -> VaultKeyMetadata {
        VaultKeyMetadata {
            version: 1,
            project_uuid: "project".to_string(),
            project: "dotlock".to_string(),
            environment: "dev".to_string(),
            kdf: "argon2id".to_string(),
            salt_b64: "salt".to_string(),
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
            kek_version: 1,
            kek_writes_since_rotate: 0,
            wrapped_dek_nonce_b64: "nonce".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks_under_dek: std::collections::HashMap::new(),
            access_mode: AccessMode::MasterPassword,
            recipients: Vec::new(),
            authorized_signers: Vec::new(),
            config: VaultConfig::default(),
            secrets_hash_nonce_b64: "hash_nonce".to_string(),
            secrets_hash_b64: "hash".to_string(),
            secrets_hash_sha256_b64: "hash_plain".to_string(),
            vault_epoch: 0,
            metadata_mac_b64: String::new(),
        }
    }

    #[test]
    fn grant_and_revoke_update_recipients() {
        let path = temp_file("shared-access");
        save_vault_metadata(&path, &metadata()).expect("save metadata");
        let identity =
            generate_identity(IdentityProtection::Encrypted("hunter2")).expect("identity");

        let granted = grant_recipient(
            path.to_str().expect("path"),
            &identity.public_key_pem,
            "alice",
            &ProjectKey::new([3u8; 32]),
        )
        .expect("grant");
        let listed = list_recipients(path.to_str().expect("path")).expect("list");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label, "alice");
        assert_eq!(
            listed[0].public_key_fingerprint,
            granted.public_key_fingerprint
        );

        let mut metadata = load_vault_metadata(path.to_str().expect("path")).expect("load vault");
        let removed = revoke_recipient_in_memory(&mut metadata, "alice").expect("revoke");
        save_vault_metadata(path.to_str().expect("path"), &metadata).expect("save after revoke");
        let listed = list_recipients(path.to_str().expect("path")).expect("list after revoke");

        assert_eq!(
            removed.public_key_fingerprint,
            granted.public_key_fingerprint
        );
        assert!(listed.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn revoke_rotates_project_key_without_bricking_envelope_vaults() {
        use base64::{Engine, engine::general_purpose};

        use crate::{
            crypto::{
                dek::{WrappedDek, unwrap_dek},
                integrity::verify_secrets_integrity,
                kdf::{KdfParams, derive_master_key},
                kek::derive_kek,
                sdk, update_master_password_metadata,
            },
            domain::{error::DotLockError, model::Alg},
            storage::secrets_lock::{load_secrets_file, upsert_plain_secret},
        };

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-revoke-rotate-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        let vault_path = dir.join("vault.toml");
        let secrets_path = dir.join("secrets.lock");
        let vault_str = vault_path.to_str().expect("vault path");
        let secrets_str = secrets_path.to_str().expect("secrets path");

        let old_dek = ProjectKey::new([8u8; 32]);
        let passphrase = "test-passphrase";
        let mut metadata = metadata();
        update_master_password_metadata(&mut metadata, &old_dek, passphrase).expect("wrap dek");
        save_vault_metadata(&vault_path, &metadata).expect("save vault");

        // Secrets set through the normal envelope path (v5, per-secret SDKs).
        upsert_plain_secret(
            &secrets_path,
            "A".to_string(),
            "1".to_string(),
            Alg::XChaCha20Poly1305,
            &old_dek,
            vault_str,
            &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
        )
        .expect("set A");
        upsert_plain_secret(
            &secrets_path,
            "B".to_string(),
            "2".to_string(),
            Alg::XChaCha20Poly1305,
            &old_dek,
            vault_str,
            &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
        )
        .expect("set B");

        // A second identity granted full access.
        let bob = crate::crypto::share::generate_identity(
            crate::crypto::share::IdentityProtection::Plain,
        )
        .expect("identity");
        let granted =
            grant_recipient(vault_str, &bob.public_key_pem, "bob", &old_dek).expect("grant");
        assert!(!granted.wrapped_dek_b64.is_empty());

        // (1) revoke succeeds (the old flow aborted with an AEAD error here).
        let outcome = revoke_recipient_and_rotate(
            vault_str,
            secrets_str,
            &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
            "bob",
            &old_dek,
            passphrase,
        )
        .expect("revoke succeeds for envelope vaults");
        assert_eq!(
            outcome.removed.public_key_fingerprint,
            granted.public_key_fingerprint
        );

        // (2) the revoked recipient's wrapped material is gone from vault.toml.
        let metadata = load_vault_metadata(vault_str).expect("reload vault");
        assert!(metadata.recipients.is_empty());
        let raw = fs::read_to_string(&vault_path).expect("read vault.toml");
        assert!(!raw.contains(&granted.wrapped_dek_b64));
        assert!(!raw.contains(&granted.public_key_fingerprint));

        // (3) the owner can still read A under the new DEK (vault not bricked)
        //     and the ciphertexts were NOT re-encrypted (SDK envelope intact).
        let file = load_secrets_file(&secrets_path).expect("load secrets");
        let record_a = file
            .secrets
            .iter()
            .find(|secret| secret.name == "A")
            .expect("record A");
        let wrapped_sdk = metadata
            .wrapped_sdks_under_dek
            .get(&record_a.id)
            .expect("SDK wrapping for A");
        let sdk_a = sdk::unwrap_sdk_with_project_key(wrapped_sdk, &outcome.new_dek)
            .expect("unwrap SDK under new DEK");
        assert_eq!(
            crate::storage::secrets_lock::decrypt_record_with_key(record_a, &sdk_a)
                .expect("decrypt A"),
            "1"
        );

        // (4) unlock with the revoked/old key material fails: the old DEK can
        //     no longer unwrap any SDK, and no recipient entry remains for bob.
        assert!(sdk::unwrap_sdk_with_project_key(wrapped_sdk, &old_dek).is_err());

        // Owner master-password unlock still works end to end.
        let salt = general_purpose::STANDARD
            .decode(&metadata.salt_b64)
            .expect("salt");
        let master_key = derive_master_key(
            passphrase,
            &salt,
            KdfParams {
                memory_kib: metadata.memory_kib,
                iterations: metadata.iterations,
                parallelism: metadata.parallelism,
            },
        )
        .expect("master key");
        let kek = derive_kek(
            &master_key,
            &metadata.project,
            &metadata.environment,
            metadata.kek_version,
        )
        .expect("kek");
        let nonce: [u8; 24] = general_purpose::STANDARD
            .decode(&metadata.wrapped_dek_nonce_b64)
            .expect("nonce b64")
            .try_into()
            .expect("nonce len");
        let wrapped = WrappedDek {
            nonce,
            ciphertext: general_purpose::STANDARD
                .decode(&metadata.wrapped_dek_b64)
                .expect("wrapped dek b64"),
        };
        let unlocked_dek = unwrap_dek(
            &kek,
            &wrapped,
            &metadata.project,
            &metadata.environment,
            metadata.kek_version,
        )
        .expect("owner password unlock");
        assert_eq!(unlocked_dek.as_bytes(), outcome.new_dek.as_bytes());

        // (5) integrity verifies under the new DEK and rejects the old one.
        verify_secrets_integrity(&secrets_path, &metadata, &outcome.new_dek)
            .expect("integrity under new DEK");
        assert!(matches!(
            verify_secrets_integrity(&secrets_path, &metadata, &old_dek),
            Err(DotLockError::TamperedSecretsFile)
        ));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn grant_can_limit_recipient_to_allowed_secret_sdks() {
        let path = temp_file("shared-access-allow");
        let mut metadata = metadata();
        metadata.wrapped_sdks_under_dek.insert(
            "foo-id".to_string(),
            crate::crypto::sdk::wrap_sdk_for_project_key(
                &crate::domain::keys::SecretKey::new([1u8; 32]),
                &ProjectKey::new([3u8; 32]),
            )
            .expect("wrap foo"),
        );
        metadata.wrapped_sdks_under_dek.insert(
            "bar-id".to_string(),
            crate::crypto::sdk::wrap_sdk_for_project_key(
                &crate::domain::keys::SecretKey::new([2u8; 32]),
                &ProjectKey::new([3u8; 32]),
            )
            .expect("wrap bar"),
        );
        save_vault_metadata(&path, &metadata).expect("save metadata");
        let identity =
            generate_identity(IdentityProtection::Encrypted("hunter2")).expect("identity");

        let granted = grant_recipient_with_secret_ids(
            path.to_str().expect("path"),
            &mut load_vault_metadata(&path).expect("load vault metadata"),
            &identity.public_key_pem,
            "alice",
            &ProjectKey::new([3u8; 32]),
            Some(&["foo-id".to_string()]),
            None,
        )
        .expect("grant");

        assert!(!granted.full_access);
        assert!(granted.wrapped_sdks.contains_key("foo-id"));
        assert!(!granted.wrapped_sdks.contains_key("bar-id"));

        let _ = fs::remove_file(path);
    }

    /// H3 migration: a vault that predates signed grants (no authorized
    /// signers, recipients without grant fields) still loads/parses, and the
    /// first `dl share grant` executed with a signing identity blesses every
    /// existing recipient and records the signer.
    #[test]
    fn grant_with_signer_signs_new_recipient_and_blesses_legacy_ones() {
        use crate::storage::{
            identity::LocalIdentity,
            shared_access::{grant_recipient_with_secret_ids, recipient_grant_is_valid},
        };

        let path = temp_file("shared-access-bless");
        let mut legacy = metadata();
        legacy.access_mode = AccessMode::Shared;
        legacy.recipients.push(crate::crypto::VaultRecipient {
            id: "legacy-id".to_string(),
            label: "legacy".to_string(),
            alg: "rsa-oaep-sha256".to_string(),
            public_key_fingerprint: "legacy-fp".to_string(),
            public_key_b64: "bGVnYWN5".to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: true,
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
        });
        save_vault_metadata(&path, &legacy).expect("save legacy vault");

        // The pre-signed-grant vault still loads (serde defaults).
        let loaded = load_vault_metadata(path.to_str().expect("path")).expect("legacy loads");
        assert!(loaded.authorized_signers.is_empty());

        let owner = generate_identity(IdentityProtection::Plain).expect("identity");
        let signer = LocalIdentity {
            fingerprint: owner.fingerprint.clone(),
            private_key_pem: owner.private_key_pem.clone(),
            public_key_pem: owner.public_key_pem.clone(),
        };
        let grantee = generate_identity(IdentityProtection::Plain).expect("grantee identity");

        let granted = grant_recipient_with_secret_ids(
            path.to_str().expect("path"),
            &mut load_vault_metadata(&path).expect("load vault metadata"),
            &grantee.public_key_pem,
            "bob",
            &ProjectKey::new([3u8; 32]),
            None,
            Some(&signer),
        )
        .expect("signed grant");
        assert!(!granted.grant_signature_b64.is_empty());
        assert_eq!(granted.grant_signer_fingerprint, owner.fingerprint);

        let metadata = load_vault_metadata(path.to_str().expect("path")).expect("reload");
        // The granting identity was recorded as an authorized signer and the
        // vault format was bumped.
        assert_eq!(metadata.authorized_signers.len(), 1);
        assert_eq!(
            metadata.authorized_signers[0].fingerprint,
            owner.fingerprint
        );
        assert!(metadata.version >= 6);
        // Every recipient — the new one AND the legacy unsigned one — now
        // carries a grant that verifies against the authorized signer.
        assert_eq!(metadata.recipients.len(), 2);
        for recipient in &metadata.recipients {
            assert!(
                recipient_grant_is_valid(
                    &metadata.project_uuid,
                    &metadata.authorized_signers,
                    recipient
                ),
                "recipient {} not blessed",
                recipient.label
            );
        }

        let _ = fs::remove_file(path);
    }
}
