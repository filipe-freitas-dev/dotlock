use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use uuid::Uuid;

use crate::{
    crypto::{
        AccessMode,
        integrity::{
            build_encrypted_hash_fields, build_encrypted_hash_fields_from_bytes, bytes_sha256_b64,
            file_sha256_b64, seal_vault_metadata, verify_metadata_mac, verify_secrets_integrity,
        },
        sdk,
        secret_cipher::{
            decryption_process, decryption_process_with_aad, encryption_process_with_aad,
        },
        share::{unwrap_dek_with_private_key, wrap_dek_for_public_key_b64},
    },
    domain::{
        error::DotLockError,
        keys::{ProjectKey, SecretKey},
        model::{Alg, DotLockResult},
    },
    storage::{
        identity::{load_local_identity, load_local_identity_metadata},
        project::SECRETS_FILE,
        secure_fs,
        vault_file::{load_vault_metadata, record_vault_write},
        vault_txn::{TxnLock, VaultPairWrite, commit_vault_pair, lock_vault_pair},
    },
};

// Secret-record entities live in the domain layer (A2); re-exported here so
// storage-centric call sites keep their historical import paths.
pub use crate::domain::secret::{
    DEFAULT_SECRET_ALG, DynamicSecretMetadata, SecretKind, SecretRecord, SecretsFile,
    secret_record_aad,
};

pub fn load_secrets_file<P: AsRef<Path>>(path: P) -> DotLockResult<SecretsFile> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(SecretsFile::default());
    }

    let content = secure_fs::read_to_string(path)?;

    if content.trim().is_empty() {
        return Ok(SecretsFile::default());
    }

    let file =
        toml::from_str::<SecretsFile>(&content).map_err(|_| DotLockError::LegacyVaultFormat)?;
    Ok(file)
}

pub fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn migrate_legacy_secret_timestamps(file: &mut SecretsFile) {
    let now = current_unix_timestamp();
    for secret in &mut file.secrets {
        // Only legacy (pre-AAD) records may have their timestamp rewritten:
        // for `version >= 1` records the timestamp is bound into the AEAD
        // associated data and must never be mutated outside a re-encryption.
        if secret.updated_at == 0 && secret.version == 0 {
            secret.updated_at = now;
        }
    }
}

/// Decrypts a record's value with the record-appropriate authentication:
/// `version >= 1` records must authenticate against their claimed
/// `id`/`name`/`updated_at`/`version` (a record whose plaintext ordering
/// metadata was forged — e.g. a replayed ciphertext with an inflated
/// timestamp — fails here); `version == 0` records are legacy pre-AAD data.
pub fn decrypt_record_with_key(secret: &SecretRecord, key: &SecretKey) -> DotLockResult<String> {
    if secret.version == 0 {
        return decryption_process(secret.data.clone(), secret_algorithm(secret)?, key);
    }
    decryption_process_with_aad(
        secret.data.clone(),
        secret_algorithm(secret)?,
        key,
        &secret.aad(),
    )
    .map_err(|_| {
        DotLockError::Crypto(format!(
            "secret `{}` failed authentication: its ciphertext does not match the claimed \
             id/name/updated_at/version (possible replay or forged metadata)",
            secret.name
        ))
    })
}

fn migrate_legacy_secret_algorithms(file: &mut SecretsFile) -> DotLockResult<()> {
    file.version = file.version.max(2);
    for secret in &mut file.secrets {
        let Some(alg) = secret.alg.as_deref() else {
            continue;
        };
        crate::utils::parse_alg(alg)?;
        if alg == DEFAULT_SECRET_ALG {
            secret.alg = None;
        }
    }
    Ok(())
}

fn serialize_secrets_file(file: &SecretsFile) -> DotLockResult<String> {
    toml::to_string_pretty(file).map_err(|e| DotLockError::Crypto(e.to_string()))
}

/// Finalizes both states in memory (secrets bytes + metadata with the
/// recomputed `secrets_hash_*`) and commits them as one transaction. Every
/// mutator of the vault pair MUST route its writes through here.
fn commit_secrets_and_metadata(
    secrets_path: &Path,
    file: &mut SecretsFile,
    metadata: &mut crate::crypto::VaultKeyMetadata,
    dek: &ProjectKey,
    vault_path: &str,
) -> DotLockResult<()> {
    migrate_legacy_secret_algorithms(file)?;
    let content = serialize_secrets_file(file)?;
    let bytes = content.as_bytes();
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields_from_bytes(bytes, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = bytes_sha256_b64(bytes);
    record_vault_write(metadata);
    seal_vault_metadata(metadata, dek)?;
    commit_vault_pair(
        Path::new(vault_path),
        secrets_path,
        VaultPairWrite {
            metadata,
            secrets_lock_bytes: Some(bytes),
        },
    )
}

pub fn refresh_vault_hash(
    secrets_path: &Path,
    dek: &ProjectKey,
    vault_path: &str,
) -> DotLockResult<()> {
    let mut metadata = load_vault_metadata(vault_path)?;
    let (nonce_b64, hash_b64) = build_encrypted_hash_fields(secrets_path, dek)?;
    metadata.secrets_hash_nonce_b64 = nonce_b64;
    metadata.secrets_hash_b64 = hash_b64;
    metadata.secrets_hash_sha256_b64 = file_sha256_b64(secrets_path)?;
    record_vault_write(&mut metadata);
    seal_vault_metadata(&mut metadata, dek)?;
    commit_vault_pair(
        Path::new(vault_path),
        secrets_path,
        VaultPairWrite {
            metadata: &metadata,
            secrets_lock_bytes: None,
        },
    )
}

/// Shared core of the upsert paths: resolves (or mints) the per-secret SDK,
/// encrypts the payload, updates the record in `file`, and registers the SDK
/// wrapping in the metadata (project key + full-access recipients).
fn upsert_record(
    file: &mut SecretsFile,
    metadata: &mut crate::crypto::VaultKeyMetadata,
    name: String,
    plaintext: String,
    alg: Alg,
    kind: SecretKind,
    dek: &ProjectKey,
) -> DotLockResult<(SecretRecord, bool)> {
    let now = current_unix_timestamp();
    let existing_index = file.secrets.iter().position(|secret| secret.name == name);
    let (record_id, sdk, next_version) = if let Some(index) = existing_index {
        let existing = &file.secrets[index];
        // Reuse the existing SDK when its wrapping is present; otherwise mint
        // a fresh one. The record is fully re-encrypted here, so a legacy or
        // orphaned record is upgraded to the envelope model instead of
        // silently reusing the raw project key as its SDK.
        let sdk = match secret_sdk_from_project_key(metadata, existing, dek)? {
            Some(sdk) => sdk,
            None => sdk::generate_sdk()?,
        };
        (
            existing.id.clone(),
            sdk,
            existing.version.saturating_add(1).max(1),
        )
    } else {
        (Uuid::new_v4().to_string(), sdk::generate_sdk()?, 1)
    };

    // Bind identity + ordering metadata into the AEAD tag (H2/M4): the fields
    // authenticated here are exactly the ones written to the record below.
    let aad = secret_record_aad(&record_id, &name, now, next_version);
    let encrypted = encryption_process_with_aad(name, plaintext, alg, &sdk, &aad)?;
    let data =
        String::from_utf8(encrypted.data).map_err(|err| DotLockError::Crypto(err.to_string()))?;

    let (record, created) = if let Some(index) = existing_index {
        let existing = &mut file.secrets[index];
        existing.alg = None;
        existing.data = data;
        existing.updated_at = now;
        existing.version = next_version;
        existing.kind = kind;
        (existing.clone(), false)
    } else {
        let record = SecretRecord {
            id: record_id,
            name: encrypted.name,
            alg: None,
            data,
            updated_at: now,
            version: next_version,
            kind,
        };
        file.secrets.push(record.clone());
        (record, true)
    };

    metadata
        .wrapped_sdks_under_dek
        .insert(record.id.clone(), sdk::wrap_sdk_for_project_key(&sdk, dek)?);
    wrap_sdk_for_authorized_full_access_recipients(metadata, &record.id, &sdk)?;

    Ok((record, created))
}

/// Wraps a per-secret SDK for every full-access recipient whose grant is
/// authorized (H3). Once a vault records authorized signers, recipients
/// lacking a valid grant signature (e.g. injected via a manually accepted
/// merge) never receive fresh key material.
fn wrap_sdk_for_authorized_full_access_recipients(
    metadata: &mut crate::crypto::VaultKeyMetadata,
    record_id: &str,
    sdk: &SecretKey,
) -> DotLockResult<()> {
    let enforce_grants = !metadata.authorized_signers.is_empty();
    let project_uuid = metadata.project_uuid.clone();
    let signers = metadata.authorized_signers.clone();
    for recipient in &mut metadata.recipients {
        if !recipient.full_access {
            continue;
        }
        if enforce_grants
            && !crate::storage::shared_access::recipient_grant_is_valid(
                &project_uuid,
                &signers,
                recipient,
            )
        {
            continue;
        }
        recipient.wrapped_sdks.insert(
            record_id.to_string(),
            wrap_dek_for_public_key_b64(sdk.as_bytes(), &recipient.public_key_b64)?,
        );
    }
    Ok(())
}

/// M1: takes the inter-process vault-pair lock and, while holding it, refreshes
/// `metadata` from disk if another writer committed since our unlock — so a
/// concurrent `dl set` cannot make us clobber its secret or drop its SDK
/// wrapping. The refreshed copy is only accepted after its MAC and the secrets
/// hash verify against the caller's project key; a mismatch (tamper, or a
/// concurrent key rotation that made our DEK stale) hard-fails instead of
/// silently committing over it. Callers MUST hold the returned guard until
/// after `commit_secrets_and_metadata`.
fn lock_pair_and_refresh_metadata(
    secrets_path: &Path,
    vault_path: &str,
    metadata: &mut crate::crypto::VaultKeyMetadata,
    dek: &ProjectKey,
) -> DotLockResult<TxnLock> {
    let guard = lock_vault_pair(Path::new(vault_path))?;
    let fresh = load_vault_metadata(vault_path)?;
    if fresh.vault_epoch > metadata.vault_epoch {
        verify_metadata_mac(&fresh, dek)?;
        verify_secrets_integrity(secrets_path, &fresh, dek)?;
        *metadata = fresh;
    }
    Ok(guard)
}

pub fn upsert_plain_secret<P: AsRef<Path>>(
    path: P,
    name: String,
    value: String,
    alg: Alg,
    dek: &ProjectKey,
    vault_path: &str,
    metadata: &mut crate::crypto::VaultKeyMetadata,
) -> DotLockResult<SecretRecord> {
    let path = path.as_ref();
    let _lock = lock_pair_and_refresh_metadata(path, vault_path, metadata, dek)?;
    let mut file = load_secrets_file(path)?;
    metadata.version = metadata.version.max(5);
    reject_limited_identity_write(metadata)?;

    let (record, _) = upsert_record(
        &mut file,
        metadata,
        name,
        value,
        alg,
        SecretKind::Static,
        dek,
    )?;

    migrate_legacy_secret_timestamps(&mut file);
    commit_secrets_and_metadata(path, &mut file, metadata, dek, vault_path)?;

    Ok(record)
}

/// Storage-side wrapper for the pure domain rule
/// [`crate::domain::vault::VaultKeyMetadata::reject_limited_identity_write_for_fingerprint`]:
/// resolves the local identity's fingerprint, then delegates.
fn reject_limited_identity_write(metadata: &crate::crypto::VaultKeyMetadata) -> DotLockResult<()> {
    if metadata.access_mode != AccessMode::Shared {
        return Ok(());
    }
    let Ok(identity_meta) = load_local_identity_metadata() else {
        return Ok(());
    };
    metadata.reject_limited_identity_write_for_fingerprint(&identity_meta.fingerprint)
}

pub fn migrate_all_secrets_to_envelope(
    dek: &ProjectKey,
    vault_path: &str,
    metadata: &mut crate::crypto::VaultKeyMetadata,
) -> DotLockResult<()> {
    let mut file = load_secrets_file(SECRETS_FILE)?;
    reject_limited_identity_write(metadata)?;
    let mut changed = false;

    for secret in &mut file.secrets {
        if metadata.wrapped_sdks_under_dek.contains_key(&secret.id) {
            continue;
        }
        // Pre-envelope record: its value is encrypted directly under the
        // project key (the sanctioned legacy DEK-as-SDK bridge).
        let value = decrypt_record_with_key(secret, &SecretKey::from_legacy_project_key(dek))?;
        let sdk = sdk::generate_sdk()?;
        let now = current_unix_timestamp();
        let next_version = secret.version.saturating_add(1).max(1);
        let aad = secret_record_aad(&secret.id, &secret.name, now, next_version);
        let encrypted = encryption_process_with_aad(
            secret.name.clone(),
            value,
            secret_algorithm(secret)?,
            &sdk,
            &aad,
        )?;
        secret.data = String::from_utf8(encrypted.data)
            .map_err(|err| DotLockError::Crypto(err.to_string()))?;
        secret.alg = None;
        secret.updated_at = now;
        secret.version = next_version;
        let secret_id = secret.id.clone();
        metadata
            .wrapped_sdks_under_dek
            .insert(secret_id.clone(), sdk::wrap_sdk_for_project_key(&sdk, dek)?);
        wrap_sdk_for_authorized_full_access_recipients(metadata, &secret_id, &sdk)?;
        changed = true;
    }

    if !changed {
        return Ok(());
    }

    metadata.version = metadata.version.max(5);
    commit_secrets_and_metadata(Path::new(SECRETS_FILE), &mut file, metadata, dek, vault_path)
}

pub fn rotate_secret_sdks_after_acl_removal(
    secret_ids: &[String],
    removed_recipient_query: &str,
    dek: &ProjectKey,
    vault_path: &str,
    metadata: &mut crate::crypto::VaultKeyMetadata,
) -> DotLockResult<()> {
    let mut file = load_secrets_file(SECRETS_FILE)?;
    reject_limited_identity_write(metadata)?;
    let removed_index = metadata
        .recipients
        .iter()
        .position(|recipient| {
            recipient.id == removed_recipient_query
                || recipient.label == removed_recipient_query
                || recipient.public_key_fingerprint == removed_recipient_query
        })
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: removed_recipient_query.to_string(),
        })?;

    for secret_id in secret_ids {
        let Some(secret) = file
            .secrets
            .iter_mut()
            .find(|secret| &secret.id == secret_id)
        else {
            continue;
        };
        if !metadata.recipients[removed_index]
            .wrapped_sdks
            .contains_key(secret_id)
        {
            continue;
        }

        let old_sdk = secret_key_from_project_key_or_legacy(metadata, secret, dek)?;
        let value = decrypt_record_with_key(secret, &old_sdk)?;
        let new_sdk = sdk::generate_sdk()?;
        let now = current_unix_timestamp();
        let next_version = secret.version.saturating_add(1).max(1);
        let aad = secret_record_aad(&secret.id, &secret.name, now, next_version);
        let encrypted = encryption_process_with_aad(
            secret.name.clone(),
            value,
            secret_algorithm(secret)?,
            &new_sdk,
            &aad,
        )?;
        secret.data = String::from_utf8(encrypted.data)
            .map_err(|err| DotLockError::Crypto(err.to_string()))?;
        secret.alg = None;
        secret.updated_at = now;
        secret.version = next_version;
        metadata.wrapped_sdks_under_dek.insert(
            secret.id.clone(),
            sdk::wrap_sdk_for_project_key(&new_sdk, dek)?,
        );

        let enforce_grants = !metadata.authorized_signers.is_empty();
        let project_uuid = metadata.project_uuid.clone();
        let signers = metadata.authorized_signers.clone();
        for (index, recipient) in metadata.recipients.iter_mut().enumerate() {
            if index == removed_index {
                recipient.wrapped_sdks.remove(secret_id);
                recipient.full_access = false;
                continue;
            }
            if enforce_grants
                && !crate::storage::shared_access::recipient_grant_is_valid(
                    &project_uuid,
                    &signers,
                    recipient,
                )
            {
                continue;
            }
            if recipient.full_access || recipient.wrapped_sdks.contains_key(secret_id) {
                recipient.wrapped_sdks.insert(
                    secret.id.clone(),
                    wrap_dek_for_public_key_b64(new_sdk.as_bytes(), &recipient.public_key_b64)?,
                );
            }
        }
    }

    commit_secrets_and_metadata(Path::new(SECRETS_FILE), &mut file, metadata, dek, vault_path)
}

pub fn decrypt_secret_value(
    secret: &SecretRecord,
    dek: &ProjectKey,
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<String> {
    let key = if metadata.access_mode == AccessMode::Shared {
        match secret_sdk_from_local_identity(metadata, secret)? {
            Some(sdk) => sdk,
            None if metadata.recipients.is_empty() => {
                secret_key_from_project_key_or_legacy(metadata, secret, dek)?
            }
            None => {
                return Err(DotLockError::AccessDenied {
                    secret: secret.name.clone(),
                });
            }
        }
    } else {
        secret_key_from_project_key_or_legacy(metadata, secret, dek)?
    };

    decrypt_record_with_key(secret, &key)
}

pub fn secret_algorithm(secret: &SecretRecord) -> DotLockResult<Alg> {
    crate::utils::parse_alg(secret.alg.as_deref().unwrap_or(DEFAULT_SECRET_ALG))
}

/// Resolves the key that decrypts `secret` from the project key. Vaults at
/// version 5+ store every secret under a per-secret SDK, so a missing wrapping
/// there is an orphaned secret and surfaces as an explicit
/// [`DotLockError::MissingSecretKeyWrapping`] — silently falling back to the
/// raw DEK is what used to turn merge bugs into undiagnosed permanent data
/// loss. Pre-v5 vaults keep the legacy DEK-direct behavior.
fn secret_key_from_project_key_or_legacy(
    metadata: &crate::crypto::VaultKeyMetadata,
    secret: &SecretRecord,
    dek: &ProjectKey,
) -> DotLockResult<SecretKey> {
    match secret_sdk_from_project_key(metadata, secret, dek)? {
        Some(sdk) => Ok(sdk),
        None if metadata.version < 5 => Ok(SecretKey::from_legacy_project_key(dek)),
        None => Err(DotLockError::MissingSecretKeyWrapping {
            id: secret.id.clone(),
        }),
    }
}

fn secret_sdk_from_project_key(
    metadata: &crate::crypto::VaultKeyMetadata,
    secret: &SecretRecord,
    dek: &ProjectKey,
) -> DotLockResult<Option<SecretKey>> {
    metadata
        .wrapped_sdks_under_dek
        .get(&secret.id)
        .map(|wrapped| sdk::unwrap_sdk_with_project_key(wrapped, dek))
        .transpose()
}

fn secret_sdk_from_local_identity(
    metadata: &crate::crypto::VaultKeyMetadata,
    secret: &SecretRecord,
) -> DotLockResult<Option<SecretKey>> {
    let Ok(identity_meta) = load_local_identity_metadata() else {
        return Ok(None);
    };
    let Some(recipient) = metadata
        .recipients
        .iter()
        .find(|recipient| recipient.public_key_fingerprint == identity_meta.fingerprint)
    else {
        return Ok(None);
    };
    let Some(wrapped_sdk) = recipient.wrapped_sdks.get(&secret.id) else {
        return Ok(None);
    };
    let identity = load_local_identity()?;
    unwrap_dek_with_private_key(wrapped_sdk, &identity.private_key_pem)
        .map(|sdk| Some(SecretKey::new(sdk)))
}

pub fn find_secret_by_name(name: &str) -> DotLockResult<SecretRecord> {
    let file = load_secrets_file(SECRETS_FILE)?;
    file.secrets
        .into_iter()
        .find(|secret| secret.name == name)
        .ok_or_else(|| DotLockError::SecretNotFound {
            name: name.to_string(),
        })
}

pub fn list_secrets() -> DotLockResult<Vec<SecretRecord>> {
    let file = load_secrets_file(SECRETS_FILE)?;
    Ok(file.secrets)
}

pub struct PlainSecretEntry {
    pub name: String,
    pub value: String,
    pub alg: Alg,
}

pub struct UpsertSummary {
    pub created: usize,
    pub updated: usize,
}

pub fn upsert_many<P: AsRef<Path>>(
    path: P,
    entries: Vec<PlainSecretEntry>,
    dek: &ProjectKey,
    vault_path: &str,
    metadata: &mut crate::crypto::VaultKeyMetadata,
) -> DotLockResult<UpsertSummary> {
    let path = path.as_ref();
    let _lock = lock_pair_and_refresh_metadata(path, vault_path, metadata, dek)?;
    let mut file = load_secrets_file(path)?;
    metadata.version = metadata.version.max(5);
    reject_limited_identity_write(metadata)?;
    let mut summary = UpsertSummary {
        created: 0,
        updated: 0,
    };

    for entry in entries {
        let (_, created) = upsert_record(
            &mut file,
            metadata,
            entry.name,
            entry.value,
            entry.alg,
            SecretKind::Static,
            dek,
        )?;
        if created {
            summary.created += 1;
        } else {
            summary.updated += 1;
        }
    }

    migrate_legacy_secret_timestamps(&mut file);
    commit_secrets_and_metadata(path, &mut file, metadata, dek, vault_path)?;

    Ok(summary)
}

pub fn upsert_dynamic_secret<P: AsRef<Path>>(
    path: P,
    name: String,
    dynamic: DynamicSecretMetadata,
    dek: &ProjectKey,
    vault_path: &str,
    metadata: &mut crate::crypto::VaultKeyMetadata,
) -> DotLockResult<SecretRecord> {
    let path = path.as_ref();
    let _lock = lock_pair_and_refresh_metadata(path, vault_path, metadata, dek)?;
    let mut file = load_secrets_file(path)?;
    metadata.version = metadata.version.max(5);
    reject_limited_identity_write(metadata)?;

    let dynamic_json =
        serde_json::to_string(&dynamic).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    let kind = SecretKind::Dynamic {
        provider: None,
        config: None,
        bootstrap: Vec::new(),
    };
    let (record, _) = upsert_record(
        &mut file,
        metadata,
        name,
        dynamic_json,
        Alg::XChaCha20Poly1305,
        kind,
        dek,
    )?;

    migrate_legacy_secret_timestamps(&mut file);
    commit_secrets_and_metadata(path, &mut file, metadata, dek, vault_path)?;

    Ok(record)
}

pub fn decrypt_dynamic_metadata(
    secret: &SecretRecord,
    dek: &ProjectKey,
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<DynamicSecretMetadata> {
    let plaintext = decrypt_secret_value(secret, dek, metadata)?;
    if !plaintext.trim().is_empty() {
        return serde_json::from_str::<DynamicSecretMetadata>(&plaintext).map_err(|err| {
            DotLockError::Crypto(format!("invalid dynamic secret metadata: {err}"))
        });
    }

    match &secret.kind {
        SecretKind::Dynamic {
            provider: Some(provider),
            config,
            bootstrap,
        } => Ok(DynamicSecretMetadata {
            provider: provider.clone(),
            config: config.clone().unwrap_or_else(|| serde_json::json!({})),
            bootstrap: bootstrap.clone(),
            provider_path: None,
            provider_sha256: None,
        }),
        SecretKind::Dynamic { .. } => Err(DotLockError::Crypto(
            "dynamic secret metadata is missing".to_string(),
        )),
        SecretKind::Static => Err(DotLockError::Crypto(
            "static secret has no dynamic metadata".to_string(),
        )),
    }
}

pub fn remove_secret_by_name(
    name: &str,
    dek: &ProjectKey,
    vault_path: &str,
    metadata: &mut crate::crypto::VaultKeyMetadata,
) -> DotLockResult<()> {
    reject_limited_identity_write(metadata)?;

    let _lock =
        lock_pair_and_refresh_metadata(Path::new(SECRETS_FILE), vault_path, metadata, dek)?;
    let mut file = load_secrets_file(SECRETS_FILE)?;
    let removed_ids = file
        .secrets
        .iter()
        .filter(|secret| secret.name == name)
        .map(|secret| secret.id.clone())
        .collect::<Vec<_>>();
    let before = file.secrets.len();
    file.secrets.retain(|secret| secret.name != name);

    if file.secrets.len() == before {
        return Err(DotLockError::SecretNotFound {
            name: name.to_string(),
        });
    }

    for id in &removed_ids {
        metadata.wrapped_sdks_under_dek.remove(id);
        for recipient in &mut metadata.recipients {
            recipient.wrapped_sdks.remove(id);
        }
    }

    commit_secrets_and_metadata(Path::new(SECRETS_FILE), &mut file, metadata, dek, vault_path)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        crypto::{
            AccessMode, VaultConfig, VaultKeyMetadata, VaultRecipient,
            secret_cipher::decryption_process,
        },
        domain::{
            keys::{ProjectKey, SecretKey},
            model::Alg,
        },
        storage::{
            secrets_lock::{
                PlainSecretEntry, SecretRecord, load_secrets_file, upsert_many, upsert_plain_secret,
            },
            vault_file::{load_vault_metadata, save_vault_metadata},
        },
    };

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    fn metadata() -> VaultKeyMetadata {
        VaultKeyMetadata {
            version: 2,
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
    fn upsert_plain_secret_encrypts_with_per_secret_sdk() {
        let dir = temp_dir("envelope");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let dek = ProjectKey::new([8u8; 32]);
        save_vault_metadata(&vault_path, &metadata()).expect("save vault");

        let record = upsert_plain_secret(
            &secrets_path,
            "FOO".to_string(),
            "bar".to_string(),
            Alg::XChaCha20Poly1305,
            &dek,
            vault_path.to_str().expect("vault path"),
            &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
        )
        .expect("upsert");
        let file = load_secrets_file(&secrets_path).expect("load secrets");
        let metadata = load_vault_metadata(&vault_path).expect("load metadata");

        // Sealed writes upgrade the vault format to v7 (M2/M3).
        assert_eq!(metadata.version, 7);
        assert_eq!(record.alg, None);
        assert_eq!(file.secrets[0].alg, None);
        let serialized = fs::read_to_string(&secrets_path).expect("read secrets");
        assert!(!serialized.contains("alg ="));
        assert!(metadata.wrapped_sdks_under_dek.contains_key(&record.id));
        // The record must NOT decrypt under the raw project key: it is
        // envelope-encrypted under its own SDK.
        assert!(
            decryption_process(
                file.secrets[0].data.clone(),
                Alg::XChaCha20Poly1305,
                &SecretKey::from_legacy_project_key(&dek)
            )
            .is_err()
        );

        let _ = fs::remove_dir_all(dir);
    }

    /// M1: two writers that unlocked BEFORE either committed (each holding
    /// its own stale metadata copy, like two concurrent `dl set` processes)
    /// must not lose each other's secret or SDK wrapping.
    #[test]
    fn concurrent_upserts_do_not_lose_updates() {
        let dir = temp_dir("concurrent");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let dek = ProjectKey::new([8u8; 32]);
        save_vault_metadata(&vault_path, &metadata()).expect("save vault");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = ["FIRST", "SECOND"]
            .into_iter()
            .map(|name| {
                let barrier = std::sync::Arc::clone(&barrier);
                let secrets_path = secrets_path.clone();
                let vault_path = vault_path.clone();
                let dek = dek.clone();
                std::thread::spawn(move || {
                    // Each writer starts from its own on-disk snapshot, taken
                    // before either commit — the lost-update scenario.
                    let mut metadata = load_vault_metadata(&vault_path).expect("load metadata");
                    barrier.wait();
                    upsert_plain_secret(
                        &secrets_path,
                        name.to_string(),
                        format!("{name}-value"),
                        Alg::XChaCha20Poly1305,
                        &dek,
                        vault_path.to_str().expect("vault path"),
                        &mut metadata,
                    )
                    .expect("upsert");
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("writer thread");
        }

        let file = load_secrets_file(&secrets_path).expect("load secrets");
        let metadata = load_vault_metadata(&vault_path).expect("load metadata");
        assert_eq!(file.secrets.len(), 2, "one writer's secret was lost");
        for name in ["FIRST", "SECOND"] {
            let secret = file
                .secrets
                .iter()
                .find(|secret| secret.name == name)
                .unwrap_or_else(|| panic!("secret {name} missing"));
            assert!(
                metadata.wrapped_sdks_under_dek.contains_key(&secret.id),
                "SDK wrapping for {name} was lost"
            );
            let value = super::decrypt_secret_value(secret, &dek, &metadata)
                .unwrap_or_else(|err| panic!("secret {name} undecryptable: {err}"));
            assert_eq!(value, format!("{name}-value"));
        }
        // The committed metadata must pass its own integrity checks.
        crate::crypto::integrity::verify_metadata_mac(&metadata, &dek).expect("metadata MAC");
        crate::crypto::integrity::verify_secrets_integrity(&secrets_path, &metadata, &dek)
            .expect("secrets integrity");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn upsert_many_encrypts_with_per_secret_sdks_and_updates_full_access_recipients() {
        let dir = temp_dir("batch-envelope");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let dek = ProjectKey::new([8u8; 32]);
        let identity = crate::crypto::share::generate_identity(
            crate::crypto::share::IdentityProtection::Plain,
        )
        .expect("identity");
        let mut metadata = metadata();
        metadata.access_mode = AccessMode::Shared;
        metadata.recipients.push(VaultRecipient {
            id: "alice-id".to_string(),
            label: "alice".to_string(),
            alg: crate::crypto::share::RECIPIENT_ALG.to_string(),
            public_key_fingerprint: identity.fingerprint,
            public_key_b64: crate::crypto::share::encode_public_key_b64(&identity.public_key_pem)
                .expect("public key b64"),
            wrapped_dek_b64: crate::crypto::share::wrap_dek_for_public_key(
                dek.as_bytes(),
                &identity.public_key_pem,
            )
            .expect("wrap project key"),
            wrapped_sdks: std::collections::HashMap::new(),
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
            full_access: true,
        });
        save_vault_metadata(&vault_path, &metadata).expect("save vault");

        upsert_many(
            &secrets_path,
            vec![PlainSecretEntry {
                name: "FOO".to_string(),
                value: "bar".to_string(),
                alg: Alg::XChaCha20Poly1305,
            }],
            &dek,
            vault_path.to_str().expect("vault path"),
            &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
        )
        .expect("upsert many");

        let file = load_secrets_file(&secrets_path).expect("load secrets");
        let metadata = load_vault_metadata(&vault_path).expect("load metadata");
        let record = &file.secrets[0];
        assert_eq!(record.alg, None);
        assert!(metadata.wrapped_sdks_under_dek.contains_key(&record.id));
        assert!(metadata.recipients[0].wrapped_sdks.contains_key(&record.id));
        assert!(
            decryption_process(
                record.data.clone(),
                Alg::XChaCha20Poly1305,
                &SecretKey::from_legacy_project_key(&dek)
            )
            .is_err()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn limited_identity_cannot_remove_secrets_or_touch_the_vault_pair() {
        use crate::{
            crypto::integrity::verify_secrets_integrity, domain::error::DotLockError,
            storage::secrets_lock::remove_secret_by_name,
        };

        let dir = temp_dir("limited-unset");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let vault_str = vault_path.to_str().expect("vault path");
        let dek = ProjectKey::new([8u8; 32]);
        save_vault_metadata(&vault_path, &metadata()).expect("save vault");

        // Owner creates a secret through the normal envelope path.
        upsert_plain_secret(
            &secrets_path,
            "FOO".to_string(),
            "bar".to_string(),
            Alg::XChaCha20Poly1305,
            &dek,
            vault_str,
            &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
        )
        .expect("owner upsert");

        // The vault is shared with a limited (read-only) recipient, and the
        // local identity IS that limited recipient.
        let identity_dir = temp_dir("limited-unset-identity");
        let identity_meta = crate::storage::identity::LocalIdentityMetadata {
            fingerprint: "limited-fp".to_string(),
            encrypted: false,
        };
        let meta_content = toml::to_string_pretty(&identity_meta).expect("identity meta");
        crate::storage::secure_fs::write_string_atomic(
            &identity_dir.join("identity.toml"),
            &meta_content,
            0o700,
            0o600,
        )
        .expect("write identity meta");

        let mut shared = load_vault_metadata(&vault_path).expect("load vault");
        shared.access_mode = AccessMode::Shared;
        shared.recipients.push(VaultRecipient {
            id: "limited-id".to_string(),
            label: "limited".to_string(),
            alg: "rsa-oaep-sha256".to_string(),
            public_key_fingerprint: "limited-fp".to_string(),
            public_key_b64: "public".to_string(),
            wrapped_dek_b64: String::new(),
            wrapped_sdks: std::collections::HashMap::from([(
                "some-id".to_string(),
                "wrapped".to_string(),
            )]),
            grant_signature_b64: String::new(),
            grant_signer_fingerprint: String::new(),
            full_access: false,
        });
        save_vault_metadata(&vault_path, &shared).expect("save shared vault");

        let vault_before = fs::read(&vault_path).expect("vault bytes");
        let secrets_before = fs::read(&secrets_path).expect("secrets bytes");

        // As the limited identity, unset must fail with a permission error.
        // (The dummy all-zero key is what the limited unlock used to return.)
        let result = {
            let _guard = crate::storage::identity::test_identity_env_lock()
                .lock()
                .expect("env lock");
            unsafe {
                std::env::set_var("DOTLOCK_IDENTITY_DIR", &identity_dir);
            }
            let result = remove_secret_by_name(
                "FOO",
                &ProjectKey::read_only_placeholder(),
                vault_str,
                &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
            );
            unsafe {
                std::env::remove_var("DOTLOCK_IDENTITY_DIR");
            }
            result
        };
        assert!(matches!(result, Err(DotLockError::AccessDenied { .. })));

        // Both files are byte-identical: nothing was corrupted.
        assert_eq!(fs::read(&vault_path).expect("vault bytes"), vault_before);
        assert_eq!(
            fs::read(&secrets_path).expect("secrets bytes"),
            secrets_before
        );

        // The owner's full-access view still verifies integrity.
        let metadata = load_vault_metadata(&vault_path).expect("load vault");
        verify_secrets_integrity(&secrets_path, &metadata, &dek)
            .expect("owner integrity check passes");

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(identity_dir);
    }

    #[test]
    fn missing_sdk_wrapping_is_an_explicit_error_for_v5_vaults() {
        use crate::domain::error::DotLockError;

        let record = SecretRecord {
            id: "orphan-id".to_string(),
            name: "FOO".to_string(),
            alg: None,
            data: "ciphertext".to_string(),
            updated_at: 1,
            version: 0,
            kind: super::SecretKind::Static,
        };
        let dek = ProjectKey::new([8u8; 32]);

        // v5+ vault: a missing wrapping is an orphaned secret, never a silent
        // fallback to the raw project key.
        let mut v5 = metadata();
        v5.version = 5;
        let result = super::secret_key_from_project_key_or_legacy(&v5, &record, &dek);
        assert!(matches!(
            result,
            Err(DotLockError::MissingSecretKeyWrapping { ref id }) if id == "orphan-id"
        ));

        // Pre-v5 vault: legacy DEK-direct records keep working.
        let legacy = metadata();
        assert_eq!(legacy.version, 2);
        let key = super::secret_key_from_project_key_or_legacy(&legacy, &record, &dek)
            .expect("legacy fallback");
        assert_eq!(key.as_bytes(), dek.as_bytes());
    }

    /// Backward compat (H2): a legacy `version == 0` record — encrypted
    /// before AAD binding existed — must keep decrypting through
    /// `decrypt_record_with_key`, while any `version >= 1` record must
    /// authenticate against its claimed metadata.
    #[test]
    fn legacy_version_zero_records_decrypt_without_aad() {
        let key = SecretKey::new([9u8; 32]);
        // Legacy ciphertext: no AAD (empty AAD is bit-compatible with the
        // pre-AAD format).
        let encrypted = crate::crypto::secret_cipher::encryption_process_with_aad(
            "FOO".to_string(),
            "legacy-value".to_string(),
            crate::domain::model::Alg::XChaCha20Poly1305,
            &key,
            &[],
        )
        .expect("encrypt legacy");
        let record = SecretRecord {
            id: "legacy-id".to_string(),
            name: "FOO".to_string(),
            alg: None,
            data: String::from_utf8(encrypted.data).expect("utf8"),
            updated_at: 42,
            version: 0,
            kind: super::SecretKind::Static,
        };

        assert_eq!(
            super::decrypt_record_with_key(&record, &key).expect("legacy decrypt"),
            "legacy-value"
        );

        // The same no-AAD ciphertext claiming `version >= 1` must FAIL: it
        // cannot authenticate against the id/name/updated_at/version AAD.
        let mut forged = record;
        forged.version = 1;
        let err = super::decrypt_record_with_key(&forged, &key)
            .expect_err("forged version must fail authentication");
        assert!(err.to_string().contains("failed authentication"));
    }

    #[test]
    fn upsert_dynamic_secret_encrypts_provider_metadata_in_data() {
        let dir = temp_dir("dynamic-envelope");
        let secrets_path = dir.join("secrets.lock");
        let vault_path = dir.join("vault.toml");
        let dek = ProjectKey::new([8u8; 32]);
        save_vault_metadata(&vault_path, &metadata()).expect("save vault");

        let record = super::upsert_dynamic_secret(
            &secrets_path,
            "DATABASE_URL".to_string(),
            super::DynamicSecretMetadata {
                provider: "echo".to_string(),
                config: serde_json::json!({"value": "minted"}),
                bootstrap: vec!["AWS_KEY".to_string()],
                provider_path: Some("/usr/bin/dotlock-provider-echo".to_string()),
                provider_sha256: Some("sha256:test".to_string()),
            },
            &dek,
            vault_path.to_str().expect("vault path"),
            &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
        )
        .expect("upsert dynamic");

        assert!(matches!(record.kind, super::SecretKind::Dynamic { .. }));
        assert!(!record.data.contains("echo"));
        assert!(!record.data.contains("AWS_KEY"));

        let vault_metadata = load_vault_metadata(&vault_path).expect("load vault");
        let wrapped_sdk = vault_metadata
            .wrapped_sdks_under_dek
            .get(&record.id)
            .expect("wrapped sdk");
        let sdk =
            crate::crypto::sdk::unwrap_sdk_with_project_key(wrapped_sdk, &dek).expect("unwrap sdk");
        let plaintext = super::decrypt_record_with_key(&record, &sdk).expect("decrypt data");
        let metadata =
            serde_json::from_str::<super::DynamicSecretMetadata>(&plaintext).expect("metadata");
        assert_eq!(metadata.provider, "echo");
        assert_eq!(metadata.bootstrap, vec!["AWS_KEY"]);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn crash_during_upsert_never_yields_tampered_secrets_file() {
        use crate::{
            crypto::integrity::verify_secrets_integrity,
            storage::vault_txn::{CrashPoint, recover_pending, test_hooks},
        };

        for point in [
            CrashPoint::AfterTemps,
            CrashPoint::AfterJournal,
            CrashPoint::AfterVaultRename,
            CrashPoint::AfterSecretsRename,
        ] {
            let dir = temp_dir("crash-upsert");
            let secrets_path = dir.join("secrets.lock");
            let vault_path = dir.join("vault.toml");
            let vault_path_str = vault_path.to_str().expect("vault path");
            let dek = ProjectKey::new([8u8; 32]);
            save_vault_metadata(&vault_path, &metadata()).expect("save vault");

            // A first, fully committed secret.
            upsert_plain_secret(
                &secrets_path,
                "FIRST".to_string(),
                "one".to_string(),
                Alg::XChaCha20Poly1305,
                &dek,
                vault_path_str,
                &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
            )
            .expect("first upsert");

            // Second upsert crashes mid-commit.
            test_hooks::set_crash_after(Some(point));
            let result = upsert_plain_secret(
                &secrets_path,
                "SECOND".to_string(),
                "two".to_string(),
                Alg::XChaCha20Poly1305,
                &dek,
                vault_path_str,
                &mut load_vault_metadata(&vault_path).expect("load vault metadata"),
            );
            test_hooks::set_crash_after(None);
            assert!(result.is_err(), "crash at {point:?} must surface an error");

            // A new process resolves the interrupted transaction on open...
            recover_pending(&vault_path, &secrets_path).expect("recover");

            // ...and the pair is consistent: integrity check passes (never
            // TamperedSecretsFile) and every present secret is decryptable.
            let recovered_metadata = load_vault_metadata(&vault_path).expect("load metadata");
            verify_secrets_integrity(&secrets_path, &recovered_metadata, &dek)
                .expect("integrity must hold after crash+recovery");

            let file = load_secrets_file(&secrets_path).expect("load secrets");
            assert!(
                file.secrets.iter().any(|secret| secret.name == "FIRST"),
                "committed secret lost after crash at {point:?}"
            );
            for secret in &file.secrets {
                let wrapped = recovered_metadata
                    .wrapped_sdks_under_dek
                    .get(&secret.id)
                    .expect("every secret must keep its SDK wrapping");
                let sdk = crate::crypto::sdk::unwrap_sdk_with_project_key(wrapped, &dek)
                    .expect("unwrap sdk");
                super::decrypt_record_with_key(secret, &sdk)
                    .expect("secret must decrypt after crash+recovery");
            }

            let _ = fs::remove_dir_all(dir);
        }
    }
}
