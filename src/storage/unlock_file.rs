use base64::{Engine, engine::general_purpose};
use colored::Colorize;
use zeroize::Zeroize;

use crate::{
    audit::record_unlock,
    crypto::{
        AccessMode,
        dek::{WrappedDek, unwrap_dek},
        integrity::{verify_public_secrets_hash, verify_secrets_integrity},
        kdf::{KdfParams, derive_master_key},
        kek::derive_kek,
        prompt_unlock_password,
        share::unwrap_dek_with_private_key,
    },
    domain::{error::DotLockError, keys::ProjectKey, model::DotLockResult},
    storage::{
        cache::{invalidate_cache, read_cached_dek, write_cached_dek},
        identity::{load_local_identity, load_local_identity_metadata},
        pending_merge::ensure_no_pending_merge,
        project::SECRETS_FILE,
        vault_file::load_vault_metadata,
        vault_txn::recover_pending,
    },
    utils::render_table,
};

/// Result of unlocking the vault. Write paths must call [`UnlockAccess::require_full`]
/// so a limited (read-only) identity can never hand "a DEK" to a mutator; the
/// legacy all-zero placeholder survives only inside [`UnlockAccess::into_read_key`]
/// and is additionally rejected by every integrity-hash writer.
pub enum UnlockAccess {
    /// Full access: the real project key (DEK) was recovered.
    Full(ProjectKey),
    /// Limited recipient: only per-secret SDKs from the recipient's
    /// `wrapped_sdks` are available; no project key exists for this identity.
    Limited,
}

impl UnlockAccess {
    /// Returns the project key, or a permission error for limited identities.
    /// Every mutating path must obtain its key through here.
    pub fn require_full(self) -> DotLockResult<ProjectKey> {
        match self {
            UnlockAccess::Full(dek) => Ok(dek),
            UnlockAccess::Limited => Err(DotLockError::AccessDenied {
                secret: "write requires full-access recipient or master password".to_string(),
            }),
        }
    }

    /// Key handed to read-only decryption paths. Limited identities get an
    /// all-zero placeholder that can never act as a project key: their
    /// per-secret SDKs are resolved from the recipient's `wrapped_sdks`, and
    /// every write/integrity path rejects the all-zero key.
    pub fn into_read_key(self) -> ProjectKey {
        match self {
            UnlockAccess::Full(dek) => dek,
            UnlockAccess::Limited => ProjectKey::read_only_placeholder(),
        }
    }
}

/// Resolves any interrupted vault-pair transaction before the vault is read,
/// and refuses to proceed while a pending-merge marker exists: merged content
/// was never signed by a key holder, so every unlock (interactive or CI) must
/// fail with a clear "run `dl reconcile`" error instead of a false
/// `TamperedSecretsFile`.
fn recover_pending_before_access(vault_path: &str) -> DotLockResult<()> {
    let vault = std::path::Path::new(vault_path);
    recover_pending(vault, std::path::Path::new(SECRETS_FILE))?;
    let lock_dir = match vault.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    ensure_no_pending_merge(lock_dir)
}

/// Unlock used exclusively by `dl reconcile`: obtains the real project key
/// WITHOUT the integrity check (after a merge the stored hash is stale by
/// construction). The caller must verify the pending-merge marker against the
/// files first. Key correctness is still guaranteed: both the identity unwrap
/// and the password unwrap fail on wrong credentials.
pub fn unlock_full_for_reconcile(path: &str) -> DotLockResult<ProjectKey> {
    recover_pending(
        std::path::Path::new(path),
        std::path::Path::new(SECRETS_FILE),
    )?;
    let metadata = load_vault_metadata(path)?;

    if metadata.access_mode == AccessMode::Shared
        && let Ok(identity_meta) = load_local_identity_metadata()
        && let Some(recipient) = metadata
            .recipients
            .iter()
            .find(|recipient| recipient.public_key_fingerprint == identity_meta.fingerprint)
        && !recipient.wrapped_dek_b64.is_empty()
        && let Ok(identity) = load_local_identity()
    {
        let dek = ProjectKey::new(unwrap_dek_with_private_key(
            &recipient.wrapped_dek_b64,
            &identity.private_key_pem,
        )?);
        record_unlock_best_effort("identity", &metadata);
        return Ok(dek);
    }

    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(&metadata, &passphrase)?;
    record_unlock_best_effort("password", &metadata);
    Ok(dek)
}

fn unwrap_dek_with_passphrase(
    metadata: &crate::crypto::VaultKeyMetadata,
    passphrase: &str,
) -> DotLockResult<ProjectKey> {
    let salt = general_purpose::STANDARD
        .decode(&metadata.salt_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let params = KdfParams {
        memory_kib: metadata.memory_kib,
        iterations: metadata.iterations,
        parallelism: metadata.parallelism,
    };

    let mut master_key = derive_master_key(passphrase, &salt, params)?;

    let mut kek = derive_kek(
        &master_key,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )?;

    master_key.zeroize();

    let nonce = general_purpose::STANDARD
        .decode(&metadata.wrapped_dek_nonce_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let wrapped_dek = general_purpose::STANDARD
        .decode(&metadata.wrapped_dek_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let wrapped = WrappedDek {
        nonce,
        ciphertext: wrapped_dek,
    };

    let dek = unwrap_dek(&kek, &wrapped, &metadata.project, &metadata.environment)
        .map_err(|_| DotLockError::InvalidMasterPassword)?;

    kek.zeroize();
    Ok(dek)
}

fn unlock_vault_with_dek(
    metadata: &crate::crypto::VaultKeyMetadata,
    dek: ProjectKey,
) -> DotLockResult<ProjectKey> {
    verify_secrets_integrity(SECRETS_FILE, metadata, &dek)?;
    write_cached_dek(&dek)?;
    Ok(dek)
}

pub fn unlock_vault_with_master_password(path: &str) -> DotLockResult<ProjectKey> {
    recover_pending_before_access(path)?;
    let metadata = load_vault_metadata(path)?;
    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(&metadata, &passphrase)?;
    let dek = unlock_vault_with_dek(&metadata, dek)?;
    record_unlock_best_effort("password", &metadata);
    Ok(dek)
}

pub fn unlock_vault_with_master_password_and_passphrase(
    path: &str,
) -> DotLockResult<(ProjectKey, String)> {
    recover_pending_before_access(path)?;
    let metadata = load_vault_metadata(path)?;
    let passphrase = prompt_unlock_password()?;
    let dek = unwrap_dek_with_passphrase(&metadata, &passphrase)?;
    let dek = unlock_vault_with_dek(&metadata, dek)?;
    record_unlock_best_effort("password", &metadata);
    Ok((dek, passphrase))
}

fn try_unlock_vault_with_local_identity(
    metadata: &crate::crypto::VaultKeyMetadata,
) -> DotLockResult<UnlockAccess> {
    let identity_meta = load_local_identity_metadata()?;
    let recipient = metadata
        .recipients
        .iter()
        .find(|recipient| recipient.public_key_fingerprint == identity_meta.fingerprint)
        .ok_or_else(|| DotLockError::RecipientNotFound {
            query: identity_meta.fingerprint.clone(),
        })?;
    let identity = load_local_identity()?;
    if recipient.wrapped_dek_b64.is_empty() && !recipient.wrapped_sdks.is_empty() {
        verify_public_secrets_hash(SECRETS_FILE, metadata)?;
        record_unlock_best_effort("identity", metadata);
        return Ok(UnlockAccess::Limited);
    }
    let dek = ProjectKey::new(unwrap_dek_with_private_key(
        &recipient.wrapped_dek_b64,
        &identity.private_key_pem,
    )?);
    let dek = unlock_vault_with_dek(metadata, dek)?;
    record_unlock_best_effort("identity", metadata);
    Ok(UnlockAccess::Full(dek))
}

fn print_shared_recipients(metadata: &crate::crypto::VaultKeyMetadata) {
    if metadata.recipients.is_empty() {
        return;
    }

    let mut recipients = metadata.recipients.clone();
    recipients.sort_by(|a, b| a.label.cmp(&b.label));

    let rows: Vec<Vec<String>> = recipients
        .iter()
        .map(|recipient| {
            vec![
                recipient.label.clone(),
                recipient.public_key_fingerprint.clone(),
            ]
        })
        .collect();

    println!();
    println!(
        "  {}",
        "shared recipients available for certificate unlock:"
            .cyan()
            .bold()
    );
    render_table(
        &["LABEL", "FINGERPRINT"],
        &rows,
        &[|s| s.bold(), |s| s.yellow()],
    );
    println!();
}

pub fn unlock_vault(path: &str) -> DotLockResult<UnlockAccess> {
    recover_pending_before_access(path)?;
    let metadata = load_vault_metadata(path)?;

    if let Some(dek) = read_cached_dek() {
        match verify_secrets_integrity(SECRETS_FILE, &metadata, &dek) {
            Ok(()) => {
                write_cached_dek(&dek)?;
                record_unlock_best_effort("cache", &metadata);
                return Ok(UnlockAccess::Full(dek));
            }
            Err(DotLockError::TamperedSecretsFile) => {
                let _ = invalidate_cache();
                return Err(DotLockError::TamperedSecretsFile);
            }
            Err(_) => {
                let _ = invalidate_cache();
            }
        }
    }

    if metadata.access_mode == AccessMode::Shared {
        match try_unlock_vault_with_local_identity(&metadata) {
            Ok(access) => return Ok(access),
            Err(DotLockError::TamperedSecretsFile) => {
                return Err(DotLockError::TamperedSecretsFile);
            }
            Err(_) => {}
        }

        print_shared_recipients(&metadata);
    }

    unlock_vault_with_master_password(path).map(UnlockAccess::Full)
}

fn record_unlock_best_effort(method: &str, metadata: &crate::crypto::VaultKeyMetadata) {
    let access_mode = match metadata.access_mode {
        AccessMode::MasterPassword => "master",
        AccessMode::Shared => "shared",
    };
    if let Err(err) = record_unlock(method, access_mode) {
        eprintln!(
            "{} audit log write failed: {}",
            "warn:".yellow().bold(),
            err
        );
    }
}

#[cfg(test)]
mod tests {
    use super::UnlockAccess;
    use crate::domain::{error::DotLockError, keys::ProjectKey};

    #[test]
    fn limited_access_never_yields_a_project_key_for_writes() {
        let result = UnlockAccess::Limited.require_full();
        assert!(matches!(result, Err(DotLockError::AccessDenied { .. })));
    }

    #[test]
    fn full_access_yields_the_project_key() {
        let dek = UnlockAccess::Full(ProjectKey::new([8u8; 32]))
            .require_full()
            .expect("full access");
        assert_eq!(dek.as_bytes(), &[8u8; 32]);
    }

    #[test]
    fn limited_read_key_is_the_all_zero_placeholder() {
        assert!(
            UnlockAccess::Limited
                .into_read_key()
                .is_read_only_placeholder()
        );
    }
}
