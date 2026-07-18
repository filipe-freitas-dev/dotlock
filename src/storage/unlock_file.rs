use base64::{Engine, engine::general_purpose};
use colored::Colorize;
use zeroize::{Zeroize, Zeroizing};

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
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        cache::{invalidate_cache, read_cached_dek, write_cached_dek},
        identity::{load_local_identity, load_local_identity_metadata},
        project::SECRETS_FILE,
        vault_file::load_vault_metadata,
        vault_txn::recover_pending,
    },
};

/// Result of unlocking the vault. Write paths must call [`UnlockAccess::require_full`]
/// so a limited (read-only) identity can never hand "a DEK" to a mutator; the
/// legacy all-zero placeholder survives only inside [`UnlockAccess::into_read_key`]
/// and is additionally rejected by every integrity-hash writer.
pub enum UnlockAccess {
    /// Full access: the real project key (DEK) was recovered.
    Full(Zeroizing<[u8; 32]>),
    /// Limited recipient: only per-secret SDKs from the recipient's
    /// `wrapped_sdks` are available; no project key exists for this identity.
    Limited,
}

impl UnlockAccess {
    /// Returns the project key, or a permission error for limited identities.
    /// Every mutating path must obtain its key through here.
    pub fn require_full(self) -> DotLockResult<Zeroizing<[u8; 32]>> {
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
    pub fn into_read_key(self) -> Zeroizing<[u8; 32]> {
        match self {
            UnlockAccess::Full(dek) => dek,
            UnlockAccess::Limited => Zeroizing::new([0u8; 32]),
        }
    }
}

/// Resolves any interrupted vault-pair transaction before the vault is read.
fn recover_pending_before_access(vault_path: &str) -> DotLockResult<()> {
    recover_pending(
        std::path::Path::new(vault_path),
        std::path::Path::new(SECRETS_FILE),
    )?;
    Ok(())
}

fn unwrap_dek_with_passphrase(
    metadata: &crate::crypto::VaultKeyMetadata,
    passphrase: &str,
) -> DotLockResult<[u8; 32]> {
    let salt = general_purpose::STANDARD
        .decode(&metadata.salt_b64)
        .map_err(|_| DotLockError::LegacyVaultFormat)?;

    let params = KdfParams {
        memory_kib: metadata.memory_kib,
        iterations: metadata.iterations,
        parallelism: metadata.parallelism,
    };

    let mut master_key = derive_master_key(passphrase, &salt, params)
        .map_err(|e| DotLockError::Crypto(e.to_string()))?;

    let mut kek = derive_kek(
        &master_key,
        &metadata.project,
        &metadata.environment,
        metadata.kek_version,
    )
    .map_err(|e| DotLockError::Crypto(e.to_string()))?;

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
    dek: [u8; 32],
) -> DotLockResult<Zeroizing<[u8; 32]>> {
    verify_secrets_integrity(SECRETS_FILE, metadata, &dek)?;
    write_cached_dek(&dek)?;
    Ok(Zeroizing::new(dek))
}

pub fn unlock_vault_with_master_password(path: &str) -> DotLockResult<Zeroizing<[u8; 32]>> {
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
) -> DotLockResult<(Zeroizing<[u8; 32]>, String)> {
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
    let dek = unwrap_dek_with_private_key(&recipient.wrapped_dek_b64, &identity.private_key_pem)?;
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

    let label_w = recipients
        .iter()
        .map(|entry| entry.label.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let fp_w = recipients
        .iter()
        .map(|entry| entry.public_key_fingerprint.len())
        .max()
        .unwrap_or(11)
        .max(11);

    println!();
    println!(
        "  {}",
        "shared recipients available for certificate unlock:"
            .cyan()
            .bold()
    );
    println!(
        "  {:label_w$}  {:fp_w$}",
        "LABEL".dimmed().bold(),
        "FINGERPRINT".dimmed().bold(),
        label_w = label_w,
        fp_w = fp_w
    );
    println!(
        "  {}  {}",
        "─".repeat(label_w).dimmed(),
        "─".repeat(fp_w).dimmed()
    );
    for recipient in recipients {
        println!(
            "  {:label_w$}  {:fp_w$}",
            recipient.label.as_str().bold(),
            recipient.public_key_fingerprint.as_str().yellow(),
            label_w = label_w,
            fp_w = fp_w
        );
    }
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
    use crate::domain::error::DotLockError;
    use zeroize::Zeroizing;

    #[test]
    fn limited_access_never_yields_a_project_key_for_writes() {
        let result = UnlockAccess::Limited.require_full();
        assert!(matches!(result, Err(DotLockError::AccessDenied { .. })));
    }

    #[test]
    fn full_access_yields_the_project_key() {
        let dek = UnlockAccess::Full(Zeroizing::new([8u8; 32]))
            .require_full()
            .expect("full access");
        assert_eq!(*dek, [8u8; 32]);
    }

    #[test]
    fn limited_read_key_is_the_all_zero_placeholder() {
        assert_eq!(*UnlockAccess::Limited.into_read_key(), [0u8; 32]);
    }
}
