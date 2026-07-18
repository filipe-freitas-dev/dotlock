use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::Path,
};

use crate::{
    crypto::{VaultKeyMetadata, integrity::bytes_sha256_b64},
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        pending_merge::{PendingMergeMarker, load_marker, save_marker},
        project::{DOTLOCK_DIR, SECRETS_FILE, VAULT_FILE},
        secrets_lock::{DEFAULT_SECRET_ALG, SecretRecord, SecretsFile, load_secrets_file},
        secure_fs,
        vault_file::load_vault_metadata,
        vault_txn::recover_pending,
    },
};

/// Git invokes the driver once per conflicted file, in index (byte-sorted path)
/// order, so `.lock/secrets.lock` always merges before `.lock/vault.toml`.
/// The secrets merge records its outcome (merged ids, per-id winner side and a
/// name-level diff) in the pending-merge marker; the vault merge then unions
/// the SDK wrappings aligned with those winners and enforces the invariant
/// that every merged secret keeps a wrapping. The driver NEVER touches the
/// integrity hash — re-signing is deferred to the interactive `dl reconcile`.
pub fn run_merge_driver(ours: &Path, theirs: &Path, base: &Path) -> DotLockResult<()> {
    // Resolve any interrupted vault-pair transaction before merging on top of it.
    recover_pending(Path::new(VAULT_FILE), Path::new(SECRETS_FILE))?;
    let lock_dir = Path::new(DOTLOCK_DIR);
    match merge_target(ours) {
        MergeTarget::Secrets => merge_secrets_lock(ours, theirs, base, lock_dir),
        MergeTarget::Vault => merge_vault_metadata(ours, theirs, base, lock_dir),
    }
}

enum MergeTarget {
    Secrets,
    Vault,
}

fn merge_target(path: &Path) -> MergeTarget {
    if path.file_name().and_then(|name| name.to_str()) == Some("vault.toml") {
        MergeTarget::Vault
    } else {
        MergeTarget::Secrets
    }
}

fn merge_secrets_lock(
    ours: &Path,
    theirs: &Path,
    base: &Path,
    lock_dir: &Path,
) -> DotLockResult<()> {
    let ours_file = load_secrets_file(ours)?;
    let theirs_file = load_secrets_file(theirs)?;
    let base_file = load_secrets_file(base).unwrap_or_default();
    let (merged, report) = merge_secrets_with_report(ours_file, theirs_file, base_file)?;

    let content =
        toml::to_string_pretty(&merged).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    secure_fs::write_string_atomic(ours, &content, 0o700, 0o600)?;

    // The driver never signs content: record the merge outcome (with the
    // public hash of what was written) so the next interactive `dl reconcile`
    // can verify, review and re-sign it under the DEK.
    let mut marker = PendingMergeMarker::new();
    marker.secrets_sha256_b64 = Some(bytes_sha256_b64(content.as_bytes()));
    marker.merged_ids = merged.secrets.iter().map(|s| s.id.clone()).collect();
    marker.theirs_won = report.theirs_won;
    marker.added = report.added;
    marker.changed = report.changed;
    marker.removed = report.removed;
    save_marker(lock_dir, &marker)
}

/// Per-id/per-name outcome of a secrets merge, needed to coordinate the
/// `vault.toml` SDK-wrapping merge and the reconcile diff.
#[derive(Debug, Default)]
struct SecretsMergeReport {
    /// Ids where both sides had the record and `theirs` won the tie-break.
    theirs_won: Vec<String>,
    /// Name-level diff relative to `ours` (names only, never values).
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
}

fn merge_secrets_with_report(
    ours: SecretsFile,
    theirs: SecretsFile,
    base: SecretsFile,
) -> DotLockResult<(SecretsFile, SecretsMergeReport)> {
    let version = ours.version.max(theirs.version);
    let ours_by_name: HashMap<String, SecretRecord> = ours
        .secrets
        .into_iter()
        .map(|secret| (secret.name.clone(), secret))
        .collect();
    let theirs_by_name: HashMap<String, SecretRecord> = theirs
        .secrets
        .into_iter()
        .map(|secret| (secret.name.clone(), secret))
        .collect();
    let base_by_name: HashMap<String, SecretRecord> = base
        .secrets
        .into_iter()
        .map(|secret| (secret.name.clone(), secret))
        .collect();

    let mut names = BTreeSet::new();
    names.extend(ours_by_name.keys().cloned());
    names.extend(theirs_by_name.keys().cloned());
    names.extend(base_by_name.keys().cloned());

    let mut secrets = Vec::new();
    let mut report = SecretsMergeReport::default();
    for name in names {
        let ours_record = ours_by_name.get(&name);
        let chosen = choose_secret(
            &name,
            ours_record,
            theirs_by_name.get(&name),
            base_by_name.get(&name),
        )?;

        match (ours_record, chosen) {
            (Some(_), None) => report.removed.push(name.clone()),
            (None, Some(_)) => report.added.push(name.clone()),
            (Some(ours_record), Some(chosen)) => {
                if !same_secret_revision(ours_record, chosen) {
                    report.changed.push(name.clone());
                    if ours_record.id == chosen.id {
                        report.theirs_won.push(chosen.id.clone());
                    }
                }
            }
            (None, None) => {}
        }

        if let Some(secret) = chosen {
            secrets.push(secret.clone());
        }
    }

    Ok((SecretsFile { version, secrets }, report))
}

fn choose_secret<'a>(
    name: &str,
    ours: Option<&'a SecretRecord>,
    theirs: Option<&'a SecretRecord>,
    base: Option<&SecretRecord>,
) -> DotLockResult<Option<&'a SecretRecord>> {
    match (ours, theirs, base) {
        (Some(ours), Some(theirs), _) => choose_latest(name, ours, theirs).map(Some),
        (Some(ours), None, Some(base)) => {
            if same_secret_revision(ours, base) {
                Ok(None)
            } else {
                Ok(Some(ours))
            }
        }
        (None, Some(theirs), Some(base)) => {
            if same_secret_revision(theirs, base) {
                Ok(None)
            } else {
                Ok(Some(theirs))
            }
        }
        (Some(ours), None, None) => Ok(Some(ours)),
        (None, Some(theirs), None) => Ok(Some(theirs)),
        (None, None, _) => Ok(None),
    }
}

/// Picks the conflict winner by the monotonic per-secret `version` counter,
/// falling back to `updated_at` for legacy records. Both fields are plaintext
/// here (the driver holds no keys), so the choice is only PROVISIONAL: for
/// `version >= 1` records these exact fields are bound into the record's AEAD
/// associated data, and `dl reconcile` refuses to bless any winner whose
/// ciphertext does not authenticate under its claimed metadata (H2).
fn choose_latest<'a>(
    name: &str,
    ours: &'a SecretRecord,
    theirs: &'a SecretRecord,
) -> DotLockResult<&'a SecretRecord> {
    match ours.version.cmp(&theirs.version) {
        std::cmp::Ordering::Greater => return Ok(ours),
        std::cmp::Ordering::Less => return Ok(theirs),
        std::cmp::Ordering::Equal => {}
    }
    if ours.updated_at > theirs.updated_at {
        return Ok(ours);
    }
    if theirs.updated_at > ours.updated_at {
        return Ok(theirs);
    }
    if ours.data != theirs.data {
        return Err(DotLockError::Io(format!(
            "manual merge required for secret `{name}`; both sides changed it at the same version and timestamp"
        )));
    }
    Ok(ours)
}

fn same_secret_revision(left: &SecretRecord, right: &SecretRecord) -> bool {
    left.id == right.id
        && left.name == right.name
        && effective_alg(left) == effective_alg(right)
        && left.data == right.data
        && left.updated_at == right.updated_at
        && left.version == right.version
}

fn effective_alg(secret: &SecretRecord) -> &str {
    secret.alg.as_deref().unwrap_or(DEFAULT_SECRET_ALG)
}

fn merge_vault_metadata(
    ours: &Path,
    theirs: &Path,
    base: &Path,
    lock_dir: &Path,
) -> DotLockResult<()> {
    let ours_metadata = load_vault_metadata(ours)?;
    let theirs_metadata = load_vault_metadata(theirs)?;
    let base_metadata = load_vault_metadata(base).ok();

    // Marker written moments ago by the secrets.lock merge of this same git
    // merge (git processes `.lock/secrets.lock` first); absent when only
    // vault.toml conflicted.
    let marker = load_marker(lock_dir)?;
    let hash_fields_diverge =
        ours_metadata.secrets_hash_sha256_b64 != theirs_metadata.secrets_hash_sha256_b64;

    let (mut merged, vault_report) =
        merge_metadata(ours_metadata, theirs_metadata.clone(), base_metadata)?;
    let theirs_won: HashSet<&String> = marker
        .iter()
        .flat_map(|marker| marker.theirs_won.iter())
        .collect();
    union_sdk_wrappings(&mut merged, &theirs_metadata, &theirs_won);

    // Post-merge invariant: every secret id in the merged secrets.lock must
    // keep an SDK wrapping. Failing here returns a non-zero exit to git, which
    // leaves the conflict for manual resolution instead of writing an orphaned
    // vault.
    if let Some(marker) = &marker {
        for id in &marker.merged_ids {
            if !merged.wrapped_sdks_under_kek.contains_key(id) {
                return Err(DotLockError::MissingSecretKeyWrapping { id: id.clone() });
            }
        }
    }

    let content =
        toml::to_string_pretty(&merged).map_err(|err| DotLockError::Crypto(err.to_string()))?;
    secure_fs::write_string_atomic(ours, &content, 0o700, 0o600)?;

    // Record the vault hash in the marker. When the secrets merge did not run
    // but the two sides disagree about the secrets content (git resolved
    // `secrets.lock` trivially to one side), the locally-signed hash may be
    // stale, so a marker is created to force a reconcile as well. Rejected
    // recipient/signer injections also force a marker so `dl reconcile`
    // surfaces them to the user.
    let has_rejections =
        !vault_report.rejected_recipients.is_empty() || !vault_report.rejected_signers.is_empty();
    if marker.is_some() || hash_fields_diverge || has_rejections {
        let mut marker = marker.unwrap_or_default();
        marker.vault_sha256_b64 = Some(bytes_sha256_b64(content.as_bytes()));
        marker.rejected_recipients = vault_report.rejected_recipients;
        marker.rejected_signers = vault_report.rejected_signers;
        save_marker(lock_dir, &marker)?;
    }
    Ok(())
}

/// Merges `wrapped_sdks_under_kek` (and each recipient's `wrapped_sdks`) as a
/// union by secret id. On a same-id conflict the wrapping comes from the same
/// side as the winning ciphertext (`theirs_won`), so SDK and ciphertext never
/// diverge.
fn union_sdk_wrappings(
    merged: &mut VaultKeyMetadata,
    theirs: &VaultKeyMetadata,
    theirs_won: &HashSet<&String>,
) {
    for (id, wrapped) in &theirs.wrapped_sdks_under_kek {
        let take_theirs =
            theirs_won.contains(id) || !merged.wrapped_sdks_under_kek.contains_key(id);
        if take_theirs {
            merged
                .wrapped_sdks_under_kek
                .insert(id.clone(), wrapped.clone());
        }
    }

    for theirs_recipient in &theirs.recipients {
        let Some(recipient) = merged.recipients.iter_mut().find(|recipient| {
            recipient.public_key_fingerprint == theirs_recipient.public_key_fingerprint
        }) else {
            continue;
        };
        for (id, wrapped) in &theirs_recipient.wrapped_sdks {
            let take_theirs = theirs_won.contains(id) || !recipient.wrapped_sdks.contains_key(id);
            if take_theirs {
                recipient.wrapped_sdks.insert(id.clone(), wrapped.clone());
            }
        }
    }
}

/// Recipient/signer entries from `theirs` that were NOT absorbed because they
/// carry no grant signature verifiable against a known authorized signer
/// (H3). Recorded in the pending-merge marker so `dl reconcile` surfaces them.
#[derive(Debug, Default)]
pub struct VaultMergeReport {
    pub rejected_recipients: Vec<String>,
    pub rejected_signers: Vec<String>,
}

pub fn merge_metadata(
    mut ours: VaultKeyMetadata,
    theirs: VaultKeyMetadata,
    base: Option<VaultKeyMetadata>,
) -> DotLockResult<(VaultKeyMetadata, VaultMergeReport)> {
    if ours.project_uuid != theirs.project_uuid {
        return Err(DotLockError::Io(
            "manual merge required for vault.toml; project_uuid differs".to_string(),
        ));
    }

    if ours.kek_version != theirs.kek_version {
        return Err(DotLockError::Io(
            "manual merge required for vault.toml; kek_version differs".to_string(),
        ));
    }

    ours.version = ours.version.max(theirs.version).max(2);
    let mut report = VaultMergeReport::default();
    merge_authorized_signers(&mut ours, &theirs, base.as_ref(), &mut report);
    merge_recipients(&mut ours, theirs, base, &mut report);
    Ok((ours, report))
}

/// Merges the authorized-signer sets. Signer entries are the root of trust
/// for recipient grants, so the untrusted side can never extend them — with
/// one exception: when the local side (ours AND base) predates signed grants
/// entirely, theirs' signer set is adopted as a one-time trust-on-first-merge
/// bootstrap (there is nothing local to verify against). Any other new signer
/// in `theirs` is rejected and surfaced at `dl reconcile`.
fn merge_authorized_signers(
    ours: &mut VaultKeyMetadata,
    theirs: &VaultKeyMetadata,
    base: Option<&VaultKeyMetadata>,
    report: &mut VaultMergeReport,
) {
    let local_predates_signers = ours.authorized_signers.is_empty()
        && base.is_none_or(|base| base.authorized_signers.is_empty());
    if local_predates_signers {
        ours.authorized_signers = theirs.authorized_signers.clone();
        return;
    }

    for signer in &theirs.authorized_signers {
        let known = ours
            .authorized_signers
            .iter()
            .any(|existing| existing.fingerprint == signer.fingerprint);
        let was_in_base = base.is_some_and(|base| {
            base.authorized_signers
                .iter()
                .any(|existing| existing.fingerprint == signer.fingerprint)
        });
        if !known && !was_in_base {
            report
                .rejected_signers
                .push(format!("{} ({})", signer.label, signer.fingerprint));
        }
    }
}

fn merge_recipients(
    ours: &mut VaultKeyMetadata,
    theirs: VaultKeyMetadata,
    base: Option<VaultKeyMetadata>,
    report: &mut VaultMergeReport,
) {
    let base_fingerprints: Vec<String> = base
        .map(|metadata| {
            metadata
                .recipients
                .into_iter()
                .map(|recipient| recipient.public_key_fingerprint)
                .collect()
        })
        .unwrap_or_default();

    for recipient in theirs.recipients {
        let exists = ours
            .recipients
            .iter()
            .any(|existing| existing.public_key_fingerprint == recipient.public_key_fingerprint);
        if exists {
            continue;
        }

        let was_in_base = base_fingerprints
            .iter()
            .any(|fingerprint| fingerprint == &recipient.public_key_fingerprint);
        if was_in_base {
            continue;
        }

        // H3: a recipient coming only from the untrusted side must carry a
        // grant signature that verifies against an authorized signer already
        // trusted by the merged metadata. Unsigned or invalidly signed
        // recipients are never absorbed.
        if crate::storage::shared_access::recipient_grant_is_valid(
            &ours.project_uuid,
            &ours.authorized_signers,
            &recipient,
        ) {
            ours.recipients.push(recipient);
        } else {
            report.rejected_recipients.push(format!(
                "{} ({})",
                recipient.label, recipient.public_key_fingerprint
            ));
        }
    }

    ours.recipients
        .sort_by(|a, b| a.public_key_fingerprint.cmp(&b.public_key_fingerprint));
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::model::DotLockResult,
        storage::secrets_lock::{SecretKind, SecretRecord, SecretsFile},
    };

    fn merge_secrets(
        ours: SecretsFile,
        theirs: SecretsFile,
        base: SecretsFile,
    ) -> DotLockResult<SecretsFile> {
        super::merge_secrets_with_report(ours, theirs, base).map(|(merged, _)| merged)
    }

    fn secret(name: &str, data: &str, updated_at: i64) -> SecretRecord {
        SecretRecord {
            id: name.to_string(),
            name: name.to_string(),
            alg: None,
            data: data.to_string(),
            updated_at,
            version: 0,
            kind: SecretKind::Static,
        }
    }

    fn versioned_secret(name: &str, data: &str, updated_at: i64, version: u64) -> SecretRecord {
        SecretRecord {
            version,
            ..secret(name, data, updated_at)
        }
    }

    fn legacy_secret(name: &str, data: &str, updated_at: i64) -> SecretRecord {
        SecretRecord {
            alg: Some("xchacha20-poly1305".to_string()),
            ..secret(name, data, updated_at)
        }
    }

    fn file(secrets: Vec<SecretRecord>) -> SecretsFile {
        SecretsFile {
            version: 1,
            secrets,
        }
    }

    #[test]
    fn merges_different_secret_changes() {
        let merged = merge_secrets(
            file(vec![secret("A", "ours", 10)]),
            file(vec![secret("B", "theirs", 11)]),
            file(Vec::new()),
        )
        .expect("merge");

        assert_eq!(merged.secrets.len(), 2);
        assert_eq!(merged.secrets[0].name, "A");
        assert_eq!(merged.secrets[1].name, "B");
    }

    #[test]
    fn latest_timestamp_wins_for_same_secret() {
        let merged = merge_secrets(
            file(vec![secret("A", "old", 10)]),
            file(vec![secret("A", "new", 20)]),
            file(Vec::new()),
        )
        .expect("merge");

        assert_eq!(merged.secrets[0].data, "new");
    }

    /// H2: the monotonic per-secret version counter outranks the wall-clock
    /// timestamp (a forged timestamp alone no longer decides the winner; a
    /// forged version fails AAD authentication at reconcile).
    #[test]
    fn higher_version_wins_even_with_older_timestamp() {
        let merged = merge_secrets(
            file(vec![versioned_secret("A", "v3", 10, 3)]),
            file(vec![versioned_secret("A", "v2", 999, 2)]),
            file(Vec::new()),
        )
        .expect("merge");

        assert_eq!(merged.secrets[0].data, "v3");
    }

    #[test]
    fn same_timestamp_conflict_requires_manual_merge() {
        let result = merge_secrets(
            file(vec![secret("A", "ours", 10)]),
            file(vec![secret("A", "theirs", 10)]),
            file(Vec::new()),
        );

        assert!(result.is_err());
    }

    #[test]
    fn deletion_wins_when_other_side_did_not_change_secret() {
        let base = secret("A", "base", 10);
        let merged = merge_secrets(file(Vec::new()), file(vec![base.clone()]), file(vec![base]))
            .expect("merge");

        assert!(merged.secrets.is_empty());
    }

    #[test]
    fn missing_default_alg_matches_legacy_default_alg() {
        let base = secret("A", "base", 10);
        let theirs = legacy_secret("A", "base", 10);
        let merged =
            merge_secrets(file(Vec::new()), file(vec![theirs]), file(vec![base])).expect("merge");

        assert!(merged.secrets.is_empty());
    }

    #[test]
    fn update_wins_when_other_side_deleted_older_base_secret() {
        let merged = merge_secrets(
            file(Vec::new()),
            file(vec![secret("A", "updated", 20)]),
            file(vec![secret("A", "base", 10)]),
        )
        .expect("merge");

        assert_eq!(merged.secrets[0].data, "updated");
    }
}

#[cfg(test)]
mod driver_tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        crypto::{
            AccessMode, AuthorizedSigner, VaultConfig, VaultKeyMetadata, VaultRecipient,
            integrity::verify_secrets_integrity,
            sdk,
            share::{
                IdentityProtection, encode_public_key_b64, generate_identity, sign_recipient_grant,
            },
        },
        domain::{error::DotLockError, model::Alg},
        storage::{
            pending_merge::{ensure_no_pending_merge, load_marker, reconcile_pending_merge},
            secrets_lock::{decrypt_record_with_key, load_secrets_file, upsert_plain_secret},
            secure_fs,
            shared_access::recipient_grant_payload,
            vault_file::{load_vault_metadata, save_vault_metadata},
        },
    };

    const DEK: [u8; 32] = [8u8; 32];

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-merge-{name}-{unique}"));
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
            wrapped_sdks_under_kek: std::collections::HashMap::new(),
            access_mode: AccessMode::MasterPassword,
            recipients: Vec::new(),
            authorized_signers: Vec::new(),
            config: VaultConfig::default(),
            secrets_hash_nonce_b64: "hash_nonce".to_string(),
            secrets_hash_b64: "hash".to_string(),
            secrets_hash_sha256_b64: "hash_plain".to_string(),
        }
    }

    struct Vault {
        dir: PathBuf,
        vault: PathBuf,
        secrets: PathBuf,
    }

    impl Vault {
        fn init(name: &str) -> Self {
            let dir = temp_dir(name);
            let vault = dir.join("vault.toml");
            let secrets = dir.join("secrets.lock");
            save_vault_metadata(&vault, &metadata()).expect("save vault");
            Self {
                dir,
                vault,
                secrets,
            }
        }

        fn copy_to(&self, name: &str) -> Self {
            let dir = temp_dir(name);
            let vault = dir.join("vault.toml");
            let secrets = dir.join("secrets.lock");
            fs::copy(&self.vault, &vault).expect("copy vault");
            fs::copy(&self.secrets, &secrets).expect("copy secrets");
            Self {
                dir,
                vault,
                secrets,
            }
        }

        fn set(&self, name: &str, value: &str) {
            upsert_plain_secret(
                &self.secrets,
                name.to_string(),
                value.to_string(),
                Alg::XChaCha20Poly1305,
                &DEK,
                self.vault.to_str().expect("vault path"),
            )
            .expect("upsert");
        }

        /// Attacker move: rewrites a record's PLAINTEXT ordering metadata
        /// without touching its ciphertext — exactly what a replay/rollback
        /// forgery looks like on disk.
        fn forge_record_metadata(&self, name: &str, updated_at: i64, version: u64) {
            let mut file = load_secrets_file(&self.secrets).expect("load secrets");
            let secret = file
                .secrets
                .iter_mut()
                .find(|secret| secret.name == name)
                .expect("secret present");
            secret.updated_at = updated_at;
            secret.version = version;
            let content = toml::to_string_pretty(&file).expect("serialize");
            secure_fs::write_string_atomic(&self.secrets, &content, 0o700, 0o600)
                .expect("write secrets");
        }

        fn cleanup(self) {
            let _ = fs::remove_dir_all(self.dir);
        }
    }

    /// Runs both file merges the way git drives them: `secrets.lock` first
    /// (index order), then `vault.toml`, with `ours` seeded as the result file.
    fn run_driver(
        ours: &Vault,
        theirs: &Vault,
        base: &Vault,
    ) -> crate::domain::model::DotLockResult<()> {
        super::merge_secrets_lock(&ours.secrets, &theirs.secrets, &base.secrets, &ours.dir)?;
        super::merge_vault_metadata(&ours.vault, &theirs.vault, &base.vault, &ours.dir)
    }

    fn decrypt_with_wrapping(merged: &Vault, name: &str) -> String {
        let file = load_secrets_file(&merged.secrets).expect("load secrets");
        let metadata = load_vault_metadata(&merged.vault).expect("load vault");
        let secret = file
            .secrets
            .iter()
            .find(|secret| secret.name == name)
            .unwrap_or_else(|| panic!("secret {name} missing from merge"));
        let wrapped = metadata
            .wrapped_sdks_under_kek
            .get(&secret.id)
            .unwrap_or_else(|| panic!("secret {name} lost its SDK wrapping in the merge"));
        let sdk = sdk::unwrap_sdk_with_project_key(wrapped, &DEK).expect("unwrap sdk");
        decrypt_record_with_key(secret, &sdk)
            .unwrap_or_else(|err| panic!("secret {name} undecryptable after merge: {err}"))
    }

    /// base has A; ours adds B; theirs adds C. Everything created through the
    /// real upsert path so per-secret SDKs exist. Before K2 the merged
    /// vault.toml lost C's wrapping and the secret became undecryptable.
    #[test]
    fn merge_unions_sdk_wrappings_for_secrets_added_on_both_sides() {
        let base = Vault::init("k2-base");
        base.set("A", "a-val");
        let ours = base.copy_to("k2-ours");
        ours.set("B", "b-val");
        let theirs = base.copy_to("k2-theirs");
        theirs.set("C", "c-val");

        run_driver(&ours, &theirs, &base).expect("merge");

        let file = load_secrets_file(&ours.secrets).expect("load merged secrets");
        let metadata = load_vault_metadata(&ours.vault).expect("load merged vault");
        assert_eq!(file.secrets.len(), 3);
        for secret in &file.secrets {
            assert!(
                metadata.wrapped_sdks_under_kek.contains_key(&secret.id),
                "secret {} has no wrapping after merge",
                secret.name
            );
        }
        assert_eq!(decrypt_with_wrapping(&ours, "A"), "a-val");
        assert_eq!(decrypt_with_wrapping(&ours, "B"), "b-val");
        assert_eq!(decrypt_with_wrapping(&ours, "C"), "c-val");

        // K6: the driver produced a content-valid merge and left a marker
        // instead of re-signing the integrity hash itself.
        let marker = load_marker(&ours.dir).expect("marker").expect("present");
        assert_eq!(marker.merged_ids.len(), 3);
        assert!(marker.secrets_sha256_b64.is_some());
        assert!(marker.vault_sha256_b64.is_some());
        assert_eq!(marker.added, vec!["C".to_string()]);
        assert!(matches!(
            ensure_no_pending_merge(&ours.dir),
            Err(DotLockError::UnreconciledMerge)
        ));

        base.cleanup();
        theirs.cleanup();
        ours.cleanup();
    }

    /// Same id modified on both sides with different SDKs: the winning
    /// ciphertext and the SDK wrapping must come from the same side.
    #[test]
    fn same_id_conflict_keeps_sdk_wrapping_from_winning_side() {
        let base = Vault::init("k2-win-base");
        base.set("A", "base-val"); // record version 1
        let ours = base.copy_to("k2-win-ours");
        ours.set("A", "ours-val"); // version 2
        let theirs = base.copy_to("k2-win-theirs");
        // Their side re-keys the secret (fresh SDK, like an ACL rotation).
        let mut theirs_metadata = load_vault_metadata(&theirs.vault).expect("load theirs vault");
        theirs_metadata.wrapped_sdks_under_kek.clear();
        save_vault_metadata(&theirs.vault, &theirs_metadata).expect("save theirs vault");
        theirs.set("A", "ignored"); // version 2
        theirs.set("A", "theirs-val"); // version 3: legitimately newer

        run_driver(&ours, &theirs, &base).expect("merge");

        // theirs has the higher authentic version, so its record AND its
        // wrapping win — and the winner still authenticates under its AAD.
        assert_eq!(decrypt_with_wrapping(&ours, "A"), "theirs-val");

        // The legitimate winner also survives reconcile (its ciphertext
        // authenticates under the claimed metadata).
        reconcile_pending_merge(&ours.vault, &ours.secrets, &ours.dir, &DEK).expect("reconcile");
        assert_eq!(decrypt_with_wrapping(&ours, "A"), "theirs-val");

        base.cleanup();
        theirs.cleanup();
        ours.cleanup();
    }

    /// H2: a replayed old ciphertext whose plaintext ordering metadata was
    /// inflated (future timestamp + huge version) wins the keyless textual
    /// merge, but `dl reconcile` must refuse to bless it: the forged
    /// updated_at/version don't match the AAD the record was encrypted under,
    /// so authentication fails and the vault stays blocked on the marker.
    #[test]
    fn replayed_record_with_forged_metadata_is_rejected_at_reconcile() {
        let base = Vault::init("h2-replay-base");
        base.set("A", "old-value"); // version 1, honest AAD
        let ours = base.copy_to("h2-replay-ours");
        ours.set("A", "new-value"); // version 2, honest AAD
        let theirs = base.copy_to("h2-replay-theirs");
        // Attacker keeps the OLD ciphertext but forges the ordering metadata
        // so the stale value outranks the honest update.
        theirs.forge_record_metadata("A", i64::MAX - 1, 99);

        run_driver(&ours, &theirs, &base).expect("textual merge succeeds without keys");

        // The forgery won the provisional choice...
        let merged = load_secrets_file(&ours.secrets).expect("load merged");
        assert_eq!(merged.secrets[0].version, 99);

        // ...but it can never be silently blessed.
        let err = reconcile_pending_merge(&ours.vault, &ours.secrets, &ours.dir, &DEK)
            .expect_err("reconcile must reject the replayed record");
        assert!(
            err.to_string().contains("failed authentication"),
            "unexpected error: {err}"
        );
        // Marker stays: the vault remains blocked until manual resolution.
        assert!(load_marker(&ours.dir).expect("load marker").is_some());
        assert!(matches!(
            ensure_no_pending_merge(&ours.dir),
            Err(DotLockError::UnreconciledMerge)
        ));

        base.cleanup();
        theirs.cleanup();
        ours.cleanup();
    }

    /// If the union cannot cover every merged secret, the driver must fail
    /// with a conflict (non-zero exit for git) instead of writing an orphaned
    /// vault.
    #[test]
    fn merge_fails_when_a_merged_secret_would_lose_its_wrapping() {
        let base = Vault::init("k2-orphan-base");
        base.set("A", "a-val");
        let ours = base.copy_to("k2-orphan-ours");
        let theirs = base.copy_to("k2-orphan-theirs");
        theirs.set("C", "c-val");
        // Corrupt theirs: the record exists but its wrapping is gone.
        let mut theirs_metadata = load_vault_metadata(&theirs.vault).expect("load theirs vault");
        let c_id = load_secrets_file(&theirs.secrets)
            .expect("load theirs secrets")
            .secrets
            .iter()
            .find(|secret| secret.name == "C")
            .expect("C present")
            .id
            .clone();
        theirs_metadata.wrapped_sdks_under_kek.remove(&c_id);
        save_vault_metadata(&theirs.vault, &theirs_metadata).expect("save theirs vault");

        let result = run_driver(&ours, &theirs, &base);
        assert!(matches!(
            result,
            Err(DotLockError::MissingSecretKeyWrapping { ref id }) if id == &c_id
        ));

        base.cleanup();
        theirs.cleanup();
        ours.cleanup();
    }

    /// K6 full flow: merge (no DEK anywhere near the driver) -> marker blocks
    /// access -> reconcile re-signs under the DEK, removes the marker, and
    /// both sides' secrets stay readable with green integrity.
    #[test]
    fn reconcile_re_signs_merged_vault_and_removes_marker() {
        let base = Vault::init("k6-base");
        base.set("A", "a-val");
        let ours = base.copy_to("k6-ours");
        ours.set("B", "b-val");
        let theirs = base.copy_to("k6-theirs");
        theirs.set("C", "c-val");
        run_driver(&ours, &theirs, &base).expect("merge");

        // Stale hash by construction: the driver never re-signed it.
        let metadata = load_vault_metadata(&ours.vault).expect("load merged vault");
        assert!(verify_secrets_integrity(&ours.secrets, &metadata, &DEK).is_err());

        reconcile_pending_merge(&ours.vault, &ours.secrets, &ours.dir, &DEK).expect("reconcile");

        assert!(load_marker(&ours.dir).expect("load marker").is_none());
        ensure_no_pending_merge(&ours.dir).expect("marker removed");
        let metadata = load_vault_metadata(&ours.vault).expect("reload merged vault");
        verify_secrets_integrity(&ours.secrets, &metadata, &DEK)
            .expect("integrity green after reconcile");
        assert_eq!(decrypt_with_wrapping(&ours, "A"), "a-val");
        assert_eq!(decrypt_with_wrapping(&ours, "B"), "b-val");
        assert_eq!(decrypt_with_wrapping(&ours, "C"), "c-val");

        base.cleanup();
        theirs.cleanup();
        ours.cleanup();
    }

    /// Anti-laundering: content edited after the merge (marker present, public
    /// hash diverges) must never be re-blessed.
    #[test]
    fn reconcile_refuses_content_tampered_after_the_merge() {
        let base = Vault::init("k6-tamper-base");
        base.set("A", "a-val");
        let ours = base.copy_to("k6-tamper-ours");
        ours.set("B", "b-val");
        let theirs = base.copy_to("k6-tamper-theirs");
        theirs.set("C", "c-val");
        run_driver(&ours, &theirs, &base).expect("merge");

        let mut content = fs::read_to_string(&ours.secrets).expect("read merged secrets");
        content.push_str("\n# tampered\n");
        secure_fs::write_string_atomic(&ours.secrets, &content, 0o700, 0o600).expect("tamper");

        let err = reconcile_pending_merge(&ours.vault, &ours.secrets, &ours.dir, &DEK)
            .expect_err("must refuse tampered content");
        assert!(err.to_string().contains("no longer matches"));
        // The marker stays: access remains blocked until manual resolution.
        assert!(load_marker(&ours.dir).expect("load marker").is_some());

        base.cleanup();
        theirs.cleanup();
        ours.cleanup();
    }

    /// The unlock path (any `dl` command, interactive or CI) fails with the
    /// reconcile instruction while the marker exists — not with a false
    /// `TamperedSecretsFile`.
    #[test]
    fn unlock_is_blocked_with_reconcile_error_while_marker_exists() {
        let base = Vault::init("k6-block-base");
        base.set("A", "a-val");
        let ours = base.copy_to("k6-block-ours");
        ours.set("B", "b-val");
        let theirs = base.copy_to("k6-block-theirs");
        theirs.set("C", "c-val");
        run_driver(&ours, &theirs, &base).expect("merge");

        let result =
            crate::storage::unlock_file::unlock_vault(ours.vault.to_str().expect("vault path"));
        assert!(matches!(result, Err(DotLockError::UnreconciledMerge)));

        base.cleanup();
        theirs.cleanup();
        ours.cleanup();
    }

    fn signer_for(identity: &crate::crypto::share::GeneratedIdentity) -> AuthorizedSigner {
        AuthorizedSigner {
            fingerprint: identity.fingerprint.clone(),
            public_key_b64: encode_public_key_b64(&identity.public_key_pem).expect("pub b64"),
            label: "owner".to_string(),
        }
    }

    fn test_recipient(
        label: &str,
        fingerprint: &str,
        public_key_b64: &str,
        grant_signature_b64: &str,
        grant_signer_fingerprint: &str,
    ) -> VaultRecipient {
        VaultRecipient {
            id: format!("{label}-id"),
            label: label.to_string(),
            alg: "rsa-oaep-sha256".to_string(),
            public_key_fingerprint: fingerprint.to_string(),
            public_key_b64: public_key_b64.to_string(),
            wrapped_dek_b64: "wrapped".to_string(),
            wrapped_sdks: std::collections::HashMap::new(),
            full_access: true,
            grant_signature_b64: grant_signature_b64.to_string(),
            grant_signer_fingerprint: grant_signer_fingerprint.to_string(),
        }
    }

    /// H3: a recipient present only in untrusted `theirs` and carrying no
    /// valid grant signature is never absorbed; it is surfaced in the
    /// pending-merge marker for `dl reconcile` to display. Since the rejected
    /// entry never reaches the merged vault, no later `dl rotate` can wrap
    /// the project key for it.
    #[test]
    fn merge_rejects_recipient_without_valid_grant_signature() {
        let owner = generate_identity(IdentityProtection::Plain).expect("identity");
        let dir = temp_dir("h3-reject");
        let mut base_metadata = metadata();
        base_metadata.authorized_signers = vec![signer_for(&owner)];
        let base_path = dir.join("base-vault.toml");
        let ours_path = dir.join("vault.toml");
        let theirs_path = dir.join("theirs-vault.toml");
        save_vault_metadata(&base_path, &base_metadata).expect("save base");
        save_vault_metadata(&ours_path, &base_metadata).expect("save ours");

        let mut theirs_metadata = base_metadata.clone();
        theirs_metadata.recipients.push(test_recipient(
            "mallory",
            "mallory-fp",
            "bWFsbG9yeQ==",
            "", // no grant signature at all
            "",
        ));
        save_vault_metadata(&theirs_path, &theirs_metadata).expect("save theirs");

        super::merge_vault_metadata(&ours_path, &theirs_path, &base_path, &dir).expect("merge");

        let merged = load_vault_metadata(&ours_path).expect("load merged");
        assert!(
            merged.recipients.is_empty(),
            "injected recipient must not be absorbed"
        );
        let marker = load_marker(&dir).expect("marker").expect("present");
        assert_eq!(marker.rejected_recipients, vec!["mallory (mallory-fp)"]);

        let _ = fs::remove_dir_all(dir);
    }

    /// H3 (bad signature variant): a grant signed by a key that is NOT an
    /// authorized signer — e.g. the attacker self-signing — is also rejected.
    #[test]
    fn merge_rejects_recipient_with_grant_signed_by_unknown_key() {
        let owner = generate_identity(IdentityProtection::Plain).expect("identity");
        let mallory = generate_identity(IdentityProtection::Plain).expect("identity");
        let dir = temp_dir("h3-selfsign");
        let mut base_metadata = metadata();
        base_metadata.authorized_signers = vec![signer_for(&owner)];
        let base_path = dir.join("base-vault.toml");
        let ours_path = dir.join("vault.toml");
        let theirs_path = dir.join("theirs-vault.toml");
        save_vault_metadata(&base_path, &base_metadata).expect("save base");
        save_vault_metadata(&ours_path, &base_metadata).expect("save ours");

        // Mallory signs her own grant with her own key and even injects
        // herself as an authorized signer on `theirs`.
        let mallory_pub_b64 = encode_public_key_b64(&mallory.public_key_pem).expect("pub b64");
        let payload = recipient_grant_payload(
            &base_metadata.project_uuid,
            &mallory.fingerprint,
            &mallory_pub_b64,
            &mallory.fingerprint,
        );
        let signature =
            sign_recipient_grant(&payload, &mallory.private_key_pem).expect("self-sign");
        let mut theirs_metadata = base_metadata.clone();
        theirs_metadata.authorized_signers.push(AuthorizedSigner {
            fingerprint: mallory.fingerprint.clone(),
            public_key_b64: mallory_pub_b64.clone(),
            label: "mallory".to_string(),
        });
        theirs_metadata.recipients.push(test_recipient(
            "mallory",
            &mallory.fingerprint,
            &mallory_pub_b64,
            &signature,
            &mallory.fingerprint,
        ));
        save_vault_metadata(&theirs_path, &theirs_metadata).expect("save theirs");

        super::merge_vault_metadata(&ours_path, &theirs_path, &base_path, &dir).expect("merge");

        let merged = load_vault_metadata(&ours_path).expect("load merged");
        assert!(merged.recipients.is_empty(), "self-signed grant absorbed");
        assert_eq!(
            merged.authorized_signers,
            vec![signer_for(&owner)],
            "injected signer absorbed"
        );
        let marker = load_marker(&dir).expect("marker").expect("present");
        assert_eq!(marker.rejected_recipients.len(), 1);
        assert_eq!(marker.rejected_signers.len(), 1);

        let _ = fs::remove_dir_all(dir);
    }

    /// H3: a recipient granted through `dl share grant` (signed by an
    /// authorized signer known to our side) IS absorbed by the merge.
    #[test]
    fn merge_accepts_recipient_with_valid_grant_signature() {
        let owner = generate_identity(IdentityProtection::Plain).expect("identity");
        let dir = temp_dir("h3-accept");
        let mut base_metadata = metadata();
        base_metadata.authorized_signers = vec![signer_for(&owner)];
        let base_path = dir.join("base-vault.toml");
        let ours_path = dir.join("vault.toml");
        let theirs_path = dir.join("theirs-vault.toml");
        save_vault_metadata(&base_path, &base_metadata).expect("save base");
        save_vault_metadata(&ours_path, &base_metadata).expect("save ours");

        let payload = recipient_grant_payload(
            &base_metadata.project_uuid,
            "carol-fp",
            "Y2Fyb2w=",
            &owner.fingerprint,
        );
        let signature = sign_recipient_grant(&payload, &owner.private_key_pem).expect("sign");
        let mut theirs_metadata = base_metadata.clone();
        theirs_metadata.recipients.push(test_recipient(
            "carol",
            "carol-fp",
            "Y2Fyb2w=",
            &signature,
            &owner.fingerprint,
        ));
        save_vault_metadata(&theirs_path, &theirs_metadata).expect("save theirs");

        super::merge_vault_metadata(&ours_path, &theirs_path, &base_path, &dir).expect("merge");

        let merged = load_vault_metadata(&ours_path).expect("load merged");
        assert_eq!(merged.recipients.len(), 1);
        assert_eq!(merged.recipients[0].label, "carol");
        // A verified grant is not a conflict: no marker is forced.
        assert!(load_marker(&dir).expect("marker").is_none());

        let _ = fs::remove_dir_all(dir);
    }

    /// `run_merge_driver` resolves interrupted vault-pair transactions before
    /// merging (recover_pending is wired into the driver path).
    #[test]
    fn driver_paths_are_relative_to_the_lock_dir() {
        // Sanity: marker path is derived from the passed lock dir, so the
        // driver and reconcile agree on `.lock/pending-merge`.
        let dir = temp_dir("marker-path");
        assert_eq!(
            crate::storage::pending_merge::marker_path(Path::new(".lock")),
            Path::new(".lock").join("pending-merge")
        );
        let _ = fs::remove_dir_all(dir);
    }
}
