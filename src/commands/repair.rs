//! `dl repair` (FG6): manual recovery for vaults in `TamperedSecretsFile`
//! caused by hash↔content desync (lost journals, partial backup restores,
//! historical merge bugs). NOT a tamper bypass: it requires a valid
//! full-access unlock (no DEK, no repair), keeps the metadata MAC check, and
//! every executed repair lands in the audit log. The Phase 0 skeleton
//! delivered the transactional plumbing (`recover_pending`,
//! `commit_vault_pair`); this command adds the diagnosis UX, the hash-stale
//! recompute+reseal path, and `--prune` for enumerated, explicit removal of
//! irrecoverable records.

use base64::{Engine, engine::general_purpose};
use colored::Colorize;

use crate::{
    audit::record_repair,
    cli::args::RepairArgs,
    crypto::integrity::{compute_file_sha256, decrypt_hash},
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        pending_merge::{confirmation_is_yes, ensure_no_pending_merge},
        project::{ensure_project_initialized, env_lock_dir, secrets_file, vault_file},
        secrets_lock::{
            decrypt_record_with_key, load_secrets_file, repair_reseal, resolve_record_key,
        },
        unlock_file::unlock_full_for_repair,
        vault_file::load_vault_metadata,
        vault_txn::{RecoveryOutcome, recover_pending},
    },
};

/// Per-record diagnosis outcome. Only ids/names are ever shown — no values.
struct RecordDiagnosis {
    id: String,
    name: String,
    problem: Option<String>,
}

enum HashDiagnosis {
    /// Stored hash decrypts under the DEK and matches `secrets.lock`.
    Ok,
    /// Stored hash decrypts but does not match the current content.
    Stale,
    /// Stored hash cannot be decrypted under this DEK (e.g. it was sealed
    /// under a rotated-away key) or is structurally invalid.
    Undecryptable,
}

pub fn run(args: RepairArgs) -> DotLockResult<()> {
    ensure_project_initialized()?;
    let vault_file = vault_file();
    let secrets_file = secrets_file();
    let vault_path = std::path::Path::new(&vault_file);
    let secrets_path = std::path::Path::new(&secrets_file);

    // Step 1: an interrupted transaction may BE the whole problem.
    match recover_pending(vault_path, secrets_path)? {
        RecoveryOutcome::Clean => {}
        outcome => {
            println!(
                "{} interrupted transaction resolved ({outcome:?}); re-run your command — \
                 if it still fails, run `dl repair` again",
                "ok:".green().bold()
            );
        }
    }
    // A merged-but-unreconciled vault has its own flow; repair must not
    // become a way to skip the reconcile review.
    ensure_no_pending_merge(std::path::Path::new(&env_lock_dir()))?;

    // Step 2: metadata. An unreadable vault.toml is out of scope — without
    // the wrapped DEK there is nothing to repair against.
    let metadata = load_vault_metadata(&vault_file).map_err(|_| {
        DotLockError::Io(
            "`.lock/vault.toml` is unreadable or corrupted; repair cannot proceed without it. \
             Restore it from git history (`git checkout <rev> -- .lock/vault.toml`) and re-run \
             `dl repair`"
                .to_string(),
        )
    })?;

    // Step 3: full-access unlock (FG2 non-interactive sources work here).
    // Fails on a wrong password or a MAC-tampered vault.toml BEFORE anything
    // is diagnosed or written.
    let dek = unlock_full_for_repair(&metadata)?;

    // Step 4: diagnosis (always printed; the only output under --dry-run).
    let file = load_secrets_file(secrets_path).map_err(|_| {
        DotLockError::Io(
            "`.lock/secrets.lock` does not parse; repair cannot enumerate records. Restore it \
             from git history (`git checkout <rev> -- .lock/secrets.lock`) and re-run `dl repair`"
                .to_string(),
        )
    })?;

    let mut records = Vec::new();
    for secret in &file.secrets {
        let problem = match resolve_record_key(&metadata, secret, &dek) {
            Err(DotLockError::MissingSecretKeyWrapping { .. }) => {
                Some("no SDK wrapping in `wrapped_sdks_under_kek`".to_string())
            }
            Err(_) => Some("SDK wrapping does not unwrap under this project key".to_string()),
            Ok(key) => match decrypt_record_with_key(secret, &key) {
                Ok(_) => None,
                Err(_) => Some("record AEAD fails under its SDK".to_string()),
            },
        };
        records.push(RecordDiagnosis {
            id: secret.id.clone(),
            name: secret.name.clone(),
            problem,
        });
    }

    let hash_diagnosis = diagnose_stored_hash(&metadata, &dek, secrets_path)?;
    print_diagnosis(&records, &hash_diagnosis);

    let irrecoverable: Vec<&RecordDiagnosis> = records
        .iter()
        .filter(|record| record.problem.is_some())
        .collect();
    let hash_needs_reseal = !matches!(hash_diagnosis, HashDiagnosis::Ok);

    if args.dry_run {
        println!("{} dry run: no changes were made", "info:".cyan().bold());
        return Ok(());
    }

    if irrecoverable.is_empty() && !hash_needs_reseal {
        println!(
            "{} vault is healthy; nothing to repair",
            "ok:".green().bold()
        );
        return Ok(());
    }

    // Irrecoverable records are only ever removed under the explicit,
    // enumerated `--prune` — never silently.
    if !irrecoverable.is_empty() && !args.prune {
        return Err(DotLockError::Io(format!(
            "{} record(s) are irrecoverable ({}); re-run with `--prune` to remove exactly those \
             and reseal the rest, or restore `.lock/` from a trusted git revision",
            irrecoverable.len(),
            irrecoverable
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )));
    }

    let prune_ids: Vec<String> = irrecoverable
        .iter()
        .map(|record| record.id.clone())
        .collect();
    let irrecoverable_names: Vec<String> = irrecoverable
        .iter()
        .map(|record| record.name.clone())
        .collect();

    // Confirmation: TTY prompt unless --yes.
    if !args.yes {
        if prune_ids.is_empty() {
            print!("recompute the integrity hash and reseal the vault? [y/N] ");
        } else {
            print!(
                "PERMANENTLY remove {} irrecoverable record(s) ({}) and reseal the rest? [y/N] ",
                prune_ids.len(),
                irrecoverable_names.join(", ")
            );
        }
        use std::io::Write as _;
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(DotLockError::from)?;
        if !confirmation_is_yes(&answer) {
            println!(
                "{} repair aborted; nothing was changed",
                "info:".cyan().bold()
            );
            return Err(DotLockError::Aborted);
        }
    }

    // Step 5: recompute + reseal through the transactional funnel (recomputes
    // the metadata MAC and advances the epoch, M2/M3).
    let mut metadata = metadata;
    repair_reseal(secrets_path, &vault_file, &mut metadata, &dek, &prune_ids)?;

    if let Err(err) = record_repair(hash_needs_reseal, &prune_ids, &irrecoverable_names) {
        eprintln!(
            "{} audit log write failed: {}",
            "warn:".yellow().bold(),
            err
        );
    }

    if prune_ids.is_empty() {
        println!(
            "{} integrity hash recomputed and vault resealed",
            "ok:".green().bold()
        );
    } else {
        println!(
            "{} removed {} irrecoverable record(s) ({}) and resealed the vault",
            "ok:".green().bold(),
            prune_ids.len(),
            irrecoverable_names.join(", ")
        );
    }
    Ok(())
}

fn diagnose_stored_hash(
    metadata: &crate::crypto::VaultKeyMetadata,
    dek: &crate::domain::keys::ProjectKey,
    secrets_path: &std::path::Path,
) -> DotLockResult<HashDiagnosis> {
    let Ok(nonce_bytes) = general_purpose::STANDARD.decode(&metadata.secrets_hash_nonce_b64) else {
        return Ok(HashDiagnosis::Undecryptable);
    };
    let Ok(nonce) = <[u8; 24]>::try_from(nonce_bytes) else {
        return Ok(HashDiagnosis::Undecryptable);
    };
    let Ok(ciphertext) = general_purpose::STANDARD.decode(&metadata.secrets_hash_b64) else {
        return Ok(HashDiagnosis::Undecryptable);
    };
    let Ok(stored) = decrypt_hash(&nonce, &ciphertext, dek) else {
        return Ok(HashDiagnosis::Undecryptable);
    };
    if stored == compute_file_sha256(secrets_path)? {
        Ok(HashDiagnosis::Ok)
    } else {
        Ok(HashDiagnosis::Stale)
    }
}

fn print_diagnosis(records: &[RecordDiagnosis], hash: &HashDiagnosis) {
    println!("{}", "diagnosis:".cyan().bold());
    println!("  secrets.lock parses: yes ({} record(s))", records.len());
    for record in records {
        match &record.problem {
            None => println!("  record {} ({}): ok", record.name.bold(), record.id),
            Some(problem) => println!(
                "  record {} ({}): {} {problem}",
                record.name.bold(),
                record.id,
                "IRRECOVERABLE:".red().bold()
            ),
        }
    }
    match hash {
        HashDiagnosis::Ok => println!("  integrity hash: matches the current secrets.lock"),
        HashDiagnosis::Stale => println!(
            "  integrity hash: {} decrypts under this key but does NOT match the current \
             secrets.lock content",
            "STALE:".yellow().bold()
        ),
        HashDiagnosis::Undecryptable => println!(
            "  integrity hash: {} cannot be decrypted under this project key (sealed under a \
             lost key?)",
            "UNDECRYPTABLE:".yellow().bold()
        ),
    }
}
