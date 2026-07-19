use colored::Colorize;

use crate::{
    cli::args::CertCommand,
    crypto::share::IDENTITY_ALG_ED25519,
    domain::model::DotLockResult,
    storage::{
        self,
        cache::invalidate_cache,
        identity::{
            LocalIdentity, initialize_local_identity, initialize_local_identity_with_options,
            load_legacy_identity_metadata, load_local_identity, load_local_identity_metadata,
            migrate_local_identity, private_key_path, public_key_path,
        },
        project::vault_file,
        shared_access::migrate_recipient_identity,
        unlock_file::{prepare_vault_access, unlock_full_with_legacy_identity},
    },
};

pub fn run(command: CertCommand) -> DotLockResult<()> {
    match command {
        CertCommand::Init { force, plain } => {
            let identity = if plain {
                initialize_local_identity_with_options(force, true)?
            } else {
                initialize_local_identity(force)?
            };
            if plain {
                println!(
                    "{} local identity ready without passphrase ({})",
                    "ok:".green().bold(),
                    identity.fingerprint.bold()
                );
            } else {
                println!(
                    "{} local identity ready ({})",
                    "ok:".green().bold(),
                    identity.fingerprint.bold()
                );
            }
            println!(
                "     {} {}",
                "private".dimmed(),
                private_key_path()?.display()
            );
            println!(
                "     {} {}",
                "public".dimmed(),
                public_key_path()?.display()
            );
            Ok(())
        }
        CertCommand::Migrate { plain } => {
            // Step 1: identity migration (RSA -> Ed25519), keeping the RSA
            // key archived for projects that were not rekeyed yet.
            let meta = load_local_identity_metadata()?;
            let new_identity: Option<LocalIdentity> = if meta.alg == IDENTITY_ALG_ED25519 {
                println!(
                    "{} local identity already uses ed25519 ({})",
                    "info:".cyan().bold(),
                    meta.fingerprint.bold()
                );
                None
            } else {
                let (new_meta, identity) = migrate_local_identity(plain)?;
                println!(
                    "{} identity migrated to ed25519 ({})",
                    "ok:".green().bold(),
                    new_meta.fingerprint.bold()
                );
                println!(
                    "     {} legacy RSA key archived next to it; kept until every shared project is rekeyed",
                    "info:".cyan().bold()
                );
                Some(identity)
            };

            // Step 2 (best effort, per project): rekey this project's
            // recipient entry so unlocking here never touches RSA again.
            rekey_current_project_recipient(new_identity)
        }
        CertCommand::Show => {
            let identity = load_local_identity()?;
            println!(
                "{} {}",
                "fingerprint:".cyan().bold(),
                identity.fingerprint.bold()
            );
            println!(
                "{} {}",
                "algorithm:".cyan().bold(),
                crate::crypto::share::identity_alg_for_private_key(&identity.private_key_pem)?
                    .bold()
            );
            println!(
                "{} {}",
                "private:".cyan().bold(),
                private_key_path()?.display()
            );
            println!(
                "{} {}",
                "public:".cyan().bold(),
                public_key_path()?.display()
            );
            Ok(())
        }
        CertCommand::ExportPub { path } => {
            let identity = load_local_identity()?;
            if let Some(path) = path {
                storage::secure_fs::write_string_atomic(
                    &path,
                    &identity.public_key_pem,
                    0o700,
                    0o644,
                )?;
                println!(
                    "{} public key exported to {}",
                    "ok:".green().bold(),
                    path.display().to_string().bold()
                );
            } else {
                print!("{}", identity.public_key_pem);
            }
            Ok(())
        }
    }
}

/// Second half of `dl cert migrate`: rewrites THIS project's recipient entry
/// from the archived legacy (RSA) identity to the new (Ed25519) one — the
/// project key is unwrapped one final time with RSA, rewrapped as an X25519
/// sealed box, the grant is re-signed, and the resealed metadata is committed
/// transactionally. Best effort: outside a shared project (or when this
/// machine holds no legacy recipient entry) it explains and succeeds, since
/// the identity migration itself already happened.
fn rekey_current_project_recipient(new_identity: Option<LocalIdentity>) -> DotLockResult<()> {
    let Ok(legacy_meta) = load_legacy_identity_metadata() else {
        println!(
            "{} no archived legacy identity; nothing left to rekey",
            "info:".cyan().bold()
        );
        return Ok(());
    };
    let vault_path = vault_file();
    if !std::path::Path::new(&vault_path).exists() {
        println!(
            "{} not inside an initialized project; run {} in each shared project to rekey its recipient entry",
            "info:".cyan().bold(),
            "dl cert migrate".bold()
        );
        return Ok(());
    }
    let mut metadata = prepare_vault_access(&vault_path)?;
    let has_legacy_recipient = metadata
        .recipients
        .iter()
        .any(|recipient| recipient.public_key_fingerprint == legacy_meta.fingerprint);
    if !has_legacy_recipient {
        println!(
            "{} this project has no recipient entry for the legacy identity; nothing to rekey here",
            "info:".cyan().bold()
        );
        return Ok(());
    }

    // One final RSA decryption (the Marvin-affected path) recovers the
    // project key; everything from here on is Ed25519/X25519.
    let dek = unlock_full_with_legacy_identity(&metadata)?;
    let new_identity = match new_identity {
        Some(identity) => identity,
        // Identity was migrated in an earlier run; load (and decrypt) it now.
        None => load_local_identity()?,
    };
    let migrated = migrate_recipient_identity(
        &vault_path,
        &mut metadata,
        &legacy_meta.fingerprint,
        &new_identity,
        &dek,
    )?;
    invalidate_cache()?;
    let _ = crate::audit::log::append_entry(
        "cert_migrate",
        serde_json::json!({
            "old_fingerprint": legacy_meta.fingerprint,
            "new_fingerprint": migrated.public_key_fingerprint,
        }),
    );
    println!(
        "{} project recipient rekeyed to the ed25519 identity ({})",
        "ok:".green().bold(),
        migrated.public_key_fingerprint.yellow()
    );
    println!(
        "     {} this project no longer needs the legacy RSA key",
        "info:".cyan().bold()
    );
    Ok(())
}
