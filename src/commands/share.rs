use colored::Colorize;

use crate::{
    cli::{args::ShareCommand, present::print_ratchet_summary},
    commands::context::VaultContext,
    domain::{error::DotLockError, model::DotLockResult},
    storage::{
        self,
        cache::invalidate_cache,
        project::{SECRETS_FILE, VAULT_FILE, ensure_project_initialized},
        secrets_lock::{
            load_secrets_file, migrate_all_secrets_to_envelope, rotate_secret_sdks_after_acl_removal,
        },
        shared_access::{
            self, add_recipient_secret_ids, enable_shared_access, list_recipient_acl,
            list_recipients, load_public_key_from_file, revoke_recipient_and_rotate,
        },
    },
};

pub fn run(command: ShareCommand) -> DotLockResult<()> {
    match command {
        ShareCommand::Enable => {
            ensure_project_initialized()?;
            let changed = enable_shared_access(VAULT_FILE)?;
            if changed {
                println!("{} shared access enabled", "ok:".green().bold());
            } else {
                println!("{} shared access already enabled", "info:".cyan().bold());
            }
            Ok(())
        }
        ShareCommand::Grant {
            pubkey,
            label,
            allow,
        } => {
            let (ctx, _passphrase) = VaultContext::unlock_with_master_password()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            migrate_all_secrets_to_envelope(&dek, VAULT_FILE, &mut metadata)?;
            let public_key_pem = load_public_key_from_file(&pubkey)?;
            let allowed_ids = allow.as_deref().map(resolve_secret_ids_csv).transpose()?;
            // Grants must be signed by an authorized signer (H3): the
            // granting user just proved master-password authority, so
            // their local identity signs the grant (and blesses any
            // legacy unsigned recipients on pre-signed-grant vaults).
            let signer = storage::identity::load_local_identity()?;
            let recipient = shared_access::grant_recipient_with_secret_ids(
                VAULT_FILE,
                &mut metadata,
                &public_key_pem,
                &label,
                &dek,
                allowed_ids.as_deref(),
                Some(&signer),
            )?;
            println!(
                "{} access granted to {} ({})",
                "ok:".green().bold(),
                recipient.label.bold(),
                recipient.public_key_fingerprint.yellow()
            );
            Ok(())
        }
        ShareCommand::Revoke { query } => {
            let (ctx, passphrase) = VaultContext::unlock_with_master_password()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            let outcome = revoke_recipient_and_rotate(
                VAULT_FILE,
                SECRETS_FILE,
                &mut metadata,
                &query,
                &dek,
                &passphrase,
            )?;
            invalidate_cache()?;
            println!(
                "{} access revoked for {} ({}); project key rotated",
                "ok:".green().bold(),
                outcome.removed.label.bold(),
                outcome.removed.public_key_fingerprint.yellow()
            );
            print_ratchet_summary(&outcome.summary);
            println!(
                "     {} the revoked identity may still hold previously fetched ciphertexts (e.g. from git history); rotate sensitive values with {}",
                "info:".cyan().bold(),
                "dl set".bold()
            );
            Ok(())
        }
        ShareCommand::Allow {
            query,
            add,
            remove,
            list,
        } => {
            ensure_project_initialized()?;
            if list {
                let ids = list_recipient_acl(VAULT_FILE, &query)?;
                for name in secret_names_for_ids(&ids)? {
                    println!("{name}");
                }
                return Ok(());
            }

            let (ctx, _passphrase) = VaultContext::unlock_with_master_password()?;
            let VaultContext {
                mut metadata,
                access,
            } = ctx;
            let dek = access.require_full()?;
            migrate_all_secrets_to_envelope(&dek, VAULT_FILE, &mut metadata)?;

            if let Some(add) = add {
                let ids = resolve_secret_ids_csv(&add)?;
                let added = add_recipient_secret_ids(VAULT_FILE, &mut metadata, &query, &ids, &dek)?;
                println!(
                    "{} added {} secret{} to {}",
                    "ok:".green().bold(),
                    added.to_string().bold(),
                    if added == 1 { "" } else { "s" },
                    query.bold()
                );
                return Ok(());
            }

            if let Some(remove) = remove {
                let ids = resolve_secret_ids_csv(&remove)?;
                rotate_secret_sdks_after_acl_removal(&ids, &query, &dek, VAULT_FILE, &mut metadata)?;
                println!(
                    "{} removed {} secret{} from {}",
                    "ok:".green().bold(),
                    ids.len().to_string().bold(),
                    if ids.len() == 1 { "" } else { "s" },
                    query.bold()
                );
                return Ok(());
            }

            Err(DotLockError::Io(
                "pass --list, --add SECRET[,SECRET], or --remove SECRET[,SECRET]".to_string(),
            ))
        }
        ShareCommand::List => {
            ensure_project_initialized()?;
            let mut recipients = list_recipients(VAULT_FILE)?;
            recipients.sort_by(|a, b| a.label.cmp(&b.label));
            crate::cli::present::print_recipients_table(&recipients);
            Ok(())
        }
    }
}

fn resolve_secret_ids_csv(value: &str) -> DotLockResult<Vec<String>> {
    let file = load_secrets_file(SECRETS_FILE)?;
    value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            file.secrets
                .iter()
                .find(|secret| secret.name == name)
                .map(|secret| secret.id.clone())
                .ok_or_else(|| DotLockError::SecretNotFound {
                    name: name.to_string(),
                })
        })
        .collect()
}

fn secret_names_for_ids(ids: &[String]) -> DotLockResult<Vec<String>> {
    let file = load_secrets_file(SECRETS_FILE)?;
    let mut names = ids
        .iter()
        .filter_map(|id| {
            file.secrets
                .iter()
                .find(|secret| &secret.id == id)
                .map(|secret| secret.name.clone())
        })
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}
