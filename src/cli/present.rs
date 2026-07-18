use colored::Colorize;

use crate::{
    crypto::VaultRecipient, storage::pending_merge::PendingMergeMarker,
    storage::vault_file::RatchetSummary, utils::render_table,
};

/// Human-readable summary of what a merge changed — secret names only, never
/// values.
pub fn print_merge_diff(marker: &PendingMergeMarker) {
    println!(
        "{} a git merge combined the vault files; the integrity hash must be re-signed",
        "info:".cyan().bold()
    );
    if marker.added.is_empty() && marker.changed.is_empty() && marker.removed.is_empty() {
        println!(
            "     {} vault metadata merged (no secret changes)",
            "info:".cyan().bold()
        );
    }
    for name in &marker.added {
        println!("     {} {}", "added".green().bold(), name.bold());
    }
    for name in &marker.changed {
        println!("     {} {}", "changed".yellow().bold(), name.bold());
    }
    for name in &marker.removed {
        println!("     {} {}", "removed".red().bold(), name.bold());
    }
    for entry in &marker.rejected_recipients {
        println!(
            "     {} recipient {} (no valid grant signature; not absorbed)",
            "rejected".red().bold(),
            entry.bold()
        );
    }
    for entry in &marker.rejected_signers {
        println!(
            "     {} authorized signer {} (unknown to this side; not absorbed)",
            "rejected".red().bold(),
            entry.bold()
        );
    }
}

pub fn print_ratchet_summary(summary: &RatchetSummary) {
    println!(
        "{} key wrapping rotated (kek_version {} -> {}, {} SDK{}, {} recipient{})",
        "ok:".green().bold(),
        summary.old_kek_version,
        summary.new_kek_version,
        summary.secrets_rewrapped.to_string().bold(),
        if summary.secrets_rewrapped == 1 {
            ""
        } else {
            "s"
        },
        summary.recipients_rewrapped.to_string().bold(),
        if summary.recipients_rewrapped == 1 {
            ""
        } else {
            "s"
        }
    );
    if summary.recipients_skipped > 0 {
        println!(
            "{} {} recipient{} skipped: grant signature did not verify against an authorized signer (re-grant with `dl share grant` or revoke)",
            "warn:".yellow().bold(),
            summary.recipients_skipped.to_string().bold(),
            if summary.recipients_skipped == 1 {
                ""
            } else {
                "s"
            }
        );
    }
}

pub fn print_recipients_table(recipients: &[VaultRecipient]) {
    if recipients.is_empty() {
        println!("{} no shared recipients", "info:".cyan().bold());
        return;
    }

    let rows: Vec<Vec<String>> = recipients
        .iter()
        .map(|recipient| {
            let access = if recipient.full_access {
                "*".to_string()
            } else {
                recipient.wrapped_sdks.len().to_string()
            };
            vec![
                recipient.label.clone(),
                recipient.public_key_fingerprint.clone(),
                access,
            ]
        })
        .collect();

    println!();
    render_table(
        &["LABEL", "FINGERPRINT", "ACCESS"],
        &rows,
        &[|s| s.bold(), |s| s.yellow()],
    );
    println!();
}
