pub mod log;
pub mod rotate;
pub mod verify;

use serde_json::json;

use crate::domain::model::DotLockResult;

pub use log::{audit_log_path, show_entries};
pub use rotate::rotate_current_log;
pub use verify::verify_log;

pub fn record_unlock(method: &str, access_mode: &str) -> DotLockResult<()> {
    log::append_entry(
        "unlock",
        json!({
            "method": method,
            "access_mode": access_mode,
        }),
    )
}

pub fn record_run(command: &[String], secrets_consumed: &[String]) -> DotLockResult<()> {
    log::append_entry(
        "run",
        json!({
            "cmd": sanitize_command(command),
            "secrets_consumed": secrets_consumed,
        }),
    )
}

pub fn record_ratchet(
    old_kek_version: u32,
    new_kek_version: u32,
    secrets_rewrapped: usize,
    recipients_rewrapped: usize,
) -> DotLockResult<()> {
    log::append_entry(
        "ratchet",
        json!({
            "old_kek_version": old_kek_version,
            "new_kek_version": new_kek_version,
            "secrets_rewrapped": secrets_rewrapped,
            "recipients_rewrapped": recipients_rewrapped,
        }),
    )
}

/// FG6: every executed repair is a security-auditable event — what kind of
/// recovery ran and exactly which record ids were pruned (never silently).
pub fn record_repair(
    hash_recomputed: bool,
    pruned_ids: &[String],
    irrecoverable_ids: &[String],
) -> DotLockResult<()> {
    log::append_entry(
        "repair",
        json!({
            "hash_recomputed": hash_recomputed,
            "pruned_ids": pruned_ids,
            "irrecoverable_ids": irrecoverable_ids,
        }),
    )
}

pub fn record_dynamic_resolve(
    provider: &str,
    secret_name: &str,
    duration_ms: u128,
    success: bool,
) -> DotLockResult<()> {
    log::append_entry(
        "dynamic_resolve",
        json!({
            "provider": provider,
            "secret_name": secret_name,
            "duration_ms": duration_ms,
            "success": success,
        }),
    )
}

fn looks_sensitive(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    if lowered == "-p" {
        // Conventional short flag for passwords (mysql, sshpass, ...).
        return true;
    }
    ["token", "secret", "password", "passwd", "key"]
        .iter()
        .any(|needle| lowered.contains(needle))
}

/// Redacts secrets from an argv before it lands in the audit log (M8): both
/// `KEY=VALUE` pairs and the value FOLLOWING a sensitive-looking flag
/// (`--token abc`, `-p hunter2`, ...).
fn sanitize_command(command: &[String]) -> Vec<String> {
    let mut sanitized = Vec::with_capacity(command.len());
    let mut redact_next = false;
    for arg in command {
        if redact_next {
            redact_next = false;
            sanitized.push("<redacted>".to_string());
            continue;
        }
        if let Some((key, _)) = arg.split_once('=') {
            if looks_sensitive(key) {
                sanitized.push(format!("{key}=<redacted>"));
                continue;
            }
        } else if arg.starts_with('-') && looks_sensitive(arg) {
            // Space-separated form: the NEXT token is the secret.
            redact_next = true;
        }
        sanitized.push(arg.clone());
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::sanitize_command;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    #[test]
    fn sanitize_command_redacts_key_value_pairs() {
        assert_eq!(
            sanitize_command(&args(&["deploy", "API_TOKEN=abc123", "REGION=eu"])),
            args(&["deploy", "API_TOKEN=<redacted>", "REGION=eu"])
        );
    }

    #[test]
    fn sanitize_command_redacts_value_after_sensitive_flag() {
        assert_eq!(
            sanitize_command(&args(&["tool", "--token", "abc123", "--verbose"])),
            args(&["tool", "--token", "<redacted>", "--verbose"])
        );
        assert_eq!(
            sanitize_command(&args(&["mysql", "-p", "hunter2"])),
            args(&["mysql", "-p", "<redacted>"])
        );
        assert_eq!(
            sanitize_command(&args(&["curl", "--api-key", "k-123", "https://x"])),
            args(&["curl", "--api-key", "<redacted>", "https://x"])
        );
    }

    #[test]
    fn sanitize_command_redacts_sensitive_flag_in_equals_form() {
        assert_eq!(
            sanitize_command(&args(&["tool", "--password=letmein"])),
            args(&["tool", "--password=<redacted>"])
        );
    }

    #[test]
    fn sanitize_command_keeps_normal_arguments() {
        let command = args(&["npm", "run", "build", "--", "--watch"]);
        assert_eq!(sanitize_command(&command), command);
    }

    #[test]
    fn sanitize_command_handles_trailing_sensitive_flag() {
        // Sensitive flag with no following value must not panic or misalign.
        assert_eq!(
            sanitize_command(&args(&["tool", "--token"])),
            args(&["tool", "--token"])
        );
    }
}
