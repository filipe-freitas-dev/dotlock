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

fn sanitize_command(command: &[String]) -> Vec<String> {
    command
        .iter()
        .map(|arg| {
            if let Some((key, _)) = arg.split_once('=') {
                let lowered = key.to_ascii_lowercase();
                if ["token", "secret", "password", "passwd", "key"]
                    .iter()
                    .any(|needle| lowered.contains(needle))
                {
                    return format!("{key}=<redacted>");
                }
            }
            arg.clone()
        })
        .collect()
}
