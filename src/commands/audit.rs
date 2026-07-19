use colored::Colorize;

use crate::{
    audit::{audit_log_path, rotate_current_log, show_entries, verify_log},
    cli::args::AuditCommand,
    domain::model::DotLockResult,
};

pub fn run(command: AuditCommand) -> DotLockResult<()> {
    match command {
        AuditCommand::Show {
            verbose,
            since,
            action,
        } => show_entries(
            verbose,
            since.as_deref(),
            action.as_deref(),
            crate::cli::global::json_output(),
        ),
        AuditCommand::Verify { lax, strict: _ } => verify_log(!lax),
        AuditCommand::Path => {
            println!("{}", audit_log_path()?.display());
            Ok(())
        }
        AuditCommand::Rotate => {
            let path = audit_log_path()?;
            match rotate_current_log(&path)? {
                Some(rotated) => println!("{}", rotated.display()),
                None => println!("{} no audit log to rotate", "info:".cyan().bold()),
            }
            Ok(())
        }
    }
}
