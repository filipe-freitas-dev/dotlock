//! L5: confirmation gate for destructive/irreversible commands (`dl unset`,
//! `dl rotate *`, `dl share revoke`, `dl env remove`). `--yes`/`-y` skips the
//! prompt for scripting/CI; without it a TTY confirmation is required. When
//! stdin is not a TTY and `--yes` was not given, the command FAILS with an
//! actionable error instead of hanging — consistent with the FG2
//! non-interactive philosophy (never block on input that cannot arrive).

use std::io::IsTerminal;

use crate::domain::{error::DotLockError, model::DotLockResult};

/// What the gate decides to do, given the flags and the terminal state.
/// Pure so the policy is unit-testable without a pseudo-terminal.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// `--yes` was passed: proceed without prompting.
    Skip,
    /// No `--yes` and no TTY: fail fast, never hang.
    Fail,
    /// Interactive terminal: ask.
    Prompt,
}

fn gate(yes: bool, stdin_is_tty: bool) -> Gate {
    if yes {
        Gate::Skip
    } else if stdin_is_tty {
        Gate::Prompt
    } else {
        Gate::Fail
    }
}

/// Requires explicit consent before running the destructive `action`
/// (phrased as an infinitive, e.g. "permanently remove secret FOO").
/// Declining (or cancelling with Ctrl-C/Esc) aborts the command; nothing has
/// been written at that point — callers must confirm BEFORE mutating.
pub fn confirm_destructive(action: &str, yes: bool) -> DotLockResult<()> {
    match gate(yes, std::io::stdin().is_terminal()) {
        Gate::Skip => Ok(()),
        Gate::Fail => Err(DotLockError::ConfirmationRequired {
            action: action.to_string(),
        }),
        Gate::Prompt => {
            let confirmed = inquire::Confirm::new(&format!("{action}?"))
                .with_default(false)
                .prompt()
                .map_err(|err| match err {
                    inquire::InquireError::OperationCanceled
                    | inquire::InquireError::OperationInterrupted => DotLockError::Aborted,
                    other => DotLockError::Io(other.to_string()),
                })?;
            if confirmed {
                Ok(())
            } else {
                Err(DotLockError::Aborted)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Gate, gate};
    use crate::domain::error::DotLockError;

    #[test]
    fn yes_always_skips_and_no_tty_always_fails() {
        // --yes wins regardless of the terminal state.
        assert_eq!(gate(true, true), Gate::Skip);
        assert_eq!(gate(true, false), Gate::Skip);
        // No --yes: prompt only on a TTY; otherwise fail fast (never hang).
        assert_eq!(gate(false, true), Gate::Prompt);
        assert_eq!(gate(false, false), Gate::Fail);
    }

    #[test]
    fn confirmation_required_error_hints_at_yes_flag() {
        let err = DotLockError::ConfirmationRequired {
            action: "remove secret FOO".to_string(),
        };
        assert!(err.to_string().contains("remove secret FOO"));
        assert!(err.hint().expect("hint").contains("--yes"));
    }
}
