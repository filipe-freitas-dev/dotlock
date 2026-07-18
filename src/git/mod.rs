pub mod fetch;
pub mod install;
pub mod merge;
pub mod sync;

use crate::domain::{error::DotLockError, model::DotLockResult};

/// Validates a remote or branch name before it is handed to `git` as a
/// positional argument. `auto_fetch_remote` comes from the committed
/// `vault.toml`, so anyone with write access to the repo controls it: a value
/// like `--upload-pack=<cmd>` would otherwise be parsed as an option by git
/// and execute attacker code (H1). Values must match `^[A-Za-z0-9._/-]+$`
/// and must not start with `-`.
pub fn validate_git_ref_component(kind: &str, value: &str) -> DotLockResult<()> {
    if value.is_empty() {
        return Err(DotLockError::Io(format!("{kind} cannot be empty")));
    }
    if value.starts_with('-') {
        return Err(DotLockError::Io(format!(
            "{kind} `{value}` is invalid: it must not start with `-`"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
    {
        return Err(DotLockError::Io(format!(
            "{kind} `{value}` is invalid: only [A-Za-z0-9._/-] characters are allowed"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_git_ref_component;

    #[test]
    fn accepts_common_remote_and_branch_names() {
        for value in ["origin", "upstream", "my-remote", "feature/x.y_z", "v1.0"] {
            validate_git_ref_component("remote", value).expect(value);
        }
    }

    #[test]
    fn rejects_option_injection_values() {
        for value in [
            "--upload-pack=/tmp/evil",
            "-r",
            "--exec=sh",
            "ext::sh -c id",
            "origin name",
            "",
        ] {
            assert!(
                validate_git_ref_component("remote", value).is_err(),
                "should reject `{value}`"
            );
        }
    }
}
