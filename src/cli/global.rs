//! Process-wide CLI output mode (FG1), set once in `main` after parsing so
//! deep call sites can pick human vs JSON rendering without threading a flag
//! through every command signature.

use std::sync::OnceLock;

static JSON_OUTPUT: OnceLock<bool> = OnceLock::new();

/// Records the `--json` flag; called exactly once from `main`.
pub fn set_json_output(enabled: bool) {
    let _ = JSON_OUTPUT.set(enabled);
}

/// True when `--json` was passed: read commands must emit machine-readable
/// JSON on stdout instead of tables/boxes. Defaults to human output.
pub fn json_output() -> bool {
    JSON_OUTPUT.get().copied().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_output_defaults_to_human_mode() {
        // The static is process-global; in the lib test binary nothing sets
        // it, so the default must be human output.
        assert!(!super::json_output());
    }
}
