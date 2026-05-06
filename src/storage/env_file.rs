use std::path::Path;

use crate::{
    domain::{error::DotLockError, model::DotLockResult},
    storage::secure_fs,
};

pub struct EnvEntry {
    pub key: String,
    pub value: String,
}

pub fn parse_env_file(path: &Path) -> DotLockResult<Vec<EnvEntry>> {
    let content = secure_fs::read_to_string(path)?;
    parse_env_str(path, &content)
}

fn parse_env_str(path: &Path, content: &str) -> DotLockResult<Vec<EnvEntry>> {
    let display = path.display().to_string();
    let mut entries = Vec::new();

    for (idx, raw) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = raw.trim_start();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let after_export = trimmed
            .strip_prefix("export ")
            .unwrap_or(trimmed)
            .trim_start();

        let (key_part, value_part) = match after_export.split_once('=') {
            Some(parts) => parts,
            None => {
                return Err(DotLockError::EnvParseError {
                    path: display,
                    line: line_num,
                    message: "expected `KEY=VALUE`".to_string(),
                });
            }
        };

        let key = key_part.trim().to_string();
        if key.is_empty() {
            return Err(DotLockError::EnvParseError {
                path: display,
                line: line_num,
                message: "empty key".to_string(),
            });
        }

        let value = strip_quotes(value_part);
        entries.push(EnvEntry { key, value });
    }

    Ok(entries)
}

fn strip_quotes(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}
