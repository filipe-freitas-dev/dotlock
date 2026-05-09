use std::{collections::HashSet, path::Path};

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

pub fn parse_env_content(path: &Path, content: &str) -> DotLockResult<Vec<EnvEntry>> {
    parse_env_str(path, content)
}

pub fn merge_exported_env_content(
    existing: Option<&str>,
    entries: &[EnvEntry],
) -> DotLockResult<EnvMergeResult> {
    let mut existing_keys = HashSet::new();
    let mut base = existing.unwrap_or_default().to_string();

    if let Some(content) = existing {
        for entry in parse_env_content(Path::new(".env"), content)? {
            existing_keys.insert(entry.key);
        }
    }

    let mut pending: Vec<&EnvEntry> = entries
        .iter()
        .filter(|entry| !existing_keys.contains(&entry.key))
        .collect();
    pending.sort_by(|a, b| a.key.cmp(&b.key));

    if pending.is_empty() {
        return Ok(EnvMergeResult {
            content: base,
            added: 0,
            skipped: entries.len(),
        });
    }

    if !base.is_empty() && !base.ends_with('\n') {
        base.push('\n');
    }

    for entry in &pending {
        base.push_str(&serialize_env_entry(entry));
        base.push('\n');
    }

    Ok(EnvMergeResult {
        content: base,
        added: pending.len(),
        skipped: entries.len() - pending.len(),
    })
}

pub fn write_env_file(path: &Path, content: &str) -> DotLockResult<()> {
    secure_fs::write_string_atomic(path, content, 0o700, 0o600)
}

pub struct EnvMergeResult {
    pub content: String,
    pub added: usize,
    pub skipped: usize,
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

        let value = parse_value(value_part)?;
        entries.push(EnvEntry { key, value });
    }

    Ok(entries)
}

fn parse_value(raw: &str) -> DotLockResult<String> {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            let inner = &trimmed[1..trimmed.len() - 1];
            if first == b'"' {
                return unescape_double_quoted(inner);
            }
            return Ok(inner.to_string());
        }
    }
    Ok(trimmed.to_string())
}

fn unescape_double_quoted(raw: &str) -> DotLockResult<String> {
    let mut output = String::with_capacity(raw.len());
    let mut chars = raw.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }

        let escaped = chars
            .next()
            .ok_or_else(|| DotLockError::Io("invalid escaped env value".to_string()))?;
        match escaped {
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            '\\' => output.push('\\'),
            '"' => output.push('"'),
            other => output.push(other),
        }
    }

    Ok(output)
}

pub fn serialize_env_entry(entry: &EnvEntry) -> String {
    format!("{}={}", entry.key, serialize_env_value(&entry.value))
}

fn serialize_env_value(value: &str) -> String {
    if !needs_quotes(value) {
        return value.to_string();
    }

    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

fn needs_quotes(value: &str) -> bool {
    value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '#' | '"' | '\'' | '\\' | '='))
}

#[cfg(test)]
mod tests {
    use super::{EnvEntry, merge_exported_env_content, parse_env_content, serialize_env_entry};
    use std::path::Path;

    #[test]
    fn parses_double_quoted_escaped_values() {
        let entries = parse_env_content(
            Path::new(".env"),
            "API_KEY=\"hello\\nworld\"\nQUOTE=\"say \\\"hi\\\"\"\n",
        )
        .expect("parse env");

        assert_eq!(entries[0].value, "hello\nworld");
        assert_eq!(entries[1].value, "say \"hi\"");
    }

    #[test]
    fn serializes_values_with_escaping() {
        let rendered = serialize_env_entry(&EnvEntry {
            key: "API_KEY".to_string(),
            value: "hello\n\"world\"".to_string(),
        });

        assert_eq!(rendered, "API_KEY=\"hello\\n\\\"world\\\"\"");
    }

    #[test]
    fn merges_only_missing_keys_into_existing_env() {
        let result = merge_exported_env_content(
            Some("FOO=bar\nEXISTING=1\n"),
            &[
                EnvEntry {
                    key: "EXISTING".to_string(),
                    value: "2".to_string(),
                },
                EnvEntry {
                    key: "NEW_KEY".to_string(),
                    value: "hello world".to_string(),
                },
            ],
        )
        .expect("merge env");

        assert_eq!(result.added, 1);
        assert_eq!(result.skipped, 1);
        assert_eq!(
            result.content,
            "FOO=bar\nEXISTING=1\nNEW_KEY=\"hello world\"\n"
        );
    }
}
