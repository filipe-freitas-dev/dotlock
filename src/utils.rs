use crate::{
    domain::{
        error::DotLockError,
        model::{Alg, DotLockResult},
    },
    storage::secrets_lock::SecretRecord,
};
use colored::Colorize;
use std::io::IsTerminal;

pub fn parse_alg(alg: &str) -> DotLockResult<Alg> {
    match alg {
        "xchacha20-poly1305" => Ok(Alg::XChaCha20Poly1305),
        other => Err(DotLockError::UnsupportedAlgorithm {
            alg: other.to_string(),
        }),
    }
}

pub fn normalize_var_name(name: &str) -> DotLockResult<String> {
    let mut chars = name.chars();

    let first = chars
        .next()
        .ok_or_else(|| DotLockError::InvalidVariableName {
            name: name.to_string(),
        })?;

    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(DotLockError::InvalidVariableName {
            name: name.to_string(),
        });
    }

    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(DotLockError::InvalidVariableName {
            name: name.to_string(),
        });
    }

    Ok(name.to_ascii_uppercase())
}

/// L7: fixed-width placeholder shown instead of the value on a TTY without
/// `--reveal`. Constant length so it leaks neither the value nor its size.
const TTY_VALUE_MASK: &str = "••••••••";

/// L7: the lines rendered inside the TTY box. Masked unless `--reveal` was
/// passed; NEVER used for piped output, which always prints the bare value.
fn tty_value_lines(value: &str, reveal: bool) -> Vec<&str> {
    if !reveal {
        return vec![TTY_VALUE_MASK];
    }
    if value.is_empty() {
        vec![""]
    } else {
        value.lines().collect()
    }
}

pub fn print_get_result(name: &str, id: &str, value: &str, reveal: bool) {
    if !std::io::stdout().is_terminal() {
        // Load-bearing since Phase 0/1: piped output is the bare value only
        // (`dl get X | pbcopy`), regardless of --reveal.
        println!("{}", value);
        return;
    }

    let short = short_uuid(id);
    let title = name.to_string();
    let id_line = format!("id: {}", short);
    let value_lines = tty_value_lines(value, reveal);

    let center = |s: &str, w: usize| {
        let len = s.chars().count();
        if len >= w {
            s.to_string()
        } else {
            let total = w - len;
            let left = total / 2;
            let right = total - left;
            format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
        }
    };
    let content_w = title.chars().count().max(id_line.chars().count()).max(
        value_lines
            .iter()
            .map(|line| line.chars().count())
            .max()
            .unwrap_or(0),
    );
    let inner_w = content_w + 2;

    println!();
    println!(
        "  {}{}{}",
        "┌".dimmed(),
        "─".repeat(inner_w).dimmed(),
        "┐".dimmed()
    );
    println!(
        "  {}{}{}",
        "│ ".dimmed(),
        center(&title, content_w).bold(),
        " │".dimmed()
    );
    println!(
        "  {}{}{}",
        "│ ".dimmed(),
        center(&id_line, content_w).yellow(),
        " │".dimmed()
    );
    println!(
        "  {}{}{}",
        "│ ".dimmed(),
        " ".repeat(content_w),
        " │".dimmed()
    );
    for line in value_lines {
        println!(
            "  {}{}{}",
            "│ ".dimmed(),
            center(line, content_w),
            " │".dimmed()
        );
    }
    println!(
        "  {}{}{}",
        "└".dimmed(),
        "─".repeat(content_w + 2).dimmed(),
        "┘".dimmed()
    );
    println!();
    if reveal {
        println!(
            "  {} pipe to a command to read the value (e.g. `dl get {} | pbcopy`)",
            "hint:".cyan().bold(),
            name
        );
    } else {
        println!(
            "  {} value masked on a terminal (L7); pass {} to show it here, or pipe it \
             (e.g. `dl get {} | pbcopy`)",
            "hint:".cyan().bold(),
            "--reveal".bold(),
            name
        );
    }
    println!();
}

/// Per-column cell style applied after padding, so alignment is computed on
/// the visible text rather than on ANSI escape sequences.
pub type CellStyle = fn(&str) -> colored::ColoredString;

/// Renders an aligned two-space-indented table: dimmed bold headers, a dimmed
/// `─` rule per column, then one styled row per entry. Column widths are the
/// max of the header and every cell in that column (in visible characters).
pub fn render_table(headers: &[&str], rows: &[Vec<String>], styles: &[CellStyle]) {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(col, header)| {
            rows.iter()
                .map(|row| row.get(col).map_or(0, |cell| cell.chars().count()))
                .max()
                .unwrap_or(0)
                .max(header.chars().count())
        })
        .collect();

    let pad = |s: &str, w: usize| {
        let len = s.chars().count();
        if len >= w {
            s.to_string()
        } else {
            format!("{}{}", s, " ".repeat(w - len))
        }
    };

    let header_line = headers
        .iter()
        .zip(&widths)
        .map(|(header, &w)| pad(header, w).dimmed().bold().to_string())
        .collect::<Vec<_>>()
        .join("  ");
    println!("  {header_line}");

    let rule = widths
        .iter()
        .map(|&w| "─".repeat(w).dimmed().to_string())
        .collect::<Vec<_>>()
        .join("  ");
    println!("  {rule}");

    for row in rows {
        let line = row
            .iter()
            .zip(&widths)
            .enumerate()
            .map(|(col, (cell, &w))| {
                let padded = pad(cell, w);
                match styles.get(col) {
                    Some(style) => style(&padded).to_string(),
                    None => padded,
                }
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("  {line}");
    }
}

pub fn print_secrets_table(entries: &[SecretRecord]) {
    if entries.is_empty() {
        println!("{} no secrets stored", "info:".cyan().bold());
        return;
    }

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|entry| vec![short_uuid(&entry.id), entry.name.clone()])
        .collect();

    println!();
    render_table(&["ID", "NAME"], &rows, &[|s| s.yellow(), |s| s.bold()]);
    println!();
    println!(
        "  {} {}",
        "total:".cyan().bold(),
        format!(
            "{} secret{}",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        )
        .bold()
    );
    println!();
}

pub fn short_uuid(id: &str) -> String {
    id.chars().take(8).collect()
}

pub fn report_error(err: &DotLockError) {
    eprintln!("{} {}", "error:".red().bold(), err);
    if let Some(hint) = err.hint() {
        eprintln!("{} {}", "hint: ".cyan().bold(), hint);
    }
}

#[cfg(test)]
mod tty_mask_tests {
    use super::{TTY_VALUE_MASK, tty_value_lines};

    #[test]
    fn tty_display_is_masked_by_default_and_leaks_no_length() {
        // L7: without --reveal the TTY box shows only the fixed-width mask —
        // identical for every value, so neither content nor length leaks.
        assert_eq!(tty_value_lines("hunter2", false), vec![TTY_VALUE_MASK]);
        assert_eq!(
            tty_value_lines("a-much-longer-multi\nline\nsecret", false),
            vec![TTY_VALUE_MASK]
        );
        assert_eq!(tty_value_lines("", false), vec![TTY_VALUE_MASK]);
    }

    #[test]
    fn tty_display_shows_the_value_lines_with_reveal() {
        assert_eq!(tty_value_lines("hunter2", true), vec!["hunter2"]);
        assert_eq!(tty_value_lines("a\nb", true), vec!["a", "b"]);
        assert_eq!(tty_value_lines("", true), vec![""]);
    }
}
