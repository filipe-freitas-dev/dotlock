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

pub fn print_get_result(name: &str, id: &str, value: &str) {
    if !std::io::stdout().is_terminal() {
        println!("{}", value);
        return;
    }

    let short = short_uuid(id);
    let title = name.to_string();
    let id_line = format!("id: {}", short);
    let value_lines: Vec<&str> = if value.is_empty() {
        vec![""]
    } else {
        value.lines().collect()
    };

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
    println!(
        "  {} pipe to a command to read the value (e.g. `dl get {} | pbcopy`)",
        "hint:".cyan().bold(),
        name
    );
    println!();
}

pub fn print_secrets_table(entries: &[SecretRecord]) {
    if entries.is_empty() {
        println!("{} no secrets stored", "info:".cyan().bold());
        return;
    }

    let id_header = "ID";
    let name_header = "NAME";

    let id_w = id_header.len().max(8);
    let name_w = entries
        .iter()
        .map(|e| e.name.chars().count())
        .max()
        .unwrap_or(0)
        .max(name_header.len());

    let pad = |s: &str, w: usize| {
        let len = s.chars().count();
        if len >= w {
            s.to_string()
        } else {
            format!("{}{}", s, " ".repeat(w - len))
        }
    };

    println!();
    println!(
        "  {}  {}",
        pad(id_header, id_w).dimmed().bold(),
        pad(name_header, name_w).dimmed().bold()
    );
    println!(
        "  {}  {}",
        "─".repeat(id_w).dimmed(),
        "─".repeat(name_w).dimmed()
    );
    for entry in entries {
        let short = short_uuid(&entry.id);
        println!(
            "  {}  {}",
            pad(&short, id_w).yellow(),
            pad(&entry.name, name_w).bold()
        );
    }
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
