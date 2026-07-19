//! `dl env` (FG3): first-class multi-environment support. Each environment
//! is an INDEPENDENT vault pair — the default one in `.lock/`, named ones in
//! `.lock/envs/<name>/` — with its own Argon2id salt, KEK derivation (the
//! MAC-covered `environment` metadata field feeds `derive_kek`) and DEK, so a
//! secret set in one environment can never be read with another's keys.

use std::path::Path;

use colored::Colorize;

use crate::{
    cli::{confirm::confirm_destructive, global::json_output},
    domain::{error::DotLockError, model::DotLockResult},
    git::install::install_merge_driver_if_in_git_repo,
    storage::{init_project::init_vault_pair, project, secure_fs},
    utils::render_table,
};

use crate::cli::args::EnvCommand;

pub fn run(command: EnvCommand) -> DotLockResult<()> {
    match command {
        EnvCommand::List => list(),
        EnvCommand::Add { name } => add(&name),
        EnvCommand::Use { name } => use_env(&name),
        EnvCommand::Remove { name, yes } => remove(&name, yes),
    }
}

/// `dl env` operates on the project as a whole, so it only requires the
/// DEFAULT environment's vault (the project root), never the active one.
fn ensure_base_project_initialized() -> DotLockResult<()> {
    if Path::new(&project::vault_file_for(None)).exists() {
        return Ok(());
    }
    Err(DotLockError::ProjectNotInitialized)
}

fn list() -> DotLockResult<()> {
    ensure_base_project_initialized()?;
    let active = project::active_env_name();
    let persisted = project::persisted_default_env();
    let envs = project::list_environments();

    if json_output() {
        // FG1 schema: `[{"name", "active", "persisted_default", "path"}]`.
        let items: Vec<serde_json::Value> = envs
            .iter()
            .map(|name| {
                let env = (name != project::DEFAULT_ENV_NAME).then_some(name.as_str());
                serde_json::json!({
                    "name": name,
                    "active": *name == active,
                    "persisted_default": persisted.as_deref() == Some(name.as_str()),
                    "path": project::vault_file_for(env),
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(items));
        return Ok(());
    }

    let rows: Vec<Vec<String>> = envs
        .iter()
        .map(|name| {
            let env = (name != project::DEFAULT_ENV_NAME).then_some(name.as_str());
            vec![
                name.clone(),
                if *name == active {
                    "*".to_string()
                } else {
                    String::new()
                },
                project::vault_file_for(env),
            ]
        })
        .collect();
    render_table(
        &["ENVIRONMENT", "ACTIVE", "VAULT"],
        &rows,
        &[|s| s.bold(), |s| s.green(), |s| s.dimmed()],
    );
    Ok(())
}

fn add(name: &str) -> DotLockResult<()> {
    ensure_base_project_initialized()?;
    project::validate_env_name(name)?;
    if name == project::DEFAULT_ENV_NAME {
        return Err(DotLockError::EnvironmentAlreadyExists {
            name: name.to_string(),
        });
    }
    if Path::new(&project::vault_file_for(Some(name))).exists() {
        return Err(DotLockError::EnvironmentAlreadyExists {
            name: name.to_string(),
        });
    }

    // Prompts for THIS environment's master password (FG2 non-interactive
    // sources apply): environments may intentionally use different passwords,
    // e.g. a prod password not shared with every dev.
    println!(
        "{} creating environment {} (choose its master password)",
        "info:".cyan().bold(),
        name.bold()
    );
    init_vault_pair(Some(name))?;

    println!(
        "{} environment {} created",
        "ok:".green().bold(),
        name.bold()
    );
    println!(
        "     {} {}",
        "created".dimmed(),
        project::vault_file_for(Some(name)).bold()
    );
    println!(
        "     {} {}",
        "created".dimmed(),
        project::secrets_file_for(Some(name)).bold()
    );
    println!(
        "     select it with {} or {}",
        format!("dl --env {name} ...").bold(),
        format!("dl env use {name}").bold()
    );

    // Cover the env-scoped paths with the merge driver (re-runs are
    // idempotent; also refreshes the driver command to the %P form).
    let _ = install_merge_driver_if_in_git_repo()?;

    Ok(())
}

/// `dl env remove <name>` (L5, deferred from FG3): permanently deletes an
/// environment's entire vault pair under `.lock/envs/<name>/`. The default
/// environment can never be removed (its vault IS the project root).
fn remove(name: &str, yes: bool) -> DotLockResult<()> {
    ensure_base_project_initialized()?;
    project::validate_env_name(name)?;
    if name == project::DEFAULT_ENV_NAME {
        return Err(DotLockError::Io(
            "the default environment cannot be removed; it is the project's root vault \
             (remove the whole project by deleting `.lock/`)"
                .to_string(),
        ));
    }
    if !Path::new(&project::vault_file_for(Some(name))).exists() {
        return Err(DotLockError::EnvironmentNotInitialized {
            name: name.to_string(),
        });
    }

    println!(
        "{} this permanently deletes environment {} — every secret stored in it is lost \
         (its vault pair under {} is removed)",
        "warn:".yellow().bold(),
        name.bold(),
        project::env_lock_dir_for(Some(name)).bold()
    );
    confirm_destructive(&format!("permanently delete environment {name}"), yes)?;

    std::fs::remove_dir_all(project::env_lock_dir_for(Some(name))).map_err(DotLockError::from)?;

    // If the removed environment was the persisted default selection, drop
    // the selection file so the checkout falls back to `default` instead of
    // erroring on a dangling name.
    if project::persisted_default_env().as_deref() == Some(name) {
        std::fs::remove_file(project::ENV_SELECTION_FILE).map_err(DotLockError::from)?;
        println!(
            "{} persisted selection reset to {} (it pointed at the removed environment)",
            "info:".cyan().bold(),
            project::DEFAULT_ENV_NAME.bold()
        );
    }

    println!(
        "{} environment {} removed",
        "ok:".green().bold(),
        name.bold()
    );
    Ok(())
}

fn use_env(name: &str) -> DotLockResult<()> {
    ensure_base_project_initialized()?;
    project::validate_env_name(name)?;
    if name != project::DEFAULT_ENV_NAME
        && !Path::new(&project::vault_file_for(Some(name))).exists()
    {
        return Err(DotLockError::EnvironmentNotInitialized {
            name: name.to_string(),
        });
    }

    // Plain, NON-secret selection file: it holds only an environment name.
    secure_fs::write_string_atomic(
        Path::new(project::ENV_SELECTION_FILE),
        &format!("{name}\n"),
        0o700,
        0o600,
    )?;
    println!(
        "{} default environment set to {} (persisted in {})",
        "ok:".green().bold(),
        name.bold(),
        project::ENV_SELECTION_FILE.dimmed()
    );
    Ok(())
}
