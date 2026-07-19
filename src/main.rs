use std::process::ExitCode;

use clap::Parser;

use crate::{
    cli::args::{AuditArgs, Cli, Commands, ConfigArgs, GitArgs, ProviderArgs, ShareArgs},
    domain::{error::DotLockError, model::DotLockResult},
    utils::report_error,
};

mod audit;
mod cli;
mod commands;
mod crypto;
mod domain;
mod git;
mod providers;
mod runtime;
mod storage;
mod utils;

fn main() -> ExitCode {
    let cli = Cli::parse();
    // FG1/FG2 globals: recorded once, before any command can prompt or print.
    cli::global::set_json_output(cli.json);
    crypto::set_password_flag_source(if cli.password_stdin {
        Some(crypto::PasswordFlagSource::Stdin)
    } else {
        cli.password_file
            .clone()
            .map(crypto::PasswordFlagSource::File)
    });
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(DotLockError::Aborted) => ExitCode::from(130),
        Err(err) => {
            report_error(&err);
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> DotLockResult<()> {
    match cli.command {
        Commands::Init => commands::init::run(),
        Commands::Set(args) => commands::set::run(args),
        Commands::Get(args) => commands::get::run(args),
        Commands::List => commands::list::run(),
        Commands::Unset(args) => commands::unset::run(args),
        Commands::Run(args) => commands::run::run(args),
        Commands::Exec(args) => commands::exec::run(args),
        Commands::Lock => commands::lock::run(),
        Commands::Migrate(args) => commands::migrate::run(args),
        Commands::Export(args) => commands::export::run(args),
        Commands::Cert(args) => commands::cert::run(args.command),
        Commands::Share(ShareArgs { command }) => commands::share::run(command),
        Commands::Rotate(args) => commands::rotate::run(args),
        Commands::Audit(AuditArgs { command }) => commands::audit::run(command),
        Commands::Git(GitArgs { command }) => commands::git::run(command),
        Commands::GitMerge(args) => commands::git::run_merge(args),
        Commands::Config(ConfigArgs { command }) => commands::config::run(command),
        Commands::Provider(ProviderArgs { command }) => commands::provider::run(command),
        Commands::Sync => commands::sync::run(),
        Commands::Reconcile => commands::reconcile::run(),
        Commands::Repair(args) => commands::repair::run(args),
    }
}
