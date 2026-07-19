use colored::Colorize;

use crate::{
    cli::args::{GitCommand, GitMergeArgs},
    domain::model::DotLockResult,
    git::{install::install_merge_driver_if_in_git_repo, merge::run_merge_driver},
};

pub fn run(command: GitCommand) -> DotLockResult<()> {
    match command {
        GitCommand::InstallMergeDriver => {
            if install_merge_driver_if_in_git_repo()? {
                println!("{} Git merge driver installed", "ok:".green().bold());
            } else {
                println!("{} not inside a Git work tree", "info:".cyan().bold());
            }
            Ok(())
        }
    }
}

pub fn run_merge(args: GitMergeArgs) -> DotLockResult<()> {
    run_merge_driver(&args.ours, &args.theirs, &args.base, args.path.as_deref())
}
