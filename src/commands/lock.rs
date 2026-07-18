use colored::Colorize;

use crate::{domain::model::DotLockResult, storage::cache::invalidate_cache};

pub fn run() -> DotLockResult<()> {
    let removed = invalidate_cache()?;
    if removed {
        println!("{} session locked", "ok:".green().bold());
    } else {
        println!("{} no active session", "info:".cyan().bold());
    }
    Ok(())
}
