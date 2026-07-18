use crate::{domain::model::DotLockResult, storage::init_project::init_project};

pub fn run() -> DotLockResult<()> {
    init_project()
}
