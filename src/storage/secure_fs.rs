use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::domain::{error::DotLockError, model::DotLockResult};

fn invalid_path(path: &Path) -> DotLockError {
    DotLockError::Io(format!("invalid path: {}", path.display()))
}

pub fn reject_symlink(path: &Path) -> DotLockResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DotLockError::Io(format!(
            "refusing to use symlinked path: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(DotLockError::from(err)),
    }
}

fn push_component(base: &mut PathBuf, component: Component<'_>) -> DotLockResult<()> {
    match component {
        Component::Prefix(prefix) => base.push(prefix.as_os_str()),
        Component::RootDir => base.push(component.as_os_str()),
        Component::CurDir => {}
        Component::Normal(part) => base.push(part),
        Component::ParentDir => return Err(invalid_path(base)),
    }
    Ok(())
}

pub fn ensure_dir(path: &Path, mode: u32) -> DotLockResult<()> {
    let mut current = if path.is_absolute() {
        PathBuf::new()
    } else {
        PathBuf::from(".")
    };

    for component in path.components() {
        push_component(&mut current, component)?;

        if current.as_os_str().is_empty() || current == Path::new(".") {
            continue;
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(DotLockError::Io(format!(
                        "refusing to use symlinked directory: {}",
                        current.display()
                    )));
                }
                if !metadata.is_dir() {
                    return Err(DotLockError::Io(format!(
                        "expected directory but found file: {}",
                        current.display()
                    )));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&current, fs::Permissions::from_mode(mode))?;
                }
            }
            Err(err) => return Err(DotLockError::from(err)),
        }
    }

    Ok(())
}

pub fn read_to_string(path: &Path) -> DotLockResult<String> {
    reject_symlink(path)?;
    fs::read_to_string(path).map_err(DotLockError::from)
}

pub fn write_string_atomic(path: &Path, content: &str, dir_mode: u32, file_mode: u32) -> DotLockResult<()> {
    let parent = path.parent().ok_or_else(|| invalid_path(path))?;
    ensure_dir(parent, dir_mode)?;
    reject_symlink(path)?;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("dotlock"),
        unique
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(file_mode);
    }

    let result = (|| -> DotLockResult<()> {
        let mut file = options.open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(file_mode))?;
        }

        fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}
