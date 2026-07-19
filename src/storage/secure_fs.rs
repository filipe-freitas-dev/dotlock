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
                // M6: apply the mode at mkdir time so the directory is never
                // world-traversable, not even for the instant between a plain
                // `create_dir` and a follow-up chmod. The umask can only
                // remove bits, so the follow-up `set_permissions` (exact
                // mode) never loosens what mkdir granted.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new().mode(mode).create(&current)?;
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&current, fs::Permissions::from_mode(mode))?;
                }
                // M9 (documented gap): Windows has no mode bits; directories
                // inherit the parent's default ACLs, so private dirs are NOT
                // owner-only there. See "Windows file permissions" in README.
                #[cfg(not(unix))]
                fs::create_dir(&current)?;
            }
            Err(err) => return Err(DotLockError::from(err)),
        }
    }

    Ok(())
}

pub fn read_to_string(path: &Path) -> DotLockResult<String> {
    // M5: open with O_NOFOLLOW so the symlink rejection is atomic with the
    // open — no check->use window where the final component can be swapped
    // for a symlink. Parent-directory components are covered by the trust
    // model: every dotlock-private directory is created 0700 (`ensure_dir`),
    // so only the owner can replace intermediate components.
    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(path).map_err(|err| {
            if err.raw_os_error() == Some(libc::ELOOP) {
                DotLockError::Io(format!(
                    "refusing to use symlinked path: {}",
                    path.display()
                ))
            } else {
                DotLockError::from(err)
            }
        })?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }
    #[cfg(not(unix))]
    {
        // Best effort without O_NOFOLLOW: check-then-open (M9 documented gap).
        reject_symlink(path)?;
        fs::read_to_string(path).map_err(DotLockError::from)
    }
}

pub fn write_string_atomic(
    path: &Path,
    content: &str,
    dir_mode: u32,
    file_mode: u32,
) -> DotLockResult<()> {
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

    // M5: `create_new` (O_CREAT|O_EXCL) never follows a symlink at the final
    // component, and O_NOFOLLOW makes that explicit; the later `rename`
    // replaces `path` itself (a symlink there is overwritten, never followed).
    // M9 (documented gap): on Windows no mode is applied; the file inherits
    // the parent directory's default ACLs. See README.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(file_mode).custom_flags(libc::O_NOFOLLOW);
    }

    let result = (|| -> DotLockResult<()> {
        let mut file = options.open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // fchmod via the open handle (umask-proof, no path re-lookup).
            file.set_permissions(fs::Permissions::from_mode(file_mode))?;
        }

        fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{ensure_dir, read_to_string};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dotlock-securefs-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    #[test]
    fn read_to_string_rejects_symlinked_target() {
        let dir = temp_dir("symlink-read");
        let target = dir.join("real.txt");
        fs::write(&target, "secret").expect("write target");
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = read_to_string(&link).expect_err("symlink must be rejected");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );
        // The real file is still readable directly.
        assert_eq!(read_to_string(&target).expect("read"), "secret");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_dir_creates_directories_with_requested_mode() {
        let dir = temp_dir("mkdir-mode");
        let nested = dir.join("a").join("b");
        ensure_dir(&nested, 0o700).expect("ensure dir");
        for path in [dir.join("a"), nested] {
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "wrong mode on {}", path.display());
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
