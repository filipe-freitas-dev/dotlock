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

/// M9 resolved for Windows: replace the DACL of dotlock-private files and
/// directories with a single access-control entry granting full control to
/// the current user only, with inheritance from the parent severed. This is
/// the Windows counterpart of the Unix 0600/0700 modes: without it every
/// file created by dotlock would silently inherit the parent directory's
/// default ACLs (often readable by other local accounts or Administrators
/// group members on shared machines).
#[cfg(windows)]
mod win_acl {
    use std::{os::windows::ffi::OsStrExt, path::Path};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_ALL, GetLastError, HANDLE, LocalFree},
        Security::{
            Authorization::{
                EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
                SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
            },
            DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation, IsValidSid,
            NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    use crate::domain::{error::DotLockError, model::DotLockResult};

    const ERROR_SUCCESS: u32 = 0;

    fn win_err(operation: &str, code: u32) -> DotLockError {
        DotLockError::Io(format!(
            "failed to apply owner-only ACL: {operation} failed (win32 error {code})"
        ))
    }

    /// The SID of the user the current process runs as, copied out of the
    /// process token so it stays valid after the token handle is closed.
    fn current_user_sid() -> DotLockResult<Vec<u8>> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(win_err("OpenProcessToken", GetLastError()));
            }
            let result = (|| -> DotLockResult<Vec<u8>> {
                let mut needed: u32 = 0;
                GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
                if needed == 0 {
                    return Err(win_err("GetTokenInformation(size)", GetLastError()));
                }
                let mut buffer = vec![0u8; needed as usize];
                if GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                ) == 0
                {
                    return Err(win_err("GetTokenInformation", GetLastError()));
                }
                let token_user = buffer.as_ptr().cast::<TOKEN_USER>();
                let sid = (*token_user).User.Sid;
                if IsValidSid(sid) == 0 {
                    return Err(win_err("IsValidSid", GetLastError()));
                }
                let sid_len = GetLengthSid(sid) as usize;
                let mut owned = vec![0u8; sid_len];
                std::ptr::copy_nonoverlapping(sid.cast::<u8>(), owned.as_mut_ptr(), sid_len);
                Ok(owned)
            })();
            CloseHandle(token);
            result
        }
    }

    /// Replaces the DACL on `path` with one ACE: full control for the current
    /// user. `PROTECTED_DACL_SECURITY_INFORMATION` severs inheritance, so no
    /// other principal keeps access through inherited entries. Directories get
    /// an inheritable ACE so files created inside them (e.g. the vault-pair
    /// transaction journal) are born owner-only.
    ///
    /// Errors are surfaced, never swallowed: a vault file that silently kept
    /// permissive ACLs would defeat the point of the hardening.
    pub fn restrict_to_owner(path: &Path, is_directory: bool) -> DotLockResult<()> {
        let mut sid = current_user_sid()?;
        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut entry: EXPLICIT_ACCESS_W = std::mem::zeroed();
            entry.grfAccessPermissions = GENERIC_ALL;
            entry.grfAccessMode = SET_ACCESS;
            entry.grfInheritance = if is_directory {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            };
            entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
            entry.Trustee.ptstrName = sid.as_mut_ptr().cast();

            let mut acl = std::ptr::null_mut();
            let status = SetEntriesInAclW(1, &entry, std::ptr::null(), &mut acl);
            if status != ERROR_SUCCESS {
                return Err(win_err("SetEntriesInAclW", status));
            }
            let status = SetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            );
            LocalFree(acl.cast());
            if status != ERROR_SUCCESS {
                return Err(win_err("SetNamedSecurityInfoW", status));
            }
        }
        Ok(())
    }
}

/// Applies the owner-only DACL on Windows (see [`win_acl`]); no-op on Unix,
/// where the mode bits passed to `ensure_dir`/`write_string_atomic` already
/// enforce owner-only access at creation time.
#[cfg(windows)]
pub fn restrict_to_owner(path: &Path, is_directory: bool) -> DotLockResult<()> {
    win_acl::restrict_to_owner(path, is_directory)
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
    // `mode` only exists as mode bits on Unix; Windows gets the DACL instead.
    #[cfg(not(unix))]
    let _ = mode;

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
                // M9: Windows has no mode bits; instead the fresh directory
                // gets an owner-only DACL with an inheritable ACE, so files
                // created inside it are born owner-only too.
                #[cfg(windows)]
                {
                    fs::create_dir(&current)?;
                    restrict_to_owner(&current, true)?;
                }
                #[cfg(not(any(unix, windows)))]
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
        // Residual (documented in README "Security Notes > Windows"): no
        // O_NOFOLLOW equivalent here, so symlink rejection is check-then-open.
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

    // `file_mode` only exists as mode bits on Unix; Windows applies the
    // owner-only DACL to the temp file right after it is created below.
    #[cfg(not(unix))]
    let _ = file_mode;

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
    // M9: on Windows there are no mode bits; the temp file gets an owner-only
    // DACL right after creation (before any content is written), and `rename`
    // carries that DACL to the final path.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(file_mode).custom_flags(libc::O_NOFOLLOW);
    }

    let result = (|| -> DotLockResult<()> {
        let mut file = options.open(&tmp_path)?;

        #[cfg(windows)]
        restrict_to_owner(&tmp_path, false)?;

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
