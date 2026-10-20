//! Provides descriptor-based directory custody and bounded skeleton inspection.

use std::ffi::{CStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;

/// Retains a directory entry opened without following symbolic links.
pub struct DirectoryChild {
    /// Native single-component entry name.
    pub name: OsString,
    /// Actual independently opened child directory.
    pub directory: File,
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir created this uniquely owned stream.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

/// Opens bounded directory-only children of a retained native directory.
///
/// # Errors
/// Returns errors for files, symbolic links, cross-device children, excessive
/// entries, inaccessible descriptors or native directory enumeration failures.
pub fn directory_children(directory: &File) -> io::Result<Vec<DirectoryChild>> {
    // SAFETY: fixed dot resolves the retained directory and returns a new FD.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly owned descriptor.
    let duplicate = unsafe { File::from_raw_fd(raw) };
    let raw = duplicate.into_raw_fd();
    // SAFETY: fdopendir consumes the descriptor only on success.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and retained ownership with the caller.
        drop(unsafe { File::from_raw_fd(raw) });
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    let device = directory.metadata()?.dev();
    let mut children = Vec::new();
    loop {
        // SAFETY: errno is thread-local and readdir returns a stream-owned
        // terminated name, valid until the next call on this private stream.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream.0)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error);
            }
            break;
        }
        // SAFETY: a successful readdir entry contains a terminated d_name.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if children.len() >= 1024 {
            return Err(io::Error::other("directory skeleton entry bound exceeded"));
        }
        // SAFETY: name is terminated and valid until the next readdir call;
        // O_NOFOLLOW and O_DIRECTORY reject links and non-directory content.
        let child = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if child == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor with unique ownership.
        let child = unsafe { File::from_raw_fd(child) };
        if child.metadata()?.dev() != device {
            return Err(io::Error::other("directory skeleton crosses devices"));
        }
        children.push(DirectoryChild {
            name: OsString::from_vec(name.to_bytes().to_vec()),
            directory: child,
        });
    }
    children.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(children)
}

/// Sets ownership and mode through the retained directory descriptor.
///
/// # Errors
/// Returns privilege, filesystem or metadata verification errors. The caller
/// must already hold exclusive provisioning custody and a durable original
/// ownership record; partial progress is intentionally left fail closed.
pub fn set_directory_custody(directory: &File, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    if !directory.metadata()?.is_dir() || mode & !0o7777 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid directory custody",
        ));
    }
    // SAFETY: fchown and fchmod operate on a live borrowed descriptor only.
    if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the mode is validated and the retained descriptor remains live.
    if unsafe { libc::fchmod(directory.as_raw_fd(), mode) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let metadata = directory.metadata()?;
    if metadata.uid() != uid || metadata.gid() != gid || metadata.mode() & 0o7777 != mode {
        return Err(io::Error::other(
            "directory custody did not preserve requested ownership and mode",
        ));
    }
    directory.sync_all()
}

/// Opens one exact child directory without following symbolic links.
///
/// # Errors
/// Returns errors for non-component names, links, files, cross-device entries
/// or inaccessible directories.
pub fn open_directory_child(directory: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child name must be one component",
        ));
    }
    let name = CString::new(bytes).map_err(|_| io::Error::other("NUL in child name"))?;
    // SAFETY: the borrowed parent and terminated name remain live throughout openat.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a uniquely owned descriptor.
    let child = unsafe { File::from_raw_fd(raw) };
    if child.metadata()?.dev() != directory.metadata()?.dev() {
        return Err(io::Error::other("child crosses filesystems"));
    }
    Ok(child)
}
