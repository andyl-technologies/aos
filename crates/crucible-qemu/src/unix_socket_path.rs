//! Length-bounded access to Unix sockets owned by a QEMU run directory.
//!
//! QEMU creates its sockets from stable relative names after changing into the
//! run directory. On Linux, joining the same name to a long Nix build directory
//! can exceed `sockaddr_un.sun_path` even though QEMU bound the socket. These
//! helpers resolve the parent through an open directory descriptor, keeping the
//! pathname supplied to the socket syscall short without changing the socket's
//! filesystem identity.

#[cfg(target_os = "linux")]
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Connects to a filesystem Unix socket without embedding a long parent path.
pub(crate) fn connect(path: &Path) -> io::Result<UnixStream> {
    let resolved = ResolvedSocketPath::new(path)?;
    UnixStream::connect(&resolved.path)
}

/// Binds a filesystem Unix socket without embedding a long parent path.
#[cfg(target_os = "linux")]
pub(crate) fn bind(path: &Path) -> io::Result<UnixListener> {
    let resolved = ResolvedSocketPath::new(path)?;
    UnixListener::bind(&resolved.path)
}

struct ResolvedSocketPath {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    _directory: Option<File>,
}

impl ResolvedSocketPath {
    fn new(path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name())
            && !parent.as_os_str().is_empty()
        {
            let directory = File::open(parent)?;
            let resolved = PathBuf::from("/proc/self/fd")
                .join(directory.as_raw_fd().to_string())
                .join(file_name);
            return Ok(Self {
                path: resolved,
                _directory: Some(directory),
            });
        }

        Ok(Self {
            path: path.to_path_buf(),
            #[cfg(target_os = "linux")]
            _directory: None,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn descriptor_relative_path_reaches_socket_beyond_sun_path_limit() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("a".repeat(64)).join("b".repeat(64));
        std::fs::create_dir_all(&directory)?;
        let socket = directory.join("console.sock");
        assert!(socket.as_os_str().as_bytes().len() > 108);

        let listener = bind(&socket)?;
        let client = connect(&socket)?;
        let (_server, _address) = listener.accept()?;
        drop(client);
        Ok(())
    }
}
