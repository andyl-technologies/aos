//! Acquires one retained control socket under the original SDK physical cut.
//!
//! The installed Source consumes its separate opaque action before calling
//! this primitive. A path, data quote or successful socket is never permission
//! to construct a controller or dispatch an initial control method. The caller
//! retains the output slot across the Source's terminal same-Child checks.

use std::{
    ffi::CStr,
    mem::size_of,
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
};

use super::OriginalPacketHostStartup;
use crate::ProviderError;

// Linux sockaddr_un.sun_path has 108 bytes, including its terminating NUL.
// Passing a borrowed CStr avoids a temporary Path/CString allocation in Arg.
const SOCKET_PATH_BYTES: usize = 108;

/// Counts explicit socket-address, descriptor and borrowed error headers.
///
/// The original SDK deadline and actual output slot are independently owned.
/// Kernel socket resources, compiler frames and allocator physical overhead
/// are separate from this fixed requested-storage declaration.
pub fn original_packet_host_initial_socket_counter_scratch_data() -> usize {
    size_of::<SocketPath>()
        + size_of::<rustix::net::SocketAddrUnix>()
        + size_of::<OwnedFd>()
        + size_of::<UnixStream>()
        + size_of::<std::io::Error>()
        + size_of::<rustix::io::Errno>()
        + size_of::<ProviderError>()
        + size_of::<&CStr>()
        + size_of::<&Path>()
        + size_of::<crate::operational_time::OperationalDeadline>()
        + size_of::<std::time::Duration>()
}

impl OriginalPacketHostStartup {
    /// Acquires the same selected initial socket without renewing its deadline.
    ///
    /// The Source's actual installed action authenticates the path against its
    /// original launch guard and spends the socket phase before this call. This
    /// SDK primitive supplies custody only. It stores the actual descriptor in
    /// `completed` before connect, flag changes or terminal deadline checks can
    /// refuse. It never replaces a failed descriptor or retries the connection.
    ///
    /// # Errors
    /// Refuses a foreign, partial or connected SDK root, occupied output,
    /// invalid path, expired original cut or unavailable socket/connection. Any
    /// descriptor already created remains in the caller's original output slot.
    pub fn acquire_original_initial_socket_into(
        &self,
        path: &Path,
        completed: &mut Option<UnixStream>,
    ) -> Result<(), ProviderError> {
        self.creator.ensure_current()?;
        if !self.prepared
            || self.preparing
            || self.connecting
            || self.connected
            || self.failure.is_some()
            || self.stream.is_some()
            || self.hello_attempt.is_some()
            || self.session.is_some()
            || self.controller.is_some()
            || completed.is_some()
        {
            return Err(refused());
        }
        let deadline = self.deadline.as_ref().ok_or_else(refused)?;
        check_deadline(deadline)?;
        let original_path = SocketPath::new(path)?;
        let address = rustix::net::SocketAddrUnix::new(original_path.as_c_str()?)
            .map_err(std::io::Error::from)?;
        let socket = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(std::io::Error::from)?;
        *completed = Some(UnixStream::from(socket));

        let stream = completed.as_ref().ok_or_else(refused)?;
        // A full listen backlog must refuse instead of spending an unbounded
        // blocking interval outside the same original physical cut.
        rustix::net::connect(stream, &address).map_err(std::io::Error::from)?;
        stream.set_nonblocking(false)?;
        check_deadline(deadline)?;
        self.creator.ensure_current()
    }
}

fn check_deadline(deadline: &super::ExchangeDeadline) -> Result<(), ProviderError> {
    deadline
        .original_cut()
        .remaining()
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or_else(refused)
}

struct SocketPath {
    bytes: [u8; SOCKET_PATH_BYTES],
    used: usize,
}

impl SocketPath {
    fn new(path: &Path) -> Result<Self, ProviderError> {
        let original = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || original.is_empty()
            || original.len() >= SOCKET_PATH_BYTES
            || original.contains(&0)
        {
            return Err(refused());
        }
        let mut bytes = [0; SOCKET_PATH_BYTES];
        bytes[..original.len()].copy_from_slice(original);
        Ok(Self {
            bytes,
            used: original.len() + 1,
        })
    }

    fn as_c_str(&self) -> Result<&CStr, ProviderError> {
        CStr::from_bytes_with_nul(&self.bytes[..self.used]).map_err(|_| refused())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original initial control socket custody")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, path::PathBuf};

    #[test]
    fn original_initial_socket_path_preserves_full_borrowed_octets() {
        let mut original = vec![b'/'];
        original.extend(std::iter::repeat_n(b'x', SOCKET_PATH_BYTES - 2));
        let path = PathBuf::from(OsStr::from_bytes(&original));
        let fixed = SocketPath::new(&path).unwrap();

        assert_eq!(fixed.as_c_str().unwrap().to_bytes(), original);
        assert_eq!(fixed.used, SOCKET_PATH_BYTES);
        assert_eq!(path.as_os_str().as_bytes(), original);
        assert!(
            original_packet_host_initial_socket_counter_scratch_data()
                >= size_of::<SocketPath>() + size_of::<rustix::net::SocketAddrUnix>()
        );
    }

    #[test]
    fn original_initial_socket_path_refuses_nul_relative_and_overwide_without_io() {
        let mut overwide = vec![b'/'];
        overwide.extend(std::iter::repeat_n(b'x', SOCKET_PATH_BYTES - 1));
        let candidates = [
            PathBuf::from("relative/control.sock"),
            PathBuf::from(OsStr::from_bytes(b"/tmp/a\0b")),
            PathBuf::from(OsStr::from_bytes(&overwide)),
        ];
        for path in candidates {
            let before = path.as_os_str().as_bytes().to_vec();
            assert!(SocketPath::new(&path).is_err());
            assert_eq!(path.as_os_str().as_bytes(), before);
        }
    }
}
