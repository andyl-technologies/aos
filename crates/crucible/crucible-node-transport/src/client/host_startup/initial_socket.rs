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
    time::Duration,
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
        + size_of::<Duration>()
        + size_of::<Option<Duration>>()
        + size_of::<Result<Duration, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&super::ExchangeDeadline>()
        + size_of::<Result<&CStr, ProviderError>>()
        + size_of::<rustix::fs::Stat>()
        + size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>()
        + size_of::<rustix::fs::AtFlags>()
        + size_of::<rustix::fs::FileType>()
        + size_of::<rustix::process::Uid>()
        + size_of::<u32>()
        + size_of::<bool>()
        + size_of::<rustix::event::Timespec>()
        + size_of::<Option<&rustix::event::Timespec>>()
        + size_of::<[rustix::event::PollFd<'static>; 0]>()
        + size_of::<&mut [rustix::event::PollFd<'static>; 0]>()
        + size_of::<&mut [rustix::event::PollFd<'static>]>()
        + size_of::<Result<usize, rustix::io::Errno>>()
        + size_of::<i64>()
        + size_of::<usize>()
}

impl OriginalPacketHostStartup {
    /// Acquires the same selected initial socket without renewing its deadline.
    ///
    /// The Source's actual installed action authenticates the path against its
    /// original launch guard and spends the socket phase before this call. This
    /// SDK primitive supplies custody only. It stores the actual descriptor in
    /// `completed` before connect, flag changes or terminal deadline checks can
    /// refuse. Before creating that descriptor, it waits for a same-user socket
    /// at the selected path under the same original deadline. Readiness is not
    /// peer authentication. It never replaces a failed descriptor or retries
    /// the connection.
    ///
    /// # Errors
    /// Refuses a foreign, partial or connected SDK root, occupied output,
    /// invalid path, symlink, non-socket or foreign-user endpoint, expired
    /// original cut, or unavailable socket/connection. Descriptors already
    /// created remain in the caller's original output slot.
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
        let borrowed_path = original_path.as_c_str()?;
        wait_for_socket(deadline, borrowed_path)?;
        let address =
            rustix::net::SocketAddrUnix::new(borrowed_path).map_err(std::io::Error::from)?;
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

// The Child consumes its inherited bootstrap and validates its full executable
// before binding. Wait only for pathname readiness: the held Source guard and
// subsequent Hello still authenticate the actual process and selected peer.
// No descriptor exists during this wait, and no unsuccessful connect is retried.
fn wait_for_socket(deadline: &super::ExchangeDeadline, path: &CStr) -> Result<(), ProviderError> {
    loop {
        let remaining = deadline
            .original_cut()
            .remaining()
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(refused)?;
        match rustix::fs::statat(rustix::fs::CWD, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => {
                if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                    != rustix::fs::FileType::Socket
                    || metadata.st_uid != rustix::process::geteuid().as_raw()
                {
                    return Err(refused());
                }
                return check_deadline(deadline);
            }
            Err(rustix::io::Errno::NOENT) => {
                // An empty descriptor list avoids creating a wait owner or
                // lazily initializing thread-parking backing. Interruptions
                // return to the same original deadline check, never renew it.
                let wait = remaining.min(Duration::from_millis(1));
                let timeout = rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: i64::from(wait.subsec_nanos()),
                };
                match rustix::event::poll(&mut [], Some(&timeout)) {
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(std::io::Error::from(error).into()),
                }
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
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

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> std::io::Result<Self> {
            use std::os::unix::fs::DirBuilderExt;
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "aos-initial-socket-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn initial_socket_waits_for_delayed_real_listener_without_renewing_cut()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::{fd::AsRawFd, unix::net::UnixListener};

        let directory = TestDirectory::new()?;
        let path = directory.0.join("control.sock");
        let (_, mut root) = super::super::tests::prepared_initial_lifecycle_model();
        let cut = super::super::ExchangeDeadline::start(Duration::from_secs(2))?;
        root.deadline = Some(cut);
        let deadline = root.deadline.as_ref().ok_or("missing original cut")?;
        let original_cut = deadline.original_cut();
        let child_path = path.clone();
        let listener = std::thread::spawn(move || {
            std::thread::park_timeout(Duration::from_millis(20));
            UnixListener::bind(child_path)
        });
        let mut completed = None;

        let acquired = root.acquire_original_initial_socket_into(&path, &mut completed);
        let listener = listener.join().map_err(|_| "listener thread unwound")??;
        acquired?;
        listener.set_nonblocking(true)?;
        let (_peer, _) = listener.accept()?;
        let stream = completed
            .as_ref()
            .ok_or("actual connected socket not retained")?;
        let descriptor = stream.as_raw_fd();

        assert_eq!(deadline.original_cut(), original_cut);
        assert!(rustix::io::fcntl_getfd(stream)?.contains(rustix::io::FdFlags::CLOEXEC));
        assert!(!rustix::fs::fcntl_getfl(stream)?.contains(rustix::fs::OFlags::NONBLOCK));
        assert!(
            root.acquire_original_initial_socket_into(&path, &mut completed)
                .is_err()
        );
        assert_eq!(
            completed.as_ref().ok_or("socket replaced")?.as_raw_fd(),
            descriptor
        );
        assert!(root.controller.is_none());
        Ok(())
    }

    #[test]
    fn initial_socket_missing_or_expired_cut_leaves_descriptor_uncreated()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::new()?;
        let path = directory.0.join("missing.sock");
        let (_, mut root) = super::super::tests::prepared_initial_lifecycle_model();
        let cut = super::super::ExchangeDeadline::start(Duration::from_millis(10))?;
        root.deadline = Some(cut);
        let original_cut = root.deadline.as_ref().ok_or("missing cut")?.original_cut();
        let mut completed = None;

        assert!(
            root.acquire_original_initial_socket_into(&path, &mut completed)
                .is_err()
        );
        assert!(completed.is_none());
        assert_eq!(
            root.deadline.as_ref().ok_or("missing cut")?.original_cut(),
            original_cut
        );
        assert!(original_cut.is_expired());
        assert!(
            root.acquire_original_initial_socket_into(&path, &mut completed)
                .is_err()
        );
        assert!(completed.is_none());
        Ok(())
    }

    #[test]
    fn initial_socket_rejects_symlink_and_non_socket_before_descriptor_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::{fs::symlink, net::UnixListener};

        let directory = TestDirectory::new()?;
        let actual = directory.0.join("actual.sock");
        let _listener = UnixListener::bind(&actual)?;
        let link = directory.0.join("foreign.sock");
        symlink(&actual, &link)?;
        let regular = directory.0.join("regular");
        std::fs::write(&regular, b"not a control socket")?;
        let (_, root) = super::super::tests::prepared_initial_lifecycle_model();

        for path in [&link, &regular, &directory.0] {
            let mut completed = None;
            assert!(
                root.acquire_original_initial_socket_into(path, &mut completed)
                    .is_err()
            );
            assert!(completed.is_none());
        }
        assert!(std::fs::symlink_metadata(link)?.file_type().is_symlink());
        Ok(())
    }

    #[test]
    fn initial_socket_failed_single_connect_keeps_original_descriptor()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::{fd::AsRawFd, unix::net::UnixListener};

        let directory = TestDirectory::new()?;
        let path = directory.0.join("stale.sock");
        drop(UnixListener::bind(&path)?);
        let (_, root) = super::super::tests::prepared_initial_lifecycle_model();
        let mut completed = None;

        assert!(
            root.acquire_original_initial_socket_into(&path, &mut completed)
                .is_err()
        );
        let descriptor = completed
            .as_ref()
            .ok_or("failed connect descriptor dropped")?
            .as_raw_fd();
        assert!(
            root.acquire_original_initial_socket_into(&path, &mut completed)
                .is_err()
        );
        assert_eq!(
            completed
                .as_ref()
                .ok_or("failed descriptor replaced")?
                .as_raw_fd(),
            descriptor
        );
        assert!(root.controller.is_none());
        Ok(())
    }
}
