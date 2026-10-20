//! Shares the fixed Cache signer connection and socket-node custody recipe.
//!
//! A retained capture keeps native metadata, connection and option Results on
//! refusal. The ordinary adapter runs the same checks and disposes successful
//! metadata at each original iteration boundary. Neither path authenticates
//! the eventual signer: an Accept=no socket can name PID 1 as its creator.

use std::error::Error;
use std::ffi::CStr;
use std::fs::{self, Metadata};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::time::{ClockId, Timespec, clock_gettime};

/// Names the sole systemd-owned Cache signer ingress socket.
pub const CACHE_SIGNER_SOCKET_PATH_V1: &str = "/run/aos/sandbox-cache-signerd.sock";

const PARENTS: [&str; 2] = ["/run", "/run/aos"];
const PEER_TIMEOUT: Duration = Duration::from_secs(5);

/// Classifies a retained native connection refusal without replacing its cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("fixed Cache signer connection is incomplete or retains a refusal")]
pub struct CacheSignerConnectionClosedV1;

#[derive(Default)]
struct PathObservation {
    metadata: [Option<io::Result<Metadata>>; 3],
    comparison: [Option<io::Result<()>>; 3],
}

impl PathObservation {
    fn observe_once(&mut self, uid: u32, gid: u32, retain: bool) -> Result<(), CacheSignerConnectionClosedV1> {
        for index in 0..3 {
            let path = if index < 2 { PARENTS[index] } else { CACHE_SIGNER_SOCKET_PATH_V1 };
            self.metadata[index] = Some(fs::symlink_metadata(path));
            let metadata = self.metadata[index].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CacheSignerConnectionClosedV1)?;
            self.comparison[index] = Some(require_metadata(metadata, index, uid, gid));
            let positive = matches!(self.comparison[index], Some(Ok(())));

            // The old local metadata is consumed before the next lookup, on
            // both a comparison refusal and a completed ordinary iteration.
            if !retain {
                drop(self.metadata[index].take());
            }
            if !positive {
                return Err(CacheSignerConnectionClosedV1);
            }
        }
        Ok(())
    }

    fn failure(&self) -> Option<&io::Error> {
        for index in 0..3 {
            if let Some(error) = self.metadata[index].as_ref().and_then(|result| result.as_ref().err()) {
                return Some(error);
            }
            if let Some(error) = self.comparison[index].as_ref().and_then(|result| result.as_ref().err()) {
                return Some(error);
            }
        }
        None
    }

    fn take_failure(&mut self) -> Option<io::Error> {
        for index in 0..3 {
            if self.metadata[index].as_ref().is_some_and(Result::is_err) {
                return self.metadata[index].take().and_then(Result::err);
            }
            if self.comparison[index].as_ref().is_some_and(Result::is_err) {
                return self.comparison[index].take().and_then(Result::err);
            }
        }
        None
    }
}

fn require_metadata(metadata: &Metadata, index: usize, uid: u32, gid: u32) -> io::Result<()> {
    if index < 2 {
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid_data("unsafe Cache signer socket parent"));
        }
    } else if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o660
        || metadata.nlink() != 1
    {
        return Err(invalid_data("unsafe Cache signer socket node"));
    }
    Ok(())
}

/// Keeps one exact fixed-path connection and every reached native refusal.
///
/// Construction performs no IO or allocation. The purpose owner prepays its
/// complete layout and must keep this capture through independent posts. A
/// successful stream is connection DATA; it supplies no Cache purpose grant.
#[must_use]
#[derive(Default)]
pub struct CacheSignerConnectionOriginalsV1 {
    before: PathObservation,
    deadline: Option<u64>,
    clock_before: Option<Timespec>,
    deadline_before: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    connect_before_clock: Option<Timespec>,
    connect_before_deadline: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    poll_before_clock: Option<Timespec>,
    poll_timeout: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    poll: Option<rustix::io::Result<usize>>,
    poll_flags: Option<PollFlags>,
    poll_clock: Option<Timespec>,
    poll_deadline: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    poll_completion: Option<Result<(), CacheSignerConnectionClosedV1>>,
    socket_error: Option<rustix::io::Result<rustix::io::Result<()>>>,
    connected_clock: Option<Timespec>,
    connected_deadline: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    options_clock: Option<Timespec>,
    options_deadline: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    socket: Option<OwnedFd>,
    socket_result: Option<rustix::io::Result<()>>,
    address: Option<rustix::io::Result<rustix::net::SocketAddrUnix>>,
    connected: Option<rustix::io::Result<()>>,
    connection: Option<UnixStream>,
    after: PathObservation,
    read_timeout: Option<io::Result<()>>,
    write_timeout: Option<io::Result<()>>,
    identity: Option<io::Result<()>>,
    entered: bool,
    complete: bool,
    closed: Option<CacheSignerConnectionClosedV1>,
}

impl CacheSignerConnectionOriginalsV1 {
    /// Creates an inert native capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Connects once nonblocking under the actual absolute boottime cutoff.
    ///
    /// The shared ordinary adapter retains its blocking socket/check sequence.
    /// Selected initial, readiness and SO_ERROR Results remain resident, with
    /// fresh cutoff checks before connection and after every positive frontier.
    ///
    /// # Errors
    /// Keeps invalid identities, unsafe path custody, native connect and socket
    /// option failures. Reentry closes the capture without replacing a cause.
    pub fn connect_once(&mut self, signer_uid: u32, socket_gid: u32, cutoff: u64) -> Result<(), CacheSignerConnectionClosedV1> {
        self.connect_inner(signer_uid, socket_gid, true, Some(cutoff))
    }

    fn connect_inner(&mut self, uid: u32, gid: u32, retain: bool, deadline: Option<u64>) -> Result<(), CacheSignerConnectionClosedV1> {
        if self.entered {
            self.closed.get_or_insert(CacheSignerConnectionClosedV1);
            return Err(CacheSignerConnectionClosedV1);
        }
        self.entered = true;
        self.deadline = deadline;
        self.identity = Some(if uid == 0 || gid == 0 {
            Err(invalid_data("invalid Cache signer identity"))
        } else {
            Ok(())
        });
        if !matches!(self.identity, Some(Ok(()))) {
            return Err(CacheSignerConnectionClosedV1);
        }

        self.before.observe_once(uid, gid, retain)?;
        self.connect_native_once(c"/run/aos/sandbox-cache-signerd.sock", retain, deadline)?;
        self.after.observe_once(uid, gid, retain)?;

        let stream = self.connection.as_ref().ok_or(CacheSignerConnectionClosedV1)?;
        self.read_timeout = Some(stream.set_read_timeout(Some(PEER_TIMEOUT)));
        if !matches!(self.read_timeout, Some(Ok(()))) {
            return Err(CacheSignerConnectionClosedV1);
        }
        self.write_timeout = Some(stream.set_write_timeout(Some(PEER_TIMEOUT)));
        if !matches!(self.write_timeout, Some(Ok(()))) {
            return Err(CacheSignerConnectionClosedV1);
        }
        if let Some(cutoff) = deadline {
            let now = clock_gettime(ClockId::Boottime);
            self.options_clock = Some(now);
            self.options_deadline = Some(deadline_timeout_v1(now, cutoff));
            if !matches!(self.options_deadline, Some(Ok(_))) {
                return Err(CacheSignerConnectionClosedV1);
            }
        }
        self.complete = true;
        Ok(())
    }

    fn connect_native_once(&mut self, path: &CStr, retain: bool, deadline: Option<u64>) -> Result<(), CacheSignerConnectionClosedV1> {
        // Ordinary mode keeps std's Linux blocking order. Selected mode
        // checks the actual cutoff before creating a nonblocking endpoint.
        if let Some(cutoff) = deadline {
            let now = clock_gettime(ClockId::Boottime);
            self.clock_before = Some(now);
            self.deadline_before = Some(deadline_timeout_v1(now, cutoff));
            if !matches!(self.deadline_before, Some(Ok(_))) {
                return Err(CacheSignerConnectionClosedV1);
            }
        }
        let flags = if deadline.is_some() {
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK
        } else {
            rustix::net::SocketFlags::CLOEXEC
        };
        self.socket_result = Some(match rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            flags,
            None,
        ) {
            Ok(socket) => {
                self.socket = Some(socket);
                Ok(())
            }
            Err(error) => Err(error),
        });
        if !matches!(self.socket_result, Some(Ok(()))) {
            return Err(CacheSignerConnectionClosedV1);
        }
        self.address = Some(rustix::net::SocketAddrUnix::new(path));
        let address = self.address.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheSignerConnectionClosedV1)?;
        let socket = self.socket.as_ref().ok_or(CacheSignerConnectionClosedV1)?;
        if let Some(cutoff) = deadline {
            let now = clock_gettime(ClockId::Boottime);
            self.connect_before_clock = Some(now);
            self.connect_before_deadline = Some(deadline_timeout_v1(now, cutoff));
            if !matches!(self.connect_before_deadline, Some(Ok(_))) {
                return Err(CacheSignerConnectionClosedV1);
            }
        }
        self.connected = Some(rustix::net::connect(socket, address));
        if let Some(cutoff) = deadline {
            let pending = matches!(self.connected, Some(Err(rustix::io::Errno::INPROGRESS)));
            // AF_UNIX backlog EAGAIN means no pending connection. SO_ERROR
            // alone may be zero on that unconnected socket: never accept it.
            if !pending && !matches!(self.connected, Some(Ok(()))) {
                return Err(CacheSignerConnectionClosedV1);
            }
            if pending {
                let now = clock_gettime(ClockId::Boottime);
                self.poll_before_clock = Some(now);
                self.poll_timeout = Some(deadline_timeout_v1(now, cutoff));
                let timeout = self.poll_timeout.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(CacheSignerConnectionClosedV1)?;
                let mut descriptors = [PollFd::new(socket, PollFlags::OUT)];
                self.poll = Some(poll(&mut descriptors, Some(timeout)));
                self.poll_flags = Some(descriptors[0].revents());
                let now = clock_gettime(ClockId::Boottime);
                self.poll_clock = Some(now);
                self.poll_deadline = Some(deadline_timeout_v1(now, cutoff));
                self.poll_completion = Some(if matches!(self.poll, Some(Ok(count)) if count != 0)
                    && self.poll_flags.is_some_and(|flags| !flags.contains(PollFlags::NVAL)
                        && flags.intersects(PollFlags::OUT | PollFlags::ERR | PollFlags::HUP))
                    && matches!(self.poll_deadline, Some(Ok(_)))
                { Ok(()) } else { Err(CacheSignerConnectionClosedV1) });
                if !matches!(self.poll_completion, Some(Ok(()))) {
                    return Err(CacheSignerConnectionClosedV1);
                }
            }
            self.socket_error = Some(rustix::net::sockopt::socket_error(socket));
            if !matches!(self.socket_error, Some(Ok(Ok(())))) {
                return Err(CacheSignerConnectionClosedV1);
            }
            let now = clock_gettime(ClockId::Boottime);
            self.connected_clock = Some(now);
            self.connected_deadline = Some(deadline_timeout_v1(now, cutoff));
            if !matches!(self.connected_deadline, Some(Ok(_))) {
                return Err(CacheSignerConnectionClosedV1);
            }
        } else if !matches!(self.connected, Some(Ok(()))) {
            return Err(CacheSignerConnectionClosedV1);
        }
        self.connection = self.socket.take().map(UnixStream::from);
        if !retain {
            drop(self.address.take());
        }
        Ok(())
    }

    /// Borrows the earliest actual refusal, including closed reentry.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native_failure().map(|error| error as &(dyn Error + 'static))
            .or_else(|| self.closed.as_ref().map(|error| error as &(dyn Error + 'static)))
    }

    fn native_failure(&self) -> Option<&(dyn Error + 'static)> {
        fn io_error(value: &Option<io::Result<()>>) -> Option<&(dyn Error + 'static)> {
            value.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)
        }
        fn raw_error(value: &Option<rustix::io::Result<()>>) -> Option<&(dyn Error + 'static)> {
            value.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)
        }
        io_error(&self.identity)
            .or_else(|| self.before.failure().map(|error| error as &dyn Error))
            .or_else(|| self.deadline_before.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| raw_error(&self.socket_result))
            .or_else(|| self.address.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| self.connect_before_deadline.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| if self.deadline.is_some() && matches!(self.connected, Some(Err(rustix::io::Errno::INPROGRESS))) {
                None
            } else { raw_error(&self.connected) })
            .or_else(|| self.poll_timeout.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| self.poll.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| self.poll_deadline.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| self.poll_completion.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| match self.socket_error.as_ref() {
                Some(Err(error)) | Some(Ok(Err(error))) => Some(error as &dyn Error),
                _ => None,
            })
            .or_else(|| self.connected_deadline.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
            .or_else(|| self.after.failure().map(|error| error as &dyn Error))
            .or_else(|| io_error(&self.read_timeout))
            .or_else(|| io_error(&self.write_timeout))
            .or_else(|| self.options_deadline.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
    }

    /// Moves the actual completed stream without claiming role authentication.
    ///
    /// # Errors
    /// Rejects incomplete, failed, closed or already moved captures.
    pub fn take_stream_once(&mut self) -> Result<UnixStream, CacheSignerConnectionClosedV1> {
        if !self.complete || self.failure().is_some() {
            self.closed.get_or_insert(CacheSignerConnectionClosedV1);
            return Err(CacheSignerConnectionClosedV1);
        }
        match self.connection.take() {
            Some(stream) => Ok(stream),
            other => {
                self.connection = other;
                self.closed.get_or_insert(CacheSignerConnectionClosedV1);
                Err(CacheSignerConnectionClosedV1)
            }
        }
    }

    fn into_ordinary_result(mut self) -> io::Result<UnixStream> {
        if self.complete && self.failure().is_none() {
            return self.take_stream_once().map_err(io::Error::other);
        }
        let error = self.identity.take().and_then(Result::err)
            .or_else(|| self.before.take_failure())
            .or_else(|| self.socket_result.take().and_then(Result::err).map(io::Error::from))
            .or_else(|| if self.address.as_ref().is_some_and(Result::is_err) {
                self.address.take().and_then(Result::err).map(io::Error::from)
            } else { None })
            .or_else(|| self.connected.take().and_then(Result::err).map(io::Error::from))
            .or_else(|| self.after.take_failure())
            .or_else(|| self.read_timeout.take().and_then(Result::err))
            .or_else(|| self.write_timeout.take().and_then(Result::err))
            .unwrap_or_else(|| io::Error::other(CacheSignerConnectionClosedV1));
        // Successful ordinary metadata has already dropped at each old local
        // boundary. This is the same connected stream dropped on a later Err.
        drop(self.address.take());
        drop(self.socket.take());
        drop(self.connection.take());
        Err(error)
    }

    /// Reports additional construction/error bytes, descriptors and cells.
    ///
    /// The enclosing owner separately pays its embedded capture. These passive
    /// dimensions charge no ledger and authenticate no configured identities.
    #[must_use]
    pub fn additional_receiving_shape_v1() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<io::Result<Metadata>>())?
            .checked_add(2 * std::mem::size_of::<Metadata>())?
            .checked_add(std::mem::size_of::<rustix::fs::Statx>())?
            .checked_add(std::mem::size_of::<rustix::io::Result<OwnedFd>>())?
            .checked_add(2 * std::mem::size_of::<rustix::net::SocketAddrUnix>())?
            .checked_add(std::mem::size_of::<PollFd<'static>>())?
            .checked_add(256)?;
        // Both path bookends inspect these same parents and socket name.
        // Their Results, native records and controls are already in bytes.
        Some((bytes, 1, PARENTS.len().checked_add(1)?))
    }
}

/// Connects through the same native engine with ordinary immediate disposal.
///
/// # Errors
/// Returns the exact original IO error for identity, custody, connection or
/// timeout failure, preserving the existing check and cleanup sequence.
pub fn connect_cache_signer_ordinary_v1(uid: u32, gid: u32) -> io::Result<UnixStream> {
    let mut originals = CacheSignerConnectionOriginalsV1::new();
    let _result = originals.connect_inner(uid, gid, false, None);
    originals.into_ordinary_result()
}

/// Checks the compiled fixed socket custody through the same ordinary recipe.
///
/// # Errors
/// Returns the original metadata or custody error at the first unsafe parent
/// or fixed socket node. This does not authenticate a service process.
pub fn require_cache_signer_socket_custody_v1(uid: u32, gid: u32) -> io::Result<()> {
    let mut observation = PathObservation::default();
    match observation.observe_once(uid, gid, false) {
        Ok(()) => Ok(()),
        Err(_) => Err(observation.take_failure().unwrap_or_else(|| io::Error::other(CacheSignerConnectionClosedV1))),
    }
}

/// Converts one observed boottime position into the same absolute deadline.
///
/// Pure comparison DATA only; it creates no budget or receiving permission.
///
/// # Errors
/// Rejects negative/invalid time, checked overflow and expired exact cutoffs.
pub fn deadline_timeout_v1(now: Timespec, cutoff: u64) -> Result<Timespec, CacheSignerConnectionClosedV1> {
    let seconds = u64::try_from(now.tv_sec).map_err(|_| CacheSignerConnectionClosedV1)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| CacheSignerConnectionClosedV1)?;
    if nanos >= 1_000_000_000 { return Err(CacheSignerConnectionClosedV1); }
    let now = seconds.checked_mul(1_000_000_000).and_then(|value| value.checked_add(nanos))
        .ok_or(CacheSignerConnectionClosedV1)?;
    let remaining = cutoff.checked_sub(now).filter(|value| *value != 0).ok_or(CacheSignerConnectionClosedV1)?;
    Ok(Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| CacheSignerConnectionClosedV1)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000).map_err(|_| CacheSignerConnectionClosedV1)?,
    })
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    #[test]
    fn invalid_identity_keeps_precise_first_error_without_connecting() {
        let mut originals = CacheSignerConnectionOriginalsV1::new();
        assert!(originals.connect_once(0, 1, u64::MAX).is_err());
        let first = originals.failure().unwrap().downcast_ref::<io::Error>().unwrap() as *const io::Error;
        assert_eq!(originals.native_failure().unwrap().to_string(), "invalid Cache signer identity");
        assert!(originals.connection.is_none());
        assert!(originals.before.metadata.iter().all(Option::is_none));

        assert!(originals.connect_once(1, 1, u64::MAX).is_err());
        let later = originals.failure().unwrap().downcast_ref::<io::Error>().unwrap() as *const io::Error;
        assert_eq!(first, later);
        assert!(originals.take_stream_once().is_err());
    }

    #[test]
    fn failed_native_connect_keeps_the_actual_new_socket_and_errno() {
        use std::os::fd::AsFd as _;
        use std::os::unix::ffi::OsStrExt as _;

        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.sock");
        let path = std::ffi::CString::new(missing.as_os_str().as_bytes()).unwrap();
        let mut originals = CacheSignerConnectionOriginalsV1::new();
        originals.entered = true;
        assert!(originals.connect_native_once(&path, true, None).is_err());
        let socket = originals.socket.as_ref().unwrap();
        assert_eq!(rustix::net::sockopt::socket_type(socket).unwrap(), rustix::net::SocketType::STREAM);
        let identity = rustix::fs::fstat(socket.as_fd()).unwrap();
        assert!(identity.st_ino != 0);
        assert_eq!(originals.connected, Some(Err(rustix::io::Errno::NOENT)));
        let first = originals.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap() as *const rustix::io::Errno;

        assert!(originals.connect_once(1, 1, u64::MAX).is_err());
        assert_eq!(first, originals.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap() as *const rustix::io::Errno);
        assert_eq!(rustix::fs::fstat(originals.socket.as_ref().unwrap()).unwrap().st_ino, identity.st_ino);
    }

    #[test]
    fn full_real_unix_backlog_refuses_without_blocking_and_keeps_nonblocking_socket() {
        use std::os::unix::ffi::OsStrExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("full.sock");
        let listener = UnixListener::bind(&path).unwrap();
        rustix::net::listen(&listener, 0).unwrap();
        let _queued = UnixStream::connect(&path).unwrap();
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let now = clock_gettime(ClockId::Boottime);
        let cutoff = u64::try_from(now.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(now.tv_nsec).unwrap() + 10_000_000_000;
        let mut originals = CacheSignerConnectionOriginalsV1::new();
        originals.deadline = Some(cutoff);
        assert!(originals.connect_native_once(&path, true, Some(cutoff)).is_err());
        assert_eq!(originals.connected, Some(Err(rustix::io::Errno::AGAIN)));
        assert!(originals.poll.is_none());
        assert!(originals.socket_error.is_none());
        let socket = originals.socket.as_ref().unwrap();
        assert!(rustix::fs::fcntl_getfl(socket).unwrap().contains(rustix::fs::OFlags::NONBLOCK));
        assert!(rustix::fs::fstat(socket).unwrap().st_ino != 0);
        assert_eq!(originals.failure().unwrap().downcast_ref::<rustix::io::Errno>(), Some(&rustix::io::Errno::AGAIN));
    }

    #[test]
    fn expired_native_connect_does_not_create_or_attempt_a_socket() {
        let mut originals = CacheSignerConnectionOriginalsV1::new();
        originals.deadline = Some(1);
        assert!(originals.connect_native_once(c"/run/aos/sandbox-cache-signerd.sock", true, Some(1)).is_err());
        assert!(originals.clock_before.is_some());
        assert!(matches!(originals.deadline_before, Some(Err(_))));
        assert!(originals.socket.is_none());
        assert!(originals.socket_result.is_none());
        assert!(originals.connected.is_none());
        assert!(originals.poll.is_none());
    }

    #[test]
    fn actual_socket_metadata_uses_the_same_mode_and_owner_predicate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let accepted = fs::symlink_metadata(&path).unwrap();
        assert!(require_metadata(&accepted, 2, accepted.uid(), accepted.gid()).is_ok());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let refused = fs::symlink_metadata(&path).unwrap();
        let failure = require_metadata(&refused, 2, refused.uid(), refused.gid()).unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::InvalidData);
        assert_eq!(failure.to_string(), "unsafe Cache signer socket node");
    }
}
