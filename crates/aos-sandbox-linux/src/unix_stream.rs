//! Retained connected Unix stream peer identity and duplicate continuity.
//!
//! This module adopts an already-connected Unix `SOCK_STREAM`; it neither
//! connects to a pathname nor sends or receives protocol bytes. Adoption pins
//! the connection establisher with `SO_PEERCRED` and `SO_PEERPIDFD` while
//! retaining the exact socket endpoint. A duplicate can be made only from that
//! retained endpoint and must preserve its kernel `SO_COOKIE`.
//!
//! Peer identity is connection-level kernel evidence, not application-role
//! authentication and not proof of which process later uses a delegated
//! descriptor. The lifetime on [`RetainedUnixStreamDuplicate`] keeps its source
//! borrowed while the wrapper exists. A caller can still duplicate or operate
//! on the borrowed descriptor through generic descriptor APIs, so the wrapper
//! is not a globally non-escapable or read-only capability.

use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

use crate::pidfd::{PidFd, PidFdInfo};
use crate::{Error, Result, uapi};

/// Owns one connected Unix stream and its kernel-pinned connection peer.
#[derive(Debug)]
pub struct RetainedUnixStream {
    fd: OwnedFd,
    peer: UnixStreamPeerIdentity,
    socket_cookie: NonZeroU64,
}

impl RetainedUnixStream {
    /// Connects to one normalized absolute filesystem Unix stream socket.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-normalized or oversized path, connection
    /// failure, or retained peer-identity failure.
    pub fn connect(path: &Path) -> Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        let normalized = path.is_absolute()
            && bytes.len() > 1
            // Linux reserves 108 bytes including the trailing NUL.
            && bytes.len() < 108
            && !bytes.contains(&0)
            && bytes[1..]
                .split(|byte| *byte == b'/')
                .all(|component| !component.is_empty() && !matches!(component, b"." | b".."))
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
        if !normalized {
            return Err(Error::invalid(
                "Unix stream connection path",
                "must be a normalized absolute filesystem path",
            ));
        }

        let stream =
            std::os::unix::net::UnixStream::connect(path).map_err(|source| Error::Syscall {
                operation: "connect Unix stream",
                source,
            })?;
        Self::from_owned(stream.into())
    }

    /// Validates and adopts an owned connected Unix `SOCK_STREAM` descriptor.
    ///
    /// The descriptor is made close-on-exec without changing its file-status
    /// flags or socket options. `SO_COOKIE` is observed around peer capture so
    /// an inconsistent kernel response fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong family or type, a listener or unconnected
    /// socket, unavailable peer credentials or pidfd, inconsistent peer
    /// identity, malformed cookie, or descriptor-flag failure.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        uapi::validate_connected_unix_stream(fd.as_fd())?;
        uapi::ensure_cloexec(fd.as_fd())?;

        let socket_cookie = nonzero_socket_cookie(uapi::socket_cookie(fd.as_fd())?)?;
        let credentials = UnixStreamPeerCredentials::from_raw(uapi::peer_credentials(fd.as_fd())?)?;
        let pidfd = PidFd::from_owned(uapi::peer_pidfd(fd.as_fd())?)?;
        let initial_info = pidfd.info()?;
        let final_cookie = nonzero_socket_cookie(uapi::socket_cookie(fd.as_fd())?)?;

        if initial_info.pid() != credentials.pid().get() {
            return Err(peer_identity_error(
                "SO_PEERCRED and SO_PEERPIDFD identify different processes",
            ));
        }
        if final_cookie != socket_cookie {
            return Err(peer_identity_error(
                "SO_COOKIE changed during Unix stream peer capture",
            ));
        }

        Ok(Self {
            fd,
            peer: UnixStreamPeerIdentity {
                credentials,
                pidfd,
                initial_info,
            },
            socket_cookie,
        })
    }

    /// Borrows the retained connected stream.
    ///
    /// Generic descriptor APIs can duplicate or operate on this borrow. The
    /// type does not constrain how an authorized caller uses the socket.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Returns the process that established the retained connection.
    ///
    /// This evidence does not identify later users after descriptor delegation.
    #[must_use]
    pub const fn peer(&self) -> &UnixStreamPeerIdentity {
        &self.peer
    }

    /// Duplicates this exact retained socket endpoint as close-on-exec.
    ///
    /// The duplicate is created with `F_DUPFD_CLOEXEC` from the retained source
    /// and its `SO_COOKIE` must equal the source cookie. Peer evidence is
    /// borrowed from the source rather than recaptured from another connection.
    ///
    /// # Errors
    ///
    /// Returns an error when duplication or cookie validation fails.
    pub fn duplicate(&self) -> Result<RetainedUnixStreamDuplicate<'_>> {
        let fd = uapi::duplicate_at_least(self.fd.as_fd(), 0)?;
        let socket_cookie = nonzero_socket_cookie(uapi::socket_cookie(fd.as_fd())?)?;
        if socket_cookie != self.socket_cookie {
            return Err(peer_identity_error(
                "duplicated Unix stream has a different SO_COOKIE",
            ));
        }

        Ok(RetainedUnixStreamDuplicate { fd, source: self })
    }
}

/// Owns a same-socket duplicate while retaining a borrow of its source.
///
/// This wrapper has no independent adoption constructor. Its lifetime keeps
/// the checked source alive in this process, but [`Self::as_fd`] remains an
/// ordinary descriptor borrow and cannot prevent downstream duplication or I/O.
#[derive(Debug)]
pub struct RetainedUnixStreamDuplicate<'stream> {
    fd: OwnedFd,
    source: &'stream RetainedUnixStream,
}

impl RetainedUnixStreamDuplicate<'_> {
    /// Borrows the duplicated socket endpoint.
    ///
    /// Generic descriptor APIs can duplicate or operate on this borrow.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Returns the source stream's retained connection peer.
    #[must_use]
    pub const fn peer(&self) -> &UnixStreamPeerIdentity {
        self.source.peer()
    }
}

/// Pins the process recorded when one Unix stream connection was established.
#[derive(Debug)]
pub struct UnixStreamPeerIdentity {
    credentials: UnixStreamPeerCredentials,
    pidfd: PidFd,
    initial_info: PidFdInfo,
}

impl UnixStreamPeerIdentity {
    /// Returns credentials fixed at connection establishment.
    #[must_use]
    pub const fn credentials(&self) -> UnixStreamPeerCredentials {
        self.credentials
    }

    /// Returns the initial process information read from the retained pidfd.
    #[must_use]
    pub const fn initial_info(&self) -> PidFdInfo {
        self.initial_info
    }

    /// Borrows the retained peer pidfd for descriptor-oriented checks.
    #[must_use]
    pub const fn pidfd(&self) -> &PidFd {
        &self.pidfd
    }

    /// Tests whether the pinned connection-establisher process still exists.
    ///
    /// # Errors
    ///
    /// Returns an error for pidfd failures other than normal process exit.
    pub fn is_alive(&self) -> Result<bool> {
        self.pidfd.is_alive()
    }
}

/// Holds credentials fixed by a Unix stream at connection establishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixStreamPeerCredentials {
    pid: NonZeroU32,
    uid: u32,
    gid: u32,
}

impl UnixStreamPeerCredentials {
    fn from_raw(raw: libc::ucred) -> Result<Self> {
        let pid = u32::try_from(raw.pid)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| peer_identity_error("SO_PEERCRED contained an invalid pid"))?;

        Ok(Self {
            pid,
            uid: raw.uid,
            gid: raw.gid,
        })
    }

    /// Returns the peer PID in the receiver's PID namespace.
    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    /// Returns the peer user ID fixed at connection establishment.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the peer group ID fixed at connection establishment.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

fn nonzero_socket_cookie(cookie: u64) -> Result<NonZeroU64> {
    NonZeroU64::new(cookie)
        .ok_or_else(|| peer_identity_error("SO_COOKIE returned the reserved zero value"))
}

fn peer_identity_error(message: &str) -> Error {
    Error::MalformedKernelResponse {
        object: "Unix stream peer identity",
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "Host time bounds isolated test-process cleanup, not runtime state."
    )]
    #![allow(
        clippy::expect_used,
        reason = "Test failures intentionally panic with context."
    )]

    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use rustix::net::{AddressFamily, SocketFlags, SocketType, socket_with};
    use tempfile::TempDir;

    use super::*;

    const FIXTURE_ENV: &str = "AOS_UNIX_STREAM_CONNECTOR_FIXTURE_V1";
    const FIXTURE_PATH_ENV: &str = "AOS_UNIX_STREAM_CONNECTOR_PATH_V1";
    const DUPLICATE_DROP_FIXTURE_ENV: &str = "AOS_UNIX_STREAM_DUPLICATE_DROP_FIXTURE_V1";
    const LOCAL_REJECTION_FIXTURE_ENV: &str = "AOS_UNIX_STREAM_LOCAL_REJECTION_FIXTURE_V1";
    const FOREIGN_REJECTION_FIXTURE_ENV: &str = "AOS_UNIX_STREAM_FOREIGN_REJECTION_FIXTURE_V1";
    const WAIT_LIMIT: Duration = Duration::from_secs(10);

    struct Connector(Child);

    impl Connector {
        fn wait_success(&mut self) {
            let deadline = Instant::now() + WAIT_LIMIT;
            loop {
                if let Some(status) = self.0.try_wait().expect("poll connector process") {
                    assert!(status.success(), "connector failed: {status}");
                    return;
                }
                assert!(Instant::now() < deadline, "connector did not exit");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    impl Drop for Connector {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn stream_pair() -> (RetainedUnixStream, UnixStream) {
        let (left, right) = UnixStream::pair().expect("create Unix stream pair");
        (
            RetainedUnixStream::from_owned(left.into()).expect("adopt Unix stream"),
            right,
        )
    }

    #[test]
    fn adopts_connected_unix_stream_and_pins_peer() {
        let (stream, _peer) = stream_pair();

        assert_eq!(stream.peer().credentials().pid().get(), std::process::id());
        assert_eq!(stream.peer().initial_info().pid(), std::process::id());
        assert_ne!(stream.socket_cookie.get(), 0);
        assert!(uapi::is_cloexec(stream.as_fd()).expect("stream CLOEXEC"));
        assert!(uapi::is_cloexec(stream.peer().pidfd().as_fd()).expect("peer pidfd CLOEXEC"));
    }

    #[test]
    fn adoption_changes_only_close_on_exec_descriptor_flag() {
        let (left, _right) = UnixStream::pair().expect("create Unix stream pair");
        left.set_nonblocking(true).expect("make stream nonblocking");
        uapi::clear_cloexec_for_test(left.as_fd()).expect("clear initial CLOEXEC");
        uapi::enable_socket_passcred_for_test(left.as_fd()).expect("enable SO_PASSCRED");

        let before_status = uapi::get_status_flags(left.as_fd()).expect("initial status flags");
        let before_passcred =
            uapi::socket_passcred_for_test(left.as_fd()).expect("initial SO_PASSCRED");
        assert_ne!(before_status & libc::O_NONBLOCK, 0);
        assert!(!uapi::is_cloexec(left.as_fd()).expect("initial CLOEXEC"));
        assert!(before_passcred);

        let stream = RetainedUnixStream::from_owned(left.into()).expect("adopt Unix stream");

        assert_eq!(
            uapi::get_status_flags(stream.as_fd()).expect("final status flags"),
            before_status
        );
        assert!(uapi::is_cloexec(stream.as_fd()).expect("stream CLOEXEC"));
        assert_eq!(
            uapi::socket_passcred_for_test(stream.as_fd()).expect("final SO_PASSCRED"),
            before_passcred
        );
    }

    #[test]
    fn duplicate_is_bound_to_the_same_owned_stream() {
        let (stream, _peer) = stream_pair();
        let duplicate = stream.duplicate().expect("duplicate retained stream");

        assert_ne!(stream.as_fd().as_raw_fd(), duplicate.as_fd().as_raw_fd());
        assert!(uapi::is_cloexec(duplicate.as_fd()).expect("duplicate CLOEXEC"));
        assert_eq!(
            uapi::socket_cookie(duplicate.as_fd()).expect("duplicate cookie"),
            stream.socket_cookie.get()
        );
        assert!(std::ptr::eq(duplicate.peer(), stream.peer()));
    }

    #[test]
    fn same_process_on_distinct_connections_is_not_same_stream() {
        let (first, _first_peer) = stream_pair();
        let (second, _second_peer) = stream_pair();

        assert_eq!(first.peer().credentials(), second.peer().credentials());
        assert_ne!(first.socket_cookie, second.socket_cookie);

        let duplicate = first.duplicate().expect("duplicate first stream");
        assert_eq!(
            uapi::socket_cookie(duplicate.as_fd()).expect("duplicate cookie"),
            first.socket_cookie.get()
        );
        assert_ne!(
            uapi::socket_cookie(duplicate.as_fd()).expect("duplicate cookie"),
            second.socket_cookie.get()
        );
    }

    #[test]
    fn listener_and_unconnected_stream_are_rejected_and_closed() {
        run_exact_fixture(
            "unix_stream::tests::local_rejection_fixture",
            LOCAL_REJECTION_FIXTURE_ENV,
        );
    }

    #[test]
    fn local_rejection_fixture() {
        if std::env::var_os(LOCAL_REJECTION_FIXTURE_ENV).as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }

        let directory = TempDir::new().expect("create socket directory");
        let listener = UnixListener::bind(directory.path().join("listener"))
            .expect("create Unix stream listener");
        assert_rejected_and_closed(listener.into());

        let unconnected = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("create unconnected Unix stream");
        assert_rejected_and_closed(unconnected);
    }

    #[test]
    fn sequenced_packet_and_inet_stream_are_rejected_and_closed() {
        run_exact_fixture(
            "unix_stream::tests::foreign_rejection_fixture",
            FOREIGN_REJECTION_FIXTURE_ENV,
        );
    }

    #[test]
    fn foreign_rejection_fixture() {
        if std::env::var_os(FOREIGN_REJECTION_FIXTURE_ENV).as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }

        let (seqpacket, _peer) = uapi::seqpacket_pair().expect("create sequenced-packet pair");
        assert_rejected_and_closed(seqpacket);

        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind TCP listener");
        let client = std::net::TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("connect TCP stream");
        let (_server, _) = listener.accept().expect("accept TCP stream");
        assert_rejected_and_closed(client.into());
    }

    #[test]
    fn duplicate_drop_preserves_the_source_stream() {
        run_exact_fixture(
            "unix_stream::tests::duplicate_drop_fixture",
            DUPLICATE_DROP_FIXTURE_ENV,
        );
    }

    #[test]
    fn duplicate_drop_fixture() {
        if std::env::var_os(DUPLICATE_DROP_FIXTURE_ENV).as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }

        let (stream, _peer) = stream_pair();
        let raw_duplicate = {
            // This exact-test subprocess runs no parallel tests, so the
            // allocator cannot reuse this number before the assertion.
            let duplicate = stream.duplicate().expect("duplicate retained stream");
            duplicate.as_fd().as_raw_fd()
        };

        assert!(!uapi::raw_fd_is_open(raw_duplicate));
        assert!(uapi::raw_fd_is_open(stream.as_fd().as_raw_fd()));
        assert!(stream.peer().is_alive().expect("source peer liveness"));
    }

    #[test]
    fn retained_peer_pidfd_observes_connector_exit() {
        let directory = TempDir::new().expect("create socket directory");
        let path = directory.path().join("connector.sock");
        let listener = UnixListener::bind(&path).expect("bind connector listener");
        listener
            .set_nonblocking(true)
            .expect("make listener nonblocking");
        let mut connector = Connector(
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "unix_stream::tests::connector_fixture",
                    "--nocapture",
                ])
                .env(FIXTURE_ENV, "1")
                .env(FIXTURE_PATH_ENV, &path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn connector fixture"),
        );
        let mut accepted = accept_by_deadline(&listener);
        accepted
            .set_read_timeout(Some(WAIT_LIMIT))
            .expect("set fixture read timeout");
        let mut ready = [0_u8; 1];
        accepted.read_exact(&mut ready).expect("read fixture ready");
        assert_eq!(ready, [1]);

        let stream = RetainedUnixStream::from_owned(accepted.into()).expect("adopt connector");
        assert_eq!(stream.peer().credentials().pid().get(), connector.0.id());
        rustix::io::write(stream.as_fd(), &[2]).expect("release connector");
        connector.wait_success();

        assert!(!stream.peer().is_alive().expect("connector pidfd liveness"));
    }

    #[test]
    fn connector_fixture() {
        if std::env::var_os(FIXTURE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        let path = std::env::var_os(FIXTURE_PATH_ENV).expect("fixture socket path");
        let mut stream = UnixStream::connect(path).expect("connect fixture stream");
        stream.write_all(&[1]).expect("send fixture ready");
        let mut finish = [0_u8; 1];
        stream
            .read_exact(&mut finish)
            .expect("wait for fixture release");
        assert_eq!(finish, [2]);
        std::process::exit(0);
    }

    fn accept_by_deadline(listener: &UnixListener) -> UnixStream {
        let deadline = Instant::now() + WAIT_LIMIT;
        loop {
            match listener.accept() {
                Ok((stream, _address)) => return stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept connector failed: {error}"),
            }
            assert!(Instant::now() < deadline, "connector accept timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn run_exact_fixture(test_name: &str, environment: &str) {
        let mut fixture = Connector(
            Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", test_name, "--nocapture"])
                .env(environment, "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn exact test fixture"),
        );
        fixture.wait_success();
    }

    fn assert_rejected_and_closed(fd: OwnedFd) {
        let raw = fd.as_raw_fd();

        assert!(RetainedUnixStream::from_owned(fd).is_err());
        assert!(!uapi::raw_fd_is_open(raw));
    }
}
