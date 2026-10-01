//! Deadline-bounded I/O on the one retained fixed Root socket.
//!
//! Readiness waits preserve the original endpoint and deadline. Issuer custody
//! additionally retains the raw original description while the unchanged
//! stream validator admits a CLOEXEC duplicate of that same socket/OFD. No
//! partial or ambiguous phase is retried on another connection.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::policy_compiler::root_v8_released_proof::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2;

pub(super) fn connect_fixed(deadline: Instant) -> Result<RetainedUnixStream, SourceGenesisErrorV1> {
    // Type=simple does not prove the fixed daemon is listening yet. Retry only
    // a refusal known to precede connection admission; no accepted endpoint or
    // partial request is discarded/reissued within an original flight.
    loop {
        require_remaining(deadline)?;
        match connect_once(deadline) {
            Err(error) if connection_not_admitted(&error) => {
                std::thread::sleep(require_remaining(deadline)?.min(Duration::from_millis(25)));
            }
            result => return result,
        }
    }
}

fn connection_not_admitted(error: &SourceGenesisErrorV1) -> bool {
    matches!(error, SourceGenesisErrorV1::Transport(error)
        if matches!(error.raw_os_error(), Some(code)
            if code == rustix::io::Errno::NOENT.raw_os_error()
                || code == rustix::io::Errno::CONNREFUSED.raw_os_error()))
}

fn connect_once(deadline: Instant) -> Result<RetainedUnixStream, SourceGenesisErrorV1> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(std::io::Error::from)?;
    connect_socket(socket.as_fd(), deadline)?;
    RetainedUnixStream::from_owned(socket).map_err(Into::into)
}

// The caller parks the only connection before any connect/wait/adoption can
// fail. This is purpose-private custody, not a supplied descriptor factory.
pub(super) fn connect_parked(
    original: &mut Option<OwnedFd>,
    deadline: Instant,
) -> Result<RetainedUnixStream, SourceGenesisErrorV1> {
    if original.is_some() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    require_remaining(deadline)?;
    *original = Some(socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    ).map_err(std::io::Error::from)?);
    let socket = original.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
    connect_socket(socket.as_fd(), deadline)?;
    let duplicate = rustix::io::fcntl_dupfd_cloexec(socket, 0).map_err(std::io::Error::from)?;
    RetainedUnixStream::from_owned(duplicate).map_err(Into::into)
}

fn connect_socket(socket: BorrowedFd<'_>, deadline: Instant) -> Result<(), SourceGenesisErrorV1> {
    let address =
        SocketAddrUnix::new(POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2).map_err(std::io::Error::from)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS) => {
            wait(socket, PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(std::io::Error::from)?
                .map_err(std::io::Error::from)?;
        }
        // AF_UNIX EAGAIN means the listener did not admit this connection.
        // Do not turn a backlog miss into an unbounded connect/reissue loop.
        Err(error) => return Err(std::io::Error::from(error).into()),
    }
    require_remaining(deadline)?;
    Ok(())
}

pub(super) fn wait(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), SourceGenesisErrorV1> {
    loop {
        let remaining = require_remaining(deadline)?.min(Duration::from_millis(100));
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        let mut descriptors = [PollFd::new(&descriptor, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
        require_remaining(deadline)?;
        let observed = descriptors[0].revents();
        if observed.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        if observed.intersects(interest) {
            return Ok(());
        }
    }
}

pub(super) fn require_remaining(deadline: Instant) -> Result<Duration, SourceGenesisErrorV1> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(SourceGenesisErrorV1::Stale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_elapsed_deadline_never_admits_io() {
        let deadline = Instant::now() - Duration::from_millis(1);
        assert!(require_remaining(deadline).is_err());
        assert!(connect_fixed(deadline).is_err());
    }

    #[test]
    fn only_unadmitted_absence_or_refusal_allows_connection_retry() {
        for errno in [rustix::io::Errno::NOENT, rustix::io::Errno::CONNREFUSED] {
            let error = SourceGenesisErrorV1::Transport(std::io::Error::from(errno));
            assert!(connection_not_admitted(&error));
        }
        for errno in [
            rustix::io::Errno::AGAIN,
            rustix::io::Errno::TIMEDOUT,
            rustix::io::Errno::INTR,
            rustix::io::Errno::CONNRESET,
            rustix::io::Errno::ACCESS,
        ] {
            let error = SourceGenesisErrorV1::Transport(std::io::Error::from(errno));
            assert!(!connection_not_admitted(&error));
        }
        assert!(!connection_not_admitted(&SourceGenesisErrorV1::Stale));
    }
}
