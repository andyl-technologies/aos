//! Deadline-bounded record exchange for record-subject services.

use std::os::fd::BorrowedFd;

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::{ReceivedRecord, RecordSubjectListener, SeqpacketError, SeqpacketSocket};

/// Reports a bounded exchange failure without assigning service policy.
#[derive(Debug, thiserror::Error)]
pub enum BoundedRecordError {
    /// The record carrier failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Polling failed.
    #[error(transparent)]
    Io(#[from] rustix::io::Errno),
    /// Boot time was invalid or the exchange deadline expired.
    #[error("bounded record exchange deadline expired or clock was invalid")]
    Clock,
}

/// Waits for one checked connection, rejecting a stale queued child.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for listener or polling failure.
pub fn accept_connection(
    listener: &mut RecordSubjectListener,
) -> Result<Option<SeqpacketSocket>, BoundedRecordError> {
    loop {
        listener.validate_current()?;
        match listener.accept() {
            Ok(connection) => return Ok(Some(connection)),
            Err(SeqpacketError::WouldBlock) => wait_unbounded(listener.as_fd(), PollFlags::IN)?,
            Err(SeqpacketError::Interrupted) => {}
            // A queued child may predate the listener's identity options.
            Err(SeqpacketError::Kernel(crate::Error::InvalidInput {
                field: "record subject options",
                ..
            })) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
}

/// Receives one complete record before a `CLOCK_BOOTTIME` deadline.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for transport, polling, or deadline failure.
pub fn receive(
    socket: &mut SeqpacketSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedRecord, BoundedRecordError> {
    loop {
        check_deadline(deadline)?;
        match socket.receive(maximum_bytes) {
            Ok(record) => {
                check_deadline(deadline)?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock) => {
                wait_until(socket.as_fd()?, PollFlags::IN, deadline)?
            }
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// Sends one complete record before a `CLOCK_BOOTTIME` deadline.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for transport, polling, or deadline failure.
pub fn send(
    socket: &mut SeqpacketSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), BoundedRecordError> {
    loop {
        check_deadline(deadline)?;
        match socket.send(payload) {
            Ok(()) => return check_deadline(deadline),
            Err(SeqpacketError::WouldBlock) => {
                wait_until(socket.as_fd()?, PollFlags::OUT, deadline)?
            }
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// Reads nonnegative `CLOCK_BOOTTIME` nanoseconds.
///
/// # Errors
///
/// Returns [`BoundedRecordError::Clock`] for negative or overflowing time.
pub fn boottime() -> Result<u64, BoundedRecordError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| BoundedRecordError::Clock)?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| BoundedRecordError::Clock)?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(BoundedRecordError::Clock)
}

fn check_deadline(deadline: u64) -> Result<(), BoundedRecordError> {
    if boottime()? >= deadline {
        return Err(BoundedRecordError::Clock);
    }

    Ok(())
}

fn wait_unbounded(fd: BorrowedFd<'_>, events: PollFlags) -> Result<(), BoundedRecordError> {
    let mut descriptors = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut descriptors, None) {
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn wait_until(
    fd: BorrowedFd<'_>,
    events: PollFlags,
    deadline: u64,
) -> Result<(), BoundedRecordError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(BoundedRecordError::Clock)?;
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| BoundedRecordError::Clock)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000).map_err(|_| BoundedRecordError::Clock)?,
    };
    let mut descriptors = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(BoundedRecordError::Clock),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
