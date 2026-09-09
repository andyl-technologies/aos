//! Bounded nonblocking record-subject transport for Storage RPC.

use std::os::fd::BorrowedFd;

use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordSubjectListener, SeqpacketError, SeqpacketSocket,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::service::StorageServiceError;

/// Fixed wall-independent ceiling for one accepted hello/request exchange.
pub(crate) const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;

/// Waits for and accepts one checked record-subject connection.
///
/// A child queued before the required listener options were installed is
/// rejected without invalidating the listener.
///
/// # Errors
///
/// Returns [`StorageServiceError`] for listener corruption, readiness polling
/// failure, or an unexpected accept error.
pub(crate) fn accept_connection(
    listener: &mut RecordSubjectListener,
) -> Result<Option<SeqpacketSocket>, StorageServiceError> {
    loop {
        listener.validate_current()?;
        match listener.accept() {
            Ok(connection) => return Ok(Some(connection)),
            Err(SeqpacketError::WouldBlock) => wait_unbounded(listener.as_fd(), PollFlags::IN)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(SeqpacketError::Kernel(aos_sandbox_linux::Error::InvalidInput {
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
/// Returns [`StorageServiceError`] for deadline expiry, polling failure, or a
/// bounded record-subject transport violation.
pub(crate) fn receive(
    socket: &mut SeqpacketSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedRecord, StorageServiceError> {
    loop {
        check_deadline(deadline)?;
        match socket.receive(maximum_bytes) {
            Ok(record) => {
                check_deadline(deadline)?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock) => {
                wait_until(socket.as_fd()?, PollFlags::IN, deadline)?;
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
/// Returns [`StorageServiceError`] for deadline expiry, polling failure, or a
/// bounded record-subject transport violation.
pub(crate) fn send(
    socket: &mut SeqpacketSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), StorageServiceError> {
    loop {
        check_deadline(deadline)?;
        match socket.send(payload) {
            Ok(()) => return check_deadline(deadline),
            Err(SeqpacketError::WouldBlock) => {
                wait_until(socket.as_fd()?, PollFlags::OUT, deadline)?;
            }
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// Reads monotonic boot time as nonnegative nanoseconds.
///
/// # Errors
///
/// Returns [`StorageServiceError::Clock`] for a negative or overflowing kernel
/// result.
pub(crate) fn boottime() -> Result<u64, StorageServiceError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| StorageServiceError::Clock)?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| StorageServiceError::Clock)?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(StorageServiceError::Clock)
}

fn check_deadline(deadline: u64) -> Result<(), StorageServiceError> {
    if boottime()? >= deadline {
        return Err(StorageServiceError::Clock);
    }

    Ok(())
}

fn wait_unbounded(fd: BorrowedFd<'_>, events: PollFlags) -> Result<(), StorageServiceError> {
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
) -> Result<(), StorageServiceError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(StorageServiceError::Clock)?;
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| StorageServiceError::Clock)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| StorageServiceError::Clock)?,
    };
    let mut descriptors = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(StorageServiceError::Clock),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
