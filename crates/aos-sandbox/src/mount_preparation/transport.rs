//! Deadline-bounded readiness for one controller-to-Mount exchange.

use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use rustix::event::{PollFd, PollFlags, poll};

use super::MountCatalogPreparationError;

const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;

pub(crate) fn boottime() -> Result<u64, MountCatalogPreparationError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| MountCatalogPreparationError::Deadline)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| MountCatalogPreparationError::Deadline)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(MountCatalogPreparationError::Deadline)
}

pub(crate) fn exchange_deadline(request: u64) -> Result<u64, MountCatalogPreparationError> {
    let now = boottime()?;
    if now >= request {
        return Err(MountCatalogPreparationError::Deadline);
    }
    Ok(request.min(
        now.checked_add(EXCHANGE_NANOSECONDS)
            .ok_or(MountCatalogPreparationError::Deadline)?,
    ))
}

pub(crate) fn check_deadline(deadline: u64) -> Result<(), MountCatalogPreparationError> {
    if boottime()? >= deadline {
        return Err(MountCatalogPreparationError::Deadline);
    }
    Ok(())
}

pub(crate) fn send(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    deadline: u64,
) -> Result<(), MountCatalogPreparationError> {
    loop {
        check_deadline(deadline)?;
        match socket.send(bytes) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::OUT, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn receive(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, MountCatalogPreparationError> {
    loop {
        check_deadline(deadline)?;
        match socket.receive(maximum_bytes, 0) {
            Ok(record) => return Ok(record),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::IN, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait(
    socket: &DescriptorSubjectSocket,
    events: PollFlags,
    deadline: u64,
) -> Result<(), MountCatalogPreparationError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(MountCatalogPreparationError::Deadline)?;
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| MountCatalogPreparationError::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| MountCatalogPreparationError::Deadline)?,
    };
    let mut fds = [PollFd::from_borrowed_fd(socket.as_fd()?, events)];
    match poll(&mut fds, Some(&timeout)) {
        Ok(0) => Err(MountCatalogPreparationError::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
