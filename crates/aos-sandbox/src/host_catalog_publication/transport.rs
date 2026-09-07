//! Deadline-bounded transport for one controller-to-Host publication.

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;

use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use super::HostCatalogPublicationError;

const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;

pub(super) fn boottime() -> Result<u64, HostCatalogPublicationError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| HostCatalogPublicationError::Deadline)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| HostCatalogPublicationError::Deadline)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(HostCatalogPublicationError::Deadline)
}

pub(super) fn exchange_deadline(request: u64) -> Result<u64, HostCatalogPublicationError> {
    let now = boottime()?;
    if now >= request {
        return Err(HostCatalogPublicationError::Deadline);
    }
    Ok(request.min(
        now.checked_add(EXCHANGE_NANOSECONDS)
            .ok_or(HostCatalogPublicationError::Deadline)?,
    ))
}

pub(super) fn check_deadline(deadline: u64) -> Result<(), HostCatalogPublicationError> {
    if boottime()? >= deadline {
        return Err(HostCatalogPublicationError::Deadline);
    }
    Ok(())
}

pub(super) fn send(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    deadline: u64,
) -> Result<(), HostCatalogPublicationError> {
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

pub(super) fn send_descriptor(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    descriptor: BorrowedFd<'_>,
    deadline: u64,
) -> Result<(), HostCatalogPublicationError> {
    loop {
        check_deadline(deadline)?;
        let descriptors = [descriptor];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(HostCatalogPublicationError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::DescriptorTableMismatch,
            ));
        }
        match sendmsg(
            socket.as_fd()?,
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(written) if written == bytes.len() => return Ok(()),
            Ok(written) => {
                return Err(SeqpacketError::PartialSend {
                    expected: bytes.len(),
                    actual: written,
                }
                .into());
            }
            Err(rustix::io::Errno::AGAIN) => wait(socket, PollFlags::OUT, deadline)?,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) fn receive(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, HostCatalogPublicationError> {
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
) -> Result<(), HostCatalogPublicationError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(HostCatalogPublicationError::Deadline)?;
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| HostCatalogPublicationError::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| HostCatalogPublicationError::Deadline)?,
    };
    let mut fds = [PollFd::from_borrowed_fd(socket.as_fd()?, events)];
    match poll(&mut fds, Some(&timeout)) {
        Ok(0) => Err(HostCatalogPublicationError::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
