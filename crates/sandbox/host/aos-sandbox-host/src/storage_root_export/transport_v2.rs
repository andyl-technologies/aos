//! Shares the existing deadline/send/receive/poll loops across custody choices.
//!
//! Retained errors own their actual lower native prefix. Ordinary adapters keep
//! the old error presentation and consuming native disposition.

use std::num::TryFromIntError;
use std::os::fd::AsFd as _;

use aos_sandbox_linux::seqpacket::{SeqpacketError, RetainedSeqpacketReceiveErrorV1};
use aos_sandbox_linux::seqpacket::descriptor_subject::{DescriptorSubjectSocket, ReceivedDescriptorRecord};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use crate::HostError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageClientTransportErrorV2 {
    #[error("root export deadline elapsed")]
    Deadline,
    #[error("root export clock overflow")]
    ClockOverflow,
    #[error(transparent)]
    Integer(#[from] TryFromIntError),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
    #[error(transparent)]
    Carrier(#[from] SeqpacketError),
    #[error(transparent)]
    RetainedReceive(#[from] RetainedSeqpacketReceiveErrorV1),
}

impl StorageClientTransportErrorV2 {
    pub(super) fn into_ordinary_error(self) -> HostError {
        match self {
            Self::Deadline => HostError::State("root export deadline elapsed".to_owned()),
            Self::ClockOverflow => HostError::State("root export clock overflow".to_owned()),
            cause => super::export_error(cause),
        }
    }
}

pub(crate) fn send_request_retaining_v2(
    socket: &mut DescriptorSubjectSocket, bytes: &[u8], deadline: u64,
) -> Result<(), StorageClientTransportErrorV2> {
    send_request_recipe_v2(socket, bytes, deadline, true)
}

pub(super) fn send_request_recipe_v2(
    socket: &mut DescriptorSubjectSocket, bytes: &[u8], deadline: u64, retained: bool,
) -> Result<(), StorageClientTransportErrorV2> {
    loop {
        if boottime_v2()? >= deadline { return Err(StorageClientTransportErrorV2::Deadline); }
        let result = if retained { socket.send_retaining(bytes) } else { socket.send(bytes) };
        match result {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_until_v2(socket, PollFlags::OUT, deadline)?;
            }
            Err(cause) => return Err(cause.into()),
        }
    }
}

pub(crate) fn receive_reply_retaining_v2(
    socket: &mut DescriptorSubjectSocket, deadline: u64, maximum_bytes: usize,
) -> Result<ReceivedDescriptorRecord, StorageClientTransportErrorV2> {
    receive_reply_recipe_v2(socket, deadline, maximum_bytes, 0, true)
}

pub(crate) fn receive_root_mount_reply_retaining_v2(
    socket: &mut DescriptorSubjectSocket, deadline: u64, maximum_bytes: usize,
) -> Result<ReceivedDescriptorRecord, StorageClientTransportErrorV2> {
    receive_reply_with_custody_v2(socket, deadline, maximum_bytes, 1, ReceiveCustodyV2::RootMount)
}

pub(crate) fn receive_capture_pipes_retaining_v2(
    socket: &mut DescriptorSubjectSocket,
    deadline: u64,
    maximum_bytes: usize,
) -> Result<ReceivedDescriptorRecord, StorageClientTransportErrorV2> {
    receive_reply_with_custody_v2(socket, deadline, maximum_bytes, 2, ReceiveCustodyV2::CapturePipes)
}

#[derive(Clone, Copy)]
enum ReceiveCustodyV2 { Ordinary, HeldOutput, RootMount, CapturePipes }

pub(super) fn receive_reply_recipe_v2(
    socket: &mut DescriptorSubjectSocket, deadline: u64, maximum_bytes: usize,
    maximum_descriptors: usize, retained: bool,
) -> Result<ReceivedDescriptorRecord, StorageClientTransportErrorV2> {
    receive_reply_with_custody_v2(socket, deadline, maximum_bytes, maximum_descriptors,
        if retained { ReceiveCustodyV2::HeldOutput } else { ReceiveCustodyV2::Ordinary })
}

fn receive_reply_with_custody_v2(
    socket: &mut DescriptorSubjectSocket, deadline: u64, maximum_bytes: usize,
    maximum_descriptors: usize, custody: ReceiveCustodyV2,
) -> Result<ReceivedDescriptorRecord, StorageClientTransportErrorV2> {
    loop {
        if boottime_v2()? >= deadline { return Err(StorageClientTransportErrorV2::Deadline); }
        if !matches!(custody, ReceiveCustodyV2::Ordinary) {
            let received = match custody {
                ReceiveCustodyV2::RootMount => socket.receive_root_mount_reply_retaining_v2(maximum_bytes),
                ReceiveCustodyV2::CapturePipes => socket.receive_storage_capture_pipes_retaining_v2(maximum_bytes),
                ReceiveCustodyV2::HeldOutput => socket.receive_storage_held_output_reply_retaining_v2(maximum_bytes),
                ReceiveCustodyV2::Ordinary => std::process::abort(),
            };
            match received {
                Ok(record) => return Ok(record),
                Err(cause) if cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted() => {
                    wait_until_v2(socket, PollFlags::IN, deadline)?;
                }
                Err(cause) => return Err(cause.into()),
            }
        } else {
            match socket.receive(maximum_bytes, maximum_descriptors) {
                Ok(record) => return Ok(record),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    wait_until_v2(socket, PollFlags::IN, deadline)?;
                }
                Err(cause) => return Err(cause.into()),
            }
        }
    }
}

pub(super) fn wait_until_v2(
    socket: &DescriptorSubjectSocket, events: PollFlags, deadline: u64,
) -> Result<(), StorageClientTransportErrorV2> {
    let remaining = deadline.checked_sub(boottime_v2()?)
        .filter(|remaining| *remaining > 0).ok_or(StorageClientTransportErrorV2::Deadline)?;
    let timeout = Timespec::try_from(std::time::Duration::from_nanos(remaining))?;
    let fd = socket.as_fd()?;
    let mut ready = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut ready, Some(&timeout)) {
        Ok(0) => Err(StorageClientTransportErrorV2::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(cause) => Err(cause.into()),
    }
}

pub(crate) fn boottime_v2() -> Result<u64, StorageClientTransportErrorV2> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)?;
    let nanos = u64::try_from(now.tv_nsec)?;
    seconds.checked_mul(1_000_000_000).and_then(|value| value.checked_add(nanos))
        .ok_or(StorageClientTransportErrorV2::ClockOverflow)
}
