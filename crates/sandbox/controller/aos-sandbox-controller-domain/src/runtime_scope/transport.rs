//! Deadline-bounded readiness around the nonblocking descriptor-subject carrier.

use aos_sandbox_linux::seqpacket::{SeqpacketError, RetainedSeqpacketReceiveErrorV1};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use rustix::event::{PollFd, PollFlags, poll};

use super::RuntimeScopeError;

const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;

pub(super) fn boottime() -> Result<u64, RuntimeScopeError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| RuntimeScopeError::Deadline)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| RuntimeScopeError::Deadline)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(RuntimeScopeError::Deadline)
}

pub(super) fn exchange_deadline(request: u64) -> Result<u64, RuntimeScopeError> {
    let now = boottime()?;
    if now >= request {
        return Err(RuntimeScopeError::Deadline);
    }
    Ok(request.min(
        now.checked_add(EXCHANGE_NANOSECONDS)
            .ok_or(RuntimeScopeError::Deadline)?,
    ))
}

pub(super) fn check_deadline(deadline: u64) -> Result<(), RuntimeScopeError> {
    if boottime()? >= deadline {
        return Err(RuntimeScopeError::Deadline);
    }
    Ok(())
}

pub(super) fn send(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    deadline: u64,
) -> Result<(), RuntimeScopeError> {
    send_with_disposition(socket, bytes, deadline, false)
}

pub(super) fn send_with_disposition(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    deadline: u64,
    retaining: bool,
) -> Result<(), RuntimeScopeError> {
    loop {
        check_deadline(deadline)?;
        let sent = if retaining { socket.send_retaining(bytes) } else { socket.send(bytes) };
        match sent {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::OUT, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) fn receive(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    descriptors: Option<usize>,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, RuntimeScopeError> {
    receive_with_disposition(socket, maximum_bytes, descriptors, deadline, None)
}

enum ReceiveErrorV1 {
    Ordinary(SeqpacketError),
    Retained(RetainedSeqpacketReceiveErrorV1),
}

impl ReceiveErrorV1 {
    fn would_block(&self) -> bool {
        match self {
            Self::Ordinary(error) => matches!(error, SeqpacketError::WouldBlock),
            Self::Retained(error) => error.is_nonconsuming_would_block(),
        }
    }

    fn interrupted(&self) -> bool {
        match self {
            Self::Ordinary(error) => matches!(error, SeqpacketError::Interrupted),
            Self::Retained(error) => error.is_nonconsuming_interrupted(),
        }
    }
}

pub(super) fn receive_with_disposition(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    descriptors: Option<usize>,
    deadline: u64,
    mut original: Option<&mut Option<RetainedSeqpacketReceiveErrorV1>>,
) -> Result<ReceivedDescriptorRecord, RuntimeScopeError> {
    loop {
        check_deadline(deadline)?;
        let received = if original.is_some() {
            match descriptors {
                Some(0) => socket.receive_zero_descriptors_retaining(maximum_bytes),
                None => socket.receive_reply_retaining_v1(maximum_bytes),
                Some(_) => return Err(RuntimeScopeError::Descriptor),
            }.map_err(ReceiveErrorV1::Retained)
        } else {
            match descriptors {
                Some(exact) => socket.receive(maximum_bytes, exact),
                None => socket.receive_reply(maximum_bytes),
            }.map_err(ReceiveErrorV1::Ordinary)
        };
        match received {
            Ok(record) => return Ok(record),
            Err(error) if error.would_block() => wait(socket, PollFlags::IN, deadline)?,
            Err(error) if error.interrupted() => {},
            Err(ReceiveErrorV1::Ordinary(error)) => return Err(error.into()),
            Err(ReceiveErrorV1::Retained(error)) => {
                let Some(destination) = original.as_deref_mut() else { std::process::abort(); };
                if destination.is_some() { std::process::abort(); }
                *destination = Some(error);
                return Err(RuntimeScopeError::RetainedNative);
            }
        }
    }
}

fn wait(
    socket: &DescriptorSubjectSocket,
    events: PollFlags,
    deadline: u64,
) -> Result<(), RuntimeScopeError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(RuntimeScopeError::Deadline)?;
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| RuntimeScopeError::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| RuntimeScopeError::Deadline)?,
    };
    let mut fds = [PollFd::from_borrowed_fd(socket.as_fd()?, events)];
    match poll(&mut fds, Some(&timeout)) {
        Ok(0) => Err(RuntimeScopeError::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
