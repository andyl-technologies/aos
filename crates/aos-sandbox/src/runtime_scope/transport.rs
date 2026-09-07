//! Deadline-bounded readiness around the nonblocking descriptor-subject carrier.

use aos_sandbox_linux::seqpacket::SeqpacketError;
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

pub(super) fn receive(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    descriptors: Option<usize>,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, RuntimeScopeError> {
    loop {
        check_deadline(deadline)?;
        let received = match descriptors {
            Some(exact) => socket.receive(maximum_bytes, exact),
            None => socket.receive_reply(maximum_bytes),
        };
        match received {
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
