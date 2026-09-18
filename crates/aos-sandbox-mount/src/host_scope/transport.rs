//! Deadline-bounded readiness for the closed RootMount descriptor carrier.

use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use rustix::event::{PollFd, PollFlags, poll};

use super::{HostScopeError, Result};

const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;

pub(super) enum ReplyProfile {
    Hello,
    Scope,
}

pub(super) fn boottime() -> Result<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| HostScopeError::Deadline)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| HostScopeError::Deadline)?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(HostScopeError::Deadline)
}

pub(super) fn exchange_deadline(request: u64) -> Result<u64> {
    let now = boottime()?;
    if now >= request {
        return Err(HostScopeError::Deadline);
    }

    let ceiling = now
        .checked_add(EXCHANGE_NANOSECONDS)
        .ok_or(HostScopeError::Deadline)?;

    Ok(request.min(ceiling))
}

pub(super) fn check_deadline(deadline: u64) -> Result<()> {
    if boottime()? >= deadline {
        return Err(HostScopeError::Deadline);
    }

    Ok(())
}

pub(super) fn send(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    deadline: u64,
) -> Result<()> {
    loop {
        check_deadline(deadline)?;

        match socket.send(bytes) {
            Ok(()) => return check_deadline(deadline),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::OUT, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) fn receive(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    profile: ReplyProfile,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord> {
    loop {
        check_deadline(deadline)?;
        let received = match profile {
            ReplyProfile::Hello => socket.receive(maximum_bytes, 0),
            ReplyProfile::Scope => socket.receive_mount_scope_reply(maximum_bytes),
        };

        match received {
            Ok(record) => {
                check_deadline(deadline)?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::IN, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait(socket: &DescriptorSubjectSocket, events: PollFlags, deadline: u64) -> Result<()> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(HostScopeError::Deadline)?;
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| HostScopeError::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000).map_err(|_| HostScopeError::Deadline)?,
    };
    let mut fds = [PollFd::from_borrowed_fd(socket.as_fd()?, events)];

    match poll(&mut fds, Some(&timeout)) {
        Ok(0) => Err(HostScopeError::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    //! Deadline rejection must precede packet consumption and descriptor adoption.

    #![allow(
        clippy::unwrap_used,
        reason = "Test fixture failures intentionally panic."
    )]

    use super::*;

    #[test]
    fn expired_exchange_deadlines_are_rejected() {
        assert!(matches!(
            exchange_deadline(0),
            Err(HostScopeError::Deadline)
        ));
        assert!(matches!(check_deadline(0), Err(HostScopeError::Deadline)));

        let before = boottime().unwrap();
        let deadline = exchange_deadline(u64::MAX).unwrap();
        let after = boottime().unwrap();

        assert!(deadline >= before + EXCHANGE_NANOSECONDS);
        assert!(deadline <= after + EXCHANGE_NANOSECONDS);
    }

    #[test]
    fn expired_receive_does_not_consume_a_queued_record() {
        let (receiver, sender) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned(receiver).unwrap();
        let mut sender = DescriptorSubjectSocket::from_owned(sender).unwrap();
        sender.send(b"hello").unwrap();

        assert!(matches!(
            receive(&mut receiver, 64, ReplyProfile::Hello, 0),
            Err(HostScopeError::Deadline)
        ));
        let record = receive(
            &mut receiver,
            64,
            ReplyProfile::Hello,
            exchange_deadline(u64::MAX).unwrap(),
        )
        .unwrap();

        assert_eq!(record.payload(), b"hello");
    }
}
