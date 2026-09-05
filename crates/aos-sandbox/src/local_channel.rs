//! Non-consuming shutdown observations shared by retained local channel proofs.
//!
//! Socket connectivity proves neither process identity nor application authority.
//! Callers combine this point-in-time check with their own retained kernel and
//! protected-state checks; it cannot fence a later close or delegated endpoint.

use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

pub(crate) fn check_connected(socket: &SeqpacketSocket) -> Result<(), SeqpacketError> {
    // A writer can close its channel while its process remains alive. Readable
    // queued records are allowed and must not be consumed by a liveness probe.
    let failures = PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL;
    let mut descriptors = [PollFd::from_borrowed_fd(socket.as_fd()?, PollFlags::RDHUP)];
    poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|source| aos_sandbox_linux::Error::Syscall {
        operation: "poll retained local connection",
        source: source.into(),
    })?;
    if descriptors[0].revents().intersects(failures) {
        return Err(SeqpacketError::Closed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Kernel fixture failures intentionally panic."
    )]

    use super::*;

    #[test]
    fn queued_record_is_not_consumed_and_last_endpoint_close_is_observed() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        check_connected(&receiver).unwrap();
        sender.send(b"queued").unwrap();
        check_connected(&receiver).unwrap();
        assert_eq!(receiver.receive(16).unwrap().payload(), b"queued");
        sender.close();
        assert!(matches!(
            check_connected(&receiver),
            Err(SeqpacketError::Closed)
        ));
    }
}
