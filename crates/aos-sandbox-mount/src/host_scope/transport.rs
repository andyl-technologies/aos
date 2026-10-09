//! Deadline-bounded readiness for the closed RootMount descriptor carrier.

use aos_sandbox_linux::seqpacket::bounded::{self, BoundedRecordError};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};

use super::{HostScopeError, Result};

const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;

pub(super) enum ReplyProfile {
    Hello,
    Scope,
}

pub(super) fn boottime() -> Result<u64> {
    bounded::boottime().map_err(map_exchange_error)
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
    bounded::send_descriptor_record(socket, bytes, deadline).map_err(map_exchange_error)
}

pub(super) fn receive(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    profile: ReplyProfile,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord> {
    let received = match profile {
        ReplyProfile::Hello => bounded::receive_zero_descriptors(socket, maximum_bytes, deadline),
        ReplyProfile::Scope => bounded::receive_mount_scope_reply(socket, maximum_bytes, deadline),
    };

    received.map_err(map_exchange_error)
}

fn map_exchange_error(error: BoundedRecordError) -> HostScopeError {
    match error {
        BoundedRecordError::Transport(error) => HostScopeError::Transport(error),
        BoundedRecordError::Io(error) => HostScopeError::Io(error),
        BoundedRecordError::Clock => HostScopeError::Deadline,
    }
}

#[cfg(test)]
mod tests {
    //! Mount owns its signed deadline cap and domain-specific error categories.

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
    fn exchange_errors_keep_the_existing_domain_categories() {
        use aos_sandbox_linux::seqpacket::SeqpacketError;

        assert!(matches!(
            map_exchange_error(BoundedRecordError::Clock),
            HostScopeError::Deadline
        ));
        assert!(matches!(
            map_exchange_error(BoundedRecordError::Io(rustix::io::Errno::IO)),
            HostScopeError::Io(rustix::io::Errno::IO)
        ));
        assert!(matches!(
            map_exchange_error(BoundedRecordError::Transport(SeqpacketError::Closed)),
            HostScopeError::Transport(SeqpacketError::Closed)
        ));
    }
}
