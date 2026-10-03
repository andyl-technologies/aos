//! Private kernel socket identity used to bind consumed records to their source.
//!
//! Linux assigns one nonzero `SO_COOKIE` value to a socket object. Duplicated
//! descriptors for that object report the same value, while the opposite
//! endpoint and independently created sockets report different values. These
//! private types retain that kernel observation only for same-socket carrier
//! continuity; they do not authenticate a peer, writer, role, or channel.

use std::fmt;
use std::num::NonZeroU64;
use std::os::fd::BorrowedFd;

use super::{RecordBindingError, SeqpacketError};
use crate::uapi;

/// Retains the nonzero kernel identity of one connected socket object.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ConnectedSocketBinding(NonZeroU64);

impl ConnectedSocketBinding {
    /// Captures an adoption-time binding with the legacy peer-error taxonomy.
    pub(super) fn capture_peer(fd: BorrowedFd<'_>) -> Result<Self, SeqpacketError> {
        let cookie = uapi::socket_cookie(fd)?;
        NonZeroU64::new(cookie)
            .map(Self)
            .ok_or(SeqpacketError::PeerIdentity(
                "SO_COOKIE returned the reserved zero value",
            ))
    }

    /// Requires the borrowed descriptor to name this exact retained socket.
    pub(super) fn require_current(self, fd: BorrowedFd<'_>) -> Result<(), RecordBindingError> {
        #[cfg(test)]
        CURRENT_QUERY_COUNT.with(|count| count.set(count.get() + 1));

        let cookie = uapi::socket_cookie(fd).map_err(|_| RecordBindingError::current_socket())?;
        if Self::decode_current_cookie(cookie)? != self {
            return Err(RecordBindingError::current_socket());
        }

        Ok(())
    }

    /// Creates a private record stamp without another kernel observation.
    pub(super) const fn received_origin(self) -> ReceivedSocketOrigin {
        ReceivedSocketOrigin(self)
    }

    /// Returns the legacy non-authorizing socket-cookie observation.
    pub(super) const fn socket_cookie(self) -> NonZeroU64 {
        self.0
    }

    fn decode_current_cookie(cookie: u64) -> Result<Self, RecordBindingError> {
        NonZeroU64::new(cookie)
            .map(Self)
            .ok_or_else(RecordBindingError::current_socket)
    }
}

impl fmt::Debug for ConnectedSocketBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectedSocketBinding")
    }
}

/// Privately stamps the exact socket from which a complete record was consumed.
pub(super) struct ReceivedSocketOrigin(ConnectedSocketBinding);

impl ReceivedSocketOrigin {
    /// Requires this stamp to name the retained connection binding.
    pub(super) fn require_binding(
        &self,
        binding: ConnectedSocketBinding,
    ) -> Result<(), RecordBindingError> {
        if self.0 != binding {
            return Err(RecordBindingError::origin_mismatch());
        }

        Ok(())
    }
}

#[cfg(test)]
std::thread_local! {
    static CURRENT_QUERY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_current_query_count() {
    CURRENT_QUERY_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn current_query_count() -> usize {
    CURRENT_QUERY_COUNT.with(std::cell::Cell::get)
}

impl fmt::Debug for ReceivedSocketOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceivedSocketOrigin")
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "Kernel socket fixture failures intentionally panic."
    )]

    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn duplicate_descriptors_share_only_their_source_socket_binding() {
        let (source, opposite) = uapi::seqpacket_pair().expect("source socket pair");
        let (independent, _independent_opposite) =
            uapi::seqpacket_pair().expect("independent socket pair");
        let duplicate = uapi::duplicate_at_least(source.as_fd(), 0).expect("duplicate source");
        let binding = ConnectedSocketBinding::capture_peer(source.as_fd()).expect("source binding");

        binding
            .require_current(duplicate.as_fd())
            .expect("same kernel socket");
        assert!(matches!(
            binding.require_current(opposite.as_fd()),
            Err(error) if error.category() == super::super::RecordBindingErrorCategory::CurrentSocket
        ));
        assert!(matches!(
            binding.require_current(independent.as_fd()),
            Err(error) if error.category() == super::super::RecordBindingErrorCategory::CurrentSocket
        ));
    }

    #[test]
    fn zero_and_cookie_query_failures_are_rejected() {
        assert!(matches!(
            ConnectedSocketBinding::decode_current_cookie(0),
            Err(error) if error.category() == super::super::RecordBindingErrorCategory::CurrentSocket
        ));

        let (socket, _opposite) = uapi::seqpacket_pair().expect("socket pair");
        let binding = ConnectedSocketBinding::capture_peer(socket.as_fd()).expect("socket binding");
        let file = tempfile::tempfile().expect("ordinary file");
        assert!(matches!(
            binding.require_current(file.as_fd()),
            Err(error) if error.category() == super::super::RecordBindingErrorCategory::CurrentSocket
        ));
    }

    #[test]
    fn capture_and_recheck_leave_socket_state_unchanged() {
        let (socket, _opposite) = uapi::seqpacket_pair().expect("socket pair");
        uapi::enable_socket_passcred_for_test(socket.as_fd()).expect("enable SO_PASSCRED");
        let status = uapi::get_status_flags(socket.as_fd()).expect("status flags");
        let cloexec = uapi::is_cloexec(socket.as_fd()).expect("descriptor flags");
        let passcred = uapi::socket_passcred_for_test(socket.as_fd()).expect("SO_PASSCRED");

        let binding =
            ConnectedSocketBinding::capture_peer(socket.as_fd()).expect("capture binding");
        binding
            .require_current(socket.as_fd())
            .expect("recheck binding");

        assert_eq!(
            uapi::get_status_flags(socket.as_fd()).expect("final status flags"),
            status
        );
        assert_eq!(
            uapi::is_cloexec(socket.as_fd()).expect("final descriptor flags"),
            cloexec
        );
        assert_eq!(
            uapi::socket_passcred_for_test(socket.as_fd()).expect("final SO_PASSCRED"),
            passcred
        );
    }
}
