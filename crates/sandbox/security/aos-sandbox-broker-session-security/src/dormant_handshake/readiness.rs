//! Keeps the actual finite readiness sample through its independent owner posts.
//!
//! The ordinary caller and selected Inventory use the same poll/time recipe.
//! This capsule adds no timeout renewal, descriptor ownership or traffic grant.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::BorrowedFd;

use rustix::event::{PollFd, Timespec};

use super::{wait_for_handshake_readiness_inner, DormantBrokerSessionHandshakeErrorV1};

#[derive(Default)]
pub(crate) struct HandshakeReadinessOriginalsV1 {
    pub(super) clock: Option<Timespec>,
    pub(super) remaining: Option<u64>,
    pub(super) timeout: Option<Timespec>,
    pub(super) native: Option<Result<usize, rustix::io::Errno>>,
    returned: Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>,
    entered: bool,
    closed: Option<DormantBrokerSessionHandshakeErrorV1>,
}

impl HandshakeReadinessOriginalsV1 {
    pub(crate) fn observe_once(
        &mut self,
        descriptor: BorrowedFd<'_>,
        wants_write: bool,
        original_cutoff: u64,
    ) -> bool {
        if self.entered {
            self.closed
                .get_or_insert(DormantBrokerSessionHandshakeErrorV1::Transport);
            return false;
        }

        self.entered = true;
        self.returned = Some(wait_for_handshake_readiness_inner(
            descriptor,
            wants_write,
            original_cutoff,
            None,
            Some(self),
        ));
        self.require_positive()
    }

    pub(crate) fn require_positive(&self) -> bool {
        self.closed.is_none()
            && matches!(self.returned, Some(Ok(())))
            && self.failure().is_none()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.as_ref()
            .and_then(|result| match result {
                Err(cause) if *cause != rustix::io::Errno::INTR => Some(cause as &dyn Error),
                _ => None,
            })
            .or_else(|| self.returned.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn receiving_construction_bytes_v1() -> Option<usize> {
        // The enclosing flight pays the resident capsule. The shared engine
        // additionally constructs one borrowed pollfd, its clock/timeout copies
        // and native/returned Result carriers; no new descriptor is opened.
        size_of::<PollFd<'static>>()
            .checked_add(4 * size_of::<Timespec>())?
            .checked_add(2 * size_of::<Option<Result<usize, rustix::io::Errno>>>())?
            .checked_add(2 * size_of::<DormantBrokerSessionHandshakeErrorV1>())
    }

    pub(crate) const fn receiving_metadata_cells_v1() -> usize {
        // Seven resident destinations plus the local pollfd/readiness flags.
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    #[test]
    fn writable_socket_keeps_the_actual_positive_poll_until_disposal() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut original = HandshakeReadinessOriginalsV1::default();

        assert!(original.observe_once(socket.as_fd(), true, u64::MAX));

        assert!(original.clock.is_some());
        assert!(original.timeout.is_some());
        assert!(matches!(original.native, Some(Ok(count)) if count > 0));
        assert!(original.failure().is_none());
    }

    #[test]
    fn expired_original_keeps_clock_and_exact_refusal_without_poll_or_renewal() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut original = HandshakeReadinessOriginalsV1::default();

        assert!(!original.observe_once(socket.as_fd(), true, 0));
        assert!(original.clock.is_some());
        assert!(original.native.is_none());
        assert!(matches!(
            original.returned,
            Some(Err(DormantBrokerSessionHandshakeErrorV1::Deadline))
        ));
        let first = original.failure().unwrap() as *const dyn Error as *const ();
        assert!(!original.observe_once(socket.as_fd(), true, u64::MAX));
        assert_eq!(
            first,
            original.failure().unwrap() as *const dyn Error as *const ()
        );
    }
}
