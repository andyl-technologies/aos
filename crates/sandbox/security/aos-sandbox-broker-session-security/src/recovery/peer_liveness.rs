//! Retains a selected recovery peer's actual returned liveness observation.
//!
//! This is once-only result DATA, never a peer, Session, payer or currentness
//! constructor. Its real caller keeps the same connected socket and genuine
//! paid Journal owner resident. Ordinary helpers use the same predicate with
//! their existing immediate native-error disposition.

use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;

use crate::BrokerSessionSecurityError;

/// Owns one selected recovery peer observation until its actual owner disposes it.
#[derive(Default)]
pub(crate) struct ObservedBrokerPeerOriginalV1 {
    liveness: Option<Result<bool, aos_linux_descriptors::Error>>,
    reentered: bool,
}

impl ObservedBrokerPeerOriginalV1 {
    pub(super) fn observe_once(
        &mut self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<bool, BrokerSessionSecurityError> {
        if self.liveness.is_some() || self.reentered {
            self.reentered = true;
            return Err(BrokerSessionSecurityError::Currentness);
        }

        self.liveness = Some(peer.is_alive());
        self.liveness
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    /// Borrows the original native error without replacing its classification.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.liveness
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
    }
}

/// Describes native-error heap, metadata and one local construction carrier.
///
/// Inline result/header storage is counted by its actual enclosing owner size.
/// The native poll returns only fixed operation/readiness text or an OS errno;
/// this explicit 256-byte dominant error-carrier permit accepts no hostile string.
/// One result and one possible native-error allocation are counted separately.
/// The third value prices a local destination before it moves into an already
/// sized retained OwnerPost; it is charged once at the actual upper frontier.
pub(crate) const fn recovery_peer_liveness_footprint_v1() -> (usize, usize, usize) {
    (256, 2, std::mem::size_of::<ObservedBrokerPeerOriginalV1>())
}

#[cfg(test)]
mod tests {
    use super::super::ObservedBrokerPeerExecutionV1;
    use super::*;
    use aos_sandbox_linux::seqpacket::SeqpacketSocket;

    #[test]
    fn semantic_refusal_keeps_actual_liveness_and_ordinary_classification() {
        let (socket, _remote) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut originals = ObservedBrokerPeerOriginalV1::default();

        let ordinary = ObservedBrokerPeerExecutionV1::from_connection(socket.peer(), [0; 16]);
        let retained = ObservedBrokerPeerExecutionV1::from_connection_with_originals(
            socket.peer(),
            [0; 16],
            Some(&mut originals),
        );

        assert!(matches!(ordinary, Err(BrokerSessionSecurityError::Currentness)));
        assert!(matches!(retained, Err(BrokerSessionSecurityError::Currentness)));
        assert!(matches!(originals.liveness, Some(Ok(true))));
        assert!(originals.failure().is_none());
        assert!(originals.observe_once(socket.peer()).is_err());
        assert!(matches!(originals.liveness, Some(Ok(true))));
    }

    #[test]
    fn original_native_error_survives_a_later_successful_peer() {
        let (socket, _remote) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let wrong_kind = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let native_error = aos_linux_descriptors::pidfd::PidFd::from_owned(wrong_kind).unwrap_err();
        // This is an explicit diagnostic fault-state fixture. It lends neither
        // a fabricated peer nor paid J authority and claims no liveness fault.
        let mut originals = ObservedBrokerPeerOriginalV1 {
            liveness: Some(Err(native_error)),
            reentered: false,
        };
        let original = originals.failure().unwrap()
            .downcast_ref::<aos_linux_descriptors::Error>().unwrap() as *const _;

        assert!(originals.observe_once(socket.peer()).is_err());

        let retained = originals.failure().unwrap()
            .downcast_ref::<aos_linux_descriptors::Error>().unwrap() as *const _;
        assert_eq!(original, retained);
        assert!(originals.reentered);
    }
}
