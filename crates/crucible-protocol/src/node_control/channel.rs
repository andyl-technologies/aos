//! Bounded nonblocking native datagrams on a separately inherited private socket.
//!
//! Socket custody is established by the supervisor's preparation path. This
//! codec does not authenticate a socket discovered by pathname or create local
//! execution authority from decoded portable identities.

#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

use super::{
    NODE_CONTROL_HEADER_BYTES, NODE_CONTROL_MAX_BODY_BYTES, NativeCommandError,
    NativeControlEdition, NativeFrame,
};

/// Reports independent native-channel framing or physical transport failure.
#[derive(Debug, thiserror::Error)]
pub enum NativeChannelError {
    /// The independently versioned frame failed its closed local codec.
    #[error(transparent)]
    Protocol(#[from] NativeCommandError),
    /// The prepared private datagram transport failed.
    #[error("native control transport failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Owns a bounded nonblocking independently prepared native control endpoint.
#[cfg(unix)]
pub struct NativeChannel {
    socket: UnixDatagram,
    edition: NativeControlEdition,
}

#[cfg(unix)]
impl NativeChannel {
    /// Takes custody of an already authenticated inherited native datagram socket.
    ///
    /// # Errors
    /// Returns an I/O error when nonblocking operation cannot be established.
    pub fn from_prepared_socket(socket: UnixDatagram) -> Result<Self, NativeChannelError> {
        Self::from_prepared_socket_for_edition(socket, NativeControlEdition::Original)
    }

    /// Takes supervised socket custody with an immutable explicitly selected edition.
    ///
    /// Selection must match the native launch profile before the first frame.
    /// Receiving another version never changes this endpoint's edition.
    ///
    /// # Errors
    /// Returns an I/O error when nonblocking operation cannot be established.
    pub fn from_prepared_socket_for_edition(
        socket: UnixDatagram,
        edition: NativeControlEdition,
    ) -> Result<Self, NativeChannelError> {
        socket.set_nonblocking(true)?;
        Ok(Self { socket, edition })
    }

    /// Creates a private connected pair for supervised descriptor handover.
    ///
    /// The host must retain one endpoint and transfer the other during native
    /// preparation. No pathname connection or externally supplied identifier
    /// can replace that custody chain.
    ///
    /// # Errors
    /// Returns the original socket creation or nonblocking setup error.
    pub fn supervised_pair() -> Result<(Self, Self), NativeChannelError> {
        Self::supervised_pair_for_edition(NativeControlEdition::Original)
    }

    /// Creates a supervised connected pair pinned to the same explicit edition.
    ///
    /// The transferred native endpoint and immutable launch configuration must
    /// retain this edition; packet contents provide no negotiation authority.
    ///
    /// # Errors
    /// Returns socket creation or nonblocking setup failure.
    pub fn supervised_pair_for_edition(
        edition: NativeControlEdition,
    ) -> Result<(Self, Self), NativeChannelError> {
        let (host, provider) = UnixDatagram::pair()?;
        Ok((
            Self::from_prepared_socket_for_edition(host, edition)?,
            Self::from_prepared_socket_for_edition(provider, edition)?,
        ))
    }

    /// Returns the edition fixed by supervised descriptor preparation.
    pub fn edition(&self) -> NativeControlEdition {
        self.edition
    }

    /// Borrows the prepared endpoint for nonsemantic host readiness polling.
    ///
    /// Descriptor readiness conveys no execution permission or producer bound.
    pub fn prepared_descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.socket.as_fd()
    }

    /// Returns the owned socket for exact inherited descriptor transfer.
    pub fn into_prepared_socket(self) -> UnixDatagram {
        self.socket
    }

    /// Reads at most one bounded native frame without waiting for host readiness.
    ///
    /// # Errors
    /// Rejects oversized, truncated or malformed records and physical I/O errors.
    /// A would-block result returns `None` without changing any command custody.
    pub fn receive(&self) -> Result<Option<NativeFrame>, NativeChannelError> {
        let mut bytes = [0u8; NODE_CONTROL_HEADER_BYTES + NODE_CONTROL_MAX_BODY_BYTES + 1];
        let length = match self.socket.recv(&mut bytes) {
            Ok(length) => length,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if length > NODE_CONTROL_HEADER_BYTES + NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit.into());
        }
        super::decode_frame_for_edition(self.edition, &bytes[..length])
            .map(Some)
            .map_err(Into::into)
    }

    /// Sends one immutable native frame without waiting for physical capacity.
    ///
    /// A false result leaves original caller custody intact for an identical
    /// retry. Successful transport does not acknowledge execution or publication.
    ///
    /// # Errors
    /// Rejects invalid local records, physical errors or an incomplete datagram.
    pub fn send(&self, frame: &NativeFrame) -> Result<bool, NativeChannelError> {
        let bytes = super::encode_frame_for_edition(self.edition, frame)?;
        match self.socket.send(&bytes) {
            Ok(length) if length == bytes.len() => Ok(true),
            Ok(_) => Err(NativeCommandError::Invalid("partial native datagram send").into()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::node_control::{NativeStopFacts, NativeStopKind};
    use crucible_node_contract::{Phase, Position, U64};

    #[test]
    fn private_nonblocking_datagrams_preserve_original_stop_facts() {
        let (host, provider) = NativeChannel::supervised_pair().unwrap();
        assert!(host.receive().unwrap().is_none());
        assert!(provider.receive().unwrap().is_none());
        let frame = NativeFrame::Stopped(NativeStopFacts {
            sequence: U64::new(1),
            command_digest: [7; 32],
            kind: NativeStopKind::HorizonPark,
            reached: Position {
                time_ps: U64::new(110),
                microstep: U64::new(0),
                phase: Phase::BoundaryControl,
            },
            retired_count: U64::new(2),
            pending_classes: u32::MAX,
            next_native_deadline_ps: None,
            next_service_deadline_ps: Some(U64::new(150)),
            pending_service_credit_ps: U64::new(10),
        });
        assert!(provider.send(&frame).unwrap());
        assert_eq!(host.receive().unwrap(), Some(frame));
        assert!(host.receive().unwrap().is_none());
    }

    #[test]
    fn oversized_datagram_fails_before_closed_record_allocation() {
        let (host, provider) = UnixDatagram::pair().unwrap();
        let host = NativeChannel::from_prepared_socket(host).unwrap();
        let malformed = vec![0u8; NODE_CONTROL_HEADER_BYTES + NODE_CONTROL_MAX_BODY_BYTES + 100];
        provider.send(&malformed).unwrap();
        assert!(matches!(
            host.receive(),
            Err(NativeChannelError::Protocol(
                NativeCommandError::ResourceLimit
            ))
        ));
        assert!(host.receive().unwrap().is_none());
    }

    #[test]
    fn prepared_edition_is_immutable_across_foreign_datagrams() {
        for edition in [
            NativeControlEdition::Original,
            NativeControlEdition::OwnedCustody,
            NativeControlEdition::PhaseProjection,
            NativeControlEdition::PreparationSuccessor,
        ] {
            let (host, provider) = NativeChannel::supervised_pair_for_edition(edition).unwrap();
            let other = match edition {
                NativeControlEdition::Original => NativeControlEdition::OwnedCustody,
                NativeControlEdition::OwnedCustody
                | NativeControlEdition::PhaseProjection
                | NativeControlEdition::PreparationSuccessor => NativeControlEdition::Original,
            };
            let frame = NativeFrame::QueryCpuPark([7; 32]);
            let foreign = super::super::encode_frame_for_edition(other, &frame).unwrap();
            provider.socket.send(&foreign).unwrap();

            assert!(
                matches!(host.receive(), Err(NativeChannelError::Protocol(NativeCommandError::UnsupportedVersion(version))) if version == other.version())
            );
            assert_eq!(host.edition(), edition);

            assert!(provider.send(&frame).unwrap());
            assert_eq!(host.receive().unwrap(), Some(frame));
        }
    }
}
