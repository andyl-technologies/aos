//! One-request synchronous mount-broker service orchestration.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerError, BrokerErrorCode, MountResult, MountState,
};
use aos_sandbox_protocol::{PeerPolicy, ProtocolValidationError};
use buffa::Message as _;
use rustix::time::{ClockId, clock_gettime};

use crate::broker::MountBroker;
use crate::peer::ControllerPeerVerifier;
use crate::transport::ActivatedSeqpacketListener;
use crate::worker::MountWorker;
use crate::{MountError, Result};

/// Classifies handling of one accepted connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionOutcome {
    /// One mount request completed successfully.
    Served,
    /// Kernel service identity rejected the peer without a response.
    PeerRejected,
    /// A verified peer received a bounded safe error.
    RequestRejected,
    /// Packet receive or send failed and the connection was closed.
    TransportRejected,
}

/// Owns fixed peer policy and the serialized durable mount broker.
pub struct MountService<W> {
    broker: MountBroker<W>,
    verifier: ControllerPeerVerifier,
    peer_policy: PeerPolicy,
}

impl<W: MountWorker> MountService<W> {
    /// Constructs the root broker service for one controller identity.
    #[must_use]
    pub const fn new(
        broker: MountBroker<W>,
        verifier: ControllerPeerVerifier,
        controller_identity: (u32, u32),
    ) -> Self {
        Self {
            broker,
            verifier,
            peer_policy: PeerPolicy {
                uid: controller_identity.0,
                gid: Some(controller_identity.1),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
        }
    }

    /// Accepts, authenticates, serves, replies, and closes one connection.
    ///
    /// # Errors
    ///
    /// Returns an error only when accepting the next connection or reading
    /// `CLOCK_BOOTTIME` fails. Per-request failures become bounded responses.
    pub fn serve_once(
        &mut self,
        listener: &ActivatedSeqpacketListener,
    ) -> Result<ConnectionOutcome> {
        let connection = listener.accept()?;
        let Ok(peer) = self.verifier.verify(connection.peer()) else {
            return Ok(ConnectionOutcome::PeerRejected);
        };
        let request = match connection.receive() {
            Ok(request) => request,
            Err(error) => {
                let _ = connection.send(&encode_error(&error));
                return Ok(ConnectionOutcome::TransportRejected);
            }
        };
        let now = boottime_nanoseconds()?;
        match self
            .broker
            .apply_mount(&request, peer.credentials(), self.peer_policy, now)
        {
            Ok(response) => match connection.send(&response) {
                Ok(()) => Ok(ConnectionOutcome::Served),
                Err(_) => Ok(ConnectionOutcome::TransportRejected),
            },
            Err(error) => match connection.send(&encode_error(&error)) {
                Ok(()) => Ok(ConnectionOutcome::RequestRejected),
                Err(_) => Ok(ConnectionOutcome::TransportRejected),
            },
        }
    }
}

fn boottime_nanoseconds() -> Result<u64> {
    let time = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(time.tv_sec)
        .map_err(|_| MountError::State("CLOCK_BOOTTIME returned negative seconds".to_owned()))?;
    let nanoseconds = u64::try_from(time.tv_nsec).map_err(|_| {
        MountError::State("CLOCK_BOOTTIME returned negative nanoseconds".to_owned())
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| MountError::State("CLOCK_BOOTTIME overflowed u64".to_owned()))
}

fn encode_error(error: &MountError) -> Vec<u8> {
    let (code, message, retryable) = classify_error(error);
    MountResult {
        state: MountState::MOUNT_STATE_FAILED.into(),
        error: Some(BrokerError {
            code: code.into(),
            safe_message: message.to_owned(),
            retryable,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn classify_error(error: &MountError) -> (BrokerErrorCode, &'static str, bool) {
    match error {
        MountError::Protocol(ProtocolValidationError::PeerCredentialMismatch) => (
            BrokerErrorCode::BROKER_ERROR_CODE_UNAUTHENTICATED_PEER,
            "peer authentication failed",
            false,
        ),
        MountError::Protocol(ProtocolValidationError::AudienceMismatch) => (
            BrokerErrorCode::BROKER_ERROR_CODE_WRONG_AUDIENCE,
            "request audience is not served here",
            false,
        ),
        MountError::Protocol(ProtocolValidationError::DeadlineExpired) => (
            BrokerErrorCode::BROKER_ERROR_CODE_DEADLINE_EXPIRED,
            "request deadline expired",
            true,
        ),
        MountError::Protocol(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "request is invalid",
            false,
        ),
        MountError::Fence(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_CONFLICT,
            "request conflicts with the durable assignment fence",
            false,
        ),
        MountError::State(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
            "durable mount state is unavailable",
            false,
        ),
        MountError::Worker(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
            "mount backend operation failed",
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_error_details_do_not_cross_protocol() {
        let bytes = encode_error(&MountError::Worker(
            "/secret/catalog/path changed".to_owned(),
        ));
        let response = MountResult::decode_from_slice(&bytes)
            .unwrap_or_else(|error| panic!("decode error response: {error}"));
        let error = response
            .error
            .as_option()
            .unwrap_or_else(|| panic!("missing error"));
        assert_eq!(error.safe_message, "mount backend operation failed");
        assert!(!bytes.windows(7).any(|window| window == b"/secret"));
    }
}
