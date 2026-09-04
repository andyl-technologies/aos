//! One-request host broker service orchestration.
//!
//! The service verifies the accepted peer's kernel service identity before it
//! reads bytes, admits exactly one packet, uses `CLOCK_BOOTTIME` for request
//! expiry, and returns either one durable runtime observation or one bounded,
//! path-free error observation.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerError, BrokerErrorCode, RuntimeObservation, RuntimeState,
};
use aos_sandbox_protocol::{PeerPolicy, ProtocolValidationError};
use buffa::Message as _;
use rustix::time::{ClockId, clock_gettime};

use crate::broker::HostBroker;
use crate::peer::ControllerPeerVerifier;
use crate::plan::HostCatalog;
use crate::state::HostStateStore;
use crate::transport::ActivatedSeqpacketListener;
use crate::worker::HostWorker;
use crate::{HostError, Result};

/// Classifies the completed handling of one accepted connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionOutcome {
    /// One runtime request completed successfully.
    Served,
    /// A kernel-credential or service-cgroup check rejected the peer silently.
    PeerRejected,
    /// A verified peer received a bounded protocol or backend error.
    RequestRejected,
    /// An accepted connection failed its bounded packet transport.
    TransportRejected,
}

/// Owns fixed peer policy and the serialized durable host broker.
pub struct HostService<C, S, W> {
    broker: HostBroker<C, S, W>,
    verifier: ControllerPeerVerifier,
    peer_policy: PeerPolicy,
}

impl<C, S, W> HostService<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker,
{
    /// Constructs the root broker service for the node controller account.
    #[must_use]
    pub const fn new(
        broker: HostBroker<C, S, W>,
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

    /// Accepts, verifies, serves, and closes one sequence-packet connection.
    ///
    /// Unauthorized service peers receive no response. A verified peer gets a
    /// single safe error observation for malformed, stale, or failed requests.
    ///
    /// # Errors
    ///
    /// Returns an error only when accepting the next connection or reading the
    /// trusted boot clock fails. Per-connection transport failures are closed
    /// and reported as [`ConnectionOutcome::TransportRejected`]. Broker
    /// failures become a bounded protocol error and
    /// [`ConnectionOutcome::RequestRejected`].
    pub async fn serve_once(
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
            .apply_runtime(&request, peer.credentials(), self.peer_policy, now)
            .await
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
        .map_err(|_| HostError::State("CLOCK_BOOTTIME returned negative seconds".to_owned()))?;
    let nanoseconds = u64::try_from(time.tv_nsec)
        .map_err(|_| HostError::State("CLOCK_BOOTTIME returned negative nanoseconds".to_owned()))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| HostError::State("CLOCK_BOOTTIME overflowed u64 nanoseconds".to_owned()))
}

fn encode_error(error: &HostError) -> Vec<u8> {
    let (code, safe_message, retryable) = classify_error(error);
    RuntimeObservation {
        state: RuntimeState::RUNTIME_STATE_FAILED.into(),
        error: Some(BrokerError {
            code: code.into(),
            safe_message: safe_message.to_owned(),
            retryable,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn classify_error(error: &HostError) -> (BrokerErrorCode, &'static str, bool) {
    match error {
        HostError::Protocol(ProtocolValidationError::PeerCredentialMismatch) => (
            BrokerErrorCode::BROKER_ERROR_CODE_UNAUTHENTICATED_PEER,
            "peer authentication failed",
            false,
        ),
        HostError::Protocol(ProtocolValidationError::AudienceMismatch) => (
            BrokerErrorCode::BROKER_ERROR_CODE_WRONG_AUDIENCE,
            "request audience is not served here",
            false,
        ),
        HostError::Protocol(ProtocolValidationError::DeadlineExpired) => (
            BrokerErrorCode::BROKER_ERROR_CODE_DEADLINE_EXPIRED,
            "request deadline expired",
            true,
        ),
        HostError::Protocol(_) | HostError::InvalidPlan(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "request is invalid",
            false,
        ),
        HostError::Catalog(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_UNKNOWN_HANDLE,
            "resource handle is unavailable",
            true,
        ),
        HostError::Fence(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_CONFLICT,
            "request conflicts with the durable assignment fence",
            false,
        ),
        HostError::State(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
            "durable broker state is unavailable",
            false,
        ),
        HostError::Worker(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
            "runtime backend operation failed",
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn errors_are_bounded_and_do_not_disclose_internal_detail() {
        let encoded = encode_error(&HostError::Catalog(
            "/private/catalog/path contained secret text".to_owned(),
        ));
        assert!(encoded.len() < 4096);
        let decoded = RuntimeObservation::decode_from_slice(&encoded).unwrap();
        let error = decoded.error.as_option().unwrap();
        assert_eq!(
            error.code,
            BrokerErrorCode::BROKER_ERROR_CODE_UNKNOWN_HANDLE
        );
        assert!(!error.safe_message.contains("private"));
    }

    #[test]
    fn boottime_is_positive_and_normalized() {
        assert!(boottime_nanoseconds().unwrap() > 0);
    }
}
