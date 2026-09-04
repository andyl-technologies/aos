//! Negotiated one-request mount-broker service orchestration.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerErrorCode, BrokerMethod};
use aos_sandbox_core::ProtocolId;
use aos_sandbox_protocol::{
    MAXIMUM_HANDSHAKE_BYTES, MAXIMUM_REQUEST_BYTES, PeerPolicy, ProtocolValidationError,
    decode_mount_request, encode_error_response_envelope, encode_success_response_envelope,
    failed_server_hello, negotiate_client_hello, validate_request_descriptor_roles,
};
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
    #[allow(clippy::too_many_lines)]
    pub fn serve_once(
        &mut self,
        listener: &ActivatedSeqpacketListener,
    ) -> Result<ConnectionOutcome> {
        let connection = listener.accept()?;
        let Ok(peer) = self.verifier.verify(connection.peer()) else {
            return Ok(ConnectionOutcome::PeerRejected);
        };
        let hello = match connection.receive(MAXIMUM_HANDSHAKE_BYTES) {
            Ok(packet) if packet.descriptors.is_empty() => packet.bytes,
            Ok(_) | Err(_) => return Ok(ConnectionOutcome::TransportRejected),
        };
        let session = match negotiate_client_hello(
            &hello,
            peer.credentials(),
            self.peer_policy,
            ProtocolId::MountBroker,
            &[],
            &[BrokerMethod::BROKER_METHOD_MOUNT_APPLY],
        ) {
            Ok(session) => session,
            Err(error) => {
                return Ok(send_hello_error(&connection, &error));
            }
        };
        if connection
            .send(&session.server_hello().encode_to_vec())
            .is_err()
        {
            return Ok(ConnectionOutcome::TransportRejected);
        }
        let Ok(packet) = connection.receive(MAXIMUM_REQUEST_BYTES) else {
            return Ok(ConnectionOutcome::TransportRejected);
        };
        let Ok(envelope) = session.decode_request(&packet.bytes, packet.descriptors.len()) else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if envelope.method() != BrokerMethod::BROKER_METHOD_MOUNT_APPLY
            || validate_request_descriptor_roles(&envelope, &[]).is_err()
        {
            return Ok(ConnectionOutcome::RequestRejected);
        }
        let now = boottime_nanoseconds()?;
        let Ok(validated) =
            decode_mount_request(envelope.body(), peer.credentials(), self.peer_policy, now)
        else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if session.validate_header(validated.header()).is_err() {
            return Ok(ConnectionOutcome::RequestRejected);
        }
        let request_id = *validated.header().request_id();
        let response_ceiling = validated.header().maximum_response_bytes();
        let response = match self.broker.apply_mount(
            envelope.body(),
            peer.credentials(),
            self.peer_policy,
            now,
        ) {
            Ok(body) => (
                encode_success_response_envelope(
                    &request_id,
                    &envelope,
                    body,
                    &[],
                    &[],
                    response_ceiling,
                ),
                ConnectionOutcome::Served,
            ),
            Err(error) => {
                let (code, message, retryable) = classify_error(&error);
                (
                    encode_error_response_envelope(
                        &request_id,
                        &envelope,
                        code,
                        message,
                        retryable,
                        None,
                        &[],
                        response_ceiling,
                    ),
                    ConnectionOutcome::RequestRejected,
                )
            }
        };
        match response {
            (Ok(bytes), outcome) if connection.send(&bytes).is_ok() => Ok(outcome),
            (Ok(_), _) => Ok(ConnectionOutcome::TransportRejected),
            (Err(_), _) => Ok(ConnectionOutcome::RequestRejected),
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

fn classify_protocol_error(
    error: &ProtocolValidationError,
) -> (BrokerErrorCode, &'static str, bool) {
    match error {
        ProtocolValidationError::PeerCredentialMismatch => (
            BrokerErrorCode::BROKER_ERROR_CODE_UNAUTHENTICATED_PEER,
            "peer authentication failed",
            false,
        ),
        ProtocolValidationError::AudienceMismatch => (
            BrokerErrorCode::BROKER_ERROR_CODE_WRONG_AUDIENCE,
            "request audience is not served here",
            false,
        ),
        ProtocolValidationError::RequiredFeatureUnavailable(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "required broker semantics are unavailable",
            false,
        ),
        _ => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "broker negotiation failed",
            false,
        ),
    }
}

fn send_hello_error(
    connection: &crate::transport::MountConnection,
    error: &ProtocolValidationError,
) -> ConnectionOutcome {
    let (code, message, retryable) = classify_protocol_error(error);
    let Ok(response) = failed_server_hello(code, message, retryable, None) else {
        return ConnectionOutcome::TransportRejected;
    };
    if connection.send(&response.encode_to_vec()).is_ok() {
        ConnectionOutcome::RequestRejected
    } else {
        ConnectionOutcome::TransportRejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_error_details_do_not_cross_protocol() {
        let (_, message, _) = classify_error(&MountError::Worker(
            "/secret/catalog/path changed".to_owned(),
        ));
        assert_eq!(message, "mount backend operation failed");
        assert!(!message.contains("/secret"));
    }
}
