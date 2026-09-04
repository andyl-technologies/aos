//! Negotiated one-request host broker service orchestration.
//!
//! The service verifies the accepted peer's kernel service identity before it
//! reads bytes, admits a two-packet hello/request session, uses `CLOCK_BOOTTIME`
//! for request expiry, and returns a bounded envelope containing either one
//! durable runtime observation or one path-free error.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerErrorCode, BrokerMethod};
use aos_sandbox_core::{FeatureRef, ProtocolId, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE;
use aos_sandbox_protocol::{
    MAXIMUM_HANDSHAKE_BYTES, MAXIMUM_REQUEST_BYTES, PeerPolicy, ProtocolValidationError,
    decode_runtime_request, encode_error_response_envelope, encode_success_response_envelope,
    failed_server_hello, negotiate_client_hello, validate_request_descriptor_roles,
};
use buffa::Message as _;
use rustix::time::{ClockId, clock_gettime};

use crate::KERNEL_CLOCK_PROVENANCE;
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
    /// Unauthorized service peers receive no response. A verified peer first
    /// negotiates the host protocol and then sends one enveloped request.
    /// Method responses are emitted only after the body has supplied a fully
    /// validated, session-bound request identifier.
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
        let Ok(hello) = connection.receive(MAXIMUM_HANDSHAKE_BYTES) else {
            return Ok(ConnectionOutcome::TransportRejected);
        };
        if !hello.descriptors.is_empty() {
            return Ok(send_hello_error(
                &connection,
                &HostError::Protocol(ProtocolValidationError::DescriptorTableMismatch),
            ));
        }
        let advertised_methods = advertised_methods(self.broker.launch_available());
        let advertised_features = [signed_plan_lease_feature()?];
        let session = match negotiate_client_hello(
            &hello.bytes,
            peer.credentials(),
            self.peer_policy,
            ProtocolId::HostBroker,
            &advertised_features,
            &advertised_methods,
        ) {
            Ok(session) => session,
            Err(error) => {
                return Ok(send_hello_error(&connection, &HostError::Protocol(error)));
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
        let Ok(request) = session.decode_request(&packet.bytes, packet.descriptors.len()) else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if validate_request_descriptor_roles(&request, &[]).is_err() {
            return Ok(ConnectionOutcome::RequestRejected);
        }
        let Some(artifacts) = request.authorization() else {
            return Ok(ConnectionOutcome::RequestRejected);
        };

        // The broker applies the live deadline to new and pending effects. This
        // first pass binds the session header and permits an exact authenticated
        // Complete receipt to remain recoverable after its effect deadline.
        let Ok(validated) =
            decode_runtime_request(request.body(), peer.credentials(), self.peer_policy, 0)
        else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if session.validate_header(validated.header()).is_err() {
            return Ok(ConnectionOutcome::RequestRejected);
        }
        let request_id = *validated.header().request_id();
        let response_ceiling = validated.header().maximum_response_bytes();

        match self
            .broker
            .apply_runtime(
                request.body(),
                artifacts,
                session.version(),
                peer.credentials(),
                self.peer_policy,
                trusted_paired_clock_sample,
            )
            .await
        {
            Ok(body) => {
                let Ok(response) = encode_success_response_envelope(
                    &request_id,
                    &request,
                    body,
                    &[],
                    &[],
                    response_ceiling,
                ) else {
                    return Ok(ConnectionOutcome::TransportRejected);
                };
                match connection.send(&response) {
                    Ok(()) => Ok(ConnectionOutcome::Served),
                    Err(_) => Ok(ConnectionOutcome::TransportRejected),
                }
            }
            Err(error) => {
                let Ok(response) =
                    encode_method_error(&request_id, &request, &error, response_ceiling)
                else {
                    return Ok(ConnectionOutcome::TransportRejected);
                };
                match connection.send(&response) {
                    Ok(()) => Ok(ConnectionOutcome::RequestRejected),
                    Err(_) => Ok(ConnectionOutcome::TransportRejected),
                }
            }
        }
    }
}

fn advertised_methods(launch_available: bool) -> Vec<BrokerMethod> {
    // Observation and inventory have protocol tags but no host dispatcher yet.
    // Do not advertise them until their non-authorizing implementations exist.
    launch_available
        .then_some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)
        .into_iter()
        .collect()
}

fn signed_plan_lease_feature() -> Result<FeatureRef> {
    FeatureRef::new(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE, 1, 0)
        .map_err(|error| HostError::State(error.to_string()))
}

fn trusted_paired_clock_sample() -> Result<RawPairedClockSample> {
    let wall = clock_gettime(ClockId::Realtime);
    let boottime = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(boottime.tv_sec)
        .map_err(|_| HostError::State("CLOCK_BOOTTIME returned negative seconds".to_owned()))?;
    let nanoseconds = u64::try_from(boottime.tv_nsec)
        .map_err(|_| HostError::State("CLOCK_BOOTTIME returned negative nanoseconds".to_owned()))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| HostError::State("CLOCK_BOOTTIME overflowed u64 nanoseconds".to_owned()))
        .and_then(|boottime_nanoseconds| {
            let provenance = RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE)
                .map_err(|error| HostError::State(error.to_string()))?;
            let boot_id = KernelBootId::current()
                .map_err(|error| HostError::State(error.to_string()))?
                .into_bytes();
            RawPairedClockSample::new_untrusted(
                provenance,
                boot_id,
                wall.tv_sec,
                boottime_nanoseconds,
            )
            .map_err(|error| HostError::State(error.to_string()))
        })
}

fn encode_method_error(
    request_id: &[u8; 16],
    request: &aos_sandbox_protocol::ValidatedBrokerRequestEnvelope,
    error: &HostError,
    maximum_bytes: u32,
) -> std::result::Result<Vec<u8>, ProtocolValidationError> {
    let (code, safe_message, retryable) = classify_error(error);
    encode_error_response_envelope(
        request_id,
        request,
        code,
        safe_message,
        retryable,
        None,
        &[],
        maximum_bytes,
    )
}

fn send_hello_error(
    connection: &crate::transport::HostConnection,
    error: &HostError,
) -> ConnectionOutcome {
    let (code, safe_message, retryable) = classify_error(error);
    let Ok(hello) = failed_server_hello(code, safe_message, retryable, None) else {
        return ConnectionOutcome::TransportRejected;
    };
    if connection.send(&hello.encode_to_vec()).is_ok() {
        ConnectionOutcome::RequestRejected
    } else {
        ConnectionOutcome::TransportRejected
    }
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
        HostError::Protocol(_) | HostError::InvalidPlan(_) | HostError::Authority(_) => (
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

    use aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope;
    use aos_sandbox_protocol::{decode_request_envelope, decode_response_envelope};

    use super::*;

    #[test]
    fn errors_are_bounded_and_do_not_disclose_internal_detail() {
        let request = decode_request_envelope(
            &BrokerRequestEnvelope {
                method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
                body: vec![1],
                ..Default::default()
            }
            .encode_to_vec(),
            ProtocolId::HostBroker,
            0,
        )
        .unwrap();
        let request_id = [1; 16];
        let encoded = encode_method_error(
            &request_id,
            &request,
            &HostError::Catalog("/private/catalog/path contained secret text".to_owned()),
            4096,
        )
        .unwrap();
        assert!(encoded.len() < 4096);
        let decoded = decode_response_envelope(
            &encoded,
            &request_id,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            request.descriptors(),
            0,
            4096,
            4096,
        )
        .unwrap();
        let error = decoded.error().unwrap();
        assert_eq!(
            error.code(),
            BrokerErrorCode::BROKER_ERROR_CODE_UNKNOWN_HANDLE
        );
        assert_eq!(error.safe_message(), "resource handle is unavailable");
        assert!(error.retryable());
        assert!(!encoded.windows(7).any(|window| window == b"private"));
    }

    #[test]
    fn boottime_is_positive_and_normalized() {
        assert!(
            trusted_paired_clock_sample()
                .unwrap()
                .boottime_nanoseconds()
                > 0
        );
    }

    #[test]
    fn launch_method_is_not_advertised_without_readiness() {
        assert!(advertised_methods(false).is_empty());
        assert_eq!(
            advertised_methods(true),
            [BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME]
        );
    }
}
