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
    MAXIMUM_HANDSHAKE_BYTES, PeerPolicy, ProtocolValidationError, decode_runtime_request,
    encode_error_response_envelope, encode_success_response_envelope, failed_server_hello,
    negotiate_client_hello, validate_request_descriptor_roles,
};
use buffa::Message as _;
use rustix::time::{ClockId, clock_gettime};

use crate::KERNEL_CLOCK_PROVENANCE;
use crate::broker::{HostBroker, RuntimeEffectQueryContext};
use crate::observation::{
    decode_inventory_runtime_request, decode_observe_runtime_request,
    decode_query_runtime_effect_request,
};
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
        let connection = match listener.accept() {
            Ok(connection) => connection,
            // A queued connector may exit before its pidfd can be inspected.
            // Reject that child without turning peer churn into daemon exit.
            Err(HostError::Protocol(ProtocolValidationError::PeerCredentialMismatch)) => {
                return Ok(ConnectionOutcome::PeerRejected);
            }
            Err(error) => return Err(error),
        };
        let Ok(peer) = self.verifier.verify(connection.peer_identity()) else {
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

        let Ok(packet) = connection.receive(session.maximum_request_bytes()) else {
            return Ok(ConnectionOutcome::TransportRejected);
        };
        let Ok(request) = session.decode_request(&packet.bytes, packet.descriptors.len()) else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if validate_request_descriptor_roles(&request, &[]).is_err() {
            return Ok(ConnectionOutcome::RequestRejected);
        }
        if !valid_service_authorization_profile(request.method(), request.authorization().is_some())
        {
            return Ok(ConnectionOutcome::RequestRejected);
        }
        let dispatch = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
                let Some(artifacts) = request.authorization() else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                // The broker applies the live deadline to new and pending
                // effects. This pass permits exact completed-receipt recovery.
                let Ok(validated) =
                    decode_runtime_request(request.body(), peer.credentials(), self.peer_policy, 0)
                else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                if session.validate_header(validated.header()).is_err() {
                    return Ok(ConnectionOutcome::RequestRejected);
                }
                let request_id = *validated.header().request_id();
                let ceiling = validated.header().maximum_response_bytes();
                let result = self
                    .broker
                    .apply_runtime(
                        request.body(),
                        artifacts,
                        session.version(),
                        peer.credentials(),
                        self.peer_policy,
                        trusted_paired_clock_sample,
                    )
                    .await;
                (request_id, ceiling, result)
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME => {
                let now = trusted_paired_clock_sample()?.boottime_nanoseconds();
                let Ok(validated) = decode_observe_runtime_request(
                    request.body(),
                    peer.credentials(),
                    self.peer_policy,
                    now,
                ) else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                if session.validate_header(&validated.header).is_err() {
                    return Ok(ConnectionOutcome::RequestRejected);
                }
                let request_id = *validated.header.request_id();
                let ceiling = validated.header.maximum_response_bytes();
                let result = self
                    .broker
                    .observe_runtime(validated.identity, validated.runtime_handle, ceiling)
                    .await;
                (request_id, ceiling, result)
            }
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => {
                let now = trusted_paired_clock_sample()?.boottime_nanoseconds();
                let Ok(header) = decode_inventory_runtime_request(
                    request.body(),
                    peer.credentials(),
                    self.peer_policy,
                    now,
                ) else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                if session.validate_header(&header).is_err() {
                    return Ok(ConnectionOutcome::RequestRejected);
                }
                let request_id = *header.request_id();
                let ceiling = header.maximum_response_bytes();
                let result = self.broker.inventory_runtime(ceiling).await;
                (request_id, ceiling, result)
            }
            BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => {
                let now = trusted_paired_clock_sample()?;
                let Ok(validated) = decode_query_runtime_effect_request(
                    request.body(),
                    peer.credentials(),
                    self.peer_policy,
                    now.boottime_nanoseconds(),
                ) else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                if session.validate_header(&validated.header).is_err() {
                    return Ok(ConnectionOutcome::RequestRejected);
                }
                let Some(artifacts) = request.authorization() else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                let request_id = *validated.header.request_id();
                let ceiling = validated.header.maximum_response_bytes();
                let result = self.broker.query_runtime_effect(
                    artifacts,
                    RuntimeEffectQueryContext {
                        original_request_bytes: &validated.original_apply_request,
                        request_id,
                        peer: peer.credentials(),
                        policy: self.peer_policy,
                        current_clock: now,
                        maximum_response_bytes: ceiling,
                    },
                );
                (request_id, ceiling, result)
            }
            _ => return Ok(ConnectionOutcome::RequestRejected),
        };
        let (request_id, response_ceiling, result) = dispatch;
        match result {
            Ok(body) => {
                let Ok((response, outcome)) =
                    encode_method_success(&request_id, &request, body, response_ceiling)
                else {
                    return Ok(ConnectionOutcome::TransportRejected);
                };
                match connection.send(&response) {
                    Ok(()) => Ok(outcome),
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
    let mut methods = Vec::with_capacity(4);
    if launch_available {
        methods.push(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME);
    }
    methods.push(BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME);
    methods.push(BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME);
    methods.push(BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT);
    methods
}

fn valid_service_authorization_profile(method: BrokerMethod, has_authorization: bool) -> bool {
    matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
    ) == has_authorization
}

fn encode_method_success(
    request_id: &[u8; 16],
    request: &aos_sandbox_protocol::ValidatedBrokerRequestEnvelope,
    body: Vec<u8>,
    maximum_bytes: u32,
) -> std::result::Result<(Vec<u8>, ConnectionOutcome), ProtocolValidationError> {
    match encode_success_response_envelope(request_id, request, body, &[], &[], maximum_bytes) {
        Ok(response) => Ok((response, ConnectionOutcome::Served)),
        Err(
            ProtocolValidationError::ResponseTooLarge
            | ProtocolValidationError::InvalidResponseBound,
        ) => encode_method_error(
            request_id,
            request,
            &HostError::ResourceExhausted,
            maximum_bytes,
        )
        .map(|response| (response, ConnectionOutcome::RequestRejected)),
        Err(error) => Err(error),
    }
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
        HostError::Catalog(_) | HostError::UnknownHandle => (
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
        HostError::ResourceExhausted => (
            BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
            "complete runtime inventory exceeds response bounds",
            true,
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

    use aos_proto::aos::sandbox::local::v1::{BrokerClientHello, BrokerRequestEnvelope};
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
        assert_eq!(
            advertised_methods(false),
            [
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
                BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
                BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
            ]
        );
        assert_eq!(
            advertised_methods(true),
            [
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
                BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
                BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
            ]
        );
    }

    #[test]
    fn legacy_session_negotiates_both_non_authorizing_host_methods() {
        let peer = aos_sandbox_protocol::PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 0,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            maximum_response_bytes: 4_096,
            required_methods: vec![
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME.into(),
                BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME.into(),
            ],
            ..Default::default()
        };
        let session = negotiate_client_hello(
            &hello.encode_to_vec(),
            peer,
            policy,
            ProtocolId::HostBroker,
            &[signed_plan_lease_feature().unwrap()],
            &advertised_methods(false),
        )
        .unwrap();
        assert_eq!(
            session.version(),
            aos_sandbox_core::ProtocolVersion::new(1, 0)
        );
        for method in [
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        ] {
            let request = BrokerRequestEnvelope {
                method: method.into(),
                body: vec![1],
                ..Default::default()
            };
            assert!(session.decode_request(&request.encode_to_vec(), 0).is_ok());
        }
    }

    #[test]
    fn service_rejects_carriers_on_both_observation_methods() {
        for method in [
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        ] {
            assert!(valid_service_authorization_profile(method, false));
            assert!(!valid_service_authorization_profile(method, true));
        }
        assert!(valid_service_authorization_profile(
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            true,
        ));
        assert!(!valid_service_authorization_profile(
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            false,
        ));
        assert!(valid_service_authorization_profile(
            BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
            true,
        ));
        assert!(!valid_service_authorization_profile(
            BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
            false,
        ));
    }

    #[test]
    fn envelope_overhead_becomes_a_typed_bounded_error() {
        let request = decode_request_envelope(
            &BrokerRequestEnvelope {
                method: BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME.into(),
                body: vec![1],
                ..Default::default()
            }
            .encode_to_vec(),
            ProtocolId::HostBroker,
            0,
        )
        .unwrap();
        let request_id = [9; 16];

        let (encoded, outcome) =
            encode_method_success(&request_id, &request, vec![1; 4_090], 4_096).unwrap();

        assert_eq!(outcome, ConnectionOutcome::RequestRejected);
        assert!(encoded.len() <= 4_096);
        let decoded = decode_response_envelope(
            &encoded,
            &request_id,
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            request.descriptors(),
            0,
            4_096,
            4_096,
        )
        .unwrap();
        assert_eq!(
            decoded.error().unwrap().code(),
            BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED
        );
        assert!(decoded.body().is_empty());
    }
}
