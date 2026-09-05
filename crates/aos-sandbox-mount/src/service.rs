//! Negotiated one-request mount-broker service orchestration.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerErrorCode, BrokerMethod};
use aos_sandbox_core::{FeatureRef, ProtocolId, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_protocol::mount_catalog::decode_mount_catalog_preparation;
use aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE;
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, MAXIMUM_HANDSHAKE_BYTES, PeerPolicy, ProtocolValidationError,
    ValidatedBrokerRequestEnvelope, decode_mount_inventory_request, decode_mount_request,
    encode_error_response_envelope, encode_success_response_envelope, failed_server_hello,
    negotiate_client_hello, validate_request_descriptor_roles,
};
use buffa::Message as _;
use rustix::time::{ClockId, clock_gettime};

use crate::broker::MountBroker;
use crate::host_scope::HostMountScopeClient;
use crate::peer::ControllerPeerVerifier;
use crate::transport::ActivatedSeqpacketListener;
use crate::worker::MountWorker;
use crate::{KERNEL_CLOCK_PROVENANCE, MountError, Result};

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
    host_cgroup_root: CgroupV2Root,
    peer_policy: PeerPolicy,
}

impl<W: MountWorker> MountService<W> {
    /// Constructs the root broker service for one controller identity.
    #[must_use]
    pub const fn new(
        broker: MountBroker<W>,
        verifier: ControllerPeerVerifier,
        host_cgroup_root: CgroupV2Root,
        controller_identity: (u32, u32),
    ) -> Self {
        Self {
            broker,
            verifier,
            host_cgroup_root,
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
    /// Returns an error only when accepting the next connection or reading the
    /// protected paired clock fails. Per-request failures become bounded
    /// responses.
    #[allow(clippy::too_many_lines)]
    pub fn serve_once(
        &mut self,
        listener: &ActivatedSeqpacketListener,
    ) -> Result<ConnectionOutcome> {
        let connection = match listener.accept() {
            Ok(connection) => connection,
            // A queued connector may exit before its pidfd can be inspected.
            // Reject that child without turning peer churn into daemon exit.
            Err(MountError::Protocol(ProtocolValidationError::PeerCredentialMismatch)) => {
                return Ok(ConnectionOutcome::PeerRejected);
            }
            Err(error) => return Err(error),
        };
        let Ok(peer) = self.verifier.verify(connection.peer_identity()) else {
            return Ok(ConnectionOutcome::PeerRejected);
        };
        let hello = match connection.receive(MAXIMUM_HANDSHAKE_BYTES) {
            Ok(packet) if packet.descriptors.is_empty() => packet.bytes,
            Ok(_) | Err(_) => return Ok(ConnectionOutcome::TransportRejected),
        };
        let advertised_features = [signed_plan_lease_feature()?];
        let session = match negotiate_client_hello(
            &hello,
            peer.credentials(),
            self.peer_policy,
            ProtocolId::MountBroker,
            &advertised_features,
            &[
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
                BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG,
            ],
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
        let Ok(packet) = connection.receive(session.maximum_request_bytes()) else {
            return Ok(ConnectionOutcome::TransportRejected);
        };
        let Ok(envelope) = session.decode_request(&packet.bytes, packet.descriptors.len()) else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if validate_request_descriptor_roles(&envelope, &[]).is_err() {
            return Ok(ConnectionOutcome::RequestRejected);
        }
        let now = trusted_paired_clock_sample()?.boottime_nanoseconds();
        let dispatch = match envelope.method() {
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
                let Some(artifacts) = envelope.authorization() else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                let Ok(validated) = decode_mount_request(
                    envelope.body(),
                    peer.credentials(),
                    self.peer_policy,
                    now,
                ) else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                if session.validate_header(validated.header()).is_err() {
                    return Ok(ConnectionOutcome::RequestRejected);
                }
                let ceiling = validated.header().maximum_response_bytes();
                (
                    *validated.header().request_id(),
                    ceiling,
                    self.broker.apply_mount(
                        envelope.body(),
                        artifacts,
                        session.version(),
                        peer.credentials(),
                        self.peer_policy,
                        trusted_paired_clock_sample,
                    ),
                )
            }
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES => {
                let Ok(header) = decode_mount_inventory_request(
                    envelope.body(),
                    peer.credentials(),
                    self.peer_policy,
                    now,
                ) else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                if session.validate_header(&header).is_err() {
                    return Ok(ConnectionOutcome::RequestRejected);
                }
                let ceiling = header.maximum_response_bytes();
                (
                    *header.request_id(),
                    ceiling,
                    Ok(self.broker.inventory_resources()),
                )
            }
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG => {
                let Ok(preparation) = decode_mount_catalog_preparation(
                    envelope.body(),
                    peer.credentials(),
                    self.peer_policy,
                    now,
                ) else {
                    return Ok(ConnectionOutcome::RequestRejected);
                };
                if session.validate_header(preparation.header()).is_err() {
                    return Ok(ConnectionOutcome::RequestRejected);
                }
                let artifacts = preparation.host_authorization();
                let scope = HostMountScopeClient::connect(&self.host_cgroup_root)
                    .and_then(|client| {
                        client.observe(
                            preparation.host_request_body(),
                            AuthorizationArtifactBytes {
                                broker_plan: artifacts.broker_plan(),
                                broker_plan_signature: artifacts.broker_plan_signature(),
                                ownership_lease: artifacts.ownership_lease(),
                                ownership_lease_signature: artifacts.ownership_lease_signature(),
                            },
                        )
                    })
                    .map_err(|error| {
                        MountError::Worker(format!("Host scope acquisition failed: {error}"))
                    });
                let result =
                    scope.and_then(|scope| self.broker.prepare_catalog(&preparation, scope));
                (
                    *preparation.header().request_id(),
                    preparation.header().maximum_response_bytes(),
                    result,
                )
            }
            _ => return Ok(ConnectionOutcome::RequestRejected),
        };
        let (request_id, response_ceiling, result) = dispatch;
        let response = encode_dispatch_response(&request_id, &envelope, result, response_ceiling);
        match response {
            (Ok(bytes), outcome) if connection.send(&bytes).is_ok() => Ok(outcome),
            (Ok(_), _) => Ok(ConnectionOutcome::TransportRejected),
            (Err(_), _) => Ok(ConnectionOutcome::RequestRejected),
        }
    }
}

fn encode_dispatch_response(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    result: Result<Vec<u8>>,
    maximum_bytes: u32,
) -> (
    std::result::Result<Vec<u8>, ProtocolValidationError>,
    ConnectionOutcome,
) {
    match result {
        Ok(body) => match encode_success_response_envelope(
            request_id,
            request,
            body,
            &[],
            &[],
            maximum_bytes,
        ) {
            Ok(bytes) => (Ok(bytes), ConnectionOutcome::Served),
            Err(_) => (
                encode_error_response_envelope(
                    request_id,
                    request,
                    BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
                    "response exceeds the negotiated packet ceiling",
                    true,
                    None,
                    &[],
                    maximum_bytes,
                ),
                ConnectionOutcome::RequestRejected,
            ),
        },
        Err(error) => {
            let (code, message, retryable) = classify_error(&error);
            (
                encode_error_response_envelope(
                    request_id,
                    request,
                    code,
                    message,
                    retryable,
                    None,
                    &[],
                    maximum_bytes,
                ),
                ConnectionOutcome::RequestRejected,
            )
        }
    }
}

fn signed_plan_lease_feature() -> Result<FeatureRef> {
    FeatureRef::new(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE, 1, 0)
        .map_err(|error| MountError::State(error.to_string()))
}

/// Reads wall time and BOOTTIME from the kernel in one protected adapter call.
///
/// The provenance identity is a local source label, not a trust credential.
/// Callers invoke this function again after durable admission and immediately
/// before an effect, preventing an earlier transport timestamp from becoming
/// executable authority.
fn trusted_paired_clock_sample() -> Result<RawPairedClockSample> {
    let wall = clock_gettime(ClockId::Realtime);
    let boottime = clock_gettime(ClockId::Boottime);
    let wall_seconds = wall.tv_sec;
    let seconds = u64::try_from(boottime.tv_sec)
        .map_err(|_| MountError::State("CLOCK_BOOTTIME returned negative seconds".to_owned()))?;
    let nanoseconds = u64::try_from(boottime.tv_nsec).map_err(|_| {
        MountError::State("CLOCK_BOOTTIME returned negative nanoseconds".to_owned())
    })?;
    let boottime_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| MountError::State("CLOCK_BOOTTIME overflowed u64".to_owned()))?;
    let provenance = RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE)
        .map_err(|error| MountError::State(error.to_string()))?;
    let boot_id = KernelBootId::current()
        .map_err(|error| MountError::State(error.to_string()))?
        .into_bytes();
    RawPairedClockSample::new_untrusted(provenance, boot_id, wall_seconds, boottime_nanoseconds)
        .map_err(|error| MountError::State(error.to_string()))
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
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{BrokerRequestEnvelope, BrokerResponseEnvelope};
    use aos_sandbox_protocol::decode_request_envelope;

    use super::*;

    #[test]
    fn private_error_details_do_not_cross_protocol() {
        let (_, message, _) = classify_error(&MountError::Worker(
            "/secret/catalog/path changed".to_owned(),
        ));
        assert_eq!(message, "mount backend operation failed");
        assert!(!message.contains("/secret"));
    }

    #[test]
    fn body_fits_but_envelope_overhead_becomes_a_bounded_resource_error() {
        let request = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES.into(),
            body: vec![1],
            ..Default::default()
        };
        let request =
            decode_request_envelope(&request.encode_to_vec(), ProtocolId::MountBroker, 0).unwrap();
        let ceiling = aos_sandbox_protocol::MINIMUM_RESPONSE_BYTES;
        let (encoded, outcome) =
            encode_dispatch_response(&[7; 16], &request, Ok(vec![8; ceiling as usize]), ceiling);
        let encoded = encoded.unwrap();
        assert_eq!(outcome, ConnectionOutcome::RequestRejected);
        assert!(encoded.len() <= ceiling as usize);
        let response = BrokerResponseEnvelope::decode_from_slice(&encoded).unwrap();
        assert!(response.body.is_empty());
        assert_eq!(
            response.error.as_option().unwrap().code.as_known(),
            Some(BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED)
        );
    }
}
