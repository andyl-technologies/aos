//! Authenticated one-request Storage repair and inventory service.
//!
//! The service verifies the connection establisher before reading bytes, then
//! requires both hello and request records to name that same live controller
//! leader in the exact retained service cgroup. Its carrier forbids
//! `SCM_RIGHTS`; the only public mutation input is the canonical Storage 1.4
//! repair body plus the standard signed authorization artifacts.
//!
//! Generic Apply, catalog preparation, legacy inventory, physical storage
//! names, internal observer/worker envelopes, and caller-selected proofs are
//! outside this boundary.

use aos_proto::aos::sandbox::local::v1::{BrokerErrorCode, BrokerMethod, StorageResult};
use aos_sandbox_core::{FeatureRef, ProtocolId, ProtocolVersion, RawClockProvenance};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::session::{
    SIGNED_PLAN_LEASE_FEATURE_NAMESPACE, ValidatedUntrustedAuthorizationArtifacts,
};
use aos_sandbox_protocol::{
    MAXIMUM_HANDSHAKE_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedBrokerRequestEnvelope, decode_storage_resource_inventory_request,
    encode_error_response_envelope, encode_success_response_envelope, failed_server_hello,
    negotiate_client_hello, validate_request_descriptor_roles,
};
use buffa::Message as _;

use crate::StorageAdmissionError;
use crate::broker::{StorageBrokerError, advertised_storage_methods};
use crate::peer::ControllerPeerVerifier;
use crate::runtime::{
    StorageBrokerRuntime, StorageRuntimeError, WorkspacePinRepairExecutionOutcomeV1,
};
use crate::transport::{EXCHANGE_NANOSECONDS, accept_connection, boottime, receive, send};

const KERNEL_CLOCK_PROVENANCE: [u8; 16] = *b"aos-kernel-clock";

/// Classifies handling of one accepted Storage connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageConnectionOutcome {
    /// One repair or authoritative inventory request completed successfully.
    Served,
    /// The connection or a record did not name the configured controller.
    PeerRejected,
    /// A verified peer sent an invalid request or received a bounded safe error.
    RequestRejected,
    /// The accepted child failed its bounded packet exchange.
    TransportRejected,
}

/// Reports fatal Storage service construction, clock, or transport failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageServiceError {
    /// The record-subject carrier failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// A retained cgroup, pidfd, or protected filesystem operation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// A protocol value produced internally violated the closed schema.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// Protected Storage runtime construction or reconciliation failed.
    #[error(transparent)]
    Runtime(#[from] StorageRuntimeError),
    /// A local poll operation failed.
    #[error("Storage service kernel I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// `CLOCK_BOOTTIME` or its paired wall observation was invalid.
    #[error("Storage service kernel clock observation is invalid")]
    Clock,
    /// Process startup did not provide the exact fixed activation contract.
    #[error("Storage service activation is invalid: {0}")]
    Activation(String),
}

/// Defines the narrow runtime surface reachable from public Storage RPC.
pub trait StorageRpcRuntime {
    /// Reports whether fresh repair admission is available.
    fn is_repair_ready(&self) -> bool;

    /// Reports whether authenticated non-legacy inventory is available.
    fn is_inventory_ready(&self) -> bool;

    /// Repairs an existing workspace root pin from public request authority.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for failed authority, observation,
    /// durable admission, dispatch, or exact postcondition verification.
    #[allow(clippy::too_many_arguments)]
    fn repair_workspace_pin<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<WorkspacePinRepairExecutionOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, StorageAdmissionError>;

    /// Encodes the complete current physically validated workspace inventory.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when non-legacy inventory is unavailable
    /// or a protected catalog row fails physical revalidation.
    fn inventory_resources(&self) -> Result<Vec<u8>, StorageRuntimeError>;
}

impl StorageRpcRuntime for StorageBrokerRuntime {
    fn is_repair_ready(&self) -> bool {
        Self::is_repair_ready(self)
    }

    fn is_inventory_ready(&self) -> bool {
        Self::is_inventory_ready(self)
    }

    fn repair_workspace_pin<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<WorkspacePinRepairExecutionOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, StorageAdmissionError>,
    {
        Self::repair_workspace_pin(
            self,
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            trusted_clock,
        )
    }

    fn inventory_resources(&self) -> Result<Vec<u8>, StorageRuntimeError> {
        Self::inventory_resources(self)
    }
}

/// Serves the closed Storage repair and authoritative-inventory method set.
pub struct StorageService<R> {
    runtime: R,
    verifier: ControllerPeerVerifier,
}

impl<R: StorageRpcRuntime> StorageService<R> {
    /// Constructs a service around a protected runtime and exact peer verifier.
    #[must_use]
    pub const fn new(runtime: R, verifier: ControllerPeerVerifier) -> Self {
        Self { runtime, verifier }
    }

    /// Accepts, authenticates, serves, replies, and closes one connection.
    ///
    /// The connection establisher is verified before the first record is read.
    /// The request record and original connection are checked again immediately
    /// before inventory observation or repair dispatch. Transport operations
    /// are bounded by ten seconds of `CLOCK_BOOTTIME` and by the request's own
    /// shorter response deadline. That transport bound does not cancel a repair
    /// once durable admission has begun: loss of its reply requires inventory
    /// reconciliation, never blind reissue.
    ///
    /// # Errors
    ///
    /// Returns [`StorageServiceError`] for a corrupted listener or configured
    /// controller cgroup, failed readiness polling, or invalid local clock.
    /// Peer, request, runtime, and accepted-child transport failures remain
    /// contained to the connection and are returned as an outcome.
    pub fn serve_once(
        &mut self,
        listener: &mut RecordSubjectListener,
    ) -> Result<StorageConnectionOutcome, StorageServiceError> {
        self.verifier.validate_current()?;
        let Some(mut connection) = accept_connection(listener)? else {
            return Ok(StorageConnectionOutcome::TransportRejected);
        };
        let execution = match self.verifier.verify_connection(connection.peer()) {
            Ok(execution) => execution,
            Err(()) => return Ok(StorageConnectionOutcome::PeerRejected),
        };
        let exchange_deadline = boottime()?
            .checked_add(EXCHANGE_NANOSECONDS)
            .ok_or(StorageServiceError::Clock)?;

        let hello = match receive(&mut connection, MAXIMUM_HANDSHAKE_BYTES, exchange_deadline) {
            Ok(hello) => hello,
            Err(_) => return Ok(StorageConnectionOutcome::TransportRejected),
        };
        if self
            .verifier
            .verify_record(execution, connection.peer(), hello.subject())
            .is_err()
        {
            return Ok(StorageConnectionOutcome::PeerRejected);
        }
        let advertised_features = [signed_plan_lease_feature()?];
        let advertised_methods = advertised_storage_methods(
            self.runtime.is_inventory_ready(),
            self.runtime.is_repair_ready(),
        );
        let session = match negotiate_client_hello(
            hello.payload(),
            execution.credentials(),
            self.verifier.policy(),
            ProtocolId::StorageBroker,
            &advertised_features,
            &advertised_methods,
        ) {
            Ok(session) => session,
            Err(error) => {
                return Ok(send_hello_error(&mut connection, &error, exchange_deadline));
            }
        };
        if self
            .verifier
            .recheck_connection(execution, connection.peer())
            .is_err()
        {
            return Ok(StorageConnectionOutcome::PeerRejected);
        }
        if send(
            &mut connection,
            &session.server_hello().encode_to_vec(),
            exchange_deadline,
        )
        .is_err()
        {
            return Ok(StorageConnectionOutcome::TransportRejected);
        }

        let request = match receive(
            &mut connection,
            session.maximum_request_bytes(),
            exchange_deadline,
        ) {
            Ok(request) => request,
            Err(_) => return Ok(StorageConnectionOutcome::TransportRejected),
        };
        if self
            .verifier
            .verify_record(execution, connection.peer(), request.subject())
            .is_err()
        {
            return Ok(StorageConnectionOutcome::PeerRejected);
        }
        let envelope = match session.decode_request(request.payload(), 0) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
        };
        if validate_request_descriptor_roles(&envelope, &[]).is_err() {
            return Ok(StorageConnectionOutcome::RequestRejected);
        }

        let response = match envelope.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
                self.dispatch_repair(execution, connection.peer(), &session, &envelope)
            }
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
                self.dispatch_inventory(execution, connection.peer(), &session, &envelope)
            }
            _ => return Ok(StorageConnectionOutcome::RequestRejected),
        };
        let Ok((response, outcome, request_deadline)) = response else {
            return Ok(StorageConnectionOutcome::RequestRejected);
        };
        if self
            .verifier
            .recheck_connection(execution, connection.peer())
            .is_err()
        {
            return Ok(StorageConnectionOutcome::PeerRejected);
        }
        if send(
            &mut connection,
            &response,
            exchange_deadline.min(request_deadline),
        )
        .is_err()
        {
            return Ok(StorageConnectionOutcome::TransportRejected);
        }

        Ok(outcome)
    }

    fn dispatch_inventory(
        &mut self,
        execution: crate::peer::ControllerExecution,
        connection: &aos_sandbox_linux::seqpacket::ConnectionPeerIdentity,
        session: &aos_sandbox_protocol::NegotiatedBrokerSession,
        envelope: &ValidatedBrokerRequestEnvelope,
    ) -> Result<(Vec<u8>, StorageConnectionOutcome, u64), ProtocolValidationError> {
        if envelope.authorization().is_some() || !self.runtime.is_inventory_ready() {
            return Err(ProtocolValidationError::MethodMismatch);
        }
        let now = boottime().map_err(|_| ProtocolValidationError::DeadlineExpired)?;
        let header = decode_storage_resource_inventory_request(
            envelope.body(),
            execution.credentials(),
            self.verifier.policy(),
            now,
        )?;
        session.validate_header(&header)?;
        if self
            .verifier
            .recheck_connection(execution, connection)
            .is_err()
        {
            return Err(ProtocolValidationError::PeerCredentialMismatch);
        }

        let encoded = match self.runtime.inventory_resources() {
            Ok(body) => encode_success_or_resource_exhausted(
                header.request_id(),
                envelope,
                body,
                header.maximum_response_bytes(),
                "complete Storage inventory exceeds the response ceiling",
                true,
            ),
            Err(error) => encode_runtime_error(
                header.request_id(),
                envelope,
                &error,
                header.maximum_response_bytes(),
            ),
        }?;

        Ok((encoded.0, encoded.1, header.deadline_boottime_nanoseconds()))
    }

    fn dispatch_repair(
        &mut self,
        execution: crate::peer::ControllerExecution,
        connection: &aos_sandbox_linux::seqpacket::ConnectionPeerIdentity,
        session: &aos_sandbox_protocol::NegotiatedBrokerSession,
        envelope: &ValidatedBrokerRequestEnvelope,
    ) -> Result<(Vec<u8>, StorageConnectionOutcome, u64), ProtocolValidationError> {
        if !self.runtime.is_repair_ready() {
            return Err(ProtocolValidationError::MethodMismatch);
        }
        let artifacts = envelope
            .authorization()
            .ok_or(ProtocolValidationError::InvalidField(
                "envelope.authorization profile",
            ))?;
        let initial_clock =
            trusted_paired_clock_sample().map_err(|_| ProtocolValidationError::DeadlineExpired)?;
        let semantics = CanonicalStorageRepairSemanticsV1::decode(
            envelope.body(),
            execution.credentials(),
            self.verifier.policy(),
            initial_clock.boottime_nanoseconds(),
        )
        .map_err(|_| ProtocolValidationError::InvalidField("repair request"))?;
        session.validate_header(semantics.header())?;
        if self
            .verifier
            .recheck_connection(execution, connection)
            .is_err()
        {
            return Err(ProtocolValidationError::PeerCredentialMismatch);
        }

        let mut trusted_clock =
            || trusted_paired_clock_sample().map_err(|_| StorageAdmissionError::VerificationFailed);
        let result = self.runtime.repair_workspace_pin(
            envelope.body(),
            artifacts,
            session.version(),
            execution.credentials(),
            self.verifier.policy(),
            &mut trusted_clock,
        );
        let encoded = match result {
            Ok(WorkspacePinRepairExecutionOutcomeV1::Satisfied) => {
                let body = StorageResult {
                    storage_handle: semantics.storage_handle().as_bytes().to_vec(),
                    ..Default::default()
                }
                .encode_to_vec();
                encode_success_or_resource_exhausted(
                    semantics.header().request_id(),
                    envelope,
                    body,
                    semantics.header().maximum_response_bytes(),
                    "Storage repair result exceeds the response ceiling",
                    false,
                )
            }
            Ok(WorkspacePinRepairExecutionOutcomeV1::ObservationRequired) => encode_safe_error(
                semantics.header().request_id(),
                envelope,
                BrokerErrorCode::BROKER_ERROR_CODE_CONFLICT,
                "repair operation is durable and requires authoritative inventory",
                false,
                semantics.header().maximum_response_bytes(),
            ),
            Err(error) => encode_runtime_error(
                semantics.header().request_id(),
                envelope,
                &error,
                semantics.header().maximum_response_bytes(),
            ),
        }?;

        Ok((
            encoded.0,
            encoded.1,
            semantics.header().deadline_boottime_nanoseconds(),
        ))
    }
}

fn signed_plan_lease_feature() -> Result<FeatureRef, StorageServiceError> {
    FeatureRef::new(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE, 1, 0)
        .map_err(|error| StorageServiceError::Activation(error.to_string()))
}

fn trusted_paired_clock_sample()
-> Result<aos_sandbox_core::RawPairedClockSample, StorageServiceError> {
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let provenance = RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE)
        .map_err(|_| StorageServiceError::Clock)?;
    let boot_id = KernelBootId::current()
        .map_err(|_| StorageServiceError::Clock)?
        .into_bytes();
    aos_sandbox_core::RawPairedClockSample::new_untrusted(
        provenance,
        boot_id,
        wall.tv_sec,
        boottime()?,
    )
    .map_err(|_| StorageServiceError::Clock)
}

fn encode_success_or_resource_exhausted(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    body: Vec<u8>,
    maximum_bytes: u32,
    exhausted_message: &'static str,
    retryable: bool,
) -> Result<(Vec<u8>, StorageConnectionOutcome), ProtocolValidationError> {
    match encode_success_response_envelope(request_id, request, body, &[], &[], maximum_bytes) {
        Ok(response) => Ok((response, StorageConnectionOutcome::Served)),
        Err(
            ProtocolValidationError::ResponseTooLarge
            | ProtocolValidationError::InvalidResponseBound,
        ) => encode_safe_error(
            request_id,
            request,
            BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
            exhausted_message,
            retryable,
            maximum_bytes,
        ),
        Err(error) => Err(error),
    }
}

fn encode_runtime_error(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    error: &StorageRuntimeError,
    maximum_bytes: u32,
) -> Result<(Vec<u8>, StorageConnectionOutcome), ProtocolValidationError> {
    let (code, message) = match error {
        StorageRuntimeError::Admission(
            StorageBrokerError::Request | StorageBrokerError::Authority,
        ) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "Storage repair authority was rejected",
        ),
        StorageRuntimeError::Configuration(_)
        | StorageRuntimeError::Bootstrap
        | StorageRuntimeError::State(_)
        | StorageRuntimeError::WorkspaceCatalog(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
            "protected Storage state is unavailable",
        ),
        StorageRuntimeError::Worker(_)
        | StorageRuntimeError::Transaction(_)
        | StorageRuntimeError::Recovery
        | StorageRuntimeError::WorkspacePinScope
        | StorageRuntimeError::Admission(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
            "Storage repair requires reconciliation",
        ),
    };

    // A public caller must reconcile inventory and obtain new authority before
    // another mutation. No ambiguous failure is labelled safely retryable.
    encode_safe_error(request_id, request, code, message, false, maximum_bytes)
}

fn encode_safe_error(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    code: BrokerErrorCode,
    message: &'static str,
    retryable: bool,
    maximum_bytes: u32,
) -> Result<(Vec<u8>, StorageConnectionOutcome), ProtocolValidationError> {
    encode_error_response_envelope(
        request_id,
        request,
        code,
        message,
        retryable,
        None,
        &[],
        maximum_bytes,
    )
    .map(|response| (response, StorageConnectionOutcome::RequestRejected))
}

fn send_hello_error(
    connection: &mut aos_sandbox_linux::seqpacket::SeqpacketSocket,
    error: &ProtocolValidationError,
    deadline: u64,
) -> StorageConnectionOutcome {
    let (code, message) = match error {
        ProtocolValidationError::AudienceMismatch => (
            BrokerErrorCode::BROKER_ERROR_CODE_WRONG_AUDIENCE,
            "request audience is not served here",
        ),
        ProtocolValidationError::RequiredFeatureUnavailable(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE,
            "required Storage semantics are unavailable",
        ),
        _ => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "Storage broker negotiation failed",
        ),
    };
    let Ok(hello) = failed_server_hello(code, message, false, None) else {
        return StorageConnectionOutcome::TransportRejected;
    };
    if send(connection, &hello.encode_to_vec(), deadline).is_ok() {
        StorageConnectionOutcome::RequestRejected
    } else {
        StorageConnectionOutcome::TransportRejected
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope;

    use super::*;

    #[test]
    fn public_method_set_never_includes_apply_prepare_or_legacy_inventory() {
        assert!(advertised_storage_methods(false, false).is_empty());
        assert_eq!(
            advertised_storage_methods(true, false),
            [BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES]
        );
        assert_eq!(
            advertised_storage_methods(false, true),
            [BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN]
        );
        let methods = advertised_storage_methods(true, true);

        assert_eq!(
            methods,
            [
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
                BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN,
            ]
        );
        assert!(!methods.contains(&BrokerMethod::BROKER_METHOD_STORAGE_APPLY));
        assert!(!methods.contains(&BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG));
        assert!(!methods.contains(&BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY));
    }

    #[test]
    fn ambiguous_runtime_failures_are_never_labelled_retryable() {
        let request_id = [7; 16];
        let raw = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN.into(),
            body: vec![1],
            ..Default::default()
        };
        let request = aos_sandbox_protocol::decode_request_envelope(
            &raw.encode_to_vec(),
            ProtocolId::StorageBroker,
            0,
        )
        .unwrap();
        let (encoded, outcome) =
            encode_runtime_error(&request_id, &request, &StorageRuntimeError::Recovery, 4096)
                .unwrap();
        let response =
            aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope::decode_from_slice(&encoded)
                .unwrap();

        assert_eq!(outcome, StorageConnectionOutcome::RequestRejected);
        assert_eq!(
            response.error.as_option().unwrap().code.as_known(),
            Some(BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE)
        );
        assert!(!response.error.as_option().unwrap().retryable);
        assert!(response.body.is_empty());
    }

    #[test]
    fn oversized_post_repair_success_is_never_labelled_retryable() {
        let request_id = [8; 16];
        let raw = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN.into(),
            body: vec![1],
            ..Default::default()
        };
        let request = aos_sandbox_protocol::decode_request_envelope(
            &raw.encode_to_vec(),
            ProtocolId::StorageBroker,
            0,
        )
        .unwrap();
        let (encoded, outcome) = encode_success_or_resource_exhausted(
            &request_id,
            &request,
            vec![0; 4_096],
            4_096,
            "Storage repair result exceeds the response ceiling",
            false,
        )
        .unwrap();
        let response =
            aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope::decode_from_slice(&encoded)
                .unwrap();

        assert_eq!(outcome, StorageConnectionOutcome::RequestRejected);
        assert_eq!(
            response.error.as_option().unwrap().code.as_known(),
            Some(BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED)
        );
        assert!(!response.error.as_option().unwrap().retryable);
        assert!(response.body.is_empty());
    }
}
