//! Authenticated one-request Storage broker service.
//!
//! The service verifies the connection establisher before reading bytes, then
//! requires both hello and request records to name that same live controller
//! leader in the exact retained service cgroup. Its carrier forbids
//! `SCM_RIGHTS`. Prepare, repair, and gated Apply accept only their canonical
//! Storage bodies plus the standard signed authorization artifacts. Prepare
//! retains journaled authority and resolution evidence but performs no physical
//! mutation; repair and Apply may dispatch their fixed physical workers.
//!
//! Apply dispatch remains unreachable unless the runtime presents complete
//! backend and deployment readiness; current production construction keeps
//! that gate closed. Physical storage names, internal
//! observer/worker envelopes, and caller-selected proofs remain outside this
//! boundary. Prepare is non-authorizing and resolves only through protected
//! policy and freshly authenticated local state.

use aos_proto::aos::sandbox::local::v1::{
    ApplyStorageRequest, BrokerErrorCode, BrokerMethod, StorageResult,
};
use aos_sandbox_core::{FeatureRef, ProtocolId, ProtocolVersion, RawClockProvenance};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_protocol::semantics::storage_prepare::CanonicalStoragePreparationSemanticsV1;
use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::session::{
    SIGNED_PLAN_LEASE_FEATURE_NAMESPACE, ValidatedUntrustedAuthorizationArtifacts,
};
use aos_sandbox_protocol::{
    MAXIMUM_HANDSHAKE_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedBrokerRequestEnvelope, decode_storage_resource_inventory_request,
    encode_error_response_envelope, encode_success_response_envelope, failed_server_hello,
    negotiate_client_hello, validate_request_descriptor_roles, validate_request_header,
};
use buffa::Message as _;

use crate::broker::{StorageBrokerError, advertised_storage_methods};
use crate::peer::ControllerPeerVerifier;
use crate::runtime::{
    StorageApplyReadiness, StorageBrokerRuntime, StorageRuntimeError,
    StorageRuntimeMutationOutcome, WorkspacePinRepairExecutionOutcomeV1,
};
use crate::transport::{EXCHANGE_NANOSECONDS, accept_connection, boottime, receive, send};
use crate::{StorageAdmissionError, StorageCatalogPreparationOutcomeV1};

const KERNEL_CLOCK_PROVENANCE: [u8; 16] = *b"aos-kernel-clock";
const CATALOG_OBSERVATION_NANOSECONDS: u64 = 35_000_000_000;
const CATALOG_OBSERVATION_QUIESCENCE_RESERVE_NANOSECONDS: u64 = 6_000_000_000;
const INVENTORY_RESPONSE_RESERVE_NANOSECONDS: u64 = 1_000_000_000;
const INVENTORY_METHOD_NANOSECONDS: u64 = 42_000_000_000;
const INVENTORY_POST_OBSERVATION_RESERVE_NANOSECONDS: u64 =
    CATALOG_OBSERVATION_QUIESCENCE_RESERVE_NANOSECONDS + INVENTORY_RESPONSE_RESERVE_NANOSECONDS;

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
    /// Reports whether the service must exit and reopen protected state.
    fn requires_reopen(&self) -> bool;

    /// Reports whether protected policy and runtime state permit Prepare.
    fn is_prepare_ready(&self) -> bool;

    /// Returns the fail-closed production Apply backend classification.
    fn apply_readiness(&self) -> StorageApplyReadiness;

    /// Reports whether fresh repair admission is available.
    fn is_repair_ready(&self) -> bool;

    /// Reports whether authenticated current inventory is available.
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
    /// Returns [`StorageRuntimeError`] when authenticated inventory is unavailable
    /// or a protected catalog row fails physical revalidation.
    fn inventory_resources(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError>;

    /// Resolves and durably retains one non-authorizing catalog preparation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for unavailable readiness, rejected
    /// authority or policy, stale state, clock failure, or durable retention.
    #[allow(clippy::too_many_arguments)]
    fn prepare_catalog<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<StorageCatalogPreparationOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, StorageAdmissionError>;

    /// Admits and consumes one Storage 1.0 Apply request.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when the complete Apply composition is
    /// unavailable, signed admission fails, or execution requires recovery.
    #[allow(clippy::too_many_arguments)]
    fn apply_storage<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, StorageAdmissionError>;
}

impl StorageRpcRuntime for StorageBrokerRuntime {
    fn requires_reopen(&self) -> bool {
        Self::requires_reopen(self)
    }

    fn is_prepare_ready(&self) -> bool {
        Self::is_prepare_ready(self)
    }

    fn apply_readiness(&self) -> StorageApplyReadiness {
        Self::apply_readiness(self)
    }

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

    fn inventory_resources(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        Self::inventory_resources(
            self,
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        )
    }

    fn prepare_catalog<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<StorageCatalogPreparationOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, StorageAdmissionError>,
    {
        Self::prepare_catalog(
            self,
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            trusted_clock,
        )
    }

    fn apply_storage<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, StorageAdmissionError>,
    {
        let current_clock = trusted_clock().map_err(|_| StorageRuntimeError::Recovery)?;
        let (operation_id, _operation, admission) = Self::admit_signed_apply_intent(
            self,
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            &current_clock,
        )?;
        match admission {
            crate::StorageAdmissionOutcome::Prepared { .. }
            | crate::StorageAdmissionOutcome::ObservationRequired {
                phase: crate::DurableStoragePhase::Prepared,
                ..
            } => Self::execute_admitted(self, operation_id, trusted_clock),
            crate::StorageAdmissionOutcome::ObservationRequired {
                phase,
                mutation_digest,
            } => Ok(StorageRuntimeMutationOutcome::ObservationRequired {
                phase,
                mutation_digest,
            }),
            crate::StorageAdmissionOutcome::Replay(result) => {
                Ok(StorageRuntimeMutationOutcome::Committed(result))
            }
        }
    }
}

/// Serves the closed, independently gated Storage method set.
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
    /// controller cgroup, failed readiness polling, invalid local clock, or a
    /// runtime whose protected journal custody requires a process restart.
    /// Other peer, request, runtime, and accepted-child transport failures
    /// remain contained to the connection and are returned as an outcome.
    pub fn serve_once(
        &mut self,
        listener: &mut RecordSubjectListener,
    ) -> Result<StorageConnectionOutcome, StorageServiceError> {
        if self.runtime.requires_reopen() {
            return Err(StorageRuntimeError::ReopenRequired.into());
        }
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
            self.runtime.is_prepare_ready(),
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

        let inventory_method =
            envelope.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES;
        let response = match envelope.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
                self.dispatch_apply(execution, connection.peer(), &session, &envelope)
            }
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
                self.dispatch_prepare(execution, connection.peer(), &session, &envelope)
            }
            BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
                self.dispatch_repair(execution, connection.peer(), &session, &envelope)
            }
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
                self.dispatch_inventory(execution, connection.peer(), &session, &envelope)
            }
            _ => return Ok(StorageConnectionOutcome::RequestRejected),
        };
        let (response, outcome, request_deadline) = match response {
            Ok(response) => response,
            Err(_) if self.runtime.requires_reopen() => {
                return Err(StorageRuntimeError::ReopenRequired.into());
            }
            Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
        };
        if self
            .verifier
            .recheck_connection(execution, connection.peer())
            .is_err()
        {
            if self.runtime.requires_reopen() {
                return Err(StorageRuntimeError::ReopenRequired.into());
            }
            return Ok(StorageConnectionOutcome::PeerRejected);
        }
        let response_deadline = if inventory_method {
            request_deadline
        } else {
            exchange_deadline.min(request_deadline)
        };
        let response_sent = send(&mut connection, &response, response_deadline).is_ok();
        finish_dispatched_response(self.runtime.requires_reopen(), response_sent, outcome)
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

        let activation_deadline = header.deadline_boottime_nanoseconds().min(
            now.checked_add(INVENTORY_METHOD_NANOSECONDS)
                .ok_or(ProtocolValidationError::DeadlineExpired)?,
        );
        let minimum_completion = now
            .checked_add(INVENTORY_POST_OBSERVATION_RESERVE_NANOSECONDS)
            .ok_or(ProtocolValidationError::DeadlineExpired)?;
        if activation_deadline <= minimum_completion {
            return Err(ProtocolValidationError::DeadlineExpired);
        }
        let worker_cutoff = now
            .checked_add(CATALOG_OBSERVATION_NANOSECONDS)
            .ok_or(ProtocolValidationError::DeadlineExpired)?
            .min(
                activation_deadline
                    .checked_sub(INVENTORY_POST_OBSERVATION_RESERVE_NANOSECONDS)
                    .ok_or(ProtocolValidationError::DeadlineExpired)?,
            );

        let encoded = match self
            .runtime
            .inventory_resources(activation_deadline, worker_cutoff)
        {
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

        Ok((encoded.0, encoded.1, activation_deadline))
    }

    fn dispatch_apply(
        &mut self,
        execution: crate::peer::ControllerExecution,
        connection: &aos_sandbox_linux::seqpacket::ConnectionPeerIdentity,
        session: &aos_sandbox_protocol::NegotiatedBrokerSession,
        envelope: &ValidatedBrokerRequestEnvelope,
    ) -> Result<(Vec<u8>, StorageConnectionOutcome, u64), ProtocolValidationError> {
        if self.runtime.apply_readiness() == StorageApplyReadiness::WorkspaceBackendUnavailable
            || session.version() != ProtocolVersion::new(1, 0)
        {
            return Err(ProtocolValidationError::MethodMismatch);
        }
        let artifacts = envelope
            .authorization()
            .ok_or(ProtocolValidationError::InvalidField(
                "envelope.authorization profile",
            ))?;
        let initial_clock =
            trusted_paired_clock_sample().map_err(|_| ProtocolValidationError::DeadlineExpired)?;
        let request = ApplyStorageRequest::decode_from_slice(envelope.body())
            .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields);
        }
        let header = request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?;
        let header = validate_request_header(
            header,
            execution.credentials(),
            self.verifier.policy(),
            ProtocolId::StorageBroker,
            initial_clock.boottime_nanoseconds(),
        )?;
        session.validate_header(&header)?;
        if self
            .verifier
            .recheck_connection(execution, connection)
            .is_err()
        {
            return Err(ProtocolValidationError::PeerCredentialMismatch);
        }

        let mut trusted_clock =
            || trusted_paired_clock_sample().map_err(|_| StorageAdmissionError::VerificationFailed);
        let result = self.runtime.apply_storage(
            envelope.body(),
            artifacts,
            session.version(),
            execution.credentials(),
            self.verifier.policy(),
            &mut trusted_clock,
        );
        let encoded = match result {
            Ok(StorageRuntimeMutationOutcome::Committed(result)) => {
                let body = StorageResult {
                    storage_handle: result
                        .storage_handle()
                        .map_or_else(Vec::new, |handle| handle.to_vec()),
                    immutable_version_handle: result
                        .immutable_version_handle()
                        .map_or_else(Vec::new, |handle| handle.to_vec()),
                    non_secret_receipt: result.result_digest().as_bytes().to_vec(),
                    ..Default::default()
                }
                .encode_to_vec();
                encode_success_or_resource_exhausted(
                    header.request_id(),
                    envelope,
                    body,
                    header.maximum_response_bytes(),
                    "Storage Apply result exceeds the response ceiling",
                    false,
                )
            }
            Ok(StorageRuntimeMutationOutcome::ObservationRequired { .. }) => encode_safe_error(
                header.request_id(),
                envelope,
                BrokerErrorCode::BROKER_ERROR_CODE_CONFLICT,
                "Storage operation is durable and requires authoritative inventory",
                false,
                header.maximum_response_bytes(),
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

    fn dispatch_prepare(
        &mut self,
        execution: crate::peer::ControllerExecution,
        connection: &aos_sandbox_linux::seqpacket::ConnectionPeerIdentity,
        session: &aos_sandbox_protocol::NegotiatedBrokerSession,
        envelope: &ValidatedBrokerRequestEnvelope,
    ) -> Result<(Vec<u8>, StorageConnectionOutcome, u64), ProtocolValidationError> {
        if !self.runtime.is_prepare_ready() {
            return Err(ProtocolValidationError::MethodMismatch);
        }
        let artifacts = envelope
            .authorization()
            .ok_or(ProtocolValidationError::InvalidField(
                "envelope.authorization profile",
            ))?;
        let initial_clock =
            trusted_paired_clock_sample().map_err(|_| ProtocolValidationError::DeadlineExpired)?;
        let semantics = CanonicalStoragePreparationSemanticsV1::decode(
            envelope.body(),
            execution.credentials(),
            self.verifier.policy(),
            initial_clock.boottime_nanoseconds(),
        )
        .map_err(|_| ProtocolValidationError::InvalidField("Storage Prepare request"))?;
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
        let result = self.runtime.prepare_catalog(
            envelope.body(),
            artifacts,
            session.version(),
            execution.credentials(),
            self.verifier.policy(),
            &mut trusted_clock,
        );
        let encoded = match result {
            Ok(outcome) => encode_success_or_resource_exhausted(
                semantics.header().request_id(),
                envelope,
                outcome.response().encode_to_vec(),
                semantics.header().maximum_response_bytes(),
                "Storage Prepare result exceeds the response ceiling",
                false,
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
            "Storage request authority was rejected",
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
        | StorageRuntimeError::ReopenRequired
        | StorageRuntimeError::WorkspacePinScope
        | StorageRuntimeError::Admission(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
            "Storage request requires reconciliation",
        ),
    };

    // A public caller must reconcile inventory and obtain new authority before
    // another mutation. No ambiguous failure is labelled safely retryable.
    encode_safe_error(request_id, request, code, message, false, maximum_bytes)
}

pub(crate) fn finish_dispatched_response(
    reopen_required: bool,
    response_sent: bool,
    outcome: StorageConnectionOutcome,
) -> Result<StorageConnectionOutcome, StorageServiceError> {
    // Once custody is ambiguous, even a failed response send must not return to
    // the accept loop. Exiting lets systemd reopen and replay protected state.
    if reopen_required {
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    if !response_sent {
        return Ok(StorageConnectionOutcome::TransportRejected);
    }

    Ok(outcome)
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

    use aos_proto::aos::sandbox::local::v1::{
        Audience, BrokerClientHello, BrokerRequestEnvelope, Feature,
    };

    use super::*;

    #[test]
    fn public_method_set_never_includes_apply_without_complete_readiness() {
        assert!(advertised_storage_methods(false, false, false).is_empty());
        assert_eq!(
            advertised_storage_methods(true, false, false),
            [BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES]
        );
        assert_eq!(
            advertised_storage_methods(false, false, true),
            [BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN]
        );
        let methods = advertised_storage_methods(true, true, true);

        assert_eq!(
            methods,
            [
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
                BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
                BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN,
            ]
        );
        assert!(!methods.contains(&BrokerMethod::BROKER_METHOD_STORAGE_APPLY));
    }

    #[test]
    fn prepare_negotiation_accepts_only_storage_one_zero() {
        let feature = signed_plan_lease_feature().unwrap();
        let features = [feature.clone()];
        let methods = advertised_storage_methods(true, true, true);
        let peer = PeerCredentials {
            uid: 811,
            gid: 811,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 811,
            gid: Some(811),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };

        for minor in 0..=2 {
            let hello = BrokerClientHello {
                protocol_major: 1,
                protocol_minor: minor,
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                required_features: vec![Feature {
                    namespace: feature.namespace().to_owned(),
                    major: feature.major(),
                    minor: feature.minor(),
                    ..Default::default()
                }],
                maximum_response_bytes: 4096,
                required_methods: vec![BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG.into()],
                ..Default::default()
            };
            let negotiated = negotiate_client_hello(
                &hello.encode_to_vec(),
                peer,
                policy,
                ProtocolId::StorageBroker,
                &features,
                &methods,
            );

            if minor == 0 {
                let session = negotiated.unwrap();
                assert_eq!(session.version(), ProtocolVersion::new(1, 0));
                assert!(
                    session
                        .advertised_methods()
                        .contains(&BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG)
                );
            } else {
                assert!(matches!(
                    negotiated,
                    Err(ProtocolValidationError::Protocol(_))
                ));
            }
        }
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
    fn reopen_required_exits_after_bounded_response_handling() {
        for response_sent in [false, true] {
            let error = finish_dispatched_response(
                true,
                response_sent,
                StorageConnectionOutcome::RequestRejected,
            )
            .unwrap_err();

            assert!(matches!(
                error,
                StorageServiceError::Runtime(StorageRuntimeError::ReopenRequired)
            ));
        }

        assert_eq!(
            finish_dispatched_response(false, true, StorageConnectionOutcome::RequestRejected,)
                .unwrap(),
            StorageConnectionOutcome::RequestRejected
        );
        assert_eq!(
            finish_dispatched_response(false, false, StorageConnectionOutcome::RequestRejected,)
                .unwrap(),
            StorageConnectionOutcome::TransportRejected
        );
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
