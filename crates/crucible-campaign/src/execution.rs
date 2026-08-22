//! Transport-neutral local executor assignment contracts.
//!
//! The coordinator submits one immutable semantic [`AttemptId`] together with
//! bounded operational ceilings. The strict component-message formats are:
//!
//! ```text
//! SubmitAttemptRequestV2 = version | assignment | daemon-epoch | lineage |
//!                          attempt | resource-limits | retention-intent
//! SubmitAttemptResponseV2 = version | assignment | daemon-epoch | attempt |
//!                           request-digest | disposition
//! GetAttemptExecutionRequestV2 = version | daemon-epoch | lineage | attempt |
//!                                execution | execution-basis-digest
//! GetAttemptExecutionResponseV2 = version | daemon-epoch | attempt | execution |
//!                                 request-digest | disposition
//! ResumeAttemptExecutionRequestV2 = version | assignment | daemon-epoch |
//!                                    lineage | attempt | prior-execution |
//!                                    checkpoint | resource-limits |
//!                                    retention-intent
//! ResumeAttemptExecutionResponseV2 = version | assignment | daemon-epoch |
//!                                     attempt | prior-execution | checkpoint |
//!                                     request-digest | disposition
//! CheckpointAttemptExecutionRequestV2 = version | daemon-epoch | lineage |
//!                                       attempt | execution |
//!                                       execution-basis-digest
//! CheckpointAttemptExecutionResponseV2 = version | daemon-epoch | attempt |
//!                                        execution | request-digest |
//!                                        disposition
//! CancelAttemptExecutionRequestV2 = version | daemon-epoch | lineage | attempt |
//!                                   execution | execution-basis-digest
//! CancelAttemptExecutionResponseV2 = version | daemon-epoch | attempt | execution |
//!                                    request-digest | disposition
//! ```
//!
//! Assignment, execution, epoch, resource, and retention fields are local
//! execution metadata. They never enter the identity of an attempt,
//! configuration, observation, or finding.

use std::collections::BTreeMap;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::validate_identifier;
use crate::{
    AttemptId, CampaignCodecError, CampaignHash, CampaignLineage, CampaignLineageId,
    ExactCheckpointId, ObservationId,
};

const EXECUTOR_MESSAGE_SCHEMA_VERSION: u32 = 2;

/// Maximum canonical bytes in one executor component message.
pub const MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES: usize = 4 * 1024;

/// Exact local compatibility profile admitted by one executor incarnation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorCompatibilityProfile {
    crucible_version: String,
    qemu_build: String,
    protocol_versions: BTreeMap<String, u32>,
    scenario_schema: u32,
    exact_closure_schema: u32,
}

impl ExecutorCompatibilityProfile {
    /// Builds one exact executor compatibility profile.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an identifier or protocol map is
    /// empty/oversized, or any required version is zero.
    pub fn new(
        crucible_version: impl Into<String>,
        qemu_build: impl Into<String>,
        protocol_versions: BTreeMap<String, u32>,
        scenario_schema: u32,
        exact_closure_schema: u32,
    ) -> Result<Self, CampaignCodecError> {
        let crucible_version = crucible_version.into();
        let qemu_build = qemu_build.into();
        validate_identifier(&crucible_version, "executor Crucible version is invalid")?;
        validate_identifier(&qemu_build, "executor QEMU build identity is invalid")?;
        if protocol_versions.is_empty() || protocol_versions.len() > 256 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor protocol-version set is empty or oversized",
            });
        }
        for (component, version) in &protocol_versions {
            validate_identifier(component, "executor protocol component is invalid")?;
            if *version == 0 {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "executor protocol version is zero",
                });
            }
        }
        if scenario_schema == 0 || exact_closure_schema == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor lineage schema version is zero",
            });
        }
        Ok(Self {
            crucible_version,
            qemu_build,
            protocol_versions,
            scenario_schema,
            exact_closure_schema,
        })
    }

    /// Copies the exact compatibility basis from an authenticated lineage.
    #[must_use]
    pub fn from_lineage(lineage: &CampaignLineage) -> Self {
        Self {
            crucible_version: lineage.crucible_version().to_owned(),
            qemu_build: lineage.qemu_build().to_owned(),
            protocol_versions: lineage.protocol_versions().clone(),
            scenario_schema: lineage.scenario_schema(),
            exact_closure_schema: lineage.exact_closure_schema(),
        }
    }

    /// Returns the exact Crucible build/version identity.
    #[must_use]
    pub fn crucible_version(&self) -> &str {
        &self.crucible_version
    }

    /// Returns the exact QEMU build identity.
    #[must_use]
    pub fn qemu_build(&self) -> &str {
        &self.qemu_build
    }

    /// Returns the exact component protocol-version map.
    #[must_use]
    pub const fn protocol_versions(&self) -> &BTreeMap<String, u32> {
        &self.protocol_versions
    }

    /// Returns the admitted scenario schema version.
    #[must_use]
    pub const fn scenario_schema(&self) -> u32 {
        self.scenario_schema
    }

    /// Returns the admitted exact-closure schema version.
    #[must_use]
    pub const fn exact_closure_schema(&self) -> u32 {
        self.exact_closure_schema
    }

    /// Returns whether all compatibility fields exactly match a lineage.
    #[must_use]
    pub fn admits(&self, lineage: &CampaignLineage) -> bool {
        self.crucible_version == lineage.crucible_version()
            && self.qemu_build == lineage.qemu_build()
            && self.protocol_versions == *lineage.protocol_versions()
            && self.scenario_schema == lineage.scenario_schema()
            && self.exact_closure_schema == lineage.exact_closure_schema()
    }
}

impl Canonical for ExecutorCompatibilityProfile {
    fn encode(&self, encoder: &mut Encoder) {
        self.crucible_version.encode(encoder);
        self.qemu_build.encode(encoder);
        self.protocol_versions.encode(encoder);
        self.scenario_schema.encode(encoder);
        self.exact_closure_schema.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            String::decode(decoder)?,
            String::decode(decoder)?,
            decoder.map_bounded(256, "executor-protocol-version-count")?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

macro_rules! operational_id {
    ($name:ident, $summary:literal, $zero_reason:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Builds an operational identity from a nonzero 128-bit value.
            ///
            /// # Errors
            ///
            /// Returns [`CampaignCodecError::InvalidValue`] for the all-zero
            /// sentinel.
            pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, CampaignCodecError> {
                if bytes == [0; 16] {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: $zero_reason,
                    });
                }
                Ok(Self(bytes))
            }

            /// Returns the exact operational identity bytes.
            #[must_use]
            pub const fn as_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl Canonical for $name {
            fn encode(&self, encoder: &mut Encoder) {
                encoder.fixed(&self.0);
            }

            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
                Self::from_bytes(decoder.fixed()?)
            }
        }
    };
}

operational_id!(
    DaemonEpoch,
    "Identifies one process-local daemon incarnation.",
    "daemon epoch is all zero"
);
operational_id!(
    AssignmentId,
    "Identifies one idempotent coordinator-to-executor assignment.",
    "executor assignment identity is all zero"
);
operational_id!(
    ExecutionId,
    "Identifies one local execution incarnation of an assignment.",
    "executor execution identity is all zero"
);

/// Bounded host resources available to one local attempt execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptResourceLimits {
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_disk_bytes: u64,
    maximum_execution_quanta: u64,
}

impl AttemptResourceLimits {
    /// Builds explicit nonzero CPU, memory, and modeled-progress ceilings.
    ///
    /// A zero disk allowance is valid for attempts that do not materialize
    /// writable disk state.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when the CPU, resident
    /// memory, or execution-quantum ceiling is zero.
    pub const fn new(
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_disk_bytes: u64,
        maximum_execution_quanta: u64,
    ) -> Result<Self, CampaignCodecError> {
        if maximum_vcpus == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor resource limit has zero vcpus",
            });
        }
        if maximum_resident_bytes == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor resource limit has zero resident bytes",
            });
        }
        if maximum_execution_quanta == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor resource limit has zero execution quanta",
            });
        }
        Ok(Self {
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_disk_bytes,
            maximum_execution_quanta,
        })
    }

    /// Returns the maximum virtual CPU count.
    #[must_use]
    pub const fn maximum_vcpus(self) -> u32 {
        self.maximum_vcpus
    }

    /// Returns the maximum resident host-memory bytes.
    #[must_use]
    pub const fn maximum_resident_bytes(self) -> u64 {
        self.maximum_resident_bytes
    }

    /// Returns the maximum writable materialization bytes.
    #[must_use]
    pub const fn maximum_disk_bytes(self) -> u64 {
        self.maximum_disk_bytes
    }

    /// Returns the maximum deterministic execution quanta.
    #[must_use]
    pub const fn maximum_execution_quanta(self) -> u64 {
        self.maximum_execution_quanta
    }
}

impl Canonical for AttemptResourceLimits {
    fn encode(&self, encoder: &mut Encoder) {
        self.maximum_vcpus.encode(encoder);
        self.maximum_resident_bytes.encode(encoder);
        self.maximum_disk_bytes.encode(encoder);
        self.maximum_execution_quanta.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Operational exact-closure retention requested for one execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionRetentionIntent {
    /// Retains no exact closure solely because of this assignment.
    Discard,
    /// Retains an exact closure only when modeled execution reports a failure.
    RetainOnFailure,
    /// Retains an exact closure for every completed execution.
    RetainAlways,
}

impl Canonical for ExecutionRetentionIntent {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Discard => 0,
            Self::RetainOnFailure => 1,
            Self::RetainAlways => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Discard),
            1 => Ok(Self::RetainOnFailure),
            2 => Ok(Self::RetainAlways),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "execution-retention-intent",
                tag,
            }),
        }
    }
}

/// Strict bounded request for one local executor assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitAttemptRequest {
    schema_version: u32,
    assignment: AssignmentId,
    daemon_epoch: DaemonEpoch,
    lineage: CampaignLineageId,
    attempt: AttemptId,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
}

impl SubmitAttemptRequest {
    /// Builds one transport-neutral assignment request.
    ///
    /// The canonical [`AttemptId`] is itself the immutable attempt
    /// specification; the protocol does not introduce a second semantic
    /// `AttemptSpecId` authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds its strict
    /// encoded bound.
    pub fn new(
        assignment: AssignmentId,
        daemon_epoch: DaemonEpoch,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        resources: AttemptResourceLimits,
        retention: ExecutionRetentionIntent,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            assignment,
            daemon_epoch,
            lineage,
            attempt,
            resources,
            retention,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "submit-attempt-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Returns the idempotent operational assignment identity.
    #[must_use]
    pub const fn assignment(&self) -> AssignmentId {
        self.assignment
    }

    /// Returns the daemon incarnation that issued the assignment.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the compatibility lineage the executor must authenticate.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the immutable semantic attempt to execute.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the assignment's operational resource ceilings.
    #[must_use]
    pub const fn resources(&self) -> AttemptResourceLimits {
        self.resources
    }

    /// Returns the requested exact-closure retention behavior.
    #[must_use]
    pub const fn retention(&self) -> ExecutionRetentionIntent {
        self.retention
    }

    /// Returns the domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign.submit-attempt-request.v2",
            &self.canonical_bytes(),
        )
    }

    /// Returns the assignment-neutral local execution-contract digest.
    ///
    /// The digest binds lineage, attempt, resource ceilings, and retention but
    /// excludes assignment and daemon-epoch identities. Fresh assignments may
    /// share one running or completed execution only when this digest matches.
    #[must_use]
    pub fn execution_basis_digest(&self) -> CampaignHash {
        let mut encoder = Encoder::new();
        self.lineage.encode(&mut encoder);
        self.attempt.encode(&mut encoder);
        self.resources.encode(&mut encoder);
        self.retention.encode(&mut encoder);
        CampaignHash::derive(
            "crucible.campaign.submit-attempt-execution-basis.v1",
            &encoder.finish(),
        )
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "submit-attempt-request-encoded-bytes")
    }
}

impl Canonical for SubmitAttemptRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.assignment.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.lineage.encode(encoder);
        self.attempt.encode(encoder);
        self.resources.encode(encoder);
        self.retention.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let assignment = AssignmentId::decode(decoder)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        Self::new(
            assignment,
            daemon_epoch,
            CampaignLineageId::decode(decoder)?,
            AttemptId::decode(decoder)?,
            AttemptResourceLimits::decode(decoder)?,
            ExecutionRetentionIntent::decode(decoder)?,
        )
    }
}

/// Stable reason an executor rejected an assignment without guest execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorRejection {
    /// The executor cannot satisfy the lineage or protocol requirements.
    Incompatible,
    /// Bounded local execution capacity is currently exhausted.
    Backpressure,
    /// A required immutable input is not currently readable.
    UnavailableInput,
    /// The caller or daemon epoch is not authorized for this executor.
    Unauthorized,
    /// One assignment identity was reused with different canonical request bytes.
    ConflictingAssignment,
}

impl ExecutorRejection {
    /// Reports whether retry may succeed after choosing a new assignment ID.
    ///
    /// Exact replay of any assignment must reproduce its original response.
    /// Backpressure and temporarily unavailable input are the only rejection
    /// classes whose unchanged semantic attempt is immediately retryable, and
    /// that retry uses a fresh [`AssignmentId`].
    #[must_use]
    pub const fn retry_with_new_assignment(self) -> bool {
        matches!(self, Self::Backpressure | Self::UnavailableInput)
    }
}

impl Canonical for ExecutorRejection {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Incompatible => 0,
            Self::Backpressure => 1,
            Self::UnavailableInput => 2,
            Self::Unauthorized => 3,
            Self::ConflictingAssignment => 4,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Incompatible),
            1 => Ok(Self::Backpressure),
            2 => Ok(Self::UnavailableInput),
            3 => Ok(Self::Unauthorized),
            4 => Ok(Self::ConflictingAssignment),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "executor-rejection",
                tag,
            }),
        }
    }
}

/// Idempotent outcome of one `SubmitAttempt` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitAttemptDisposition {
    /// A new local execution was admitted.
    Accepted {
        /// Newly admitted local execution identity.
        execution: ExecutionId,
    },
    /// The same semantic attempt is already executing locally.
    AlreadyRunning {
        /// Existing local execution identity.
        execution: ExecutionId,
    },
    /// The executor already published an immutable observation body.
    AlreadyCompleted {
        /// Previously published immutable observation identity.
        observation: ObservationId,
    },
    /// The executor already stopped at a complete exact checkpoint.
    AlreadyPaused {
        /// Existing local execution identity.
        execution: ExecutionId,
        /// Complete durable exact-checkpoint root.
        checkpoint: ExactCheckpointId,
    },
    /// The request was rejected before guest execution.
    Rejected {
        /// Stable rejection class.
        reason: ExecutorRejection,
    },
}

impl Canonical for SubmitAttemptDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Accepted { execution } => {
                encoder.u8(0);
                execution.encode(encoder);
            }
            Self::AlreadyRunning { execution } => {
                encoder.u8(1);
                execution.encode(encoder);
            }
            Self::AlreadyCompleted { observation } => {
                encoder.u8(2);
                observation.encode(encoder);
            }
            Self::Rejected { reason } => {
                encoder.u8(3);
                reason.encode(encoder);
            }
            Self::AlreadyPaused {
                execution,
                checkpoint,
            } => {
                encoder.u8(4);
                execution.encode(encoder);
                checkpoint.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Accepted {
                execution: ExecutionId::decode(decoder)?,
            }),
            1 => Ok(Self::AlreadyRunning {
                execution: ExecutionId::decode(decoder)?,
            }),
            2 => Ok(Self::AlreadyCompleted {
                observation: ObservationId::decode(decoder)?,
            }),
            3 => Ok(Self::Rejected {
                reason: ExecutorRejection::decode(decoder)?,
            }),
            4 => Ok(Self::AlreadyPaused {
                execution: ExecutionId::decode(decoder)?,
                checkpoint: ExactCheckpointId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "submit-attempt-disposition",
                tag,
            }),
        }
    }
}

/// Strict response bound to the exact assignment, epoch, and attempt request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitAttemptResponse {
    schema_version: u32,
    assignment: AssignmentId,
    daemon_epoch: DaemonEpoch,
    attempt: AttemptId,
    request_digest: CampaignHash,
    disposition: SubmitAttemptDisposition,
}

impl SubmitAttemptResponse {
    /// Builds one response that cannot be replayed across another assignment.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds its strict
    /// encoded bound.
    pub fn new(
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            assignment: request.assignment,
            daemon_epoch: request.daemon_epoch,
            attempt: request.attempt,
            request_digest: request.request_digest(),
            disposition,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "submit-attempt-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the assignment identity copied from the request.
    #[must_use]
    pub const fn assignment(&self) -> AssignmentId {
        self.assignment
    }

    /// Returns the daemon epoch copied from the request.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the semantic attempt copied from the request.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the digest of the complete request this response answers.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the executor's stable submission outcome.
    #[must_use]
    pub const fn disposition(&self) -> SubmitAttemptDisposition {
        self.disposition
    }

    /// Reports whether this response belongs to the exact request basis.
    #[must_use]
    pub fn matches_request(&self, request: &SubmitAttemptRequest) -> bool {
        self.assignment == request.assignment
            && self.daemon_epoch == request.daemon_epoch
            && self.attempt == request.attempt
            && self.request_digest == request.request_digest()
    }

    /// Validates that this response answers every field of one exact request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when the response belongs
    /// to another assignment basis.
    pub fn validate_for(&self, request: &SubmitAttemptRequest) -> Result<(), CampaignCodecError> {
        if self.matches_request(request) {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "submit attempt response does not match request",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "submit-attempt-response-encoded-bytes")
    }

    /// Decodes a response and binds it to one exact request.
    ///
    /// RPC and other untrusted adapters use this entry point so a syntactically
    /// valid response cannot be replayed across changed resource or retention
    /// fields under a reused assignment identity.
    ///
    /// # Errors
    ///
    /// Returns an error for every ordinary strict-decoding failure or when the
    /// response does not commit to the supplied request's complete canonical
    /// bytes.
    pub fn from_canonical_bytes_for(
        request: &SubmitAttemptRequest,
        bytes: &[u8],
    ) -> Result<Self, CampaignCodecError> {
        let response = Self::from_canonical_bytes(bytes)?;
        response.validate_for(request)?;
        Ok(response)
    }
}

impl Canonical for SubmitAttemptResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.assignment.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.attempt.encode(encoder);
        self.request_digest.encode(encoder);
        self.disposition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let assignment = AssignmentId::decode(decoder)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let request_digest = CampaignHash::decode(decoder)?;
        let disposition = SubmitAttemptDisposition::decode(decoder)?;
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            assignment,
            daemon_epoch,
            attempt,
            request_digest,
            disposition,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "submit-attempt-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Strict read-only query for one exact local execution incarnation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAttemptExecutionRequest {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    lineage: CampaignLineageId,
    attempt: AttemptId,
    execution: ExecutionId,
    execution_basis: CampaignHash,
}

impl GetAttemptExecutionRequest {
    /// Builds a status query from the exact accepted assignment basis.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        assignment: &SubmitAttemptRequest,
        execution: ExecutionId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            execution,
            execution_basis: assignment.execution_basis_digest(),
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "get-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Returns the daemon incarnation that accepted the execution.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the exact compatibility lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the local execution incarnation being queried.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the assignment-neutral execution-contract digest.
    #[must_use]
    pub const fn execution_basis(&self) -> CampaignHash {
        self.execution_basis
    }

    /// Returns a domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign.get-attempt-execution-request.v2",
            &self.canonical_bytes(),
        )
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "get-attempt-execution-request-encoded-bytes")
    }
}

impl Canonical for GetAttemptExecutionRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.lineage.encode(encoder);
        self.attempt.encode(encoder);
        self.execution.encode(encoder);
        self.execution_basis.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: DaemonEpoch::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            attempt: AttemptId::decode(decoder)?,
            execution: ExecutionId::decode(decoder)?,
            execution_basis: CampaignHash::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "get-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }
}

/// Read-only state of one exact local execution incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetAttemptExecutionDisposition {
    /// The accepted execution or its publication reconciliation remains active.
    Running,
    /// The execution has durably latched an exact-checkpoint request.
    CheckpointRequested,
    /// Checkpoint publication is in progress under a retained root.
    CheckpointPublishing {
        /// Exact root retained before immutable publication began.
        checkpoint: ExactCheckpointId,
    },
    /// The execution stopped at a complete durable exact checkpoint.
    Paused {
        /// Complete exact-checkpoint root.
        checkpoint: ExactCheckpointId,
    },
    /// The executor durably retained one completed observation.
    Completed {
        /// Immutable observation identity ready for coordinator authentication.
        observation: ObservationId,
    },
    /// Durable cancellation won before completion.
    Canceled,
    /// No current runtime record matches the complete query basis.
    NotCurrent,
}

impl Canonical for GetAttemptExecutionDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Running => encoder.u8(0),
            Self::Completed { observation } => {
                encoder.u8(1);
                observation.encode(encoder);
            }
            Self::Canceled => encoder.u8(2),
            Self::NotCurrent => encoder.u8(3),
            Self::CheckpointRequested => encoder.u8(4),
            Self::CheckpointPublishing { checkpoint } => {
                encoder.u8(5);
                checkpoint.encode(encoder);
            }
            Self::Paused { checkpoint } => {
                encoder.u8(6);
                checkpoint.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Running),
            1 => Ok(Self::Completed {
                observation: ObservationId::decode(decoder)?,
            }),
            2 => Ok(Self::Canceled),
            3 => Ok(Self::NotCurrent),
            4 => Ok(Self::CheckpointRequested),
            5 => Ok(Self::CheckpointPublishing {
                checkpoint: ExactCheckpointId::decode(decoder)?,
            }),
            6 => Ok(Self::Paused {
                checkpoint: ExactCheckpointId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "get-attempt-execution-disposition",
                tag,
            }),
        }
    }
}

/// Strict status response bound to one exact execution query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAttemptExecutionResponse {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    attempt: AttemptId,
    execution: ExecutionId,
    request_digest: CampaignHash,
    disposition: GetAttemptExecutionDisposition,
}

impl GetAttemptExecutionResponse {
    /// Builds one response that cannot be replayed across another execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        request: &GetAttemptExecutionRequest,
        disposition: GetAttemptExecutionDisposition,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            execution: request.execution(),
            request_digest: request.request_digest(),
            disposition,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "get-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the daemon incarnation copied from the request.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the semantic attempt copied from the request.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the local execution copied from the request.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the digest of the complete request this response answers.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the exact current execution state.
    #[must_use]
    pub const fn disposition(&self) -> GetAttemptExecutionDisposition {
        self.disposition
    }

    /// Validates that this response answers every field of one exact request.
    ///
    /// # Errors
    ///
    /// Returns an error when any echoed identity or request digest differs.
    pub fn validate_for(
        &self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.daemon_epoch == request.daemon_epoch()
            && self.attempt == request.attempt()
            && self.execution == request.execution()
            && self.request_digest == request.request_digest()
        {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "get attempt execution response does not match request",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "get-attempt-execution-response-encoded-bytes")
    }

    /// Decodes and binds a response to one exact execution query.
    ///
    /// # Errors
    ///
    /// Returns an ordinary strict-decoding error or a cross-request mismatch.
    pub fn from_canonical_bytes_for(
        request: &GetAttemptExecutionRequest,
        bytes: &[u8],
    ) -> Result<Self, CampaignCodecError> {
        let response = Self::from_canonical_bytes(bytes)?;
        response.validate_for(request)?;
        Ok(response)
    }
}

impl Canonical for GetAttemptExecutionResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.attempt.encode(encoder);
        self.execution.encode(encoder);
        self.request_digest.encode(encoder);
        self.disposition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: DaemonEpoch::decode(decoder)?,
            attempt: AttemptId::decode(decoder)?,
            execution: ExecutionId::decode(decoder)?,
            request_digest: CampaignHash::decode(decoder)?,
            disposition: GetAttemptExecutionDisposition::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "get-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Strict request to resume one durably paused execution from its exact root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeAttemptExecutionRequest {
    schema_version: u32,
    assignment: AssignmentId,
    daemon_epoch: DaemonEpoch,
    lineage: CampaignLineageId,
    attempt: AttemptId,
    prior_execution: ExecutionId,
    checkpoint: ExactCheckpointId,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
}

impl ResumeAttemptExecutionRequest {
    /// Builds a resume request from one fresh assignment and exact paused root.
    ///
    /// The supplied assignment provides the new daemon incarnation, resource,
    /// retention, lineage, and semantic-attempt basis. It is not submitted
    /// separately: this request is the sole idempotent admission operation for
    /// the new execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        assignment: &SubmitAttemptRequest,
        prior_execution: ExecutionId,
        checkpoint: ExactCheckpointId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            assignment: assignment.assignment(),
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            prior_execution,
            checkpoint,
            resources: assignment.resources(),
            retention: assignment.retention(),
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "resume-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Returns the fresh idempotent assignment identity.
    #[must_use]
    pub const fn assignment(&self) -> AssignmentId {
        self.assignment
    }

    /// Returns the daemon incarnation that will own resumed execution.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the exact compatibility lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the immutable semantic attempt being resumed.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the execution incarnation that published the paused root.
    #[must_use]
    pub const fn prior_execution(&self) -> ExecutionId {
        self.prior_execution
    }

    /// Returns the complete exact checkpoint selected for resume.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the resumed execution's hard resource ceilings.
    #[must_use]
    pub const fn resources(&self) -> AttemptResourceLimits {
        self.resources
    }

    /// Returns the resumed execution's retention intent.
    #[must_use]
    pub const fn retention(&self) -> ExecutionRetentionIntent {
        self.retention
    }

    /// Returns the assignment-neutral execution-contract digest.
    #[must_use]
    pub fn execution_basis_digest(&self) -> CampaignHash {
        let mut encoder = Encoder::new();
        self.lineage.encode(&mut encoder);
        self.attempt.encode(&mut encoder);
        self.resources.encode(&mut encoder);
        self.retention.encode(&mut encoder);
        CampaignHash::derive(
            "crucible.campaign.submit-attempt-execution-basis.v1",
            &encoder.finish(),
        )
    }

    /// Returns the domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign.resume-attempt-execution-request.v2",
            &self.canonical_bytes(),
        )
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "resume-attempt-execution-request-encoded-bytes")
    }
}

impl Canonical for ResumeAttemptExecutionRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.assignment.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.lineage.encode(encoder);
        self.attempt.encode(encoder);
        self.prior_execution.encode(encoder);
        self.checkpoint.encode(encoder);
        self.resources.encode(encoder);
        self.retention.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let assignment = AssignmentId::decode(decoder)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let lineage = CampaignLineageId::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let prior_execution = ExecutionId::decode(decoder)?;
        let checkpoint = ExactCheckpointId::decode(decoder)?;
        let resources = AttemptResourceLimits::decode(decoder)?;
        let retention = ExecutionRetentionIntent::decode(decoder)?;
        let assignment = SubmitAttemptRequest::new(
            assignment,
            daemon_epoch,
            lineage,
            attempt,
            resources,
            retention,
        )?;
        Self::new(&assignment, prior_execution, checkpoint)
    }
}

/// Idempotent outcome of one exact paused-execution resume request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeAttemptExecutionDisposition {
    /// A new local execution incarnation was admitted from the checkpoint.
    Accepted {
        /// Newly admitted local execution identity.
        execution: ExecutionId,
    },
    /// This exact resume request already owns a running incarnation.
    AlreadyRunning {
        /// Existing resumed execution identity.
        execution: ExecutionId,
    },
    /// Canonical completion won before resume.
    AlreadyCompleted {
        /// Published immutable observation identity.
        observation: ObservationId,
    },
    /// Durable cancellation won before resume.
    AlreadyCanceled,
    /// The named prior execution/checkpoint is not the current paused state.
    NotCurrent,
    /// Resume admission was rejected without guest execution.
    Rejected {
        /// Stable rejection reason.
        reason: ExecutorRejection,
    },
}

impl Canonical for ResumeAttemptExecutionDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Accepted { execution } => {
                encoder.u8(0);
                execution.encode(encoder);
            }
            Self::AlreadyRunning { execution } => {
                encoder.u8(1);
                execution.encode(encoder);
            }
            Self::AlreadyCompleted { observation } => {
                encoder.u8(2);
                observation.encode(encoder);
            }
            Self::AlreadyCanceled => encoder.u8(3),
            Self::NotCurrent => encoder.u8(4),
            Self::Rejected { reason } => {
                encoder.u8(5);
                reason.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Accepted {
                execution: ExecutionId::decode(decoder)?,
            }),
            1 => Ok(Self::AlreadyRunning {
                execution: ExecutionId::decode(decoder)?,
            }),
            2 => Ok(Self::AlreadyCompleted {
                observation: ObservationId::decode(decoder)?,
            }),
            3 => Ok(Self::AlreadyCanceled),
            4 => Ok(Self::NotCurrent),
            5 => Ok(Self::Rejected {
                reason: ExecutorRejection::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "resume-attempt-execution-disposition",
                tag,
            }),
        }
    }
}

/// Strict response bound to one exact paused-execution resume request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeAttemptExecutionResponse {
    schema_version: u32,
    assignment: AssignmentId,
    daemon_epoch: DaemonEpoch,
    attempt: AttemptId,
    prior_execution: ExecutionId,
    checkpoint: ExactCheckpointId,
    request_digest: CampaignHash,
    disposition: ResumeAttemptExecutionDisposition,
}

impl ResumeAttemptExecutionResponse {
    /// Builds one response that cannot be replayed across another paused root.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        request: &ResumeAttemptExecutionRequest,
        disposition: ResumeAttemptExecutionDisposition,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            assignment: request.assignment(),
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            prior_execution: request.prior_execution(),
            checkpoint: request.checkpoint(),
            request_digest: request.request_digest(),
            disposition,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "resume-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the fresh assignment identity copied from the request.
    #[must_use]
    pub const fn assignment(&self) -> AssignmentId {
        self.assignment
    }

    /// Returns the new daemon incarnation copied from the request.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the semantic attempt copied from the request.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the prior execution copied from the request.
    #[must_use]
    pub const fn prior_execution(&self) -> ExecutionId {
        self.prior_execution
    }

    /// Returns the exact checkpoint copied from the request.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the digest of the complete request this response answers.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the executor's stable resume outcome.
    #[must_use]
    pub const fn disposition(&self) -> ResumeAttemptExecutionDisposition {
        self.disposition
    }

    /// Validates that this response answers every field of one exact request.
    ///
    /// # Errors
    ///
    /// Returns an error when an echoed identity or request digest differs.
    pub fn validate_for(
        &self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.assignment == request.assignment()
            && self.daemon_epoch == request.daemon_epoch()
            && self.attempt == request.attempt()
            && self.prior_execution == request.prior_execution()
            && self.checkpoint == request.checkpoint()
            && self.request_digest == request.request_digest()
        {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "resume attempt execution response does not match request",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "resume-attempt-execution-response-encoded-bytes")
    }

    /// Decodes and binds a response to one exact resume request.
    ///
    /// # Errors
    ///
    /// Returns an ordinary strict-decoding error or a cross-request mismatch.
    pub fn from_canonical_bytes_for(
        request: &ResumeAttemptExecutionRequest,
        bytes: &[u8],
    ) -> Result<Self, CampaignCodecError> {
        let response = Self::from_canonical_bytes(bytes)?;
        response.validate_for(request)?;
        Ok(response)
    }
}

impl Canonical for ResumeAttemptExecutionResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.assignment.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.attempt.encode(encoder);
        self.prior_execution.encode(encoder);
        self.checkpoint.encode(encoder);
        self.request_digest.encode(encoder);
        self.disposition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            assignment: AssignmentId::decode(decoder)?,
            daemon_epoch: DaemonEpoch::decode(decoder)?,
            attempt: AttemptId::decode(decoder)?,
            prior_execution: ExecutionId::decode(decoder)?,
            checkpoint: ExactCheckpointId::decode(decoder)?,
            request_digest: CampaignHash::decode(decoder)?,
            disposition: ResumeAttemptExecutionDisposition::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "resume-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Strict idempotent exact-checkpoint request for one execution incarnation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointAttemptExecutionRequest {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    lineage: CampaignLineageId,
    attempt: AttemptId,
    execution: ExecutionId,
    execution_basis: CampaignHash,
}

impl CheckpointAttemptExecutionRequest {
    /// Builds a checkpoint request from the exact accepted assignment basis.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        assignment: &SubmitAttemptRequest,
        execution: ExecutionId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            execution,
            execution_basis: assignment.execution_basis_digest(),
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "checkpoint-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Returns the daemon incarnation that accepted the execution.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the exact compatibility lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the local execution incarnation to pause.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the assignment-neutral execution-contract digest.
    #[must_use]
    pub const fn execution_basis(&self) -> CampaignHash {
        self.execution_basis
    }

    /// Returns a domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign.checkpoint-attempt-execution-request.v2",
            &self.canonical_bytes(),
        )
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "checkpoint-attempt-execution-request-encoded-bytes")
    }
}

impl Canonical for CheckpointAttemptExecutionRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.lineage.encode(encoder);
        self.attempt.encode(encoder);
        self.execution.encode(encoder);
        self.execution_basis.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: DaemonEpoch::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            attempt: AttemptId::decode(decoder)?,
            execution: ExecutionId::decode(decoder)?,
            execution_basis: CampaignHash::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "checkpoint-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }
}

/// Idempotent outcome of requesting one exact local checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAttemptExecutionDisposition {
    /// This call durably latched the checkpoint request.
    Requested,
    /// The same execution had already latched a checkpoint request.
    AlreadyRequested,
    /// Immutable checkpoint publication is in progress under a durable root.
    Publishing {
        /// Exact checkpoint root retained before publication began.
        checkpoint: ExactCheckpointId,
    },
    /// The execution is paused at one complete durable exact checkpoint.
    Paused {
        /// Complete exact checkpoint root available to the coordinator.
        checkpoint: ExactCheckpointId,
    },
    /// Canonical completion won before the checkpoint request.
    AlreadyCompleted {
        /// Published immutable observation identity.
        observation: ObservationId,
    },
    /// Durable cancellation won before the checkpoint request.
    AlreadyCanceled,
    /// The named execution is not the current attempt incarnation.
    NotCurrent,
}

impl Canonical for CheckpointAttemptExecutionDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Requested => encoder.u8(0),
            Self::AlreadyRequested => encoder.u8(1),
            Self::Publishing { checkpoint } => {
                encoder.u8(2);
                checkpoint.encode(encoder);
            }
            Self::Paused { checkpoint } => {
                encoder.u8(3);
                checkpoint.encode(encoder);
            }
            Self::AlreadyCompleted { observation } => {
                encoder.u8(4);
                observation.encode(encoder);
            }
            Self::AlreadyCanceled => encoder.u8(5),
            Self::NotCurrent => encoder.u8(6),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Requested),
            1 => Ok(Self::AlreadyRequested),
            2 => Ok(Self::Publishing {
                checkpoint: ExactCheckpointId::decode(decoder)?,
            }),
            3 => Ok(Self::Paused {
                checkpoint: ExactCheckpointId::decode(decoder)?,
            }),
            4 => Ok(Self::AlreadyCompleted {
                observation: ObservationId::decode(decoder)?,
            }),
            5 => Ok(Self::AlreadyCanceled),
            6 => Ok(Self::NotCurrent),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "checkpoint-attempt-execution-disposition",
                tag,
            }),
        }
    }
}

/// Strict response bound to one exact checkpoint request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointAttemptExecutionResponse {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    attempt: AttemptId,
    execution: ExecutionId,
    request_digest: CampaignHash,
    disposition: CheckpointAttemptExecutionDisposition,
}

impl CheckpointAttemptExecutionResponse {
    /// Builds one response that cannot be replayed across another execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        request: &CheckpointAttemptExecutionRequest,
        disposition: CheckpointAttemptExecutionDisposition,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            execution: request.execution(),
            request_digest: request.request_digest(),
            disposition,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "checkpoint-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the daemon incarnation copied from the request.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the semantic attempt copied from the request.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the local execution copied from the request.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the digest of the complete request this response answers.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the executor's stable checkpoint-request outcome.
    #[must_use]
    pub const fn disposition(&self) -> CheckpointAttemptExecutionDisposition {
        self.disposition
    }

    /// Validates that this response answers every field of one exact request.
    ///
    /// # Errors
    ///
    /// Returns an error when any echoed identity or request digest differs.
    pub fn validate_for(
        &self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.daemon_epoch == request.daemon_epoch()
            && self.attempt == request.attempt()
            && self.execution == request.execution()
            && self.request_digest == request.request_digest()
        {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "checkpoint attempt execution response does not match request",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "checkpoint-attempt-execution-response-encoded-bytes")
    }

    /// Decodes and binds a response to one exact checkpoint request.
    ///
    /// # Errors
    ///
    /// Returns an ordinary strict-decoding error or a cross-request mismatch.
    pub fn from_canonical_bytes_for(
        request: &CheckpointAttemptExecutionRequest,
        bytes: &[u8],
    ) -> Result<Self, CampaignCodecError> {
        let response = Self::from_canonical_bytes(bytes)?;
        response.validate_for(request)?;
        Ok(response)
    }
}

impl Canonical for CheckpointAttemptExecutionResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.attempt.encode(encoder);
        self.execution.encode(encoder);
        self.request_digest.encode(encoder);
        self.disposition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: DaemonEpoch::decode(decoder)?,
            attempt: AttemptId::decode(decoder)?,
            execution: ExecutionId::decode(decoder)?,
            request_digest: CampaignHash::decode(decoder)?,
            disposition: CheckpointAttemptExecutionDisposition::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "checkpoint-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Strict idempotent cancellation request for one exact execution incarnation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelAttemptExecutionRequest {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    lineage: CampaignLineageId,
    attempt: AttemptId,
    execution: ExecutionId,
    execution_basis: CampaignHash,
}

impl CancelAttemptExecutionRequest {
    /// Builds a cancellation request from the exact accepted assignment basis.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        assignment: &SubmitAttemptRequest,
        execution: ExecutionId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            execution,
            execution_basis: assignment.execution_basis_digest(),
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "cancel-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Returns the daemon incarnation that accepted the execution.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the exact compatibility lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the local execution incarnation to cancel.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the assignment-neutral execution-contract digest.
    #[must_use]
    pub const fn execution_basis(&self) -> CampaignHash {
        self.execution_basis
    }

    /// Returns a domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign.cancel-attempt-execution-request.v2",
            &self.canonical_bytes(),
        )
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "cancel-attempt-execution-request-encoded-bytes")
    }
}

impl Canonical for CancelAttemptExecutionRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.lineage.encode(encoder);
        self.attempt.encode(encoder);
        self.execution.encode(encoder);
        self.execution_basis.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let request = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: DaemonEpoch::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            attempt: AttemptId::decode(decoder)?,
            execution: ExecutionId::decode(decoder)?,
            execution_basis: CampaignHash::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "cancel-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }
}

/// Idempotent outcome of canceling one exact execution incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelAttemptExecutionDisposition {
    /// Cancellation became durable for the named execution.
    Canceled,
    /// The exact execution was already durably canceled.
    AlreadyCanceled,
    /// Canonical completion won before cancellation.
    AlreadyCompleted {
        /// Published immutable observation identity.
        observation: ObservationId,
    },
    /// The named execution is not the current incarnation of this attempt.
    NotCurrent,
}

impl Canonical for CancelAttemptExecutionDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Canceled => encoder.u8(0),
            Self::AlreadyCanceled => encoder.u8(1),
            Self::AlreadyCompleted { observation } => {
                encoder.u8(2);
                observation.encode(encoder);
            }
            Self::NotCurrent => encoder.u8(3),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Canceled),
            1 => Ok(Self::AlreadyCanceled),
            2 => Ok(Self::AlreadyCompleted {
                observation: ObservationId::decode(decoder)?,
            }),
            3 => Ok(Self::NotCurrent),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "cancel-attempt-execution-disposition",
                tag,
            }),
        }
    }
}

/// Strict response bound to one exact cancellation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelAttemptExecutionResponse {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    attempt: AttemptId,
    execution: ExecutionId,
    request_digest: CampaignHash,
    disposition: CancelAttemptExecutionDisposition,
}

impl CancelAttemptExecutionResponse {
    /// Builds one response that cannot be replayed across another execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds 4 KiB.
    pub fn new(
        request: &CancelAttemptExecutionRequest,
        disposition: CancelAttemptExecutionDisposition,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            execution: request.execution(),
            request_digest: request.request_digest(),
            disposition,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "cancel-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the daemon incarnation copied from the request.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the semantic attempt copied from the request.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the local execution incarnation copied from the request.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the digest of the complete request this response answers.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the executor's stable cancellation outcome.
    #[must_use]
    pub const fn disposition(&self) -> CancelAttemptExecutionDisposition {
        self.disposition
    }

    /// Validates that this response answers every field of one exact request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when the response belongs
    /// to another cancellation basis.
    pub fn validate_for(
        &self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.daemon_epoch == request.daemon_epoch()
            && self.attempt == request.attempt()
            && self.execution == request.execution()
            && self.request_digest == request.request_digest()
        {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "cancel attempt execution response does not match request",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_executor_message(bytes, "cancel-attempt-execution-response-encoded-bytes")
    }

    /// Decodes a response and binds it to one exact cancellation request.
    ///
    /// # Errors
    ///
    /// Returns an error for strict decoding failure or a response for another
    /// request basis.
    pub fn from_canonical_bytes_for(
        request: &CancelAttemptExecutionRequest,
        bytes: &[u8],
    ) -> Result<Self, CampaignCodecError> {
        let response = Self::from_canonical_bytes(bytes)?;
        response.validate_for(request)?;
        Ok(response)
    }
}

impl Canonical for CancelAttemptExecutionResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.attempt.encode(encoder);
        self.execution.encode(encoder);
        self.request_digest.encode(encoder);
        self.disposition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_executor_message_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: EXECUTOR_MESSAGE_SCHEMA_VERSION,
            daemon_epoch: DaemonEpoch::decode(decoder)?,
            attempt: AttemptId::decode(decoder)?,
            execution: ExecutionId::decode(decoder)?,
            request_digest: CampaignHash::decode(decoder)?,
            disposition: CancelAttemptExecutionDisposition::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "cancel-attempt-execution-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Implementor-facing transport-neutral executor assignment interface.
///
/// A loopback RPC adapter must strictly decode the same
/// [`SubmitAttemptRequest`] bytes and return the same [`SubmitAttemptResponse`]
/// vocabulary. Implementations own local placement and execution but receive no
/// mutable campaign-ref capability. Coordinators call services only through
/// [`ExecutorClient`], which applies the same exact-response validation to
/// direct and RPC implementations.
pub trait ExecutorService {
    /// Implementation-specific transport or local service failure.
    type Error;

    /// Submits one idempotent local attempt assignment.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when the service could not
    /// produce a protocol response. Ordinary incompatibility, backpressure,
    /// unavailable input, and authorization failures are successful protocol
    /// responses in [`SubmitAttemptDisposition::Rejected`].
    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error>;
}

/// Read-only status extension implemented by direct and RPC executors.
pub trait ExecutorStatusService: ExecutorService {
    /// Returns the current state of one exact execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be read or a protocol response cannot be constructed.
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error>;
}

/// Idempotent cancellation extension implemented by direct and RPC executors.
pub trait ExecutorControlService: ExecutorStatusService {
    /// Requests a durable exact checkpoint of one execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be changed or a protocol response cannot be constructed.
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error>;

    /// Requests cancellation of one exact execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be changed or a protocol response cannot be constructed.
    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error>;
}

/// Coordinator-facing checked client over one direct or RPC executor service.
pub struct ExecutorClient<S> {
    service: S,
}

impl<S> ExecutorClient<S> {
    /// Wraps one implementor-facing executor service.
    #[must_use]
    pub const fn new(service: S) -> Self {
        Self { service }
    }

    /// Returns the wrapped service after coordinator ownership ends.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.service
    }
}

impl<S: ExecutorService> ExecutorClient<S> {
    /// Submits an assignment and validates the exact response basis.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] when the implementation cannot
    /// produce a protocol response, or [`ExecutorClientError::InvalidResponse`]
    /// when it returns a response for any other canonical request.
    pub fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .submit_attempt(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }
}

impl<S: ExecutorStatusService> ExecutorClient<S> {
    /// Reads and validates one exact local execution status response.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .get_attempt_execution(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }
}

impl<S: ExecutorControlService> ExecutorClient<S> {
    /// Requests and validates one exact local checkpoint operation.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .checkpoint_attempt_execution(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }

    /// Cancels and validates one exact local execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .cancel_attempt_execution(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }
}

impl<S: crate::executor_capability::ExecutorCapabilityService> ExecutorClient<S> {
    /// Fetches immutable capabilities and the current daemon epoch.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] when the implementation cannot
    /// produce a description.
    pub fn describe_executor(
        &mut self,
    ) -> Result<crate::ExecutorDescription, ExecutorClientError<S::Error>> {
        self.service
            .describe_executor()
            .map_err(ExecutorClientError::Service)
    }

    /// Fetches and validates the next volatile capacity report.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] when the implementation cannot
    /// produce a report, or [`ExecutorClientError::InvalidResponse`] when the
    /// report belongs to another daemon/capability set, fails to advance the
    /// cursor, exceeds immutable ceilings, or advertises unsupported locality.
    pub fn watch_capacity(
        &mut self,
        description: &crate::ExecutorDescription,
        after_sequence: Option<u64>,
    ) -> Result<crate::ExecutorCapacityReport, ExecutorClientError<S::Error>> {
        let request = crate::WatchExecutorCapacityRequest::new(description, after_sequence)
            .map_err(ExecutorClientError::InvalidResponse)?;
        let report = self
            .service
            .watch_capacity(&request)
            .map_err(ExecutorClientError::Service)?;
        report
            .validate_for(description, after_sequence)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(report)
    }
}

/// Failure from the coordinator-facing checked executor client.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecutorClientError<E> {
    /// The direct or RPC implementation failed to produce a response.
    #[error("executor service failed: {0}")]
    Service(E),
    /// The implementation returned a malformed cross-request response.
    #[error(transparent)]
    InvalidResponse(CampaignCodecError),
}

fn decode_executor_message<T: Canonical>(
    bytes: &[u8],
    limit: &'static str,
) -> Result<T, CampaignCodecError> {
    if bytes.len() > MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES {
        return Err(CampaignCodecError::LimitExceeded { limit });
    }
    codec::decode(bytes)
}

const fn require_executor_message_version(version: u32) -> Result<(), CampaignCodecError> {
    if version == EXECUTOR_MESSAGE_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version",
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::CampaignHash;
    use crucible_cas::content_store::{ContentId, ObjectKind};

    fn fixture_request() -> SubmitAttemptRequest {
        SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x11; 16]).expect("assignment"),
            DaemonEpoch::from_bytes([0x22; 16]).expect("daemon epoch"),
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"executor-lineage",
            ))
            .expect("lineage"),
            AttemptId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"executor-attempt",
            ))
            .expect("attempt"),
            AttemptResourceLimits::new(4, 8 * 1024 * 1024 * 1024, 32 * 1024 * 1024, 500_000)
                .expect("resource limits"),
            ExecutionRetentionIntent::RetainOnFailure,
        )
        .expect("submit attempt request")
    }

    #[test]
    fn submit_attempt_messages_are_strict_bounded_and_request_bound() {
        let request = fixture_request();
        let request_bytes = request.canonical_bytes();
        assert_eq!(
            SubmitAttemptRequest::from_canonical_bytes(&request_bytes).expect("request decode"),
            request
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.submit-attempt-request-vector.v2",
                &request_bytes
            )
            .to_hex(),
            "0e799560b178b6f6d2a8fe1822e141ac55f436b3600bed1e5fa07ce27aaf5e69"
        );

        let response = SubmitAttemptResponse::new(
            &request,
            SubmitAttemptDisposition::Accepted {
                execution: ExecutionId::from_bytes([0x33; 16]).expect("execution"),
            },
        )
        .expect("submit attempt response");
        let response_bytes = response.canonical_bytes();
        assert_eq!(
            SubmitAttemptResponse::from_canonical_bytes(&response_bytes).expect("response decode"),
            response
        );
        assert_eq!(
            SubmitAttemptResponse::from_canonical_bytes_for(&request, &response_bytes)
                .expect("request-bound response decode"),
            response
        );
        assert!(response.matches_request(&request));
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.submit-attempt-response-vector.v2",
                &response_bytes,
            )
            .to_hex(),
            "9bf8c3a08b4637c75bca9ff467de181a98ea2828c5e302ed0ed5552dfc60f698"
        );

        let different = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x44; 16]).expect("different assignment"),
            request.daemon_epoch(),
            request.lineage(),
            request.attempt(),
            request.resources(),
            request.retention(),
        )
        .expect("different request");
        assert!(!response.matches_request(&different));
        assert_eq!(
            request.execution_basis_digest(),
            different.execution_basis_digest()
        );

        let changed_resources = SubmitAttemptRequest::new(
            request.assignment(),
            request.daemon_epoch(),
            request.lineage(),
            request.attempt(),
            AttemptResourceLimits::new(2, 4 * 1024 * 1024, 0, 100).expect("changed resources"),
            request.retention(),
        )
        .expect("changed-resource request");
        assert_ne!(
            request.execution_basis_digest(),
            changed_resources.execution_basis_digest()
        );
        assert!(!response.matches_request(&changed_resources));
        assert_eq!(
            SubmitAttemptResponse::from_canonical_bytes_for(&changed_resources, &response_bytes),
            Err(CampaignCodecError::InvalidValue {
                reason: "submit attempt response does not match request"
            })
        );

        let mut unsupported_version = request_bytes.clone();
        unsupported_version[..4].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            SubmitAttemptRequest::from_canonical_bytes(&unsupported_version),
            Err(CampaignCodecError::InvalidValue {
                reason: "unsupported executor component-message schema version"
            })
        );
        let mut zero_assignment = request_bytes.clone();
        zero_assignment[4..20].fill(0);
        assert_eq!(
            SubmitAttemptRequest::from_canonical_bytes(&zero_assignment),
            Err(CampaignCodecError::InvalidValue {
                reason: "executor assignment identity is all zero"
            })
        );
        let mut unknown_retention = request_bytes.clone();
        *unknown_retention.last_mut().expect("retention tag") = 0xff;
        assert_eq!(
            SubmitAttemptRequest::from_canonical_bytes(&unknown_retention),
            Err(CampaignCodecError::UnknownTag {
                kind: "execution-retention-intent",
                tag: 0xff
            })
        );
        assert_eq!(
            SubmitAttemptRequest::from_canonical_bytes(&request_bytes[..request_bytes.len() - 1]),
            Err(CampaignCodecError::Truncated)
        );
    }

    #[test]
    fn get_attempt_execution_messages_are_strict_and_exact_request_bound() {
        let assignment = fixture_request();
        let execution = ExecutionId::from_bytes([0x37; 16]).expect("execution");
        let request =
            GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
        let request_bytes = request.canonical_bytes();
        assert_eq!(
            GetAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
                .expect("status request decode"),
            request
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.get-attempt-execution-request-vector.v2",
                &request_bytes,
            )
            .to_hex(),
            "ef1b1a52e9f1bce2ad5f56a3d038c2a48cbd7c3e1809e0cd999edb4f1f64d5f3"
        );

        let observation = ObservationId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"executor-status-observation",
        ))
        .expect("observation");
        let response = GetAttemptExecutionResponse::new(
            &request,
            GetAttemptExecutionDisposition::Completed { observation },
        )
        .expect("status response");
        let response_bytes = response.canonical_bytes();
        assert_eq!(
            GetAttemptExecutionResponse::from_canonical_bytes_for(&request, &response_bytes)
                .expect("status response decode"),
            response
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.get-attempt-execution-response-vector.v2",
                &response_bytes,
            )
            .to_hex(),
            "52a161cda68e3b020734a39e141906ba8b707768a93964e597884cd1777b03fb"
        );

        let other_execution = ExecutionId::from_bytes([0x38; 16]).expect("other execution");
        let other = GetAttemptExecutionRequest::new(&assignment, other_execution)
            .expect("other status request");
        assert_eq!(
            GetAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
            Err(CampaignCodecError::InvalidValue {
                reason: "get attempt execution response does not match request"
            })
        );

        let mut unknown_disposition =
            GetAttemptExecutionResponse::new(&request, GetAttemptExecutionDisposition::Canceled)
                .expect("canceled status response")
                .canonical_bytes();
        *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
        assert_eq!(
            GetAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
            Err(CampaignCodecError::UnknownTag {
                kind: "get-attempt-execution-disposition",
                tag: 0xff
            })
        );
    }

    #[test]
    fn resume_attempt_execution_messages_bind_the_exact_paused_root() {
        let assignment = fixture_request();
        let prior_execution = ExecutionId::from_bytes([0x3d; 16]).expect("prior execution");
        let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            2,
            b"executor-resume-checkpoint-root",
        ))
        .expect("checkpoint root");
        let request = ResumeAttemptExecutionRequest::new(&assignment, prior_execution, checkpoint)
            .expect("resume request");
        let request_bytes = request.canonical_bytes();
        assert_eq!(
            ResumeAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
                .expect("resume request decode"),
            request
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.resume-attempt-execution-request-vector.v2",
                &request_bytes,
            )
            .to_hex(),
            "5ac0a6c32480b9b337a39f9b4768db543de765dbe7de44099066565ee6b4a24c"
        );

        let execution = ExecutionId::from_bytes([0x3e; 16]).expect("resumed execution");
        let response = ResumeAttemptExecutionResponse::new(
            &request,
            ResumeAttemptExecutionDisposition::Accepted { execution },
        )
        .expect("resume response");
        let response_bytes = response.canonical_bytes();
        assert_eq!(
            ResumeAttemptExecutionResponse::from_canonical_bytes_for(&request, &response_bytes)
                .expect("resume response decode"),
            response
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.resume-attempt-execution-response-vector.v2",
                &response_bytes,
            )
            .to_hex(),
            "fda096f0dfd2bccd0d8cc060fb90eed72e0e965c62e2f3c597113663a73c34e4"
        );

        let other_checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            2,
            b"other-resume-checkpoint-root",
        ))
        .expect("other checkpoint root");
        let other =
            ResumeAttemptExecutionRequest::new(&assignment, prior_execution, other_checkpoint)
                .expect("other resume request");
        assert_eq!(
            ResumeAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
            Err(CampaignCodecError::InvalidValue {
                reason: "resume attempt execution response does not match request"
            })
        );

        let mut unknown_disposition = ResumeAttemptExecutionResponse::new(
            &request,
            ResumeAttemptExecutionDisposition::AlreadyCanceled,
        )
        .expect("already canceled response")
        .canonical_bytes();
        *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
        assert_eq!(
            ResumeAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
            Err(CampaignCodecError::UnknownTag {
                kind: "resume-attempt-execution-disposition",
                tag: 0xff
            })
        );
    }

    #[test]
    fn cancel_attempt_execution_messages_are_strict_and_exact_request_bound() {
        let assignment = fixture_request();
        let execution = ExecutionId::from_bytes([0x39; 16]).expect("execution");
        let request = CancelAttemptExecutionRequest::new(&assignment, execution)
            .expect("cancellation request");
        let request_bytes = request.canonical_bytes();
        assert_eq!(
            CancelAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
                .expect("cancellation request decode"),
            request
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.cancel-attempt-execution-request-vector.v2",
                &request_bytes,
            )
            .to_hex(),
            "b3ca93e0286e939ba61708de078d38588c5e9298611b4c30482453ee649e367e"
        );

        let observation = ObservationId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"executor-cancellation-observation",
        ))
        .expect("observation");
        let response = CancelAttemptExecutionResponse::new(
            &request,
            CancelAttemptExecutionDisposition::AlreadyCompleted { observation },
        )
        .expect("cancellation response");
        let response_bytes = response.canonical_bytes();
        assert_eq!(
            CancelAttemptExecutionResponse::from_canonical_bytes_for(&request, &response_bytes)
                .expect("cancellation response decode"),
            response
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.cancel-attempt-execution-response-vector.v2",
                &response_bytes,
            )
            .to_hex(),
            "fd77a046700eedf86394ce59e290a5396105a04b9f1fe224d767eaa79d119fac"
        );

        let other = CancelAttemptExecutionRequest::new(
            &assignment,
            ExecutionId::from_bytes([0x3a; 16]).expect("other execution"),
        )
        .expect("other cancellation request");
        assert_eq!(
            CancelAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
            Err(CampaignCodecError::InvalidValue {
                reason: "cancel attempt execution response does not match request"
            })
        );

        let mut unknown_disposition = CancelAttemptExecutionResponse::new(
            &request,
            CancelAttemptExecutionDisposition::AlreadyCanceled,
        )
        .expect("already canceled response")
        .canonical_bytes();
        *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
        assert_eq!(
            CancelAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
            Err(CampaignCodecError::UnknownTag {
                kind: "cancel-attempt-execution-disposition",
                tag: 0xff
            })
        );
    }

    #[test]
    fn checkpoint_attempt_execution_messages_bind_the_exact_root_and_request() {
        let assignment = fixture_request();
        let execution = ExecutionId::from_bytes([0x3b; 16]).expect("execution");
        let request = CheckpointAttemptExecutionRequest::new(&assignment, execution)
            .expect("checkpoint request");
        let request_bytes = request.canonical_bytes();
        assert_eq!(
            CheckpointAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
                .expect("checkpoint request decode"),
            request
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.checkpoint-attempt-execution-request-vector.v2",
                &request_bytes,
            )
            .to_hex(),
            "2f1dfdb45541a18fd2b09e3033e982af8e110c8ebd443bc06823751c45cc4a2e"
        );

        let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            2,
            b"executor-checkpoint-root",
        ))
        .expect("checkpoint root");
        let response = CheckpointAttemptExecutionResponse::new(
            &request,
            CheckpointAttemptExecutionDisposition::Paused { checkpoint },
        )
        .expect("checkpoint response");
        let response_bytes = response.canonical_bytes();
        assert_eq!(
            CheckpointAttemptExecutionResponse::from_canonical_bytes_for(
                &request,
                &response_bytes,
            )
            .expect("checkpoint response decode"),
            response
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.checkpoint-attempt-execution-response-vector.v2",
                &response_bytes,
            )
            .to_hex(),
            "ff859c55efc7e56f7e81c6dd969fbe068a0c583e346a37023531a81a8a61877d"
        );

        let other = CheckpointAttemptExecutionRequest::new(
            &assignment,
            ExecutionId::from_bytes([0x3c; 16]).expect("other execution"),
        )
        .expect("other checkpoint request");
        assert_eq!(
            CheckpointAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
            Err(CampaignCodecError::InvalidValue {
                reason: "checkpoint attempt execution response does not match request"
            })
        );

        let mut unknown_disposition = CheckpointAttemptExecutionResponse::new(
            &request,
            CheckpointAttemptExecutionDisposition::AlreadyRequested,
        )
        .expect("already requested response")
        .canonical_bytes();
        *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
        assert_eq!(
            CheckpointAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
            Err(CampaignCodecError::UnknownTag {
                kind: "checkpoint-attempt-execution-disposition",
                tag: 0xff
            })
        );
    }

    #[test]
    fn executor_service_uses_rejections_as_protocol_outcomes() {
        struct RejectingExecutor;

        impl ExecutorService for RejectingExecutor {
            type Error = std::convert::Infallible;

            fn submit_attempt(
                &mut self,
                request: &SubmitAttemptRequest,
            ) -> Result<SubmitAttemptResponse, Self::Error> {
                Ok(SubmitAttemptResponse::new(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Backpressure,
                    },
                )
                .expect("bounded rejection"))
            }
        }

        let request = fixture_request();
        let response = ExecutorClient::new(RejectingExecutor)
            .submit_attempt(&request)
            .expect("checked infallible service");
        assert!(response.matches_request(&request));
        assert_eq!(
            response.disposition(),
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::Backpressure
            }
        );
        assert_eq!(
            AttemptResourceLimits::new(0, 1, 0, 1),
            Err(CampaignCodecError::InvalidValue {
                reason: "executor resource limit has zero vcpus"
            })
        );
        assert!(ExecutorRejection::Backpressure.retry_with_new_assignment());
        assert!(!ExecutorRejection::ConflictingAssignment.retry_with_new_assignment());
    }

    #[test]
    fn checked_client_rejects_cross_request_replay_and_ledger_is_exact() {
        struct ReplayingExecutor {
            prior: SubmitAttemptResponse,
        }

        impl ExecutorService for ReplayingExecutor {
            type Error = std::convert::Infallible;

            fn submit_attempt(
                &mut self,
                _request: &SubmitAttemptRequest,
            ) -> Result<SubmitAttemptResponse, Self::Error> {
                Ok(self.prior.clone())
            }
        }

        let prior_request = fixture_request();
        let prior_response = SubmitAttemptResponse::new(
            &prior_request,
            SubmitAttemptDisposition::Accepted {
                execution: ExecutionId::from_bytes([0x55; 16]).expect("prior execution"),
            },
        )
        .expect("prior response");
        let changed_request = SubmitAttemptRequest::new(
            prior_request.assignment(),
            prior_request.daemon_epoch(),
            prior_request.lineage(),
            prior_request.attempt(),
            AttemptResourceLimits::new(8, 16 * 1024 * 1024, 0, 1_000).expect("changed limits"),
            prior_request.retention(),
        )
        .expect("changed request");
        assert_eq!(
            ExecutorClient::new(ReplayingExecutor {
                prior: prior_response,
            })
            .submit_attempt(&changed_request),
            Err(ExecutorClientError::InvalidResponse(
                CampaignCodecError::InvalidValue {
                    reason: "submit attempt response does not match request"
                }
            ))
        );

        #[derive(Default)]
        struct ExactLedger {
            accepted: Option<(AssignmentId, CampaignHash, SubmitAttemptResponse)>,
        }

        impl ExecutorService for ExactLedger {
            type Error = std::convert::Infallible;

            fn submit_attempt(
                &mut self,
                request: &SubmitAttemptRequest,
            ) -> Result<SubmitAttemptResponse, Self::Error> {
                if let Some((assignment, digest, response)) = &self.accepted
                    && *assignment == request.assignment()
                {
                    return if *digest == request.request_digest() {
                        Ok(response.clone())
                    } else {
                        Ok(SubmitAttemptResponse::new(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::ConflictingAssignment,
                            },
                        )
                        .expect("bounded conflict"))
                    };
                }
                let response = SubmitAttemptResponse::new(
                    request,
                    SubmitAttemptDisposition::Accepted {
                        execution: ExecutionId::from_bytes([0x66; 16]).expect("execution"),
                    },
                )
                .expect("bounded acceptance");
                self.accepted = Some((
                    request.assignment(),
                    request.request_digest(),
                    response.clone(),
                ));
                Ok(response)
            }
        }

        let mut ledger = ExecutorClient::new(ExactLedger::default());
        let accepted = ledger
            .submit_attempt(&prior_request)
            .expect("initial exact assignment");
        assert_eq!(
            ledger
                .submit_attempt(&prior_request)
                .expect("exact assignment replay"),
            accepted
        );
        assert_eq!(
            ledger
                .submit_attempt(&changed_request)
                .expect("stable assignment conflict")
                .disposition(),
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::ConflictingAssignment
            }
        );
    }
}
