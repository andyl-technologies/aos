//! Transport-neutral local executor assignment contracts.
//!
//! The coordinator submits one immutable semantic [`AttemptId`] together with
//! bounded operational ceilings. The strict component-message formats are:
//!
//! ```text
//! SubmitAttemptRequestV2 = version | assignment | daemon-epoch | lineage |
//!                          attempt | resource-limits | retention-intent
//! SubmitAttemptRequestV3 = version | assignment | daemon-epoch | lineage |
//!                          attempt | resource-limits | retention-intent |
//!                          start-mode
//! SubmitAttemptRequestV4 = version | assignment | daemon-epoch | lineage |
//!                          attempt | resource-limits | retention-intent |
//!                          scoped-start-mode
//! SubmitAttemptResponseV2/V3 = version | assignment | daemon-epoch | attempt |
//!                              request-digest | disposition
//! SubmitAttemptResponseV4 = version | assignment | daemon-epoch | attempt |
//!                           request-digest | completed-disposition |
//!                           finding-candidate
//! GetAttemptExecutionRequestV2 = version | daemon-epoch | lineage | attempt |
//!                                execution | execution-basis-digest
//! GetAttemptExecutionRequestV3 = version | daemon-epoch | lineage | attempt |
//!                                execution | execution-basis-digest | scope
//! GetAttemptExecutionResponseV2/V3 = version | daemon-epoch | attempt |
//!                                    execution | request-digest | disposition
//! GetAttemptExecutionResponseV4 = version | daemon-epoch | attempt | execution |
//!                                 request-digest | completed-disposition |
//!                                 finding-candidate
//! ResumeAttemptExecutionRequestV2 = version | assignment | daemon-epoch |
//!                                    lineage | attempt | prior-execution |
//!                                    checkpoint | resource-limits |
//!                                    retention-intent
//! ResumeAttemptExecutionRequestV3 = version | assignment | daemon-epoch |
//!                                    lineage | attempt | prior-execution |
//!                                    checkpoint | resource-limits |
//!                                    retention-intent | prior-start-mode
//! ResumeAttemptExecutionResponseV2/V3 = version | assignment | daemon-epoch |
//!                                        attempt | prior-execution | checkpoint |
//!                                        request-digest | disposition
//! ResumeAttemptExecutionResponseV4 = version | assignment | daemon-epoch |
//!                                     attempt | prior-execution | checkpoint |
//!                                     request-digest | completed-disposition |
//!                                     finding-candidate
//! CheckpointAttemptExecutionRequestV2 = version | daemon-epoch | lineage |
//!                                       attempt | execution |
//!                                       execution-basis-digest
//! CheckpointAttemptExecutionRequestV3 = version | daemon-epoch | lineage |
//!                                       attempt | execution |
//!                                       execution-basis-digest | scope
//! CheckpointAttemptExecutionResponseV2 = version | daemon-epoch | attempt |
//!                                        execution | request-digest |
//!                                        disposition
//! CheckpointAttemptExecutionResponseV4 = version | daemon-epoch | attempt |
//!                                        execution | request-digest |
//!                                        completed-disposition | finding-candidate
//! CancelAttemptExecutionRequestV2 = version | daemon-epoch | lineage | attempt |
//!                                   execution | execution-basis-digest
//! CancelAttemptExecutionRequestV3 = version | daemon-epoch | lineage | attempt |
//!                                   execution | execution-basis-digest | scope
//! CancelAttemptExecutionResponseV2 = version | daemon-epoch | attempt | execution |
//!                                    request-digest | disposition
//! CancelAttemptExecutionResponseV4 = version | daemon-epoch | attempt | execution |
//!                                    request-digest | completed-disposition |
//!                                    finding-candidate
//! ```
//!
//! Version 4 is valid only for a completed disposition with one candidate.
//! Decoding a version 2 or version 3 response yields no finding candidate.
//!
//! Assignment, execution, epoch, resource, and retention fields are local
//! execution metadata. They never enter the identity of an attempt,
//! configuration, observation, or finding.

use std::collections::BTreeMap;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::validate_identifier;
use crate::{
    AttemptId, CampaignCodecError, CampaignFactId, CampaignHash, CampaignLineage,
    CampaignLineageId, ConfigurationArtifactId, ExactCheckpointId, FindingCandidateBundleId,
    ObservationId,
};

const EXECUTOR_MESSAGE_SCHEMA_VERSION: u32 = 2;
const MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION: u32 = 3;
const SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION: u32 = 4;
const SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION: u32 = 3;
const RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION: u32 = 3;
const SUBMIT_ATTEMPT_RESPONSE_SCHEMA_VERSION: u32 = 3;
const GET_ATTEMPT_EXECUTION_RESPONSE_SCHEMA_VERSION: u32 = 3;
const RESUME_ATTEMPT_EXECUTION_RESPONSE_SCHEMA_VERSION: u32 = 3;
const FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION: u32 = 4;

/// Maximum canonical bytes in one executor component message.
pub const MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES: usize = 4 * 1024;

/// Derives the assignment-neutral digest of one local execution contract.
///
/// The digest binds the exact lineage, semantic attempt, resource ceilings,
/// and retention intent. Assignment and daemon-incarnation identities are
/// deliberately excluded so exact retries can share one execution.
#[must_use]
pub fn attempt_execution_basis_digest(
    lineage: CampaignLineageId,
    attempt: AttemptId,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
) -> CampaignHash {
    let mut encoder = Encoder::new();
    lineage.encode(&mut encoder);
    attempt.encode(&mut encoder);
    resources.encode(&mut encoder);
    retention.encode(&mut encoder);
    CampaignHash::derive(
        "crucible.campaign.submit-attempt-execution-basis.v1",
        &encoder.finish(),
    )
}

/// Derives the assignment-neutral digest for an explicit attempt start mode.
///
/// [`AttemptStartMode::Execute`] preserves the version 1 execution-basis
/// digest exactly. Materialized-start capture uses a separate version 2 domain
/// that also authenticates the requested configuration artifact.
#[must_use]
pub fn attempt_execution_basis_digest_for_start_mode(
    lineage: CampaignLineageId,
    attempt: AttemptId,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
    start_mode: AttemptStartMode,
) -> CampaignHash {
    if start_mode == AttemptStartMode::Execute {
        return attempt_execution_basis_digest(lineage, attempt, resources, retention);
    }

    let mut encoder = Encoder::new();
    lineage.encode(&mut encoder);
    attempt.encode(&mut encoder);
    resources.encode(&mut encoder);
    retention.encode(&mut encoder);
    start_mode.encode(&mut encoder);
    CampaignHash::derive(
        "crucible.campaign.submit-attempt-execution-basis.v2",
        &encoder.finish(),
    )
}

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

/// Durable namespace for one operational execution record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttemptExecutionScope {
    /// Ordinary semantic attempt execution and exact-checkpoint continuation.
    #[default]
    Semantic,
    /// Preparatory savepoint capture identified by its immutable request fact.
    SavepointCapture {
        /// Exact campaign fact that requested this operational capture.
        request: CampaignFactId,
    },
}

impl AttemptExecutionScope {
    /// Returns the strict canonical bytes used in durable execution keys.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        codec::encode(&self)
    }

    /// Decodes one strict canonical durable execution scope.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or trailing input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }
}

impl Canonical for AttemptExecutionScope {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Semantic => encoder.u8(0),
            Self::SavepointCapture { request } => {
                encoder.u8(1);
                request.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Semantic),
            1 => Ok(Self::SavepointCapture {
                request: CampaignFactId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-execution-scope",
                tag,
            }),
        }
    }
}

/// Operational behavior requested immediately after start materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptStartMode {
    /// Runs the semantic attempt from its authenticated start configuration.
    Execute,
    /// Captures the exact materialized start before any modeled quantum.
    CaptureMaterializedStart {
        /// Exact configuration artifact the worker must authenticate at start.
        configuration: ConfigurationArtifactId,
    },
    /// Captures a campaign-requested savepoint in its own operational scope.
    SavepointCapture {
        /// Exact campaign fact that requested this operational capture.
        request: CampaignFactId,
        /// Exact configuration artifact the worker must authenticate at start.
        configuration: ConfigurationArtifactId,
    },
}

impl AttemptStartMode {
    /// Returns the durable operational namespace selected by this start mode.
    #[must_use]
    pub const fn execution_scope(self) -> AttemptExecutionScope {
        match self {
            Self::Execute | Self::CaptureMaterializedStart { .. } => {
                AttemptExecutionScope::Semantic
            }
            Self::SavepointCapture { request, .. } => {
                AttemptExecutionScope::SavepointCapture { request }
            }
        }
    }
}

impl Canonical for AttemptStartMode {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Execute => encoder.u8(0),
            Self::CaptureMaterializedStart { configuration } => {
                encoder.u8(1);
                configuration.encode(encoder);
            }
            Self::SavepointCapture {
                request,
                configuration,
            } => {
                encoder.u8(2);
                request.encode(encoder);
                configuration.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Execute),
            1 => Ok(Self::CaptureMaterializedStart {
                configuration: ConfigurationArtifactId::decode(decoder)?,
            }),
            2 => Ok(Self::SavepointCapture {
                request: CampaignFactId::decode(decoder)?,
                configuration: ConfigurationArtifactId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-start-mode",
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
    start_mode: AttemptStartMode,
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
            start_mode: AttemptStartMode::Execute,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "submit-attempt-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Builds an assignment that captures its authenticated materialized start.
    ///
    /// The executor durably requests an exact checkpoint before dispatch. The
    /// worker must authenticate `configuration` against the resolved start
    /// artifact before publishing the checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds its strict
    /// encoded bound.
    pub fn new_capture_materialized_start(
        assignment: AssignmentId,
        daemon_epoch: DaemonEpoch,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        resources: AttemptResourceLimits,
        retention: ExecutionRetentionIntent,
        configuration: ConfigurationArtifactId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION,
            assignment,
            daemon_epoch,
            lineage,
            attempt,
            resources,
            retention,
            start_mode: AttemptStartMode::CaptureMaterializedStart { configuration },
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "submit-attempt-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Builds a campaign savepoint capture in its isolated operational scope.
    ///
    /// The capture request fact is part of both the canonical assignment and
    /// its durable execution scope. This permits the same immutable attempt to
    /// have an ordinary semantic execution without sharing runtime state.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds its strict
    /// encoded bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new_savepoint_capture(
        assignment: AssignmentId,
        daemon_epoch: DaemonEpoch,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        resources: AttemptResourceLimits,
        retention: ExecutionRetentionIntent,
        request: CampaignFactId,
        configuration: ConfigurationArtifactId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION,
            assignment,
            daemon_epoch,
            lineage,
            attempt,
            resources,
            retention,
            start_mode: AttemptStartMode::SavepointCapture {
                request,
                configuration,
            },
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

    /// Returns the requested behavior at the materialized execution start.
    #[must_use]
    pub const fn start_mode(&self) -> AttemptStartMode {
        self.start_mode
    }

    /// Returns the durable operational namespace selected by this assignment.
    #[must_use]
    pub const fn execution_scope(&self) -> AttemptExecutionScope {
        self.start_mode.execution_scope()
    }

    /// Returns the domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        let domain = match self.schema_version {
            EXECUTOR_MESSAGE_SCHEMA_VERSION => "crucible.campaign.submit-attempt-request.v2",
            MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION => {
                "crucible.campaign.submit-attempt-request.v3"
            }
            SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION => {
                "crucible.campaign.submit-attempt-request.v4"
            }
            _ => unreachable!("validated submit request schema"),
        };
        CampaignHash::derive(domain, &self.canonical_bytes())
    }

    /// Returns the assignment-neutral local execution-contract digest.
    ///
    /// The digest binds lineage, attempt, resource ceilings, and retention but
    /// excludes assignment and daemon-epoch identities. Fresh assignments may
    /// share one running or completed execution only when this digest matches.
    #[must_use]
    pub fn execution_basis_digest(&self) -> CampaignHash {
        attempt_execution_basis_digest_for_start_mode(
            self.lineage,
            self.attempt,
            self.resources,
            self.retention,
            self.start_mode,
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
        if self.schema_version == MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION
            || self.schema_version == SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION
        {
            self.start_mode.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        require_submit_attempt_request_version(schema_version)?;
        let assignment = AssignmentId::decode(decoder)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let lineage = CampaignLineageId::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let resources = AttemptResourceLimits::decode(decoder)?;
        let retention = ExecutionRetentionIntent::decode(decoder)?;
        if schema_version == EXECUTOR_MESSAGE_SCHEMA_VERSION {
            return Self::new(
                assignment,
                daemon_epoch,
                lineage,
                attempt,
                resources,
                retention,
            );
        }

        let start_mode = AttemptStartMode::decode(decoder)?;
        match (schema_version, start_mode) {
            (
                MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION,
                AttemptStartMode::CaptureMaterializedStart { configuration },
            ) => Self::new_capture_materialized_start(
                assignment,
                daemon_epoch,
                lineage,
                attempt,
                resources,
                retention,
                configuration,
            ),
            (
                SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION,
                AttemptStartMode::SavepointCapture {
                    request,
                    configuration,
                },
            ) => Self::new_savepoint_capture(
                assignment,
                daemon_epoch,
                lineage,
                attempt,
                resources,
                retention,
                request,
                configuration,
            ),
            (MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION, _) => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "submit attempt request version 3 requires materialized-start capture",
                })
            }
            (SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION, _) => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "submit attempt request version 4 requires savepoint capture",
                })
            }
            _ => unreachable!("validated submit request schema"),
        }
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
    /// A prior non-retryable worker failure durably quarantined the attempt.
    TerminalFailure,
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
            Self::TerminalFailure => 5,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Incompatible),
            1 => Ok(Self::Backpressure),
            2 => Ok(Self::UnavailableInput),
            3 => Ok(Self::Unauthorized),
            4 => Ok(Self::ConflictingAssignment),
            5 => Ok(Self::TerminalFailure),
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

impl SubmitAttemptDisposition {
    const fn is_completed(self) -> bool {
        matches!(self, Self::AlreadyCompleted { .. })
    }

    const fn uses_terminal_failure_schema(self) -> bool {
        matches!(
            self,
            Self::Rejected {
                reason: ExecutorRejection::TerminalFailure
            }
        )
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
    finding_candidate: Option<FindingCandidateBundleId>,
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
        Self::new_with_optional_finding_candidate(request, disposition, None)
    }

    /// Builds a completed response that reports one retained finding candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when `disposition` is not a completed outcome or the
    /// resulting component message exceeds its strict encoded bound.
    pub fn new_with_finding_candidate(
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
        finding_candidate: FindingCandidateBundleId,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_with_optional_finding_candidate(request, disposition, Some(finding_candidate))
    }

    fn new_with_optional_finding_candidate(
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: response_schema_version(
                disposition.is_completed(),
                disposition.uses_terminal_failure_schema(),
                finding_candidate,
            )?,
            assignment: request.assignment,
            daemon_epoch: request.daemon_epoch,
            attempt: request.attempt,
            request_digest: request.request_digest(),
            disposition,
            finding_candidate,
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

    /// Returns the retained candidate published with a completed attempt.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<FindingCandidateBundleId> {
        self.finding_candidate
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
        if let Some(finding_candidate) = self.finding_candidate {
            finding_candidate.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != EXECUTOR_MESSAGE_SCHEMA_VERSION
            && schema_version != SUBMIT_ATTEMPT_RESPONSE_SCHEMA_VERSION
            && schema_version != FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported submit attempt response schema version",
            });
        }
        let assignment = AssignmentId::decode(decoder)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let request_digest = CampaignHash::decode(decoder)?;
        let disposition = SubmitAttemptDisposition::decode(decoder)?;
        let finding_candidate = if schema_version == FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION {
            Some(FindingCandidateBundleId::decode(decoder)?)
        } else {
            None
        };
        let response = Self {
            schema_version,
            assignment,
            daemon_epoch,
            attempt,
            request_digest,
            disposition,
            finding_candidate,
        };
        if response_schema_version(
            response.disposition.is_completed(),
            response.disposition.uses_terminal_failure_schema(),
            response.finding_candidate,
        )? != schema_version
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "submit attempt response schema/disposition mismatch",
            });
        }
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
    scope: AttemptExecutionScope,
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
            schema_version: SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION,
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            execution,
            execution_basis: assignment.execution_basis_digest(),
            scope: assignment.execution_scope(),
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

    /// Returns the exact durable execution namespace being queried.
    #[must_use]
    pub const fn execution_scope(&self) -> AttemptExecutionScope {
        self.scope
    }

    /// Returns a domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        let domain = if self.schema_version == EXECUTOR_MESSAGE_SCHEMA_VERSION {
            "crucible.campaign.get-attempt-execution-request.v2"
        } else {
            "crucible.campaign.get-attempt-execution-request.v3"
        };
        CampaignHash::derive(domain, &self.canonical_bytes())
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
        if self.schema_version == SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION {
            self.scope.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        require_executor_control_request_version(schema_version)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let lineage = CampaignLineageId::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let execution = ExecutionId::decode(decoder)?;
        let execution_basis = CampaignHash::decode(decoder)?;
        let scope = if schema_version == SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION {
            AttemptExecutionScope::decode(decoder)?
        } else {
            AttemptExecutionScope::Semantic
        };
        let request = Self {
            schema_version,
            daemon_epoch,
            lineage,
            attempt,
            execution,
            execution_basis,
            scope,
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
    /// A non-retryable worker failure durably stopped this incarnation.
    TerminalFailure,
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
            Self::TerminalFailure => encoder.u8(7),
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
            7 => Ok(Self::TerminalFailure),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "get-attempt-execution-disposition",
                tag,
            }),
        }
    }
}

impl GetAttemptExecutionDisposition {
    const fn is_completed(self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    const fn uses_terminal_failure_schema(self) -> bool {
        matches!(self, Self::TerminalFailure)
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
    finding_candidate: Option<FindingCandidateBundleId>,
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
        Self::new_with_optional_finding_candidate(request, disposition, None)
    }

    /// Builds a completed status response with one retained finding candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when `disposition` is not completed or the response
    /// exceeds the strict component-message bound.
    pub fn new_with_finding_candidate(
        request: &GetAttemptExecutionRequest,
        disposition: GetAttemptExecutionDisposition,
        finding_candidate: FindingCandidateBundleId,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_with_optional_finding_candidate(request, disposition, Some(finding_candidate))
    }

    fn new_with_optional_finding_candidate(
        request: &GetAttemptExecutionRequest,
        disposition: GetAttemptExecutionDisposition,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: response_schema_version(
                disposition.is_completed(),
                disposition.uses_terminal_failure_schema(),
                finding_candidate,
            )?,
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            execution: request.execution(),
            request_digest: request.request_digest(),
            disposition,
            finding_candidate,
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

    /// Returns the retained candidate published with completed status.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<FindingCandidateBundleId> {
        self.finding_candidate
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
        if let Some(finding_candidate) = self.finding_candidate {
            finding_candidate.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != EXECUTOR_MESSAGE_SCHEMA_VERSION
            && schema_version != GET_ATTEMPT_EXECUTION_RESPONSE_SCHEMA_VERSION
            && schema_version != FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported get attempt execution response schema version",
            });
        }
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let execution = ExecutionId::decode(decoder)?;
        let request_digest = CampaignHash::decode(decoder)?;
        let disposition = GetAttemptExecutionDisposition::decode(decoder)?;
        let finding_candidate = if schema_version == FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION {
            Some(FindingCandidateBundleId::decode(decoder)?)
        } else {
            None
        };
        let response = Self {
            schema_version,
            daemon_epoch,
            attempt,
            execution,
            request_digest,
            disposition,
            finding_candidate,
        };
        if response_schema_version(
            response.disposition.is_completed(),
            response.disposition.uses_terminal_failure_schema(),
            response.finding_candidate,
        )? != schema_version
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "get attempt execution response schema/disposition mismatch",
            });
        }
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
    prior_start_mode: AttemptStartMode,
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
    /// Returns an error if `assignment` is a materialized-start capture or the
    /// resulting component message exceeds 4 KiB.
    pub fn new(
        assignment: &SubmitAttemptRequest,
        prior_execution: ExecutionId,
        checkpoint: ExactCheckpointId,
    ) -> Result<Self, CampaignCodecError> {
        require_execute_resume_assignment(assignment)?;
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
            prior_start_mode: AttemptStartMode::Execute,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "resume-attempt-execution-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Builds a request that resumes a materialized-start capture as execution.
    ///
    /// `assignment` is the fresh ordinary-execution assignment. The prior
    /// capture mode remains separately authenticated so the executor can match
    /// the paused root before replacing its operational basis.
    ///
    /// # Errors
    ///
    /// Returns an error if `assignment` is itself a capture request or the
    /// resulting component message exceeds its strict encoded bound.
    pub fn new_from_materialized_start(
        assignment: &SubmitAttemptRequest,
        prior_execution: ExecutionId,
        checkpoint: ExactCheckpointId,
        configuration: ConfigurationArtifactId,
    ) -> Result<Self, CampaignCodecError> {
        require_execute_resume_assignment(assignment)?;
        let request = Self {
            schema_version: RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION,
            assignment: assignment.assignment(),
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            prior_execution,
            checkpoint,
            resources: assignment.resources(),
            retention: assignment.retention(),
            prior_start_mode: AttemptStartMode::CaptureMaterializedStart { configuration },
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

    /// Returns the start mode that produced the paused checkpoint.
    #[must_use]
    pub const fn prior_start_mode(&self) -> AttemptStartMode {
        self.prior_start_mode
    }

    /// Reconstructs the exact new-incarnation assignment basis.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fields of this already-valid request no
    /// longer satisfy the bounded submit-message contract.
    pub fn assignment_request(&self) -> Result<SubmitAttemptRequest, CampaignCodecError> {
        SubmitAttemptRequest::new(
            self.assignment,
            self.daemon_epoch,
            self.lineage,
            self.attempt,
            self.resources,
            self.retention,
        )
    }

    /// Returns the assignment-neutral execution-contract digest.
    #[must_use]
    pub fn execution_basis_digest(&self) -> CampaignHash {
        attempt_execution_basis_digest(self.lineage, self.attempt, self.resources, self.retention)
    }

    /// Returns the execution basis that must own the paused checkpoint.
    #[must_use]
    pub fn prior_execution_basis_digest(&self) -> CampaignHash {
        attempt_execution_basis_digest_for_start_mode(
            self.lineage,
            self.attempt,
            self.resources,
            self.retention,
            self.prior_start_mode,
        )
    }

    /// Returns the domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        let domain = if self.schema_version == EXECUTOR_MESSAGE_SCHEMA_VERSION {
            "crucible.campaign.resume-attempt-execution-request.v2"
        } else {
            "crucible.campaign.resume-attempt-execution-request.v3"
        };
        CampaignHash::derive(domain, &self.canonical_bytes())
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
        if self.schema_version == RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION {
            self.prior_start_mode.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        require_resume_attempt_execution_request_version(schema_version)?;
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
        if schema_version == EXECUTOR_MESSAGE_SCHEMA_VERSION {
            return Self::new(&assignment, prior_execution, checkpoint);
        }

        let prior_start_mode = AttemptStartMode::decode(decoder)?;
        let AttemptStartMode::CaptureMaterializedStart { configuration } = prior_start_mode else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "resume attempt request version 3 requires materialized-start capture",
            });
        };
        Self::new_from_materialized_start(&assignment, prior_execution, checkpoint, configuration)
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

impl ResumeAttemptExecutionDisposition {
    const fn is_completed(self) -> bool {
        matches!(self, Self::AlreadyCompleted { .. })
    }

    const fn uses_terminal_failure_schema(self) -> bool {
        matches!(
            self,
            Self::Rejected {
                reason: ExecutorRejection::TerminalFailure
            }
        )
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
    finding_candidate: Option<FindingCandidateBundleId>,
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
        Self::new_with_optional_finding_candidate(request, disposition, None)
    }

    /// Builds a completed resume response with one retained finding candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when `disposition` is not completed or the response
    /// exceeds the strict component-message bound.
    pub fn new_with_finding_candidate(
        request: &ResumeAttemptExecutionRequest,
        disposition: ResumeAttemptExecutionDisposition,
        finding_candidate: FindingCandidateBundleId,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_with_optional_finding_candidate(request, disposition, Some(finding_candidate))
    }

    fn new_with_optional_finding_candidate(
        request: &ResumeAttemptExecutionRequest,
        disposition: ResumeAttemptExecutionDisposition,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: response_schema_version(
                disposition.is_completed(),
                disposition.uses_terminal_failure_schema(),
                finding_candidate,
            )?,
            assignment: request.assignment(),
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            prior_execution: request.prior_execution(),
            checkpoint: request.checkpoint(),
            request_digest: request.request_digest(),
            disposition,
            finding_candidate,
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

    /// Returns the retained candidate published with completed resume status.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<FindingCandidateBundleId> {
        self.finding_candidate
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
        if let Some(finding_candidate) = self.finding_candidate {
            finding_candidate.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != EXECUTOR_MESSAGE_SCHEMA_VERSION
            && schema_version != RESUME_ATTEMPT_EXECUTION_RESPONSE_SCHEMA_VERSION
            && schema_version != FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported resume attempt execution response schema version",
            });
        }
        let assignment = AssignmentId::decode(decoder)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let prior_execution = ExecutionId::decode(decoder)?;
        let checkpoint = ExactCheckpointId::decode(decoder)?;
        let request_digest = CampaignHash::decode(decoder)?;
        let disposition = ResumeAttemptExecutionDisposition::decode(decoder)?;
        let finding_candidate = if schema_version == FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION {
            Some(FindingCandidateBundleId::decode(decoder)?)
        } else {
            None
        };
        let response = Self {
            schema_version,
            assignment,
            daemon_epoch,
            attempt,
            prior_execution,
            checkpoint,
            request_digest,
            disposition,
            finding_candidate,
        };
        if response_schema_version(
            response.disposition.is_completed(),
            response.disposition.uses_terminal_failure_schema(),
            response.finding_candidate,
        )? != schema_version
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "resume attempt execution response schema/disposition mismatch",
            });
        }
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
    scope: AttemptExecutionScope,
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
            schema_version: SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION,
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            execution,
            execution_basis: assignment.execution_basis_digest(),
            scope: assignment.execution_scope(),
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

    /// Returns the exact durable execution namespace to checkpoint.
    #[must_use]
    pub const fn execution_scope(&self) -> AttemptExecutionScope {
        self.scope
    }

    /// Returns a domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        let domain = if self.schema_version == EXECUTOR_MESSAGE_SCHEMA_VERSION {
            "crucible.campaign.checkpoint-attempt-execution-request.v2"
        } else {
            "crucible.campaign.checkpoint-attempt-execution-request.v3"
        };
        CampaignHash::derive(domain, &self.canonical_bytes())
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
        if self.schema_version == SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION {
            self.scope.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        require_executor_control_request_version(schema_version)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let lineage = CampaignLineageId::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let execution = ExecutionId::decode(decoder)?;
        let execution_basis = CampaignHash::decode(decoder)?;
        let scope = if schema_version == SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION {
            AttemptExecutionScope::decode(decoder)?
        } else {
            AttemptExecutionScope::Semantic
        };
        let request = Self {
            schema_version,
            daemon_epoch,
            lineage,
            attempt,
            execution,
            execution_basis,
            scope,
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

impl CheckpointAttemptExecutionDisposition {
    const fn is_completed(self) -> bool {
        matches!(self, Self::AlreadyCompleted { .. })
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
    finding_candidate: Option<FindingCandidateBundleId>,
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
        Self::new_with_optional_finding_candidate(request, disposition, None)
    }

    /// Builds a completed checkpoint response with one retained candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when `disposition` is not completed or the response
    /// exceeds the strict component-message bound.
    pub fn new_with_finding_candidate(
        request: &CheckpointAttemptExecutionRequest,
        disposition: CheckpointAttemptExecutionDisposition,
        finding_candidate: FindingCandidateBundleId,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_with_optional_finding_candidate(request, disposition, Some(finding_candidate))
    }

    fn new_with_optional_finding_candidate(
        request: &CheckpointAttemptExecutionRequest,
        disposition: CheckpointAttemptExecutionDisposition,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: response_schema_version(
                disposition.is_completed(),
                false,
                finding_candidate,
            )?,
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            execution: request.execution(),
            request_digest: request.request_digest(),
            disposition,
            finding_candidate,
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

    /// Returns the retained candidate published with completed status.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<FindingCandidateBundleId> {
        self.finding_candidate
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
        if let Some(finding_candidate) = self.finding_candidate {
            finding_candidate.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != EXECUTOR_MESSAGE_SCHEMA_VERSION
            && schema_version != FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported checkpoint attempt execution response schema version",
            });
        }
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let execution = ExecutionId::decode(decoder)?;
        let request_digest = CampaignHash::decode(decoder)?;
        let disposition = CheckpointAttemptExecutionDisposition::decode(decoder)?;
        let finding_candidate = if schema_version == FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION {
            Some(FindingCandidateBundleId::decode(decoder)?)
        } else {
            None
        };
        let response = Self {
            schema_version,
            daemon_epoch,
            attempt,
            execution,
            request_digest,
            disposition,
            finding_candidate,
        };
        if response_schema_version(
            response.disposition.is_completed(),
            false,
            response.finding_candidate,
        )? != schema_version
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "checkpoint attempt execution response schema/disposition mismatch",
            });
        }
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
    scope: AttemptExecutionScope,
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
            schema_version: SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION,
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            execution,
            execution_basis: assignment.execution_basis_digest(),
            scope: assignment.execution_scope(),
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

    /// Returns the exact durable execution namespace to cancel.
    #[must_use]
    pub const fn execution_scope(&self) -> AttemptExecutionScope {
        self.scope
    }

    /// Returns a domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        let domain = if self.schema_version == EXECUTOR_MESSAGE_SCHEMA_VERSION {
            "crucible.campaign.cancel-attempt-execution-request.v2"
        } else {
            "crucible.campaign.cancel-attempt-execution-request.v3"
        };
        CampaignHash::derive(domain, &self.canonical_bytes())
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
        if self.schema_version == SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION {
            self.scope.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        require_executor_control_request_version(schema_version)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let lineage = CampaignLineageId::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let execution = ExecutionId::decode(decoder)?;
        let execution_basis = CampaignHash::decode(decoder)?;
        let scope = if schema_version == SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION {
            AttemptExecutionScope::decode(decoder)?
        } else {
            AttemptExecutionScope::Semantic
        };
        let request = Self {
            schema_version,
            daemon_epoch,
            lineage,
            attempt,
            execution,
            execution_basis,
            scope,
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

impl CancelAttemptExecutionDisposition {
    const fn is_completed(self) -> bool {
        matches!(self, Self::AlreadyCompleted { .. })
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
    finding_candidate: Option<FindingCandidateBundleId>,
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
        Self::new_with_optional_finding_candidate(request, disposition, None)
    }

    /// Builds a completed cancellation response with one retained candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when `disposition` is not completed or the response
    /// exceeds the strict component-message bound.
    pub fn new_with_finding_candidate(
        request: &CancelAttemptExecutionRequest,
        disposition: CancelAttemptExecutionDisposition,
        finding_candidate: FindingCandidateBundleId,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_with_optional_finding_candidate(request, disposition, Some(finding_candidate))
    }

    fn new_with_optional_finding_candidate(
        request: &CancelAttemptExecutionRequest,
        disposition: CancelAttemptExecutionDisposition,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: response_schema_version(
                disposition.is_completed(),
                false,
                finding_candidate,
            )?,
            daemon_epoch: request.daemon_epoch(),
            attempt: request.attempt(),
            execution: request.execution(),
            request_digest: request.request_digest(),
            disposition,
            finding_candidate,
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

    /// Returns the retained candidate published with completed status.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<FindingCandidateBundleId> {
        self.finding_candidate
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
        if let Some(finding_candidate) = self.finding_candidate {
            finding_candidate.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != EXECUTOR_MESSAGE_SCHEMA_VERSION
            && schema_version != FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported cancel attempt execution response schema version",
            });
        }
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let execution = ExecutionId::decode(decoder)?;
        let request_digest = CampaignHash::decode(decoder)?;
        let disposition = CancelAttemptExecutionDisposition::decode(decoder)?;
        let finding_candidate = if schema_version == FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION {
            Some(FindingCandidateBundleId::decode(decoder)?)
        } else {
            None
        };
        let response = Self {
            schema_version,
            daemon_epoch,
            attempt,
            execution,
            request_digest,
            disposition,
            finding_candidate,
        };
        if response_schema_version(
            response.disposition.is_completed(),
            false,
            response.finding_candidate,
        )? != schema_version
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "cancel attempt execution response schema/disposition mismatch",
            });
        }
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

/// Exact-checkpoint resume extension implemented by direct and RPC executors.
pub trait ExecutorResumeService: ExecutorStatusService {
    /// Admits one fresh execution incarnation from a durable paused root.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be authenticated or changed, or a protocol response cannot be built.
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error>;
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

impl<S: ExecutorResumeService> ExecutorClient<S> {
    /// Resumes and validates one exact durable paused execution.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .resume_attempt_execution(request)
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
    Service(#[source] E),
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

fn response_schema_version(
    is_completed: bool,
    uses_terminal_failure_schema: bool,
    finding_candidate: Option<FindingCandidateBundleId>,
) -> Result<u32, CampaignCodecError> {
    if finding_candidate.is_some() {
        if !is_completed {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding candidate requires a completed executor response",
            });
        }
        return Ok(FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION);
    }
    if uses_terminal_failure_schema {
        return Ok(SUBMIT_ATTEMPT_RESPONSE_SCHEMA_VERSION);
    }
    Ok(EXECUTOR_MESSAGE_SCHEMA_VERSION)
}

const fn require_executor_control_request_version(version: u32) -> Result<(), CampaignCodecError> {
    if version == EXECUTOR_MESSAGE_SCHEMA_VERSION
        || version == SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION
    {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor control-request schema version",
        })
    }
}

const fn require_submit_attempt_request_version(version: u32) -> Result<(), CampaignCodecError> {
    if version == EXECUTOR_MESSAGE_SCHEMA_VERSION
        || version == MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION
        || version == SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION
    {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version",
        })
    }
}

const fn require_resume_attempt_execution_request_version(
    version: u32,
) -> Result<(), CampaignCodecError> {
    if version == EXECUTOR_MESSAGE_SCHEMA_VERSION
        || version == RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION
    {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version",
        })
    }
}

fn require_execute_resume_assignment(
    assignment: &SubmitAttemptRequest,
) -> Result<(), CampaignCodecError> {
    if assignment.start_mode() == AttemptStartMode::Execute {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "resume requires an execute assignment",
        })
    }
}

#[cfg(test)]
mod tests;
