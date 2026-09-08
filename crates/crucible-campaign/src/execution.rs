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
//! SubmitAttemptRequestV5 = version | assignment | daemon-epoch | lineage |
//!                          attempt | resource-limits | retention-intent |
//!                          selected-savepoint-start-mode
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
//! ResumeAttemptExecutionRequestV4 = version | assignment | daemon-epoch |
//!                                    lineage | attempt | prior-execution |
//!                                    checkpoint | resource-limits |
//!                                    retention-intent | selected-start-mode
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
    CampaignLineageId, CampaignSnapshotId, ConfigurationArtifactId, ExactCheckpointId,
    FindingCandidateBundleId, ObservationId,
};

const EXECUTOR_MESSAGE_SCHEMA_VERSION: u32 = 2;
const MATERIALIZED_START_SUBMIT_REQUEST_SCHEMA_VERSION: u32 = 3;
const SCOPED_SUBMIT_ATTEMPT_REQUEST_SCHEMA_VERSION: u32 = 4;
const SELECTED_SAVEPOINT_SUBMIT_REQUEST_SCHEMA_VERSION: u32 = 5;
const SCOPED_EXECUTOR_CONTROL_REQUEST_SCHEMA_VERSION: u32 = 3;
const RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION: u32 = 3;
const SELECTED_RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION: u32 = 4;
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
    /// Prefers the first authenticated physical source for a semantic continuation.
    SelectedSavepoint {
        /// Snapshot whose accounting root authenticates the immutable first source.
        snapshot: CampaignSnapshotId,
        /// Selection fact naming the first accepted physical-source cause.
        selection: CampaignFactId,
        /// Capture request whose paused ledger scope owns the preferred root.
        request: CampaignFactId,
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
            Self::SelectedSavepoint { .. } => AttemptExecutionScope::Semantic,
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
            Self::SelectedSavepoint {
                snapshot,
                selection,
                request,
            } => {
                encoder.u8(3);
                snapshot.encode(encoder);
                selection.encode(encoder);
                request.encode(encoder);
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
            3 => Ok(Self::SelectedSavepoint {
                snapshot: CampaignSnapshotId::decode(decoder)?,
                selection: CampaignFactId::decode(decoder)?,
                request: CampaignFactId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-start-mode",
                tag,
            }),
        }
    }
}

mod cancel;
mod checkpoint;
mod client;
mod resume;
mod status;
mod submit;

pub use cancel::*;
pub use checkpoint::*;
pub use client::*;
pub use resume::*;
pub use status::*;
pub use submit::*;

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
        || version == SELECTED_SAVEPOINT_SUBMIT_REQUEST_SCHEMA_VERSION
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
        || version == SELECTED_RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION
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

fn require_semantic_resume_assignment(
    assignment: &SubmitAttemptRequest,
) -> Result<(), CampaignCodecError> {
    if matches!(
        assignment.start_mode(),
        AttemptStartMode::Execute | AttemptStartMode::SelectedSavepoint { .. }
    ) {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "resume requires a semantic assignment",
        })
    }
}

#[cfg(test)]
mod tests;
