//! Attempt submission requests and responses.
//!
//! This module owns the canonical submission request and response codecs.
//! Their current wire shapes are:
//!
//! ```text
//! SubmitAttemptRequestV5 = version | assignment | daemon-epoch | lineage |
//!                          attempt | resource-limits | retention-intent |
//!                          selected-savepoint-start-mode
//! SubmitAttemptResponseV4 = version | assignment | daemon-epoch | attempt |
//!                           request-digest | completed-disposition |
//!                           finding-candidate
//! ```
//!
//! The parent module catalogs the retained earlier versions.

use super::*;

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

    /// Builds an ordinary semantic assignment with a selected savepoint preference.
    ///
    /// The executor reauthenticates `selection` as the immutable first-source
    /// mapping at `snapshot` and resolves `request` through its own operational
    /// ledger. An absent physical root permits deterministic cold replay; an
    /// inconsistent retained root fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting component message exceeds its strict
    /// encoded bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new_selected_savepoint(
        assignment: AssignmentId,
        daemon_epoch: DaemonEpoch,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        resources: AttemptResourceLimits,
        retention: ExecutionRetentionIntent,
        snapshot: CampaignSnapshotId,
        selection: CampaignFactId,
        request: CampaignFactId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: SELECTED_SAVEPOINT_SUBMIT_REQUEST_SCHEMA_VERSION,
            assignment,
            daemon_epoch,
            lineage,
            attempt,
            resources,
            retention,
            start_mode: AttemptStartMode::SelectedSavepoint {
                snapshot,
                selection,
                request,
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
            SELECTED_SAVEPOINT_SUBMIT_REQUEST_SCHEMA_VERSION => {
                "crucible.campaign.submit-attempt-request.v5"
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
            || self.schema_version == SELECTED_SAVEPOINT_SUBMIT_REQUEST_SCHEMA_VERSION
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
            (
                SELECTED_SAVEPOINT_SUBMIT_REQUEST_SCHEMA_VERSION,
                AttemptStartMode::SelectedSavepoint {
                    snapshot,
                    selection,
                    request,
                },
            ) => Self::new_selected_savepoint(
                assignment,
                daemon_epoch,
                lineage,
                attempt,
                resources,
                retention,
                snapshot,
                selection,
                request,
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
            (SELECTED_SAVEPOINT_SUBMIT_REQUEST_SCHEMA_VERSION, _) => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "submit attempt request version 5 requires selected savepoint",
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
