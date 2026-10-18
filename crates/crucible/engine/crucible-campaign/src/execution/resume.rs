//! Exact-checkpoint resume requests and responses.
//!
//! This module owns the canonical resume request and response codecs. Their
//! current wire shapes are:
//!
//! ```text
//! ResumeAttemptExecutionRequestV6 = version | assignment | daemon-epoch |
//!                                    lineage | attempt | prior-execution |
//!                                    checkpoint | resource-limits |
//!                                    retention-intent | prior-start-mode |
//!                                    finding-retention-policy-basis |
//!                                    prior-finding-retention-policy-basis
//! FindingRetentionPolicyBasis = source-snapshot | admission | policy
//! ResumeAttemptExecutionResponseV4 = version | assignment | daemon-epoch |
//!                                     attempt | prior-execution | checkpoint |
//!                                     request-digest | completed-disposition |
//!                                     finding-candidate
//! ```
//!
//! Decoders reject every request or response version other than these current shapes.

use super::*;

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
    retention_policy: AttemptRetentionPolicyDisposition,
    prior_retention_policy: AttemptRetentionPolicyDisposition,
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
    /// Returns an error if `assignment` is an operational capture or the
    /// resulting component message exceeds 4 KiB.
    pub fn new(
        assignment: &SubmitAttemptRequest,
        prior_execution: ExecutionId,
        checkpoint: ExactCheckpointId,
    ) -> Result<Self, CampaignCodecError> {
        require_semantic_resume_assignment(assignment)?;
        let prior_start_mode = assignment.start_mode();
        let retention_policy = assignment.retention_policy();
        let request = Self {
            schema_version:
                MATERIALIZED_RETENTION_POLICY_RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION,
            assignment: assignment.assignment(),
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            prior_execution,
            checkpoint,
            resources: assignment.resources(),
            retention: assignment.retention(),
            prior_start_mode,
            retention_policy,
            prior_retention_policy: retention_policy,
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
            schema_version:
                MATERIALIZED_RETENTION_POLICY_RESUME_ATTEMPT_EXECUTION_REQUEST_SCHEMA_VERSION,
            assignment: assignment.assignment(),
            daemon_epoch: assignment.daemon_epoch(),
            lineage: assignment.lineage(),
            attempt: assignment.attempt(),
            prior_execution,
            checkpoint,
            resources: assignment.resources(),
            retention: assignment.retention(),
            prior_start_mode: AttemptStartMode::CaptureMaterializedStart { configuration },
            retention_policy: assignment.retention_policy(),
            prior_retention_policy: crate::AttemptRetentionPolicyDisposition::Disabled,
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

    /// Returns the fresh assignment's explicit retention policy.
    #[must_use]
    pub const fn retention_policy(&self) -> AttemptRetentionPolicyDisposition {
        self.retention_policy
    }

    /// Reconstructs the exact new-incarnation assignment basis.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fields of this already-valid request no
    /// longer satisfy the bounded submit-message contract.
    pub fn assignment_request(&self) -> Result<SubmitAttemptRequest, CampaignCodecError> {
        let assignment = SubmitAttemptRequest::new(
            self.assignment,
            self.daemon_epoch,
            self.lineage,
            self.attempt,
            self.resources,
            self.retention,
            self.retention_policy,
        )?;
        match self.prior_start_mode {
            AttemptStartMode::SelectedSavepoint {
                snapshot,
                selection,
                request,
            } => SubmitAttemptRequest::new_selected_savepoint(
                assignment, snapshot, selection, request,
            ),
            AttemptStartMode::Execute
            | AttemptStartMode::CaptureMaterializedStart { .. }
            | AttemptStartMode::SavepointCapture { .. } => Ok(assignment),
        }
    }

    /// Returns the assignment-neutral execution-contract digest.
    #[must_use]
    pub fn execution_basis_digest(&self) -> CampaignHash {
        let start_mode = match self.prior_start_mode {
            selected @ AttemptStartMode::SelectedSavepoint { .. } => selected,
            AttemptStartMode::Execute
            | AttemptStartMode::CaptureMaterializedStart { .. }
            | AttemptStartMode::SavepointCapture { .. } => AttemptStartMode::Execute,
        };
        attempt_execution_basis_digest_with_retention_policy(
            self.lineage,
            self.attempt,
            self.resources,
            self.retention,
            start_mode,
            self.retention_policy,
        )
    }

    /// Returns the execution basis that must own the paused checkpoint.
    #[must_use]
    pub fn prior_execution_basis_digest(&self) -> CampaignHash {
        attempt_execution_basis_digest_with_retention_policy(
            self.lineage,
            self.attempt,
            self.resources,
            self.retention,
            self.prior_start_mode,
            self.prior_retention_policy,
        )
    }

    /// Returns the domain-separated digest of every canonical request field.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        let domain = format!(
            "crucible.campaign.resume-attempt-execution-request.v{}",
            self.schema_version
        );
        CampaignHash::derive(&domain, &self.canonical_bytes())
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
        self.prior_start_mode.encode(encoder);
        self.retention_policy.encode(encoder);
        self.prior_retention_policy.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        require_resume_attempt_execution_request_version(schema_version)?;
        let assignment_id = AssignmentId::decode(decoder)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let lineage = CampaignLineageId::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let prior_execution = ExecutionId::decode(decoder)?;
        let checkpoint = ExactCheckpointId::decode(decoder)?;
        let resources = AttemptResourceLimits::decode(decoder)?;
        let retention = ExecutionRetentionIntent::decode(decoder)?;
        let prior_start_mode = AttemptStartMode::decode(decoder)?;
        let retention_policy = crate::AttemptRetentionPolicyDisposition::decode(decoder)?;
        let prior_retention_policy = crate::AttemptRetentionPolicyDisposition::decode(decoder)?;

        let assignment = SubmitAttemptRequest::new(
            assignment_id,
            daemon_epoch,
            lineage,
            attempt,
            resources,
            retention,
            retention_policy,
        )?;
        match prior_start_mode {
            AttemptStartMode::Execute => {
                require_unchanged_resume_policy(retention_policy, prior_retention_policy)?;
                Self::new(&assignment, prior_execution, checkpoint)
            }
            AttemptStartMode::SelectedSavepoint {
                snapshot,
                selection,
                request,
            } => {
                require_unchanged_resume_policy(retention_policy, prior_retention_policy)?;
                let assignment = SubmitAttemptRequest::new_selected_savepoint(
                    assignment, snapshot, selection, request,
                )?;
                Self::new(&assignment, prior_execution, checkpoint)
            }
            AttemptStartMode::CaptureMaterializedStart { configuration } => {
                if prior_retention_policy != crate::AttemptRetentionPolicyDisposition::Disabled {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "materialized-start capture has finding retention enabled",
                    });
                }
                Self::new_from_materialized_start(
                    &assignment,
                    prior_execution,
                    checkpoint,
                    configuration,
                )
            }
            AttemptStartMode::SavepointCapture { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "semantic resume request has a savepoint-capture start mode",
            }),
        }
    }
}

fn require_unchanged_resume_policy(
    retention_policy: AttemptRetentionPolicyDisposition,
    prior_retention_policy: AttemptRetentionPolicyDisposition,
) -> Result<(), CampaignCodecError> {
    if retention_policy == prior_retention_policy {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "resume request changes the prior execution retention policy",
        })
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
            schema_version: response_schema_version(disposition.is_completed(), finding_candidate)?,
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
        self.finding_candidate.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != FINDING_CANDIDATE_RESPONSE_SCHEMA_VERSION {
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
        let finding_candidate = Option::<FindingCandidateBundleId>::decode(decoder)?;
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
