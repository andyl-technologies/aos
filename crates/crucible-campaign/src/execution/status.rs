//! Read-only execution status requests and responses.
//!
//! This module owns the canonical status request and response codecs. Their
//! current wire shapes are:
//!
//! ```text
//! GetAttemptExecutionRequestV3 = version | daemon-epoch | lineage | attempt |
//!                                execution | execution-basis-digest | scope
//! GetAttemptExecutionResponseV4 = version | daemon-epoch | attempt | execution |
//!                                 request-digest | completed-disposition |
//!                                 finding-candidate
//! ```
//!
//! The parent module catalogs the retained earlier versions.

use super::*;

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
