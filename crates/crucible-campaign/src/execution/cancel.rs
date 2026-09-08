//! Execution cancellation control messages.
//!
//! This module owns the canonical cancellation request and response codecs.
//! Their current wire shapes are:
//!
//! ```text
//! CancelAttemptExecutionRequestV3 = version | daemon-epoch | lineage | attempt |
//!                                   execution | execution-basis-digest | scope
//! CancelAttemptExecutionResponseV4 = version | daemon-epoch | attempt | execution |
//!                                    request-digest | completed-disposition |
//!                                    finding-candidate
//! ```
//!
//! The parent module catalogs the retained earlier versions.

use super::*;

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
