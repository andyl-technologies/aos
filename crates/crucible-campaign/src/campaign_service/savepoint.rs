//! Bounded public commands for exact attempt-stop capture and continuation.

use super::*;
use crate::{
    AttemptId, CampaignCommandId, CampaignFactId, ConfigurationId, ObservationId,
    SavepointCaptureRequest, SavepointCaptureResolution, StopCondition,
};

/// Immutable reason identifying captures whose selected execution requires exact restore.
pub const PUBLIC_EXACT_CAPTURE_REASON: &str = "public exact pending-choice capture";

/// One requested savepoint action at an exact current campaign snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignSavepointAction {
    /// Replay a completed attempt and capture its declared stop boundary.
    Capture {
        /// Idempotency key for this capture request.
        command: CampaignCommandId,
        /// Completed attempt whose stop is captured.
        attempt: AttemptId,
    },
    /// Read one capture request, resolution, and scoped runtime state.
    Status {
        /// Immutable capture request fact identifier.
        request: CampaignFactId,
    },
    /// Admit a continuation from a Ready capture and a later stop.
    Select {
        /// Idempotency key for this continuation selection.
        command: CampaignCommandId,
        /// Ready capture request fact identifier.
        request: CampaignFactId,
        /// Stop reached after the retained pending choice is answered.
        stop: StopCondition,
    },
}

impl Canonical for CampaignSavepointAction {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Capture { command, attempt } => {
                encoder.u8(0);
                command.encode(encoder);
                attempt.encode(encoder);
            }
            Self::Status { request } => {
                encoder.u8(1);
                request.encode(encoder);
            }
            Self::Select {
                command,
                request,
                stop,
            } => {
                encoder.u8(2);
                command.encode(encoder);
                request.encode(encoder);
                stop.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Capture {
                command: CampaignCommandId::decode(decoder)?,
                attempt: AttemptId::decode(decoder)?,
            }),
            1 => Ok(Self::Status {
                request: CampaignFactId::decode(decoder)?,
            }),
            2 => Ok(Self::Select {
                command: CampaignCommandId::decode(decoder)?,
                request: CampaignFactId::decode(decoder)?,
                stop: StopCondition::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-savepoint-action",
                tag,
            }),
        }
    }
}

/// Principal-bound exact-snapshot savepoint request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignSavepointRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    action: CampaignSavepointAction,
}

impl CampaignSavepointRequest {
    /// Builds one bounded capture, status, or selection request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop or oversized message.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        action: CampaignSavepointAction,
    ) -> Result<Self, CampaignCodecError> {
        if let CampaignSavepointAction::Select { stop, .. } = &action {
            stop.validate()?;
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            action,
        };
        ensure_message_size(&request, "campaign-savepoint-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the named campaign.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the required current snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the selected operation.
    #[must_use]
    pub const fn action(&self) -> &CampaignSavepointAction {
        &self.action
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("campaign-savepoint", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "campaign-savepoint-request-encoded-bytes")
    }
}

impl Canonical for CampaignSavepointRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.action.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            CampaignSavepointAction::decode(decoder)?,
        )
    }
}

/// One bounded, request-bound capture result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignSavepointResult {
    /// An idempotent capture request was accepted.
    Captured {
        /// Snapshot containing the accepted request.
        snapshot: CampaignSnapshotId,
        /// Immutable capture request fact identifier.
        request: CampaignFactId,
        /// Whether the same command was already admitted.
        replayed: bool,
    },
    /// The exact capture and its current durable disposition were read.
    Status {
        /// Immutable capture request.
        capture: SavepointCaptureRequest,
        /// Durable capture resolution, if published.
        resolution: Option<SavepointCaptureResolution>,
        /// Authenticated operational state scoped to the capture request.
        runtime: Option<CampaignAttemptRuntime>,
        /// Observation that reached the original pending choice.
        source_observation: ObservationId,
        /// Child configuration containing the pending choice.
        reached_configuration: ConfigurationId,
    },
    /// One semantic continuation was admitted from the selected source.
    Selected {
        /// Snapshot containing the selected continuation.
        snapshot: CampaignSnapshotId,
        /// Admitted continuation attempt identifier.
        attempt: AttemptId,
        /// Whether the same command was already admitted.
        replayed: bool,
    },
}

impl Canonical for CampaignSavepointResult {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Captured {
                snapshot,
                request,
                replayed,
            } => {
                encoder.u8(0);
                snapshot.encode(encoder);
                request.encode(encoder);
                replayed.encode(encoder);
            }
            Self::Status {
                capture,
                resolution,
                runtime,
                source_observation,
                reached_configuration,
            } => {
                encoder.u8(1);
                capture.encode(encoder);
                resolution.encode(encoder);
                runtime.encode(encoder);
                source_observation.encode(encoder);
                reached_configuration.encode(encoder);
            }
            Self::Selected {
                snapshot,
                attempt,
                replayed,
            } => {
                encoder.u8(2);
                snapshot.encode(encoder);
                attempt.encode(encoder);
                replayed.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Captured {
                snapshot: CampaignSnapshotId::decode(decoder)?,
                request: CampaignFactId::decode(decoder)?,
                replayed: bool::decode(decoder)?,
            }),
            1 => Ok(Self::Status {
                capture: SavepointCaptureRequest::decode(decoder)?,
                resolution: Option::decode(decoder)?,
                runtime: Option::decode(decoder)?,
                source_observation: ObservationId::decode(decoder)?,
                reached_configuration: ConfigurationId::decode(decoder)?,
            }),
            2 => Ok(Self::Selected {
                snapshot: CampaignSnapshotId::decode(decoder)?,
                attempt: AttemptId::decode(decoder)?,
                replayed: bool::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-savepoint-result",
                tag,
            }),
        }
    }
}

/// Strict response for one authenticated savepoint action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignSavepointResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    result: CampaignSavepointResult,
}

impl CampaignSavepointResponse {
    /// Builds a bounded response that matches one request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for mismatched operation, stale status,
    /// missing Ready evidence, or excessive encoded size.
    pub fn new(
        request: &CampaignSavepointRequest,
        result: CampaignSavepointResult,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            result,
        };
        response.validate_for(request)?;
        ensure_message_size(&response, "campaign-savepoint-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the validated result body.
    #[must_use]
    pub const fn result(&self) -> &CampaignSavepointResult {
        &self.result
    }

    /// Validates exact request binding and status evidence shape.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for mismatched or incomplete evidence.
    pub fn validate_for(
        &self,
        request: &CampaignSavepointRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        let valid = match (request.action(), &self.result) {
            (CampaignSavepointAction::Capture { .. }, CampaignSavepointResult::Captured { .. }) => {
                true
            }
            (CampaignSavepointAction::Select { .. }, CampaignSavepointResult::Selected { .. }) => {
                true
            }
            (
                CampaignSavepointAction::Status { request: expected },
                CampaignSavepointResult::Status {
                    capture,
                    resolution,
                    runtime,
                    ..
                },
            ) => {
                let capture_id =
                    crate::CampaignFact::SavepointCaptureRequested(capture.clone()).id()?;
                capture_id == *expected
                    && resolution
                        .as_ref()
                        .is_none_or(|value| value.request == *expected)
                    && !resolution.as_ref().is_some_and(|value| {
                        value.outcome == crate::SavepointCaptureOutcome::Ready
                            && !runtime.as_ref().is_some_and(|state| {
                                state.phase() == CampaignAttemptPhase::Paused
                                    && state.checkpoint().is_some()
                            })
                    })
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "campaign savepoint response does not match request",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "campaign-savepoint-response-encoded-bytes")
    }
}

impl Canonical for CampaignSavepointResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.result.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            result: CampaignSavepointResult::decode(decoder)?,
        };
        ensure_message_size(&response, "campaign-savepoint-response-encoded-bytes")?;
        Ok(response)
    }
}
