//! Durable dispatch reservations and independent observed-result ledger states.

use super::*;
use crate::policy::validate_identifier;

/// Retains the authoritative lifecycle of an independently identified execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedAttemptState {
    /// Dispatch was reserved durably; retry must not dispatch a second execution.
    Reserved(ObservedAttemptRequest),
    /// The original observed result was published and is returned on every retry.
    Completed(ObservedAttemptResult),
    /// Execution ownership or native outcome is uncertain and needs reconciliation.
    Quarantined {
        /// Original immutable admitted execution request.
        request: ObservedAttemptRequest,
        /// Bounded machine-readable reason for refusing further dispatch.
        reason: String,
    },
}

impl ObservedAttemptState {
    /// Returns strict version-one lifecycle-state bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes bounded canonical version-one lifecycle-state bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported, malformed, noncanonical, oversized
    /// or trailing bytes, including an invalid quarantine reason.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode_bounded(bytes, MAX_OBSERVED_RECORD_BYTES, "observed state bytes")
    }

    /// Returns the original request in every lifecycle state.
    #[must_use]
    pub fn request(&self) -> &ObservedAttemptRequest {
        match self {
            Self::Reserved(request) | Self::Quarantined { request, .. } => request,
            Self::Completed(result) => result.request(),
        }
    }

    pub(crate) fn envelope(&self) -> Result<ContentEnvelope, CampaignCodecError> {
        let mut children = vec![("request", self.request().content_id()?)];
        if let Self::Completed(result) = self {
            children.push(("result", result.id()?.content_id()));
        }
        envelope(
            "crucible.observed-node-state",
            children,
            codec::encode(self),
        )
    }
}

impl Canonical for ObservedAttemptState {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(VERSION);
        match self {
            Self::Reserved(request) => {
                encoder.u8(0);
                request.encode(encoder);
            }
            Self::Completed(result) => {
                encoder.u8(1);
                result.encode(encoder);
            }
            Self::Quarantined { request, reason } => {
                encoder.u8(2);
                request.encode(encoder);
                encoder.string(reason);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_version(decoder)?;
        match decoder.u8()? {
            0 => Ok(Self::Reserved(ObservedAttemptRequest::decode(decoder)?)),
            1 => Ok(Self::Completed(ObservedAttemptResult::decode(decoder)?)),
            2 => {
                let request = ObservedAttemptRequest::decode(decoder)?;
                let reason = decoder.string_bounded(256, "observed quarantine reason")?;
                validate_identifier(&reason, "observed quarantine reason is invalid")?;
                Ok(Self::Quarantined { request, reason })
            }
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "observed-node-state",
                tag,
            }),
        }
    }
}

/// Authorizes exactly one worker dispatch after authoritative reservation.
///
/// The permit is deliberately not cloneable or serializable. A recovered ledger
/// reservation supplies the existing state, never another permit. It does not
/// establish native completion or permit a second start after an uncertain error.
#[derive(Debug)]
pub struct ObservedExecutionPermit {
    pub(crate) ledger: String,
    pub(crate) request: ObservedAttemptRequest,
}

impl ObservedExecutionPermit {
    /// Returns the exact reserved execution request.
    #[must_use]
    pub const fn request(&self) -> &ObservedAttemptRequest {
        &self.request
    }

    /// Returns the authoritative ledger owning this reservation.
    #[must_use]
    pub fn ledger(&self) -> &str {
        &self.ledger
    }
}

/// Distinguishes a first dispatch reservation from an idempotent request retry.
#[derive(Debug)]
pub enum ObservedReservation {
    /// A newly persisted reservation authorizes the worker's first dispatch.
    Fresh(ObservedExecutionPermit),
    /// Existing ownership or result must be reused without another dispatch.
    Existing(ObservedAttemptState),
}

pub(crate) struct ObservedLedger {
    pub(crate) capabilities: CampaignHash,
    pub(crate) executions: ContentId,
}

pub(crate) struct ObservedDispatchReservation {
    pub(crate) ledger: String,
    pub(crate) request: ObservedAttemptRequest,
}

impl ObservedDispatchReservation {
    pub(crate) fn envelope(&self) -> Result<ContentEnvelope, CampaignCodecError> {
        envelope(
            "crucible.observed-node-dispatch-reservation",
            [("request", self.request.content_id()?)],
            codec::encode(self),
        )
    }
}

impl Canonical for ObservedDispatchReservation {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(VERSION);
        encoder.string(&self.ledger);
        self.request.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_version(decoder)?;
        let ledger = decoder.string_bounded(255, "observed dispatch ledger name")?;
        if ledger.is_empty() || ledger.contains('/') {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed dispatch ledger name must be one ref segment",
            });
        }
        crucible_cas::content_store::RefName::new(format!("observed-attempt-ledgers/{ledger}"))
            .map_err(|_| CampaignCodecError::InvalidValue {
                reason: "observed dispatch ledger name is invalid",
            })?;
        Ok(Self {
            ledger,
            request: ObservedAttemptRequest::decode(decoder)?,
        })
    }
}

impl ObservedLedger {
    pub(crate) fn envelope(&self) -> Result<ContentEnvelope, CampaignCodecError> {
        envelope(
            "crucible.observed-node-ledger",
            [("executions", self.executions)],
            codec::encode(self),
        )
    }
}

impl Canonical for ObservedLedger {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(VERSION);
        self.capabilities.encode(encoder);
        Canonical::encode(&self.executions, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_version(decoder)?;
        let capabilities = CampaignHash::decode(decoder)?;
        let executions = ContentId::decode(decoder)?;
        if executions.kind() != ObjectKind::MerkleNode {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed ledger execution index is not a Merkle node",
            });
        }
        Ok(Self {
            capabilities,
            executions,
        })
    }
}

pub(crate) fn execution_key(execution: ExecutionId) -> CampaignHash {
    CampaignHash::derive(
        "crucible.observed-node-execution-index.v1",
        &execution.as_bytes(),
    )
}
