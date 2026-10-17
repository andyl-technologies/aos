//! Actual execution provenance and observed result identities.

use super::*;

/// Identifies actual observed bytes, independently of the planned configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservedAttemptId(ContentId);

impl ObservedAttemptId {
    /// Wraps a version-one observation-kind identity for later schema authentication.
    ///
    /// The repository authenticates the actual observed-record schema when
    /// loading bytes. This shape check does not relabel a legacy observation.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign object kind or unsupported version.
    pub fn from_content_id(id: ContentId) -> Result<Self, CampaignCodecError> {
        if id.kind() != ObjectKind::Observation || id.schema_version() != VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed result identity kind or version is unsupported",
            });
        }
        Ok(Self(id))
    }

    /// Returns the versioned observed result's content identity.
    #[must_use]
    pub const fn content_id(self) -> ContentId {
        self.0
    }
}

/// Classifies an actual observed execution without deterministic replay claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedAttemptOutcome {
    /// The requested observation completed successfully.
    Completed,
    /// The observed guest or scenario property failed.
    Failed,
    /// The execution was stopped at its operational budget.
    BudgetExhausted,
    /// The executor explicitly cancelled the observation.
    Cancelled,
}

impl Canonical for ObservedAttemptOutcome {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Completed => 0,
            Self::Failed => 1,
            Self::BudgetExhausted => 2,
            Self::Cancelled => 3,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Completed),
            1 => Ok(Self::Failed),
            2 => Ok(Self::BudgetExhausted),
            3 => Ok(Self::Cancelled),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "observed-node-outcome",
                tag,
            }),
        }
    }
}

/// Retains actual boundary provenance for one independently named execution.
///
/// Incoming and outgoing trace roots include actual ordering, timestamps and
/// payloads, including external nondeterministic input. Evidence retains the
/// closure needed to interpret those traces and the reported outcome. These
/// references do not themselves qualify conditional replay: a transcript verifier
/// must independently prove completeness, preconditions and owner compatibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedAttemptResult {
    request: ObservedAttemptRequest,
    incoming: ContentId,
    outgoing: ContentId,
    evidence: ContentId,
    outcome: ObservedAttemptOutcome,
}

impl ObservedAttemptResult {
    /// Builds an observed result with actual input/output trace roots.
    ///
    /// # Errors
    ///
    /// Returns an error when either boundary root is not a trace object.
    pub fn new(
        request: ObservedAttemptRequest,
        incoming: ContentId,
        outgoing: ContentId,
        evidence: ContentId,
        outcome: ObservedAttemptOutcome,
    ) -> Result<Self, CampaignCodecError> {
        if incoming.kind() != ObjectKind::Trace || outgoing.kind() != ObjectKind::Trace {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed boundary provenance must use trace objects",
            });
        }
        let result = Self {
            request,
            incoming,
            outgoing,
            evidence,
            outcome,
        };
        codec::ensure_encoded_size(
            &result,
            MAX_OBSERVED_RECORD_BYTES - 1024,
            "observed result bytes",
        )?;
        Ok(result)
    }

    /// Returns the original admitted request and independent execution nonce.
    #[must_use]
    pub const fn request(&self) -> &ObservedAttemptRequest {
        &self.request
    }

    /// Returns actual incoming boundary provenance.
    #[must_use]
    pub const fn incoming(&self) -> ContentId {
        self.incoming
    }

    /// Returns actual outgoing boundary provenance.
    #[must_use]
    pub const fn outgoing(&self) -> ContentId {
        self.outgoing
    }

    /// Returns the evidence closure interpreting the observation.
    #[must_use]
    pub const fn evidence(&self) -> ContentId {
        self.evidence
    }

    /// Returns the actual outcome of this execution.
    #[must_use]
    pub const fn outcome(&self) -> ObservedAttemptOutcome {
        self.outcome
    }

    /// Computes the result identity, including the independent execution nonce.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical envelope construction fails.
    pub fn id(&self) -> Result<ObservedAttemptId, CampaignCodecError> {
        Ok(ObservedAttemptId(
            self.envelope()?.content_id(ObjectKind::Observation),
        ))
    }

    /// Returns strict version-one observed result bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes bounded canonical version-one observed result bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported, malformed, noncanonical, oversized,
    /// invalid trace kinds or trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode_bounded(bytes, MAX_OBSERVED_RECORD_BYTES, "observed result bytes")
    }

    pub(crate) fn envelope(&self) -> Result<ContentEnvelope, CampaignCodecError> {
        envelope(
            "crucible.observed-node-result",
            [
                ("request", self.request.content_id()?),
                ("incoming", self.incoming),
                ("outgoing", self.outgoing),
                ("evidence", self.evidence),
            ],
            self.canonical_bytes(),
        )
    }
}

impl Canonical for ObservedAttemptResult {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(VERSION);
        self.request.encode(encoder);
        Canonical::encode(&self.incoming, encoder);
        Canonical::encode(&self.outgoing, encoder);
        Canonical::encode(&self.evidence, encoder);
        self.outcome.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_version(decoder)?;
        Self::new(
            ObservedAttemptRequest::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ObservedAttemptOutcome::decode(decoder)?,
        )
    }
}
