//! Lazy frontier continuation and expansion projection records.

use super::*;

/// Validated progress toward a continuation's next widening threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeedbackWait {
    completed_visits: u64,
    required_visits: u64,
}

impl FeedbackWait {
    /// Builds a wait whose widening threshold has not yet been reached.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when completed visits already meet or
    /// exceed the required visit count.
    pub fn new(completed_visits: u64, required_visits: u64) -> Result<Self, CampaignCodecError> {
        if required_visits <= completed_visits {
            return Err(CampaignCodecError::InvalidValue {
                reason: "waiting continuation is already eligible",
            });
        }
        Ok(Self {
            completed_visits,
            required_visits,
        })
    }

    /// Returns visits currently credited.
    #[must_use]
    pub const fn completed_visits(self) -> u64 {
        self.completed_visits
    }

    /// Returns visits required for the next child.
    #[must_use]
    pub const fn required_visits(self) -> u64 {
        self.required_visits
    }
}

impl Canonical for FeedbackWait {
    fn encode(&self, encoder: &mut Encoder) {
        self.completed_visits.encode(encoder);
        self.required_visits.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(u64::decode(decoder)?, u64::decode(decoder)?)
    }
}

/// Derived readiness of one request's suspended continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContinuationState {
    /// Eligible to yield under current feedback and budgets.
    Ready,
    /// Requires more completed descendant visits before widening.
    WaitingForFeedback(FeedbackWait),
    /// Sampling source remains unbounded/open but is not currently ready.
    Open,
    /// Source has a complete exhaustion proof.
    Exhausted,
    /// Request budget or explicit policy permanently closed the source.
    Closed,
}

impl Canonical for ContinuationState {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Ready => encoder.u8(0),
            Self::WaitingForFeedback(wait) => {
                encoder.u8(1);
                wait.encode(encoder);
            }
            Self::Open => encoder.u8(2),
            Self::Exhausted => encoder.u8(3),
            Self::Closed => encoder.u8(4),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Ready),
            1 => Ok(Self::WaitingForFeedback(FeedbackWait::decode(decoder)?)),
            2 => Ok(Self::Open),
            3 => Ok(Self::Exhausted),
            4 => Ok(Self::Closed),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "continuation-state",
                tag,
            }),
        }
    }
}

/// Exact integer statistics projected for one semantic branch point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExpansionStatistics {
    /// Distinct proposed edges.
    pub admitted_children: u64,
    /// Completed descendant visits credited exactly once.
    pub completed_visits: u64,
    /// Signed fixed-point reward sum in millionths.
    pub reward_sum_micros: i64,
    /// Distinct coverage/semantic novelty events.
    pub novelty_events: u64,
    /// Distinct correctness findings.
    pub findings: u64,
}

impl Canonical for ExpansionStatistics {
    fn encode(&self, encoder: &mut Encoder) {
        self.admitted_children.encode(encoder);
        self.completed_visits.encode(encoder);
        self.reward_sum_micros.encode(encoder);
        self.novelty_events.encode(encoder);
        self.findings.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            admitted_children: u64::decode(decoder)?,
            completed_visits: u64::decode(decoder)?,
            reward_sum_micros: i64::decode(decoder)?,
            novelty_events: u64::decode(decoder)?,
            findings: u64::decode(decoder)?,
        })
    }
}

/// Rebuildable authenticated continuation projection for one branch point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpansionState {
    schema_version: u32,
    branch_point: BranchPointId,
    request_root: ContentId,
    proposal_root: ContentId,
    observation_root: ContentId,
    statistics: ExpansionStatistics,
    continuations: BTreeMap<BranchRequestId, ContinuationState>,
}

impl ExpansionState {
    /// Builds a bounded expansion projection over exact semantic roots.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a root is not a Merkle node or the
    /// continuation map exceeds 65,536 entries.
    pub fn new(
        branch_point: BranchPointId,
        request_root: ContentId,
        proposal_root: ContentId,
        observation_root: ContentId,
        statistics: ExpansionStatistics,
        continuations: BTreeMap<BranchRequestId, ContinuationState>,
    ) -> Result<Self, CampaignCodecError> {
        if [request_root, proposal_root, observation_root]
            .iter()
            .any(|id| id.kind() != crucible_cas::content_store::ObjectKind::MerkleNode)
            || continuations.len() > MAX_CONTINUATIONS
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "expansion state has invalid roots or too many continuations",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            branch_point,
            request_root,
            proposal_root,
            observation_root,
            statistics,
            continuations,
        })
    }

    /// Returns the semantic branch point.
    #[must_use]
    pub const fn branch_point(&self) -> BranchPointId {
        self.branch_point
    }

    /// Returns the request-fact root used to derive this projection.
    #[must_use]
    pub const fn request_root(&self) -> ContentId {
        self.request_root
    }

    /// Returns the proposal-fact root used to derive this projection.
    #[must_use]
    pub const fn proposal_root(&self) -> ContentId {
        self.proposal_root
    }

    /// Returns the observation root used to derive this projection.
    #[must_use]
    pub const fn observation_root(&self) -> ContentId {
        self.observation_root
    }

    /// Returns derived exact statistics.
    #[must_use]
    pub const fn statistics(&self) -> ExpansionStatistics {
        self.statistics
    }

    /// Returns request continuation states in canonical request-ID order.
    #[must_use]
    pub const fn continuations(&self) -> &BTreeMap<BranchRequestId, ContinuationState> {
        &self.continuations
    }

    /// Returns strict canonical projection bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict canonical expansion projection.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_exact_record(bytes, "expansion-state-encoded-bytes")
    }

    /// Returns the exact content-derived projection identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ExpansionStateId, CampaignCodecError> {
        ExpansionStateId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::ExpansionState,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("requests".to_owned(), self.request_root),
            ("proposals".to_owned(), self.proposal_root),
            ("observations".to_owned(), self.observation_root),
        ];
        children.extend(
            self.continuations
                .keys()
                .enumerate()
                .map(|(index, request)| {
                    (format!("continuation.{index:08x}"), request.content_id())
                }),
        );
        children
    }
}

impl Canonical for ExpansionState {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.branch_point.encode(encoder);
        Canonical::encode(&self.request_root, encoder);
        Canonical::encode(&self.proposal_root, encoder);
        Canonical::encode(&self.observation_root, encoder);
        self.statistics.encode(encoder);
        self.continuations.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            BranchPointId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ExpansionStatistics::decode(decoder)?,
            decoder.map_bounded(MAX_CONTINUATIONS, "expansion-continuation-count")?,
        )
    }
}
