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
    /// Source remains open but is not currently eligible to yield.
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
    /// Distinct admitted semantic attempts rooted at this branch point.
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
    source_snapshot: CampaignSnapshotId,
    input_view: CampaignViewId,
    branch_point: BranchPointId,
    request_root: ContentId,
    proposal_root: ContentId,
    admission_root: ContentId,
    observation_root: ContentId,
    statistics: ExpansionStatistics,
    page_after: Option<BranchRequestId>,
    page_size: u32,
    next_after: Option<BranchRequestId>,
    continuations: BTreeMap<BranchRequestId, ContinuationState>,
}

impl ExpansionState {
    /// Builds one bounded page over snapshot-derived homogeneous roots.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a root is not a Merkle node, the page
    /// size is outside 1 through 10,000, the continuation map exceeds the page
    /// size, or the next cursor is not the page's last request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_snapshot: CampaignSnapshotId,
        input_view: CampaignViewId,
        branch_point: BranchPointId,
        request_root: ContentId,
        proposal_root: ContentId,
        admission_root: ContentId,
        observation_root: ContentId,
        statistics: ExpansionStatistics,
        page_after: Option<BranchRequestId>,
        page_size: u32,
        next_after: Option<BranchRequestId>,
        continuations: BTreeMap<BranchRequestId, ContinuationState>,
    ) -> Result<Self, CampaignCodecError> {
        let page_size =
            usize::try_from(page_size).map_err(|_| CampaignCodecError::InvalidValue {
                reason: "expansion page size is invalid",
            })?;
        if [
            request_root,
            proposal_root,
            admission_root,
            observation_root,
        ]
        .iter()
        .any(|id| id.kind() != crucible_cas::content_store::ObjectKind::MerkleNode)
            || page_size == 0
            || page_size > MAX_EXPANSION_PAGE_ITEMS
            || continuations.len() > page_size
            || continuations.len() > MAX_CONTINUATIONS
            || next_after.is_some_and(|next| {
                continuations.last_key_value().map(|entry| *entry.0) != Some(next)
            })
            || (continuations.is_empty() && next_after.is_some())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "expansion state has invalid roots, page bounds, or cursor",
            });
        }
        Ok(Self {
            schema_version: EXPANSION_STATE_SCHEMA_VERSION,
            source_snapshot,
            input_view,
            branch_point,
            request_root,
            proposal_root,
            admission_root,
            observation_root,
            statistics,
            page_after,
            page_size: page_size as u32,
            next_after,
            continuations,
        })
    }

    /// Returns the exact campaign snapshot from which this page was projected.
    #[must_use]
    pub const fn source_snapshot(&self) -> CampaignSnapshotId {
        self.source_snapshot
    }

    /// Returns the complete planning view derived from the source snapshot.
    #[must_use]
    pub const fn input_view(&self) -> CampaignViewId {
        self.input_view
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

    /// Returns the homogeneous attempt-admission projection root.
    #[must_use]
    pub const fn admission_root(&self) -> ContentId {
        self.admission_root
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

    /// Returns the exclusive request cursor that began this page.
    #[must_use]
    pub const fn page_after(&self) -> Option<BranchRequestId> {
        self.page_after
    }

    /// Returns the maximum continuation count requested for this page.
    #[must_use]
    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    /// Returns the exclusive cursor for the next page, or `None` at EOF.
    #[must_use]
    pub const fn next_after(&self) -> Option<BranchRequestId> {
        self.next_after
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
            (
                "source-snapshot".to_owned(),
                self.source_snapshot.content_id(),
            ),
            ("input-view".to_owned(), self.input_view.content_id()),
            ("requests".to_owned(), self.request_root),
            ("proposals".to_owned(), self.proposal_root),
            ("admissions".to_owned(), self.admission_root),
            ("observations".to_owned(), self.observation_root),
        ];
        if let Some(after) = self.page_after {
            children.push(("page-after".to_owned(), after.content_id()));
        }
        if let Some(after) = self.next_after {
            children.push(("next-after".to_owned(), after.content_id()));
        }
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
        self.source_snapshot.encode(encoder);
        self.input_view.encode(encoder);
        self.branch_point.encode(encoder);
        Canonical::encode(&self.request_root, encoder);
        Canonical::encode(&self.proposal_root, encoder);
        Canonical::encode(&self.admission_root, encoder);
        Canonical::encode(&self.observation_root, encoder);
        self.statistics.encode(encoder);
        self.page_after.encode(encoder);
        self.page_size.encode(encoder);
        self.next_after.encode(encoder);
        self.continuations.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema_version(u32::decode(decoder)?, EXPANSION_STATE_SCHEMA_VERSION)?;
        Self::new(
            CampaignSnapshotId::decode(decoder)?,
            CampaignViewId::decode(decoder)?,
            BranchPointId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ExpansionStatistics::decode(decoder)?,
            Option::decode(decoder)?,
            u32::decode(decoder)?,
            Option::decode(decoder)?,
            decoder.map_bounded(MAX_CONTINUATIONS, "expansion-continuation-count")?,
        )
    }
}
