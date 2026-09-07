//! Snapshot-bound fixed-point guidance supplied to pure planner engines.
//!
//! The coordinator constructs these records from authenticated repository
//! projections. The record repeats the exact offer tuple, domain semantics,
//! and decomposed PUCT input, including exact objective reward, so an
//! authority-free planner can validate its interpretation and derive the score
//! using the by-value active policy.

use super::*;

const MAX_PLANNER_CANDIDATE_GUIDANCE_BYTES: usize = 64 * 1024;
const MAX_PLANNER_CANDIDATE_FINDING_KINDS: usize = 3;
const PLANNER_CANDIDATE_GUIDANCE_SCHEMA_VERSION: u32 = 2;

/// Maximum unique canonical choice-domain bytes resolved for one guidance batch.
pub const MAX_PLANNER_GUIDANCE_DOMAIN_BYTES: usize = 128 * 1024 * 1024;

/// Exact owner-built guidance for one Ready planner candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerCandidateGuidance {
    schema_version: u32,
    input_view: CampaignViewId,
    policy: CampaignPolicyId,
    position: PlanningScanPosition,
    domain: ChoiceDomainId,
    domain_semantics: ChoiceDomainSemanticId,
    value: ChoiceValue,
    ordinal: u64,
    edge: BranchEdgeId,
    statistics: PuctEdgeStatistics,
    novelty_events: u64,
    objective_reward_micros: i64,
    finding_events: BTreeMap<FindingKind, u64>,
}

impl PlannerCandidateGuidance {
    /// Builds one structurally complete candidate-guidance record.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the ordinal is zero, the edge does
    /// not derive from the point/domain/value tuple, evidence counts disagree
    /// with the PUCT predicates, a legacy record carries objective reward,
    /// finding counts are empty or oversized, or the canonical record exceeds
    /// 64 KiB.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        input_view: CampaignViewId,
        policy: CampaignPolicyId,
        position: PlanningScanPosition,
        domain: ChoiceDomainId,
        domain_semantics: ChoiceDomainSemanticId,
        value: ChoiceValue,
        ordinal: u64,
        edge: BranchEdgeId,
        statistics: PuctEdgeStatistics,
        novelty_events: u64,
        objective_reward_micros: i64,
        finding_events: BTreeMap<FindingKind, u64>,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_for_schema(
            PLANNER_CANDIDATE_GUIDANCE_SCHEMA_VERSION,
            input_view,
            policy,
            position,
            domain,
            domain_semantics,
            value,
            ordinal,
            edge,
            statistics,
            novelty_events,
            objective_reward_micros,
            finding_events,
        )
    }

    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_schema(
        schema_version: u32,
        input_view: CampaignViewId,
        policy: CampaignPolicyId,
        position: PlanningScanPosition,
        domain: ChoiceDomainId,
        domain_semantics: ChoiceDomainSemanticId,
        value: ChoiceValue,
        ordinal: u64,
        edge: BranchEdgeId,
        statistics: PuctEdgeStatistics,
        novelty_events: u64,
        objective_reward_micros: i64,
        finding_events: BTreeMap<FindingKind, u64>,
    ) -> Result<Self, CampaignCodecError> {
        if !matches!(
            schema_version,
            1 | PLANNER_CANDIDATE_GUIDANCE_SCHEMA_VERSION
        ) || schema_version == 1 && objective_reward_micros != 0
            || ordinal == 0
            || edge
                != crate::Selection::campaign_edge_id(
                    position.branch_point(),
                    domain_semantics,
                    &value,
                )
            || statistics.is_novel() != (novelty_events != 0)
            || finding_events.len() > MAX_PLANNER_CANDIDATE_FINDING_KINDS
            || finding_events.values().any(|count| *count == 0)
            || statistics.edge_visits() == 0
                && (objective_reward_micros != 0 || !finding_events.is_empty())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner candidate guidance has inconsistent edge or evidence",
            });
        }
        let value = Self {
            schema_version,
            input_view,
            policy,
            position,
            domain,
            domain_semantics,
            value,
            ordinal,
            edge,
            statistics,
            novelty_events,
            objective_reward_micros,
            finding_events,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_PLANNER_CANDIDATE_GUIDANCE_BYTES,
            "planner-candidate-guidance-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the exact planning view from which guidance was projected.
    #[must_use]
    pub const fn input_view(&self) -> CampaignViewId {
        self.input_view
    }

    /// Returns the active policy that interprets the statistics.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the served frontier position.
    #[must_use]
    pub const fn position(&self) -> PlanningScanPosition {
        self.position
    }

    /// Returns the exact offered domain.
    #[must_use]
    pub const fn domain(&self) -> ChoiceDomainId {
        self.domain
    }

    /// Returns the authenticated semantic domain used by edge derivation.
    #[must_use]
    pub const fn domain_semantics(&self) -> ChoiceDomainSemanticId {
        self.domain_semantics
    }

    /// Returns the offered legal value.
    #[must_use]
    pub const fn value(&self) -> &ChoiceValue {
        &self.value
    }

    /// Returns the request-local one-based proposal ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Returns the semantic edge receiving this score.
    #[must_use]
    pub const fn edge(&self) -> BranchEdgeId {
        self.edge
    }

    /// Returns exact decomposed fixed-point statistics.
    #[must_use]
    pub const fn statistics(&self) -> PuctEdgeStatistics {
        self.statistics
    }

    /// Returns owner-derived globally unique coverage-event count.
    #[must_use]
    pub const fn novelty_events(&self) -> u64 {
        self.novelty_events
    }

    /// Returns the exact owner-derived scalar-objective reward in millionths.
    #[must_use]
    pub const fn objective_reward_micros(&self) -> i64 {
        self.objective_reward_micros
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(crate) const fn current_schema_version() -> u32 {
        PLANNER_CANDIDATE_GUIDANCE_SCHEMA_VERSION
    }

    /// Returns owner-verified finding occurrences by closed finding class.
    #[must_use]
    pub const fn finding_events(&self) -> &BTreeMap<FindingKind, u64> {
        &self.finding_events
    }

    /// Validates this record against one exact offer and active policy, then
    /// returns its derived fixed-point score.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the offer tuple, policy/view basis,
    /// closed finding weights, objective/finding reward sum, or PUCT score
    /// input disagrees.
    pub fn validate_for(
        &self,
        offer: &Proposal,
        policy: &crate::CampaignPolicy,
        input_view: CampaignViewId,
    ) -> Result<PuctScore, CampaignCodecError> {
        if policy.id()? != self.policy
            || input_view != self.input_view
            || offer.policy() != self.policy
            || offer.guidance_basis() != self.input_view
            || offer.branch_point() != self.position.branch_point()
            || offer.request() != self.position.source()
            || offer.domain() != self.domain
            || offer.value() != &self.value
            || offer.ordinal() != self.ordinal
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner candidate guidance disagrees with offer basis",
            });
        }
        self.score_for_policy(policy, input_view)
    }

    pub(crate) fn score_for_policy(
        &self,
        policy: &crate::CampaignPolicy,
        input_view: CampaignViewId,
    ) -> Result<PuctScore, CampaignCodecError> {
        let crate::ExplorerPolicy::TreeSearch { puct, .. } = policy.explorer() else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner candidate guidance requires tree-search policy",
            });
        };
        if policy.id()? != self.policy || input_view != self.input_view {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner candidate guidance disagrees with policy or view",
            });
        }
        let reward = self
            .finding_events
            .iter()
            .try_fold(0_u128, |total, (kind, count)| {
                let weight = policy
                    .guidance()
                    .get(kind.guidance_signal())
                    .map_or(0, |weight| weight.weight_micros());
                if weight == 0 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "planner candidate guidance uses an unweighted finding class",
                    });
                }
                Ok(total.saturating_add(u128::from(weight).saturating_mul(u128::from(*count))))
            })?;
        let reward = self
            .objective_reward_micros
            .saturating_add(reward.min(u128::from(i64::MAX.unsigned_abs())) as i64);
        if reward != self.statistics.reward_sum_micros() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner candidate guidance reward disagrees with objective or finding evidence",
            });
        }
        PuctScore::derive(*puct, self.statistics)
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded guidance record.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, inconsistent,
    /// or oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_PLANNER_CANDIDATE_GUIDANCE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-candidate-guidance-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the content-derived guidance identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if strict envelope construction fails.
    pub fn id(&self) -> Result<PlannerCandidateGuidanceId, CampaignCodecError> {
        PlannerCandidateGuidanceId::from_content_id(
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::PlannerCandidateGuidance,
                self.schema_version,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        vec![
            ("input-view", self.input_view.content_id()),
            ("policy", self.policy.content_id()),
            ("request", self.position.source().content_id()),
            ("domain", self.domain.content_id()),
        ]
    }
}

impl Canonical for PlannerCandidateGuidance {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.input_view.encode(encoder);
        self.policy.encode(encoder);
        self.position.encode(encoder);
        self.domain.encode(encoder);
        self.domain_semantics.encode(encoder);
        self.value.encode(encoder);
        self.ordinal.encode(encoder);
        self.edge.encode(encoder);
        self.statistics.encode(encoder);
        self.novelty_events.encode(encoder);
        if self.schema_version >= 2 {
            self.objective_reward_micros.encode(encoder);
        }
        self.finding_events.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(
            schema_version,
            1 | PLANNER_CANDIDATE_GUIDANCE_SCHEMA_VERSION
        ) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported planner candidate guidance schema version",
            });
        }
        let input_view = CampaignViewId::decode(decoder)?;
        let policy = CampaignPolicyId::decode(decoder)?;
        let position = PlanningScanPosition::decode(decoder)?;
        let domain = ChoiceDomainId::decode(decoder)?;
        let domain_semantics = ChoiceDomainSemanticId::decode(decoder)?;
        let value = ChoiceValue::decode(decoder)?;
        let ordinal = u64::decode(decoder)?;
        let edge = BranchEdgeId::decode(decoder)?;
        let statistics = PuctEdgeStatistics::decode(decoder)?;
        let novelty_events = u64::decode(decoder)?;
        let objective_reward_micros = if schema_version >= 2 {
            i64::decode(decoder)?
        } else {
            0
        };
        let finding_events = decoder.map_bounded_by(
            MAX_PLANNER_CANDIDATE_FINDING_KINDS,
            "planner-candidate-guidance-finding-count",
            FindingKind::decode,
            u64::decode,
        )?;
        Self::new_for_schema(
            schema_version,
            input_view,
            policy,
            position,
            domain,
            domain_semantics,
            value,
            ordinal,
            edge,
            statistics,
            novelty_events,
            objective_reward_micros,
            finding_events,
        )
    }
}
