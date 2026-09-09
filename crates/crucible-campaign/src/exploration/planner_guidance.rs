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

/// One immutable sibling cohort for Beam survival.
///
/// A request cohort contains the child configurations produced by one exact
/// parent, opportunity, and candidate source. A standalone cohort covers a
/// discovery or savepoint-continuation attempt that has no producing proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlannerBeamBarrier {
    /// A configuration reached without a producing branch request.
    Standalone {
        /// Exact execution attempt that reached the configuration.
        attempt: crate::AttemptId,
    },
    /// Sibling configurations produced by one exact branch request.
    Request {
        /// Request whose admitted proposals define the complete cohort.
        request: crate::BranchRequestId,
    },
}

impl PlannerBeamBarrier {
    pub(crate) const fn standalone(attempt: crate::AttemptId) -> Self {
        Self::Standalone { attempt }
    }

    pub(crate) const fn request(request: crate::BranchRequestId) -> Self {
        Self::Request { request }
    }
}

impl Canonical for PlannerBeamBarrier {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Standalone { attempt } => {
                encoder.u8(0);
                attempt.encode(encoder);
            }
            Self::Request { request } => {
                encoder.u8(1);
                request.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::standalone(crate::AttemptId::decode(decoder)?)),
            1 => Ok(Self::request(crate::BranchRequestId::decode(decoder)?)),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "planner-beam-barrier",
                tag,
            }),
        }
    }
}

/// Counts explicit terminal reasons excluded while closing a Beam cohort.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlannerBeamClosureSummary {
    operator_cancelled: u64,
    permanently_incompatible: u64,
    invalid_input: u64,
    unauthorized: u64,
    terminal_worker_failure: u64,
}

impl PlannerBeamClosureSummary {
    pub(crate) fn record(
        &mut self,
        disposition: crate::NonModeledAttemptDisposition,
    ) -> Result<(), CampaignCodecError> {
        let count = match disposition {
            crate::NonModeledAttemptDisposition::OperatorCancelled => &mut self.operator_cancelled,
            crate::NonModeledAttemptDisposition::PermanentlyIncompatible => {
                &mut self.permanently_incompatible
            }
            crate::NonModeledAttemptDisposition::InvalidInput => &mut self.invalid_input,
            crate::NonModeledAttemptDisposition::Unauthorized => &mut self.unauthorized,
            crate::NonModeledAttemptDisposition::TerminalWorkerFailure => {
                &mut self.terminal_worker_failure
            }
        };
        *count = count
            .checked_add(1)
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "planner-beam-non-modeled-attempt-count",
            })?;
        Ok(())
    }

    /// Returns the total number of explicitly closed non-modeled attempts.
    #[must_use]
    pub fn total(self) -> Option<u64> {
        [
            self.operator_cancelled,
            self.permanently_incompatible,
            self.invalid_input,
            self.unauthorized,
            self.terminal_worker_failure,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
    }
}

impl Canonical for PlannerBeamClosureSummary {
    fn encode(&self, encoder: &mut Encoder) {
        self.operator_cancelled.encode(encoder);
        self.permanently_incompatible.encode(encoder);
        self.invalid_input.encode(encoder);
        self.unauthorized.encode(encoder);
        self.terminal_worker_failure.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let value = Self {
            operator_cancelled: u64::decode(decoder)?,
            permanently_incompatible: u64::decode(decoder)?,
            invalid_input: u64::decode(decoder)?,
            unauthorized: u64::decode(decoder)?,
            terminal_worker_failure: u64::decode(decoder)?,
        };
        value.total().ok_or(CampaignCodecError::LimitExceeded {
            limit: "planner-beam-non-modeled-attempt-count",
        })?;
        Ok(value)
    }
}

/// Owner-recomputed closure state for one Beam sibling cohort.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannerBeamCohortState {
    /// The producing request can still issue or await more candidates.
    AwaitingRequestClosure(crate::ContinuationState),
    /// Admitted sibling attempts still lack a modeled or terminal result.
    AwaitingAttempts(u64),
    /// Modeled sibling observations still lack a policy evaluation.
    AwaitingEvaluations(u64),
    /// The closed cohort exceeds the exact ranking evidence bound.
    CohortLimitExceeded(u64),
    /// Every modeled observation was intervention-derived and excluded.
    InterventionExcluded(u64),
    /// The immutable cohort has one replayed survivor decision.
    Settled(SurvivorSelectionId),
    /// The cohort settled after excluding intervention-derived observations.
    SettledWithInterventionExclusions {
        /// Replayed survivor decision over the eligible observations.
        selection: SurvivorSelectionId,
        /// Number of intervention-derived observations excluded from ranking.
        excluded: u64,
    },
}

impl PlannerBeamCohortState {
    /// Returns the immutable survivor decision after the cohort settles.
    #[must_use]
    pub const fn selection(&self) -> Option<SurvivorSelectionId> {
        match self {
            Self::Settled(selection)
            | Self::SettledWithInterventionExclusions { selection, .. } => Some(*selection),
            Self::AwaitingRequestClosure(_)
            | Self::AwaitingAttempts(_)
            | Self::AwaitingEvaluations(_)
            | Self::CohortLimitExceeded(_)
            | Self::InterventionExcluded(_) => None,
        }
    }

    /// Returns the number of intervention observations excluded from ranking.
    #[must_use]
    pub const fn intervention_exclusions(&self) -> u64 {
        match self {
            Self::InterventionExcluded(excluded)
            | Self::SettledWithInterventionExclusions { excluded, .. } => *excluded,
            Self::AwaitingRequestClosure(_)
            | Self::AwaitingAttempts(_)
            | Self::AwaitingEvaluations(_)
            | Self::CohortLimitExceeded(_)
            | Self::Settled(_) => 0,
        }
    }
}

impl Canonical for PlannerBeamCohortState {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::AwaitingRequestClosure(state) => {
                encoder.u8(0);
                state.encode(encoder);
            }
            Self::AwaitingAttempts(count) => {
                encoder.u8(1);
                count.encode(encoder);
            }
            Self::AwaitingEvaluations(count) => {
                encoder.u8(2);
                count.encode(encoder);
            }
            Self::CohortLimitExceeded(count) => {
                encoder.u8(3);
                count.encode(encoder);
            }
            Self::Settled(selection) => {
                encoder.u8(4);
                selection.encode(encoder);
            }
            Self::InterventionExcluded(count) => {
                encoder.u8(5);
                count.encode(encoder);
            }
            Self::SettledWithInterventionExclusions {
                selection,
                excluded,
            } => {
                encoder.u8(6);
                selection.encode(encoder);
                excluded.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::AwaitingRequestClosure(
                crate::ContinuationState::decode(decoder)?,
            )),
            1 => {
                let count = u64::decode(decoder)?;
                if count == 0 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "Beam pending-attempt count is zero",
                    });
                }
                Ok(Self::AwaitingAttempts(count))
            }
            2 => {
                let count = u64::decode(decoder)?;
                if count == 0 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "Beam pending-evaluation count is zero",
                    });
                }
                Ok(Self::AwaitingEvaluations(count))
            }
            3 => {
                let count = u64::decode(decoder)?;
                if count <= crate::MAX_SURVIVOR_CANDIDATES as u64 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "Beam over-limit cohort count is within the ranking bound",
                    });
                }
                Ok(Self::CohortLimitExceeded(count))
            }
            4 => Ok(Self::Settled(SurvivorSelectionId::decode(decoder)?)),
            5 => {
                let count = u64::decode(decoder)?;
                if count == 0 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "Beam intervention-exclusion count is zero",
                    });
                }
                Ok(Self::InterventionExcluded(count))
            }
            6 => {
                let selection = SurvivorSelectionId::decode(decoder)?;
                let excluded = u64::decode(decoder)?;
                if excluded == 0 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "Beam intervention-exclusion count is zero",
                    });
                }
                Ok(Self::SettledWithInterventionExclusions {
                    selection,
                    excluded,
                })
            }
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "planner-beam-cohort-state",
                tag,
            }),
        }
    }
}

/// Snapshot-bound Beam membership for one planner scan position.
///
/// The owner ties the served request to its exact parent configuration and
/// producing sibling cohort. The cohort state explains whether candidate
/// generation, execution, or objective evaluation still blocks a durable
/// selection. Explicit terminal attempt dispositions are counted separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerBeamCandidate {
    schema_version: u32,
    input_view: CampaignViewId,
    policy: CampaignPolicyId,
    position: PlanningScanPosition,
    parent: ConfigurationArtifactId,
    configuration: crate::ConfigurationId,
    barrier: PlannerBeamBarrier,
    cohort_state: PlannerBeamCohortState,
    closed_attempts: PlannerBeamClosureSummary,
}

impl PlannerBeamCandidate {
    pub(crate) fn new(
        input_view: CampaignViewId,
        policy: CampaignPolicyId,
        position: PlanningScanPosition,
        parent: ConfigurationArtifactId,
        configuration: crate::ConfigurationId,
        barrier: PlannerBeamBarrier,
        cohort_state: PlannerBeamCohortState,
        closed_attempts: PlannerBeamClosureSummary,
    ) -> Result<Self, CampaignCodecError> {
        let schema_version = if cohort_state.intervention_exclusions() == 0 {
            RECORD_SCHEMA_VERSION
        } else {
            2
        };
        let value = Self {
            schema_version,
            input_view,
            policy,
            position,
            parent,
            configuration,
            barrier,
            cohort_state,
            closed_attempts,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_PLANNER_CANDIDATE_GUIDANCE_BYTES,
            "planner-beam-candidate-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the exact planning view from which membership was projected.
    #[must_use]
    pub const fn input_view(&self) -> CampaignViewId {
        self.input_view
    }

    /// Returns the active policy used for survivor ranking.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the served frontier position.
    #[must_use]
    pub const fn position(&self) -> PlanningScanPosition {
        self.position
    }

    /// Returns the exact parent configuration artifact named by the request.
    #[must_use]
    pub const fn parent(&self) -> ConfigurationArtifactId {
        self.parent
    }

    /// Returns the semantic parent configuration ranked at the barrier.
    #[must_use]
    pub const fn configuration(&self) -> crate::ConfigurationId {
        self.configuration
    }

    /// Returns the exact barrier group whose width applies to this candidate.
    #[must_use]
    pub const fn barrier(&self) -> &PlannerBeamBarrier {
        &self.barrier
    }

    /// Returns the exact closure state of the producing sibling cohort.
    #[must_use]
    pub const fn cohort_state(&self) -> &PlannerBeamCohortState {
        &self.cohort_state
    }

    /// Returns the replayed survivor decision after the cohort settles.
    #[must_use]
    pub const fn selection(&self) -> Option<SurvivorSelectionId> {
        self.cohort_state.selection()
    }

    /// Returns terminal non-modeled attempt counts excluded from ranking.
    #[must_use]
    pub const fn closed_attempts(&self) -> PlannerBeamClosureSummary {
        self.closed_attempts
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded Beam candidate projection.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_PLANNER_CANDIDATE_GUIDANCE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-beam-candidate-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the content-derived projection identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if strict envelope construction fails.
    pub fn id(&self) -> Result<PlannerBeamCandidateId, CampaignCodecError> {
        PlannerBeamCandidateId::from_content_id(
            crate::ObjectEnvelope::for_beam_candidate(self)?.content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        let mut children = vec![
            ("input-view", self.input_view.content_id()),
            ("policy", self.policy.content_id()),
            ("request", self.position.source().content_id()),
            ("parent", self.parent.content_id()),
        ];
        match self.barrier {
            PlannerBeamBarrier::Standalone { attempt } => {
                children.push(("cohort-attempt", attempt.content_id()));
            }
            PlannerBeamBarrier::Request { request } => {
                children.push(("cohort-request", request.content_id()));
            }
        }
        if let Some(selection) = self.selection() {
            children.push(("selection", selection.content_id()));
        }
        children
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Canonical for PlannerBeamCandidate {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.input_view.encode(encoder);
        self.policy.encode(encoder);
        self.position.encode(encoder);
        self.parent.encode(encoder);
        self.configuration.encode(encoder);
        self.barrier.encode(encoder);
        self.cohort_state.encode(encoder);
        self.closed_attempts.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(schema_version, 1 | 2) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported planner-Beam-candidate schema version",
            });
        }
        let value = Self::new(
            CampaignViewId::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
            PlanningScanPosition::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            crate::ConfigurationId::decode(decoder)?,
            PlannerBeamBarrier::decode(decoder)?,
            PlannerBeamCohortState::decode(decoder)?,
            PlannerBeamClosureSummary::decode(decoder)?,
        )?;
        if value.schema_version != schema_version {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner-Beam-candidate schema disagrees with cohort state",
            });
        }
        Ok(value)
    }
}
