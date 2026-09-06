//! Owner-recomputed, snapshot-bound campaign projection pages.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use num_bigint::BigUint;

use super::*;
use crate::{ChoiceValue, IntegerDomain, IntegerRepresentation, IntegerValue};

mod branch;

const PROJECTION_SCAN_PAGE_ITEMS: usize = 10_000;
const MAX_STATIC_GENERATOR_CANDIDATES: usize = 512;
const MAX_WEIGHTED_CATEGORICAL_REJECTION_DRAWS: u64 = 256;

struct FiniteExpansionInputs {
    requests: ContentId,
    proposals: ContentId,
    admissions: ContentId,
    admitted_children: u64,
    completed_visits: u64,
}

struct BranchCreditedObservation {
    observation: ObservationId,
    edge: crate::BranchEdgeId,
    coverage: crate::CoverageProjectionId,
}

struct BranchEdgeVisitEvidence {
    statistics: crate::BranchEdgeVisitStatistics,
    prior_weights: BTreeMap<crate::BranchEdgeId, u64>,
    observations: Vec<BranchCreditedObservation>,
}

#[derive(Default)]
struct BranchCoverageGuidance {
    novelty_events: BTreeMap<crate::BranchEdgeId, u64>,
    rarity_weights: BTreeMap<crate::BranchEdgeId, u64>,
}

#[derive(Clone, Copy)]
struct AttemptProposalPrior {
    admission_ordinal: AdmissionOrdinal,
    raw_weight: u64,
}

#[derive(Default)]
pub(super) struct PlannerCandidateProjectionCache {
    requests: BTreeMap<BranchRequestId, Arc<BranchRequest>>,
    domains: BTreeMap<crate::ChoiceDomainId, Arc<ChoiceDomain>>,
    domain_bytes: usize,
    prospective_priors:
        BTreeMap<(crate::BranchPointId, u64), crate::exploration::BranchProspectivePriorBasis>,
    prior_normalization_visits: usize,
}

#[derive(Default)]
struct BranchEdgeProjectionWork {
    total_credits: u64,
    evidence_bytes: usize,
    prior_cache: BTreeMap<AttemptId, AttemptProposalPrior>,
    prior_request_cache: BTreeMap<BranchRequestId, Arc<BranchRequest>>,
    charged_prior_records: BTreeSet<ContentId>,
}

type BranchFindingEvents = BTreeMap<crate::BranchEdgeId, BTreeMap<crate::FindingKind, u64>>;
type BranchPointFindingEvents = BTreeMap<crate::BranchPointId, BranchFindingEvents>;
type BranchObjectiveRewards = BTreeMap<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, i64>>;

struct MixtureComponentState {
    values: Vec<ChoiceValue>,
    cursor: usize,
    weight: u64,
}

struct ContinuationProgress {
    profile: CandidateSourceProfile,
    proposed: u64,
    pending: bool,
    next_candidate: Option<ChoiceValue>,
}

/// One exact active-policy binding for feedback-sensitive candidate selection.
#[derive(Clone, Copy)]
pub(super) struct CandidateFeedbackProjection<'a> {
    policy: crate::CampaignPolicyId,
    projection: &'a crate::BranchPuctProjection,
}

impl<'a> CandidateFeedbackProjection<'a> {
    /// Binds an owner-built projection to the policy of its source snapshot.
    pub(super) const fn new(
        policy: crate::CampaignPolicyId,
        projection: &'a crate::BranchPuctProjection,
    ) -> Self {
        Self { policy, projection }
    }
}

/// Snapshot roots and optional feedback needed to reproduce one candidate.
pub(super) struct CandidateEnumerationBasis<'a> {
    view: CandidateViewRoots,
    completed_visits: u64,
    additional_previous: &'a [Proposal],
    feedback_projection: Option<CandidateFeedbackProjection<'a>>,
}

impl<'a> CandidateEnumerationBasis<'a> {
    /// Builds one enumeration basis without an in-flight proposal overlay.
    pub(super) const fn new(view: CandidateViewRoots, completed_visits: u64) -> Self {
        Self {
            view,
            completed_visits,
            additional_previous: &[],
            feedback_projection: None,
        }
    }

    /// Adds proposals already validated in the same atomic owner transition.
    pub(super) const fn with_additional_previous(
        mut self,
        additional_previous: &'a [Proposal],
    ) -> Self {
        self.additional_previous = additional_previous;
        self
    }

    /// Adds the exact active-policy projection used by feedback versions 11 through 15.
    pub(super) const fn with_feedback(
        mut self,
        feedback_projection: Option<CandidateFeedbackProjection<'a>>,
    ) -> Self {
        self.feedback_projection = feedback_projection;
        self
    }
}

#[derive(Clone, Copy)]
pub(super) struct CandidateViewRoots {
    exploration: ContentId,
    observations: ContentId,
    corpus: ContentId,
    accounting: ContentId,
}

impl CandidateViewRoots {
    pub(super) const fn from_planning_view(view: &CampaignPlanningView) -> Self {
        Self {
            exploration: view.exploration(),
            observations: view.observations(),
            corpus: view.corpus(),
            accounting: view.accounting(),
        }
    }

    pub(super) const fn from_roots(roots: crate::CampaignRoots) -> Self {
        Self {
            exploration: roots.exploration,
            observations: roots.observations,
            corpus: roots.corpus,
            accounting: roots.accounting,
        }
    }

    pub(super) const fn new(
        exploration: ContentId,
        observations: ContentId,
        corpus: ContentId,
        accounting: ContentId,
    ) -> Self {
        Self {
            exploration,
            observations,
            corpus,
            accounting,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CandidateSourceProfile {
    Static {
        count: u64,
        exhausts_domain: bool,
    },
    ProgressiveInteger {
        count: u64,
        initial_count: u64,
        feedback_interval: u64,
        exhausts_domain: bool,
        score_intervals: bool,
    },
    CorpusMutation,
}

impl CandidateSourceProfile {
    pub(super) const fn count(self) -> Option<u64> {
        match self {
            Self::Static { count, .. } | Self::ProgressiveInteger { count, .. } => Some(count),
            Self::CorpusMutation => None,
        }
    }

    fn available_count(self, completed_visits: u64) -> Result<u64, CampaignRepositoryError> {
        match self {
            Self::Static { count, .. } => Ok(count),
            Self::ProgressiveInteger {
                count,
                initial_count,
                feedback_interval,
                ..
            } => initial_count
                .checked_add(completed_visits / feedback_interval)
                .map(|available| available.min(count))
                .ok_or_else(|| integrity("progressive-generator-availability-overflow")),
            Self::CorpusMutation => Err(integrity(
                "corpus-mutation-availability-requires-candidate-view",
            )),
        }
    }

    fn required_visits(self, proposed: u64) -> Result<Option<u64>, CampaignRepositoryError> {
        let Self::ProgressiveInteger {
            initial_count,
            feedback_interval,
            ..
        } = self
        else {
            return Ok(None);
        };
        if proposed < initial_count {
            return Ok(None);
        }
        proposed
            .checked_sub(initial_count)
            .and_then(|refinements| refinements.checked_add(1))
            .and_then(|refinements| refinements.checked_mul(feedback_interval))
            .map(Some)
            .ok_or_else(|| integrity("progressive-generator-feedback-threshold-overflow"))
    }

    const fn exhausts_at_count(self) -> bool {
        match self {
            Self::Static {
                exhausts_domain, ..
            } => exhausts_domain,
            Self::ProgressiveInteger {
                exhausts_domain, ..
            } => exhausts_domain,
            Self::CorpusMutation => false,
        }
    }

    pub(super) const fn requires_feedback_index(self) -> bool {
        matches!(self, Self::ProgressiveInteger { .. } | Self::CorpusMutation)
    }

    pub(super) const fn scores_intervals(self) -> bool {
        matches!(
            self,
            Self::ProgressiveInteger {
                score_intervals: true,
                ..
            }
        )
    }

    pub(super) const fn scores_interval_at(self, ordinal: u64) -> bool {
        matches!(
            self,
            Self::ProgressiveInteger {
                initial_count,
                score_intervals: true,
                ..
            } if ordinal > initial_count
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RefinementGap {
    lower: u128,
    upper: u128,
}

impl RefinementGap {
    const fn len(self) -> u128 {
        self.upper - self.lower + 1
    }
}

impl Ord for RefinementGap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.len()
            .cmp(&other.len())
            .then_with(|| other.lower.cmp(&self.lower))
    }
}

impl PartialOrd for RefinementGap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Retains one endpoint-mean difference as an unreduced exact rational.
struct ExactMeanDiscontinuity {
    numerator: u128,
    denominator: u128,
}

#[derive(Clone, Copy)]
struct FeedbackEndpoint {
    edge: Option<crate::BranchEdgeId>,
    score_micros: i64,
}

#[derive(Clone, Copy)]
struct FeedbackIntervalTerms {
    landmarks: bool,
    objective_discontinuity: bool,
    novelty_discontinuity: bool,
    finding_discontinuity: bool,
    rarity_discontinuity: bool,
}

impl FeedbackIntervalTerms {
    fn for_implementation(version: u32) -> Self {
        Self {
            landmarks: matches!(
                version,
                crate::LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            ),
            objective_discontinuity: matches!(
                version,
                crate::MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            ),
            novelty_discontinuity: matches!(
                version,
                crate::COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            ),
            finding_discontinuity: matches!(
                version,
                crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            ),
            rarity_discontinuity: version
                == crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        }
    }
}

impl ExactMeanDiscontinuity {
    const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };
}

impl Ord for ExactMeanDiscontinuity {
    fn cmp(&self, other: &Self) -> Ordering {
        // The projection bounds keep every operand small, while `BigUint`
        // keeps cross multiplication exact without adding a hidden overflow
        // condition to the language-neutral interval order.
        (BigUint::from(self.numerator) * BigUint::from(other.denominator))
            .cmp(&(BigUint::from(other.numerator) * BigUint::from(self.denominator)))
    }
}

impl PartialOrd for ExactMeanDiscontinuity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FeedbackRefinementGap {
    gap: RefinementGap,
    rarity_discontinuity: ExactMeanDiscontinuity,
    finding_discontinuity: ExactMeanDiscontinuity,
    novelty_discontinuity: ExactMeanDiscontinuity,
    objective_discontinuity: ExactMeanDiscontinuity,
    producer_landmarks: usize,
    endpoint_score_delta: u64,
}

impl Ord for FeedbackRefinementGap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rarity_discontinuity
            .cmp(&other.rarity_discontinuity)
            .then_with(|| self.finding_discontinuity.cmp(&other.finding_discontinuity))
            .then_with(|| self.novelty_discontinuity.cmp(&other.novelty_discontinuity))
            .then_with(|| {
                self.objective_discontinuity
                    .cmp(&other.objective_discontinuity)
            })
            .then_with(|| self.producer_landmarks.cmp(&other.producer_landmarks))
            .then_with(|| self.endpoint_score_delta.cmp(&other.endpoint_score_delta))
            .then_with(|| self.gap.len().cmp(&other.gap.len()))
            .then_with(|| other.gap.lower.cmp(&self.gap.lower))
    }
}

impl PartialOrd for FeedbackRefinementGap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl CampaignRepository {
    #[cfg(test)]
    pub(super) fn initial_continuation_state(
        &self,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        Ok(match self.candidate_source_profile(request, &domain)? {
            Some(CandidateSourceProfile::CorpusMutation) | None => crate::ContinuationState::Open,
            Some(_) => crate::ContinuationState::Ready,
        })
    }

    pub(super) fn initial_continuation_state_at(
        &self,
        request: &BranchRequest,
        view: CandidateViewRoots,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let Some(profile) = self.candidate_source_profile(request, &domain)? else {
            return Ok(crate::ContinuationState::Open);
        };
        if profile != CandidateSourceProfile::CorpusMutation {
            return Ok(crate::ContinuationState::Ready);
        }
        let completed_visits =
            self.branch_completed_visits(view.observations, request.branch_point())?;
        continuation_state_after_progress(
            profile,
            0,
            false,
            self.corpus_mutation_next_candidate(request, &domain, view, 1)?
                .is_some(),
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    pub(super) fn candidate_source_profile(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<Option<CandidateSourceProfile>, CampaignRepositoryError> {
        if let Some(count) = self.static_candidate_count(request, domain)? {
            let exhausts_domain = !matches!(request.source(), CandidateSource::ModeledGenerated(_))
                || domain.cardinality() <= u128::from(request.budget().maximum_proposals());
            return Ok(Some(CandidateSourceProfile::Static {
                count,
                exhausts_domain,
            }));
        }
        let Some(generator) = request.source().generator() else {
            return Ok(None);
        };
        let spec = self.read_generator(generator.content_id())?;
        if let (
            CandidateGeneratorAlgorithm::MutateNearCorpus { maximum_distance },
            crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
            ChoiceDomain::Integer(_),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        {
            if *maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE {
                return Err(integrity("corpus-mutation-generator-distance-limit"));
            }
            if request.budget().maximum_proposals() > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS
            {
                return Err(integrity("corpus-mutation-generator-proposal-limit"));
            }
            return Ok(Some(CandidateSourceProfile::CorpusMutation));
        }
        if matches!(
            (spec.algorithm(), spec.implementation_version(), domain),
            (
                CandidateGeneratorAlgorithm::MutateNearCorpus { .. },
                crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
        ) {
            return Err(integrity("candidate-generator-domain-family-mismatch"));
        }

        let (
            CandidateGeneratorAlgorithm::ProgressiveInteger {
                initial_strata,
                feedback_interval,
            },
            implementation_version,
            ChoiceDomain::Integer(integer),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        else {
            return Ok(None);
        };
        let score_intervals = match implementation_version {
            crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION => false,
            crate::FEEDBACK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            | crate::LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            | crate::MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            | crate::COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            | crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            | crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION => true,
            _ => return Ok(None),
        };
        if *initial_strata > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA {
            return Err(integrity("progressive-generator-initial-strata-limit"));
        }
        if request.budget().maximum_proposals() > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS
        {
            return Err(integrity("progressive-generator-proposal-limit"));
        }

        let budget = request.budget().maximum_proposals();
        let cardinality = integer.cardinality();
        let count = u64::try_from(cardinality.min(u128::from(budget)))
            .map_err(|_| integrity("candidate-source-cardinality-overflow"))?;
        let initial_count = count.min(u64::from(*initial_strata));
        count
            .checked_sub(initial_count)
            .and_then(|refinements| refinements.checked_mul(*feedback_interval))
            .ok_or_else(|| integrity("progressive-generator-feedback-threshold-overflow"))?;
        Ok(Some(CandidateSourceProfile::ProgressiveInteger {
            count,
            initial_count,
            feedback_interval: *feedback_interval,
            exhausts_domain: cardinality <= u128::from(budget),
            score_intervals,
        }))
    }

    /// Resolves the exact cardinality of a history-independent source.
    ///
    /// `None` means that the source requires a generator owner with cursor or
    /// feedback semantics that this repository checkpoint does not implement.
    pub(super) fn static_candidate_count(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<Option<u64>, CampaignRepositoryError> {
        if let Some(values) = request.source().finite_values() {
            return u64::try_from(values.len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow"));
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => Ok(Some(2)),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => u64::try_from(discrete.alternatives().len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => u64::try_from(
                self.weighted_categorical_candidates(request, discrete, weights)?
                    .len(),
            )
            .map(Some)
            .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => self
                .ordered_mixture_candidates(request, domain, components)?
                .map(|candidates| {
                    u64::try_from(candidates.len())
                        .map_err(|_| integrity("candidate-source-cardinality-overflow"))
                })
                .transpose(),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(_),
            )
            | (
                CandidateGeneratorAlgorithm::WeightedCategorical { .. },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Integer(_),
            )
            | (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::StratifiedInteger { .. },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::LogInteger { .. },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            ) => Err(integrity("candidate-generator-domain-family-mismatch")),
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => u64::try_from(self.boundary_integer_candidates(request, integer)?.len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => stratified_integer_candidate_count(*strata, integer).map(Some),
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => u64::try_from(log_integer_candidates(*base, integer)?.len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => permuted_integer_candidate_count(integer).map(Some),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) if matches!(request.source(), CandidateSource::ModeledGenerated(_)) => {
                modeled_uniform_integer_candidate_count(request, integer).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Resolves one one-based candidate ordinal from a history-independent source.
    pub(super) fn static_candidate_at(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        if ordinal == 0 {
            return Err(integrity("proposal-ordinal-is-not-canonical"));
        }
        if let Some(values) = request.source().finite_values() {
            return values
                .iter()
                .nth(candidate_index(ordinal)?)
                .cloned()
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality"));
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => match ordinal {
                1 => Ok(Some(ChoiceValue::Boolean(false))),
                2 => Ok(Some(ChoiceValue::Boolean(true))),
                _ => Err(integrity("proposal-ordinal-exceeds-source-cardinality")),
            },
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => discrete
                .alternatives()
                .keys()
                .nth(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Discrete)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => self
                .weighted_categorical_candidates(request, discrete, weights)?
                .get(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Discrete)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => self
                .ordered_mixture_candidates(request, domain, components)?
                .ok_or_else(|| integrity("generated-proposal-owner-is-not-implemented"))?
                .get(candidate_index(ordinal)?)
                .cloned()
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(_),
            )
            | (
                CandidateGeneratorAlgorithm::WeightedCategorical { .. },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Integer(_),
            )
            | (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::StratifiedInteger { .. },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::LogInteger { .. },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            ) => Err(integrity("candidate-generator-domain-family-mismatch")),
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => self
                .boundary_integer_candidates(request, integer)?
                .get(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Integer)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => stratified_integer_candidate(*strata, integer, ordinal)
                .map(ChoiceValue::Integer)
                .map(Some),
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => log_integer_candidates(*base, integer)?
                .get(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Integer)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => permuted_integer_candidate(request, integer, ordinal)
                .map(ChoiceValue::Integer)
                .map(Some),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) if matches!(request.source(), CandidateSource::ModeledGenerated(_)) => {
                modeled_uniform_integer_candidate(request, integer, ordinal)
                    .map(ChoiceValue::Integer)
                    .map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Resolves one bounded prefix without repeating source traversal or generation.
    pub(super) fn static_candidate_prefix(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        limit: u64,
    ) -> Result<Vec<ChoiceValue>, CampaignRepositoryError> {
        let limit = usize::try_from(limit)
            .map_err(|_| integrity("static-candidate-prefix-limit-overflow"))?;
        if let Some(values) = request.source().finite_values() {
            return Ok(values.iter().take(limit).cloned().collect());
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        let ordinals = || {
            u64::try_from(limit)
                .map(|limit| 1..=limit)
                .map_err(|_| integrity("static-candidate-prefix-limit-overflow"))
        };
        let candidates = match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => [ChoiceValue::Boolean(false), ChoiceValue::Boolean(true)]
                .into_iter()
                .take(limit)
                .collect(),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => discrete
                .alternatives()
                .keys()
                .take(limit)
                .copied()
                .map(ChoiceValue::Discrete)
                .collect(),
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => self
                .weighted_categorical_candidates(request, discrete, weights)?
                .into_iter()
                .take(limit)
                .map(ChoiceValue::Discrete)
                .collect(),
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => self
                .ordered_mixture_candidates(request, domain, components)?
                .ok_or_else(|| integrity("generated-proposal-owner-is-not-implemented"))?
                .into_iter()
                .take(limit)
                .collect(),
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => self
                .boundary_integer_candidates(request, integer)?
                .into_iter()
                .take(limit)
                .map(ChoiceValue::Integer)
                .collect(),
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => ordinals()?
                .map(|ordinal| {
                    stratified_integer_candidate(*strata, integer, ordinal)
                        .map(ChoiceValue::Integer)
                })
                .collect::<Result<Vec<_>, _>>()?,
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => log_integer_candidates(*base, integer)?
                .into_iter()
                .take(limit)
                .map(ChoiceValue::Integer)
                .collect(),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => ordinals()?
                .map(|ordinal| {
                    permuted_integer_candidate(request, integer, ordinal).map(ChoiceValue::Integer)
                })
                .collect::<Result<Vec<_>, _>>()?,
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) if matches!(request.source(), CandidateSource::ModeledGenerated(_)) => ordinals()?
                .map(|ordinal| {
                    modeled_uniform_integer_candidate(request, integer, ordinal)
                        .map(ChoiceValue::Integer)
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(integrity("static-candidate-prefix-is-not-implemented")),
        };
        Ok(candidates)
    }

    pub(super) fn candidate_at_with_feedback(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
        completed_visits: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        let Some(profile) = self.candidate_source_profile(request, domain)? else {
            return Ok(None);
        };
        let Some(count) = profile.count() else {
            return Ok(None);
        };
        if ordinal == 0 || ordinal > count {
            return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
        }
        if ordinal > profile.available_count(completed_visits)? {
            return Err(integrity("progressive-generator-feedback-is-insufficient"));
        }
        if let Some(value) = self.static_candidate_at(request, domain, ordinal)? {
            return Ok(Some(value));
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        let (
            CandidateGeneratorAlgorithm::ProgressiveInteger { initial_strata, .. },
            crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
            ChoiceDomain::Integer(integer),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        else {
            return Ok(None);
        };
        progressive_integer_candidate(*initial_strata, integer, ordinal)
            .map(ChoiceValue::Integer)
            .map(Some)
    }

    fn corpus_mutation_next_candidate(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        view: CandidateViewRoots,
        ordinal: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        if ordinal == 0 || ordinal > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS {
            return Err(integrity("corpus-mutation-proposal-ordinal-limit"));
        }
        self.expected_candidate_at_view(
            request,
            domain,
            ordinal,
            CandidateEnumerationBasis::new(view, 0),
        )
    }

    pub(super) fn expected_candidate_at_view(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
        basis: CandidateEnumerationBasis<'_>,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        let CandidateEnumerationBasis {
            view,
            completed_visits,
            additional_previous,
            feedback_projection,
        } = basis;
        let Some(profile) = self.candidate_source_profile(request, domain)? else {
            return Ok(None);
        };
        if profile.scores_intervals() {
            let count = profile.count().unwrap_or_default();
            if ordinal == 0 || ordinal > count {
                return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
            }
            if ordinal > profile.available_count(completed_visits)? {
                return Err(integrity("progressive-generator-feedback-is-insufficient"));
            }
            let ChoiceDomain::Integer(integer) = domain else {
                return Err(integrity("candidate-generator-domain-family-mismatch"));
            };
            let generator = request
                .source()
                .generator()
                .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
            let spec = self.read_generator(generator.content_id())?;
            let CandidateGeneratorAlgorithm::ProgressiveInteger { initial_strata, .. } =
                spec.algorithm()
            else {
                return Err(integrity("progressive-generator-basis-mismatch"));
            };
            let terms = FeedbackIntervalTerms::for_implementation(spec.implementation_version());
            if ordinal <= u64::from(*initial_strata).min(count) {
                return stratified_integer_candidate(*initial_strata, integer, ordinal)
                    .map(ChoiceValue::Integer)
                    .map(Some);
            }
            let feedback = feedback_projection
                .ok_or_else(|| integrity("progressive-generator-feedback-projection-is-missing"))?;
            let additional_count = u64::try_from(additional_previous.len())
                .map_err(|_| integrity("progressive-generator-proposal-history-mismatch"))?;
            let base_ordinal = ordinal
                .checked_sub(additional_count)
                .ok_or_else(|| integrity("progressive-generator-proposal-history-mismatch"))?;
            let mut proposed =
                self.proposed_values_before(view.exploration, request.id()?, base_ordinal)?;
            for (index, proposal) in additional_previous.iter().enumerate() {
                let expected_ordinal = base_ordinal
                    .checked_add(u64::try_from(index).map_err(|_| {
                        integrity("progressive-generator-proposal-history-mismatch")
                    })?)
                    .ok_or_else(|| integrity("progressive-generator-proposal-history-mismatch"))?;
                if proposal.request() != request.id()?
                    || proposal.ordinal() != expected_ordinal
                    || !proposed.insert(proposal.value().clone())
                {
                    return Err(integrity("progressive-generator-proposal-history-mismatch"));
                }
            }
            return feedback_progressive_integer_candidate(
                request,
                integer,
                domain.semantic_id(),
                &proposed,
                feedback,
                terms,
            )
            .map(ChoiceValue::Integer)
            .map(Some);
        }
        if profile != CandidateSourceProfile::CorpusMutation {
            return self.candidate_at_with_feedback(request, domain, ordinal, completed_visits);
        }
        if ordinal == 0 || ordinal > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS {
            return Err(integrity("corpus-mutation-proposal-ordinal-limit"));
        }
        let additional_count = u64::try_from(additional_previous.len())
            .map_err(|_| integrity("corpus-mutation-proposal-ordinal-limit"))?;
        let base_ordinal = ordinal
            .checked_sub(additional_count)
            .ok_or_else(|| integrity("corpus-mutation-proposal-history-mismatch"))?;
        let mut proposed =
            self.proposed_values_before(view.exploration, request.id()?, base_ordinal)?;
        for (index, proposal) in additional_previous.iter().enumerate() {
            let expected_ordinal = base_ordinal
                .checked_add(
                    u64::try_from(index)
                        .map_err(|_| integrity("corpus-mutation-proposal-ordinal-limit"))?,
                )
                .ok_or_else(|| integrity("corpus-mutation-proposal-ordinal-limit"))?;
            if proposal.request() != request.id()?
                || proposal.ordinal() != expected_ordinal
                || !proposed.insert(proposal.value().clone())
            {
                return Err(integrity("corpus-mutation-proposal-history-mismatch"));
            }
        }
        Ok(self
            .corpus_mutation_candidates(request, domain, view, None)?
            .into_iter()
            .find(|candidate| !proposed.contains(candidate)))
    }

    fn proposed_values_before(
        &self,
        exploration_root: ContentId,
        request: BranchRequestId,
        ordinal: u64,
    ) -> Result<BTreeSet<ChoiceValue>, CampaignRepositoryError> {
        let mut proposed = BTreeSet::new();
        for prior_ordinal in 1..ordinal {
            let content = self
                .merkle
                .get(
                    exploration_root,
                    proposal_ordinal_key(request, prior_ordinal),
                )?
                .ok_or_else(|| integrity("corpus-mutation-proposal-history-gap"))?;
            let proposal = self.read_proposal(content)?;
            if proposal.request() != request
                || proposal.ordinal() != prior_ordinal
                || self.merkle.get(
                    exploration_root,
                    map_key_content("exploration.proposal", content),
                )? != Some(content)
                || self.merkle.get(
                    exploration_root,
                    proposal_value_key(request, proposal.value()),
                )? != Some(content)
                || !proposed.insert(proposal.value().clone())
            {
                return Err(integrity("corpus-mutation-proposal-history-mismatch"));
            }
        }
        Ok(proposed)
    }

    fn corpus_mutation_candidates(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        view: CandidateViewRoots,
        additional_selection: Option<SelectionId>,
    ) -> Result<Vec<ChoiceValue>, CampaignRepositoryError> {
        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        let (
            CandidateGeneratorAlgorithm::MutateNearCorpus { maximum_distance },
            crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
            ChoiceDomain::Integer(integer),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        else {
            return Err(integrity("corpus-mutation-generator-basis-mismatch"));
        };
        if *maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE
            || request.budget().maximum_proposals() > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS
        {
            return Err(integrity("corpus-mutation-generator-owner-limit"));
        }

        let index = self.merkle.get(
            view.observations,
            branch_credit_index_key(request.branch_point()),
        )?;

        let mut input_bytes = 0_usize;
        let mut selections = Vec::new();
        if let Some(index) = index {
            let entry_count = self.merkle.inspect_shallow(index)?.entry_count();
            if entry_count > crate::CORPUS_MUTATION_GENERATOR_MAX_CREDITS {
                return Err(integrity("corpus-mutation-generator-credit-limit"));
            }
            let limit = usize::try_from(entry_count)
                .map_err(|_| integrity("corpus-mutation-generator-credit-limit"))?;
            let page = self.merkle.scan(index, None, limit)?;
            if page.next_after().is_some() || page.entries().len() != limit {
                return Err(integrity("corpus-mutation-credit-index-scan-mismatch"));
            }
            for (key, content) in page.entries() {
                let credit = self.read_expansion_credit(*content)?;
                input_bytes =
                    charge_corpus_mutation_input(input_bytes, credit.canonical_bytes().len())?;
                if credit.id().as_hash() != *key || credit.branch_point() != request.branch_point()
                {
                    return Err(integrity("corpus-mutation-credit-index-mismatch"));
                }
                let observation = self.decode_observation(credit.observation().content_id())?;
                input_bytes =
                    charge_corpus_mutation_input(input_bytes, observation.canonical_bytes().len())?;
                if self.merkle.get(
                    view.corpus,
                    map_key_hash("corpus.configuration", observation.child().as_hash()),
                )? != Some(observation.child_content().content_id())
                {
                    return Err(integrity("corpus-mutation-observation-is-not-retained"));
                }
                let attempt = self.read_attempt(observation.attempt().content_id())?;
                input_bytes =
                    charge_corpus_mutation_input(input_bytes, attempt.canonical_bytes().len())?;
                let AttemptStart::Branch { selection, .. } = attempt.start() else {
                    continue;
                };
                selections.push(selection);
            }
        }
        if let Some(selection) = additional_selection {
            if selections.len() >= crate::CORPUS_MUTATION_GENERATOR_MAX_CREDITS as usize {
                return Err(integrity("corpus-mutation-generator-credit-limit"));
            }
            selections.push(selection);
        }

        let resolved = self.resolve_selections(&selections)?;
        let mut anchors = BTreeSet::new();
        for resolved in resolved {
            let selection = resolved.selection();
            let crate::SelectionOrigin::CampaignBranch { branch_point, .. } = selection.origin()
            else {
                return Err(integrity("corpus-mutation-selection-origin-mismatch"));
            };
            if branch_point != request.branch_point() {
                continue;
            }
            if selection.opportunity() != request.opportunity()
                || selection.domain() != request.domain()
            {
                return Err(integrity("corpus-mutation-selection-basis-mismatch"));
            }
            let ChoiceValue::Integer(value) = selection.value() else {
                return Err(integrity("corpus-mutation-selection-is-not-integer"));
            };
            anchors.insert(*value);
        }

        let maximum_candidates = usize::try_from(request.budget().maximum_proposals())
            .map_err(|_| integrity("corpus-mutation-generator-proposal-limit"))?;
        corpus_mutation_integer_candidates(integer, &anchors, *maximum_distance, maximum_candidates)
            .map(|values| values.into_iter().map(ChoiceValue::Integer).collect())
    }

    fn weighted_categorical_candidates(
        &self,
        request: &BranchRequest,
        domain: &crate::DiscreteDomain,
        weights: &BTreeMap<crate::AlternativeId, u64>,
    ) -> Result<Vec<crate::AlternativeId>, CampaignRepositoryError> {
        if weights.len() > crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES {
            return Err(integrity("weighted-generator-alternative-limit"));
        }
        if weights
            .keys()
            .any(|alternative| !domain.alternatives().contains_key(alternative))
        {
            return Err(integrity(
                "candidate-generator-discrete-alternative-mismatch",
            ));
        }

        let request_digest = request.id()?.content_id().digest();
        let mut remaining = weights
            .iter()
            .map(|(alternative, weight)| (*alternative, *weight))
            .collect::<Vec<_>>();
        let mut candidates = Vec::with_capacity(remaining.len());
        while !remaining.is_empty() {
            let total_weight = remaining.iter().try_fold(0_u128, |total, (_, weight)| {
                total
                    .checked_add(u128::from(*weight))
                    .ok_or_else(|| integrity("weighted-generator-weight-sum-overflow"))
            })?;
            let draw = weighted_categorical_draw(
                request_digest,
                u64::try_from(candidates.len())
                    .map_err(|_| integrity("candidate-source-cardinality-overflow"))?,
                total_weight,
            )?;
            let mut cumulative = 0_u128;
            let mut selected = None;
            for (index, (_, weight)) in remaining.iter().enumerate() {
                cumulative = cumulative
                    .checked_add(u128::from(*weight))
                    .ok_or_else(|| integrity("weighted-generator-weight-sum-overflow"))?;
                if draw < cumulative {
                    selected = Some(index);
                    break;
                }
            }
            let selected =
                selected.ok_or_else(|| integrity("weighted-generator-draw-is-out-of-range"))?;
            candidates.push(remaining.remove(selected).0);
        }
        Ok(candidates)
    }

    fn ordered_mixture_candidates(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        components: &[crate::WeightedGenerator],
    ) -> Result<Option<Vec<ChoiceValue>>, CampaignRepositoryError> {
        let mut remaining_work = crate::ORDERED_MIXTURE_GENERATOR_MAX_WORK_ITEMS;
        self.ordered_mixture_candidates_with_budget(
            request,
            domain,
            components,
            0,
            &mut remaining_work,
        )
    }

    fn ordered_mixture_candidates_with_budget(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        components: &[crate::WeightedGenerator],
        depth: usize,
        remaining_work: &mut usize,
    ) -> Result<Option<Vec<ChoiceValue>>, CampaignRepositoryError> {
        if depth > crate::ORDERED_MIXTURE_GENERATOR_MAX_DEPTH {
            return Err(integrity("ordered-mixture-generator-depth-limit"));
        }
        let mut states = Vec::with_capacity(components.len());
        for component in components {
            let Some(values) = self.bounded_static_generator_candidates(
                request,
                domain,
                component.generator(),
                depth + 1,
                remaining_work,
            )?
            else {
                return Ok(None);
            };
            states.push(MixtureComponentState {
                values,
                cursor: 0,
                weight: component.weight(),
            });
        }

        let mut emitted = BTreeSet::new();
        let mut candidates = Vec::new();
        while let Some(selected) = next_mixture_component(&states)? {
            charge_mixture_work(remaining_work, 1)?;
            let state = &mut states[selected];
            let value = state
                .values
                .get(state.cursor)
                .cloned()
                .ok_or_else(|| integrity("ordered-mixture-cursor-is-invalid"))?;
            state.cursor += 1;
            if !emitted.insert(value.clone()) {
                continue;
            }
            if candidates.len() == crate::ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES {
                return Err(integrity("ordered-mixture-generator-candidate-limit"));
            }
            candidates.push(value);
        }
        Ok(Some(candidates))
    }

    fn bounded_static_generator_candidates(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        generator: CandidateGeneratorSpecId,
        depth: usize,
        remaining_work: &mut usize,
    ) -> Result<Option<Vec<ChoiceValue>>, CampaignRepositoryError> {
        if depth > crate::ORDERED_MIXTURE_GENERATOR_MAX_DEPTH {
            return Err(integrity("ordered-mixture-generator-depth-limit"));
        }
        let spec = self.read_generator(generator.content_id())?;
        let values = match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => vec![ChoiceValue::Boolean(false), ChoiceValue::Boolean(true)],
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => {
                require_mixture_work_capacity(remaining_work, discrete.alternatives().len())?;
                discrete
                    .alternatives()
                    .keys()
                    .copied()
                    .map(ChoiceValue::Discrete)
                    .collect()
            }
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => self
                .boundary_integer_candidates(request, integer)?
                .into_iter()
                .map(ChoiceValue::Integer)
                .collect(),
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => {
                let count = stratified_integer_candidate_count(*strata, integer)?;
                let count = usize::try_from(count)
                    .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?;
                require_mixture_work_capacity(remaining_work, count)?;
                (1..=count)
                    .map(|ordinal| {
                        let ordinal = u64::try_from(ordinal)
                            .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?;
                        stratified_integer_candidate(*strata, integer, ordinal)
                            .map(ChoiceValue::Integer)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => log_integer_candidates(*base, integer)?
                .into_iter()
                .map(ChoiceValue::Integer)
                .collect(),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => {
                let count = permuted_integer_candidate_count(integer)?;
                let count = usize::try_from(count)
                    .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?;
                require_mixture_work_capacity(remaining_work, count)?;
                (1..=count)
                    .map(|index| {
                        let ordinal = u64::try_from(index)
                            .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?;
                        permuted_integer_candidate(request, integer, ordinal)
                            .map(ChoiceValue::Integer)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => self
                .weighted_categorical_candidates(request, discrete, weights)?
                .into_iter()
                .map(ChoiceValue::Discrete)
                .collect(),
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => {
                return self.ordered_mixture_candidates_with_budget(
                    request,
                    domain,
                    components,
                    depth,
                    remaining_work,
                );
            }
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(_),
            )
            | (
                CandidateGeneratorAlgorithm::WeightedCategorical { .. },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Integer(_),
            )
            | (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::StratifiedInteger { .. },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::LogInteger { .. },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            ) => return Err(integrity("candidate-generator-domain-family-mismatch")),
            _ => return Ok(None),
        };
        charge_mixture_work(remaining_work, values.len())?;
        Ok(Some(values))
    }

    fn boundary_integer_candidates(
        &self,
        request: &BranchRequest,
        domain: &IntegerDomain,
    ) -> Result<Vec<IntegerValue>, CampaignRepositoryError> {
        if domain.landmarks().len() > crate::BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS {
            return Err(integrity("boundary-generator-landmark-limit"));
        }
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let ChoiceValue::Integer(default) = opportunity.default() else {
            return Err(integrity("boundary-generator-default-is-not-integer"));
        };
        let mut values = Vec::new();
        let mut seen = BTreeSet::new();
        push_static_integer_candidate(&mut values, &mut seen, domain, domain.minimum())?;
        push_static_integer_candidate(&mut values, &mut seen, domain, domain.maximum())?;
        push_static_integer_candidate(&mut values, &mut seen, domain, *default)?;
        for landmark in domain.landmarks() {
            push_static_integer_candidate(&mut values, &mut seen, domain, *landmark)?;
        }

        let anchors = values.clone();
        for anchor in anchors {
            if let Some(lower) = integer_step_neighbor(anchor, domain.step(), false) {
                push_static_integer_candidate(&mut values, &mut seen, domain, lower)?;
            }
            if let Some(upper) = integer_step_neighbor(anchor, domain.step(), true) {
                push_static_integer_candidate(&mut values, &mut seen, domain, upper)?;
            }
        }

        match domain.representation() {
            IntegerRepresentation::Unsigned64 => {
                for exponent in 0..64 {
                    if let Some(value) = 1_u64.checked_shl(exponent) {
                        push_static_integer_candidate(
                            &mut values,
                            &mut seen,
                            domain,
                            IntegerValue::Unsigned(value),
                        )?;
                    }
                }
            }
            IntegerRepresentation::Signed64 => {
                for exponent in 0..64 {
                    if exponent < 63 {
                        push_static_integer_candidate(
                            &mut values,
                            &mut seen,
                            domain,
                            IntegerValue::Signed(1_i64 << exponent),
                        )?;
                    }
                    let negative = if exponent == 63 {
                        i64::MIN
                    } else {
                        -(1_i64 << exponent)
                    };
                    push_static_integer_candidate(
                        &mut values,
                        &mut seen,
                        domain,
                        IntegerValue::Signed(negative),
                    )?;
                }
            }
        }
        Ok(values)
    }

    pub(super) fn frontier_index_after(
        &self,
        exploration_root: ContentId,
        projections: &[(
            BranchRequestId,
            crate::BranchPointId,
            crate::ContinuationState,
        )],
        publish: bool,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let Some(frontier_index) = self
            .merkle
            .get(exploration_root, frontier_index_anchor_key())?
        else {
            return Ok(None);
        };
        let mut upserts = BTreeMap::new();
        for (request, branch_point, state) in projections {
            let projection = ContinuationProjection::new(*request, *branch_point, *state);
            let projection_id = projection.id()?;
            if publish {
                let content = self.put_continuation_projection(&projection)?;
                if content != projection_id.content_id() {
                    return Err(integrity("continuation-projection-publication-id-mismatch"));
                }
            }
            upserts.insert(
                frontier_index_order_key(*request),
                projection_id.content_id(),
            );
        }
        if publish {
            let mut root = frontier_index;
            for (key, value) in upserts {
                root = self.merkle.insert(root, key, value)?.content_id();
            }
            Ok(Some(root))
        } else {
            self.merkle
                .root_after_upserts(frontier_index, &upserts)
                .map(Some)
                .map_err(Into::into)
        }
    }

    pub(super) fn branch_request_index_after(
        &self,
        exploration_root: ContentId,
        requests: &[(BranchRequestId, crate::BranchPointId)],
        publish: bool,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let index = match self
            .merkle
            .get(exploration_root, branch_request_index_anchor_key())?
        {
            Some(index) => index,
            None if requests.is_empty() => return Ok(None),
            None => MerkleMap::empty_content_id()?,
        };
        let mut projected_entry_count =
            usize::try_from(self.merkle.inspect_shallow(index)?.entry_count())
                .map_err(|_| integrity("feedback-branch-request-index-limit"))?;
        let mut grouped = BTreeMap::<crate::BranchPointId, Vec<BranchRequestId>>::new();
        for (request, branch_point) in requests {
            grouped.entry(*branch_point).or_default().push(*request);
        }
        let mut index_upserts = BTreeMap::new();
        for (branch_point, branch_requests) in grouped {
            let branch_key = branch_request_index_branch_key(branch_point);
            let existing_branch_root = self.merkle.get(index, branch_key)?;
            let mut branch_root = existing_branch_root.unwrap_or(MerkleMap::empty_content_id()?);
            if existing_branch_root.is_none() {
                projected_entry_count = projected_entry_count
                    .checked_add(1)
                    .ok_or_else(|| integrity("feedback-branch-request-index-limit"))?;
            }
            let upserts = branch_requests
                .into_iter()
                .map(|request| (frontier_index_order_key(request), request.content_id()))
                .collect::<BTreeMap<_, _>>();
            for (key, value) in &upserts {
                if let Some(existing) = self.merkle.get(branch_root, *key)?
                    && existing != *value
                {
                    return Err(integrity("branch-request-point-index-conflict"));
                }
                let request = BranchRequestId::from_content_id(*value)?;
                let membership_key = branch_request_index_membership_key(request);
                if let Some(existing) = self.merkle.get(index, membership_key)? {
                    if existing != *value {
                        return Err(integrity("feedback-branch-request-index-conflict"));
                    }
                } else {
                    projected_entry_count = projected_entry_count
                        .checked_add(1)
                        .ok_or_else(|| integrity("feedback-branch-request-index-limit"))?;
                }
                index_upserts.insert(membership_key, *value);
            }
            branch_root = if publish {
                let mut root = branch_root;
                for (key, value) in upserts {
                    root = self.merkle.insert(root, key, value)?.content_id();
                }
                root
            } else {
                self.merkle.root_after_upserts(branch_root, &upserts)?
            };
            index_upserts.insert(branch_key, branch_root);
        }
        if projected_entry_count > MAX_FEEDBACK_FRONTIER_UPDATES {
            return Err(integrity("feedback-branch-request-index-limit"));
        }
        if publish {
            let mut root = index;
            for (key, value) in index_upserts {
                root = self.merkle.insert(root, key, value)?.content_id();
            }
            Ok(Some(root))
        } else {
            self.merkle
                .root_after_upserts(index, &index_upserts)
                .map(Some)
                .map_err(Into::into)
        }
    }

    /// Returns the bounded authoritative request set indexed at one branch point.
    pub(super) fn branch_point_requests(
        &self,
        exploration_root: ContentId,
        branch_point: crate::BranchPointId,
        remaining: &mut usize,
    ) -> Result<Vec<BranchRequestId>, CampaignRepositoryError> {
        let Some(index) = self
            .merkle
            .get(exploration_root, branch_request_index_anchor_key())?
        else {
            return Ok(Vec::new());
        };
        let index_entry_count = usize::try_from(self.merkle.inspect_shallow(index)?.entry_count())
            .map_err(|_| integrity("feedback-branch-request-index-limit"))?;
        if index_entry_count > MAX_FEEDBACK_FRONTIER_UPDATES {
            return Err(integrity("feedback-branch-request-index-limit"));
        }
        let Some(branch_root) = self
            .merkle
            .get(index, branch_request_index_branch_key(branch_point))?
        else {
            return Ok(Vec::new());
        };
        let entry_count = usize::try_from(self.merkle.inspect_shallow(branch_root)?.entry_count())
            .map_err(|_| integrity("feedback-frontier-update-limit"))?;
        *remaining = remaining
            .checked_sub(entry_count)
            .ok_or_else(|| integrity("feedback-frontier-update-limit"))?;

        let mut requests = Vec::with_capacity(entry_count);
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(branch_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                let request = BranchRequestId::from_content_id(*value)?;
                if *key != frontier_index_order_key(request) {
                    return Err(integrity("branch-request-point-index-mismatch"));
                }
                if self
                    .merkle
                    .get(index, branch_request_index_membership_key(request))?
                    != Some(request.content_id())
                {
                    return Err(integrity("feedback-branch-request-membership-mismatch"));
                }
                requests.push(request);
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if requests.len() != entry_count {
            return Err(integrity("branch-request-point-index-count-mismatch"));
        }
        Ok(requests)
    }

    pub(super) fn validate_frontier_projection(
        &self,
        frontier_index: ContentId,
        request: BranchRequestId,
        branch_point: crate::BranchPointId,
        state: crate::ContinuationState,
    ) -> Result<(), CampaignRepositoryError> {
        let content = self
            .merkle
            .get(frontier_index, frontier_index_order_key(request))?
            .ok_or_else(|| integrity("frontier-index-request-is-missing"))?;
        let projection = self.read_continuation_projection(content)?;
        if projection != ContinuationProjection::new(request, branch_point, state) {
            return Err(integrity("frontier-index-projection-mismatch"));
        }
        Ok(())
    }

    pub(super) fn planner_continuation_projection(
        &self,
        snapshot: &LoadedSnapshot,
        position: crate::PlanningScanPosition,
    ) -> Result<ContinuationProjection, CampaignRepositoryError> {
        let frontier = self
            .merkle
            .get(
                snapshot.snapshot.roots().exploration,
                frontier_index_anchor_key(),
            )?
            .ok_or_else(|| integrity("planner-candidate-frontier-index-is-missing"))?;
        let projection_content = self
            .merkle
            .get(frontier, frontier_index_order_key(position.source()))?
            .ok_or_else(|| integrity("planner-candidate-projection-is-missing"))?;
        let projection = self.read_continuation_projection(projection_content)?;
        if projection.request() != position.source()
            || projection.branch_point() != position.branch_point()
        {
            return Err(integrity("planner-candidate-position-mismatch"));
        }
        Ok(projection)
    }

    pub(super) fn planner_candidate_input(
        &self,
        snapshot: &LoadedSnapshot,
        invocation_id: crate::PlannerInvocationId,
        position: crate::PlanningScanPosition,
        cache: &mut PlannerCandidateProjectionCache,
        feedback_projection: Option<&crate::BranchPuctProjection>,
    ) -> Result<(ContinuationProjection, Option<Proposal>), CampaignRepositoryError> {
        let observations = snapshot.snapshot.roots().observations;
        let candidate_view = CandidateViewRoots::from_roots(snapshot.snapshot.roots());
        let projection = self.planner_continuation_projection(snapshot, position)?;
        let request = match cache.requests.get(&position.source()) {
            Some(request) => Arc::clone(request),
            None => {
                let request = Arc::new(self.read_branch_request(position.source().content_id())?);
                cache
                    .requests
                    .insert(position.source(), Arc::clone(&request));
                request
            }
        };

        let completed_visits =
            self.branch_completed_visits(observations, request.branch_point())?;
        let domain = self.read_planner_guidance_domain(
            request.domain(),
            &mut cache.domains,
            &mut cache.domain_bytes,
        )?;
        if self
            .candidate_source_profile(&request, domain.as_ref())?
            .is_none()
        {
            let expected = ContinuationProjection::new(
                position.source(),
                position.branch_point(),
                crate::ContinuationState::Open,
            );
            if projection != expected {
                return Err(integrity("planner-candidate-frontier-projection-mismatch"));
            }
            return Ok((projection, None));
        }
        let progress = self.continuation_progress(
            candidate_view,
            position.source(),
            &request,
            domain.as_ref(),
        )?;
        let state = continuation_state_after_progress(
            progress.profile,
            progress.proposed,
            progress.pending,
            progress.next_candidate.is_some(),
            request.budget().maximum_proposals(),
            completed_visits,
        )?;
        if projection
            != ContinuationProjection::new(position.source(), position.branch_point(), state)
        {
            return Err(integrity("planner-candidate-frontier-projection-mismatch"));
        }

        let offer = if state == crate::ContinuationState::Ready {
            let ordinal = progress
                .proposed
                .checked_add(1)
                .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?;
            let value = match progress.next_candidate {
                Some(value) => value,
                None => self
                    .expected_candidate_at_view(
                        &request,
                        domain.as_ref(),
                        ordinal,
                        CandidateEnumerationBasis::new(candidate_view, completed_visits)
                            .with_feedback(feedback_projection.map(|projection| {
                                CandidateFeedbackProjection::new(
                                    snapshot.snapshot.active_policy(),
                                    projection,
                                )
                            })),
                    )?
                    .ok_or_else(|| integrity("planner-candidate-enumerator-is-not-implemented"))?,
            };
            Some(Proposal::new(
                position.branch_point(),
                position.source(),
                request.domain(),
                value,
                snapshot.snapshot.active_policy(),
                Some(invocation_id),
                ordinal,
                snapshot.snapshot.planning_view().id()?,
            )?)
        } else {
            None
        };
        Ok((projection, offer))
    }

    fn read_planner_guidance_domain(
        &self,
        domain_id: crate::ChoiceDomainId,
        domain_cache: &mut BTreeMap<crate::ChoiceDomainId, Arc<ChoiceDomain>>,
        domain_bytes: &mut usize,
    ) -> Result<Arc<ChoiceDomain>, CampaignRepositoryError> {
        if let Some(domain) = domain_cache.get(&domain_id) {
            return Ok(Arc::clone(domain));
        }
        let domain = self.read_choice_domain(domain_id.content_id())?;
        if domain.id()? != domain_id {
            return Err(integrity("planner-candidate-guidance-domain-mismatch"));
        }
        *domain_bytes =
            charge_planner_guidance_domain_work(*domain_bytes, domain.canonical_bytes().len())?;
        let domain = Arc::new(domain);
        domain_cache.insert(domain_id, Arc::clone(&domain));
        Ok(domain)
    }
}

fn projection_order_key(id: ContentId) -> CampaignHash {
    CampaignHash::from_bytes(id.digest())
}

fn candidate_index(ordinal: u64) -> Result<usize, CampaignRepositoryError> {
    usize::try_from(ordinal - 1).map_err(|_| integrity("proposal-ordinal-is-not-canonical"))
}

pub(super) fn continuation_state_after_progress(
    profile: CandidateSourceProfile,
    proposed: u64,
    pending: bool,
    has_next_candidate: bool,
    maximum_proposals: u64,
    completed_visits: u64,
) -> Result<crate::ContinuationState, CampaignRepositoryError> {
    if pending {
        return Ok(crate::ContinuationState::Open);
    }
    if profile == CandidateSourceProfile::CorpusMutation {
        if proposed >= maximum_proposals {
            return Ok(crate::ContinuationState::Closed);
        }
        if has_next_candidate {
            return Ok(crate::ContinuationState::Ready);
        }
        let required = completed_visits
            .checked_add(1)
            .ok_or_else(|| integrity("corpus-mutation-feedback-threshold-overflow"))?;
        return Ok(crate::ContinuationState::WaitingForFeedback(
            crate::FeedbackWait::new(completed_visits, required)?,
        ));
    }
    if Some(proposed) == profile.count() {
        return Ok(if profile.exhausts_at_count() {
            crate::ContinuationState::Exhausted
        } else {
            crate::ContinuationState::Closed
        });
    }
    if proposed >= maximum_proposals {
        return Ok(crate::ContinuationState::Closed);
    }
    if proposed < profile.available_count(completed_visits)? {
        return Ok(crate::ContinuationState::Ready);
    }
    let required = profile
        .required_visits(proposed)?
        .ok_or_else(|| integrity("candidate-source-readiness-is-inconsistent"))?;
    Ok(crate::ContinuationState::WaitingForFeedback(
        crate::FeedbackWait::new(completed_visits, required)?,
    ))
}

fn next_mixture_component(
    states: &[MixtureComponentState],
) -> Result<Option<usize>, CampaignRepositoryError> {
    let mut selected = None;
    for (index, state) in states.iter().enumerate() {
        if state.cursor == state.values.len() {
            continue;
        }
        let Some(current) = selected else {
            selected = Some(index);
            continue;
        };
        let current_state = &states[current];
        let state_finish = u128::try_from(
            state
                .cursor
                .checked_add(1)
                .ok_or_else(|| integrity("ordered-mixture-generator-work-limit"))?,
        )
        .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?
        .checked_mul(u128::from(current_state.weight))
        .ok_or_else(|| integrity("ordered-mixture-generator-weight-overflow"))?;
        let current_finish = u128::try_from(
            current_state
                .cursor
                .checked_add(1)
                .ok_or_else(|| integrity("ordered-mixture-generator-work-limit"))?,
        )
        .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?
        .checked_mul(u128::from(state.weight))
        .ok_or_else(|| integrity("ordered-mixture-generator-weight-overflow"))?;
        if state_finish < current_finish {
            selected = Some(index);
        }
    }
    Ok(selected)
}

fn charge_mixture_work(
    remaining_work: &mut usize,
    work: usize,
) -> Result<(), CampaignRepositoryError> {
    *remaining_work = remaining_work
        .checked_sub(work)
        .ok_or_else(|| integrity("ordered-mixture-generator-work-limit"))?;
    Ok(())
}

fn require_mixture_work_capacity(
    remaining_work: &usize,
    work: usize,
) -> Result<(), CampaignRepositoryError> {
    if work > *remaining_work {
        return Err(integrity("ordered-mixture-generator-work-limit"));
    }
    Ok(())
}

fn weighted_categorical_draw(
    request_digest: [u8; 32],
    draw_index: u64,
    total_weight: u128,
) -> Result<u128, CampaignRepositoryError> {
    if total_weight == 0 {
        return Err(integrity("weighted-generator-weight-sum-is-zero"));
    }
    let rejection_threshold = 0_u128.wrapping_sub(total_weight) % total_weight;
    for nonce in 0..MAX_WEIGHTED_CATEGORICAL_REJECTION_DRAWS {
        let mut basis = [0_u8; 48];
        basis[..32].copy_from_slice(&request_digest);
        basis[32..40].copy_from_slice(&draw_index.to_be_bytes());
        basis[40..].copy_from_slice(&nonce.to_be_bytes());
        let hash = CampaignHash::derive(
            "crucible.campaign.generator.weighted-categorical.v7",
            &basis,
        );
        let mut sample_bytes = [0_u8; 16];
        sample_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        let sample = u128::from_be_bytes(sample_bytes);
        if sample >= rejection_threshold {
            return Ok(sample % total_weight);
        }
    }
    Err(integrity("weighted-generator-rejection-limit"))
}

fn push_static_integer_candidate(
    values: &mut Vec<IntegerValue>,
    seen: &mut BTreeSet<IntegerValue>,
    domain: &IntegerDomain,
    value: IntegerValue,
) -> Result<(), CampaignRepositoryError> {
    if domain.contains_integer(value) && seen.insert(value) {
        if values.len() == MAX_STATIC_GENERATOR_CANDIDATES {
            return Err(integrity("static-generator-candidate-limit"));
        }
        values.push(value);
    }
    Ok(())
}

fn log_integer_candidates(
    base: u32,
    domain: &IntegerDomain,
) -> Result<Vec<IntegerValue>, CampaignRepositoryError> {
    if base < 2 {
        return Err(integrity("log-generator-base-is-invalid"));
    }
    let minimum = positive_integer_magnitude(domain.minimum())
        .ok_or_else(|| integrity("log-generator-domain-is-not-positive"))?;
    let maximum = positive_integer_magnitude(domain.maximum())
        .ok_or_else(|| integrity("log-generator-domain-is-not-positive"))?;
    let step = u128::from(domain.step());
    let mut values = Vec::new();
    let mut seen = BTreeSet::new();
    push_static_integer_candidate(&mut values, &mut seen, domain, domain.minimum())?;

    let mut power = 1_u128;
    while power <= maximum {
        let rounded = if power <= minimum {
            minimum
        } else {
            let distance = power - minimum;
            let steps = distance / step + u128::from(!distance.is_multiple_of(step));
            minimum
                .checked_add(
                    steps
                        .checked_mul(step)
                        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?,
                )
                .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?
        };
        if rounded <= maximum {
            let value = integer_value_from_magnitude(domain.representation(), rounded)?;
            push_static_integer_candidate(&mut values, &mut seen, domain, value)?;
        }
        power = match power.checked_mul(u128::from(base)) {
            Some(next) => next,
            None => break,
        };
    }

    push_static_integer_candidate(&mut values, &mut seen, domain, domain.maximum())?;
    if values.len() > crate::LOG_INTEGER_GENERATOR_MAX_CANDIDATES {
        return Err(integrity("log-generator-candidate-limit"));
    }
    Ok(values)
}

fn positive_integer_magnitude(value: IntegerValue) -> Option<u128> {
    match value {
        IntegerValue::Signed(value) => u128::try_from(value).ok().filter(|value| *value > 0),
        IntegerValue::Unsigned(value) => (value > 0).then_some(u128::from(value)),
    }
}

fn integer_value_from_magnitude(
    representation: IntegerRepresentation,
    magnitude: u128,
) -> Result<IntegerValue, CampaignRepositoryError> {
    match representation {
        IntegerRepresentation::Signed64 => i64::try_from(magnitude)
            .map(IntegerValue::Signed)
            .map_err(|_| integrity("candidate-source-cardinality-overflow")),
        IntegerRepresentation::Unsigned64 => u64::try_from(magnitude)
            .map(IntegerValue::Unsigned)
            .map_err(|_| integrity("candidate-source-cardinality-overflow")),
    }
}

fn integer_step_neighbor(value: IntegerValue, step: u64, add: bool) -> Option<IntegerValue> {
    match value {
        IntegerValue::Signed(value) => {
            let value = i128::from(value);
            let step = i128::from(step);
            let neighbor = if add {
                value.checked_add(step)?
            } else {
                value.checked_sub(step)?
            };
            i64::try_from(neighbor).ok().map(IntegerValue::Signed)
        }
        IntegerValue::Unsigned(value) => {
            let neighbor = if add {
                value.checked_add(step)?
            } else {
                value.checked_sub(step)?
            };
            Some(IntegerValue::Unsigned(neighbor))
        }
    }
}

fn charge_corpus_mutation_input(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("corpus-mutation-generator-input-byte-limit"))?;
    if total > crate::CORPUS_MUTATION_GENERATOR_MAX_INPUT_BYTES {
        return Err(integrity("corpus-mutation-generator-input-byte-limit"));
    }
    Ok(total)
}

fn charge_branch_edge_visit_evidence(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("branch-edge-visit-projection-byte-limit"))?;
    if total > crate::MAX_BRANCH_EDGE_VISIT_PROJECTION_BYTES {
        return Err(integrity("branch-edge-visit-projection-byte-limit"));
    }
    Ok(total)
}

fn charge_unique_branch_prior_record(
    charged: &mut BTreeSet<ContentId>,
    content: ContentId,
    encoded_len: impl FnOnce() -> usize,
    evidence_bytes: &mut usize,
) -> Result<(), CampaignRepositoryError> {
    if charged.insert(content) {
        *evidence_bytes = charge_branch_edge_visit_evidence(*evidence_bytes, encoded_len())?;
    }
    Ok(())
}

pub(super) fn charge_branch_edge_visit_credits(
    prior: u64,
    credits: u64,
) -> Result<u64, CampaignRepositoryError> {
    let total = prior
        .checked_add(credits)
        .ok_or_else(|| integrity("branch-edge-visit-projection-count"))?;
    if total > crate::MAX_BRANCH_EDGE_VISIT_PROJECTION_CREDITS {
        return Err(integrity("branch-edge-visit-projection-count"));
    }
    Ok(total)
}

pub(super) fn charge_branch_prior_normalization_visits(
    prior: usize,
    visits: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(visits)
        .ok_or_else(|| integrity("planner-prior-normalization-visit-count"))?;
    if total > crate::MAX_BRANCH_PRIOR_NORMALIZATION_VISITS {
        return Err(integrity("planner-prior-normalization-visit-count"));
    }
    Ok(total)
}

fn coverage_guidance_for_identities(
    identities: &[crate::CampaignHash],
    frequencies: &BTreeMap<crate::CampaignHash, u64>,
) -> Result<(u64, u64), CampaignRepositoryError> {
    identities
        .iter()
        .try_fold((0_u64, 0_u64), |(events, rarity), identity| {
            let frequency = frequencies
                .get(identity)
                .copied()
                .filter(|frequency| *frequency != 0)
                .ok_or_else(|| integrity("branch-novelty-target-cache-mismatch"))?;
            let events = if frequency == 1 {
                events
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-event-count-overflow"))?
            } else {
                events
            };
            let rarity = rarity
                .checked_add(crate::MAX_BRANCH_NOVELTY_OBSERVATIONS / frequency)
                .ok_or_else(|| integrity("branch-rarity-weight-overflow"))?;
            Ok((events, rarity))
        })
}

pub(super) fn charge_branch_novelty_work(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("branch-novelty-projection-byte-limit"))?;
    if total > crate::MAX_BRANCH_NOVELTY_PROJECTION_BYTES {
        return Err(integrity("branch-novelty-projection-byte-limit"));
    }
    Ok(total)
}

pub(super) fn charge_branch_novelty_identity_visits(
    prior: u64,
    identities: usize,
) -> Result<u64, CampaignRepositoryError> {
    let identities =
        u64::try_from(identities).map_err(|_| integrity("branch-novelty-identity-visit-limit"))?;
    let total = prior
        .checked_add(identities)
        .ok_or_else(|| integrity("branch-novelty-identity-visit-limit"))?;
    if total > crate::MAX_BRANCH_NOVELTY_IDENTITY_VISITS {
        return Err(integrity("branch-novelty-identity-visit-limit"));
    }
    Ok(total)
}

pub(super) fn charge_branch_finding_work(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("branch-finding-projection-byte-limit"))?;
    if total > crate::MAX_BRANCH_FINDING_PROJECTION_BYTES {
        return Err(integrity("branch-finding-projection-byte-limit"));
    }
    Ok(total)
}

pub(super) fn charge_branch_finding_occurrence_visits(
    prior: u64,
    occurrences: u64,
) -> Result<u64, CampaignRepositoryError> {
    let total = prior
        .checked_add(occurrences)
        .ok_or_else(|| integrity("branch-finding-occurrence-visit-limit"))?;
    if total > crate::MAX_BRANCH_FINDING_OCCURRENCE_VISITS {
        return Err(integrity("branch-finding-occurrence-visit-limit"));
    }
    Ok(total)
}

pub(super) fn charge_branch_objective_work(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("branch-objective-projection-byte-limit"))?;
    if total > crate::MAX_BRANCH_OBJECTIVE_PROJECTION_BYTES {
        return Err(integrity("branch-objective-projection-byte-limit"));
    }
    Ok(total)
}

fn charge_branch_objective_record(
    prior: usize,
    id: ContentId,
    bytes: usize,
    charged: &mut BTreeSet<ContentId>,
) -> Result<usize, CampaignRepositoryError> {
    if !charged.insert(id) {
        return Ok(prior);
    }
    charge_branch_objective_work(prior, bytes)
}

pub(super) fn charge_branch_objective_evaluations(
    prior: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(1)
        .ok_or_else(|| integrity("branch-objective-evaluation-count"))?;
    if total > crate::MAX_BRANCH_OBJECTIVE_EVALUATIONS {
        return Err(integrity("branch-objective-evaluation-count"));
    }
    Ok(total)
}

pub(super) fn charge_planner_guidance_domain_work(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("planner-guidance-domain-byte-limit"))?;
    if total > crate::MAX_PLANNER_GUIDANCE_DOMAIN_BYTES {
        return Err(integrity("planner-guidance-domain-byte-limit"));
    }
    Ok(total)
}

fn corpus_mutation_integer_candidates(
    domain: &IntegerDomain,
    anchors: &BTreeSet<IntegerValue>,
    maximum_distance: u64,
    maximum_candidates: usize,
) -> Result<Vec<IntegerValue>, CampaignRepositoryError> {
    if maximum_distance == 0
        || maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE
        || maximum_candidates > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS as usize
    {
        return Err(integrity("corpus-mutation-generator-owner-limit"));
    }

    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    let mut work = 0_usize;
    for anchor in anchors.iter().copied() {
        let mut lower = Some(anchor);
        let mut upper = Some(anchor);
        for _ in 0..maximum_distance {
            work = work
                .checked_add(1)
                .ok_or_else(|| integrity("corpus-mutation-generator-work-limit"))?;
            if work > crate::CORPUS_MUTATION_GENERATOR_MAX_WORK_ITEMS {
                return Err(integrity("corpus-mutation-generator-work-limit"));
            }

            lower = lower.and_then(|value| integer_step_neighbor(value, domain.step(), false));
            upper = upper.and_then(|value| integer_step_neighbor(value, domain.step(), true));
            let mut admitted = false;
            for candidate in [lower, upper].into_iter().flatten() {
                if domain.contains_integer(candidate) && seen.insert(candidate) {
                    candidates.push(candidate);
                    admitted = true;
                    if candidates.len() == maximum_candidates {
                        return Ok(candidates);
                    }
                }
            }
            if lower.is_none() && upper.is_none() {
                break;
            }
            if !admitted
                && lower.is_none_or(|value| !domain.contains_integer(value))
                && upper.is_none_or(|value| !domain.contains_integer(value))
            {
                break;
            }
        }
    }
    Ok(candidates)
}

fn stratified_integer_candidate_count(
    strata: u32,
    domain: &IntegerDomain,
) -> Result<u64, CampaignRepositoryError> {
    if strata > crate::STRATIFIED_INTEGER_GENERATOR_MAX_STRATA {
        return Err(integrity("stratified-generator-strata-limit"));
    }
    u64::try_from(domain.cardinality().min(u128::from(strata)))
        .map_err(|_| integrity("candidate-source-cardinality-overflow"))
}

fn stratified_integer_candidate(
    strata: u32,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    integer_candidate_at_offset(domain, stratified_integer_offset(strata, domain, ordinal)?)
}

fn stratified_integer_offset(
    strata: u32,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<u128, CampaignRepositoryError> {
    let candidate_count = stratified_integer_candidate_count(strata, domain)?;
    if ordinal == 0 || ordinal > candidate_count {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }

    let maximum_offset = domain
        .cardinality()
        .checked_sub(1)
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let offset = if candidate_count == 1 {
        maximum_offset / 2
    } else {
        u128::from(ordinal - 1)
            .checked_mul(maximum_offset)
            .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?
            / u128::from(candidate_count - 1)
    };
    Ok(offset)
}

fn progressive_integer_candidate(
    initial_strata: u32,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    if initial_strata > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA {
        return Err(integrity("progressive-generator-initial-strata-limit"));
    }
    if ordinal == 0 || ordinal > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }
    let initial_count = u64::try_from(domain.cardinality().min(u128::from(initial_strata)))
        .map_err(|_| integrity("candidate-source-cardinality-overflow"))?;
    if ordinal <= initial_count {
        return stratified_integer_candidate(initial_strata, domain, ordinal);
    }

    let mut selected = BTreeSet::new();
    for initial_ordinal in 1..=initial_count {
        selected.insert(stratified_integer_offset(
            initial_strata,
            domain,
            initial_ordinal,
        )?);
    }
    let mut gaps = progressive_refinement_gaps(domain.cardinality(), &selected)?;
    let refinements = ordinal
        .checked_sub(initial_count)
        .ok_or_else(|| integrity("progressive-generator-ordinal-underflow"))?;
    let mut selected_offset = None;
    for _ in 0..refinements {
        let gap = gaps
            .pop()
            .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality"))?;
        let midpoint = gap
            .lower
            .checked_add((gap.len() - 1) / 2)
            .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
        if midpoint > gap.lower {
            gaps.push(RefinementGap {
                lower: gap.lower,
                upper: midpoint - 1,
            });
        }
        if midpoint < gap.upper {
            gaps.push(RefinementGap {
                lower: midpoint + 1,
                upper: gap.upper,
            });
        }
        selected_offset = Some(midpoint);
    }
    integer_candidate_at_offset(
        domain,
        selected_offset.ok_or_else(|| integrity("progressive-generator-refinement-is-empty"))?,
    )
}

fn feedback_progressive_integer_candidate(
    request: &BranchRequest,
    domain: &IntegerDomain,
    domain_semantic: crate::ChoiceDomainSemanticId,
    proposed: &BTreeSet<ChoiceValue>,
    feedback: CandidateFeedbackProjection<'_>,
    terms: FeedbackIntervalTerms,
) -> Result<IntegerValue, CampaignRepositoryError> {
    let projection = feedback.projection;
    if projection.branch_point() != request.branch_point() || projection.policy() != feedback.policy
    {
        return Err(integrity(
            "progressive-generator-feedback-projection-basis-mismatch",
        ));
    }
    if proposed.len() >= crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS as usize {
        return Err(integrity("progressive-generator-proposal-limit"));
    }

    let mut selected = BTreeSet::new();
    for value in proposed {
        let ChoiceValue::Integer(value) = value else {
            return Err(integrity("candidate-generator-domain-family-mismatch"));
        };
        selected.insert(integer_candidate_offset(domain, *value)?);
    }
    let gaps = progressive_refinement_gaps(domain.cardinality(), &selected)?;
    let landmark_offsets = if terms.landmarks {
        domain
            .landmarks()
            .iter()
            .map(|landmark| integer_candidate_offset(domain, *landmark))
            .collect::<Result<BTreeSet<_>, _>>()?
    } else {
        BTreeSet::new()
    };
    let prospective_prior = projection.prospective_prior_basis(1)?;
    let mut endpoints = BTreeMap::<u128, FeedbackEndpoint>::new();
    let mut scored = BinaryHeap::new();
    for gap in gaps {
        let lower_endpoint = selected.range(..gap.lower).next_back().copied();
        let upper_endpoint = selected
            .range((
                std::ops::Bound::Excluded(gap.upper),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .copied();
        let lower = feedback_endpoint(
            request,
            domain,
            domain_semantic,
            projection,
            prospective_prior,
            lower_endpoint,
            &mut endpoints,
        )?;
        let upper = feedback_endpoint(
            request,
            domain,
            domain_semantic,
            projection,
            prospective_prior,
            upper_endpoint,
            &mut endpoints,
        )?;
        scored.push(FeedbackRefinementGap {
            gap,
            rarity_discontinuity: if terms.rarity_discontinuity {
                rarity_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            finding_discontinuity: if terms.finding_discontinuity {
                finding_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            novelty_discontinuity: if terms.novelty_discontinuity {
                novelty_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            objective_discontinuity: if terms.objective_discontinuity {
                objective_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            producer_landmarks: landmark_offsets.range(gap.lower..=gap.upper).count(),
            endpoint_score_delta: lower.score_micros.abs_diff(upper.score_micros),
        });
    }
    let selected = scored
        .pop()
        .ok_or_else(|| integrity("progressive-generator-refinement-is-empty"))?;
    let midpoint = selected
        .gap
        .lower
        .checked_add((selected.gap.len() - 1) / 2)
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let offset = if selected.producer_landmarks == 0 {
        midpoint
    } else {
        landmark_offsets
            .range(selected.gap.lower..=selected.gap.upper)
            .min_by_key(|landmark| (landmark.abs_diff(midpoint), **landmark))
            .copied()
            .ok_or_else(|| integrity("progressive-generator-landmark-index-mismatch"))?
    };
    integer_candidate_at_offset(domain, offset)
}

fn feedback_endpoint(
    request: &BranchRequest,
    domain: &IntegerDomain,
    domain_semantic: crate::ChoiceDomainSemanticId,
    projection: &crate::BranchPuctProjection,
    prospective_prior: crate::exploration::BranchProspectivePriorBasis,
    offset: Option<u128>,
    cache: &mut BTreeMap<u128, FeedbackEndpoint>,
) -> Result<FeedbackEndpoint, CampaignRepositoryError> {
    let Some(offset) = offset else {
        return Ok(FeedbackEndpoint {
            edge: None,
            score_micros: 0,
        });
    };
    if let Some(endpoint) = cache.get(&offset) {
        return Ok(*endpoint);
    }
    let value = ChoiceValue::Integer(integer_candidate_at_offset(domain, offset)?);
    let edge = crate::Selection::campaign_edge_id(request.branch_point(), domain_semantic, &value);
    let raw_prior_weight = request
        .source()
        .prior_weight(&value)
        .ok_or_else(|| integrity("progressive-generator-endpoint-is-not-in-source"))?;
    if raw_prior_weight != 1 {
        return Err(integrity(
            "progressive-generator-endpoint-prior-is-not-uniform",
        ));
    }
    let evidence = if projection.edge_statistics().contains_key(&edge) {
        projection.candidate_evidence_with_prior(edge, raw_prior_weight)?
    } else {
        projection.candidate_evidence_with_prior_basis(edge, prospective_prior)?
    };
    let endpoint = FeedbackEndpoint {
        edge: Some(edge),
        score_micros: crate::PuctScore::derive(projection.puct(), evidence.statistics)?
            .total_micros(),
    };
    cache.insert(offset, endpoint);
    Ok(endpoint)
}

fn objective_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_reward, lower_visits) = objective_endpoint_mean_basis(projection, lower);
    let (upper_reward, upper_visits) = objective_endpoint_mean_basis(projection, upper);
    let lower_scaled = i128::from(lower_reward)
        .checked_mul(i128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?;
    let upper_scaled = i128::from(upper_reward)
        .checked_mul(i128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?;
    let numerator = lower_scaled
        .checked_sub(upper_scaled)
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?
        .unsigned_abs();
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn novelty_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_events, lower_visits) = novelty_endpoint_mean_basis(projection, lower);
    let (upper_events, upper_visits) = novelty_endpoint_mean_basis(projection, upper);
    let lower_scaled = u128::from(lower_events)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-novelty-discontinuity-overflow"))?;
    let upper_scaled = u128::from(upper_events)
        .checked_mul(u128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-novelty-discontinuity-overflow"))?;
    let numerator = lower_scaled.abs_diff(upper_scaled);
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-novelty-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn finding_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_reward, lower_visits) = finding_endpoint_mean_basis(projection, lower);
    let (upper_reward, upper_visits) = finding_endpoint_mean_basis(projection, upper);
    let lower_scaled = i128::from(lower_reward)
        .checked_mul(i128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?;
    let upper_scaled = i128::from(upper_reward)
        .checked_mul(i128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?;
    let numerator = lower_scaled
        .checked_sub(upper_scaled)
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?
        .unsigned_abs();
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn rarity_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_weight, lower_visits) = rarity_endpoint_mean_basis(projection, lower);
    let (upper_weight, upper_visits) = rarity_endpoint_mean_basis(projection, upper);
    let lower_scaled = u128::from(lower_weight)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-rarity-discontinuity-overflow"))?;
    let upper_scaled = u128::from(upper_weight)
        .checked_mul(u128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-rarity-discontinuity-overflow"))?;
    let numerator = lower_scaled.abs_diff(upper_scaled);
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-rarity-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn rarity_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (u64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_rarity_weights()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn finding_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (i64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_finding_reward_micros()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn novelty_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (u64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_novelty_events()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn objective_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (i64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_objective_reward_micros()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn integer_candidate_offset(
    domain: &IntegerDomain,
    value: IntegerValue,
) -> Result<u128, CampaignRepositoryError> {
    if !domain.contains_integer(value) {
        return Err(integrity("candidate-source-integer-is-not-in-domain"));
    }
    let delta = match (domain.minimum(), value) {
        (IntegerValue::Signed(minimum), IntegerValue::Signed(value)) => {
            u128::try_from(i128::from(value) - i128::from(minimum))
                .map_err(|_| integrity("candidate-source-cardinality-overflow"))?
        }
        (IntegerValue::Unsigned(minimum), IntegerValue::Unsigned(value)) => {
            u128::from(value - minimum)
        }
        _ => return Err(integrity("candidate-generator-domain-family-mismatch")),
    };
    Ok(delta / u128::from(domain.step()))
}

fn progressive_refinement_gaps(
    cardinality: u128,
    selected: &BTreeSet<u128>,
) -> Result<BinaryHeap<RefinementGap>, CampaignRepositoryError> {
    let maximum = cardinality
        .checked_sub(1)
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let mut gaps = BinaryHeap::new();
    let mut prior = None;
    for offset in selected.iter().copied() {
        let lower = prior.map_or(0, |value: u128| value + 1);
        if lower < offset {
            gaps.push(RefinementGap {
                lower,
                upper: offset - 1,
            });
        }
        prior = Some(offset);
    }
    let lower = prior.map_or(0, |value| value + 1);
    if lower <= maximum {
        gaps.push(RefinementGap {
            lower,
            upper: maximum,
        });
    }
    Ok(gaps)
}

fn integer_candidate_at_offset(
    domain: &IntegerDomain,
    offset: u128,
) -> Result<IntegerValue, CampaignRepositoryError> {
    if offset >= domain.cardinality() {
        return Err(integrity("candidate-source-offset-is-out-of-range"));
    }
    let delta = offset
        .checked_mul(u128::from(domain.step()))
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let value = match domain.minimum() {
        IntegerValue::Signed(minimum) => {
            let delta = i128::try_from(delta)
                .map_err(|_| integrity("candidate-source-cardinality-overflow"))?;
            let value = i128::from(minimum)
                .checked_add(delta)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
            IntegerValue::Signed(value)
        }
        IntegerValue::Unsigned(minimum) => {
            let value = u128::from(minimum)
                .checked_add(delta)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
            IntegerValue::Unsigned(value)
        }
    };
    if !domain.contains_integer(value) {
        return Err(integrity("static-generator-produced-illegal-integer"));
    }
    Ok(value)
}

fn permuted_integer_candidate_count(
    domain: &IntegerDomain,
) -> Result<u64, CampaignRepositoryError> {
    if domain.cardinality() > crate::PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY {
        return Err(integrity("permuted-generator-cardinality-limit"));
    }
    u64::try_from(domain.cardinality())
        .map_err(|_| integrity("permuted-generator-cardinality-limit"))
}

fn permuted_integer_candidate(
    request: &BranchRequest,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    let cardinality = permuted_integer_candidate_count(domain)?;
    if ordinal == 0 || ordinal > cardinality {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }
    let request_digest = request.id()?.content_id().digest();
    let key = CampaignHash::derive(
        "crucible.campaign.generator.permuted-integer.v6",
        &request_digest,
    );
    let envelope_mask = u64::try_from(u128::from(cardinality).next_power_of_two() - 1)
        .map_err(|_| integrity("permuted-generator-cardinality-limit"))?;
    let mut offset = ordinal - 1;
    for (round, chunk) in key.as_bytes().chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        let word = u64::from_be_bytes(bytes);
        let candidate = if round % 2 == 0 {
            offset ^ (word & envelope_mask)
        } else {
            word.wrapping_sub(offset) & envelope_mask
        };
        if candidate < cardinality {
            offset = candidate;
        }
    }
    integer_candidate_at_offset(domain, u128::from(offset))
}

fn modeled_uniform_integer_candidate_count(
    request: &BranchRequest,
    domain: &IntegerDomain,
) -> Result<u64, CampaignRepositoryError> {
    let cardinality = domain.cardinality();
    if cardinality == 0
        || !cardinality.is_power_of_two()
        || cardinality > (u128::from(u64::MAX) + 1)
    {
        return Err(integrity("modeled-uniform-integer-domain-is-not-supported"));
    }
    u64::try_from(cardinality.min(u128::from(request.budget().maximum_proposals())))
        .map_err(|_| integrity("candidate-source-cardinality-overflow"))
}

fn modeled_uniform_integer_candidate(
    request: &BranchRequest,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    let count = modeled_uniform_integer_candidate_count(request, domain)?;
    if ordinal == 0 || ordinal > count {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }

    let cardinality = domain.cardinality();
    let request_digest = request.id()?.content_id().digest();
    let key = CampaignHash::derive(
        "crucible.campaign.generator.modeled-uniform-integer.v17",
        &request_digest,
    );
    let envelope_mask = if cardinality == u128::from(u64::MAX) + 1 {
        u64::MAX
    } else {
        u64::try_from(cardinality - 1)
            .map_err(|_| integrity("modeled-uniform-integer-cardinality-limit"))?
    };
    let mut offset = ordinal - 1;
    for (round, chunk) in key.as_bytes().chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        let word = u64::from_be_bytes(bytes);
        offset = if round % 2 == 0 {
            offset ^ (word & envelope_mask)
        } else {
            word.wrapping_sub(offset) & envelope_mask
        };
    }
    integer_candidate_at_offset(domain, u128::from(offset))
}
