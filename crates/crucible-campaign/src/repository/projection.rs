//! Owner-recomputed, snapshot-bound campaign projection pages.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use super::*;
use crate::{ChoiceValue, IntegerDomain, IntegerRepresentation, IntegerValue};

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
    observations: Vec<BranchCreditedObservation>,
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
    },
    ProgressiveInteger {
        count: u64,
        initial_count: u64,
        feedback_interval: u64,
        exhausts_domain: bool,
    },
    CorpusMutation,
}

impl CandidateSourceProfile {
    const fn count(self) -> Option<u64> {
        match self {
            Self::Static { count } | Self::ProgressiveInteger { count, .. } => Some(count),
            Self::CorpusMutation => None,
        }
    }

    fn available_count(self, completed_visits: u64) -> Result<u64, CampaignRepositoryError> {
        match self {
            Self::Static { count } => Ok(count),
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
            Self::Static { .. } => true,
            Self::ProgressiveInteger {
                exhausts_domain, ..
            } => exhausts_domain,
            Self::CorpusMutation => false,
        }
    }

    pub(super) const fn requires_feedback_index(self) -> bool {
        matches!(self, Self::ProgressiveInteger { .. } | Self::CorpusMutation)
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
            return Ok(Some(CandidateSourceProfile::Static { count }));
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
            crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
            ChoiceDomain::Integer(integer),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        else {
            return Ok(None);
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
            _ => Ok(None),
        }
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
        self.expected_candidate_at_view(request, domain, view, ordinal, 0, &[])
    }

    pub(super) fn expected_candidate_at_view(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        view: CandidateViewRoots,
        ordinal: u64,
        completed_visits: u64,
        additional_previous: &[Proposal],
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        let Some(profile) = self.candidate_source_profile(request, domain)? else {
            return Ok(None);
        };
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
        domain_cache: &mut BTreeMap<crate::ChoiceDomainId, Arc<ChoiceDomain>>,
        domain_bytes: &mut usize,
    ) -> Result<(ContinuationProjection, Option<Proposal>), CampaignRepositoryError> {
        let observations = snapshot.snapshot.roots().observations;
        let candidate_view = CandidateViewRoots::from_roots(snapshot.snapshot.roots());
        let projection = self.planner_continuation_projection(snapshot, position)?;
        let request = self.read_branch_request(position.source().content_id())?;

        let completed_visits =
            self.branch_completed_visits(observations, request.branch_point())?;
        let domain =
            self.read_planner_guidance_domain(request.domain(), domain_cache, domain_bytes)?;
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
                    .candidate_at_with_feedback(
                        &request,
                        domain.as_ref(),
                        ordinal,
                        completed_visits,
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

    /// Projects and publishes one bounded static-continuation page.
    ///
    /// The page is derived from one authenticated historical or current
    /// snapshot. Its cursor is meaningful only for that immutable snapshot and
    /// branch point. Implementation-version 2 `all` generators and
    /// implementation-version 3 boundary-integer generators share the
    /// finite-source path. Static continuation state is independent of modeled
    /// observations, but every page still binds the source view's exact
    /// observation root. History-dependent generators remain fail-closed until
    /// their feedback owners are implemented.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid snapshot closure, fabricated or
    /// cross-branch cursor, invalid page size, unsupported generated request or
    /// inconsistent proposal/admission indexes, or store failure.
    pub fn project_finite_expansion(
        &self,
        source_snapshot: CampaignSnapshotId,
        branch_point: crate::BranchPointId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<ExpansionStateId, CampaignRepositoryError> {
        self.validate_complete_head(source_snapshot.content_id())?;
        let state =
            self.recompute_finite_expansion(source_snapshot, branch_point, page_after, page_size)?;
        let state_id = state.id()?;
        let content = self.put_expansion_state(&state)?;
        if content != state_id.content_id() {
            return Err(integrity("expansion-state-publication-id-mismatch"));
        }
        self.read_expansion_state(content)?;
        Ok(state_id)
    }

    pub(super) fn recompute_finite_expansion(
        &self,
        source_snapshot: CampaignSnapshotId,
        branch_point: crate::BranchPointId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let loaded = self.read_snapshot(source_snapshot.content_id())?;
        let view = loaded.snapshot.planning_view();
        let view_id = view.id()?;
        let view_content = self.put_planning_view(&view)?;
        if view_content != view_id.content_id() {
            return Err(integrity("expansion-state-planning-view-id-mismatch"));
        }
        let inputs = self.derive_finite_expansion_inputs(&view, branch_point)?;
        let (continuations, next_after) = self.finite_continuation_page(
            CandidateViewRoots::from_planning_view(&view),
            inputs.requests,
            page_after,
            page_size,
        )?;
        ExpansionState::new(
            source_snapshot,
            view_id,
            branch_point,
            inputs.requests,
            inputs.proposals,
            inputs.admissions,
            view.observations(),
            crate::ExpansionStatistics {
                admitted_children: inputs.admitted_children,
                completed_visits: inputs.completed_visits,
                ..crate::ExpansionStatistics::default()
            },
            page_after,
            page_size,
            next_after,
            continuations,
        )
        .map_err(Into::into)
    }

    fn derive_finite_expansion_inputs(
        &self,
        view: &CampaignPlanningView,
        branch_point: crate::BranchPointId,
    ) -> Result<FiniteExpansionInputs, CampaignRepositoryError> {
        let mut requests = self.merkle.empty()?.content_id();
        let mut proposals = self.merkle.empty()?.content_id();
        let mut admissions = self.merkle.empty()?.content_id();

        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(view.exploration(), after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                if *key == map_key_content("exploration.branch-request", *value) {
                    let request = self.read_branch_request(*value)?;
                    if request.branch_point() == branch_point {
                        let domain = self.read_choice_domain(request.domain().content_id())?;
                        if self.candidate_source_profile(&request, &domain)?.is_none() {
                            return Err(integrity(
                                "generated-expansion-projector-is-not-implemented",
                            ));
                        }
                        requests = self
                            .merkle
                            .insert(requests, projection_order_key(*value), *value)?
                            .content_id();
                    }
                } else if *key == map_key_content("exploration.proposal", *value) {
                    let proposal = self.read_proposal(*value)?;
                    if proposal.branch_point() == branch_point {
                        proposals = self
                            .merkle
                            .insert(proposals, projection_order_key(*value), *value)?
                            .content_id();
                    }
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }

        let mut admitted_children = 0_u64;
        after = None;
        loop {
            let page = self
                .merkle
                .scan(view.accounting(), after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                if *key != map_key_content("accounting.attempt-admission", *value) {
                    continue;
                }
                let admission = self.read_attempt_admission(*value)?;
                let (proposal, is_execution_basis) = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    } => (proposal, true),
                    AttemptAdmissionRole::AdditionalCause { proposal } => (proposal, false),
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => continue,
                };
                if self.read_proposal(proposal.content_id())?.branch_point() != branch_point {
                    continue;
                }
                admissions = self
                    .merkle
                    .insert(admissions, projection_order_key(*value), *value)?
                    .content_id();
                if is_execution_basis {
                    admitted_children = admitted_children
                        .checked_add(1)
                        .ok_or_else(|| integrity("expansion-admitted-child-count-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }

        Ok(FiniteExpansionInputs {
            requests,
            proposals,
            admissions,
            admitted_children,
            completed_visits: self.branch_completed_visits(view.observations(), branch_point)?,
        })
    }

    pub(super) fn branch_completed_visits(
        &self,
        observation_root: ContentId,
        branch_point: crate::BranchPointId,
    ) -> Result<u64, CampaignRepositoryError> {
        let Some(index) = self
            .merkle
            .get(observation_root, branch_credit_index_key(branch_point))?
        else {
            return Ok(0);
        };
        Ok(self.merkle.inspect_shallow(index)?.entry_count())
    }

    /// Rebuilds exact completed visits partitioned by semantic branch edge.
    ///
    /// The projection authenticates the complete supplied snapshot first, then
    /// follows the branch point's idempotent observation-credit index. Every
    /// credited observation must contain exactly one scoped path segment for
    /// `branch_point`, so duplicate observations and convergent causes cannot
    /// receive additional credit.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot closure or ancestry is invalid, a
    /// credit/path basis is inconsistent, more than 65,536 credits are present,
    /// more than 128 MiB of canonical evidence would be inspected, or storage
    /// access fails.
    pub fn project_branch_edge_visits(
        &self,
        snapshot: crate::CampaignSnapshotId,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchEdgeVisitStatistics, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        self.project_branch_edge_visit_evidence(&loaded, branch_point)
            .map(|evidence| evidence.statistics)
    }

    /// Rebuilds the active policy's bounded PUCT scores for one branch point.
    ///
    /// The projection authenticates the exact snapshot once, derives its
    /// completed edge-visit partition, assigns a canonical uniform prior,
    /// projects globally unique coverage identities onto credited edges, folds
    /// policy-weighted verified finding occurrences into reward, and reserves
    /// fairness for the least-visited edge. The active policy must select tree
    /// search.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot or edge evidence is invalid, the
    /// active policy is not tree search, a projection bound is exceeded, or
    /// storage access fails.
    pub fn project_branch_puct(
        &self,
        snapshot: crate::CampaignSnapshotId,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchPuctProjection, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        self.project_branch_puct_loaded(&loaded, branch_point)
    }

    pub(super) fn project_branch_puct_loaded(
        &self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchPuctProjection, CampaignRepositoryError> {
        let policy = self.read_policy(loaded.snapshot.active_policy().content_id())?;
        let crate::ExplorerPolicy::TreeSearch { puct, .. } = policy.explorer() else {
            return Err(integrity(
                "branch-puct-projection-requires-tree-search-policy",
            ));
        };
        let evidence = self.project_branch_edge_visit_evidence(loaded, branch_point)?;
        let novelty = self.project_branch_novelty_events(loaded, &evidence)?;
        let finding_weights = [
            crate::FindingKind::PropertyViolation,
            crate::FindingKind::Divergence,
            crate::FindingKind::Timeout,
        ]
        .into_iter()
        .filter_map(|kind| {
            policy
                .guidance()
                .get(kind.guidance_signal())
                .map(|weight| (kind, weight.weight_micros()))
        })
        .collect::<BTreeMap<_, _>>();
        let finding_events =
            self.project_branch_finding_events(loaded, &evidence, &finding_weights)?;
        let mut objective_rewards = self.project_branch_objective_rewards(
            loaded,
            &policy,
            std::iter::once((branch_point, &evidence)),
        )?;
        crate::BranchPuctProjection::new_with_evidence(
            loaded.snapshot.active_policy(),
            *puct,
            evidence.statistics,
            novelty,
            finding_weights,
            finding_events,
            objective_rewards.remove(&branch_point).unwrap_or_default(),
        )
        .map_err(Into::into)
    }

    pub(super) fn project_branch_puct_batch_loaded(
        &self,
        loaded: &LoadedSnapshot,
        branch_points: impl IntoIterator<Item = crate::BranchPointId>,
    ) -> Result<BTreeMap<crate::BranchPointId, crate::BranchPuctProjection>, CampaignRepositoryError>
    {
        let policy = self.read_policy(loaded.snapshot.active_policy().content_id())?;
        let crate::ExplorerPolicy::TreeSearch { puct, .. } = policy.explorer() else {
            return Err(integrity(
                "branch-puct-projection-requires-tree-search-policy",
            ));
        };
        let branch_points = branch_points.into_iter().collect::<BTreeSet<_>>();
        let evidence = self.project_branch_edge_visit_evidence_batch(loaded, &branch_points)?;
        let mut novelty = self.project_branch_novelty_events_batch(loaded, &evidence)?;
        let finding_weights = [
            crate::FindingKind::PropertyViolation,
            crate::FindingKind::Divergence,
            crate::FindingKind::Timeout,
        ]
        .into_iter()
        .filter_map(|kind| {
            policy
                .guidance()
                .get(kind.guidance_signal())
                .map(|weight| (kind, weight.weight_micros()))
        })
        .collect::<BTreeMap<_, _>>();
        let mut finding_events =
            self.project_branch_finding_events_batch(loaded, &evidence, &finding_weights)?;
        let mut objective_rewards = self.project_branch_objective_rewards(
            loaded,
            &policy,
            evidence
                .iter()
                .map(|(branch_point, evidence)| (*branch_point, evidence)),
        )?;
        evidence
            .into_iter()
            .map(|(branch_point, evidence)| {
                crate::BranchPuctProjection::new_with_evidence(
                    loaded.snapshot.active_policy(),
                    *puct,
                    evidence.statistics,
                    novelty.remove(&branch_point).unwrap_or_default(),
                    finding_weights.clone(),
                    finding_events.remove(&branch_point).unwrap_or_default(),
                    objective_rewards.remove(&branch_point).unwrap_or_default(),
                )
                .map(|projection| (branch_point, projection))
                .map_err(Into::into)
            })
            .collect()
    }

    pub(super) fn planner_candidate_guidance(
        &self,
        loaded: &LoadedSnapshot,
        projection: &crate::BranchPuctProjection,
        offer: &Proposal,
        schema_version: u32,
        domain_cache: &mut BTreeMap<crate::ChoiceDomainId, Arc<ChoiceDomain>>,
        domain_bytes: &mut usize,
    ) -> Result<crate::PlannerCandidateGuidance, CampaignRepositoryError> {
        if projection.branch_point() != offer.branch_point()
            || projection.policy() != loaded.snapshot.active_policy()
        {
            return Err(integrity(
                "planner-candidate-guidance-projection-basis-mismatch",
            ));
        }
        let semantic_id = self
            .read_planner_guidance_domain(offer.domain(), domain_cache, domain_bytes)?
            .semantic_id();
        let edge =
            crate::Selection::campaign_edge_id(offer.branch_point(), semantic_id, offer.value());
        let evidence = projection.candidate_evidence(edge)?;
        crate::PlannerCandidateGuidance::new_for_schema(
            schema_version,
            loaded.snapshot.planning_view().id()?,
            loaded.snapshot.active_policy(),
            crate::PlanningScanPosition::new(offer.branch_point(), offer.request()),
            offer.domain(),
            semantic_id,
            offer.value().clone(),
            offer.ordinal(),
            edge,
            evidence.statistics,
            evidence.novelty_events,
            evidence.objective_reward_micros,
            evidence.finding_events,
        )
        .map_err(Into::into)
    }

    fn project_branch_edge_visit_evidence(
        &self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
    ) -> Result<BranchEdgeVisitEvidence, CampaignRepositoryError> {
        let mut total_credits = 0_u64;
        let mut evidence_bytes = 0_usize;
        self.project_branch_edge_visit_evidence_bounded(
            loaded,
            branch_point,
            &mut total_credits,
            &mut evidence_bytes,
        )
    }

    fn project_branch_edge_visit_evidence_batch(
        &self,
        loaded: &LoadedSnapshot,
        branch_points: &BTreeSet<crate::BranchPointId>,
    ) -> Result<BTreeMap<crate::BranchPointId, BranchEdgeVisitEvidence>, CampaignRepositoryError>
    {
        let mut total_credits = 0_u64;
        let mut evidence_bytes = 0_usize;
        branch_points
            .iter()
            .map(|branch_point| {
                self.project_branch_edge_visit_evidence_bounded(
                    loaded,
                    *branch_point,
                    &mut total_credits,
                    &mut evidence_bytes,
                )
                .map(|evidence| (*branch_point, evidence))
            })
            .collect()
    }

    fn project_branch_edge_visit_evidence_bounded(
        &self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
        total_credits: &mut u64,
        evidence_bytes: &mut usize,
    ) -> Result<BranchEdgeVisitEvidence, CampaignRepositoryError> {
        let Some(index) = self.merkle.get(
            loaded.snapshot.roots().observations,
            branch_credit_index_key(branch_point),
        )?
        else {
            return Ok(BranchEdgeVisitEvidence {
                statistics: crate::BranchEdgeVisitStatistics::new(
                    branch_point,
                    0,
                    BTreeMap::new(),
                )?,
                observations: Vec::new(),
            });
        };
        let parent_visits = self.merkle.inspect_shallow(index)?.entry_count();
        *total_credits = charge_branch_edge_visit_credits(*total_credits, parent_visits)?;

        let mut after = None;
        let mut edge_visits = BTreeMap::<crate::BranchEdgeId, u64>::new();
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(
                usize::try_from(parent_visits)
                    .map_err(|_| integrity("branch-edge-visit-projection-count"))?,
            )
            .map_err(|_| integrity("branch-edge-visit-projection-count"))?;
        let mut visited = 0_u64;
        loop {
            let page = self.merkle.scan(index, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                let credit = self.read_expansion_credit(*content)?;
                *evidence_bytes = charge_branch_edge_visit_evidence(
                    *evidence_bytes,
                    credit.canonical_bytes().len(),
                )?;
                if credit.id().as_hash() != *key || credit.branch_point() != branch_point {
                    return Err(integrity("branch-edge-visit-credit-index-mismatch"));
                }

                let observation = self.decode_observation(credit.observation().content_id())?;
                *evidence_bytes = charge_branch_edge_visit_evidence(
                    *evidence_bytes,
                    observation.canonical_bytes().len(),
                )?;
                let attempt = self.read_attempt(observation.attempt().content_id())?;
                *evidence_bytes = charge_branch_edge_visit_evidence(
                    *evidence_bytes,
                    attempt.canonical_bytes().len(),
                )?;
                let path = self.read_branch_path(attempt.path().content_id())?;
                *evidence_bytes = charge_branch_edge_visit_evidence(
                    *evidence_bytes,
                    path.canonical_bytes().len(),
                )?;
                if observation.path() != attempt.path() {
                    return Err(integrity("branch-edge-visit-observation-path-mismatch"));
                }
                let mut matching = path
                    .segments()
                    .ok_or_else(|| integrity("branch-edge-visits-require-scoped-paths"))?
                    .iter()
                    .filter(|segment| segment.branch_point() == branch_point);
                let edge = matching
                    .next()
                    .ok_or_else(|| integrity("branch-edge-visit-path-missing-branch-point"))?
                    .edge();
                if matching.next().is_some() {
                    return Err(integrity("branch-edge-visit-path-repeats-branch-point"));
                }
                let visits = edge_visits.entry(edge).or_default();
                *visits = visits
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
                observations.push(BranchCreditedObservation {
                    observation: credit.observation(),
                    edge,
                    coverage: observation.coverage(),
                });
                visited = visited
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if visited != parent_visits {
            return Err(integrity("branch-edge-visit-credit-scan-mismatch"));
        }
        Ok(BranchEdgeVisitEvidence {
            statistics: crate::BranchEdgeVisitStatistics::new(
                branch_point,
                parent_visits,
                edge_visits,
            )?,
            observations,
        })
    }

    fn project_branch_novelty_events(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BranchEdgeVisitEvidence,
    ) -> Result<BTreeMap<crate::BranchEdgeId, u64>, CampaignRepositoryError> {
        if evidence.observations.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut work_bytes = 0_usize;
        let mut identity_visits = 0_u64;
        let mut targets = BTreeSet::new();
        let mut coverage_targets =
            BTreeMap::<crate::CoverageProjectionId, Vec<crate::CampaignHash>>::new();
        for credited in &evidence.observations {
            if coverage_targets.contains_key(&credited.coverage) {
                continue;
            }
            let coverage = self.read_coverage_projection(credited.coverage.content_id())?;
            work_bytes = charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
            identity_visits = charge_branch_novelty_identity_visits(
                identity_visits,
                coverage.identities().len(),
            )?;
            targets.extend(coverage.identities().iter().copied());
            if targets.len() > crate::MAX_BRANCH_NOVELTY_IDENTITIES {
                return Err(integrity("branch-novelty-identity-count"));
            }
            coverage_targets.insert(
                credited.coverage,
                coverage.identities().iter().copied().collect(),
            );
        }
        if targets.is_empty() {
            return Ok(BTreeMap::new());
        }

        let observation_root = loaded.snapshot.roots().observations;
        let root_entries = self.merkle.inspect_shallow(observation_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_NOVELTY_ROOT_ENTRIES {
            return Err(integrity("branch-novelty-observation-root-entry-count"));
        }
        let mut frequencies = targets
            .iter()
            .copied()
            .map(|identity| (identity, 0_u64))
            .collect::<BTreeMap<_, _>>();
        let mut canonical_observations = 0_u64;
        let mut scanned_entries = 0_u64;
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(observation_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_entries = scanned_entries
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-root-entry-count"))?;
                if *key != map_key_content("observations.observation", *content) {
                    continue;
                }
                canonical_observations = canonical_observations
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-count"))?;
                if canonical_observations > crate::MAX_BRANCH_NOVELTY_OBSERVATIONS {
                    return Err(integrity("branch-novelty-observation-count"));
                }
                let observation = self.decode_observation(*content)?;
                work_bytes =
                    charge_branch_novelty_work(work_bytes, observation.canonical_bytes().len())?;
                let coverage_id = observation.coverage();
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    coverage_targets.entry(coverage_id)
                {
                    let coverage = self.read_coverage_projection(coverage_id.content_id())?;
                    work_bytes =
                        charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
                    identity_visits = charge_branch_novelty_identity_visits(
                        identity_visits,
                        coverage.identities().len(),
                    )?;
                    entry.insert(
                        coverage
                            .identities()
                            .intersection(&targets)
                            .copied()
                            .collect(),
                    );
                }
                for identity in &coverage_targets[&coverage_id] {
                    let frequency = frequencies
                        .get_mut(identity)
                        .ok_or_else(|| integrity("branch-novelty-target-cache-mismatch"))?;
                    *frequency = frequency
                        .checked_add(1)
                        .ok_or_else(|| integrity("branch-novelty-frequency-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_entries != root_entries || frequencies.values().any(|frequency| *frequency == 0)
        {
            return Err(integrity("branch-novelty-observation-scan-mismatch"));
        }

        let mut edge_events = BTreeMap::<crate::BranchEdgeId, u64>::new();
        for credited in &evidence.observations {
            let events = coverage_targets[&credited.coverage]
                .iter()
                .filter(|identity| frequencies.get(identity) == Some(&1))
                .count();
            if events == 0 {
                continue;
            }
            let events = u64::try_from(events)
                .map_err(|_| integrity("branch-novelty-event-count-overflow"))?;
            let total = edge_events.entry(credited.edge).or_default();
            *total = total
                .checked_add(events)
                .ok_or_else(|| integrity("branch-novelty-event-count-overflow"))?;
        }
        Ok(edge_events)
    }

    fn project_branch_novelty_events_batch(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BTreeMap<crate::BranchPointId, BranchEdgeVisitEvidence>,
    ) -> Result<
        BTreeMap<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, u64>>,
        CampaignRepositoryError,
    > {
        if evidence
            .values()
            .all(|branch| branch.observations.is_empty())
        {
            return Ok(BTreeMap::new());
        }

        let mut work_bytes = 0_usize;
        let mut identity_visits = 0_u64;
        let mut targets = BTreeSet::new();
        let mut coverage_targets =
            BTreeMap::<crate::CoverageProjectionId, Vec<crate::CampaignHash>>::new();
        for branch in evidence.values() {
            for credited in &branch.observations {
                if coverage_targets.contains_key(&credited.coverage) {
                    continue;
                }
                let coverage = self.read_coverage_projection(credited.coverage.content_id())?;
                work_bytes =
                    charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
                identity_visits = charge_branch_novelty_identity_visits(
                    identity_visits,
                    coverage.identities().len(),
                )?;
                targets.extend(coverage.identities().iter().copied());
                if targets.len() > crate::MAX_BRANCH_NOVELTY_IDENTITIES {
                    return Err(integrity("branch-novelty-identity-count"));
                }
                coverage_targets.insert(
                    credited.coverage,
                    coverage.identities().iter().copied().collect(),
                );
            }
        }
        if targets.is_empty() {
            return Ok(BTreeMap::new());
        }

        let observation_root = loaded.snapshot.roots().observations;
        let root_entries = self.merkle.inspect_shallow(observation_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_NOVELTY_ROOT_ENTRIES {
            return Err(integrity("branch-novelty-observation-root-entry-count"));
        }
        let mut frequencies = targets
            .iter()
            .copied()
            .map(|identity| (identity, 0_u64))
            .collect::<BTreeMap<_, _>>();
        let mut canonical_observations = 0_u64;
        let mut scanned_entries = 0_u64;
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(observation_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_entries = scanned_entries
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-root-entry-count"))?;
                if *key != map_key_content("observations.observation", *content) {
                    continue;
                }
                canonical_observations = canonical_observations
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-count"))?;
                if canonical_observations > crate::MAX_BRANCH_NOVELTY_OBSERVATIONS {
                    return Err(integrity("branch-novelty-observation-count"));
                }
                let observation = self.decode_observation(*content)?;
                work_bytes =
                    charge_branch_novelty_work(work_bytes, observation.canonical_bytes().len())?;
                let coverage_id = observation.coverage();
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    coverage_targets.entry(coverage_id)
                {
                    let coverage = self.read_coverage_projection(coverage_id.content_id())?;
                    work_bytes =
                        charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
                    identity_visits = charge_branch_novelty_identity_visits(
                        identity_visits,
                        coverage.identities().len(),
                    )?;
                    entry.insert(
                        coverage
                            .identities()
                            .intersection(&targets)
                            .copied()
                            .collect(),
                    );
                }
                for identity in &coverage_targets[&coverage_id] {
                    let frequency = frequencies
                        .get_mut(identity)
                        .ok_or_else(|| integrity("branch-novelty-target-cache-mismatch"))?;
                    *frequency = frequency
                        .checked_add(1)
                        .ok_or_else(|| integrity("branch-novelty-frequency-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_entries != root_entries || frequencies.values().any(|frequency| *frequency == 0)
        {
            return Err(integrity("branch-novelty-observation-scan-mismatch"));
        }

        let mut branch_events =
            BTreeMap::<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, u64>>::new();
        for (branch_point, branch) in evidence {
            for credited in &branch.observations {
                let events = coverage_targets[&credited.coverage]
                    .iter()
                    .filter(|identity| frequencies.get(identity) == Some(&1))
                    .count();
                if events == 0 {
                    continue;
                }
                let events = u64::try_from(events)
                    .map_err(|_| integrity("branch-novelty-event-count-overflow"))?;
                let total = branch_events
                    .entry(*branch_point)
                    .or_default()
                    .entry(credited.edge)
                    .or_default();
                *total = total
                    .checked_add(events)
                    .ok_or_else(|| integrity("branch-novelty-event-count-overflow"))?;
            }
        }
        Ok(branch_events)
    }

    fn project_branch_finding_events(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BranchEdgeVisitEvidence,
        finding_weights: &BTreeMap<crate::FindingKind, u64>,
    ) -> Result<
        BTreeMap<crate::BranchEdgeId, BTreeMap<crate::FindingKind, u64>>,
        CampaignRepositoryError,
    > {
        if evidence.observations.is_empty() || finding_weights.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut targets = BTreeMap::new();
        for credited in &evidence.observations {
            if targets
                .insert(credited.observation, credited.edge)
                .is_some()
            {
                return Err(integrity("branch-finding-credited-observation-duplicate"));
            }
        }

        let finding_root = loaded.snapshot.roots().findings;
        let root_entries = self.merkle.inspect_shallow(finding_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_FINDING_ROOT_ENTRIES {
            return Err(integrity("branch-finding-root-entry-count"));
        }
        let mut work_bytes = 0_usize;
        let mut occurrence_visits = 0_u64;
        let mut scanned_findings = 0_u64;
        let mut edge_events =
            BTreeMap::<crate::BranchEdgeId, BTreeMap<crate::FindingKind, u64>>::new();
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(finding_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_findings = scanned_findings
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-finding-root-entry-count"))?;
                let finding = self.decode_finding(*content)?;
                work_bytes =
                    charge_branch_finding_work(work_bytes, finding.canonical_bytes().len())?;
                if *key != finding_signature_key(finding.signature().cluster_key()) {
                    return Err(integrity("branch-finding-root-index-mismatch"));
                }
                let kind = finding.signature().kind();
                if !finding_weights.contains_key(&kind) {
                    continue;
                }

                let occurrence_count = u64::from(finding.occurrence_count());
                occurrence_visits =
                    charge_branch_finding_occurrence_visits(occurrence_visits, occurrence_count)?;
                let mut scanned_occurrences = 0_u64;
                let mut occurrence_after = None;
                loop {
                    let occurrences = self.merkle.scan(
                        finding.occurrences(),
                        occurrence_after,
                        PROJECTION_SCAN_PAGE_ITEMS,
                    )?;
                    for (occurrence_key, occurrence_content) in occurrences.entries() {
                        scanned_occurrences = scanned_occurrences
                            .checked_add(1)
                            .ok_or_else(|| integrity("branch-finding-occurrence-visit-limit"))?;
                        if scanned_occurrences > occurrence_count {
                            return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                        }
                        let observation = ObservationId::from_content_id(*occurrence_content)?;
                        if *occurrence_key != finding_occurrence_key(observation) {
                            return Err(integrity("branch-finding-occurrence-index-mismatch"));
                        }
                        let Some(edge) = targets.get(&observation) else {
                            continue;
                        };
                        let count = edge_events
                            .entry(*edge)
                            .or_default()
                            .entry(kind)
                            .or_default();
                        *count = count
                            .checked_add(1)
                            .ok_or_else(|| integrity("branch-finding-event-count-overflow"))?;
                    }
                    let Some(next) = occurrences.next_after() else {
                        break;
                    };
                    occurrence_after = Some(next);
                }
                if scanned_occurrences != occurrence_count {
                    return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_findings != root_entries {
            return Err(integrity("branch-finding-root-scan-mismatch"));
        }
        Ok(edge_events)
    }

    fn project_branch_objective_rewards<'a>(
        &self,
        loaded: &LoadedSnapshot,
        policy_value: &crate::CampaignPolicy,
        evidence: impl IntoIterator<Item = (crate::BranchPointId, &'a BranchEdgeVisitEvidence)>,
    ) -> Result<BranchObjectiveRewards, CampaignRepositoryError> {
        let mut targets =
            BTreeMap::<ObservationId, Vec<(crate::BranchPointId, crate::BranchEdgeId)>>::new();
        for (branch_point, branch) in evidence {
            for credited in &branch.observations {
                targets
                    .entry(credited.observation)
                    .or_default()
                    .push((branch_point, credited.edge));
            }
        }
        if targets.is_empty() {
            return Ok(BTreeMap::new());
        }

        let policy = loaded.snapshot.active_policy();
        if policy_value.id()? != policy {
            return Err(integrity("branch-objective-policy-basis-mismatch"));
        }
        let objective_contract = policy_value.objective_contract_hash();
        let observation_root = loaded.snapshot.roots().observations;
        let mut decoded = BTreeMap::<ContentId, (ObservationId, i64)>::new();
        let mut properties =
            BTreeMap::<crate::PropertyVerdictSetId, Arc<crate::PropertyVerdictSet>>::new();
        let mut charged = BTreeSet::<ContentId>::new();
        let mut evaluation_count = 0_usize;
        let mut work_bytes = 0_usize;
        let mut reward_sums =
            BTreeMap::<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, i128>>::new();
        for (observation, edges) in targets {
            let Some(content) = self.merkle.get(
                observation_root,
                objective_evaluation_key(policy, observation),
            )?
            else {
                continue;
            };
            let reward = if let Some((retained_observation, reward)) = decoded.get(&content) {
                if *retained_observation != observation {
                    return Err(integrity(
                        "branch-objective-evaluation-index-reuses-content",
                    ));
                }
                *reward
            } else {
                evaluation_count = charge_branch_objective_evaluations(evaluation_count)?;
                let evaluation_envelope = self
                    .require_record_kind(content, crate::CampaignRecordKind::ObjectiveEvaluation)?;
                work_bytes = charge_branch_objective_record(
                    work_bytes,
                    content,
                    evaluation_envelope.body().len(),
                    &mut charged,
                )?;
                let evaluation =
                    crate::ObjectiveEvaluation::from_canonical_bytes(evaluation_envelope.body())?;
                if evaluation.id()?.content_id() != content {
                    return Err(integrity("objective-evaluation-envelope-shape"));
                }
                if evaluation.policy() != policy || evaluation.observation() != observation {
                    return Err(integrity("branch-objective-evaluation-index-mismatch"));
                }
                let observation_envelope = self.require_record_kind(
                    observation.content_id(),
                    crate::CampaignRecordKind::Observation,
                )?;
                work_bytes = charge_branch_objective_record(
                    work_bytes,
                    observation.content_id(),
                    observation_envelope.body().len(),
                    &mut charged,
                )?;
                let observation_value =
                    crate::Observation::from_canonical_bytes(observation_envelope.body())?;
                if observation_value.id()? != observation {
                    return Err(integrity("observation-envelope-shape"));
                }
                let properties_id = observation_value.properties();
                let properties_value = if let Some(value) = properties.get(&properties_id) {
                    Arc::clone(value)
                } else {
                    let envelope = self.require_record_kind(
                        properties_id.content_id(),
                        crate::CampaignRecordKind::PropertyVerdictSet,
                    )?;
                    work_bytes = charge_branch_objective_record(
                        work_bytes,
                        properties_id.content_id(),
                        envelope.body().len(),
                        &mut charged,
                    )?;
                    let value = Arc::new(crate::PropertyVerdictSet::from_canonical_bytes(
                        envelope.body(),
                    )?);
                    if value.id()? != properties_id {
                        return Err(integrity("property-verdict-set-envelope-shape"));
                    }
                    properties.insert(properties_id, Arc::clone(&value));
                    value
                };
                evaluation.validate_compact_basis(
                    policy,
                    objective_contract,
                    &observation_value,
                    properties_value.as_ref(),
                )?;
                let reward = evaluation
                    .scalar_reward()
                    .map_or(0, crate::FixedReward::to_micros_saturating);
                decoded.insert(content, (observation, reward));
                reward
            };
            if reward == 0 {
                continue;
            }
            for (branch_point, edge) in edges {
                let total = reward_sums
                    .entry(branch_point)
                    .or_default()
                    .entry(edge)
                    .or_default();
                *total += i128::from(reward);
            }
        }
        Ok(reward_sums
            .into_iter()
            .filter_map(|(branch_point, edge_sums)| {
                let rewards = edge_sums
                    .into_iter()
                    .filter_map(|(edge, total)| {
                        let reward = total.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
                        (reward != 0).then_some((edge, reward))
                    })
                    .collect::<BTreeMap<_, _>>();
                (!rewards.is_empty()).then_some((branch_point, rewards))
            })
            .collect())
    }

    fn project_branch_finding_events_batch(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BTreeMap<crate::BranchPointId, BranchEdgeVisitEvidence>,
        finding_weights: &BTreeMap<crate::FindingKind, u64>,
    ) -> Result<BranchPointFindingEvents, CampaignRepositoryError> {
        if finding_weights.is_empty()
            || evidence
                .values()
                .all(|branch| branch.observations.is_empty())
        {
            return Ok(BTreeMap::new());
        }

        let mut targets =
            BTreeMap::<ObservationId, Vec<(crate::BranchPointId, crate::BranchEdgeId)>>::new();
        for (branch_point, branch) in evidence {
            for credited in &branch.observations {
                targets
                    .entry(credited.observation)
                    .or_default()
                    .push((*branch_point, credited.edge));
            }
        }

        let finding_root = loaded.snapshot.roots().findings;
        let root_entries = self.merkle.inspect_shallow(finding_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_FINDING_ROOT_ENTRIES {
            return Err(integrity("branch-finding-root-entry-count"));
        }
        let mut work_bytes = 0_usize;
        let mut occurrence_visits = 0_u64;
        let mut scanned_findings = 0_u64;
        let mut branch_events = BranchPointFindingEvents::new();
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(finding_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_findings = scanned_findings
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-finding-root-entry-count"))?;
                let finding = self.decode_finding(*content)?;
                work_bytes =
                    charge_branch_finding_work(work_bytes, finding.canonical_bytes().len())?;
                if *key != finding_signature_key(finding.signature().cluster_key()) {
                    return Err(integrity("branch-finding-root-index-mismatch"));
                }
                let kind = finding.signature().kind();
                if !finding_weights.contains_key(&kind) {
                    continue;
                }

                let occurrence_count = u64::from(finding.occurrence_count());
                occurrence_visits =
                    charge_branch_finding_occurrence_visits(occurrence_visits, occurrence_count)?;
                let mut scanned_occurrences = 0_u64;
                let mut occurrence_after = None;
                loop {
                    let occurrences = self.merkle.scan(
                        finding.occurrences(),
                        occurrence_after,
                        PROJECTION_SCAN_PAGE_ITEMS,
                    )?;
                    for (occurrence_key, occurrence_content) in occurrences.entries() {
                        scanned_occurrences = scanned_occurrences
                            .checked_add(1)
                            .ok_or_else(|| integrity("branch-finding-occurrence-visit-limit"))?;
                        if scanned_occurrences > occurrence_count {
                            return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                        }
                        let observation = ObservationId::from_content_id(*occurrence_content)?;
                        if *occurrence_key != finding_occurrence_key(observation) {
                            return Err(integrity("branch-finding-occurrence-index-mismatch"));
                        }
                        let Some(edges) = targets.get(&observation) else {
                            continue;
                        };
                        for (branch_point, edge) in edges {
                            let count = branch_events
                                .entry(*branch_point)
                                .or_default()
                                .entry(*edge)
                                .or_default()
                                .entry(kind)
                                .or_default();
                            *count = count
                                .checked_add(1)
                                .ok_or_else(|| integrity("branch-finding-event-count-overflow"))?;
                        }
                    }
                    let Some(next) = occurrences.next_after() else {
                        break;
                    };
                    occurrence_after = Some(next);
                }
                if scanned_occurrences != occurrence_count {
                    return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_findings != root_entries {
            return Err(integrity("branch-finding-root-scan-mismatch"));
        }
        Ok(branch_events)
    }

    fn finite_continuation_page(
        &self,
        view: CandidateViewRoots,
        request_root: ContentId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<
        (
            BTreeMap<BranchRequestId, crate::ContinuationState>,
            Option<BranchRequestId>,
        ),
        CampaignRepositoryError,
    > {
        let limit =
            usize::try_from(page_size).map_err(|_| integrity("expansion-page-size-is-invalid"))?;
        let after_key = page_after.map(|request| projection_order_key(request.content_id()));
        if let Some(request) = page_after
            && self
                .merkle
                .get(request_root, projection_order_key(request.content_id()))?
                != Some(request.content_id())
        {
            return Err(integrity("expansion-page-cursor-is-not-in-request-root"));
        }

        let page = self.merkle.scan(request_root, after_key, limit)?;
        let mut continuations = BTreeMap::new();
        for (key, value) in page.entries() {
            if *key != projection_order_key(*value) {
                return Err(integrity("expansion-request-order-index-mismatch"));
            }
            let request_id = BranchRequestId::from_content_id(*value)?;
            let request = self.read_branch_request(*value)?;
            let state = self.continuation_state(view, request_id, &request)?;
            continuations.insert(request_id, state);
        }
        let next_after = if page.next_after().is_some() {
            continuations.last_key_value().map(|entry| *entry.0)
        } else {
            None
        };
        Ok((continuations, next_after))
    }

    pub(super) fn continuation_state(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let completed_visits =
            self.branch_completed_visits(view.observations, request.branch_point())?;
        self.continuation_state_with_completed_visits(view, request_id, request, completed_visits)
    }

    pub(super) fn continuation_state_with_completed_visits(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        completed_visits: u64,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let progress = self.continuation_progress(view, request_id, request, &domain)?;
        continuation_state_after_progress(
            progress.profile,
            progress.proposed,
            progress.pending,
            progress.next_candidate.is_some(),
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    pub(super) fn continuation_state_after_observation(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        observation: &Observation,
        completed_visits: u64,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let progress = self.continuation_progress(view, request_id, request, &domain)?;
        if progress.profile != CandidateSourceProfile::CorpusMutation {
            return continuation_state_after_progress(
                progress.profile,
                progress.proposed,
                progress.pending,
                progress.next_candidate.is_some(),
                request.budget().maximum_proposals(),
                completed_visits,
            );
        }
        if progress.proposed >= request.budget().maximum_proposals() {
            return continuation_state_after_progress(
                progress.profile,
                progress.proposed,
                progress.pending,
                false,
                request.budget().maximum_proposals(),
                completed_visits,
            );
        }

        let attempt = self.read_attempt(observation.attempt().content_id())?;
        let additional_selection = match attempt.start() {
            AttemptStart::Branch { selection, .. } => Some(selection),
            AttemptStart::Discover { .. } => None,
        };
        let proposed = self.proposed_values_before(
            view.exploration,
            request_id,
            progress
                .proposed
                .checked_add(1)
                .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?,
        )?;
        let has_next_candidate = self
            .corpus_mutation_candidates(request, &domain, view, additional_selection)?
            .into_iter()
            .any(|candidate| !proposed.contains(&candidate));
        continuation_state_after_progress(
            progress.profile,
            progress.proposed,
            progress.pending,
            has_next_candidate,
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    fn continuation_progress(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<ContinuationProgress, CampaignRepositoryError> {
        let profile = self
            .candidate_source_profile(request, domain)?
            .ok_or_else(|| integrity("generated-expansion-projector-is-not-implemented"))?;
        let maximum_proposals = request.budget().maximum_proposals();
        let check_count = profile
            .count()
            .unwrap_or(maximum_proposals)
            .min(maximum_proposals);
        let mut proposed = 0_u64;
        let mut pending = false;

        for ordinal in 1..=check_count {
            let Some(proposal_content) = self
                .merkle
                .get(view.exploration, proposal_ordinal_key(request_id, ordinal))?
            else {
                break;
            };
            let proposal = self.read_proposal(proposal_content)?;
            if proposal.request() != request_id
                || proposal.ordinal() != ordinal
                || self.merkle.get(
                    view.exploration,
                    map_key_content("exploration.proposal", proposal_content),
                )? != Some(proposal_content)
            {
                return Err(integrity("finite-expansion-proposal-index-mismatch"));
            }
            proposed = ordinal;

            let Some(admission_content) = self.merkle.get(
                view.accounting,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            else {
                pending = true;
                continue;
            };
            if self.merkle.get(
                view.accounting,
                map_key_content("accounting.attempt-admission", admission_content),
            )? != Some(admission_content)
            {
                return Err(integrity("finite-expansion-admission-index-mismatch"));
            }
            let admission = self.read_attempt_admission(admission_content)?;
            let admitted_proposal = match admission.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                }
                | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                    return Err(integrity("finite-expansion-discovery-admission"));
                }
            };
            if admitted_proposal.content_id() != proposal_content {
                return Err(integrity("finite-expansion-proposal-admission-mismatch"));
            }
        }

        Ok(ContinuationProgress {
            profile,
            proposed,
            pending,
            next_candidate: if profile == CandidateSourceProfile::CorpusMutation
                && proposed < maximum_proposals
            {
                self.corpus_mutation_next_candidate(
                    request,
                    domain,
                    view,
                    proposed
                        .checked_add(1)
                        .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?,
                )?
            } else {
                None
            },
        })
    }

    pub(super) fn put_expansion_state(
        &self,
        state: &ExpansionState,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ExpansionState,
            crate::object::content_children(state.content_children())?,
            state.canonical_bytes(),
        )?)
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
