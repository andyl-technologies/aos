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

struct MixtureComponentState {
    values: Vec<ChoiceValue>,
    cursor: usize,
    weight: u64,
}

#[derive(Clone, Copy)]
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
}

impl CandidateSourceProfile {
    const fn count(self) -> u64 {
        match self {
            Self::Static { count } | Self::ProgressiveInteger { count, .. } => count,
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
        }
    }

    pub(super) const fn requires_feedback_index(self) -> bool {
        matches!(self, Self::ProgressiveInteger { .. })
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
    pub(super) fn initial_continuation_state(
        &self,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        Ok(
            if self.candidate_source_profile(request, &domain)?.is_some() {
                crate::ContinuationState::Ready
            } else {
                crate::ContinuationState::Open
            },
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
        if ordinal == 0 || ordinal > profile.count() {
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
            view.exploration(),
            view.accounting(),
            view.observations(),
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

    fn finite_continuation_page(
        &self,
        exploration_root: ContentId,
        accounting_root: ContentId,
        observation_root: ContentId,
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
            let state = self.continuation_state(
                exploration_root,
                accounting_root,
                observation_root,
                request_id,
                &request,
            )?;
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
        exploration_root: ContentId,
        accounting_root: ContentId,
        observation_root: ContentId,
        request_id: BranchRequestId,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let completed_visits =
            self.branch_completed_visits(observation_root, request.branch_point())?;
        self.continuation_state_with_completed_visits(
            exploration_root,
            accounting_root,
            request_id,
            request,
            completed_visits,
        )
    }

    pub(super) fn continuation_state_with_completed_visits(
        &self,
        exploration_root: ContentId,
        accounting_root: ContentId,
        request_id: BranchRequestId,
        request: &BranchRequest,
        completed_visits: u64,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let profile = self
            .candidate_source_profile(request, &domain)?
            .ok_or_else(|| integrity("generated-expansion-projector-is-not-implemented"))?;
        let value_count = profile.count();
        let maximum_proposals = request.budget().maximum_proposals();
        let check_count = value_count.min(maximum_proposals);
        let mut proposed = 0_u64;
        let mut pending = false;

        for ordinal in 1..=check_count {
            let Some(proposal_content) = self
                .merkle
                .get(exploration_root, proposal_ordinal_key(request_id, ordinal))?
            else {
                break;
            };
            let proposal = self.read_proposal(proposal_content)?;
            if proposal.request() != request_id
                || proposal.ordinal() != ordinal
                || self.merkle.get(
                    exploration_root,
                    map_key_content("exploration.proposal", proposal_content),
                )? != Some(proposal_content)
            {
                return Err(integrity("finite-expansion-proposal-index-mismatch"));
            }
            proposed = ordinal;

            let Some(admission_content) = self.merkle.get(
                accounting_root,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            else {
                pending = true;
                continue;
            };
            if self.merkle.get(
                accounting_root,
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

        continuation_state_after_progress(
            profile,
            proposed,
            pending,
            maximum_proposals,
            completed_visits,
        )
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
    maximum_proposals: u64,
    completed_visits: u64,
) -> Result<crate::ContinuationState, CampaignRepositoryError> {
    if pending {
        return Ok(crate::ContinuationState::Open);
    }
    if proposed == profile.count() {
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
