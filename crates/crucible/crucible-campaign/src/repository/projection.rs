//! Owner-recomputed, snapshot-bound campaign projection pages.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use num_bigint::BigUint;

use super::*;
use crate::repository::closure::read::{ClosureSemanticRead, with_compatibility_semantic};
use crate::{ChoiceValue, IntegerDomain, IntegerRepresentation, IntegerValue};

mod beam;
mod branch;
mod candidate_generation;
mod source;

pub(super) use beam::BeamProjectionCacheEntry;
pub(super) use candidate_generation::*;

pub(super) const PROJECTION_SCAN_PAGE_ITEMS: usize = 10_000;
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
    cause: BranchRequestCause,
}

#[derive(Default)]
pub(super) struct PlannerCandidateProjectionCache {
    requests: BTreeMap<BranchRequestId, Arc<BranchRequest>>,
    domains: BTreeMap<crate::ChoiceDomainId, Arc<ChoiceDomain>>,
    checked_requests: BTreeMap<BranchRequestId, BranchRequest>,
    checked_domains: BTreeMap<crate::ChoiceDomainId, ChoiceDomain>,
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

fn execution_basis_is_guidance_eligible(
    policy: &crate::CampaignPolicy,
    cause: BranchRequestCause,
) -> bool {
    !matches!(
        cause,
        BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_)
    ) || matches!(
        policy.intervention_learning_policy(),
        crate::InterventionLearningPolicy::IncludeInGuidance
    )
}

type BranchFindingEvents = BTreeMap<crate::BranchEdgeId, BTreeMap<crate::FindingKind, u64>>;
type BranchPointFindingEvents = BTreeMap<crate::BranchPointId, BranchFindingEvents>;
type BranchObjectiveRewards = BTreeMap<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, i64>>;

struct MixtureComponentState {
    values: Vec<ChoiceValue>,
    cursor: usize,
    weight: u64,
}

pub(in crate::repository) struct ContinuationProgress {
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

    /// Adds the exact active-policy projection used by progressive implementation 16.
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
    progress_basis: ContinuationProgressBasis,
}

#[derive(Clone, Copy)]
pub(super) enum ContinuationProgressBasis {
    Unavailable,
    Indexed(ContentId),
    UnpublishedAccounting,
}

impl CandidateViewRoots {
    pub(super) const fn observations(self) -> ContentId {
        self.observations
    }

    pub(super) const fn corpus(self) -> ContentId {
        self.corpus
    }

    pub(super) const fn from_roots(roots: crate::CampaignRoots) -> Self {
        Self {
            exploration: roots.exploration,
            observations: roots.observations,
            corpus: roots.corpus,
            accounting: roots.accounting,
            progress_basis: ContinuationProgressBasis::Unavailable,
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
            progress_basis: ContinuationProgressBasis::Unavailable,
        }
    }

    pub(super) const fn with_request_admissions(mut self, root: ContentId) -> Self {
        self.progress_basis = ContinuationProgressBasis::Indexed(root);
        self
    }

    pub(super) const fn with_unpublished_accounting(mut self) -> Self {
        self.progress_basis = ContinuationProgressBasis::UnpublishedAccounting;
        self
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

    pub(super) fn available_count(
        self,
        completed_visits: u64,
    ) -> Result<u64, CampaignRepositoryError> {
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

    pub(super) fn required_visits(
        self,
        proposed: u64,
    ) -> Result<Option<u64>, CampaignRepositoryError> {
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
        matches!(self, Self::ProgressiveInteger { .. })
    }

    pub(super) const fn scores_interval_at(self, ordinal: u64) -> bool {
        matches!(
            self,
            Self::ProgressiveInteger {
                initial_count,
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
        with_compatibility_semantic(self, |reader| {
            reader.candidate_source_profile(request, domain)
        })
    }

    /// Resolves the exact cardinality of a history-independent source.
    ///
    /// `None` means that the source requires a generator owner with cursor or
    /// feedback semantics that this repository checkpoint does not implement.
    #[cfg(test)]
    pub(super) fn static_candidate_count(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<Option<u64>, CampaignRepositoryError> {
        with_compatibility_semantic(self, |reader| {
            reader.static_candidate_count(request, domain)
        })
    }

    /// Resolves one one-based candidate ordinal from a history-independent source.
    #[cfg(test)]
    pub(super) fn static_candidate_at(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        with_compatibility_semantic(self, |reader| {
            reader.static_candidate_at(request, domain, ordinal)
        })
    }

    /// Resolves one mutation ordinal from its authenticated corpus view.
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
        with_compatibility_semantic(self, |reader| {
            reader.expected_candidate_at_view(request, domain, ordinal, basis)
        })
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

    pub(super) fn frontier_index_after(
        &self,
        exploration_root: ContentId,
        projections: &[(
            BranchRequestId,
            crate::BranchPointId,
            crate::ContinuationState,
        )],
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let frontier_index = self
            .merkle
            .get(exploration_root, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-frontier-index-is-missing"))?;
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
            Ok(root)
        } else {
            self.merkle
                .root_after_upserts(frontier_index, &upserts)
                .map_err(Into::into)
        }
    }

    pub(super) fn branch_request_index_after(
        &self,
        exploration_root: ContentId,
        requests: &[(BranchRequestId, crate::BranchPointId)],
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        if !publish {
            return with_compatibility_semantic(self, |reader| {
                reader.branch_request_index_after(exploration_root, requests)
            });
        }

        let index = self
            .merkle
            .get(exploration_root, branch_request_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-branch-request-index-is-missing"))?;
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
            Ok(root)
        } else {
            self.merkle
                .root_after_upserts(index, &index_upserts)
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
        let index = self
            .merkle
            .get(exploration_root, branch_request_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-branch-request-index-is-missing"))?;
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
        let candidate_view = CandidateViewRoots::from_roots(snapshot.snapshot.roots())
            .with_request_admissions(self.parent_budget_ledger(snapshot)?.request_admissions());
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
            Some(Proposal::new_for_request(
                position.branch_point(),
                position.source(),
                request.domain(),
                value,
                snapshot.snapshot.active_policy(),
                Some(invocation_id),
                ordinal,
                snapshot.snapshot.planning_view().id()?,
                &request,
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
