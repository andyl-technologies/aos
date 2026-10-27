//! Checked continuation state and corpus candidate replay.

use super::*;
use crate::repository::projection::{
    CandidateSourceProfile, charge_corpus_mutation_input, continuation_state_after_progress,
    integer_step_neighbor,
};
use crate::{CampaignRoots, ChoiceValue, IntegerDomain, IntegerValue};

struct ObservationContinuationProgress {
    profile: CandidateSourceProfile,
    proposed: u64,
    pending: bool,
    next_candidate: Option<ChoiceValue>,
}

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn branch_completed_visits(
        &mut self,
        observations: ContentId,
        branch_point: crate::BranchPointId,
    ) -> Result<u64, CampaignRepositoryError> {
        let Some(index) = self.merkle_get(observations, branch_credit_index_key(branch_point))?
        else {
            return Ok(0);
        };
        Ok(self.merkle_inspect_shallow(index)?.entry_count())
    }

    pub(in crate::repository) fn validate_frontier_projection(
        &mut self,
        frontier_index: ContentId,
        request: BranchRequestId,
        branch_point: crate::BranchPointId,
        state: crate::ContinuationState,
    ) -> Result<(), CampaignRepositoryError> {
        let content = self
            .merkle_get(frontier_index, frontier_index_order_key(request))?
            .ok_or_else(|| integrity("frontier-index-request-is-missing"))?;
        let projection = self.read_continuation_projection(content)?;
        if projection != ContinuationProjection::new(request, branch_point, state) {
            return Err(integrity("frontier-index-projection-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn frontier_index_after(
        &mut self,
        exploration_root: ContentId,
        projections: &[(
            BranchRequestId,
            crate::BranchPointId,
            crate::ContinuationState,
        )],
    ) -> Result<ContentId, CampaignRepositoryError> {
        let frontier_index = self
            .merkle_get(exploration_root, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-frontier-index-is-missing"))?;
        let mut upserts = BTreeMap::new();
        for (request, branch_point, state) in projections {
            let projection = ContinuationProjection::new(*request, *branch_point, *state);
            self.insert_map(
                &mut upserts,
                frontier_index_order_key(*request),
                projection.id()?.content_id(),
            )?;
        }
        self.merkle_root_after_upserts(frontier_index, &upserts)
    }

    pub(in crate::repository) fn continuation_state_indexed(
        &mut self,
        roots: CampaignRoots,
        request_admissions: ContentId,
        request_id: BranchRequestId,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let completed_visits =
            self.branch_completed_visits(roots.observations, request.branch_point())?;
        let progress =
            self.observation_continuation_progress(roots, request_admissions, request_id, request)?;
        continuation_state_after_progress(
            progress.profile,
            progress.proposed,
            progress.pending,
            progress.next_candidate.is_some(),
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    pub(in crate::repository) fn initial_continuation_state(
        &mut self,
        roots: CampaignRoots,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let Some(profile) = self.candidate_source_profile(request, &domain)? else {
            return Ok(crate::ContinuationState::Open);
        };
        if profile != CandidateSourceProfile::CorpusMutation {
            return Ok(crate::ContinuationState::Ready);
        }
        let completed_visits =
            self.branch_completed_visits(roots.observations, request.branch_point())?;
        let has_next_candidate = self
            .corpus_mutation_next_candidate(request, roots, 1)?
            .is_some();
        continuation_state_after_progress(
            profile,
            0,
            false,
            has_next_candidate,
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    pub(in crate::repository) fn continuation_state_unpublished(
        &mut self,
        roots: CampaignRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let profile = self
            .candidate_source_profile(request, &domain)?
            .ok_or_else(|| integrity("generated-expansion-projector-is-not-implemented"))?;
        let maximum_proposals = request.budget().maximum_proposals();
        let check_count = profile
            .count()
            .unwrap_or(maximum_proposals)
            .min(maximum_proposals);
        let mut proposed = 0_u64;
        let mut pending = false;
        for ordinal in 1..=check_count {
            let Some(content) =
                self.merkle_get(roots.exploration, proposal_ordinal_key(request_id, ordinal))?
            else {
                break;
            };
            let proposal = self.read_proposal(content)?;
            if proposal.request() != request_id
                || proposal.ordinal() != ordinal
                || self.merkle_get(
                    roots.exploration,
                    map_key_content("exploration.proposal", content),
                )? != Some(content)
            {
                return Err(integrity("finite-expansion-proposal-index-mismatch"));
            }
            proposed = ordinal;

            let Some(admission_content) = self.merkle_get(
                roots.accounting,
                map_key_content("accounting.proposal-admission", content),
            )?
            else {
                pending = true;
                continue;
            };
            if self.merkle_get(
                roots.accounting,
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
            if admitted_proposal.content_id() != content {
                return Err(integrity("finite-expansion-proposal-admission-mismatch"));
            }
        }
        let next_candidate =
            if profile == CandidateSourceProfile::CorpusMutation && proposed < maximum_proposals {
                self.corpus_mutation_next_candidate(
                    request,
                    roots,
                    proposed
                        .checked_add(1)
                        .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?,
                )?
            } else {
                None
            };
        let completed_visits =
            self.branch_completed_visits(roots.observations, request.branch_point())?;
        continuation_state_after_progress(
            profile,
            proposed,
            pending,
            next_candidate.is_some(),
            maximum_proposals,
            completed_visits,
        )
    }

    pub(super) fn observation_continuation_state_after(
        &mut self,
        roots: CampaignRoots,
        request_admissions: ContentId,
        request_id: BranchRequestId,
        request: &BranchRequest,
        observation: &Observation,
        completed_visits: u64,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let progress =
            self.observation_continuation_progress(roots, request_admissions, request_id, request)?;
        if progress.profile != CandidateSourceProfile::CorpusMutation
            || progress.proposed >= request.budget().maximum_proposals()
        {
            return continuation_state_after_progress(
                progress.profile,
                progress.proposed,
                progress.pending,
                progress.next_candidate.is_some(),
                request.budget().maximum_proposals(),
                completed_visits,
            );
        }

        let attempt = self.read_attempt_cached(
            observation.attempt().content_id(),
            &mut ChoiceValidationCache::default(),
        )?;
        let additional_selection = match attempt.start() {
            AttemptStart::Branch { selection, .. } => Some(selection),
            AttemptStart::Discover { .. } | AttemptStart::AfterAttempt { .. } => None,
        };
        let next_ordinal = progress
            .proposed
            .checked_add(1)
            .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?;
        let proposed = self.proposed_values_before(roots.exploration, request_id, next_ordinal)?;
        let has_next_candidate = self
            .corpus_mutation_candidates(request, roots, additional_selection)?
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

    fn observation_continuation_progress(
        &mut self,
        roots: CampaignRoots,
        request_admissions: ContentId,
        request_id: BranchRequestId,
        request: &BranchRequest,
    ) -> Result<ObservationContinuationProgress, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let profile = self
            .candidate_source_profile(request, &domain)?
            .ok_or_else(|| integrity("generated-expansion-projector-is-not-implemented"))?;
        let maximum_proposals = request.budget().maximum_proposals();
        let check_count = profile
            .count()
            .unwrap_or(maximum_proposals)
            .min(maximum_proposals);
        let head = self.merkle_get(roots.exploration, proposal_head_key(request_id))?;
        let proposed = match head {
            Some(content) => {
                let proposal = self.read_proposal(content)?;
                let ordinal = proposal.ordinal();
                if proposal.request() != request_id
                    || ordinal == 0
                    || ordinal > check_count
                    || self
                        .merkle_get(roots.exploration, proposal_ordinal_key(request_id, ordinal))?
                        != Some(content)
                    || self.merkle_get(
                        roots.exploration,
                        map_key_content("exploration.proposal", content),
                    )? != Some(content)
                {
                    return Err(integrity("finite-expansion-proposal-index-mismatch"));
                }
                if ordinal < check_count
                    && self
                        .merkle_get(
                            roots.exploration,
                            proposal_ordinal_key(request_id, ordinal + 1),
                        )?
                        .is_some()
                {
                    return Err(integrity("finite-expansion-proposal-head-is-stale"));
                }
                ordinal
            }
            None => {
                if self
                    .merkle_get(roots.exploration, proposal_ordinal_key(request_id, 1))?
                    .is_some()
                {
                    return Err(integrity("finite-expansion-proposal-head-is-missing"));
                }
                0
            }
        };
        let admitted =
            match self.merkle_get(request_admissions, request_admissions_key(request_id))? {
                Some(root) => self.merkle_inspect_shallow(root)?.entry_count(),
                None => 0,
            };
        if admitted > proposed {
            return Err(integrity("finite-expansion-admission-index-mismatch"));
        }

        Ok(ObservationContinuationProgress {
            profile,
            proposed,
            pending: admitted != proposed,
            next_candidate: if profile == CandidateSourceProfile::CorpusMutation
                && proposed < maximum_proposals
            {
                self.corpus_mutation_next_candidate(
                    request,
                    roots,
                    proposed
                        .checked_add(1)
                        .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?,
                )?
            } else {
                None
            },
        })
    }

    pub(in crate::repository) fn planner_candidate_progress(
        &mut self,
        roots: CampaignRoots,
        request_admissions: ContentId,
        request: &BranchRequest,
    ) -> Result<
        (CandidateSourceProfile, u64, bool, Option<ChoiceValue>, u64),
        CampaignRepositoryError,
    > {
        let request_id = request.id()?;
        let progress =
            self.observation_continuation_progress(roots, request_admissions, request_id, request)?;
        let completed_visits =
            self.branch_completed_visits(roots.observations, request.branch_point())?;
        Ok((
            progress.profile,
            progress.proposed,
            progress.pending,
            progress.next_candidate,
            completed_visits,
        ))
    }

    fn corpus_mutation_next_candidate(
        &mut self,
        request: &BranchRequest,
        roots: CampaignRoots,
        ordinal: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        if ordinal == 0 || ordinal > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS {
            return Err(integrity("corpus-mutation-proposal-ordinal-limit"));
        }
        let proposed = self.proposed_values_before(roots.exploration, request.id()?, ordinal)?;
        Ok(self
            .corpus_mutation_candidates(request, roots, None)?
            .into_iter()
            .find(|candidate| !proposed.contains(candidate)))
    }

    pub(in crate::repository) fn proposed_values_before(
        &mut self,
        exploration_root: ContentId,
        request: BranchRequestId,
        ordinal: u64,
    ) -> Result<BTreeSet<ChoiceValue>, CampaignRepositoryError> {
        let mut proposed = BTreeSet::new();
        for prior_ordinal in 1..ordinal {
            let content = self
                .merkle_get(
                    exploration_root,
                    proposal_ordinal_key(request, prior_ordinal),
                )?
                .ok_or_else(|| integrity("corpus-mutation-proposal-history-gap"))?;
            let proposal = self.read_proposal(content)?;
            let proposal_value = proposal.value().clone_admitted()?;
            if proposal.request() != request
                || proposal.ordinal() != prior_ordinal
                || self.merkle_get(
                    exploration_root,
                    map_key_content("exploration.proposal", content),
                )? != Some(content)
                || self.merkle_get(
                    exploration_root,
                    proposal_value_key(request, proposal.value()),
                )? != Some(content)
                || !self.insert_set(&mut proposed, proposal_value)?
            {
                return Err(integrity("corpus-mutation-proposal-history-mismatch"));
            }
        }
        Ok(proposed)
    }

    pub(in crate::repository) fn corpus_mutation_candidates(
        &mut self,
        request: &BranchRequest,
        roots: CampaignRoots,
        additional_selection: Option<SelectionId>,
    ) -> Result<Vec<ChoiceValue>, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        self.corpus_mutation_candidates_for_view(
            request,
            &domain,
            crate::repository::projection::CandidateViewRoots::from_roots(roots),
            additional_selection,
        )
    }

    pub(in crate::repository) fn corpus_mutation_candidates_for_view(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        view: crate::repository::projection::CandidateViewRoots,
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

        let index = self.merkle_get(
            view.observations(),
            branch_credit_index_key(request.branch_point()),
        )?;
        let mut input_bytes = 0_usize;
        let mut selections = Vec::new();
        if let Some(index) = index {
            let entry_count = self.merkle_inspect_shallow(index)?.entry_count();
            if entry_count > crate::CORPUS_MUTATION_GENERATOR_MAX_CREDITS {
                return Err(integrity("corpus-mutation-generator-credit-limit"));
            }
            let limit = usize::try_from(entry_count)
                .map_err(|_| integrity("corpus-mutation-generator-credit-limit"))?;
            let page = self.merkle_scan(index, None, limit)?;
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
                if self.merkle_get(
                    view.corpus(),
                    map_key_hash("corpus.configuration", observation.child().as_hash()),
                )? != Some(observation.child_content().content_id())
                {
                    return Err(integrity("corpus-mutation-observation-is-not-retained"));
                }
                let attempt = self.read_attempt_cached(
                    observation.attempt().content_id(),
                    &mut ChoiceValidationCache::default(),
                )?;
                input_bytes =
                    charge_corpus_mutation_input(input_bytes, attempt.canonical_bytes().len())?;
                let AttemptStart::Branch { selection, .. } = attempt.start() else {
                    continue;
                };
                self.push(&mut selections, selection)?;
            }
        }
        if let Some(selection) = additional_selection {
            if selections.len() >= crate::CORPUS_MUTATION_GENERATOR_MAX_CREDITS as usize {
                return Err(integrity("corpus-mutation-generator-credit-limit"));
            }
            self.push(&mut selections, selection)?;
        }

        let mut choice_cache = ChoiceValidationCache::default();
        let mut anchors = BTreeSet::new();
        for selection_id in selections {
            let (selection, _, _) =
                self.read_resolved_selection(selection_id, &mut choice_cache)?;
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
            self.insert_set(&mut anchors, *value)?;
        }

        let maximum_candidates = usize::try_from(request.budget().maximum_proposals())
            .map_err(|_| integrity("corpus-mutation-generator-proposal-limit"))?;
        self.corpus_mutation_integer_candidates(
            integer,
            &anchors,
            *maximum_distance,
            maximum_candidates,
        )
    }

    fn corpus_mutation_integer_candidates(
        &self,
        domain: &IntegerDomain,
        anchors: &BTreeSet<IntegerValue>,
        maximum_distance: u64,
        maximum_candidates: usize,
    ) -> Result<Vec<ChoiceValue>, CampaignRepositoryError> {
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
                    if domain.contains_integer(candidate)
                        && self.insert_set(&mut seen, candidate)?
                    {
                        self.push(&mut candidates, ChoiceValue::Integer(candidate))?;
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
}
