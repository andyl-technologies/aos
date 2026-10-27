//! Checked owner replay for retained Beam planner projections.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::repository::closure::read::ClosureSemanticRead;

struct BeamCohortCandidates<'a> {
    observations: &'a [BeamObservation],
    indices: Vec<usize>,
}

impl ClosureSemanticRead<'_, '_> {
    /// Replays one complete Beam planner projection through checked semantic reads.
    pub(in crate::repository) fn project_beam_planner(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<Arc<BeamPlannerProjection>, CampaignRepositoryError> {
        let _operation = self.enter_operation();

        let crate::ExplorerPolicy::Beam {
            width,
            novelty_reserve,
        } = policy.explorer()
        else {
            return Err(integrity("beam-projection-requires-beam-policy"));
        };
        let keep = u32::try_from(*width)
            .map_err(|_| integrity("beam-survivor-width-exceeds-owner-limit"))?;
        let novelty = u32::try_from(*novelty_reserve)
            .map_err(|_| integrity("beam-novelty-reserve-exceeds-owner-limit"))?;
        if keep as usize > crate::MAX_SURVIVOR_CANDIDATES {
            return Err(integrity("beam-survivor-width-exceeds-owner-limit"));
        }
        let rule = crate::SurvivorRule::new(crate::RankingMethod::ParetoTopK, keep, novelty, 0)?;

        let view = snapshot.snapshot.planning_view();
        let input_view = view.id()?;
        let policy_id = policy.id()?;
        snapshot.snapshot.id()?;

        let mut work = BeamProjectionWork::default();
        let observations = self.beam_observations(snapshot, &mut work)?;
        let mut source_observations = BTreeMap::new();
        let mut observations_by_barrier = BTreeMap::new();
        self.index_beam_observations(
            &observations,
            &mut source_observations,
            &mut observations_by_barrier,
            &mut work,
        )?;

        let frontier_positions = self.beam_frontier_positions(&view)?;
        let mut positions = Vec::new();
        for position in frontier_positions {
            let continuation = self.beam_continuation_projection(snapshot, position)?;
            if continuation.state() == crate::ContinuationState::Ready {
                self.push(&mut positions, position)?;
            }
        }

        let mut requests = BTreeMap::new();
        let mut source_keys = BTreeSet::new();
        for position in &positions {
            let request = self.read_branch_request(position.source())?;
            self.insert_set(&mut source_keys, (request.parent(), request.opportunity()))?;
            self.insert_map(&mut requests, *position, request)?;
        }

        let sources =
            self.beam_source_observations(&observations, &source_observations, &source_keys)?;
        let mut candidate_bases = BTreeMap::new();
        let mut target_barriers = BTreeSet::new();
        for (position, request) in &requests {
            let source_index = sources
                .get(&(request.parent(), request.opportunity()))
                .ok_or_else(|| integrity("beam-frontier-source-observation-is-missing"))?;
            let source = observations
                .get(*source_index)
                .ok_or_else(|| integrity("beam-source-observation-cache-index"))?;
            let parent = self.read_configuration_artifact(request.parent().content_id())?;
            if source.observation.child_content() != request.parent()
                || source.observation.child() != parent.configuration()
            {
                return Err(integrity("beam-frontier-parent-observation-mismatch"));
            }
            self.insert_set(&mut target_barriers, source.barrier)?;
            self.insert_map(
                &mut candidate_bases,
                *position,
                (request.parent(), parent.configuration(), source.barrier),
            )?;
        }

        let mut request_barriers = BTreeSet::new();
        for barrier in &target_barriers {
            if let crate::PlannerBeamBarrier::Request { request } = barrier {
                self.insert_set(&mut request_barriers, *request)?;
            }
        }
        let attempt_closures =
            self.beam_request_attempt_closures(snapshot, &request_barriers, &mut work)?;

        let mut candidates_by_barrier = BTreeMap::new();
        for barrier in target_barriers.iter().copied() {
            let mut candidates = Vec::new();
            if let Some(indices) = observations_by_barrier.get(&barrier) {
                for index in indices {
                    observations
                        .get(*index)
                        .ok_or_else(|| integrity("beam-barrier-observation-cache-index"))?;
                    self.push(&mut candidates, *index)?;
                }
            }
            self.insert_map(&mut candidates_by_barrier, barrier, candidates)?;
        }

        let mut selections = BTreeMap::new();
        let mut state_by_barrier = BTreeMap::new();
        let mut closure_by_barrier = BTreeMap::new();
        for (barrier, candidate_indices) in candidates_by_barrier {
            let closure = match barrier {
                crate::PlannerBeamBarrier::Standalone { .. } => BeamAttemptClosure::default(),
                crate::PlannerBeamBarrier::Request { request } => {
                    attempt_closures.get(&request).cloned().unwrap_or_default()
                }
            };
            let request_state = match barrier {
                crate::PlannerBeamBarrier::Standalone { .. } => None,
                crate::PlannerBeamBarrier::Request { request } => {
                    let request_value = self.read_branch_request(request)?;
                    let position = PlanningScanPosition::new(request_value.branch_point(), request);
                    Some(
                        self.beam_continuation_projection(snapshot, position)?
                            .state(),
                    )
                }
            };
            let state = match request_state {
                Some(
                    state @ (crate::ContinuationState::Open
                    | crate::ContinuationState::Ready
                    | crate::ContinuationState::WaitingForFeedback(_)),
                ) => crate::PlannerBeamCohortState::AwaitingRequestClosure(state),
                Some(crate::ContinuationState::Exhausted | crate::ContinuationState::Closed)
                | None
                    if closure.pending != 0 =>
                {
                    crate::PlannerBeamCohortState::AwaitingAttempts(closure.pending)
                }
                Some(crate::ContinuationState::Exhausted | crate::ContinuationState::Closed)
                | None => self.settled_beam_cohort_state(
                    snapshot,
                    policy,
                    rule,
                    BeamCohortCandidates {
                        observations: &observations,
                        indices: candidate_indices,
                    },
                    &mut selections,
                    &mut work,
                )?,
            };
            self.insert_map(&mut closure_by_barrier, barrier, closure.closed)?;
            self.insert_map(&mut state_by_barrier, barrier, state)?;
        }

        let mut candidates = BTreeMap::new();
        for (position, (parent, configuration, barrier)) in candidate_bases {
            let state = state_by_barrier
                .get(&barrier)
                .ok_or_else(|| integrity("beam-barrier-state-cache-mismatch"))?
                .clone();
            let closure = closure_by_barrier
                .get(&barrier)
                .copied()
                .ok_or_else(|| integrity("beam-barrier-closure-cache-mismatch"))?;
            let candidate = crate::PlannerBeamCandidate::new(
                input_view,
                policy_id,
                position,
                parent,
                configuration,
                barrier,
                state,
                closure,
            )?;
            self.insert_map(&mut candidates, position, candidate)?;
        }

        crucible_store::owned_decode::charge_array::<BeamPlannerProjection>(1)
            .map_err(CampaignCodecError::from)?;
        let projection = Arc::new(BeamPlannerProjection {
            candidates,
            selections,
        });
        validate_retained_beam_projection_size(&projection)?;
        Ok(projection)
    }

    fn beam_frontier_positions(
        &mut self,
        view: &CampaignPlanningView,
    ) -> Result<Vec<PlanningScanPosition>, CampaignRepositoryError> {
        let mut positions = Vec::new();
        let mut after = None;
        loop {
            let page = self.planner_scan_page(view, after, BEAM_FRONTIER_SCAN_PAGE_ITEMS)?;
            for position in page.positions().iter().copied() {
                self.push(&mut positions, position)?;
            }
            if positions.len() > MAX_BEAM_FRONTIER_POSITIONS {
                return Err(integrity("beam-frontier-position-count"));
            }
            if page.complete() {
                return Ok(positions);
            }
            after = page.last();
        }
    }

    fn beam_observations(
        &mut self,
        snapshot: &LoadedSnapshot,
        work: &mut BeamProjectionWork,
    ) -> Result<Vec<BeamObservation>, CampaignRepositoryError> {
        let mut observations = Vec::new();
        let mut seen = BTreeSet::new();
        let mut scanned = 0_usize;
        let mut after = None;
        loop {
            let page = self.merkle_scan(
                snapshot.snapshot.roots().observations,
                after,
                PROJECTION_SCAN_PAGE_ITEMS,
            )?;
            for (_, content) in page.entries() {
                self.poll()?;
                scanned = scanned
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-observation-root-scan-count"))?;
                if scanned > MAX_BEAM_OBSERVATION_ROOT_ENTRIES {
                    return Err(integrity("beam-observation-root-scan-count"));
                }
                if !self.insert_set(&mut seen, *content)? {
                    continue;
                }
                if content.kind() != ObjectKind::Observation {
                    continue;
                }
                if let Some(observation) = self.beam_observation(snapshot, *content, work)? {
                    self.push(&mut observations, observation)?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        Ok(observations)
    }

    fn beam_observation(
        &mut self,
        snapshot: &LoadedSnapshot,
        content: ContentId,
        work: &mut BeamProjectionWork,
    ) -> Result<Option<BeamObservation>, CampaignRepositoryError> {
        let envelope = self.read_envelope(content)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Observation {
            return Ok(None);
        }
        charge_beam_limit(
            &mut work.observation_bytes,
            envelope.body().len(),
            MAX_BEAM_OBSERVATION_BYTES,
            "beam-observation-byte-limit",
        )?;
        let observation = Observation::from_canonical_bytes(envelope.body())?;
        if observation.id()?.content_id() != content {
            return Err(integrity("beam-source-observation-envelope-shape"));
        }
        if self.merkle_get(
            snapshot.snapshot.roots().observations,
            map_key_content("observations.attempt", observation.attempt().content_id()),
        )? != Some(content)
        {
            return Ok(None);
        }
        let (_, ordinal) =
            self.observation_execution_basis(snapshot.snapshot.roots().accounting, &observation)?;
        let (barrier, cause) = self.beam_observation_barrier(snapshot, &observation)?;
        Ok(Some(BeamObservation {
            observation,
            ordinal,
            barrier,
            cause,
        }))
    }

    fn beam_observation_barrier(
        &mut self,
        snapshot: &LoadedSnapshot,
        observation: &Observation,
    ) -> Result<(crate::PlannerBeamBarrier, BranchRequestCause), CampaignRepositoryError> {
        let basis_content = self
            .merkle_get(
                snapshot.snapshot.roots().accounting,
                map_key_content(
                    "accounting.attempt-execution-basis",
                    observation.attempt().content_id(),
                ),
            )?
            .ok_or_else(|| integrity("beam-observation-execution-basis-is-missing"))?;
        let admission = self.read_attempt_admission(basis_content)?;
        let AttemptAdmissionRole::ExecutionBasis {
            proposal, cause, ..
        } = admission.role()
        else {
            return Err(integrity("beam-observation-execution-basis-role"));
        };
        if admission.attempt() != observation.attempt() {
            return Err(integrity("beam-observation-execution-basis-mismatch"));
        }
        match proposal {
            Some(proposal) => Ok((
                crate::PlannerBeamBarrier::request(
                    self.read_proposal(proposal.content_id())?.request(),
                ),
                cause,
            )),
            None => Ok((
                crate::PlannerBeamBarrier::standalone(observation.attempt()),
                cause,
            )),
        }
    }

    fn index_beam_observations(
        &mut self,
        observations: &[BeamObservation],
        sources: &mut BTreeMap<(ConfigurationArtifactId, ChoiceOpportunityId), usize>,
        barriers: &mut BTreeMap<crate::PlannerBeamBarrier, Vec<usize>>,
        work: &mut BeamProjectionWork,
    ) -> Result<(), CampaignRepositoryError> {
        for (index, observation) in observations.iter().enumerate() {
            self.poll()?;
            if !barriers.contains_key(&observation.barrier) {
                self.insert_map(barriers, observation.barrier, Vec::new())?;
            }
            let indices = barriers
                .get_mut(&observation.barrier)
                .ok_or_else(|| integrity("beam-barrier-observation-cache-index"))?;
            self.push(indices, index)?;

            for opportunity in observation.observation.discovered_choices() {
                charge_beam_limit(
                    &mut work.discovered_choice_visits,
                    1,
                    MAX_BEAM_DISCOVERED_CHOICE_VISITS,
                    "beam-discovered-choice-visit-limit",
                )?;
                let key = (observation.observation.child_content(), *opportunity);
                let replace = match sources.get(&key) {
                    Some(current) => {
                        let current = observations
                            .get(*current)
                            .ok_or_else(|| integrity("beam-source-observation-cache-index"))?;
                        (observation.ordinal, observation.observation.id()?)
                            < (current.ordinal, current.observation.id()?)
                    }
                    None => true,
                };
                if replace {
                    self.insert_map(sources, key, index)?;
                }
            }
        }
        Ok(())
    }

    fn beam_source_observations(
        &self,
        observations: &[BeamObservation],
        indexed: &BTreeMap<(ConfigurationArtifactId, ChoiceOpportunityId), usize>,
        targets: &BTreeSet<(ConfigurationArtifactId, ChoiceOpportunityId)>,
    ) -> Result<
        BTreeMap<(ConfigurationArtifactId, ChoiceOpportunityId), usize>,
        CampaignRepositoryError,
    > {
        let mut sources = BTreeMap::new();
        for target in targets {
            let index = indexed
                .get(target)
                .copied()
                .ok_or_else(|| integrity("beam-frontier-source-observation-is-missing"))?;
            observations
                .get(index)
                .ok_or_else(|| integrity("beam-source-observation-cache-index"))?;
            self.insert_map(&mut sources, *target, index)?;
        }
        Ok(sources)
    }

    fn beam_continuation_projection(
        &mut self,
        snapshot: &LoadedSnapshot,
        position: PlanningScanPosition,
    ) -> Result<ContinuationProjection, CampaignRepositoryError> {
        let frontier = self
            .merkle_get(
                snapshot.snapshot.roots().exploration,
                frontier_index_anchor_key(),
            )?
            .ok_or_else(|| integrity("planner-candidate-frontier-index-is-missing"))?;
        let projection_content = self
            .merkle_get(frontier, frontier_index_order_key(position.source()))?
            .ok_or_else(|| integrity("planner-candidate-projection-is-missing"))?;
        let projection = self.read_continuation_projection(projection_content)?;
        if projection.request() != position.source()
            || projection.branch_point() != position.branch_point()
        {
            return Err(integrity("planner-candidate-position-mismatch"));
        }
        Ok(projection)
    }

    fn beam_request_attempt_closures(
        &mut self,
        snapshot: &LoadedSnapshot,
        requests: &BTreeSet<BranchRequestId>,
        _work: &mut BeamProjectionWork,
    ) -> Result<BTreeMap<BranchRequestId, BeamAttemptClosure>, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        let mut closures = BTreeMap::new();
        let mut visited_attempts = 0_usize;
        let mut visited_proposals = 0_usize;
        for request_id in requests {
            let request = self.read_branch_request(*request_id)?;
            let mut closure = BeamAttemptClosure::default();
            for ordinal in 1..=request.budget().maximum_proposals() {
                self.poll()?;
                charge_beam_target_proposal_visit(&mut visited_proposals)?;
                let Some(proposal_content) = self.merkle_get(
                    roots.exploration,
                    proposal_ordinal_key(*request_id, ordinal),
                )?
                else {
                    break;
                };
                let proposal = self.read_proposal(proposal_content)?;
                if proposal.request() != *request_id || proposal.ordinal() != ordinal {
                    return Err(integrity("beam-cohort-proposal-index-mismatch"));
                }
                let Some(admission_content) = self.merkle_get(
                    roots.accounting,
                    map_key_content("accounting.proposal-admission", proposal_content),
                )?
                else {
                    continue;
                };
                let admission = self.read_attempt_admission(admission_content)?;
                let AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(admitted_proposal),
                    ..
                } = admission.role()
                else {
                    continue;
                };
                if admitted_proposal.content_id() != proposal_content {
                    return Err(integrity("beam-cohort-proposal-admission-mismatch"));
                }
                visited_attempts = visited_attempts
                    .checked_add(1)
                    .filter(|visited| *visited <= MAX_BEAM_TARGET_COHORT_ATTEMPTS)
                    .ok_or_else(|| integrity("beam-target-cohort-attempt-count"))?;
                let attempt = admission.attempt();
                if self
                    .merkle_get(
                        roots.observations,
                        map_key_content("observations.attempt", attempt.content_id()),
                    )?
                    .is_some()
                {
                    continue;
                }
                if let Some(fact) =
                    self.merkle_get(roots.accounting, non_modeled_attempt_key(attempt))?
                {
                    let fact = self.read_fact(fact)?;
                    let CampaignFact::AttemptClosed {
                        attempt: closed_attempt,
                        disposition,
                        ..
                    } = fact
                    else {
                        return Err(integrity("beam-attempt-closure-index-type-mismatch"));
                    };
                    if closed_attempt != attempt {
                        return Err(integrity("beam-attempt-closure-basis-mismatch"));
                    }
                    closure.closed.record(disposition)?;
                } else {
                    closure.pending = closure
                        .pending
                        .checked_add(1)
                        .ok_or_else(|| integrity("beam-pending-attempt-count-overflow"))?;
                }
            }
            self.insert_map(&mut closures, *request_id, closure)?;
        }
        Ok(closures)
    }

    fn settled_beam_cohort_state(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        rule: crate::SurvivorRule,
        cohort: BeamCohortCandidates<'_>,
        selections: &mut BTreeMap<SurvivorSelectionId, SurvivorSelectionBundle>,
        work: &mut BeamProjectionWork,
    ) -> Result<crate::PlannerBeamCohortState, CampaignRepositoryError> {
        let BeamCohortCandidates {
            observations,
            indices: candidate_indices,
        } = cohort;
        if candidate_indices.is_empty() {
            return Err(integrity("beam-frontier-cohort-has-no-modeled-observation"));
        }
        let mut intervention_exclusions = 0_u64;
        let mut candidates = Vec::new();
        for index in candidate_indices {
            let observation = observations
                .get(index)
                .ok_or_else(|| integrity("beam-barrier-observation-cache-index"))?;
            if execution_basis_is_guidance_eligible(policy, observation.cause) {
                self.push(&mut candidates, index)?;
            } else {
                intervention_exclusions = intervention_exclusions
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-intervention-exclusion-count-overflow"))?;
            }
        }
        if candidates.is_empty() {
            return Ok(crate::PlannerBeamCohortState::InterventionExcluded(
                intervention_exclusions,
            ));
        }
        let candidate_count = u64::try_from(candidates.len())
            .map_err(|_| integrity("beam-cohort-candidate-count-overflow"))?;
        if candidates.len() > crate::MAX_SURVIVOR_CANDIDATES {
            return Ok(crate::PlannerBeamCohortState::CohortLimitExceeded(
                candidate_count,
            ));
        }

        let mut missing = 0_u64;
        let mut representatives =
            BTreeMap::<ConfigurationId, (usize, ObjectiveEvaluation, CoverageProjection)>::new();
        for index in candidates {
            self.poll()?;
            let observation = observations
                .get(index)
                .ok_or_else(|| integrity("beam-barrier-observation-cache-index"))?;
            let observation_id = observation.observation.id()?;
            let coverage = self
                .read_beam_coverage_projection(observation.observation.coverage().content_id())?;
            charge_beam_limit(
                &mut work.coverage_bytes,
                coverage.canonical_bytes().len(),
                MAX_BEAM_COVERAGE_BYTES,
                "beam-coverage-projection-byte-limit",
            )?;
            let evaluation = self
                .merkle_get(
                    snapshot.snapshot.roots().observations,
                    objective_evaluation_key(policy.id()?, observation_id),
                )?
                .map(|content| self.read_objective_evaluation(content))
                .transpose()?;
            let Some(evaluation) = evaluation else {
                missing = missing
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-missing-evaluation-count-overflow"))?;
                continue;
            };
            charge_beam_limit(
                &mut work.evaluation_bytes,
                evaluation.canonical_bytes().len(),
                MAX_BEAM_EVALUATION_BYTES,
                "beam-objective-evaluation-byte-limit",
            )?;
            if evaluation.configuration() != observation.observation.child()
                || evaluation.observation() != observation_id
                || evaluation.policy() != policy.id()?
            {
                return Err(integrity("beam-objective-evaluation-basis-mismatch"));
            }
            let configuration = observation.observation.child();
            let replace = match representatives.get(&configuration) {
                Some((current_index, _, _)) => {
                    let current = observations
                        .get(*current_index)
                        .ok_or_else(|| integrity("beam-barrier-observation-cache-index"))?;
                    (observation.ordinal, observation_id)
                        < (current.ordinal, current.observation.id()?)
                }
                None => true,
            };
            if replace {
                self.insert_map(
                    &mut representatives,
                    configuration,
                    (index, evaluation, coverage),
                )?;
            }
        }
        if missing != 0 {
            return Ok(crate::PlannerBeamCohortState::AwaitingEvaluations(missing));
        }

        let novelty_scores = self.beam_cohort_novelty_scores(&representatives, work)?;
        let mut ranking = Vec::new();
        for (configuration, (index, evaluation, _)) in representatives {
            let observation = observations
                .get(index)
                .ok_or_else(|| integrity("beam-barrier-observation-cache-index"))?;
            self.push(
                &mut ranking,
                crate::RankingCandidate::new(
                    evaluation,
                    novelty_scores[&configuration],
                    observation.ordinal.value(),
                ),
            )?;
        }

        self.charge_survivor_ranking_work(&ranking)?;
        let bundle = crate::rank_survivors(policy, rule, ranking)?;
        let selection_id = bundle.selection().id()?;
        self.insert_map(selections, selection_id, bundle)?;
        if intervention_exclusions == 0 {
            Ok(crate::PlannerBeamCohortState::Settled(selection_id))
        } else {
            Ok(
                crate::PlannerBeamCohortState::SettledWithInterventionExclusions {
                    selection: selection_id,
                    excluded: intervention_exclusions,
                },
            )
        }
    }

    fn read_beam_coverage_projection(
        &mut self,
        id: ContentId,
    ) -> Result<CoverageProjection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::CoverageProjection)?;
        self.repository()
            .decode_coverage_projection_envelope(id, &envelope)
    }

    fn beam_cohort_novelty_scores(
        &mut self,
        representatives: &BTreeMap<
            ConfigurationId,
            (usize, ObjectiveEvaluation, CoverageProjection),
        >,
        work: &mut BeamProjectionWork,
    ) -> Result<BTreeMap<ConfigurationId, u64>, CampaignRepositoryError> {
        let mut frequencies = BTreeMap::<CampaignHash, u64>::new();
        for (_, _, coverage) in representatives.values() {
            self.poll()?;
            for identity in coverage.identities() {
                charge_beam_limit(
                    &mut work.coverage_identity_visits,
                    1,
                    MAX_BEAM_COVERAGE_IDENTITY_VISITS,
                    "beam-coverage-identity-visit-limit",
                )?;
                if let Some(frequency) = frequencies.get_mut(identity) {
                    *frequency = frequency
                        .checked_add(1)
                        .ok_or_else(|| integrity("beam-coverage-identity-frequency-overflow"))?;
                } else {
                    self.insert_map(&mut frequencies, *identity, 1)?;
                }
            }
        }

        let mut scores = BTreeMap::new();
        for (configuration, (_, _, coverage)) in representatives {
            self.poll()?;
            let mut score = 0_u64;
            for identity in coverage.identities() {
                charge_beam_limit(
                    &mut work.coverage_identity_visits,
                    1,
                    MAX_BEAM_COVERAGE_IDENTITY_VISITS,
                    "beam-coverage-identity-visit-limit",
                )?;
                if frequencies.get(identity) == Some(&1) {
                    score = score
                        .checked_add(1)
                        .ok_or_else(|| integrity("beam-novelty-score-overflow"))?;
                }
            }
            self.insert_map(&mut scores, *configuration, score)?;
        }
        Ok(scores)
    }

    fn charge_survivor_ranking_work(
        &self,
        candidates: &[crate::RankingCandidate],
    ) -> Result<(), CampaignRepositoryError> {
        let count = candidates.len();
        for _ in 0..count {
            self.charge_btree_entry::<ConfigurationId, crate::RankingCandidate>()?;
            self.charge_btree_entry::<ConfigurationId, ObjectiveEvaluationId>()?;
            self.charge_btree_entry::<ConfigurationId, ObjectiveEvaluationId>()?;
            self.charge_btree_entry::<ConfigurationId, u32>()?;
            self.charge_btree_entry::<ConfigurationId, ()>()?;
            self.charge_btree_entry::<ConfigurationId, crate::RankingDisposition>()?;
            self.charge_btree_entry::<ConfigurationId, ObjectiveEvaluation>()?;
            self.charge_btree_entry::<ConfigurationId, crate::RankingExplanation>()?;
            self.charge_btree_entry::<ConfigurationId, crate::RankingExplanationId>()?;
        }
        for candidate in candidates {
            for rejection in candidate.evaluation().rejections() {
                self.charge_btree_entry::<crate::ObjectiveRejection, ()>()?;
                let bytes = match rejection {
                    crate::ObjectiveRejection::MissingMeasurement(value)
                    | crate::ObjectiveRejection::PropertyFailed(value)
                    | crate::ObjectiveRejection::PropertyInconclusive(value)
                    | crate::ObjectiveRejection::GuestCrash(value)
                    | crate::ObjectiveRejection::AssertionFailure(value) => value.len(),
                    crate::ObjectiveRejection::ScenarioFailure(_) => 0,
                };
                crucible_store::owned_decode::charge_array::<u8>(bytes)
                    .map_err(CampaignCodecError::from)?;
            }
        }
        for _ in 0..5 {
            crucible_store::owned_decode::charge_array::<ConfigurationId>(count)
                .map_err(CampaignCodecError::from)?;
        }
        Ok(())
    }
}
