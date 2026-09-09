//! Owner-replayed Beam membership over immutable producing-request cohorts.
//!
//! The novelty reserve counts coverage identities present in exactly one
//! canonical configuration representative inside the closed cohort. It never
//! consults the later global coverage union, so a settled survivor decision is
//! stable as unrelated campaign observations arrive.

use super::*;

const MAX_BEAM_FRONTIER_POSITIONS: usize = 65_536;
const MAX_BEAM_OBSERVATION_ROOT_ENTRIES: usize = 262_144;
const MAX_BEAM_TARGET_COHORT_ATTEMPTS: usize = 262_144;
const MAX_BEAM_TARGET_PROPOSAL_VISITS: usize = 262_144;
const BEAM_FRONTIER_SCAN_PAGE_ITEMS: u32 = MAX_PLANNER_SCAN_PAGE_ITEMS - 1;
const MAX_BEAM_OBSERVATION_BYTES: usize = 256 * 1024 * 1024;
const MAX_BEAM_DISCOVERED_CHOICE_VISITS: usize = 1_000_000;
const MAX_BEAM_EVALUATION_BYTES: usize = 256 * 1024 * 1024;
const MAX_BEAM_COVERAGE_BYTES: usize = 256 * 1024 * 1024;
const MAX_BEAM_COVERAGE_IDENTITY_VISITS: usize = 4_000_000;
const MAX_BEAM_RETAINED_PROJECTION_BYTES: usize = 256 * 1024 * 1024;
const MAX_BEAM_CACHE_DELTA_SNAPSHOTS: usize = 10_000;

#[derive(Clone)]
pub(in crate::repository) struct BeamPlannerProjection {
    pub(in crate::repository) candidates:
        BTreeMap<PlanningScanPosition, crate::PlannerBeamCandidate>,
    pub(in crate::repository) selections: BTreeMap<SurvivorSelectionId, SurvivorSelectionBundle>,
}

pub(in crate::repository) struct BeamProjectionCacheEntry {
    snapshot: CampaignSnapshotId,
    policy: CampaignPolicyId,
    view: CampaignViewId,
    observations: Vec<BeamObservation>,
    observation_ids: BTreeSet<ContentId>,
    source_observations: BTreeMap<(ConfigurationArtifactId, ChoiceOpportunityId), usize>,
    observations_by_barrier: BTreeMap<crate::PlannerBeamBarrier, Vec<usize>>,
    observation_bytes: usize,
    discovered_choice_visits: usize,
    projection: Option<Arc<BeamPlannerProjection>>,
    #[cfg(test)]
    pub(in crate::repository) full_observation_root_visits: usize,
    #[cfg(test)]
    pub(in crate::repository) delta_snapshot_visits: usize,
    #[cfg(test)]
    pub(in crate::repository) target_attempt_visits: usize,
}

#[derive(Clone)]
struct BeamObservation {
    observation: Observation,
    ordinal: AdmissionOrdinal,
    barrier: crate::PlannerBeamBarrier,
}

#[derive(Clone, Default)]
struct BeamAttemptClosure {
    pending: u64,
    closed: crate::PlannerBeamClosureSummary,
}

#[derive(Default)]
struct BeamProjectionWork {
    observation_bytes: usize,
    discovered_choice_visits: usize,
    evaluation_bytes: usize,
    coverage_bytes: usize,
    coverage_identity_visits: usize,
    #[cfg(test)]
    full_observation_root_visits: usize,
    #[cfg(test)]
    delta_snapshot_visits: usize,
    #[cfg(test)]
    target_attempt_visits: usize,
}

impl CampaignRepository {
    pub(in crate::repository) fn project_beam_planner(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<Arc<BeamPlannerProjection>, CampaignRepositoryError> {
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
        let snapshot_id = snapshot.snapshot.id()?;
        let mut cache = self
            .beam_projection_cache
            .lock()
            .map_err(|_| CampaignRepositoryError::Poisoned)?;
        if let Some(entry) = cache.as_ref()
            && entry.view == input_view
            && entry.policy == policy_id
            && let Some(projection) = &entry.projection
        {
            return Ok(Arc::clone(projection));
        }

        let mut work = BeamProjectionWork::default();
        let mut cache_entry = match cache.take() {
            Some(mut entry) if entry.policy == policy_id => {
                match self.beam_observation_delta(
                    snapshot,
                    entry.snapshot,
                    &entry.observation_ids,
                    &mut work,
                )? {
                    Some(delta) => {
                        let first_new = entry.observations.len();
                        first_new
                            .checked_add(delta.len())
                            .filter(|count| *count <= MAX_BEAM_OBSERVATION_ROOT_ENTRIES)
                            .ok_or_else(|| integrity("beam-observation-cache-count"))?;
                        charge_beam_limit(
                            &mut entry.observation_bytes,
                            work.observation_bytes,
                            MAX_BEAM_OBSERVATION_BYTES,
                            "beam-observation-byte-limit",
                        )?;
                        for observation in &delta {
                            entry
                                .observation_ids
                                .insert(observation.observation.id()?.content_id());
                        }
                        entry.observations.extend(delta);
                        let prior_visits = work.discovered_choice_visits;
                        index_beam_observations(
                            &entry.observations,
                            first_new,
                            &mut entry.source_observations,
                            &mut entry.observations_by_barrier,
                            &mut work,
                        )?;
                        charge_beam_limit(
                            &mut entry.discovered_choice_visits,
                            work.discovered_choice_visits - prior_visits,
                            MAX_BEAM_DISCOVERED_CHOICE_VISITS,
                            "beam-discovered-choice-visit-limit",
                        )?;
                    }
                    None => {
                        work = BeamProjectionWork::default();
                        entry.observations = self.beam_observations(snapshot, &mut work)?;
                        entry.observation_ids = entry
                            .observations
                            .iter()
                            .map(|observation| {
                                observation.observation.id().map(|id| id.content_id())
                            })
                            .collect::<Result<_, _>>()?;
                        entry.source_observations.clear();
                        entry.observations_by_barrier.clear();
                        index_beam_observations(
                            &entry.observations,
                            0,
                            &mut entry.source_observations,
                            &mut entry.observations_by_barrier,
                            &mut work,
                        )?;
                        entry.observation_bytes = work.observation_bytes;
                        entry.discovered_choice_visits = work.discovered_choice_visits;
                    }
                }
                entry.snapshot = snapshot_id;
                entry.view = input_view;
                entry.projection = None;
                entry
            }
            _ => {
                let observations = self.beam_observations(snapshot, &mut work)?;
                let observation_ids = observations
                    .iter()
                    .map(|observation| observation.observation.id().map(|id| id.content_id()))
                    .collect::<Result<_, _>>()?;
                let mut source_observations = BTreeMap::new();
                let mut observations_by_barrier = BTreeMap::new();
                index_beam_observations(
                    &observations,
                    0,
                    &mut source_observations,
                    &mut observations_by_barrier,
                    &mut work,
                )?;
                BeamProjectionCacheEntry {
                    snapshot: snapshot_id,
                    policy: policy_id,
                    view: input_view,
                    observations,
                    observation_ids,
                    source_observations,
                    observations_by_barrier,
                    observation_bytes: work.observation_bytes,
                    discovered_choice_visits: work.discovered_choice_visits,
                    projection: None,
                    #[cfg(test)]
                    full_observation_root_visits: 0,
                    #[cfg(test)]
                    delta_snapshot_visits: 0,
                    #[cfg(test)]
                    target_attempt_visits: 0,
                }
            }
        };

        let frontier_positions = self.beam_frontier_positions(&view)?;
        let mut positions = Vec::new();
        for position in frontier_positions {
            let continuation = self.planner_continuation_projection(snapshot, position)?;
            if continuation.state() == crate::ContinuationState::Ready {
                positions.push(position);
            }
        }
        let mut requests = BTreeMap::new();
        let mut source_keys = BTreeSet::new();
        for position in &positions {
            let request = self.read_branch_request(position.source().content_id())?;
            source_keys.insert((request.parent(), request.opportunity()));
            requests.insert(*position, request);
        }

        let sources = beam_source_observations(&cache_entry, &source_keys)?;
        let mut candidate_bases = BTreeMap::new();
        let mut target_barriers = BTreeSet::new();
        for (position, request) in &requests {
            let source = sources
                .get(&(request.parent(), request.opportunity()))
                .ok_or_else(|| integrity("beam-frontier-source-observation-is-missing"))?;
            let parent = self.read_configuration_artifact(request.parent().content_id())?;
            if source.observation.child_content() != request.parent()
                || source.observation.child() != parent.configuration()
            {
                return Err(integrity("beam-frontier-parent-observation-mismatch"));
            }
            target_barriers.insert(source.barrier);
            candidate_bases.insert(
                *position,
                (request.parent(), parent.configuration(), source.barrier),
            );
        }

        let request_barriers = target_barriers
            .iter()
            .filter_map(|barrier| match barrier {
                crate::PlannerBeamBarrier::Request { request } => Some(*request),
                crate::PlannerBeamBarrier::Standalone { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        let attempt_closures =
            self.beam_request_attempt_closures(snapshot, &request_barriers, &mut work)?;

        let candidates_by_barrier = target_barriers
            .iter()
            .copied()
            .map(|barrier| {
                let candidates = cache_entry
                    .observations_by_barrier
                    .get(&barrier)
                    .into_iter()
                    .flatten()
                    .map(|index| {
                        cache_entry
                            .observations
                            .get(*index)
                            .ok_or_else(|| integrity("beam-barrier-observation-cache-index"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((barrier, candidates))
            })
            .collect::<Result<
                BTreeMap<crate::PlannerBeamBarrier, Vec<&BeamObservation>>,
                CampaignRepositoryError,
            >>()?;

        let mut selections = BTreeMap::new();
        let mut state_by_barrier = BTreeMap::new();
        let mut closure_by_barrier = BTreeMap::new();
        for (barrier, candidates) in candidates_by_barrier {
            let closure = match barrier {
                crate::PlannerBeamBarrier::Standalone { .. } => BeamAttemptClosure::default(),
                crate::PlannerBeamBarrier::Request { request } => {
                    attempt_closures.get(&request).cloned().unwrap_or_default()
                }
            };
            let request_state = match barrier {
                crate::PlannerBeamBarrier::Standalone { .. } => None,
                crate::PlannerBeamBarrier::Request { request } => {
                    let request_value = self.read_branch_request(request.content_id())?;
                    let position = PlanningScanPosition::new(request_value.branch_point(), request);
                    Some(
                        self.planner_continuation_projection(snapshot, position)?
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
                    candidates,
                    &mut selections,
                    &mut work,
                )?,
            };
            closure_by_barrier.insert(barrier, closure.closed);
            state_by_barrier.insert(barrier, state);
        }

        let candidates = candidate_bases
            .into_iter()
            .map(|(position, (parent, configuration, barrier))| {
                crate::PlannerBeamCandidate::new(
                    input_view,
                    policy_id,
                    position,
                    parent,
                    configuration,
                    barrier,
                    state_by_barrier[&barrier].clone(),
                    closure_by_barrier[&barrier],
                )
                .map(|candidate| (position, candidate))
            })
            .collect::<Result<_, _>>()?;
        let projection = Arc::new(BeamPlannerProjection {
            candidates,
            selections,
        });
        validate_retained_beam_projection_size(&projection)?;
        #[cfg(test)]
        {
            cache_entry.full_observation_root_visits = cache_entry
                .full_observation_root_visits
                .checked_add(work.full_observation_root_visits)
                .ok_or_else(|| integrity("beam-test-observation-root-visit-overflow"))?;
            cache_entry.delta_snapshot_visits = cache_entry
                .delta_snapshot_visits
                .checked_add(work.delta_snapshot_visits)
                .ok_or_else(|| integrity("beam-test-delta-snapshot-visit-overflow"))?;
            cache_entry.target_attempt_visits = cache_entry
                .target_attempt_visits
                .checked_add(work.target_attempt_visits)
                .ok_or_else(|| integrity("beam-test-target-attempt-visit-overflow"))?;
        }
        cache_entry.projection = Some(Arc::clone(&projection));
        *cache = Some(cache_entry);
        Ok(projection)
    }

    fn settled_beam_cohort_state(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        rule: crate::SurvivorRule,
        candidates: Vec<&BeamObservation>,
        selections: &mut BTreeMap<SurvivorSelectionId, SurvivorSelectionBundle>,
        work: &mut BeamProjectionWork,
    ) -> Result<crate::PlannerBeamCohortState, CampaignRepositoryError> {
        let candidate_count = u64::try_from(candidates.len())
            .map_err(|_| integrity("beam-cohort-candidate-count-overflow"))?;
        if candidates.len() > crate::MAX_SURVIVOR_CANDIDATES {
            return Ok(crate::PlannerBeamCohortState::CohortLimitExceeded(
                candidate_count,
            ));
        }
        if candidates.is_empty() {
            return Err(integrity("beam-frontier-cohort-has-no-modeled-observation"));
        }

        let mut missing = 0_u64;
        let mut representatives = BTreeMap::<
            ConfigurationId,
            (&BeamObservation, ObjectiveEvaluation, CoverageProjection),
        >::new();
        for observation in candidates {
            let observation_id = observation.observation.id()?;
            let coverage =
                self.read_coverage_projection(observation.observation.coverage().content_id())?;
            charge_beam_limit(
                &mut work.coverage_bytes,
                coverage.canonical_bytes().len(),
                MAX_BEAM_COVERAGE_BYTES,
                "beam-coverage-projection-byte-limit",
            )?;
            let evaluation = self
                .merkle
                .get(
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
                Some((current, _, _)) => {
                    (observation.ordinal, observation_id)
                        < (current.ordinal, current.observation.id()?)
                }
                None => true,
            };
            if replace {
                representatives.insert(configuration, (observation, evaluation, coverage));
            }
        }
        if missing != 0 {
            return Ok(crate::PlannerBeamCohortState::AwaitingEvaluations(missing));
        }

        let novelty_scores = beam_cohort_novelty_scores(
            representatives
                .iter()
                .map(|(configuration, (_, _, coverage))| (*configuration, coverage)),
            work,
        )?;
        let mut ranking = Vec::with_capacity(representatives.len());
        for (configuration, (observation, evaluation, _)) in representatives {
            ranking.push(crate::RankingCandidate::new(
                evaluation,
                novelty_scores[&configuration],
                observation.ordinal.value(),
            ));
        }

        let bundle = crate::rank_survivors(policy, rule, ranking)?;
        let selection_id = bundle.selection().id()?;
        selections.insert(selection_id, bundle);
        Ok(crate::PlannerBeamCohortState::Settled(selection_id))
    }

    fn beam_frontier_positions(
        &self,
        view: &CampaignPlanningView,
    ) -> Result<Vec<PlanningScanPosition>, CampaignRepositoryError> {
        let mut positions = Vec::new();
        let mut after = None;
        loop {
            let page = self.planner_scan_page(view, after, BEAM_FRONTIER_SCAN_PAGE_ITEMS)?;
            positions.extend_from_slice(page.positions());
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
        &self,
        snapshot: &LoadedSnapshot,
        work: &mut BeamProjectionWork,
    ) -> Result<Vec<BeamObservation>, CampaignRepositoryError> {
        let mut observations = Vec::new();
        let mut seen = BTreeSet::new();
        let mut scanned = 0_usize;
        let mut after = None;
        loop {
            let page = self.merkle.scan(
                snapshot.snapshot.roots().observations,
                after,
                PROJECTION_SCAN_PAGE_ITEMS,
            )?;
            for (_, content) in page.entries() {
                scanned = scanned
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-observation-root-scan-count"))?;
                #[cfg(test)]
                {
                    work.full_observation_root_visits = work
                        .full_observation_root_visits
                        .checked_add(1)
                        .ok_or_else(|| integrity("beam-test-observation-root-visit-overflow"))?;
                }
                if scanned > MAX_BEAM_OBSERVATION_ROOT_ENTRIES {
                    return Err(integrity("beam-observation-root-scan-count"));
                }
                if !seen.insert(*content) {
                    continue;
                }
                if content.kind() != ObjectKind::Observation {
                    continue;
                }
                if let Some(observation) = self.beam_observation(snapshot, *content, work)? {
                    observations.push(observation);
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        Ok(observations)
    }

    fn beam_observation_delta(
        &self,
        snapshot: &LoadedSnapshot,
        cached_snapshot: CampaignSnapshotId,
        known: &BTreeSet<ContentId>,
        work: &mut BeamProjectionWork,
    ) -> Result<Option<Vec<BeamObservation>>, CampaignRepositoryError> {
        let mut current = snapshot.snapshot.clone();
        let mut content = BTreeSet::new();
        for _ in 0..MAX_BEAM_CACHE_DELTA_SNAPSHOTS {
            #[cfg(test)]
            {
                work.delta_snapshot_visits = work
                    .delta_snapshot_visits
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-test-delta-snapshot-visit-overflow"))?;
            }
            if current.id()? == cached_snapshot {
                let mut observations = Vec::with_capacity(content.len());
                for content in content {
                    if let Some(observation) = self.beam_observation(snapshot, content, work)? {
                        observations.push(observation);
                    }
                }
                return Ok(Some(observations));
            }
            let Some(parent) = current.parent() else {
                return Ok(None);
            };
            if let Some(transition) = current.transition() {
                match self.read_fact(transition.content_id())? {
                    CampaignFact::ObservationPublished(observation)
                    | CampaignFact::ObservationCredited(observation) => {
                        if !known.contains(&observation.content_id()) {
                            content.insert(observation.content_id());
                        }
                    }
                    _ => {}
                }
            }
            current = self.read_snapshot(parent.content_id())?.snapshot;
        }

        Err(integrity("beam-projection-cache-snapshot-delta-limit"))
    }

    fn beam_observation(
        &self,
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
        if self.merkle.get(
            snapshot.snapshot.roots().observations,
            map_key_content("observations.attempt", observation.attempt().content_id()),
        )? != Some(content)
        {
            return Ok(None);
        }
        let (_, ordinal) =
            self.observation_execution_basis(snapshot.snapshot.roots().accounting, &observation)?;
        let barrier = self.beam_observation_barrier(snapshot, &observation)?;
        Ok(Some(BeamObservation {
            observation,
            ordinal,
            barrier,
        }))
    }

    fn beam_observation_barrier(
        &self,
        snapshot: &LoadedSnapshot,
        observation: &Observation,
    ) -> Result<crate::PlannerBeamBarrier, CampaignRepositoryError> {
        let basis_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                map_key_content(
                    "accounting.attempt-execution-basis",
                    observation.attempt().content_id(),
                ),
            )?
            .ok_or_else(|| integrity("beam-observation-execution-basis-is-missing"))?;
        let admission = self.read_attempt_admission(basis_content)?;
        let AttemptAdmissionRole::ExecutionBasis { proposal, .. } = admission.role() else {
            return Err(integrity("beam-observation-execution-basis-role"));
        };
        if admission.attempt() != observation.attempt() {
            return Err(integrity("beam-observation-execution-basis-mismatch"));
        }
        match proposal {
            Some(proposal) => Ok(crate::PlannerBeamBarrier::request(
                self.read_proposal(proposal.content_id())?.request(),
            )),
            None => Ok(crate::PlannerBeamBarrier::standalone(observation.attempt())),
        }
    }

    fn beam_request_attempt_closures(
        &self,
        snapshot: &LoadedSnapshot,
        requests: &BTreeSet<BranchRequestId>,
        _work: &mut BeamProjectionWork,
    ) -> Result<BTreeMap<BranchRequestId, BeamAttemptClosure>, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        let mut closures = BTreeMap::new();
        let mut visited_attempts = 0_usize;
        let mut visited_proposals = 0_usize;
        for request_id in requests {
            let request = self.read_branch_request(request_id.content_id())?;
            let mut closure = BeamAttemptClosure::default();
            for ordinal in 1..=request.budget().maximum_proposals() {
                charge_beam_target_proposal_visit(&mut visited_proposals)?;
                let Some(proposal_content) = self.merkle.get(
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
                let Some(admission_content) = self.merkle.get(
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
                #[cfg(test)]
                {
                    _work.target_attempt_visits = _work
                        .target_attempt_visits
                        .checked_add(1)
                        .ok_or_else(|| integrity("beam-test-target-attempt-visit-overflow"))?;
                }
                let attempt = admission.attempt();
                if self
                    .merkle
                    .get(
                        roots.observations,
                        map_key_content("observations.attempt", attempt.content_id()),
                    )?
                    .is_some()
                {
                    continue;
                }
                if let Some(fact) = self
                    .merkle
                    .get(roots.accounting, non_modeled_attempt_key(attempt))?
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
            closures.insert(*request_id, closure);
        }
        Ok(closures)
    }
}

fn beam_source_observations<'a>(
    cache: &'a BeamProjectionCacheEntry,
    targets: &BTreeSet<(ConfigurationArtifactId, ChoiceOpportunityId)>,
) -> Result<
    BTreeMap<(ConfigurationArtifactId, ChoiceOpportunityId), &'a BeamObservation>,
    CampaignRepositoryError,
> {
    targets
        .iter()
        .map(|target| {
            let index = cache
                .source_observations
                .get(target)
                .ok_or_else(|| integrity("beam-frontier-source-observation-is-missing"))?;
            let observation = cache
                .observations
                .get(*index)
                .ok_or_else(|| integrity("beam-source-observation-cache-index"))?;
            Ok((*target, observation))
        })
        .collect()
}

fn index_beam_observations(
    observations: &[BeamObservation],
    first_new: usize,
    sources: &mut BTreeMap<(ConfigurationArtifactId, ChoiceOpportunityId), usize>,
    barriers: &mut BTreeMap<crate::PlannerBeamBarrier, Vec<usize>>,
    work: &mut BeamProjectionWork,
) -> Result<(), CampaignRepositoryError> {
    for (index, observation) in observations.iter().enumerate().skip(first_new) {
        barriers.entry(observation.barrier).or_default().push(index);
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
                sources.insert(key, index);
            }
        }
    }
    Ok(())
}

fn validate_retained_beam_projection_size(
    projection: &BeamPlannerProjection,
) -> Result<(), CampaignRepositoryError> {
    let mut retained_bytes = 0_usize;
    for candidate in projection.candidates.values() {
        charge_beam_limit(
            &mut retained_bytes,
            candidate.canonical_bytes().len(),
            MAX_BEAM_RETAINED_PROJECTION_BYTES,
            "beam-retained-projection-byte-limit",
        )?;
    }
    for bundle in projection.selections.values() {
        for evaluation in bundle.evaluations().values() {
            charge_beam_limit(
                &mut retained_bytes,
                evaluation.canonical_bytes().len(),
                MAX_BEAM_RETAINED_PROJECTION_BYTES,
                "beam-retained-projection-byte-limit",
            )?;
        }
        for explanation in bundle.explanations().values() {
            charge_beam_limit(
                &mut retained_bytes,
                explanation.canonical_bytes().len(),
                MAX_BEAM_RETAINED_PROJECTION_BYTES,
                "beam-retained-projection-byte-limit",
            )?;
        }
        charge_beam_limit(
            &mut retained_bytes,
            bundle.selection().canonical_bytes().len(),
            MAX_BEAM_RETAINED_PROJECTION_BYTES,
            "beam-retained-projection-byte-limit",
        )?;
    }
    Ok(())
}

fn beam_cohort_novelty_scores<'a>(
    coverages: impl IntoIterator<Item = (ConfigurationId, &'a CoverageProjection)>,
    work: &mut BeamProjectionWork,
) -> Result<BTreeMap<ConfigurationId, u64>, CampaignRepositoryError> {
    let coverages = coverages.into_iter().collect::<Vec<_>>();
    let mut frequencies = BTreeMap::<CampaignHash, u64>::new();
    for (_, coverage) in &coverages {
        for identity in coverage.identities() {
            charge_beam_limit(
                &mut work.coverage_identity_visits,
                1,
                MAX_BEAM_COVERAGE_IDENTITY_VISITS,
                "beam-coverage-identity-visit-limit",
            )?;
            let frequency = frequencies.entry(*identity).or_default();
            *frequency = frequency
                .checked_add(1)
                .ok_or_else(|| integrity("beam-coverage-identity-frequency-overflow"))?;
        }
    }

    let mut scores = BTreeMap::new();
    for (configuration, coverage) in coverages {
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
        scores.insert(configuration, score);
    }
    Ok(scores)
}

fn charge_beam_limit(
    total: &mut usize,
    added: usize,
    maximum: usize,
    reason: &'static str,
) -> Result<(), CampaignRepositoryError> {
    *total = total
        .checked_add(added)
        .filter(|total| *total <= maximum)
        .ok_or_else(|| integrity(reason))?;
    Ok(())
}

fn charge_beam_target_proposal_visit(visited: &mut usize) -> Result<(), CampaignRepositoryError> {
    *visited = visited
        .checked_add(1)
        .filter(|visited| *visited <= MAX_BEAM_TARGET_PROPOSAL_VISITS)
        .ok_or_else(|| integrity("beam-target-proposal-visit-count"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CampaignMode, CampaignSeed, ExplorerPolicy, FairnessPolicy, MeasurementSet, MetricValue,
        Objective, ObjectiveGoal, ObjectiveValue, PropertyVerdictSet, RankingDisposition,
        RetentionPolicy, StopOutcome,
    };
    use crucible_cas::content_store::{ContentId, ObjectKind};

    #[test]
    fn aggregate_projection_charge_rejects_limit_and_integer_overflow() {
        let mut total = 7;
        assert!(matches!(
            charge_beam_limit(&mut total, 4, 10, "beam-test-work-limit"),
            Err(CampaignRepositoryError::Integrity {
                reason: "beam-test-work-limit"
            })
        ));

        let mut total = usize::MAX;
        assert!(matches!(
            charge_beam_limit(&mut total, 1, usize::MAX, "beam-test-work-overflow"),
            Err(CampaignRepositoryError::Integrity {
                reason: "beam-test-work-overflow"
            })
        ));
    }

    #[test]
    fn target_proposal_visits_are_bounded_before_admission_filtering() {
        let mut visits = MAX_BEAM_TARGET_PROPOSAL_VISITS - 1;
        charge_beam_target_proposal_visit(&mut visits).expect("exact proposal visit boundary");
        assert!(matches!(
            charge_beam_target_proposal_visit(&mut visits),
            Err(CampaignRepositoryError::Integrity {
                reason: "beam-target-proposal-visit-count"
            })
        ));
    }

    #[test]
    fn novelty_reserve_selects_unique_coverage_over_common_high_volume_coverage() {
        let common = (0_u64..64)
            .map(|value| CampaignHash::derive("beam-common-coverage", &value.to_be_bytes()))
            .collect::<BTreeSet<_>>();
        let first_common = CoverageProjection::new(common.clone(), BTreeSet::new())
            .expect("first common coverage");
        let second_common =
            CoverageProjection::new(common, BTreeSet::new()).expect("second common coverage");
        let unique = CoverageProjection::new(
            BTreeSet::from([CampaignHash::derive("beam-unique-coverage", b"unique")]),
            BTreeSet::new(),
        )
        .expect("unique coverage");
        let first = ConfigurationId::from_hash(CampaignHash::derive("beam-config", b"first"));
        let second = ConfigurationId::from_hash(CampaignHash::derive("beam-config", b"second"));
        let third = ConfigurationId::from_hash(CampaignHash::derive("beam-config", b"third"));
        let mut work = BeamProjectionWork::default();

        let scores = beam_cohort_novelty_scores(
            [
                (first, &first_common),
                (second, &second_common),
                (third, &unique),
            ],
            &mut work,
        )
        .expect("cohort novelty scores");

        assert_eq!(scores[&first], 0);
        assert_eq!(scores[&second], 0);
        assert_eq!(scores[&third], 1);
        assert_eq!(work.coverage_identity_visits, 258);

        let metric = "beam.latency";
        let policy = CampaignPolicy::new(
            crate::ScenarioDefId::from_hash(CampaignHash::derive("beam-test", b"scenario")),
            CampaignSeed::from_bytes([0x42; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Beam {
                width: 1,
                novelty_reserve: 1,
            },
            BTreeMap::new(),
            BTreeMap::from([(
                metric.to_owned(),
                Objective::new(metric, ObjectiveGoal::Minimize, 1_000_000).expect("Beam objective"),
            )]),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 64, true, true),
            false,
        )
        .expect("Beam policy");
        let candidates = [(first, 1_u64), (second, 2), (third, 100)]
            .into_iter()
            .map(|(configuration, latency)| {
                let measurements = MeasurementSet::new(BTreeMap::from([(
                    metric.to_owned(),
                    crate::MeasurementSeries::new(
                        vec![MetricValue::Unsigned(latency)],
                        MetricValue::Unsigned(latency),
                        BTreeSet::new(),
                    )
                    .expect("measurement series"),
                )]))
                .expect("measurements");
                let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
                let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                    .expect("evaluation coverage");
                let suffix = configuration.to_hex();
                let observation = Observation::new(
                    crate::AttemptId::from_content_id(ContentId::for_bytes(
                        ObjectKind::CampaignFact,
                        1,
                        format!("attempt-{suffix}").as_bytes(),
                    ))
                    .expect("attempt id"),
                    configuration,
                    crate::ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
                        ObjectKind::Configuration,
                        1,
                        format!("configuration-{suffix}").as_bytes(),
                    ))
                    .expect("configuration artifact id"),
                    crate::BranchPathId::from_content_id(ContentId::for_bytes(
                        ObjectKind::CampaignFact,
                        1,
                        format!("path-{suffix}").as_bytes(),
                    ))
                    .expect("branch path id"),
                    StopOutcome::TerminalSuccess,
                    measurements.id().expect("measurements id"),
                    properties.id().expect("properties id"),
                    coverage.id().expect("coverage id"),
                    BTreeSet::new(),
                )
                .expect("observation");
                let evaluation = crate::evaluate_objectives(
                    &policy,
                    &observation,
                    &properties,
                    BTreeMap::from([(metric.to_owned(), ObjectiveValue::Unsigned(latency))]),
                )
                .expect("objective evaluation");

                crate::RankingCandidate::new(evaluation, scores[&configuration], latency)
            })
            .collect();

        let selection = crate::rank_survivors(
            &policy,
            crate::SurvivorRule::new(crate::RankingMethod::ParetoTopK, 1, 1, 0)
                .expect("Beam survivor rule"),
            candidates,
        )
        .expect("Beam survivor selection");

        assert_eq!(selection.selection().selected(), &BTreeSet::from([third]));
        assert_eq!(
            selection.explanations()[&third].disposition(),
            &RankingDisposition::SelectedNovelty
        );
        assert!(!selection.selection().selected().contains(&first));
    }
}
