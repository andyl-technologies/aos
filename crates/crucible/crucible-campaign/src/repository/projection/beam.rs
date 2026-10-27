//! Page-scoped Beam membership over immutable producing-request cohorts.
//!
//! A Beam planner page carries one candidate per `Ready` scan position. Each
//! candidate depends only on its own request, the canonical observation that
//! discovered the request's `(parent, opportunity)` pair, and the cohort of that
//! observation's producing request or standalone attempt (its *barrier*). The
//! owner therefore recomputes exactly the served page from snapshot indexes:
//!
//! 1. the observation-root choice-source index names the earliest canonical
//!    discovering observation of each position;
//! 2. the producing request's dense proposal-ordinal index, the
//!    proposal-admission index, and `observations.attempt` enumerate the
//!    cohort's attempts, yielding both modeled members and closure counts in one
//!    walk;
//! 3. a settled cohort decodes only its own members' observations, coverage
//!    projections, and objective evaluations.
//!
//! No owner retains campaign-wide decoded observations. One page's work is
//! bounded by the page size and its cohorts' proposal budgets, not by campaign
//! history, and every survivor decision charges its own evidence bounds.
//!
//! The novelty reserve counts coverage identities present in exactly one
//! canonical configuration representative inside the closed cohort. It never
//! consults the later global coverage union, so a settled survivor decision is
//! stable as unrelated campaign observations arrive.

use std::collections::btree_map::Entry;

use super::*;

// Page-wide bounds on the cohort walks. A page holds at most
// `MAX_PLANNER_SCAN_PAGE_ITEMS` positions, so these scale with the page and the
// producing requests' proposal budgets rather than with campaign history.
const MAX_BEAM_TARGET_COHORT_ATTEMPTS: usize = 262_144;
const MAX_BEAM_TARGET_PROPOSAL_VISITS: usize = 262_144;
// One cohort's novelty scoring needs every representative's coverage at once to
// compute cohort-local frequencies. Both counters reset for each cohort.
const MAX_BEAM_COHORT_COVERAGE_BYTES: usize = 256 * 1024 * 1024;
const MAX_BEAM_COHORT_COVERAGE_IDENTITY_VISITS: usize = 4_000_000;
// Candidates and survivor bundles built for one page, charged as they are
// produced so a page of many settled cohorts stays bounded while it is built.
const MAX_BEAM_PAGE_PROJECTION_BYTES: usize = 256 * 1024 * 1024;

/// Beam candidates and survivor bundles projected for one planner page.
pub(in crate::repository) struct BeamPlannerProjection {
    pub(in crate::repository) candidates:
        BTreeMap<PlanningScanPosition, crate::PlannerBeamCandidate>,
    pub(in crate::repository) selections: BTreeMap<SurvivorSelectionId, SurvivorSelectionBundle>,
}

/// Work charged while projecting one page.
#[derive(Default)]
pub(in crate::repository) struct BeamPageWork {
    proposal_visits: usize,
    cohort_attempts: usize,
    projection_bytes: usize,
    /// Observation bodies decoded for sources and settled cohort members.
    pub(in crate::repository) decoded_observations: usize,
}

/// Work charged for one cohort's survivor decision.
#[derive(Default)]
struct BeamCohortWork {
    coverage_bytes: usize,
    coverage_identity_visits: usize,
    evidence_bytes: usize,
}

/// Canonical discovering observation of one position and its barrier.
#[derive(Clone, Copy)]
struct BeamSource {
    observation: ContentId,
    configuration: ConfigurationId,
    barrier: crate::PlannerBeamBarrier,
}

/// One modeled cohort attempt, resolved from accounting before its
/// observation body is decoded.
struct BeamCohortMember {
    attempt: AttemptId,
    observation: ContentId,
    ordinal: AdmissionOrdinal,
    cause: BranchRequestCause,
}

#[derive(Clone, Copy, Default)]
struct BeamAttemptClosure {
    pending: u64,
    closed: crate::PlannerBeamClosureSummary,
}

/// Modeled members and non-modeled closure counts of one barrier.
#[derive(Default)]
struct BeamCohort {
    /// Continuation state of the producing request; `None` for a standalone
    /// attempt, which has no request to close.
    request_state: Option<crate::ContinuationState>,
    members: Vec<BeamCohortMember>,
    closure: BeamAttemptClosure,
}

/// Objective evidence of one closed cohort.
enum BeamCohortEvidence {
    /// Every eligible member is evaluated; one representative per configuration.
    Complete(BTreeMap<ConfigurationId, BeamRepresentative>),
    /// The number of eligible members still lacking an evaluation.
    AwaitingEvaluations(u64),
}

/// Earliest admitted modeled observation of one configuration in a cohort.
struct BeamRepresentative {
    ordinal: AdmissionOrdinal,
    observation: ObservationId,
    evaluation: ObjectiveEvaluation,
    coverage: CoverageProjection,
}

impl CampaignRepository {
    /// Projects Beam candidates for the `Ready` positions of one served page.
    ///
    /// Positions that are not `Ready` produce no candidate. Every candidate is
    /// a pure function of its own position and barrier, so projecting a page
    /// yields the same candidate bytes as any other page containing that
    /// position.
    ///
    /// # Errors
    ///
    /// Returns an integrity error when the policy is not a valid Beam policy,
    /// the page exceeds `MAX_PLANNER_SCAN_PAGE_ITEMS`, a source observation or
    /// cohort index is missing or inconsistent, or a page or cohort work bound
    /// is exceeded. Store and codec errors propagate from record reads.
    pub(in crate::repository) fn project_beam_page(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        positions: &[PlanningScanPosition],
    ) -> Result<BeamPlannerProjection, CampaignRepositoryError> {
        self.project_beam_page_measured(snapshot, policy, positions, &mut BeamPageWork::default())
    }

    /// Projects one page like [`Self::project_beam_page`] and reports its work.
    pub(in crate::repository) fn project_beam_page_measured(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        positions: &[PlanningScanPosition],
        work: &mut BeamPageWork,
    ) -> Result<BeamPlannerProjection, CampaignRepositoryError> {
        let rule = beam_survivor_rule(policy)?;
        let page_limit = usize::try_from(MAX_PLANNER_SCAN_PAGE_ITEMS)
            .map_err(|_| integrity("beam-page-position-count"))?;
        if positions.len() > page_limit {
            return Err(integrity("beam-page-position-count"));
        }
        let input_view = snapshot.snapshot.planning_view().id()?;
        let policy_id = policy.id()?;

        let mut sources = BTreeMap::new();
        let mut candidate_bases = BTreeMap::new();
        for position in positions {
            let continuation = self.planner_continuation_projection(snapshot, *position)?;
            if continuation.state() != crate::ContinuationState::Ready {
                continue;
            }
            let request = self.read_branch_request(position.source().content_id())?;
            let source = match sources.entry((request.parent(), request.opportunity())) {
                Entry::Occupied(entry) => *entry.get(),
                Entry::Vacant(entry) => *entry.insert(self.beam_source(
                    snapshot,
                    request.parent(),
                    request.opportunity(),
                    work,
                )?),
            };
            let parent = self.read_configuration_artifact(request.parent().content_id())?;
            if source.configuration != parent.configuration() {
                return Err(integrity("beam-frontier-parent-observation-mismatch"));
            }
            candidate_bases.insert(
                *position,
                (request.parent(), parent.configuration(), source),
            );
        }

        let mut cohort_sources = BTreeMap::<crate::PlannerBeamBarrier, BTreeSet<ContentId>>::new();
        for (_, _, source) in candidate_bases.values() {
            cohort_sources
                .entry(source.barrier)
                .or_default()
                .insert(source.observation);
        }

        let mut selections = BTreeMap::new();
        let mut cohort_states = BTreeMap::new();
        for (barrier, source_observations) in cohort_sources {
            let cohort = self.beam_cohort(snapshot, barrier, work)?;
            let members = cohort
                .members
                .iter()
                .map(|member| member.observation)
                .collect::<BTreeSet<_>>();
            if !source_observations.is_subset(&members) {
                return Err(integrity("beam-source-observation-is-outside-its-cohort"));
            }
            let state =
                self.beam_cohort_state(snapshot, policy, rule, &cohort, &mut selections, work)?;
            cohort_states.insert(barrier, (state, cohort.closure.closed));
        }

        let mut candidates = BTreeMap::new();
        for (position, (parent, configuration, source)) in candidate_bases {
            let (state, closed) = cohort_states
                .get(&source.barrier)
                .ok_or_else(|| integrity("beam-page-cohort-state-is-missing"))?;
            let candidate = crate::PlannerBeamCandidate::new(
                input_view,
                policy_id,
                position,
                parent,
                configuration,
                source.barrier,
                state.clone(),
                *closed,
            )?;
            charge_beam_limit(
                &mut work.projection_bytes,
                candidate.canonical_bytes().len(),
                MAX_BEAM_PAGE_PROJECTION_BYTES,
                "beam-page-projection-byte-limit",
            )?;
            candidates.insert(position, candidate);
        }

        Ok(BeamPlannerProjection {
            candidates,
            selections,
        })
    }

    /// Resolves the earliest canonical observation that discovered one pair.
    fn beam_source(
        &self,
        snapshot: &LoadedSnapshot,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
        work: &mut BeamPageWork,
    ) -> Result<BeamSource, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        let content = self
            .choice_source_observation(roots.observations, parent, opportunity)?
            .ok_or_else(|| integrity("beam-frontier-source-observation-is-missing"))?;

        charge_beam_decoded_observation(work)?;
        let observation = self.decode_observation(content)?;
        if self.merkle.get(
            roots.observations,
            attempt_observation_key(observation.attempt()),
        )? != Some(content)
        {
            return Err(integrity("beam-source-observation-is-not-canonical"));
        }
        if observation.child_content() != parent
            || !self.observation_discovers(&observation, opportunity)?
        {
            return Err(integrity("beam-frontier-parent-observation-mismatch"));
        }

        Ok(BeamSource {
            observation: content,
            configuration: observation.child(),
            barrier: self.beam_observation_barrier(snapshot, &observation)?,
        })
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
                attempt_execution_basis_key(observation.attempt()),
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

    fn beam_cohort(
        &self,
        snapshot: &LoadedSnapshot,
        barrier: crate::PlannerBeamBarrier,
        work: &mut BeamPageWork,
    ) -> Result<BeamCohort, CampaignRepositoryError> {
        match barrier {
            crate::PlannerBeamBarrier::Standalone { attempt } => {
                self.standalone_beam_cohort(snapshot, attempt)
            }
            crate::PlannerBeamBarrier::Request { request } => {
                self.request_beam_cohort(snapshot, request, work)
            }
        }
    }

    /// Returns the single modeled member of a proposal-less attempt.
    fn standalone_beam_cohort(
        &self,
        snapshot: &LoadedSnapshot,
        attempt: AttemptId,
    ) -> Result<BeamCohort, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        let observation = self
            .merkle
            .get(roots.observations, attempt_observation_key(attempt))?
            .ok_or_else(|| integrity("beam-standalone-cohort-observation-is-missing"))?;
        let basis_content = self
            .merkle
            .get(roots.accounting, attempt_execution_basis_key(attempt))?
            .ok_or_else(|| integrity("beam-observation-execution-basis-is-missing"))?;
        let admission = self.read_attempt_admission(basis_content)?;
        let AttemptAdmissionRole::ExecutionBasis {
            proposal: None,
            cause,
            admission_ordinal,
        } = admission.role()
        else {
            return Err(integrity("beam-standalone-cohort-execution-basis-role"));
        };
        if admission.attempt() != attempt {
            return Err(integrity("beam-observation-execution-basis-mismatch"));
        }

        Ok(BeamCohort {
            request_state: None,
            members: vec![BeamCohortMember {
                attempt,
                observation,
                ordinal: admission_ordinal,
                cause,
            }],
            closure: BeamAttemptClosure::default(),
        })
    }

    /// Walks one producing request's proposals into members and closure counts.
    ///
    /// Membership is defined in the attempt-to-request direction: an
    /// observation belongs to request `R` when its attempt's execution basis
    /// names a proposal of `R`. Walking `R`'s dense proposal ordinals reaches
    /// the same set because each proposal has at most one admission and each
    /// attempt exactly one execution basis; the walk checks the latter so a
    /// divergent index fails closed instead of changing the cohort.
    fn request_beam_cohort(
        &self,
        snapshot: &LoadedSnapshot,
        request_id: BranchRequestId,
        work: &mut BeamPageWork,
    ) -> Result<BeamCohort, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        let request = self.read_branch_request(request_id.content_id())?;
        let request_position = PlanningScanPosition::new(request.branch_point(), request_id);
        let mut cohort = BeamCohort {
            request_state: Some(
                self.planner_continuation_projection(snapshot, request_position)?
                    .state(),
            ),
            ..BeamCohort::default()
        };
        for ordinal in 1..=request.budget().maximum_proposals() {
            charge_beam_target_proposal_visit(&mut work.proposal_visits)?;
            let Some(proposal_content) = self
                .merkle
                .get(roots.exploration, proposal_ordinal_key(request_id, ordinal))?
            else {
                break;
            };
            let proposal = self.read_proposal(proposal_content)?;
            if proposal.request() != request_id || proposal.ordinal() != ordinal {
                return Err(integrity("beam-cohort-proposal-index-mismatch"));
            }
            let Some(admission_content) = self.merkle.get(
                roots.accounting,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            else {
                continue;
            };

            // A deduplicated proposal converged on an attempt whose execution
            // basis, and therefore cohort, belongs to the earlier proposal.
            let admission = self.read_attempt_admission(admission_content)?;
            let AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(admitted_proposal),
                cause,
                admission_ordinal,
            } = admission.role()
            else {
                continue;
            };
            if admitted_proposal.content_id() != proposal_content {
                return Err(integrity("beam-cohort-proposal-admission-mismatch"));
            }
            let attempt = admission.attempt();
            if self
                .merkle
                .get(roots.accounting, attempt_execution_basis_key(attempt))?
                != Some(admission_content)
            {
                return Err(integrity("beam-cohort-attempt-execution-basis-mismatch"));
            }
            charge_beam_limit(
                &mut work.cohort_attempts,
                1,
                MAX_BEAM_TARGET_COHORT_ATTEMPTS,
                "beam-target-cohort-attempt-count",
            )?;

            if let Some(observation) = self
                .merkle
                .get(roots.observations, attempt_observation_key(attempt))?
            {
                cohort.members.push(BeamCohortMember {
                    attempt,
                    observation,
                    ordinal: admission_ordinal,
                    cause,
                });
            } else if let Some(fact) = self
                .merkle
                .get(roots.accounting, non_modeled_attempt_key(attempt))?
            {
                let CampaignFact::AttemptClosed {
                    attempt: closed_attempt,
                    disposition,
                    ..
                } = self.read_fact(fact)?
                else {
                    return Err(integrity("beam-attempt-closure-index-type-mismatch"));
                };
                if closed_attempt != attempt {
                    return Err(integrity("beam-attempt-closure-basis-mismatch"));
                }
                cohort.closure.closed.record(disposition)?;
            } else {
                cohort.closure.pending = cohort
                    .closure
                    .pending
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-pending-attempt-count-overflow"))?;
            }
        }
        Ok(cohort)
    }

    /// Settles a cohort only once its request and every attempt are closed.
    fn beam_cohort_state(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        rule: crate::SurvivorRule,
        cohort: &BeamCohort,
        selections: &mut BTreeMap<SurvivorSelectionId, SurvivorSelectionBundle>,
        work: &mut BeamPageWork,
    ) -> Result<crate::PlannerBeamCohortState, CampaignRepositoryError> {
        match cohort.request_state {
            Some(
                state @ (crate::ContinuationState::Open
                | crate::ContinuationState::Ready
                | crate::ContinuationState::WaitingForFeedback(_)),
            ) => Ok(crate::PlannerBeamCohortState::AwaitingRequestClosure(state)),
            Some(crate::ContinuationState::Exhausted | crate::ContinuationState::Closed) | None
                if cohort.closure.pending != 0 =>
            {
                Ok(crate::PlannerBeamCohortState::AwaitingAttempts(
                    cohort.closure.pending,
                ))
            }
            Some(crate::ContinuationState::Exhausted | crate::ContinuationState::Closed) | None => {
                self.settled_beam_cohort_state(
                    snapshot,
                    policy,
                    rule,
                    &cohort.members,
                    selections,
                    work,
                )
            }
        }
    }

    fn settled_beam_cohort_state(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        rule: crate::SurvivorRule,
        members: &[BeamCohortMember],
        selections: &mut BTreeMap<SurvivorSelectionId, SurvivorSelectionBundle>,
        work: &mut BeamPageWork,
    ) -> Result<crate::PlannerBeamCohortState, CampaignRepositoryError> {
        if members.is_empty() {
            return Err(integrity("beam-frontier-cohort-has-no-modeled-observation"));
        }
        let mut intervention_exclusions = 0_u64;
        let mut eligible = Vec::with_capacity(members.len());
        for member in members {
            if execution_basis_is_guidance_eligible(policy, member.cause) {
                eligible.push(member);
            } else {
                intervention_exclusions = intervention_exclusions
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-intervention-exclusion-count-overflow"))?;
            }
        }
        if eligible.is_empty() {
            return Ok(crate::PlannerBeamCohortState::InterventionExcluded(
                intervention_exclusions,
            ));
        }
        let candidate_count = u64::try_from(eligible.len())
            .map_err(|_| integrity("beam-cohort-candidate-count-overflow"))?;
        if eligible.len() > crate::MAX_SURVIVOR_CANDIDATES {
            return Ok(crate::PlannerBeamCohortState::CohortLimitExceeded(
                candidate_count,
            ));
        }

        let mut cohort_work = BeamCohortWork::default();
        let representatives =
            match self.beam_cohort_evidence(snapshot, policy, &eligible, &mut cohort_work, work)? {
                BeamCohortEvidence::Complete(representatives) => representatives,
                BeamCohortEvidence::AwaitingEvaluations(missing) => {
                    return Ok(crate::PlannerBeamCohortState::AwaitingEvaluations(missing));
                }
            };
        let novelty_scores = beam_cohort_novelty_scores(
            representatives
                .iter()
                .map(|(configuration, representative)| (*configuration, &representative.coverage)),
            &mut cohort_work,
        )?;
        let mut ranking = Vec::with_capacity(representatives.len());
        for (configuration, representative) in representatives {
            let novelty = novelty_scores
                .get(&configuration)
                .copied()
                .ok_or_else(|| integrity("beam-novelty-score-is-missing"))?;
            ranking.push(crate::RankingCandidate::new(
                representative.evaluation,
                novelty,
                representative.ordinal.value(),
            ));
        }

        let bundle = crate::rank_survivors(policy, rule, ranking)?;
        charge_beam_bundle_bytes(&mut work.projection_bytes, &bundle)?;
        let selection_id = bundle.selection().id()?;
        selections.insert(selection_id, bundle);

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

    /// Loads one closed cohort's objective evidence and representatives.
    ///
    /// Each configuration is represented by its earliest admitted modeled
    /// observation. Once any evaluation is missing the decision cannot settle,
    /// so later members are only counted and their bodies are not loaded.
    fn beam_cohort_evidence(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        members: &[&BeamCohortMember],
        cohort_work: &mut BeamCohortWork,
        work: &mut BeamPageWork,
    ) -> Result<BeamCohortEvidence, CampaignRepositoryError> {
        let policy_id = policy.id()?;
        let mut missing = 0_u64;
        let mut representatives = BTreeMap::<ConfigurationId, BeamRepresentative>::new();
        for member in members {
            let observation_id = ObservationId::from_content_id(member.observation)?;
            let Some(evaluation_content) = self.merkle.get(
                snapshot.snapshot.roots().observations,
                objective_evaluation_key(policy_id, observation_id),
            )?
            else {
                missing = missing
                    .checked_add(1)
                    .ok_or_else(|| integrity("beam-missing-evaluation-count-overflow"))?;
                continue;
            };
            if missing != 0 {
                continue;
            }

            let evaluation = self.read_objective_evaluation(evaluation_content)?;
            crate::objective::charge_survivor_evidence_bytes(
                &mut cohort_work.evidence_bytes,
                evaluation.canonical_bytes().len(),
            )?;
            charge_beam_decoded_observation(work)?;
            let observation = self.decode_observation(member.observation)?;
            if observation.attempt() != member.attempt {
                return Err(integrity("beam-cohort-observation-attempt-mismatch"));
            }
            let configuration = observation.child();
            if evaluation.configuration() != configuration
                || evaluation.observation() != observation_id
                || evaluation.policy() != policy_id
            {
                return Err(integrity("beam-objective-evaluation-basis-mismatch"));
            }
            let coverage = self.read_coverage_projection(observation.coverage().content_id())?;
            charge_beam_limit(
                &mut cohort_work.coverage_bytes,
                coverage.canonical_bytes().len(),
                MAX_BEAM_COHORT_COVERAGE_BYTES,
                "beam-coverage-projection-byte-limit",
            )?;

            let replaces = representatives.get(&configuration).is_none_or(|current| {
                (member.ordinal, observation_id) < (current.ordinal, current.observation)
            });
            if replaces {
                representatives.insert(
                    configuration,
                    BeamRepresentative {
                        ordinal: member.ordinal,
                        observation: observation_id,
                        evaluation,
                        coverage,
                    },
                );
            }
        }

        if missing == 0 {
            Ok(BeamCohortEvidence::Complete(representatives))
        } else {
            Ok(BeamCohortEvidence::AwaitingEvaluations(missing))
        }
    }
}

fn beam_survivor_rule(
    policy: &CampaignPolicy,
) -> Result<crate::SurvivorRule, CampaignRepositoryError> {
    let crate::ExplorerPolicy::Beam {
        width,
        novelty_reserve,
    } = policy.explorer()
    else {
        return Err(integrity("beam-projection-requires-beam-policy"));
    };
    let keep =
        u32::try_from(*width).map_err(|_| integrity("beam-survivor-width-exceeds-owner-limit"))?;
    let novelty = u32::try_from(*novelty_reserve)
        .map_err(|_| integrity("beam-novelty-reserve-exceeds-owner-limit"))?;
    if keep as usize > crate::MAX_SURVIVOR_CANDIDATES {
        return Err(integrity("beam-survivor-width-exceeds-owner-limit"));
    }
    Ok(crate::SurvivorRule::new(
        crate::RankingMethod::ParetoTopK,
        keep,
        novelty,
        0,
    )?)
}

fn charge_beam_bundle_bytes(
    projection_bytes: &mut usize,
    bundle: &SurvivorSelectionBundle,
) -> Result<(), CampaignRepositoryError> {
    let evaluations = bundle
        .evaluations()
        .values()
        .map(|evaluation| evaluation.canonical_bytes().len());
    let explanations = bundle
        .explanations()
        .values()
        .map(|explanation| explanation.canonical_bytes().len());
    let selection = std::iter::once(bundle.selection().canonical_bytes().len());
    for bytes in evaluations.chain(explanations).chain(selection) {
        charge_beam_limit(
            projection_bytes,
            bytes,
            MAX_BEAM_PAGE_PROJECTION_BYTES,
            "beam-page-projection-byte-limit",
        )?;
    }
    Ok(())
}

fn beam_cohort_novelty_scores<'a>(
    coverages: impl IntoIterator<Item = (ConfigurationId, &'a CoverageProjection)>,
    work: &mut BeamCohortWork,
) -> Result<BTreeMap<ConfigurationId, u64>, CampaignRepositoryError> {
    let coverages = coverages.into_iter().collect::<Vec<_>>();
    let mut frequencies = BTreeMap::<CampaignHash, u64>::new();
    for (_, coverage) in &coverages {
        for identity in coverage.identities() {
            charge_beam_coverage_identity_visit(work)?;
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
            charge_beam_coverage_identity_visit(work)?;
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

fn charge_beam_coverage_identity_visit(
    work: &mut BeamCohortWork,
) -> Result<(), CampaignRepositoryError> {
    charge_beam_limit(
        &mut work.coverage_identity_visits,
        1,
        MAX_BEAM_COHORT_COVERAGE_IDENTITY_VISITS,
        "beam-coverage-identity-visit-limit",
    )
}

fn charge_beam_decoded_observation(work: &mut BeamPageWork) -> Result<(), CampaignRepositoryError> {
    work.decoded_observations = work
        .decoded_observations
        .checked_add(1)
        .ok_or_else(|| integrity("beam-decoded-observation-count-overflow"))?;
    Ok(())
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
    charge_beam_limit(
        visited,
        1,
        MAX_BEAM_TARGET_PROPOSAL_VISITS,
        "beam-target-proposal-visit-count",
    )
}

#[cfg(test)]
impl CampaignRepository {
    /// Projects every page of one snapshot's planning frontier and merges the
    /// results, for tests that assert outcomes across the whole frontier.
    pub(in crate::repository) fn project_beam_frontier(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<BeamPlannerProjection, CampaignRepositoryError> {
        let view = snapshot.snapshot.planning_view();
        let mut merged = BeamPlannerProjection {
            candidates: BTreeMap::new(),
            selections: BTreeMap::new(),
        };
        let mut after = None;
        loop {
            let page = self.planner_scan_page(&view, after, MAX_PLANNER_SCAN_PAGE_ITEMS - 1)?;
            let projection = self.project_beam_page(snapshot, policy, page.positions())?;
            merged.candidates.extend(projection.candidates);
            merged.selections.extend(projection.selections);
            if page.complete() {
                return Ok(merged);
            }
            after = page.last();
        }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- these focused pure-projection tests use panics to identify invalid fixtures.
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::{
        CampaignCommandId, CampaignMode, CampaignSeed, DebugSessionId, ExplorerPolicy,
        FairnessPolicy, MeasurementSet, Objective, ObjectiveGoal, ObjectiveValue,
        PropertyVerdictSet, RankingDisposition, RetentionPolicy, StopOutcome,
    };
    use crucible_store::content_store::{ContentId, ObjectKind};

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
        let mut work = BeamCohortWork::default();

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
            CampaignPolicy::identity(
                crate::ScenarioDefId::from_hash(CampaignHash::derive("beam-test", b"scenario")),
                CampaignSeed::from_bytes([0x42; 32]),
                CampaignMode::Strict,
                ExplorerPolicy::Beam {
                    width: 1,
                    novelty_reserve: 1,
                },
            ),
            CampaignPolicy::rules(
                BTreeMap::new(),
                BTreeMap::from([(
                    metric.to_owned(),
                    Objective::new(metric, ObjectiveGoal::Minimize, 1_000_000)
                        .expect("Beam objective"),
                )]),
                BTreeMap::new(),
                BTreeSet::new(),
                FairnessPolicy::new(0, 0).expect("fairness"),
                RetentionPolicy::new(true, 64, true, true),
                false,
            ),
        )
        .expect("Beam policy");
        assert!(!execution_basis_is_guidance_eligible(
            &policy,
            BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
                "beam-test",
                b"operator",
            ))),
        ));
        assert!(!execution_basis_is_guidance_eligible(
            &policy,
            BranchRequestCause::Debugger(DebugSessionId::from_hash(CampaignHash::derive(
                "beam-test",
                b"debugger",
            ))),
        ));
        let candidates = [(first, 1_u64), (second, 2), (third, 100)]
            .into_iter()
            .map(|(configuration, latency)| {
                let measurements =
                    MeasurementSet::test_evaluation(&latency.to_be_bytes(), BTreeSet::new())
                        .expect("measurements");
                let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
                let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                    .expect("evaluation coverage");
                let suffix = configuration.to_hex();
                let observation = Observation::new(
                    crate::AttemptId::from_content_id(ContentId::for_bytes(
                        ObjectKind::CampaignFact,
                        9,
                        format!("attempt-{suffix}").as_bytes(),
                    ))
                    .expect("attempt id"),
                    Observation::outcome(
                        configuration,
                        crate::ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
                            ObjectKind::Configuration,
                            1,
                            format!("configuration-{suffix}").as_bytes(),
                        ))
                        .expect("configuration artifact id"),
                        crate::BranchPathId::from_content_id(ContentId::for_bytes(
                            ObjectKind::CampaignFact,
                            2,
                            format!("path-{suffix}").as_bytes(),
                        ))
                        .expect("branch path id"),
                        StopOutcome::TerminalSuccess,
                        measurements.id().expect("measurements id"),
                        properties.id().expect("properties id"),
                        coverage.id().expect("coverage id"),
                    ),
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
