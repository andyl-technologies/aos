//! Shared supervisors and driver fixtures for coordination planning tests.

use super::*;

pub(super) fn exercise_beam_out_of_order_completion(
    mode: CampaignMode,
    intervention_learning: InterventionLearningPolicy,
) {
    let (repository, lineage, base_policy) = fixture();
    let policy = CampaignPolicy::new(
        base_policy.scenario(),
        base_policy.campaign_seed(),
        mode,
        ExplorerPolicy::Beam {
            width: 1,
            novelty_reserve: 0,
        },
        base_policy.choice_policies().clone(),
        base_policy.objectives().clone(),
        base_policy.guidance().clone(),
        base_policy.stop_conditions().clone(),
        base_policy.fairness(),
        base_policy.retention(),
        base_policy.admits_scenario_defaults(),
    )
    .expect("Beam closure policy");
    let policy = match intervention_learning {
        InterventionLearningPolicy::Exclude => policy,
        InterventionLearningPolicy::IncludeInGuidance => policy
            .with_intervention_learning_policy(intervention_learning)
            .expect("intervention-learning Beam closure policy"),
    };
    let mode_name = match mode {
        CampaignMode::Strict => "strict",
        CampaignMode::Streaming => "streaming",
        CampaignMode::Statistical => panic!("test only covers deterministic completion modes"),
    };
    let learning_name = match intervention_learning {
        InterventionLearningPolicy::Exclude => "excluded",
        InterventionLearningPolicy::IncludeInGuidance => "included",
    };
    let name = format!("beam-out-of-order-{mode_name}-{learning_name}");
    let genesis = repository
        .create_funded(&name, &lineage, &policy, &BTreeMap::new())
        .expect("create Beam closure campaign");
    let producing_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        &format!("{name}-producing"),
    );
    let requested = repository
        .submit_known_branch_request(&name, genesis.snapshot_id(), &producing_request)
        .expect("submit producing request");

    let first_proposal = finite_proposal(
        &producing_request,
        &policy,
        &repository.head(&name).expect("first proposal head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let first_issued = repository
        .issue_proposal(&name, requested.new_snapshot, &first_proposal)
        .expect("issue first sibling");
    let (first_selection, first_path, first_attempt) =
        branch_attempt(&repository, &producing_request, &first_proposal);
    let first_admitted = repository
        .admit_proposal(
            &name,
            first_issued.new_snapshot,
            first_issued.proposal,
            &first_selection,
            &first_path,
            &first_attempt,
        )
        .expect("admit first sibling");
    let second_proposal = finite_proposal(
        &producing_request,
        &policy,
        &repository.head(&name).expect("second proposal head"),
        ChoiceValue::Boolean(true),
        2,
    );
    let second_issued = repository
        .issue_proposal(&name, first_admitted.new_snapshot, &second_proposal)
        .expect("issue second sibling");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &producing_request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            &name,
            second_issued.new_snapshot,
            second_issued.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("admit second sibling");

    let make_child = |label: &str| {
        let configuration = ConfigurationId::from_hash(CampaignHash::derive(
            "test-beam-closure-child",
            format!("{mode_name}-{label}").as_bytes(),
        ));
        let content = repository
            .publish_configuration_artifact(
                lineage.scenario(),
                lineage.scenario_content(),
                configuration,
                1,
                format!("{mode_name} {label} child").into_bytes(),
            )
            .expect("publish Beam closure child");
        let continuation = branch_request(
            &repository,
            &lineage,
            content,
            configuration,
            &format!("{name}-{label}-continuation"),
        );
        (configuration, content, continuation)
    };
    let (first_configuration, first_content, first_continuation) = make_child("first");
    let (second_configuration, second_content, second_continuation) = make_child("second");
    let measurements = repository
        .publish_measurement_set(&MeasurementSet::new(BTreeMap::new()).expect("measurements"))
        .expect("publish measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let properties_id = repository
        .publish_property_verdict_set(&properties)
        .expect("publish properties");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
        )
        .expect("publish coverage");
    let first_observation = Observation::new(
        first_admitted.attempt,
        first_configuration,
        first_content,
        first_path.id().expect("first path"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties_id,
        coverage,
        BTreeSet::from([first_continuation.opportunity()]),
    )
    .expect("first observation");
    let second_observation = Observation::new(
        second_admitted.attempt,
        second_configuration,
        second_content,
        second_path.id().expect("second path"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties_id,
        coverage,
        BTreeSet::from([second_continuation.opportunity()]),
    )
    .expect("second observation");

    let (first_observed, second_observed) = if mode == CampaignMode::Streaming {
        let second = repository
            .publish_observation(&name, second_admitted.new_snapshot, &second_observation)
            .expect("streaming accepts ordinal two first");
        let second_requested = repository
            .submit_known_branch_request(&name, second.new_snapshot, &second_continuation)
            .expect("submit second continuation");
        let snapshot = repository
            .read_snapshot(second_requested.new_snapshot.content_id())
            .expect("load partially closed streaming cohort");
        let projection = repository
            .project_beam_planner(&snapshot, &policy)
            .expect("project partially closed streaming cohort");
        let second_position = PlanningScanPosition::new(
            second_continuation.branch_point(),
            second_continuation.id().expect("second continuation ID"),
        );
        assert!(matches!(
            projection.candidates[&second_position].cohort_state(),
            crate::PlannerBeamCohortState::AwaitingAttempts(1)
        ));
        let first = repository
            .publish_observation(&name, second_requested.new_snapshot, &first_observation)
            .expect("streaming accepts late ordinal one");
        (first, second)
    } else {
        assert!(matches!(
            repository.publish_observation(
                &name,
                second_admitted.new_snapshot,
                &second_observation
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "strict-completion-order-gap"
            })
        ));
        let first = repository
            .publish_observation(&name, second_admitted.new_snapshot, &first_observation)
            .expect("strict accepts ordinal one");
        let first_requested = repository
            .submit_known_branch_request(&name, first.new_snapshot, &first_continuation)
            .expect("submit first continuation");
        let snapshot = repository
            .read_snapshot(first_requested.new_snapshot.content_id())
            .expect("load partially closed strict cohort");
        let projection = repository
            .project_beam_planner(&snapshot, &policy)
            .expect("project partially closed strict cohort");
        let first_position = PlanningScanPosition::new(
            first_continuation.branch_point(),
            first_continuation.id().expect("first continuation ID"),
        );
        assert!(matches!(
            projection.candidates[&first_position].cohort_state(),
            crate::PlannerBeamCohortState::AwaitingAttempts(1)
        ));
        let second = repository
            .publish_observation(&name, first_requested.new_snapshot, &second_observation)
            .expect("strict accepts ordinal two after ordinal one");
        (first, second)
    };

    let first_evaluation =
        evaluate_objectives(&policy, &first_observation, &properties, BTreeMap::new())
            .expect("evaluate first observation");
    let first_evaluated = repository
        .publish_objective_evaluation(
            &name,
            repository
                .head(&name)
                .expect("first evaluation head")
                .snapshot_id(),
            &first_evaluation,
        )
        .expect("publish first evaluation");
    let second_evaluation =
        evaluate_objectives(&policy, &second_observation, &properties, BTreeMap::new())
            .expect("evaluate second observation");
    let second_evaluated = repository
        .publish_objective_evaluation(&name, first_evaluated.new_snapshot, &second_evaluation)
        .expect("publish second evaluation");
    repository
        .submit_known_branch_request(&name, second_evaluated.new_snapshot, &first_continuation)
        .expect("ensure first continuation");
    let current = repository.head(&name).expect("continuation replay head");
    repository
        .submit_known_branch_request(&name, current.snapshot_id(), &second_continuation)
        .expect("ensure second continuation");
    assert!(first_observed.new_snapshot != second_observed.new_snapshot);
    let settled_snapshot = repository
        .head(&name)
        .expect("settled Beam closure head")
        .snapshot_id();
    let snapshot = repository
        .read_snapshot(settled_snapshot.content_id())
        .expect("load settled Beam closure cohort");
    let projection = repository
        .project_beam_planner(&snapshot, &policy)
        .expect("project settled Beam closure cohort");
    let first_position = PlanningScanPosition::new(
        first_continuation.branch_point(),
        first_continuation.id().expect("first continuation ID"),
    );
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let restarted_snapshot = restarted
        .read_snapshot(settled_snapshot.content_id())
        .expect("load closure cohort after restart");
    let restarted_projection = restarted
        .project_beam_planner(&restarted_snapshot, &policy)
        .expect("cold replay closure cohort");
    assert_eq!(restarted_projection.candidates, projection.candidates);
    assert_eq!(restarted_projection.selections, projection.selections);

    if intervention_learning == InterventionLearningPolicy::Exclude {
        assert!(matches!(
            projection.candidates[&first_position].cohort_state(),
            crate::PlannerBeamCohortState::InterventionExcluded(2)
        ));
        assert!(projection.selections.is_empty());

        let basis = repository
            .publish_canonical_beam_planner_basis()
            .expect("publish excluded-cohort Beam planner basis");
        let invocation = repository
            .prepare_planner_invocation(
                &name,
                settled_snapshot,
                basis.engine(),
                basis.artifact(),
                basis.initial_state(),
                None,
                100,
                PlanningBudget::new(4, 4, 100, 4 * 1024 * 1024, 10_000)
                    .expect("excluded-cohort Beam planning budget"),
            )
            .expect("prepare excluded-cohort Beam invocation");
        let request = repository
            .build_planner_request(
                settled_snapshot,
                invocation.id().expect("excluded-cohort Beam invocation ID"),
            )
            .expect("build excluded-cohort Beam request");
        let output = CanonicalBeamPlanner
            .plan(&request)
            .expect("plan excluded intervention cohort");
        assert!(matches!(
            output.proposal().disposition(),
            PlannerProposalDisposition::NoWork
        ));
        assert_eq!(
            output.proposal().explanation().terms_micros()["intervention-excluded-cohorts"],
            1
        );
        assert_eq!(
            output.proposal().explanation().terms_micros()["intervention-excluded-observations"],
            2
        );
        return;
    }

    let selection = projection.candidates[&first_position]
        .selection()
        .expect("settled selection");
    assert_eq!(
        restarted_projection.candidates[&first_position].selection(),
        Some(selection)
    );
}

#[derive(Clone)]
pub(super) struct ExactCanonicalPlannerSupervisor {
    pub(super) calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::PlannerExecutionSupervisor<CanonicalFrontierPlanner>
    for ExactCanonicalPlannerSupervisor
{
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<crate::SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .expect("page count fits u64")
            + 1;
        Ok(crate::SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

pub(super) fn canonical_planner_driver_basis(
    repository: &CampaignRepository,
) -> (PlannerEngine, PolicyArtifact, PlannerState, PlanningBudget) {
    let engine = CanonicalFrontierPlanner::descriptor().expect("canonical planner descriptor");
    let dependency_bytes = b"campaign planner driver dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("planner dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("engine id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("planner artifact");
    let initial_state = CanonicalFrontierPlanner::initial_state().expect("initial planner state");
    let budget = PlanningBudget::new(1, 1, 8, 8_192, 100).expect("planner budget");
    (engine, artifact, initial_state, budget)
}

pub(super) fn legacy_request_budget_planner_driver_basis(
    repository: &CampaignRepository,
) -> (PlannerEngine, PolicyArtifact, PlannerState, PlanningBudget) {
    let engine = PlannerEngine::new(
        "crucible-canonical-frontier",
        5,
        1,
        BTreeSet::from([
            crate::CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned(),
            crate::CANONICAL_FRONTIER_BUDGET_CAPABILITY.to_owned(),
            crate::CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY.to_owned(),
        ]),
    )
    .expect("legacy request-budget planner descriptor");
    let dependency_bytes = b"legacy request-budget planner driver dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("legacy planner dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("legacy engine id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("legacy planner artifact");
    let initial_state = CanonicalFrontierPlanner::initial_state_for_engine(&engine)
        .expect("legacy initial planner state");
    let budget = PlanningBudget::new(1, 1, 8, 8_192, 100).expect("legacy planner budget");
    (engine, artifact, initial_state, budget)
}

pub(super) fn canonical_planner_client(
    authority: &PlannerAuthorityKey,
    calls: Arc<std::sync::atomic::AtomicUsize>,
) -> crate::PlannerClient<
    crate::AuthorizedPlannerService<CanonicalFrontierPlanner, ExactCanonicalPlannerSupervisor>,
> {
    crate::PlannerClient::new(
        crate::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            ExactCanonicalPlannerSupervisor { calls },
            authority.clone(),
        ),
        authority.clone(),
    )
}

#[derive(Clone)]
pub(super) struct ExactSearchPlannerSupervisor {
    pub(super) calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::PlannerExecutionSupervisor<crate::CanonicalSearchPlanner>
    for ExactSearchPlannerSupervisor
{
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        engine: &mut crate::CanonicalSearchPlanner,
        request: &PlannerRequest,
    ) -> Result<crate::SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .expect("page count fits u64")
            + 1;
        Ok(crate::SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

pub(super) fn canonical_search_planner_client(
    authority: &PlannerAuthorityKey,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    strategy: crate::CanonicalSearchStrategy,
) -> crate::PlannerClient<
    crate::AuthorizedPlannerService<crate::CanonicalSearchPlanner, ExactSearchPlannerSupervisor>,
> {
    crate::PlannerClient::new(
        crate::AuthorizedPlannerService::new(
            crate::CanonicalSearchPlanner::new(strategy),
            ExactSearchPlannerSupervisor { calls },
            authority.clone(),
        ),
        authority.clone(),
    )
}

pub(super) struct SupervisorExecutor {
    pub(super) execution: ExecutionId,
    pub(super) cancellations: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::ExecutorService for SupervisorExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Accepted {
                execution: self.execution,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorStatusService for SupervisorExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &crate::GetAttemptExecutionRequest,
    ) -> Result<crate::GetAttemptExecutionResponse, Self::Error> {
        crate::GetAttemptExecutionResponse::new(
            request,
            crate::GetAttemptExecutionDisposition::Running,
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorControlService for SupervisorExecutor {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &crate::CheckpointAttemptExecutionRequest,
    ) -> Result<crate::CheckpointAttemptExecutionResponse, Self::Error> {
        crate::CheckpointAttemptExecutionResponse::new(
            request,
            crate::CheckpointAttemptExecutionDisposition::Requested,
        )
        .map_err(|_| "response encoding")
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &crate::CancelAttemptExecutionRequest,
    ) -> Result<crate::CancelAttemptExecutionResponse, Self::Error> {
        self.cancellations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::CancelAttemptExecutionResponse::new(
            request,
            crate::CancelAttemptExecutionDisposition::Canceled,
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorResumeService for SupervisorExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &crate::ResumeAttemptExecutionRequest,
    ) -> Result<crate::ResumeAttemptExecutionResponse, Self::Error> {
        crate::ResumeAttemptExecutionResponse::new(
            request,
            crate::ResumeAttemptExecutionDisposition::NotCurrent,
        )
        .map_err(|_| "response encoding")
    }
}
