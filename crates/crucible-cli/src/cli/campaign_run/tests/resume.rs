//! Tests authenticated campaign resume projection.

use super::*;

#[test]
fn resume_authenticates_attempt_timeout_and_bounded_primary_frontier() {
    let temporary = TempDir::new().or_panic("bounded resume workspace");
    let evidence = resume_evidence(Schedule::empty(), VirtualTime { ticks: 5 });
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::VirtualTime;
    plan.max_virtual_time_ticks = Some(10);
    let primary =
        StopCondition::bounded(StopCondition::VirtualTimePicoseconds(10), Some(20), Some(8))
            .or_panic("bounded resume stop");
    let reached = StopOutcome::BoundedPrimaryReached {
        stop: primary,
        proof: crucible_campaign::BoundedStopProof::new(10, 2),
    };

    assert_eq!(
        campaign_resume_status(&plan, &reached).or_panic("bounded primary status"),
        (BackendCommandStatus::Passed, OutcomeKind::Passed)
    );
    assert_eq!(
        campaign_resume_final_state(&plan, &reached, OutcomeKind::Passed),
        "virtual-time"
    );
    validate_campaign_resume_frontier(
        &plan,
        VirtualTime { ticks: 5 },
        &reached,
        VirtualTime { ticks: 10 },
    )
    .or_panic("bounded primary frontier");
    assert!(
        validate_campaign_resume_frontier(
            &plan,
            VirtualTime { ticks: 5 },
            &reached,
            VirtualTime { ticks: 9 },
        )
        .is_err()
    );

    plan.max_virtual_time_ticks = Some(30);
    let policy_stop =
        StopCondition::bounded(StopCondition::VirtualTimePicoseconds(30), Some(20), Some(8))
            .or_panic("policy-preempted resume stop");
    let timed_out = StopOutcome::PolicyTimeout {
        stop: policy_stop,
        kind: crucible_campaign::PolicyTimeoutKind::VirtualTime,
        proof: crucible_campaign::BoundedStopProof::new(20, 3),
    };
    assert_eq!(
        campaign_resume_status(&plan, &timed_out).or_panic("policy timeout status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );
    plan.terminal_condition = RunTerminalCondition::Stopped;
    assert_eq!(
        campaign_resume_final_state(&plan, &timed_out, OutcomeKind::Timeout),
        "timeout"
    );
}

#[test]
fn campaign_resume_route_accepts_only_standard_selection_free_workflows() {
    let temporary = TempDir::new().or_panic("resume route workspace");
    let supported = Schedule::from_decisions([
        crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 5 },
            order: Vec::new(),
        }),
        crucible::Decision::RngDraw(crucible::RngDecision {
            stream: crucible::RngStreamId::from_name("guarded-campaign-resume-route"),
            value: 7,
        }),
    ]);
    let evidence = resume_evidence(supported, VirtualTime { ticks: 5 });
    let default = default_resume_plan(&evidence, temporary.path());
    assert!(guarded_campaign_resume_eligible(&default, &evidence));

    let mut virtual_time = default.clone();
    virtual_time.terminal_condition = RunTerminalCondition::VirtualTime;
    virtual_time.max_virtual_time = Some(String::from("10ticks"));
    virtual_time.max_virtual_time_ticks = Some(10);
    assert!(guarded_campaign_resume_eligible(&virtual_time, &evidence));

    let mut unsupported_evidence = evidence.clone();
    unsupported_evidence.schedule =
        Schedule::from_decisions([crucible::Decision::Override(crucible::OverrideDecision {
            point: crucible::SchedulingPoint {
                key: String::from("guarded-campaign-resume/override"),
            },
            choice: crucible::ChoiceTag {
                name: String::from("alternate"),
            },
        })]);
    assert!(!guarded_campaign_resume_eligible(
        &default,
        &unsupported_evidence
    ));
    unsupported_evidence.schedule = typed_selection_schedule(&evidence.scenario);
    assert!(!guarded_campaign_resume_eligible(
        &default,
        &unsupported_evidence
    ));

    let mut property = default.clone();
    property.terminal_condition = RunTerminalCondition::Property;
    assert_eq!(
        guarded_campaign_resume_eligible(&property, &evidence),
        !evidence.scenario_form.properties().assertions().is_empty()
    );
    let property_evidence = resume_evidence_with_assertion(VirtualTime { ticks: 5 });
    let mut property = default_resume_plan(&property_evidence, temporary.path());
    property.terminal_condition = RunTerminalCondition::Property;
    assert!(guarded_campaign_resume_eligible(
        &property,
        &property_evidence
    ));
    assert_eq!(
        guarded_resume_stop(&property, &property_evidence).or_panic("property stop"),
        StopCondition::Observation(ObservationCondition::AnyAssertionViolationTransition)
    );
    let mut interactive = default.clone();
    interactive.execution_mode = RunExecutionMode::Interactive;
    interactive.startup_commands = vec![SessionCommandKind::Start];
    interactive.accepted_interactive_commands = run_interactive_session_command_set();
    assert!(!guarded_campaign_resume_eligible(&interactive, &evidence));
    let mut changed_controls = default;
    changed_controls.initial_control_commands.clear();
    assert!(!guarded_campaign_resume_eligible(
        &changed_controls,
        &evidence
    ));
}

#[test]
fn campaign_resume_projection_preserves_source_oracle_watch_and_cleanup() {
    let temporary = TempDir::new().or_panic("resume projection workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let schedule = Schedule::empty();
    let evidence = resume_evidence(schedule.clone(), source_frontier);
    let mut resume_plan = default_resume_plan(&evidence, temporary.path());
    resume_plan.terminal_condition = RunTerminalCondition::VirtualTime;
    resume_plan.max_virtual_time = Some(String::from("10ticks"));
    resume_plan.max_virtual_time_ticks = Some(10);
    resume_plan.watch_streams_live_status = true;
    let ResumeCampaignFixture {
        campaign,
        checkpoints,
        checkpoint_directory,
        checkpoint_root,
    } = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::VirtualTimePicoseconds(10),
        true,
    );
    let result = campaign_resume_workflow_report(&resume_plan, &evidence, &campaign);
    let proof = campaign.resume().cloned().or_panic("campaign resume proof");
    let terminal_observation = campaign.terminal().id();
    drop(campaign);
    let report = complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        result,
    )
    .or_panic("project campaign resume into the command contract");

    assert_eq!(report.run.execution_owner, RunExecutionOwner::Campaign);
    assert_eq!(report.source_checkpoint, evidence.checkpoint.id);
    assert_eq!(report.resumed_configuration, evidence.configuration.id());
    assert_eq!(report.run.final_frontier_ticks, 10);
    assert_eq!(report.run.final_state, "virtual-time");
    assert_eq!(
        report.run.terminal_savepoint,
        Some(report.terminal_oracle.fat_checkpoint)
    );
    assert_eq!(
        report
            .terminal_oracle
            .schedule
            .prefix(evidence.schedule.len()),
        Ok(evidence.schedule.clone())
    );
    assert!(report.run.campaign_replay_closure.is_some());
    assert!(!report.run.watch_statuses.is_empty());
    assert!(
        report
            .run
            .watch_statuses
            .iter()
            .all(|status| status.contains("owner=campaign"))
    );
    assert!(
        report.run.watch_statuses.iter().any(|status| {
            status.contains(&format!("observation={}", proof.source_observation()))
        })
    );
    assert!(
        report
            .run
            .watch_statuses
            .iter()
            .any(|status| { status.contains(&format!("observation={terminal_observation}")) })
    );
    assert_eq!(proof.source_frontier(), source_frontier);
    assert!(proof.source_savepoint().is_some());
    assert!(proof.ready().is_some());
    assert!(proof.selection().is_some());
    assert!(proof.continuation().is_some());

    assert!(!checkpoint_root.exists());
}

#[test]
fn campaign_resume_projects_quiescence_observation() {
    let temporary = TempDir::new().or_panic("resume observation workspace");
    let evidence = resume_evidence(Schedule::empty(), VirtualTime { ticks: 5 });
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::Quiescence;
    let fixture = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::Observation(ObservationCondition::SchedulerQuiescent),
        false,
    );

    let report = campaign_resume_workflow_report(&plan, &evidence, &fixture.campaign)
        .or_panic("project quiescence observation resume");
    let stop = fixture.campaign.terminal().observation().stop();
    let StopOutcome::ObservationReached(proof) = stop else {
        panic!("quiescence resume requires an observation proof");
    };

    assert_eq!(proof.condition(), &ObservationCondition::SchedulerQuiescent);
    assert_eq!(
        proof.satisfaction(),
        ObservationStopSatisfaction::SchedulerQuiescent
    );
    assert_eq!(report.run.status, BackendCommandStatus::Passed);
    assert_eq!(report.run.outcome, Some(OutcomeKind::Passed));
    assert_eq!(report.run.final_state, "quiescent");
}

#[test]
fn campaign_resume_projects_property_violation_observation() {
    let temporary = TempDir::new().or_panic("resume property workspace");
    let scenario = fixed_checkpoint_scenario_form();
    let evidence =
        resume_evidence_for_scenario(scenario, Schedule::empty(), VirtualTime { ticks: 5 });
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::Property;
    let fixture = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::Observation(ObservationCondition::AnyAssertionViolationTransition),
        false,
    );

    let report = campaign_resume_workflow_report(&plan, &evidence, &fixture.campaign)
        .or_panic("project property observation resume");
    let stop = fixture.campaign.terminal().observation().stop();
    let StopOutcome::ObservationReached(proof) = stop else {
        panic!("property resume requires an observation proof");
    };

    assert_eq!(
        proof.condition(),
        &ObservationCondition::AnyAssertionViolationTransition
    );
    assert_eq!(
        proof.satisfaction(),
        ObservationStopSatisfaction::AssertionViolationTransition
    );
    assert_eq!(
        proof
            .assertion_witness()
            .or_panic("property observation witness")
            .assertion(),
        "no-split-brain"
    );
    assert_eq!(report.run.status, BackendCommandStatus::Failed);
    assert_eq!(report.run.outcome, Some(OutcomeKind::Failed));
    assert_eq!(report.run.final_state, "property-failed");
}

#[test]
fn campaign_resume_projection_does_not_rewind_for_an_earlier_deadline() {
    let temporary = TempDir::new().or_panic("resume no-rewind workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let evidence = resume_evidence(Schedule::empty(), source_frontier);
    let mut resume_plan = default_resume_plan(&evidence, temporary.path());
    resume_plan.terminal_condition = RunTerminalCondition::VirtualTime;
    resume_plan.max_virtual_time = Some(String::from("3ticks"));
    resume_plan.max_virtual_time_ticks = Some(3);
    let ResumeCampaignFixture {
        campaign,
        checkpoints,
        checkpoint_directory,
        checkpoint_root,
    } = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::VirtualTimePicoseconds(3),
        false,
    );

    assert_eq!(
        campaign.terminal().observation().stop(),
        &StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(3))
    );
    assert_eq!(campaign.evidence().frontier(), source_frontier);

    let result = campaign_resume_workflow_report(&resume_plan, &evidence, &campaign);
    drop(campaign);
    let report = complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        result,
    )
    .or_panic("project no-rewind campaign resume into the command contract");

    assert_eq!(report.run.status, BackendCommandStatus::Passed);
    assert_eq!(report.run.outcome, Some(OutcomeKind::Passed));
    assert_eq!(report.run.final_frontier_ticks, source_frontier.ticks);
    assert_eq!(report.terminal_oracle.frontier, source_frontier);
    assert!(!checkpoint_root.exists());
}

#[test]
fn campaign_resume_frontier_validation_binds_reached_deadlines_only() {
    let temporary = TempDir::new().or_panic("resume frontier workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let evidence = resume_evidence(Schedule::empty(), source_frontier);
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::VirtualTime;
    plan.max_virtual_time = Some(String::from("3ticks"));
    plan.max_virtual_time_ticks = Some(3);
    let earlier_stop = StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(3));

    validate_campaign_resume_frontier(&plan, source_frontier, &earlier_stop, source_frontier)
        .or_panic("an earlier deadline must preserve the source frontier");
    assert!(
        validate_campaign_resume_frontier(
            &plan,
            source_frontier,
            &earlier_stop,
            VirtualTime { ticks: 3 }
        )
        .is_err()
    );
    assert!(
        validate_campaign_resume_frontier(
            &plan,
            source_frontier,
            &earlier_stop,
            VirtualTime { ticks: 6 }
        )
        .is_err()
    );

    plan.max_virtual_time = Some(String::from("10ticks"));
    plan.max_virtual_time_ticks = Some(10);
    let future_stop = StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(10));
    validate_campaign_resume_frontier(
        &plan,
        source_frontier,
        &future_stop,
        VirtualTime { ticks: 10 },
    )
    .or_panic("a future deadline must advance to that exact frontier");
}

#[test]
fn campaign_resume_terminal_outcomes_bypass_the_requested_future_deadline() {
    let temporary = TempDir::new().or_panic("resume terminal outcome workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let evidence = resume_evidence(Schedule::empty(), source_frontier);
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::VirtualTime;
    plan.max_virtual_time = Some(String::from("10ticks"));
    plan.max_virtual_time_ticks = Some(10);
    let terminal_cases = [
        (
            StopOutcome::ModeledTimeout(String::from("deadline")),
            BackendCommandStatus::Timeout,
            OutcomeKind::Timeout,
        ),
        (
            StopOutcome::GuestCrash(String::from("guest-crash")),
            BackendCommandStatus::Crashed,
            OutcomeKind::Crashed,
        ),
        (
            StopOutcome::AssertionFailure(String::from("invariant")),
            BackendCommandStatus::Failed,
            OutcomeKind::Failed,
        ),
        (
            StopOutcome::ScenarioFailure(vec![String::from("scenario failed")]),
            BackendCommandStatus::Failed,
            OutcomeKind::Failed,
        ),
    ];

    for (stop, expected_status, expected_outcome) in terminal_cases {
        assert_eq!(
            campaign_resume_status(&plan, &stop).or_panic("terminal outcome status"),
            (expected_status, expected_outcome)
        );
        validate_campaign_resume_frontier(&plan, source_frontier, &stop, source_frontier)
            .or_panic("terminal outcomes may precede the requested future deadline");
    }
}

#[test]
fn transient_checkpoint_cleanup_preserves_the_execution_error() {
    let temporary = TempDir::new().or_panic("cleanup workspace");
    let checkpoint_directory = tempfile::Builder::new()
        .prefix("transient-resume-error-")
        .tempdir_in(temporary.path())
        .or_panic("transient exact directory");
    let checkpoint_root = checkpoint_directory.path().to_path_buf();
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "guarded-campaign-resume-cleanup-test",
        &checkpoint_root,
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(backend, 1024 * 1024).or_panic("exact checkpoint store"),
    );
    let expected = "injected campaign resume failure";
    let result: Result<(), CliError> = Err(backend_error(expected));

    let error = complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        result,
    )
    .error_or_panic("execution failure must survive successful cleanup");

    assert!(error.to_string().contains(expected));
    assert!(!checkpoint_root.exists());
}
