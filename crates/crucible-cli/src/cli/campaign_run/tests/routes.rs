//! Tests campaign run and save route admission.

use super::*;

#[test]
fn default_run_reports_attempt_timeout_and_bounded_primary_separately() {
    let mut plan = default_run_plan();
    plan.max_virtual_time_ticks = Some(10);
    let primary =
        StopCondition::bounded(StopCondition::VirtualTimeNanoseconds(10), Some(20), Some(8))
            .or_panic("bounded default stop");
    let reached = StopOutcome::BoundedPrimaryReached {
        stop: primary,
        proof: crucible_campaign::BoundedStopProof::new(10, 2),
    };
    assert_eq!(
        campaign_stop_status(&plan, &reached).or_panic("primary status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );
    assert!(campaign_stop_label(&reached).starts_with("bounded-primary-reached:"));

    plan.max_virtual_time_ticks = Some(30);
    let policy_stop =
        StopCondition::bounded(StopCondition::VirtualTimeNanoseconds(30), Some(20), Some(8))
            .or_panic("policy-preempted default stop");
    let policy = StopOutcome::PolicyTimeout {
        stop: policy_stop,
        kind: crucible_campaign::PolicyTimeoutKind::VirtualTime,
        proof: crucible_campaign::BoundedStopProof::new(20, 3),
    };
    assert_eq!(
        campaign_stop_status(&plan, &policy).or_panic("policy timeout status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );
    assert!(campaign_stop_label(&policy).contains("policy-timeout:VirtualTime:"));
}

#[test]
fn batch_campaign_route_accepts_exact_semantic_stops() {
    let mut default = default_run_plan();
    assert!(batch_campaign_run_eligible(&default));
    default.campaign_deployment = Some(PathBuf::from("guarded.toml"));
    assert!(batch_campaign_run_eligible(&default));

    let mut plan = default.clone();
    plan.terminal_condition = RunTerminalCondition::VirtualTime;
    plan.max_virtual_time = Some(String::from("1tick"));
    plan.max_virtual_time_ticks = Some(1);
    assert!(batch_campaign_run_eligible(&plan));
    assert_eq!(
        guarded_discovery_stop(&plan).or_panic("virtual-time stop"),
        StopCondition::VirtualTimeNanoseconds(1)
    );

    let cli = Cli::parse_from([
        "crucible",
        "run",
        "builtin:happy-path.scn",
        "--until",
        "virtual-time",
        "--max-virtual-time",
        "2ms",
    ]);
    let Commands::Run(args) = &cli.command else {
        panic!("expected run command");
    };
    let plan = plan_run_invocation(args, Path::new("."))
        .or_panic("virtual-time run should produce an invocation plan");
    assert_eq!(
        guarded_discovery_stop(&plan).or_panic("converted virtual-time stop"),
        StopCondition::VirtualTimeNanoseconds(2_000_000)
    );
    assert_eq!(
        campaign_stop_status(
            &plan,
            &StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(2_000_000)),
        )
        .or_panic("reached deadline status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );

    let mut plan = default.clone();
    plan.max_virtual_time = Some(String::from("1tick"));
    assert!(!batch_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.max_virtual_time_ticks = Some(1);
    assert!(!batch_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.terminal_condition = RunTerminalCondition::Stopped;
    assert!(batch_campaign_run_eligible(&plan));
    assert_eq!(
        guarded_discovery_stop(&plan).or_panic("terminal stop"),
        StopCondition::Terminal
    );

    let mut plan = default.clone();
    plan.terminal_condition = RunTerminalCondition::Property;
    assert!(batch_campaign_run_eligible(&plan));
    assert_eq!(
        guarded_discovery_stop(&plan).or_panic("property observation stop"),
        StopCondition::Observation(ObservationCondition::AnyAssertionViolationTransition)
    );

    let form = crucible::ScenarioDefForm::from_components(
        plan.scenario.scenario_form().world(),
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        plan.scenario.scenario_form().seed(),
    )
    .or_panic("assertion-free run scenario");
    plan.scenario = plan.scenario.with_form(form);
    assert!(!batch_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.max_quanta = Some(1);
    assert!(batch_campaign_run_eligible(&plan));
    assert_eq!(
        guarded_discovery_stop(&plan).or_panic("execution-quanta stop"),
        StopCondition::ExecutionQuanta(1)
    );
    assert_eq!(
        campaign_stop_status(
            &plan,
            &StopOutcome::Reached(StopCondition::ExecutionQuanta(1)),
        )
        .or_panic("reached execution-quanta status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );

    plan.max_virtual_time = Some(String::from("2ms"));
    plan.max_virtual_time_ticks = Some(2_000_000);
    assert_eq!(
        guarded_discovery_stop(&plan).or_panic("combined stop"),
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: 2_000_000,
            execution_quanta: 1,
        }
    );
    assert_eq!(
        campaign_stop_status(
            &plan,
            &StopOutcome::Reached(StopCondition::VirtualTimeOrExecutionQuanta {
                virtual_time_nanoseconds: 2_000_000,
                execution_quanta: 1,
            }),
        )
        .or_panic("reached combined status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );

    let mut plan = default.clone();
    plan.save_policy = RunSavePolicy::OnFail;
    assert!(!batch_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.watch_streams_live_status = true;
    assert!(batch_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.startup_commands.pop();
    assert!(!batch_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.initial_control_commands.clear();
    assert!(!batch_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.host_profile = VERIFY_HOSTILE_PROFILES[0];
    assert!(batch_campaign_run_eligible(&plan));

    let mut plan = default;
    plan.collect_execution_fingerprints = true;
    assert!(!batch_campaign_run_eligible(&plan));
}

#[test]
fn campaign_save_route_accepts_standard_virtual_time_and_marker_saves() {
    let cli = Cli::parse_from([
        "crucible",
        "save",
        "builtin:happy-path.scn",
        "--at",
        "virtual-time",
        "--max-virtual-time",
        "2ms",
    ]);
    let Commands::Save(args) = &cli.command else {
        panic!("expected save command");
    };
    let mut plan = plan_save_invocation(args, Path::new("."), Path::new("./artifacts"))
        .or_panic("virtual-time save plan");

    assert!(plan.run_plan.campaign_deployment.is_none());
    assert!(guarded_campaign_save_eligible(&plan));

    plan.run_plan.campaign_deployment = Some(PathBuf::from("guarded.toml"));
    assert!(guarded_campaign_save_eligible(&plan));

    let marker_cli = Cli::parse_from([
        "crucible",
        "save",
        "builtin:happy-path.scn",
        "--at",
        "marker",
        "--marker",
        "checkpoint",
    ]);
    let Commands::Save(args) = &marker_cli.command else {
        panic!("expected marker save command");
    };
    let marker = plan_save_invocation(args, Path::new("."), Path::new("./artifacts"))
        .or_panic("marker save plan");
    assert!(guarded_campaign_save_eligible(&marker));
    assert_eq!(
        guarded_campaign_save_stop(&marker).or_panic("marker campaign stop"),
        StopCondition::NamedBoundary(String::from("checkpoint"))
    );

    let mut quiescence = plan.clone();
    quiescence.at = SaveAtArg::Quiescence;
    quiescence.run_plan.terminal_condition = RunTerminalCondition::Quiescence;
    quiescence.run_plan.max_virtual_time = None;
    quiescence.run_plan.max_virtual_time_ticks = None;
    assert!(guarded_campaign_save_eligible(&quiescence));
    assert_eq!(
        guarded_campaign_save_stop(&quiescence).or_panic("quiescence campaign stop"),
        StopCondition::Observation(ObservationCondition::SchedulerQuiescent)
    );

    let mut unsupported = plan.clone();
    unsupported.selector = Some(SaveAtSelector::Marker {
        name: String::from("checkpoint"),
    });
    assert!(!guarded_campaign_save_eligible(&unsupported));

    let mut unsupported = plan;
    unsupported.run_plan.execution_mode = RunExecutionMode::Interactive;
    assert!(!guarded_campaign_save_eligible(&unsupported));
}

#[test]
fn campaign_save_schedule_taxonomy_admits_typed_selections() {
    let scenario = default_run_plan().scenario.scenario_def().clone();
    let schedule = typed_selection_schedule(&scenario);

    validate_portable_campaign_save_schedule(&schedule)
        .or_panic("typed saves carry their portable replay closure during export");
    validate_portable_campaign_save_schedule(&Schedule::empty())
        .or_panic("selection-free saves remain portable");
}

#[test]
fn campaign_virtual_time_save_exports_closure_for_resume_and_replay_readers() {
    assert_campaign_save_exports_closure(
        &["--at", "virtual-time", "--max-virtual-time", "2ms"],
        StopCondition::VirtualTimeNanoseconds(2_000_000),
        false,
    );
}

#[test]
fn campaign_marker_save_exports_current_event_proof_for_resume_and_replay_readers() {
    let marker = "guarded-campaign-save-fixture-marker";
    assert_campaign_save_exports_closure(
        &["--at", "marker", "--marker", marker],
        StopCondition::NamedBoundary(String::from(marker)),
        false,
    );
}

#[test]
fn campaign_marker_save_after_a_typed_choice_exports_a_portable_resume() {
    let marker = "guarded-campaign-save-fixture-marker";
    assert_campaign_save_exports_closure(
        &["--at", "marker", "--marker", marker],
        StopCondition::NamedBoundary(String::from(marker)),
        true,
    );
}

#[test]
fn campaign_virtual_time_save_after_a_typed_choice_exports_a_portable_resume() {
    assert_campaign_save_exports_closure(
        &["--at", "virtual-time", "--max-virtual-time", "2ticks"],
        StopCondition::VirtualTimeNanoseconds(2),
        true,
    );
}

#[test]
fn campaign_quiescence_save_after_a_typed_choice_replays_its_observation_proof() {
    assert_campaign_save_exports_closure(
        &["--at", "quiescence"],
        StopCondition::Observation(ObservationCondition::SchedulerQuiescent),
        true,
    );
}

#[test]
fn campaign_property_save_after_a_typed_choice_replays_its_observation_proof() {
    assert_campaign_save_exports_closure(
        &["--at", "property", "--property", "no-split-brain"],
        StopCondition::Observation(ObservationCondition::AssertionViolationTransition(
            String::from("no-split-brain"),
        )),
        true,
    );
}

#[test]
fn campaign_typed_save_without_a_replay_closure_fails_before_export() {
    let marker = "guarded-campaign-save-fixture-marker";
    let stop = StopCondition::NamedBoundary(String::from(marker));
    let capture = capture_campaign_save(&["--at", "marker", "--marker", marker], stop.clone());
    let report = campaign_save_workflow_report(&capture.save_plan, &capture.campaign, &stop)
        .or_panic("typed campaign save report");
    let thin_plan = plan_cli_invocation(&capture.cli);
    let backend_plan = plan_backend_selection(&capture.cli)
        .or_panic("backend plan")
        .or_panic("save requires a backend");
    let mut outcome =
        finish_save_workflow_outcome(&thin_plan, &backend_plan, None, &capture.save_plan, report)
            .or_panic("finish typed save report");
    outcome
        .savepoint_oracle
        .as_mut()
        .or_panic("typed save oracle")
        .schedule = typed_selection_schedule(capture.save_plan.run_plan.scenario.scenario_def());
    outcome.savepoint_replay_closure = None;

    let error = export_savepoint_handle(&capture.save_plan, &mut outcome)
        .error_or_panic("typed save missing its closure must fail before persistence");

    assert!(
        error
            .to_string()
            .contains("missing its authenticated replay closure")
    );
    assert!(!capture.output.exists());
    assert!(!capture.temporary.path().join("_indexes").exists());
}
