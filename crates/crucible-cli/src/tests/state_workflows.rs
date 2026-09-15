//! Save, resume, and search/fuzz workflow tests.

use super::*;
#[test]
pub(super) fn cli_save_selector_proof_rejects_invalid_breakpoint_evidence()
-> Result<(), Box<dyn Error>> {
    let selector = SaveAtSelector::PropertyViolation {
        assertion: String::from(SAVE_DOUBLE_ASSERTION_VIOLATION),
    };
    let marker_selector = SaveAtSelector::Marker {
        name: String::from(SAVE_DOUBLE_GUEST_MARKER),
    };
    assert_eq!(
        save_selector_predicate(&marker_selector)?,
        crucible::Predicate::guest_marker(crucible::MarkerId::from_name(SAVE_DOUBLE_GUEST_MARKER))
    );
    let boundary = save_selector_test_boundary(2, 2);
    let predicate = save_selector_predicate(&selector)?;
    let valid_firing =
        save_selector_test_firing(7, predicate.clone(), BreakpointDisposition::Suspend, 2, 2);

    validate_save_selector_firing(&selector, 7, &boundary, std::slice::from_ref(&valid_firing))?;

    let error = validate_save_selector_firing(&selector, 7, &boundary, &[])
        .expect_err("missing breakpoint firing must fail");
    assert!(matches!(error, CliError::Identity(_)));
    assert!(error.to_string().contains("did not fire"));

    let wrong_predicate = crucible::Predicate::assertion_state(
        crucible::AssertionId::from_name("split-active"),
        crucible::AssertionPhase::Violated,
    );
    let error = validate_save_selector_firing(
        &selector,
        7,
        &boundary,
        &[save_selector_test_firing(
            7,
            wrong_predicate,
            BreakpointDisposition::Suspend,
            2,
            2,
        )],
    )
    .expect_err("wrong predicate must fail");
    assert!(matches!(error, CliError::Identity(_)));
    assert!(error.to_string().contains("predicate"));

    let error = validate_save_selector_firing(
        &selector,
        7,
        &boundary,
        &[save_selector_test_firing(
            7,
            predicate.clone(),
            BreakpointDisposition::Trace,
            2,
            2,
        )],
    )
    .expect_err("wrong breakpoint disposition must fail");
    assert!(matches!(error, CliError::Identity(_)));
    assert!(error.to_string().contains("disposition"));

    let error = validate_save_selector_firing(
        &selector,
        7,
        &boundary,
        &[save_selector_test_firing(
            7,
            predicate.clone(),
            BreakpointDisposition::Suspend,
            1,
            2,
        )],
    )
    .expect_err("frontier mismatch must fail");
    assert!(matches!(error, CliError::Identity(_)));
    assert!(error.to_string().contains("boundary"));

    let error = validate_save_selector_firing(
        &selector,
        7,
        &boundary,
        &[save_selector_test_firing(
            7,
            predicate,
            BreakpointDisposition::Suspend,
            2,
            1,
        )],
    )
    .expect_err("quantum mismatch must fail");
    assert!(matches!(error, CliError::Identity(_)));
    assert!(error.to_string().contains("quantum"));

    let ambiguous_name = "check~frontier=999:forged";
    let summary = SaveBoundaryEvidence {
        at: SaveAtArg::Property,
        selector: Some(SaveAtSelector::PropertyViolation {
            assertion: ambiguous_name.to_string(),
        }),
        frontier_ticks: 2,
        quanta: 2,
        proof: SaveBoundaryProof::Breakpoint(valid_firing),
    }
    .canonical_summary();
    assert!(summary.contains("property-violation:check~frontier%3D999%3Aforged"));
    assert!(!summary.contains(ambiguous_name));
    assert!(summary.contains("disposition=suspend"));

    Ok(())
}

pub(super) fn save_selector_test_boundary(
    frontier: u64,
    quanta: u64,
) -> crucible_api::SessionSummary {
    crucible_api::SessionSummary {
        session: SessionRef::new(
            crucible_api::SessionId::new(1),
            1,
            crucible::Seed::from_u64(1),
        ),
        state: LiveStateKind::Paused,
        outcome: None,
        terminal_savepoint: None,
        frontier: crucible::VirtualTime { ticks: frontier },
        event_log_len: 0,
        quanta_stepped: quanta,
    }
}

#[test]
pub(super) fn remote_resume_rejects_final_snapshot_counter_regression() -> Result<(), Box<dyn Error>>
{
    let scenario_form = valid_run_scenario_form()?;
    let configuration = crucible::Configuration::genesis(scenario_form.scenario_def());
    let boundary = save_selector_test_boundary(5, 7);
    let mut snapshot = EngineSnapshot {
        state: EngineState::Stopped {
            outcome: Outcome::Passed,
        },
        configuration,
        terminal_savepoint: None,
        frontier: VirtualTime { ticks: 4 },
        event_log_len: 0,
        quanta: 7,
    };

    let frontier_error = validate_remote_resume_final_snapshot_boundary(&snapshot, &boundary)
        .err()
        .ok_or_else(|| {
            std::io::Error::other("a final snapshot behind the observed frontier must fail")
        })?;
    assert!(matches!(frontier_error, CliError::Identity(_)));
    assert!(frontier_error.to_string().contains("frontier 4"));
    assert!(frontier_error.to_string().contains("boundary 5"));

    snapshot.frontier = boundary.frontier;
    snapshot.quanta = 6;
    let quantum_error = validate_remote_resume_final_snapshot_boundary(&snapshot, &boundary)
        .err()
        .ok_or_else(|| {
            std::io::Error::other("a final snapshot behind the observed quantum must fail")
        })?;
    assert!(matches!(quantum_error, CliError::Identity(_)));
    assert!(quantum_error.to_string().contains("quantum 6"));
    assert!(quantum_error.to_string().contains("boundary 7"));

    snapshot.quanta = boundary.quanta_stepped;
    validate_remote_resume_final_snapshot_boundary(&snapshot, &boundary)?;
    Ok(())
}

pub(super) fn save_selector_test_firing(
    id: BreakpointId,
    predicate: crucible::Predicate,
    disposition: BreakpointDisposition,
    frontier: u64,
    quanta: u64,
) -> BreakpointFiring {
    BreakpointFiring {
        sequence: 0,
        id,
        predicate,
        disposition,
        frontier: crucible::VirtualTime { ticks: frontier },
        quanta,
        scheduler_controls: Vec::new(),
    }
}

#[test]
pub(super) fn cli_resume_workflow_plans_handles_hashes_and_rejects_malformed_inputs()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let form = valid_run_scenario_form()?;
    let scenario = form.scenario_def();
    let schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    ));
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint = configuration.id();
    let canonical_log = content_address_bytes(b"resume-log");
    let handle_path = write_savepoint_handle_fixture(
        temp.path(),
        "resume-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &canonical_log,
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("resume"),
        handle_path.display().to_string(),
        String::from("--interactive"),
        String::from("--watch"),
    ]);
    let Commands::Resume(args) = &cli.command else {
        panic!("expected resume command");
    };
    let plan = plan_resume_invocation(args, temp.path())?;

    assert!(matches!(plan.savepoint, ResumeSavepointRef::Handle(_)));
    assert_eq!(plan.savepoint.checkpoint(), checkpoint);
    assert_eq!(plan.terminal_condition, RunTerminalCondition::Quiescence);
    assert_eq!(plan.execution_mode, RunExecutionMode::Interactive);
    assert!(plan.watch_streams_live_status);
    assert_eq!(plan.startup_commands, vec![SessionCommandKind::Start]);
    assert!(
        plan.accepted_interactive_commands
            .contains(&SessionCommandKind::Continue)
    );

    let ResumeSavepointRef::Handle(resolved) = &plan.savepoint else {
        panic!("expected decoded handle");
    };
    let handle = &resolved.handle;
    assert_eq!(handle.label, "resume-source");
    assert_eq!(handle.scenario_id_hex, scenario.id().to_hex());
    assert_eq!(handle.scenario_label, "resume-scenario.toml");
    assert_eq!(handle.scenario_payload, form.to_compact_binary());
    assert_eq!(handle.schedule_payload, schedule.to_compact_binary());
    assert_eq!(handle.frontier_ticks, 1);
    assert_eq!(handle.at, SaveAtArg::Quiescence);
    assert_eq!(handle.selector, None);
    assert!(matches!(
        handle.boundary_proof,
        Some(SavepointBoundaryProof::Breakpoint {
            frontier_ticks: 1,
            ..
        })
    ));
    assert_eq!(
        handle.boundary_predicate,
        Some(crucible::Predicate::quiescent())
    );
    assert_eq!(handle.terminal_condition, RunTerminalCondition::Quiescence);
    assert_eq!(handle.materialization, "create-savepoint:reply");
    assert_eq!(handle.oracle_status, "fat==thin-passed");
    assert_eq!(handle.canonical_log_digest, canonical_log);

    let v3_text = fs::read_to_string(&handle_path)?;
    let mismatched_proof = v3_text.replace("\tsuspend\t1\t1\n", "\tsuspend\t8\t1\n");
    let error = decode_savepoint_handle(mismatched_proof.as_bytes())
        .expect_err("v3 boundary proof must match the top-level frontier");
    assert!(matches!(error, CliError::Artifact(_)));
    assert!(error.to_string().contains("did not match handle frontier"));

    let retired_v2_text = v3_text
        .lines()
        .filter(|line| {
            !line.starts_with("selector\t")
                && !line.starts_with("boundary-proof\t")
                && !line.starts_with("boundary-predicate\t")
        })
        .map(|line| {
            if line == format!("schema\t{REPLAY_CLOSURE_SAVEPOINT_HANDLE_SCHEMA}") {
                String::from("schema\tcrucible.savepoint-handle.v2")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let error = decode_savepoint_handle(retired_v2_text.as_bytes())
        .expect_err("retired v2 savepoint handles must fail closed");
    let message = error.to_string();
    assert!(message.contains("unsupported savepoint handle schema"));

    let reference = format_content_hash_ref(checkpoint);
    let hash_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("resume"),
        reference.clone(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("1ticks"),
    ]);
    let Commands::Resume(args) = &hash_cli.command else {
        panic!("expected resume command");
    };
    let hash_plan = plan_resume_invocation(args, temp.path())?;
    assert_eq!(hash_plan.savepoint.checkpoint(), checkpoint);
    assert_eq!(
        hash_plan.terminal_condition,
        RunTerminalCondition::VirtualTime
    );
    assert_eq!(hash_plan.max_virtual_time_ticks, Some(1));

    let missing = ResumeArgs::default();
    let error = match plan_resume_invocation(&missing, temp.path()) {
        Ok(_) => panic!("resume without savepoint must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);

    let error =
        match Cli::try_parse_from(["crucible", "resume", &reference, "--until", "virtual-time"]) {
            Ok(_) => panic!("virtual-time resume requires a duration budget"),
            Err(error) => error,
        };
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    assert_eq!(cli_parse_error_exit_code(&error), 64);

    let malformed = temp.path().join("malformed.crucible-savepoint");
    fs::write(
        &malformed,
        format!("schema\t{REPLAY_CLOSURE_SAVEPOINT_HANDLE_SCHEMA}\n"),
    )?;
    let malformed_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("resume"),
        malformed.display().to_string(),
    ]);
    let Commands::Resume(args) = &malformed_cli.command else {
        panic!("expected resume command");
    };
    let error = match plan_resume_invocation(args, temp.path()) {
        Ok(_) => panic!("malformed savepoint handle must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Artifact(_)));
    assert_eq!(error.exit_code(), 5);
    assert!(error.to_string().contains("missing `scenario` line"));

    Ok(())
}

#[test]
pub(super) fn cli_resume_workflow_rejects_bare_hash_without_authenticated_handle()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let checkpoint = crucible::ContentHash::from_bytes(b"missing-resume-store-index");
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        temp.path().join("store").display().to_string(),
        String::from("resume"),
        format_content_hash_ref(checkpoint),
    ]);
    let error = match dispatch(&cli) {
        Ok(_) => panic!("resume from a missing store index must fail as artifact input"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Artifact(_)));
    assert_eq!(error.exit_code(), 5);
    assert!(
        error
            .to_string()
            .contains("requires an authenticated .crucible-savepoint handle")
    );

    Ok(())
}

#[test]
pub(super) fn cli_resume_workflow_rejects_unverified_handle_evidence() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    ));
    let configuration = crucible::Configuration {
        def: scenario,
        schedule: schedule.clone(),
    };
    let checkpoint = configuration.id();
    let handle_path = write_savepoint_handle_fixture(
        temp.path(),
        "resume-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &content_address_bytes(b"resume-log"),
    )?;
    let handle_text = fs::read_to_string(&handle_path)?;
    let bad_oracle = temp.path().join("bad-oracle.crucible-savepoint");
    fs::write(
        &bad_oracle,
        handle_text.replace("oracle\tfat==thin-passed\n", "oracle\tfailed\n"),
    )?;
    let bad_materialization = temp.path().join("bad-materialization.crucible-savepoint");
    fs::write(
        &bad_materialization,
        handle_text.replace(
            "materialization\tcreate-savepoint\treply\n",
            "materialization\tmanual\tfixture\n",
        ),
    )?;

    for (path, needle) in [
        (bad_oracle, "oracle status"),
        (bad_materialization, "materialization"),
    ] {
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--quiet"),
            String::from("--backend"),
            String::from("double"),
            String::from("resume"),
            path.display().to_string(),
        ]);
        let error = match dispatch(&cli) {
            Ok(_) => panic!("resume must reject unverified savepoint evidence"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Artifact(_)));
        assert_eq!(error.exit_code(), 5);
        assert!(error.to_string().contains(needle));
    }

    Ok(())
}

#[test]
pub(super) fn cli_resume_workflow_rejects_tampered_handle_frontier() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    ));
    let configuration = crucible::Configuration {
        def: scenario,
        schedule: schedule.clone(),
    };
    let handle_path = write_savepoint_handle_fixture(
        temp.path(),
        "resume-source",
        &form,
        &schedule,
        configuration.id(),
        1,
        &content_address_bytes(b"resume-log"),
    )?;
    let tampered_path = temp.path().join("bad-frontier.crucible-savepoint");
    fs::write(
        &tampered_path,
        fs::read_to_string(&handle_path)?
            .replace("frontier\t1\n", "frontier\t8\n")
            .replace("\tsuspend\t1\t1\n", "\tsuspend\t8\t1\n"),
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("resume"),
        tampered_path.display().to_string(),
    ]);
    let error = match dispatch(&cli) {
        Ok(_) => panic!("resume must reject a tampered savepoint frontier"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(
        error
            .to_string()
            .contains("exceeded the latest recorded decision boundary")
    );

    Ok(())
}

#[test]
pub(super) fn cli_resume_terminal_oracle_rejects_non_descendant_snapshot()
-> Result<(), Box<dyn Error>> {
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let source_schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    ));
    let source_configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: source_schedule.clone(),
    };
    let source_checkpoint =
        checkpoint_for_resume_configuration(&source_configuration, VirtualTime { ticks: 1 })?;
    let replay_closure = crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(b"CCRC\0\0\0\x01\0\0\0\0")?;
    let evidence = ResumeHandleEvidence {
        scenario_form: form,
        scenario: scenario.clone(),
        schedule: source_schedule,
        configuration: source_configuration,
        checkpoint: source_checkpoint,
        replay_closure,
        source_observation_proof: None,
        source_observation_evidence: None,
    };
    let sibling_schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 2 },
            order: Vec::new(),
        },
    ));
    let final_configuration = crucible::Configuration {
        def: scenario,
        schedule: sibling_schedule,
    };
    let final_checkpoint =
        checkpoint_for_resume_configuration(&final_configuration, VirtualTime { ticks: 1 })?;
    let snapshot = EngineSnapshot {
        state: EngineState::Stopped {
            outcome: Outcome::Passed,
        },
        configuration: final_configuration,
        terminal_savepoint: Some(final_checkpoint),
        frontier: VirtualTime { ticks: 1 },
        event_log_len: 0,
        quanta: 0,
    };
    let error = match validate_resume_terminal_savepoint(&evidence, &snapshot) {
        Ok(_) => panic!("resume oracle must reject a non-descendant terminal snapshot"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Identity(_)));
    assert!(error.to_string().contains("not descended"));

    Ok(())
}

#[test]
pub(super) fn cli_resume_workflow_executes_local_double_handle() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let form = valid_run_scenario_form()?;
    let scenario = form.scenario_def();
    let schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    ));
    let configuration = crucible::Configuration {
        def: scenario,
        schedule: schedule.clone(),
    };
    let checkpoint = configuration.id();
    let handle_path = write_savepoint_handle_fixture(
        temp.path(),
        "resume-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &content_address_bytes(b"resume-log"),
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("resume"),
        handle_path.display().to_string(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
    ]);
    let Commands::Resume(args) = &cli.command else {
        panic!("expected resume command");
    };
    let resume_plan = plan_resume_invocation(args, temp.path())?;
    let backend_plan = plan_backend_selection(&cli)?.expect("resume should route to backend");
    let outcome = run_local_double_resume_workflow(
        &plan_cli_invocation(&cli),
        &backend_plan,
        None,
        &resume_plan,
    )?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.terminal_savepoint.is_some());
    assert!(outcome.savepoint_oracle.is_some());
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains("final=virtual-time")
            && line.contains("frontier_ticks=2")
    }));
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("resume-oracle\t")
            && line.contains("status=fat==thin-passed")
            && line.contains("fat=blake3:")
            && line.contains("thin=blake3:")
    }));
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "resume_checkpoint")
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "resume_oracle_validation")
    );

    let interactive_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("resume"),
        handle_path.display().to_string(),
        String::from("--interactive"),
        String::from("--watch"),
    ]);
    let Commands::Resume(args) = &interactive_cli.command else {
        panic!("expected resume command");
    };
    let interactive_plan = plan_resume_invocation(args, temp.path())?;
    assert_eq!(
        interactive_plan.execution_mode,
        RunExecutionMode::Interactive
    );
    let backend_plan =
        plan_backend_selection(&interactive_cli)?.expect("resume should route to backend");
    let interactive_outcome = run_local_double_resume_workflow_with_interactive_commands(
        &plan_cli_invocation(&interactive_cli),
        &backend_plan,
        None,
        &interactive_plan,
        &[
            SessionCommandKind::StepQuantum,
            SessionCommandKind::CreateSavepoint,
            SessionCommandKind::Query,
        ],
    )?;

    assert_eq!(interactive_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(interactive_outcome.exit_code, 0);
    assert!(interactive_outcome.terminal_savepoint.is_some());
    assert!(interactive_outcome.savepoint_oracle.is_some());
    assert!(interactive_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains("final=interactive")
            && line.contains("frontier_ticks=2")
            && line.contains("acks=4")
    }));
    assert!(
        interactive_outcome
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-watch\tstate=paused\tfrontier_ticks=2") })
    );
    assert!(
        interactive_outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "resume_checkpoint"
                && entry.summary.contains("until=quiescence"))
    );

    let rejected = match run_local_double_resume_workflow_with_interactive_commands(
        &plan_cli_invocation(&interactive_cli),
        &backend_plan,
        None,
        &interactive_plan,
        &[SessionCommandKind::Start],
    ) {
        Ok(_) => panic!("resume interactive command rejection must not be acknowledged"),
        Err(error) => error,
    };
    assert!(matches!(rejected, CliError::Backend(_)));
    assert!(rejected.to_string().contains("interactive command `start`"));

    let property_form = property_selector_scenario_form()?;
    let property_scenario = property_form.scenario_def();
    let property_schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    ));
    let property_configuration = crucible::Configuration {
        def: property_scenario,
        schedule: property_schedule.clone(),
    };
    let property_handle = write_savepoint_handle_fixture(
        temp.path(),
        "property-resume-source",
        &property_form,
        &property_schedule,
        property_configuration.id(),
        1,
        &content_address_bytes(b"property-resume-log"),
    )?;
    let property_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("resume"),
        property_handle.display().to_string(),
        String::from("--until"),
        String::from("property"),
    ]);
    let Commands::Resume(args) = &property_cli.command else {
        panic!("expected resume command");
    };
    let property_plan = plan_resume_invocation(args, temp.path())?;
    let backend_plan =
        plan_backend_selection(&property_cli)?.expect("resume should route to backend");
    let property_outcome = run_local_double_resume_workflow(
        &plan_cli_invocation(&property_cli),
        &backend_plan,
        None,
        &property_plan,
    )?;
    assert_eq!(property_outcome.status, BackendCommandStatus::Failed);
    assert_eq!(property_outcome.exit_code, 1);
    assert!(property_outcome.terminal_savepoint.is_some());
    assert!(property_outcome.savepoint_oracle.is_some());
    assert!(property_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains("final=property-failed")
            && line.contains("outcome=failed")
    }));
    assert!(property_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-oracle\t") && line.contains("status=fat==thin-passed")
    }));
    assert!(
        property_outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "resume_checkpoint"
                && entry.summary.contains("until=property"))
    );

    Ok(())
}

#[test]
pub(super) fn cli_resume_workflow_allows_virtual_time_beyond_ack_yield_bound()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = Schedule::empty().appended(crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    ));
    let configuration = crucible::Configuration {
        def: scenario,
        schedule: schedule.clone(),
    };
    let checkpoint = configuration.id();
    let handle_path = write_savepoint_handle_fixture(
        temp.path(),
        "resume-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &content_address_bytes(b"resume-log"),
    )?;
    let target_ticks = RUN_INTERACTIVE_ACK_QUANTA_BOUND.saturating_add(2);
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("resume"),
        handle_path.display().to_string(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        format!("{target_ticks}ticks"),
    ]);
    let Commands::Resume(args) = &cli.command else {
        panic!("expected resume command");
    };
    let resume_plan = plan_resume_invocation(args, temp.path())?;
    let backend_plan = plan_backend_selection(&cli)?.expect("resume should route to backend");
    let outcome = run_local_double_resume_workflow(
        &plan_cli_invocation(&cli),
        &backend_plan,
        None,
        &resume_plan,
    )?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains(&format!("frontier_ticks={target_ticks}"))
    }));

    Ok(())
}
