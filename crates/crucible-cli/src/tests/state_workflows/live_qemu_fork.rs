//! Live-QEMU fork routing and transient interactive artifact tests.

use super::*;

#[test]
pub(super) fn cli_fork_workflow_routes_local_qemu_into_live_guest_configuration()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let store_root = temp.path().join("store");
    let artifact_dir = temp.path().join("interactive-artifacts");
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
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
        "qemu-fork-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &content_address_bytes(b"qemu-fork-log"),
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("qemu"),
        String::from("--qemu"),
        qemu.clone(),
        String::from("--plugin"),
        plugin.clone(),
        String::from("--seed"),
        String::from("7"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("qemu-child"),
    ]);
    let Commands::Fork(args) = &cli.command else {
        panic!("expected fork command");
    };
    let fork_plan = plan_fork_invocation(args, Some(7), &cli.artifact_dir, &store_root)?;
    let backend_plan = plan_backend_selection(&cli)?.expect("fork should route to backend");
    assert!(matches!(
        backend_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    ));
    assert!(should_capture_fork_reproduction_artifact(
        &fork_plan,
        backend_plan.resolved_backend.as_ref()
    ));
    let mut interactive_fork_plan = fork_plan.clone();
    interactive_fork_plan.execution_mode = RunExecutionMode::Interactive;
    assert!(!should_capture_fork_reproduction_artifact(
        &interactive_fork_plan,
        backend_plan.resolved_backend.as_ref()
    ));
    let interactive_report = ForkWorkflowReport {
        run: RunWorkflowReport {
            status: BackendCommandStatus::Passed,
            execution_owner: RunExecutionOwner::Session,
            campaign_replay_closure: None,
            created_state: String::from("paused"),
            final_state: String::from("interactive"),
            outcome: Some(OutcomeKind::Stopped),
            terminal_savepoint: Some(checkpoint),
            terminal_configuration: Some(configuration.clone()),
            final_frontier_ticks: 1,
            final_quanta: 0,
            budget_timed_out: false,
            state_updates: vec![String::from("paused"), String::from("stopped")],
            streamed_events: Vec::new(),
            streamed_event_frames: Vec::new(),
            coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(&[]),
            execution_fingerprints: Vec::new(),
            resolved_effect_trace: None,
            acknowledged_commands: vec![SessionCommandKind::Query, SessionCommandKind::Stop],
            watch_statuses: Vec::new(),
        },
        source_checkpoint: checkpoint,
        branch_checkpoint: checkpoint,
        branch_configuration: checkpoint,
        terminal_configuration: configuration.clone(),
        scenario_form: form.clone(),
        scenario_label: String::from("qemu-fork-source"),
        label: String::from("qemu-child"),
        terminal_oracle: SavepointOracleProof {
            configuration: checkpoint,
            fat_checkpoint: checkpoint,
            thin_checkpoint: checkpoint,
            frontier: VirtualTime { ticks: 1 },
            schedule: schedule.clone(),
            store_objects: 0,
        },
    };
    let interactive_outcome = finish_fork_workflow_outcome(
        &plan_cli_invocation(&cli),
        &backend_plan,
        None,
        &interactive_fork_plan,
        interactive_report,
    )?;
    assert_eq!(interactive_outcome.status, BackendCommandStatus::Passed);
    assert!(interactive_outcome.stdout.iter().any(|line| {
        line
            == "fork-artifact\tstatus=not-captured\treason=interactive-live-controls\treplayable=false"
    }));
    assert!(interactive_outcome.canonical_log.iter().any(|entry| {
        entry.kind == "fork_reproduction_artifact"
            && entry.summary
                == "status=not-captured reason=interactive-live-controls replayable=false"
    }));
    assert!(!artifact_dir.exists());
    let error =
        run_local_qemu_fork_workflow(&plan_cli_invocation(&cli), &backend_plan, None, &fork_plan)
            .expect_err("fixture QEMU fork must reach live-guest discovery or production launch");
    let message = error.to_string();
    assert!(
        matches!(error, CliError::Backend(_)),
        "unexpected QEMU fork error: {error}"
    );
    assert!(
        message.contains("requires the AOS kernel")
            || message.contains("requires the AOS root image")
            || message.contains("session execution backend construction failed"),
        "unexpected QEMU fork error: {error}"
    );
    assert!(!message.contains("execution is unavailable"));
    assert!(!message.contains("double fallback"));

    Ok(())
}
