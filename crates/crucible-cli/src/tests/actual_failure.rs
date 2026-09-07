//! Actual failed-run reproduction artifact tests.

use super::*;

#[test]
fn cli_non_passing_run_artifact_captures_actual_run_evidence() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario_path = write_valid_run_scenario(&temp)?;
    let cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "--seed",
        "85",
        "run",
        &scenario_path.display().to_string(),
    ]);
    let Commands::Run(args) = &cli.command else {
        panic!("expected run command");
    };
    let mut run_plan = plan_run_invocation(args, temp.path())?;
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("run should resolve a seed");
    pin_run_invocation_seed(
        &mut run_plan,
        crucible::Seed::from_u64(seed_plan.seed.value),
    )?;
    let backend = plan_backend_selection(&cli)?.expect("run should select a backend");
    let fingerprint = crucible::ContentHash::from_canonical_material(
        "crucible.cli.test.actual-failure-fingerprint.v1",
        "actual failed run",
    );
    let terminal_configuration =
        crucible::Configuration::genesis(run_plan.scenario.scenario_def().clone());
    let expected_model = crucible::ReproductionArtifact::capture(
        run_plan.scenario.scenario_form(),
        &terminal_configuration.schedule,
    )?
    .replay()?;
    let expected_decisions = terminal_configuration.schedule.len();
    let report = RunWorkflowReport {
        status: BackendCommandStatus::Failed,
        execution_owner: RunExecutionOwner::Session,
        created_state: String::from("paused"),
        final_state: String::from("stopped"),
        outcome: Some(OutcomeKind::Failed),
        terminal_savepoint: None,
        terminal_configuration: Some(terminal_configuration),
        final_frontier_ticks: 17,
        final_quanta: 2,
        budget_timed_out: false,
        state_updates: vec![String::from("running"), String::from("stopped")],
        streamed_events: vec![String::from("property assertion failed")],
        streamed_event_frames: vec![b"property assertion failed".to_vec()],
        coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(&[]),
        execution_fingerprints: vec![crucible::FingerprintSample {
            node: crucible::NodeId {
                name: String::from("actual-node"),
            },
            at: crucible::VirtualTime { ticks: 17 },
            fingerprint: crucible::ExecutionFingerprint { hash: fingerprint },
        }],
        resolved_effect_trace: None,
        acknowledged_commands: vec![SessionCommandKind::Start, SessionCommandKind::Continue],
        watch_statuses: Vec::new(),
    };
    let outcome = finish_run_workflow_outcome(
        &plan_cli_invocation(&cli),
        &backend,
        Some(&seed_plan),
        &run_plan,
        report,
    )?;

    let bytes = outcome
        .reproduction_artifact
        .as_ref()
        .expect("a failed local run must carry its reproduction artifact");
    let artifact = decode_reproduction_artifact(bytes)?;
    assert_eq!(artifact.seed, 85);
    let scenario_payload = artifact
        .payloads
        .iter()
        .find(|payload| payload.digest == artifact.scenario.digest)
        .expect("the actual scenario form must be embedded");
    let captured = crucible::ScenarioDefForm::from_compact_binary(&scenario_payload.bytes)?;
    assert_eq!(
        captured.scenario_def().id(),
        run_plan.scenario.scenario_def().id()
    );
    assert!(
        artifact
            .decisions
            .iter()
            .any(|decision| decision.kind == "run_stream_event")
    );
    assert_eq!(artifact.fingerprints.len(), 1);
    assert_eq!(
        artifact.fingerprints[0].digest,
        format!("{}{}", CONTENT_ADDRESS_PREFIX, fingerprint.to_hex())
    );
    let path = temp.path().join("actual-failure.crucible");
    fs::write(&path, bytes)?;
    let replay_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "replay",
        &path.display().to_string(),
    ]);
    let Commands::Replay(replay_args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let replay = replay_reproduction_artifact(&replay_cli, replay_args)?;
    let reduction = replay
        .reduction
        .expect("a failed-run artifact must reexecute its embedded model reproduction");
    assert_eq!(reduction.scenario, run_plan.scenario.scenario_def().id());
    assert_eq!(reduction.schedule, expected_model.schedule);
    assert_eq!(reduction.state, expected_model.state);
    assert_eq!(reduction.reconstructed_decisions, expected_decisions);
    Ok(())
}
