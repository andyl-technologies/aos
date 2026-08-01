//! Local-double run workflow and timeout-budget test.

use super::*;

#[test]
pub(super) fn cli_run_workflow_executes_local_double_session_and_timeout_budget()
-> Result<(), Box<dyn Error>> {
    #[derive(Default)]
    struct NonQuiescentLifecycleLoop {
        quanta: u64,
    }

    impl EngineLoop for NonQuiescentLifecycleLoop {
        fn drive_quantum(&mut self, request: QReq) -> Result<QOut, QErr> {
            self.quanta = self.quanta.saturating_add(1);
            Ok(QOut {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: self.quanta },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: Default::default(),
                scheduler_quiescence: None,
            })
        }
    }

    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let pass_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("1"),
        String::from("run"),
        scenario.display().to_string(),
        String::from("--watch"),
    ]);
    let Commands::Run(pass_args) = &pass_cli.command else {
        panic!("expected run command");
    };
    let pass_run = plan_run_invocation(pass_args, temp.path())?;
    let pass_seed = plan_determinism_ergonomics(
        &pass_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("run should resolve a seed");
    let pass_outcome = execute_backend_routed_command(
        &plan_cli_invocation(&pass_cli),
        &plan_backend_selection(&pass_cli)?.expect("run should require backend selection"),
        Some(&pass_seed),
        Some(&pass_run),
        None,
        None,
        &mut NullBackendCommandRunner,
    )?;

    assert_eq!(pass_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(pass_outcome.exit_code, 0);
    assert!(
        pass_outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "run_scenario")
    );
    assert!(
        pass_outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "run_state_update" && entry.summary == "quiescent")
    );
    assert!(
        pass_outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "run_stream_event"
                && entry.summary == "crucible.event.diagnostic")
    );
    assert!(
        pass_outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("run-watch\t"))
    );
    assert!(
        pass_outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "run_watch_status")
    );

    let timeout_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("2"),
        String::from("run"),
        scenario.display().to_string(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("1ticks"),
        String::from("--save-on"),
        String::from("fail"),
    ]);
    let Commands::Run(timeout_args) = &timeout_cli.command else {
        panic!("expected run command");
    };
    let timeout_run = plan_run_invocation(timeout_args, temp.path())?;
    let timeout_seed = plan_determinism_ergonomics(
        &timeout_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("run should resolve a seed");
    let timeout_thin_plan = plan_cli_invocation(&timeout_cli);
    let timeout_backend_plan =
        plan_backend_selection(&timeout_cli)?.expect("run should require backend selection");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-timeout-test",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| NonQuiescentLifecycleLoop::default(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    let timeout_report = runtime.block_on(run_control_client_workflow_async(
        &client,
        &timeout_run,
        &[],
    ))?;
    let timeout_outcome = finish_run_workflow_outcome(
        &timeout_thin_plan,
        &timeout_backend_plan,
        Some(&timeout_seed),
        &timeout_run,
        timeout_report,
    )?;

    assert_eq!(timeout_outcome.status, BackendCommandStatus::Timeout);
    assert_eq!(timeout_outcome.exit_code, 2);
    assert!(timeout_outcome.reproduction_artifact.is_some());
    assert!(
        timeout_outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("run-savepoint\tpolicy=fail\tcheckpoint=blake3:"))
    );

    let property_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("4"),
        String::from("run"),
        scenario.display().to_string(),
        String::from("--until"),
        String::from("property"),
        String::from("--save-on"),
        String::from("fail"),
    ]);
    let Commands::Run(property_args) = &property_cli.command else {
        panic!("expected run command");
    };
    let property_run = plan_run_invocation(property_args, temp.path())?;
    let property_seed = plan_determinism_ergonomics(
        &property_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("run should resolve a seed");
    let property_outcome = execute_backend_routed_command(
        &plan_cli_invocation(&property_cli),
        &plan_backend_selection(&property_cli)?.expect("run should require backend selection"),
        Some(&property_seed),
        Some(&property_run),
        None,
        None,
        &mut NullBackendCommandRunner,
    )?;

    assert_eq!(property_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(property_outcome.exit_code, 0);
    assert!(property_outcome.reproduction_artifact.is_none());
    assert!(property_outcome.stdout.iter().any(|line| {
        line.starts_with("run-session\t") && line.contains("final=property-missing")
    }));
    assert!(
        !property_outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("run-savepoint\tpolicy=fail\tcheckpoint=blake3:"))
    );

    let dispatch_artifacts = temp.path().join("dispatch-failure-artifacts");
    let dispatch_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("3"),
        String::from("--artifact-dir"),
        dispatch_artifacts.display().to_string(),
        String::from("run"),
        scenario.display().to_string(),
        String::from("--until"),
        String::from("property"),
    ]);
    dispatch(&dispatch_cli)?;
    assert!(!dispatch_artifacts.exists());

    Ok(())
}
