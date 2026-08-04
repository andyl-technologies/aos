//! Verification, dispatch, selftest, and failure-path tests.

use super::*;

struct FakeLiveQemuProbeRunner {
    reports: Vec<LiveQemuProbeEvidence>,
    next: usize,
}

impl LiveQemuProbeRunner for FakeLiveQemuProbeRunner {
    fn run_probe(
        &mut self,
        _backend: &ResolvedLocalBackend,
    ) -> Result<LiveQemuProbeEvidence, CliError> {
        let report = self.reports.get(self.next).cloned().ok_or_else(|| {
            backend_error("fake live-QEMU probe did not receive enough evidence reports")
        })?;
        self.next += 1;
        Ok(report)
    }
}

#[test]
pub(super) fn cli_verify_workflow_localizes_divergence_and_writes_side_artifacts()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = crucible::partition_recovery_scenario()?
        .scenario
        .scenario_def();
    let entries = canonical_trace_entries();
    let first_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"first-verify-fingerprint-sample"),
    }];
    let first = verify_reproduction_artifact_bytes(
        12,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &first_samples,
    )?;
    let mut diverged_entries = entries.clone();
    diverged_entries[1].summary.push_str(" diverged");
    let second_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"second-verify-fingerprint-sample"),
    }];
    let second = verify_reproduction_artifact_bytes(
        12,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &diverged_entries,
        &second_samples,
    )?;
    let left = temp.path().join("left.crucible");
    let right = temp.path().join("right.crucible");
    fs::write(&left, first)?;
    fs::write(&right, second)?;
    let artifact_dir = temp.path().join("verify-artifacts");
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("12"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("verify"),
        String::from("--compare"),
        left.display().to_string(),
        right.display().to_string(),
        String::from("--bisect"),
    ]);
    let Commands::Verify(args) = &cli.command else {
        panic!("expected verify command");
    };
    let verify_plan = plan_verify_invocation(args, temp.path())?;
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("verify should resolve a seed");

    let outcome = execute_backend_routed_command(
        &plan_cli_invocation(&cli),
        &plan_backend_selection(&cli)?.expect("verify should require backend selection"),
        Some(&seed_plan),
        None,
        Some(&verify_plan),
        None,
        &mut NullBackendCommandRunner,
    )?;

    assert_eq!(outcome.status, BackendCommandStatus::Failed);
    assert_eq!(outcome.exit_code, 1);
    assert_eq!(outcome.side_reproduction_artifacts.len(), 2);
    let divergence_line = outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("verify-divergence\t"))
        .expect("divergence report line should be emitted");
    assert!(divergence_line.contains("\tleft=0\tright=1\t"));
    assert!(divergence_line.contains("\tmismatch=canonical-log+fingerprint-stream\t"));
    assert!(divergence_line.contains("\tfirst_decision=1\t"));
    assert!(divergence_line.contains("\tfirst_fingerprint_sample=0\t"));
    assert!(divergence_line.contains("\tfirst_instruction=12\t"));
    assert!(divergence_line.contains("\tnode=node-b\t"));
    assert!(divergence_line.contains("\tbyte="));
    let bisect_line = outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("verify-bisect-state\t"))
        .expect("bisection state line should be emitted");
    assert!(bisect_line.starts_with("verify-bisect-state\tleft_state=crucible-hash:"));
    assert!(bisect_line.contains("\tright_state=crucible-hash:"));
    assert!(bisect_line.contains("\tleft_dump=scenario=crucible-hash:"));
    assert!(bisect_line.contains(" seed=12 decisions=2 fingerprints=1 schedule=crucible-hash:"));
    assert!(bisect_line.contains("\tright_dump=scenario=crucible-hash:"));
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("verify-divergence\t"))
    );
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("verify-bisect-state\t"))
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "verify_divergence_bisection")
    );

    emit_backend_command_output(&cli, &outcome)?;
    let artifacts = fs::read_dir(&artifact_dir)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(artifacts.len(), 2);
    for entry in artifacts {
        let artifact = ReproductionArtifact::decode(&fs::read(entry.path())?)?;
        assert_eq!(artifact.seed, 12);
    }

    Ok(())
}

#[test]
pub(super) fn cli_verify_workflow_remote_divergence_skips_side_artifacts_without_producer_identity()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--daemon"),
        String::from("127.0.0.1:9000"),
        String::from("--seed"),
        String::from("12"),
        String::from("verify"),
        scenario.display().to_string(),
        String::from("--runs"),
        String::from("2"),
    ]);
    let Commands::Verify(args) = &cli.command else {
        panic!("expected verify command");
    };
    let verify_plan = plan_verify_invocation(args, temp.path())?;
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("verify should resolve a seed");
    let backend = plan_backend_selection(&cli)?.expect("verify should require backend");
    assert_eq!(backend.target, BackendExecutionTarget::RemoteDaemon);

    let left_log = canonical_trace_entries();
    let mut right_log = left_log.clone();
    right_log[1].summary.push_str(" diverged");
    let left_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 12,
        node: String::from("node-b"),
        digest: content_address_bytes(b"remote-left-fingerprint"),
    }];
    let right_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 12,
        node: String::from("node-b"),
        digest: content_address_bytes(b"remote-right-fingerprint"),
    }];
    let witnesses = vec![
        VerifyRunWitness {
            reduction: verify_plan.reductions[0].clone(),
            canonical_log: left_log.clone(),
            canonical_log_bytes: canonical_log_entry_bytes(&left_log),
            fingerprint_stream: verify_fingerprint_stream_bytes(&left_samples),
            fingerprint_samples: left_samples,
            state_dump: String::from("left-state"),
            artifact: None,
        },
        VerifyRunWitness {
            reduction: verify_plan.reductions[1].clone(),
            canonical_log: right_log.clone(),
            canonical_log_bytes: canonical_log_entry_bytes(&right_log),
            fingerprint_stream: verify_fingerprint_stream_bytes(&right_samples),
            fingerprint_samples: right_samples,
            state_dump: String::from("right-state"),
            artifact: None,
        },
    ];
    let divergence = compare_verify_witnesses(&witnesses).expect("fixture should diverge");
    let report = VerifyWorkflowReport {
        witnesses,
        divergence: Some(divergence),
    };

    let outcome = finish_verify_workflow_outcome(
        &plan_cli_invocation(&cli),
        &backend,
        Some(&seed_plan),
        &verify_plan,
        report,
    )?;

    assert_eq!(outcome.status, BackendCommandStatus::Failed);
    assert!(outcome.side_reproduction_artifacts.is_empty());
    assert!(outcome.stdout.iter().any(
        |line| line == "verify-reproduction-artifacts\tskipped=producer-provenance-unavailable"
    ));
    emit_backend_command_output(&cli, &outcome)?;

    Ok(())
}

#[test]
pub(super) fn cli_verify_workflow_compares_existing_reproduction_artifacts()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario_path = write_valid_run_scenario(&temp)?;
    let scenario = resolve_run_scenario(Some(&scenario_path.display().to_string()), temp.path())?
        .scenario_def()
        .clone();
    let mut entries = canonical_trace_entries();
    let first_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"first-compare-fingerprint-sample"),
    }];
    let first = verify_reproduction_artifact_bytes(
        21,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &first_samples,
    )?;
    entries[1].summary.push_str(" diverged");
    let second_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"second-compare-fingerprint-sample"),
    }];
    let second = verify_reproduction_artifact_bytes(
        21,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &second_samples,
    )?;
    let left = temp.path().join("left.crucible");
    let right = temp.path().join("right.crucible");
    fs::write(&left, first)?;
    fs::write(&right, second)?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("verify"),
        String::from("--compare"),
        left.display().to_string(),
        right.display().to_string(),
    ]);
    let Commands::Verify(args) = &cli.command else {
        panic!("expected verify command");
    };
    let verify_plan = plan_verify_invocation(args, temp.path())?;

    let outcome = execute_backend_routed_command(
        &plan_cli_invocation(&cli),
        &plan_backend_selection(&cli)?.expect("verify should require backend selection"),
        None,
        None,
        Some(&verify_plan),
        None,
        &mut NullBackendCommandRunner,
    )?;

    assert!(matches!(
        verify_plan.mode,
        VerifyMode::CompareArtifacts { .. }
    ));
    assert_eq!(outcome.status, BackendCommandStatus::Failed);
    assert_eq!(outcome.side_reproduction_artifacts.len(), 2);
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| line.contains("mismatch=canonical-log+fingerprint-stream"))
    );

    let different_seed = verify_reproduction_artifact_bytes(
        22,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &second_samples,
    )?;
    let seed_mismatch = verify_compare_artifacts_with_paths(&left, &different_seed, &cli)?;
    assert!(matches!(
        seed_mismatch,
        CliError::Artifact(message) if message.contains("matching seeds")
    ));

    let different_scenario = crucible::ScenarioDef::from_canonical_material_with_seed(
        "cli-verify-test-scenario",
        "different scenario",
        scenario.seed(),
    );
    let scenario_mismatch_artifact = verify_reproduction_artifact_bytes(
        21,
        Some(&ResolvedLocalBackend::Double),
        &different_scenario,
        &entries,
        &second_samples,
    )?;
    let scenario_mismatch =
        verify_compare_artifacts_with_paths(&left, &scenario_mismatch_artifact, &cli)?;
    assert!(matches!(
        scenario_mismatch,
        CliError::Artifact(message) if message.contains("matching scenario digests")
    ));

    Ok(())
}

#[test]
pub(super) fn cli_verify_workflow_runs_fresh_remote_daemon_reductions() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let daemon = spawn_production_lifecycle_server()?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--daemon"),
        daemon,
        String::from("--seed"),
        String::from("13"),
        String::from("verify"),
        scenario.display().to_string(),
        String::from("--runs"),
        String::from("2"),
    ]);
    let Commands::Verify(args) = &cli.command else {
        panic!("expected verify command");
    };
    let verify_plan = plan_verify_invocation(args, temp.path())?;
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("verify should resolve a seed");
    let backend_plan = plan_backend_selection(&cli)?.expect("remote verify should route daemon");
    assert_eq!(backend_plan.target, BackendExecutionTarget::RemoteDaemon);

    let outcome = execute_backend_routed_command(
        &plan_cli_invocation(&cli),
        &backend_plan,
        Some(&seed_plan),
        None,
        Some(&verify_plan),
        None,
        &mut NullBackendCommandRunner,
    )
    .expect("fresh remote daemon verify should run independent reductions");

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| line.contains("verify-plan\tmode=run-scenario\truns=2"))
    );
    assert_eq!(
        outcome
            .stdout
            .iter()
            .filter(|line| line.starts_with("verify-run\t"))
            .count(),
        2
    );
    assert!(
        outcome
            .stdout
            .iter()
            .filter(|line| line.starts_with("verify-run\t"))
            .all(|line| line.contains("\tfingerprint=") && line.contains("\tsamples=2"))
    );
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| line.contains("verify-result\tstatus=passed"))
    );

    Ok(())
}

#[test]
pub(super) fn cli_verify_workflow_routes_local_qemu_into_production_factory()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("qemu"),
        String::from("--qemu"),
        qemu,
        String::from("--plugin"),
        plugin,
        String::from("verify"),
        scenario.display().to_string(),
        String::from("--runs"),
        String::from("2"),
    ]);
    let Commands::Verify(args) = &cli.command else {
        panic!("expected verify command");
    };
    let verify_plan = plan_verify_invocation(args, temp.path())?;
    let backend_plan =
        plan_backend_selection(&cli)?.expect("qemu verify should require backend selection");

    let error = execute_backend_routed_command(
        &plan_cli_invocation(&cli),
        &backend_plan,
        None,
        None,
        Some(&verify_plan),
        None,
        &mut NullBackendCommandRunner,
    )
    .expect_err("fixture QEMU artifacts must fail production backend construction");
    assert!(matches!(error, CliError::Backend(_)));
    let message = error.to_string();
    assert!(
        message.contains("execution backend construction failed")
            || message.contains("production QEMU")
            || message.contains("live local QEMU execution requires")
            || message.contains("root overlay")
            || message.contains("qemu-img"),
        "unexpected production QEMU factory error: {message}"
    );
    assert!(!message.contains("double fallback"));

    Ok(())
}

#[test]
pub(super) fn cli_backend_selection_routes_daemon_over_api_without_local_backend()
-> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:9000",
        "--backend",
        "qemu",
        "run",
        TEST_SCENARIO,
    ]);
    let backend_plan = plan_backend_selection(&cli)?.expect("run should require backend selection");
    assert_eq!(backend_plan.target, BackendExecutionTarget::RemoteDaemon);
    assert_eq!(backend_plan.daemon.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(backend_plan.resolved_backend, None);
    assert!(backend_plan.remote_uses_control_api);
    assert!(!backend_plan.local_uses_simulation_backend);
    assert!(backend_plan.has_consistent_route());

    let thin_plan = plan_cli_invocation(&cli);
    assert!(
        thin_plan
            .delegated_drivers
            .contains(&CliDelegatedDriver::ControlApi)
    );
    assert!(
        thin_plan
            .state_references
            .contains(&CliStateReferenceKind::DaemonConnection)
    );
    let mut recorder = RecordingBackendRouteRecorder::default();
    execute_backend_selection_plan(&backend_plan, false, &mut recorder)?;
    assert_eq!(
        recorder.remote_daemons,
        vec![String::from("127.0.0.1:9000")]
    );
    assert!(recorder.local_backends.is_empty());
    let mut runner = RecordingBackendCommandRunner::default();
    let outcome = execute_backend_routed_command(
        &thin_plan,
        &backend_plan,
        None,
        None,
        None,
        None,
        &mut runner,
    )?;
    assert_eq!(runner.remote_runs, vec![String::from("127.0.0.1:9000")]);
    assert!(runner.local_runs.is_empty());
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stderr.is_empty());

    Ok(())
}

#[test]
pub(super) fn cli_backend_selection_local_and_remote_have_equivalent_canonical_outcome()
-> Result<(), Box<dyn Error>> {
    let local_cli = Cli::parse_from(["crucible", "--backend", "double", "run", TEST_SCENARIO]);
    let remote_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "--daemon",
        "127.0.0.1:9000",
        "run",
        TEST_SCENARIO,
    ]);
    let local_thin = plan_cli_invocation(&local_cli);
    let remote_thin = plan_cli_invocation(&remote_cli);
    let local_backend =
        plan_backend_selection(&local_cli)?.expect("run should require backend selection");
    let remote_backend =
        plan_backend_selection(&remote_cli)?.expect("run should require backend selection");
    let mut local_runner = RecordingBackendCommandRunner::default();
    let mut remote_runner = RecordingBackendCommandRunner::default();
    let local_outcome = execute_backend_routed_command(
        &local_thin,
        &local_backend,
        None,
        None,
        None,
        None,
        &mut local_runner,
    )?;
    let remote_outcome = execute_backend_routed_command(
        &remote_thin,
        &remote_backend,
        None,
        None,
        None,
        None,
        &mut remote_runner,
    )?;

    assert!(local_backend.has_consistent_route());
    assert!(remote_backend.has_consistent_route());
    assert_eq!(local_runner.local_runs, vec![ResolvedLocalBackend::Double]);
    assert!(local_runner.remote_runs.is_empty());
    assert_eq!(
        remote_runner.remote_runs,
        vec![String::from("127.0.0.1:9000")]
    );
    assert!(remote_runner.local_runs.is_empty());
    assert_eq!(
        local_outcome.normalized(),
        remote_outcome.normalized(),
        "daemon routing must preserve the canonical session/API outcome projection",
    );
    assert_eq!(local_outcome.exit_code, 0);
    assert_eq!(remote_outcome.exit_code, 0);
    assert_eq!(local_outcome.stdout, remote_outcome.stdout);
    assert_eq!(local_outcome.stderr, remote_outcome.stderr);

    Ok(())
}

#[test]
pub(super) fn cli_backend_selection_rejects_execution_identity_divergence()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        qemu.as_str(),
        "--plugin",
        plugin.as_str(),
        "run",
        TEST_SCENARIO,
    ]);
    let thin_plan = plan_cli_invocation(&cli);
    let backend_plan = plan_backend_selection(&cli)?.expect("run should require backend selection");
    let mut runner = RecordingBackendCommandRunner {
        evidence_override: Some(BackendExecutionEvidence::LocalProduction {
            build_id: content_address_bytes(b"different-qemu-build"),
            plugin_abi: required_qemu_plugin_abi(),
        }),
        ..RecordingBackendCommandRunner::default()
    };

    let error = execute_backend_routed_command(
        &thin_plan,
        &backend_plan,
        None,
        None,
        None,
        None,
        &mut runner,
    )
    .expect_err("an executed build identity mismatch must fail closed");

    assert!(
        error
            .to_string()
            .contains("executed backend identity does not match")
    );
    assert_eq!(runner.local_runs.len(), 1);
    Ok(())
}

#[test]
pub(super) fn cli_backend_execution_observation_reloads_invoked_artifact_identity()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        qemu.as_str(),
        "--plugin",
        plugin.as_str(),
        "run",
        TEST_SCENARIO,
    ]);
    let backend_plan = plan_backend_selection(&cli)?.expect("run should require backend selection");
    let mut executed_backend = backend_plan
        .resolved_backend
        .clone()
        .expect("local route should resolve a backend");
    let ResolvedLocalBackend::Qemu { qemu_build_id, .. } = &mut executed_backend else {
        panic!("explicit QEMU route should resolve QEMU");
    };
    *qemu_build_id = content_address_bytes(b"identity-not-present-in-invoked-artifacts");

    let observed = observe_local_backend_execution(&executed_backend)?;
    let error = validate_backend_execution_evidence(
        &BackendSelectionPlan {
            resolved_backend: Some(executed_backend),
            ..backend_plan
        },
        &observed,
    )
    .expect_err("post-execution artifact observation must reject stale selected identity");

    assert!(
        error
            .to_string()
            .contains("executed backend identity does not match")
    );
    Ok(())
}

#[test]
pub(super) fn cli_backend_selection_rejects_daemon_on_serve() {
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:9000",
        "serve",
        "--listen",
        "127.0.0.1:9000",
    ]);
    let error = match plan_backend_selection(&cli) {
        Ok(_) => panic!("serve is the daemon host and must reject --daemon"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("serve"));
}

#[test]
pub(super) fn cli_determinism_ergonomics_resolves_seed_by_flag_env_or_generated()
-> Result<(), Box<dyn Error>> {
    let mut entropy = FakeSeedEntropySource::new(0xfeed_face_cafe_beef);
    let flag_cli = Cli::parse_from(["crucible", "--seed", "0x2a", "run", TEST_SCENARIO]);
    let flag_plan = plan_determinism_ergonomics(
        &flag_cli,
        &FakeSeedEnvironment {
            seed: Some(String::from("99")),
        },
        &mut entropy,
    )?
    .expect("run should resolve a seed");

    assert_eq!(flag_plan.seed.value, 42);
    assert_eq!(flag_plan.seed.source, SeedSource::Flag);
    assert_eq!(entropy.draws, 0);
    assert!(flag_plan.seed_announcement().contains("--seed"));
    assert!(flag_plan.proves_t_cli_4());

    let env_cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let env_plan = plan_determinism_ergonomics(
        &env_cli,
        &FakeSeedEnvironment {
            seed: Some(String::from("0X10")),
        },
        &mut entropy,
    )?
    .expect("run should resolve a seed");

    assert_eq!(env_plan.seed.value, 16);
    assert_eq!(env_plan.seed.source, SeedSource::Environment);
    assert_eq!(entropy.draws, 0);
    assert!(env_plan.seed_announcement().contains(CRUCIBLE_SEED_ENV));
    assert!(env_plan.proves_t_cli_4());

    let generated_cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let generated_plan = plan_determinism_ergonomics(
        &generated_cli,
        &FakeSeedEnvironment::default(),
        &mut entropy,
    )?
    .expect("run should resolve a seed");

    assert_eq!(generated_plan.seed.value, 0xfeed_face_cafe_beef);
    assert_eq!(generated_plan.seed.source, SeedSource::Generated);
    assert_eq!(entropy.draws, 1);
    assert!(generated_plan.generated_seed_drawn_before_run);
    assert!(generated_plan.generated_seed_is_identity_only);
    assert!(
        generated_plan
            .seed_announcement()
            .contains("generated seed = 0xfeedfacecafebeef")
    );
    assert!(generated_plan.proves_t_cli_4());

    let mut recorder = RecordingDeterminismErgonomicsRecorder::default();
    execute_determinism_ergonomics_plan(&generated_plan, &mut recorder)?;
    assert_eq!(recorder.seeds, vec![generated_plan.seed.clone()]);
    assert_eq!(
        recorder.formats,
        vec![OutputFormat::Jsonl, OutputFormat::Json, OutputFormat::Table]
    );
    assert_eq!(
        recorder.failure_rules,
        vec![generated_plan.failure_artifact_rule.clone()]
    );

    Ok(())
}

#[test]
pub(super) fn cli_determinism_ergonomics_rejects_invalid_seed_and_markdown_trace_format()
-> Result<(), Box<dyn Error>> {
    let mut entropy = FakeSeedEntropySource::new(7);
    let bad_seed = Cli::parse_from(["crucible", "--seed", "not-a-seed", "run", TEST_SCENARIO]);
    let error =
        match plan_determinism_ergonomics(&bad_seed, &FakeSeedEnvironment::default(), &mut entropy)
        {
            Ok(_) => panic!("invalid seed must be rejected before dispatch"),
            Err(error) => error,
        };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("--seed"));

    let markdown_trace =
        Cli::parse_from(["crucible", "--format", "markdown", "run", TEST_SCENARIO]);
    let error = match plan_determinism_ergonomics(
        &markdown_trace,
        &FakeSeedEnvironment::default(),
        &mut entropy,
    ) {
        Ok(_) => panic!("markdown must not render canonical event-log traces"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("triage reports"));

    let triage = Cli::parse_from(["crucible", "--format", "markdown", "triage", "findings"]);
    assert!(
        plan_determinism_ergonomics(&triage, &FakeSeedEnvironment::default(), &mut entropy)?
            .is_none()
    );
    assert_eq!(
        seed_resolution_mode(&Cli::parse_from(["crucible", "replay", "case.crucible"]).command),
        SeedResolutionMode::ArtifactOrSavepointOwned
    );
    assert_eq!(
        seed_resolution_mode(
            &Cli::parse_from(["crucible", "resume", "blake3:test-savepoint"]).command
        ),
        SeedResolutionMode::ArtifactOrSavepointOwned
    );
    let draws_before = entropy.draws;
    assert!(
        plan_determinism_ergonomics(
            &Cli::parse_from(["crucible", "replay", "case.crucible"]),
            &FakeSeedEnvironment::default(),
            &mut entropy,
        )?
        .is_none()
    );
    assert_eq!(entropy.draws, draws_before);

    Ok(())
}

#[test]
pub(super) fn cli_determinism_ergonomics_renders_three_formats_over_same_canonical_log()
-> Result<(), Box<dyn Error>> {
    let entries = canonical_trace_entries();
    let jsonl = render_canonical_event_log(OutputFormat::Jsonl, &entries)?;
    let json = render_canonical_event_log(OutputFormat::Json, &entries)?;
    let table = render_canonical_event_log(OutputFormat::Table, &entries)?;

    assert_eq!(jsonl.entry_count, entries.len());
    assert_eq!(json.entry_count, entries.len());
    assert_eq!(table.entry_count, entries.len());
    assert_eq!(jsonl.canonical_digest, json.canonical_digest);
    assert_eq!(json.canonical_digest, table.canonical_digest);
    assert!(jsonl.jsonl_streams_entries);
    assert!(!json.jsonl_streams_entries);
    assert!(!table.jsonl_streams_entries);
    assert_eq!(
        String::from_utf8(jsonl.bytes.clone())?.lines().count(),
        entries.len()
    );
    assert!(String::from_utf8(jsonl.bytes.clone())?.ends_with('\n'));
    assert!(String::from_utf8(json.bytes)?.starts_with('['));
    assert!(String::from_utf8(table.bytes)?.starts_with("seq\tvirtual_time"));

    let error = match render_canonical_event_log(OutputFormat::Markdown, &entries) {
        Ok(_) => panic!("markdown is not a canonical event-log trace format"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));

    Ok(())
}

#[test]
pub(super) fn cli_determinism_ergonomics_threads_seed_into_backend_outcome()
-> Result<(), Box<dyn Error>> {
    let local_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "--seed",
        "1",
        "run",
        TEST_SCENARIO,
    ]);
    let remote_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "--daemon",
        "127.0.0.1:9000",
        "--seed",
        "1",
        "run",
        TEST_SCENARIO,
    ]);
    let different_seed_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "--seed",
        "2",
        "run",
        TEST_SCENARIO,
    ]);
    let mut entropy = FakeSeedEntropySource::new(99);
    let seed_one =
        plan_determinism_ergonomics(&local_cli, &FakeSeedEnvironment::default(), &mut entropy)?
            .expect("run should resolve a seed");
    let remote_seed_one =
        plan_determinism_ergonomics(&remote_cli, &FakeSeedEnvironment::default(), &mut entropy)?
            .expect("remote run should resolve a seed");
    let seed_two = plan_determinism_ergonomics(
        &different_seed_cli,
        &FakeSeedEnvironment::default(),
        &mut entropy,
    )?
    .expect("run should resolve a seed");

    let local_thin = plan_cli_invocation(&local_cli);
    let remote_thin = plan_cli_invocation(&remote_cli);
    let different_seed_thin = plan_cli_invocation(&different_seed_cli);
    let local_backend =
        plan_backend_selection(&local_cli)?.expect("run should require backend selection");
    let remote_backend =
        plan_backend_selection(&remote_cli)?.expect("run should require backend selection");
    let different_seed_backend =
        plan_backend_selection(&different_seed_cli)?.expect("run should require backend selection");
    let mut local_runner = RecordingBackendCommandRunner::default();
    let mut remote_runner = RecordingBackendCommandRunner::default();
    let mut different_seed_runner = RecordingBackendCommandRunner::default();

    let local = execute_backend_routed_command(
        &local_thin,
        &local_backend,
        Some(&seed_one),
        None,
        None,
        None,
        &mut local_runner,
    )?;
    let remote = execute_backend_routed_command(
        &remote_thin,
        &remote_backend,
        Some(&remote_seed_one),
        None,
        None,
        None,
        &mut remote_runner,
    )?;
    let different_seed = execute_backend_routed_command(
        &different_seed_thin,
        &different_seed_backend,
        Some(&seed_two),
        None,
        None,
        None,
        &mut different_seed_runner,
    )?;

    assert_eq!(local.normalized(), remote.normalized());
    assert_ne!(
        local.canonical_log_digest,
        different_seed.canonical_log_digest
    );
    assert_ne!(local.artifact_digest, different_seed.artifact_digest);
    assert!(
        local
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "run_identity"
                && entry.summary.contains("0x0000000000000001"))
    );

    Ok(())
}

#[test]
pub(super) fn cli_determinism_ergonomics_failure_artifact_carries_resolved_seed_and_footer()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("artifacts");
    let cli = Cli::parse_from([
        "crucible",
        "--seed",
        "0x1234",
        "--artifact-dir",
        artifact_dir.to_str().unwrap_or("."),
        "run",
        TEST_SCENARIO,
    ]);
    let mut entropy = FakeSeedEntropySource::new(9);
    let plan = plan_determinism_ergonomics(&cli, &FakeSeedEnvironment::default(), &mut entropy)?
        .expect("run should resolve a seed");
    let artifact_bytes = mock_failure_reproduction_artifact_bytes(&cli, plan.seed.value)?;
    let artifact = ReproductionArtifact::decode(&artifact_bytes)?;
    let report = write_failure_reproduction_artifact(&cli, &artifact_bytes, "Property Violation")?;

    assert_eq!(artifact.seed, 0x1234);
    assert_eq!(report.footer.artifact_path, report.path);
    assert!(report.footer.self_contained_artifact);
    assert!(report.footer.replay_command.starts_with("crucible replay "));
    assert!(report.footer.debug_command.ends_with(" --at-failure"));
    replay_reproduction_artifact(
        &cli,
        &ReplayArgs {
            artifact: report.path.clone(),
            to: None,
            check: None,
            bisect: None,
        },
    )?;

    Ok(())
}

#[test]
pub(super) fn cli_determinism_ergonomics_emits_trace_and_failure_artifact_from_outcome()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("artifact dir with spaces");
    let trace = temp.path().join("trace.jsonl");
    let cli = Cli::parse_from([
        "crucible",
        "--seed",
        "0x55",
        "--artifact-dir",
        artifact_dir.to_str().unwrap_or("."),
        "--trace",
        trace.to_str().unwrap_or("."),
        "--format",
        "jsonl",
        "run",
        TEST_SCENARIO,
    ]);
    let mut entropy = FakeSeedEntropySource::new(1);
    let plan = plan_determinism_ergonomics(&cli, &FakeSeedEnvironment::default(), &mut entropy)?
        .expect("run should resolve a seed");
    let thin = plan_cli_invocation(&cli);
    let backend = plan_backend_selection(&cli)?.expect("run should require backend selection");
    let mut runner = RecordingBackendCommandRunner::default();
    let mut outcome = execute_backend_routed_command(
        &thin,
        &backend,
        Some(&plan),
        None,
        None,
        None,
        &mut runner,
    )?;
    mark_mock_failure_outcome(&cli, &backend, &mut outcome, Some(&plan))?;

    emit_backend_command_output(&cli, &outcome)?;

    let trace_text = fs::read_to_string(&trace)?;
    assert_eq!(trace_text.lines().count(), outcome.canonical_log.len() + 1);
    assert!(
        trace_text
            .lines()
            .last()
            .expect("trace should include final outcome")
            .contains("\"kind\":\"final_outcome\"")
    );
    let artifact_entries = fs::read_dir(&artifact_dir)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(artifact_entries.len(), 1);
    let artifact_path = artifact_entries[0].path();
    let artifact = ReproductionArtifact::decode(&fs::read(&artifact_path)?)?;
    assert_eq!(artifact.seed, 0x55);
    let footer = failure_reproduction_footer(artifact_path);
    assert!(footer.replay_command.contains('\''));
    assert!(footer.debug_command.contains('\''));
    assert!(footer.replay_command.starts_with("crucible replay "));
    assert!(footer.debug_command.ends_with(" --at-failure"));
    assert_eq!(
        CliError::Outcome(BackendCommandStatus::Failed).exit_code(),
        1
    );
    assert_eq!(
        CliError::Outcome(BackendCommandStatus::Timeout).exit_code(),
        2
    );
    assert_eq!(
        CliError::Outcome(BackendCommandStatus::Crashed).exit_code(),
        3
    );

    let dispatch_artifacts = temp.path().join("dispatch-artifacts");
    let scenario = write_valid_run_scenario(&temp)?;
    let dispatch_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--seed"),
        String::from("0x55"),
        String::from("--artifact-dir"),
        dispatch_artifacts.display().to_string(),
        String::from("run"),
        scenario.display().to_string(),
        String::from("--emit-mock-failure-artifact"),
    ]);
    let error = match dispatch(&dispatch_cli) {
        Ok(_) => panic!("non-passing dispatch must propagate the outcome exit code"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CliError::Outcome(BackendCommandStatus::Failed)
    ));
    assert_eq!(error.exit_code(), 1);
    assert_eq!(
        fs::read_dir(&dispatch_artifacts)?
            .collect::<Result<Vec<_>, _>>()?
            .len(),
        1
    );

    Ok(())
}

#[test]
pub(super) fn cli_determinism_ergonomics_rejects_remote_mock_failure_artifact()
-> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:9000",
        "--seed",
        "0x55",
        "run",
        TEST_SCENARIO,
        "--emit-mock-failure-artifact",
    ]);
    let mut entropy = FakeSeedEntropySource::new(1);
    let plan = plan_determinism_ergonomics(&cli, &FakeSeedEnvironment::default(), &mut entropy)?
        .expect("run should resolve a seed");
    let thin = plan_cli_invocation(&cli);
    let backend = plan_backend_selection(&cli)?.expect("run should require backend selection");
    assert_eq!(backend.target, BackendExecutionTarget::RemoteDaemon);
    let mut runner = RecordingBackendCommandRunner::default();
    let mut outcome = execute_backend_routed_command(
        &thin,
        &backend,
        Some(&plan),
        None,
        None,
        None,
        &mut runner,
    )?;

    let error = match mark_mock_failure_outcome(&cli, &backend, &mut outcome, Some(&plan)) {
        Ok(()) => panic!("remote mock failure artifact must require producer provenance"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("local producer provenance"));
    assert!(outcome.reproduction_artifact.is_none());

    Ok(())
}

#[test]
pub(super) fn cli_determinism_ergonomics_keeps_wall_clock_out_of_canonical_paths() {
    assert!(canonical_state_wall_clock_guard());
}

#[test]
pub(super) fn cli_triage_help_surface_lists_required_flags_and_exit_code_contract() {
    let mut command = Cli::command();
    let top_help = command.render_long_help().to_string();
    assert!(top_help.contains("triage"));
    assert!(top_help.contains("Cluster, dedup, and minimize discovered failures"));
    assert!(top_help.contains("--format <jsonl|json|table|markdown>"));

    let triage_help = command
        .find_subcommand_mut("triage")
        .expect("triage subcommand must be registered")
        .render_long_help()
        .to_string();
    for needle in [
        "<FINDINGS>",
        "--policy <coarse|default|fine|exact>",
        "--minimize <none|representative|all>",
        "--report <dir>",
        "--recompute-signatures",
        "--compare <other-triage-result>",
        "--format <jsonl|json|table|markdown>",
        "Trace/report render format. Default: table on a terminal, otherwise jsonl",
    ] {
        assert!(
            triage_help.contains(needle),
            "triage help is missing `{needle}`:\n{triage_help}"
        );
    }

    assert_eq!(
        CliError::Triage("signature self-check mismatch".to_string()).exit_code(),
        1
    );
    assert_eq!(
        CliError::Backend("triage discovery/config failure".to_string()).exit_code(),
        4
    );
    assert_eq!(
        CliError::Artifact("malformed findings ledger".to_string()).exit_code(),
        5
    );
    assert_eq!(
        CliError::Usage("triage usage error".to_string()).exit_code(),
        64
    );

    let missing_findings = Cli::try_parse_from(["crucible", "triage"])
        .expect_err("missing triage findings must be a parse error");
    assert_eq!(cli_parse_error_exit_code(&missing_findings), 64);

    let invalid_policy =
        Cli::try_parse_from(["crucible", "triage", "findings", "--policy", "wide"])
            .expect_err("invalid triage policy must be a parse error");
    assert_eq!(cli_parse_error_exit_code(&invalid_policy), 64);

    let help = Cli::try_parse_from(["crucible", "triage", "--help"])
        .expect_err("help must render through Clap's display path");
    assert_eq!(cli_parse_error_exit_code(&help), 0);
}

#[test]
pub(super) fn cli_triage_surface_parses_full_t_tri_7_flags_and_pipeline()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let findings = temp.path().join("findings");
    let store = temp.path().join("store");
    let reports = temp.path().join("triage-reports");
    fs::create_dir_all(&findings)?;
    let baseline_cli = Cli::parse_from([
        "crucible",
        "--store",
        store.to_str().unwrap_or("."),
        "--artifact-dir",
        temp.path().join("artifacts").to_str().unwrap_or("."),
        "triage",
        findings.to_str().unwrap_or("."),
        "--report",
        reports.to_str().unwrap_or("."),
        "--format",
        "markdown",
        "--recompute-signatures",
    ]);
    let Commands::Triage(baseline_args) = &baseline_cli.command else {
        panic!("expected triage command");
    };
    let baseline = run_triage_invocation(&baseline_cli, baseline_args)?;
    assert_eq!(baseline.ledger.artifact_count(), 0);
    assert!(baseline.report_path.exists());
    assert_eq!(baseline.stored_result.key, baseline.result.content_hash());
    let stored_findings = format_content_hash_ref(baseline.stored_ledger.key);

    let stored_cli = Cli::parse_from([
        "crucible",
        "--store",
        store.to_str().unwrap_or("."),
        "triage",
        &stored_findings,
        "--report",
        reports.to_str().unwrap_or("."),
    ]);
    let Commands::Triage(stored_args) = &stored_cli.command else {
        panic!("expected triage command");
    };
    let stored_plan = plan_triage_invocation(&stored_cli, stored_args)?;
    assert!(matches!(
        stored_plan.findings,
        TriageFindingsSource::StoredLedger(_)
    ));
    let stored_report = run_triage_invocation(&stored_cli, stored_args)?;
    assert_eq!(stored_report.ledger.artifact_count(), 0);
    assert!(stored_report.stored_ledger.cache_hit);

    let signed_findings = temp.path().join("signed-findings");
    let (signed_ledger, finding) = write_signed_triage_findings_ledger(
        &signed_findings,
        &store,
        "engine-owned.findings-ledger",
        None,
    )?;
    let prior = format_content_hash_ref(baseline.stored_result.key);

    let cli = Cli::parse_from([
        "crucible",
        "--store",
        store.to_str().unwrap_or("."),
        "--artifact-dir",
        temp.path().join("artifacts").to_str().unwrap_or("."),
        "triage",
        signed_ledger.to_str().unwrap_or("."),
        "--policy",
        "fine",
        "--minimize",
        "representative",
        "--report",
        reports.to_str().unwrap_or("."),
        "--format",
        "markdown",
        "--recompute-signatures",
        "--compare",
        &prior,
    ]);
    let Commands::Triage(args) = &cli.command else {
        panic!("expected triage command");
    };

    assert_eq!(args.findings, signed_ledger.to_string_lossy());
    assert_eq!(args.policy, TriagePolicyArg::Fine);
    assert_eq!(args.minimize, TriageMinimizeArg::Representative);
    assert_eq!(args.report.as_deref(), Some(reports.as_path()));
    assert_eq!(cli.format, Some(OutputFormat::Markdown));
    assert!(args.recompute_signatures);
    assert_eq!(args.compare.as_deref(), Some(prior.as_str()));

    let plan = plan_triage_invocation(&cli, args)?;

    assert!(matches!(plan.findings, TriageFindingsSource::Path(_)));
    assert_eq!(plan.policy.level(), crucible::SignaturePolicyLevel::Fine);
    assert_eq!(plan.minimize, TriageMinimizeArg::Representative);
    assert_eq!(plan.report_dir, reports);
    assert_eq!(plan.format, crucible::FailureClusterReportFormat::Markdown);
    assert!(matches!(
        plan.compare,
        Some(TriageCompareTarget::StoredResult(_))
    ));
    assert_eq!(plan.failure_exit_code, 1);
    assert_eq!(plan.store_root, store);
    assert_eq!(
        plan.pipeline,
        vec![
            TriagePipelineStep::LoadFindingsLedger,
            TriagePipelineStep::RecomputeSignatureSelfCheck,
            TriagePipelineStep::Cluster,
            TriagePipelineStep::MinimizeRepresentative,
            TriagePipelineStep::EmitReports,
            TriagePipelineStep::StoreTriageResult,
            TriagePipelineStep::CompareContentDiff,
        ]
    );
    assert!(plan.proves_t_tri_7());
    let report = run_triage_invocation(&cli, args)?;
    assert_eq!(report.ledger.artifact_count(), 1);
    assert_eq!(report.ledger.signed_findings().len(), 1);
    assert_eq!(
        report.ledger.signed_findings()[0].reproduction_artifact,
        finding.artifact.id()
    );
    assert_eq!(report.result.clustering.cluster_count(), 1);
    assert_eq!(report.result.minimization.cluster_count(), 1);
    assert_eq!(
        report.result.identity.findings_ledger,
        report.stored_ledger.key
    );
    let minimization_run = &report.result.minimization.runs[0];
    assert_ne!(
        minimization_run.minimization.original.artifact.id(),
        minimization_run.minimized_artifact()
    );
    assert!(
        minimization_run
            .minimization
            .attempts
            .iter()
            .any(|attempt| attempt.accepted)
    );
    assert_eq!(report.result.report_set.reports.len(), 1);
    assert_eq!(report.result.signature_self_check.checked_count, 1);
    assert!(report.result.signature_self_check.is_clean());
    assert!(report.report_path.exists());
    let rendered_report = fs::read_to_string(&report.report_path)?;
    assert!(rendered_report.contains("cli-triage-signed-finding"));
    assert!(report.compare.as_ref().is_some_and(|diff| {
        diff.status_label() == "changed" && diff.content_diff().contains("baseline\t")
    }));
    dispatch(&cli)?;

    let stored_signed_findings = format_content_hash_ref(report.stored_ledger.key);
    let stored_signed_cli = Cli::parse_from([
        "crucible",
        "--store",
        store.to_str().unwrap_or("."),
        "triage",
        &stored_signed_findings,
        "--recompute-signatures",
        "--report",
        reports.to_str().unwrap_or("."),
    ]);
    let Commands::Triage(stored_signed_args) = &stored_signed_cli.command else {
        panic!("expected triage command");
    };
    let stored_signed_report = run_triage_invocation(&stored_signed_cli, stored_signed_args)?;
    assert_eq!(stored_signed_report.ledger.artifact_count(), 1);
    assert!(stored_signed_report.stored_ledger.cache_hit);
    assert_eq!(
        stored_signed_report.result.identity.findings_ledger,
        stored_signed_report.stored_ledger.key
    );
    assert!(stored_signed_report.result.signature_self_check.is_clean());

    Ok(())
}

#[test]
pub(super) fn cli_triage_rejects_artifact_only_findings_without_engine_evidence() {
    let temp = TempDir::new().expect("tempdir must be created");
    let findings = temp.path().join("findings");
    fs::create_dir_all(&findings).expect("findings dir must be created");
    fs::write(
        findings.join("failure.artifact"),
        b"opaque failure artifact",
    )
    .expect("opaque finding artifact must be written");
    let cli = Cli::parse_from([
        "crucible",
        "--store",
        temp.path().join("store").to_str().unwrap_or("."),
        "triage",
        findings.to_str().unwrap_or("."),
    ]);
    let Commands::Triage(args) = &cli.command else {
        panic!("expected triage command");
    };

    let error = match run_triage_invocation(&cli, args) {
        Ok(_) => panic!("artifact-only findings ledgers must not be silently triaged"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Artifact(_)));
    assert_eq!(error.exit_code(), 5);
    assert!(
        error
            .to_string()
            .contains("discovery-time signature evidence")
    );
}

#[test]
pub(super) fn cli_triage_rejects_cli_sidecar_signature_evidence() {
    let temp = TempDir::new().expect("tempdir must be created");
    let findings = temp.path().join("sidecar.findings-ledger");
    let store_root = temp.path().join("store");
    let artifact = crucible::ContentHash::from_bytes(b"sidecar-artifact").to_hex();
    let ledger_bytes = format!(
        "\
crucible.failure-triage.findings-ledger.v1
artifact.0={artifact}
finding.0.kind=property
",
    )
    .into_bytes();
    fs::write(&findings, &ledger_bytes).expect("sidecar ledger must be written");
    let cli = Cli::parse_from([
        "crucible",
        "--store",
        store_root.to_str().unwrap_or("."),
        "triage",
        findings.to_str().unwrap_or("."),
    ]);
    let Commands::Triage(args) = &cli.command else {
        panic!("expected triage command");
    };

    let error = match run_triage_invocation(&cli, args) {
        Ok(_) => panic!("CLI-local sidecar signature evidence must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Artifact(_)));
    assert_eq!(error.exit_code(), 5);
    assert!(
        error
            .to_string()
            .contains("engine-owned discovery artifacts")
    );

    let store = crucible::LocalDagStore::new(store_root.clone());
    let stored_hash = store
        .put(&ledger_bytes)
        .expect("sidecar ledger must be stored");
    let stored_cli = Cli::parse_from([
        "crucible",
        "--store",
        store_root.to_str().unwrap_or("."),
        "triage",
        &format_content_hash_ref(stored_hash),
    ]);
    let Commands::Triage(stored_args) = &stored_cli.command else {
        panic!("expected triage command");
    };

    let stored_error = match run_triage_invocation(&stored_cli, stored_args) {
        Ok(_) => panic!("stored sidecar signature evidence must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(stored_error, CliError::Artifact(_)));
    assert_eq!(stored_error.exit_code(), 5);
    assert!(
        stored_error
            .to_string()
            .contains("engine-owned discovery artifacts")
    );
}

#[test]
pub(super) fn cli_triage_rejects_mismatched_engine_owned_signature_evidence() {
    let temp = TempDir::new().expect("tempdir must be created");
    let store_root = temp.path().join("store");
    let findings_dir = temp.path().join("findings");
    let (findings, _) = write_signed_triage_findings_ledger(
        &findings_dir,
        &store_root,
        "mismatched.findings-ledger",
        Some("cli-triage-different-discovery-signature"),
    )
    .expect("signed findings ledger must be written");
    for extra_args in [Vec::<&str>::new(), vec!["--recompute-signatures"]] {
        let mut argv = vec![
            "crucible",
            "--store",
            store_root.to_str().unwrap_or("."),
            "triage",
            findings.to_str().unwrap_or("."),
        ];
        argv.extend(extra_args);
        let cli = Cli::parse_from(argv);
        let Commands::Triage(args) = &cli.command else {
            panic!("expected triage command");
        };

        let error = match run_triage_invocation(&cli, args) {
            Ok(_) => panic!("mismatched signed findings ledgers must not be silently triaged"),
            Err(error) => error,
        };

        assert!(matches!(error, CliError::Triage(_)));
        assert_eq!(error.exit_code(), 1);
    }
}

#[test]
pub(super) fn cli_triage_is_offline_and_uses_uniform_failure_exit_code() {
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:9000",
        "triage",
        "findings-ledger",
    ]);
    let Commands::Triage(args) = &cli.command else {
        panic!("expected triage command");
    };
    let error = match plan_triage_invocation(&cli, args) {
        Ok(_) => panic!("triage must not use a live daemon"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("offline"));

    let self_check_failure = CliError::Triage(
        "--recompute-signatures found a discovery-time signature mismatch".to_string(),
    );
    assert_eq!(self_check_failure.exit_code(), 1);
}

#[test]
pub(super) fn cli_selftest_canonical_gate_names_match_harness_catalog() {
    let harness_gate_names = crucible_harness::canonical_gates()
        .iter()
        .map(|gate| gate.name)
        .collect::<Vec<_>>();

    assert_eq!(CANONICAL_GATE_NAMES, harness_gate_names.as_slice());
}

#[test]
pub(super) fn cli_replay_validates_reproduction_artifact() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = temp.path().join("case.crucible");
    let artifact = mock_e2e_reproduction_artifact()?;
    fs::write(&path, artifact.encode()?)?;

    let cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let report = replay_reproduction_artifact(
        &cli,
        &ReplayArgs {
            artifact: path.clone(),
            to: None,
            check: None,
            bisect: None,
        },
    )?;

    assert_eq!(report.path, path);
    assert_eq!(report.seed, artifact.seed);
    assert_eq!(report.scenario_digest, artifact.scenario.digest);
    assert_eq!(report.digest, artifact.digest()?);
    assert!(report.check.is_none());

    Ok(())
}

#[test]
pub(super) fn cli_replay_reexecutes_embedded_model_reproduction() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = temp.path().join("model-case.crucible");
    let fixture = crucible::happy_path_scenario()?;
    let schedule = replay_to_savepoint_schedule(1);
    let model = crucible::ReproductionArtifact::capture(&fixture.scenario, &schedule)?;
    let replay = model.replay()?;
    let entries = canonical_log_entries_from_engine_schedule(&schedule);
    let payloads = model_reproduction_artifact_payloads(&model, replay.state);
    let bytes = verify_reproduction_artifact_bytes_with_components(
        seed_to_u64(model.seed()),
        Some(&ResolvedLocalBackend::Double),
        &model.scenario_def(),
        &entries,
        &[],
        &payloads,
    )?;
    fs::write(&path, bytes)?;

    let cli = Cli::parse_from(["crucible", "replay", &path.display().to_string()]);
    let Commands::Replay(args) = &cli.command else {
        panic!("expected replay command");
    };
    let report = replay_reproduction_artifact(&cli, args)?;
    let reduction = report
        .reduction
        .expect("model-backed artifact should report pure reduction evidence");

    assert_eq!(reduction.artifact, replay.artifact);
    assert_eq!(reduction.scenario, replay.scenario);
    assert_eq!(reduction.schedule, replay.schedule);
    assert_eq!(reduction.state, replay.state);
    assert_eq!(reduction.reconstructed_decisions, schedule.len());
    Ok(())
}

#[test]
pub(super) fn cli_replay_check_accepts_byte_identical_canonical_log() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("case.crucible");
    let check_path = temp.path().join("original.jsonl");
    let scenario_path = write_valid_run_scenario(&temp)?;
    let scenario = resolve_run_scenario(Some(&scenario_path.display().to_string()), temp.path())?
        .scenario_def()
        .clone();
    let entries = canonical_trace_entries();
    let samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"replay-check-fingerprint-sample"),
    }];
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &samples,
    )?;
    fs::write(&artifact_path, &artifact_bytes)?;

    let emitted = emit_canonical_trace(OutputFormat::Jsonl, &entries, Some(&check_path), false)?;
    let canonical_log_bytes = canonical_log_entry_bytes(&entries);
    assert_eq!(emitted.bytes, fs::read(&check_path)?);
    assert_eq!(emitted.bytes, canonical_log_bytes);

    let artifact_arg = artifact_path.display().to_string();
    let check_arg = check_path.display().to_string();
    let replay_cli = Cli::parse_from(["crucible", "replay", &artifact_arg, "--check", &check_arg]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let report = replay_reproduction_artifact(&replay_cli, args)?;

    let Some(check) = report.check.as_ref() else {
        panic!("missing replay check report");
    };
    assert_eq!(check.path, check_path);
    assert_eq!(check.digest, content_address_bytes(&canonical_log_bytes));

    Ok(())
}

#[test]
pub(super) fn cli_replay_resolves_content_addressed_component_payloads()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("externalized.crucible");
    let check_path = temp.path().join("original.jsonl");
    let store_root = temp.path().join("store");
    let scenario_path = write_valid_run_scenario(&temp)?;
    let scenario = resolve_run_scenario(Some(&scenario_path.display().to_string()), temp.path())?
        .scenario_def()
        .clone();
    let entries = canonical_trace_entries();
    let samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"replay-store-fingerprint-sample"),
    }];
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &samples,
    )?;
    let externalized = externalized_replay_artifact_text(&artifact_bytes, &store_root, false)?;
    fs::write(&artifact_path, externalized)?;
    emit_canonical_trace(OutputFormat::Jsonl, &entries, Some(&check_path), false)?;

    let artifact_arg = artifact_path.display().to_string();
    let check_arg = check_path.display().to_string();
    let store_arg = store_root.display().to_string();
    let replay_cli = Cli::parse_from([
        "crucible",
        "--store",
        &store_arg,
        "replay",
        &artifact_arg,
        "--check",
        &check_arg,
    ]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };

    let report = replay_reproduction_artifact(&replay_cli, args)?;

    assert!(report.check.is_some());
    assert_eq!(report.path, artifact_path);

    Ok(())
}

#[test]
pub(super) fn cli_replay_to_savepoint_validates_artifact_prefix_and_oracle()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("case.crucible");
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = replay_to_savepoint_schedule(1);
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_resume_configuration(
        &configuration,
        VirtualTime {
            ticks: schedule.len() as u64,
        },
    )?;
    let target = write_savepoint_handle_fixture(
        temp.path(),
        "replay-target",
        &form,
        &schedule,
        checkpoint.id,
        schedule.len() as u64,
        &content_address_bytes(b"replay-to-savepoint-canonical-log"),
    )?;
    let entries = canonical_log_entries_from_engine_schedule(&schedule);
    let samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"replay-to-savepoint-fingerprint-sample"),
    }];
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &samples,
    )?;
    fs::write(&artifact_path, artifact_bytes)?;

    let artifact_arg = artifact_path.display().to_string();
    let target_arg = target.display().to_string();
    let replay_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "replay",
        &artifact_arg,
        "--to",
        &target_arg,
    ]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let report = replay_reproduction_artifact(&replay_cli, args)?;
    let target_report = report
        .to_savepoint
        .as_ref()
        .expect("replay --to should report a target savepoint");

    assert_eq!(target_report.checkpoint, checkpoint.id);
    assert_eq!(target_report.frontier_ticks, schedule.len() as u64);
    assert_eq!(
        target_report.schedule_prefix.target_decisions,
        schedule.len()
    );
    assert_eq!(
        target_report.schedule_prefix.artifact_decisions,
        entries.len()
    );
    assert_eq!(
        target_report.schedule_prefix.matched_decisions,
        schedule.len()
    );
    assert_eq!(
        target_report.schedule_prefix.artifact_prefix_digest,
        schedule_digest(&cli_decisions_from_canonical_log(&entries))
    );
    assert!(
        target_report
            .schedule_prefix
            .typed_prefix_digest
            .starts_with(CONTENT_ADDRESS_PREFIX)
    );
    let status_line = replay_to_savepoint_status_line(target_report);
    assert!(status_line.contains("schedule_prefix=typed"));
    assert!(status_line.contains(&format!("target_decisions={}", schedule.len())));
    assert!(status_line.contains(&format!("artifact_decisions={}", entries.len())));
    assert!(status_line.contains(&format!("matched_decisions={}", schedule.len())));
    assert!(status_line.contains("typed_prefix_digest=crucible-hash:"));
    assert!(status_line.contains("artifact_prefix_digest=crucible-hash:"));
    assert_eq!(
        target_report.materialization.materialization,
        "model-temporal-graph"
    );
    assert_eq!(target_report.materialization.operation, "replay");
    assert_eq!(
        target_report.materialization.configuration,
        configuration.id()
    );
    assert_eq!(target_report.materialization.checkpoint, checkpoint.id);
    assert_eq!(
        target_report.materialization.replay_fat_checkpoint,
        checkpoint.id
    );
    assert_eq!(
        target_report.materialization.replay_thin_checkpoint,
        checkpoint.id
    );
    assert_eq!(
        target_report.materialization.runtime_state,
        target_report.materialization.reduced_state
    );
    assert!(status_line.contains("materialization=model-temporal-graph"));
    assert!(status_line.contains("unified_operation=replay"));
    assert!(status_line.contains(&format!(
        "materialized_checkpoint={}",
        format_content_hash_ref(checkpoint.id)
    )));
    assert!(status_line.contains(&format!(
        "runtime_state={}",
        format_content_hash_ref(target_report.materialization.runtime_state)
    )));
    assert!(status_line.contains(&format!(
        "reduced_state={}",
        format_content_hash_ref(target_report.materialization.reduced_state)
    )));
    assert!(status_line.contains(&format!(
        "single_vm_fingerprint={}",
        format_content_hash_ref(target_report.materialization.single_vm_fingerprint)
    )));
    assert!(status_line.contains(&format!(
        "replay_fat={}",
        format_content_hash_ref(checkpoint.id)
    )));
    assert!(status_line.contains(&format!(
        "replay_thin={}",
        format_content_hash_ref(checkpoint.id)
    )));
    let mut replay_stdout = Vec::new();
    write_replay_report_human(&mut replay_stdout, &report)?;
    let replay_stdout = String::from_utf8(replay_stdout)?;
    assert!(replay_stdout.contains("crucible: replay artifact"));
    assert!(replay_stdout.contains(&status_line));
    assert!(replay_stdout.contains("materialization=model-temporal-graph"));
    assert!(replay_stdout.contains("unified_operation=replay"));
    assert_eq!(target_report.oracle.fat_checkpoint, checkpoint.id);
    assert_eq!(target_report.oracle.thin_checkpoint, checkpoint.id);
    dispatch(&replay_cli)?;

    let store_root = temp.path().join("store");
    write_checkpoint_closure_fixture(&store_root, &form, &schedule)?;
    let store_arg = store_root.display().to_string();
    let checkpoint_arg = format_content_hash_ref(checkpoint.id);
    let hash_replay_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "--store",
        &store_arg,
        "replay",
        &artifact_arg,
        "--to",
        &checkpoint_arg,
    ]);
    let Commands::Replay(hash_args) = &hash_replay_cli.command else {
        panic!("expected replay command");
    };
    let hash_report = replay_reproduction_artifact(&hash_replay_cli, hash_args)?;
    assert_eq!(
        hash_report
            .to_savepoint
            .as_ref()
            .expect("hash replay --to should report a target savepoint")
            .checkpoint,
        checkpoint.id
    );

    Ok(())
}

#[test]
pub(super) fn cli_replay_to_savepoint_rejects_missing_prefix_decision_payload()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("missing-prefix-payload.crucible");
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = replay_to_savepoint_schedule(1);
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_resume_configuration(
        &configuration,
        VirtualTime {
            ticks: schedule.len() as u64,
        },
    )?;
    let target = write_savepoint_handle_fixture(
        temp.path(),
        "replay-target-missing-prefix-payload",
        &form,
        &schedule,
        checkpoint.id,
        schedule.len() as u64,
        &content_address_bytes(b"replay-to-savepoint-missing-payload-canonical-log"),
    )?;
    let entries = canonical_log_entries_from_engine_schedule(&schedule);
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &[VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"replay-to-savepoint-missing-payload-fingerprint"),
        }],
    )?;
    let decoded = decode_reproduction_artifact(&artifact_bytes)?;
    let missing_digest = decoded.decisions[0].payload_digest.clone();
    let payload_prefix = format!("payload\t{missing_digest}\t");
    let artifact_text = String::from_utf8(artifact_bytes)?;
    let without_decision_payload = artifact_text
        .lines()
        .filter(|line| !line.starts_with(&payload_prefix))
        .map(|line| {
            let mut line = line.to_string();
            line.push('\n');
            line
        })
        .collect::<String>();
    fs::write(&artifact_path, without_decision_payload)?;

    let artifact_arg = artifact_path.display().to_string();
    let target_arg = target.display().to_string();
    let replay_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "replay",
        &artifact_arg,
        "--to",
        &target_arg,
    ]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let error = match replay_reproduction_artifact(&replay_cli, args) {
        Ok(_) => panic!("replay --to must reject missing prefix decision payloads"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Artifact(_)));
    assert!(error.to_string().contains("decision payload"));
    assert!(
        error
            .to_string()
            .contains("is missing from artifact payloads")
    );

    Ok(())
}

#[test]
pub(super) fn cli_replay_to_savepoint_rejects_non_matching_schedule_prefix()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("prefix-mismatch.crucible");
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let target_schedule = replay_to_savepoint_schedule(1);
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: target_schedule.clone(),
    };
    let checkpoint = checkpoint_for_resume_configuration(
        &configuration,
        VirtualTime {
            ticks: target_schedule.len() as u64,
        },
    )?;
    let target = write_savepoint_handle_fixture(
        temp.path(),
        "replay-target-prefix-mismatch",
        &form,
        &target_schedule,
        checkpoint.id,
        target_schedule.len() as u64,
        &content_address_bytes(b"replay-to-savepoint-prefix-mismatch-canonical-log"),
    )?;
    let artifact_schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 99 },
            order: Vec::new(),
        },
    )]);
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &canonical_log_entries_from_engine_schedule(&artifact_schedule),
        &[VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"replay-to-savepoint-prefix-mismatch-fingerprint"),
        }],
    )?;
    fs::write(&artifact_path, artifact_bytes)?;

    let artifact_arg = artifact_path.display().to_string();
    let target_arg = target.display().to_string();
    let replay_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "replay",
        &artifact_arg,
        "--to",
        &target_arg,
    ]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let error = match replay_reproduction_artifact(&replay_cli, args) {
        Ok(_) => panic!("replay --to must reject non-prefix savepoint schedules"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::ReplayCheck(_)));
    assert!(
        error
            .to_string()
            .contains("schedule-prefix mismatch at decision 0")
    );

    Ok(())
}

#[test]
pub(super) fn cli_replay_to_savepoint_rejects_scenario_mismatch() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("scenario-mismatch.crucible");
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = replay_to_savepoint_schedule(1);
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_resume_configuration(
        &configuration,
        VirtualTime {
            ticks: schedule.len() as u64,
        },
    )?;
    let target = write_savepoint_handle_fixture(
        temp.path(),
        "replay-target-mismatch",
        &form,
        &schedule,
        checkpoint.id,
        schedule.len() as u64,
        &content_address_bytes(b"replay-to-savepoint-mismatch-canonical-log"),
    )?;
    let other_scenario = crucible::partition_recovery_scenario()?
        .scenario
        .scenario_def();
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &other_scenario,
        &canonical_trace_entries(),
        &[VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"replay-to-savepoint-mismatch-fingerprint"),
        }],
    )?;
    fs::write(&artifact_path, artifact_bytes)?;

    let artifact_arg = artifact_path.display().to_string();
    let target_arg = target.display().to_string();
    let replay_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "replay",
        &artifact_arg,
        "--to",
        &target_arg,
    ]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let error = match replay_reproduction_artifact(&replay_cli, args) {
        Ok(_) => panic!("replay --to must reject mismatched savepoint scenarios"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Artifact(_)));
    assert!(
        error
            .to_string()
            .contains("did not match artifact scenario")
    );

    Ok(())
}

#[test]
pub(super) fn cli_replay_to_savepoint_rejects_target_beyond_artifact_prefix()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("short-artifact.crucible");
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = replay_to_savepoint_schedule(2);
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_resume_configuration(
        &configuration,
        VirtualTime {
            ticks: schedule.len() as u64,
        },
    )?;
    let target = write_savepoint_handle_fixture(
        temp.path(),
        "replay-target-beyond-artifact",
        &form,
        &schedule,
        checkpoint.id,
        schedule.len() as u64,
        &content_address_bytes(b"replay-to-savepoint-beyond-canonical-log"),
    )?;
    let entries = canonical_trace_entries();
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries[..1],
        &[VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"replay-to-savepoint-beyond-fingerprint"),
        }],
    )?;
    fs::write(&artifact_path, artifact_bytes)?;

    let artifact_arg = artifact_path.display().to_string();
    let target_arg = target.display().to_string();
    let replay_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "replay",
        &artifact_arg,
        "--to",
        &target_arg,
    ]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let error = match replay_reproduction_artifact(&replay_cli, args) {
        Ok(_) => panic!("replay --to must reject savepoints beyond the artifact prefix"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::ReplayCheck(_)));
    assert!(
        error
            .to_string()
            .contains("but artifact encodes only 1 decisions")
    );

    Ok(())
}

#[test]
pub(super) fn cli_replay_externalized_identity_mismatch_keeps_identity_exit()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("externalized-identity-drift.crucible");
    let store_root = temp.path().join("store");
    let empty_store_root = temp.path().join("empty-store");
    let scenario_path = write_valid_run_scenario(&temp)?;
    let scenario = resolve_run_scenario(Some(&scenario_path.display().to_string()), temp.path())?
        .scenario_def()
        .clone();
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &canonical_trace_entries(),
        &[VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"identity-priority-fingerprint-sample"),
        }],
    )?;
    let externalized = externalized_replay_artifact_text(&artifact_bytes, &store_root, false)?;
    let mut decoded = decode_reproduction_artifact(externalized.as_bytes())?;
    decoded.identity.qemu_build_id = content_address_bytes(b"different-qemu-build");
    fs::write(&artifact_path, canonical_artifact_text(&decoded))?;

    let store_arg = empty_store_root.display().to_string();
    let artifact_arg = artifact_path.display().to_string();
    let replay_cli = Cli::parse_from(["crucible", "--store", &store_arg, "replay", &artifact_arg]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };

    let error = match replay_reproduction_artifact(&replay_cli, args) {
        Ok(_) => panic!("externalized identity drift must fail before store hydration"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("QEMU"));

    Ok(())
}

#[test]
pub(super) fn cli_replay_rejects_inline_component_store_uri_mismatch() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("inline-store-mismatch.crucible");
    let store_root = temp.path().join("store");
    let scenario_path = write_valid_run_scenario(&temp)?;
    let scenario = resolve_run_scenario(Some(&scenario_path.display().to_string()), temp.path())?
        .scenario_def()
        .clone();
    let artifact_bytes = verify_reproduction_artifact_bytes(
        0xace,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &canonical_trace_entries(),
        &[VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"inline-store-mismatch-fingerprint-sample"),
        }],
    )?;
    let externalized = externalized_replay_artifact_text(&artifact_bytes, &store_root, true)?;
    let mut decoded = decode_reproduction_artifact(externalized.as_bytes())?;
    let wrong_key = crucible::LocalDagStore::new(store_root.clone()).put(b"wrong bytes")?;
    let wrong_uri = format_content_hash_ref(wrong_key);
    let component = decoded
        .components
        .iter_mut()
        .find(|component| component.kind == "other")
        .ok_or("fixture must include a decision payload component")?;
    component.store_uri = wrong_uri;
    fs::write(&artifact_path, canonical_artifact_text(&decoded))?;

    let store_arg = store_root.display().to_string();
    let artifact_arg = artifact_path.display().to_string();
    let replay_cli = Cli::parse_from(["crucible", "--store", &store_arg, "replay", &artifact_arg]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };

    let error = match replay_reproduction_artifact(&replay_cli, args) {
        Ok(_) => panic!("inline payload must agree with declared DAG store object"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Artifact(_)));
    assert!(
        error
            .to_string()
            .contains("inline payload does not match DAG store object")
    );

    Ok(())
}

#[test]
pub(super) fn cli_replay_check_rejects_mismatch_with_failure_exit() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("case.crucible");
    let check_path = temp.path().join("original.jsonl");
    let artifact = mock_e2e_reproduction_artifact()?;
    fs::write(&artifact_path, artifact.encode()?)?;
    fs::write(&check_path, b"not the replayed canonical log\n")?;

    let artifact_arg = artifact_path.display().to_string();
    let check_arg = check_path.display().to_string();
    let replay_cli = Cli::parse_from(["crucible", "replay", &artifact_arg, "--check", &check_arg]);
    let Commands::Replay(args) = &replay_cli.command else {
        panic!("expected replay command");
    };
    let report = replay_reproduction_artifact(&replay_cli, args)?;
    assert_eq!(replay_report_status(&report), BackendCommandStatus::Failed);
    let check = report
        .check
        .as_ref()
        .expect("replay --check mismatch should retain a check report");
    let mismatch = check
        .mismatch
        .as_ref()
        .expect("replay --check mismatch should retain mismatch details");
    let error = replay_check_mismatch_error(check, mismatch);

    assert!(matches!(error, CliError::ReplayCheck(_)));
    assert_eq!(error.exit_code(), 1);
    assert!(error.to_string().contains("replay --check mismatch"));
    assert!(error.to_string().contains("first_diff_byte=0"));
    assert!(error.to_string().contains("original_len="));
    assert!(error.to_string().contains("replayed_len="));

    let decoded_artifact =
        validate_replayable_reproduction_artifact(&replay_cli, &artifact.encode()?)?;
    let canonical_log = canonical_log_entries_from_artifact(&decoded_artifact)?;
    let canonical_log_bytes = canonical_log_entry_bytes(&canonical_log);
    assert!(
        !canonical_log_bytes.is_empty(),
        "replay mismatch fixture must have canonical log bytes"
    );
    let mut shifted_original = canonical_log_bytes.clone();
    let first_diff = shifted_original.len().saturating_sub(1).min(7);
    assert!(
        first_diff > 0,
        "replay mismatch fixture must exercise a nonzero first difference"
    );
    let replacement = shifted_original[first_diff].wrapping_add(1);
    shifted_original[first_diff] = replacement;
    fs::write(&check_path, &shifted_original)?;
    let report = replay_reproduction_artifact(&replay_cli, args)?;
    let check = report
        .check
        .as_ref()
        .expect("replay --check mismatch should retain a check report");
    let mismatch = check
        .mismatch
        .as_ref()
        .expect("replay --check mismatch should retain mismatch details");
    let error = replay_check_mismatch_error(check, mismatch);
    assert!(matches!(error, CliError::ReplayCheck(_)));
    assert!(
        error
            .to_string()
            .contains(&format!("first_diff_byte={first_diff}"))
    );
    let dispatch_error = match dispatch(&replay_cli) {
        Ok(()) => panic!("dispatch must reject replay --check mismatches"),
        Err(error) => error,
    };
    assert!(matches!(dispatch_error, CliError::ReplayCheck(_)));
    assert_eq!(dispatch_error.exit_code(), 1);

    Ok(())
}

#[test]
pub(super) fn cli_replay_bisects_artifact_divergence() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = crucible::partition_recovery_scenario()?
        .scenario
        .scenario_def();
    let entries = canonical_trace_entries();
    let first_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"replay-bisect-first-fingerprint"),
    }];
    let first = verify_reproduction_artifact_bytes(
        12,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &first_samples,
    )?;
    let mut diverged_entries = entries.clone();
    diverged_entries[1].summary.push_str(" replay-diverged");
    let second_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("session"),
        digest: content_address_bytes(b"replay-bisect-second-fingerprint"),
    }];
    let second = verify_reproduction_artifact_bytes(
        12,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &diverged_entries,
        &second_samples,
    )?;
    let left = temp.path().join("left.crucible");
    let right = temp.path().join("right.crucible");
    fs::write(&left, first)?;
    fs::write(&right, second)?;

    let cli = Cli::parse_from([
        "crucible",
        "--quiet",
        "--backend",
        "double",
        "replay",
        left.to_str().unwrap_or("."),
        "--bisect",
        right.to_str().unwrap_or("."),
    ]);
    let Commands::Replay(args) = &cli.command else {
        panic!("expected replay command");
    };
    let report = replay_reproduction_artifact(&cli, args)?;
    let bisection = report.bisect.as_ref().expect("bisection report");
    let divergence = bisection
        .divergence
        .as_ref()
        .expect("divergence should be localized");

    assert_eq!(
        divergence.mismatch,
        VerifyMismatchKind::CanonicalLogAndFingerprintStream
    );
    assert_eq!(divergence.first_different_decision, Some(1));
    assert_eq!(divergence.first_different_fingerprint_sample, Some(0));
    assert_eq!(divergence.first_different_instruction, 12);
    assert_eq!(divergence.node.as_deref(), Some("node-b"));
    assert!(divergence.first_different_byte > 0);

    let error = match dispatch(&cli) {
        Ok(_) => panic!("replay --bisect divergence must use the replay-check exit path"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::ReplayCheck(_)));
    assert_eq!(error.exit_code(), 1);
    assert!(error.to_string().contains("replay --bisect divergence"));
    assert!(error.to_string().contains("first_decision=1"));

    let seed_mismatch = verify_reproduction_artifact_bytes(
        13,
        Some(&ResolvedLocalBackend::Double),
        &scenario,
        &entries,
        &first_samples,
    )?;
    let mismatch = temp.path().join("seed-mismatch.crucible");
    fs::write(&mismatch, seed_mismatch)?;
    let mismatch_cli = Cli::parse_from([
        "crucible",
        "--quiet",
        "--backend",
        "double",
        "replay",
        left.to_str().unwrap_or("."),
        "--bisect",
        mismatch.to_str().unwrap_or("."),
    ]);
    let Commands::Replay(mismatch_args) = &mismatch_cli.command else {
        panic!("expected replay command");
    };
    let error = match replay_reproduction_artifact(&mismatch_cli, mismatch_args) {
        Ok(_) => panic!("replay --bisect must reject mismatched replay inputs"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CliError::Artifact(message)
            if message.contains("replay --bisect requires matching seeds")
    ));

    Ok(())
}

#[test]
pub(super) fn cli_replay_bisect_accepts_identical_artifacts() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = temp.path().join("case.crucible");
    let artifact = mock_e2e_reproduction_artifact()?;
    fs::write(&path, artifact.encode()?)?;
    let path_arg = path.display().to_string();
    let cli = Cli::parse_from([
        "crucible", "--quiet", "replay", &path_arg, "--bisect", &path_arg,
    ]);
    let Commands::Replay(args) = &cli.command else {
        panic!("expected replay command");
    };

    let report = replay_reproduction_artifact(&cli, args)?;

    assert!(
        report
            .bisect
            .as_ref()
            .is_some_and(|item| { item.other_path == path && item.divergence.is_none() })
    );
    dispatch(&cli)?;

    Ok(())
}

#[test]
pub(super) fn cli_replay_rejects_build_identity_mismatch_with_identity_exit()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = temp.path().join("identity-drift.crucible");
    let mut artifact = mock_e2e_reproduction_artifact()?;
    artifact.build_identity.qemu_build_id = content_address_bytes(b"different-qemu-build");
    fs::write(&path, artifact.encode()?)?;

    let cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let error = match replay_reproduction_artifact(
        &cli,
        &ReplayArgs {
            artifact: path,
            to: None,
            check: None,
            bisect: None,
        },
    ) {
        Ok(_) => panic!("replay must reject artifacts from a different QEMU identity"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("QEMU"));

    Ok(())
}

#[test]
pub(super) fn cli_replay_rejects_selected_qemu_file_identity_mismatch_with_identity_exit()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("case.crucible");
    let plugin_abi = required_qemu_plugin_abi();
    let (qemu, plugin) =
        qemu_artifacts_in_dir(temp.path(), "different-local-qemu-build", &plugin_abi)?;
    let artifact = mock_e2e_reproduction_artifact()?;
    fs::write(&artifact_path, artifact.encode()?)?;
    let cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);

    let error = match replay_reproduction_artifact(
        &cli,
        &ReplayArgs {
            artifact: artifact_path,
            to: None,
            check: None,
            bisect: None,
        },
    ) {
        Ok(_) => panic!("replay must reject the selected QEMU identity mismatch"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("QEMU"));

    Ok(())
}

#[test]
pub(super) fn cli_replay_rejects_remote_daemon_without_producer_identity()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_path = temp.path().join("case.crucible");
    let artifact = mock_e2e_reproduction_artifact()?;
    fs::write(&artifact_path, artifact.encode()?)?;
    let artifact_arg = artifact_path.display().to_string();
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:9000",
        "replay",
        &artifact_arg,
    ]);
    let Commands::Replay(args) = &cli.command else {
        panic!("expected replay command");
    };

    let error = match replay_reproduction_artifact(&cli, args) {
        Ok(_) => panic!("remote daemon replay must require producer build provenance"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("remote daemon"));
    assert!(error.to_string().contains("producer build provenance"));

    Ok(())
}

#[test]
pub(super) fn cli_failure_artifact_writer_emits_replay_and_debug_commands()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("artifact dir with spaces");
    let cli = Cli::parse_from([
        "crucible",
        "--artifact-dir",
        artifact_dir.to_str().unwrap_or("."),
        "run",
        TEST_SCENARIO,
    ]);
    let artifact = mock_e2e_reproduction_artifact()?;
    let artifact_bytes = artifact.encode()?;

    let report = write_failure_reproduction_artifact(&cli, &artifact_bytes, "Property Violation")?;

    assert!(report.path.starts_with(temp.path()));
    assert!(report.path.exists());
    assert!(report.footer.replay_command.starts_with("crucible replay "));
    assert!(report.footer.debug_command.ends_with(" --at-failure"));
    assert!(
        report
            .footer
            .debug_command
            .contains("artifact dir with spaces")
    );
    assert!(report.footer.debug_command.contains('\''));
    assert!(report.path.to_string_lossy().contains("property-violation"));
    let debug_cli = Cli::parse_from([
        "crucible",
        "debug",
        report.path.to_str().unwrap_or("."),
        "--at-failure",
        "--gdb-listen",
        "127.0.0.1:9000",
    ]);
    assert!(matches!(
        debug_cli.command,
        Commands::Debug(DebugArgs {
            target: Some(_),
            at_failure: true,
            gdb_listen: Some(_),
            ..
        })
    ));
    assert_eq!(
        ReproductionArtifact::decode(&fs::read(&report.path)?)?,
        artifact
    );
    replay_reproduction_artifact(
        &cli,
        &ReplayArgs {
            artifact: report.path.clone(),
            to: None,
            check: None,
            bisect: None,
        },
    )?;
    assert_eq!(report.digest, artifact.digest()?);

    Ok(())
}

#[test]
pub(super) fn cli_debug_surface_parses_full_t_dbg_8_flags_and_verbs() -> Result<(), Box<dyn Error>>
{
    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "case.crucible",
        "--at",
        "icount:guest-a:102",
        "--node",
        "guest-a",
        "--gdb-listen",
        "127.0.0.1:9000",
        "--checkpoint-stride",
        "4",
        "reverse-step",
        "event",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };

    assert_eq!(args.target.as_deref(), Some("case.crucible"));
    assert_eq!(args.at.as_deref(), Some("icount:guest-a:102"));
    assert_eq!(args.node.as_deref(), Some("guest-a"));
    assert_eq!(args.gdb_listen.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(args.checkpoint_stride, Some(4));
    assert!(matches!(
        &args.verb,
        Some(DebugVerbArgs::ReverseStep {
            grain: DebugStepGrainArg::Event
        })
    ));

    let plan = plan_debug_invocation(&cli, args)?;

    assert!(matches!(&plan.target, DebugPlanTarget::Artifact(_)));
    assert!(matches!(
        &plan.coordinate,
        DebugPlanCoordinate::At(crucible::DebugCoordinate::NodeIcount {
            node,
            icount
        }) if node.name == "guest-a" && icount.retired == 102
    ));
    assert_eq!(plan.node.as_deref(), Some("guest-a"));
    assert!(plan.read_only);
    assert!(!plan.allow_mutate);
    assert_eq!(plan.checkpoint_stride, Some(4));
    assert!(
        plan.session_commands
            .iter()
            .all(SessionCommand::is_read_only),
        "reverse-step grains are realized by the debug reverse-step/goto path, not unsupported session step modes"
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::ReverseStep)
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::RestoreNearestCheckpointReplay)
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::CheckpointCadence)
    );
    assert!(plan.proves_t_dbg_8());

    Ok(())
}

#[test]
pub(super) fn cli_debug_surface_supports_session_checkpoint_and_allow_mutate()
-> Result<(), Box<dyn Error>> {
    let checkpoint = "blake3:0000000000000000000000000000000000000000000000000000000000000000";
    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "--session",
        "127.0.0.1:7000",
        "--at-checkpoint",
        checkpoint,
        "--allow-mutate",
        "goto",
        "vtime:7",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };

    let plan = plan_debug_invocation(&cli, args)?;

    assert!(matches!(&plan.target, DebugPlanTarget::Session(_)));
    assert!(matches!(
        &plan.coordinate,
        DebugPlanCoordinate::AtCheckpoint(_)
    ));
    assert!(matches!(
        &plan.verb,
        DebugInteractiveVerbPlan::Goto(crucible::DebugCoordinate::VirtualTime(
            crucible::VirtualTime { ticks: 7 }
        ))
    ));
    assert!(plan.allow_mutate);
    assert!(!plan.read_only);
    assert_eq!(
        plan.non_canonical_branch_label.as_deref(),
        Some("NON-CANONICAL debug branch")
    );
    assert!(
        plan.session_commands
            .contains(&SessionCommand::fork_current())
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::NonCanonicalBranchFork)
    );
    assert!(plan.proves_t_dbg_8());

    Ok(())
}

#[test]
pub(super) fn cli_debug_surface_rejects_conflicts_and_backend_without_gdbstub() {
    assert!(
        Cli::try_parse_from([
            "crucible",
            "debug",
            "case.crucible",
            "--read-only",
            "--allow-mutate",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "crucible",
            "debug",
            "case.crucible",
            "--at-event",
            "1",
            "--at-failure",
        ])
        .is_err()
    );

    let cli = Cli::parse_from(["crucible", "--backend", "double", "debug", "case.crucible"]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = match plan_debug_invocation(&cli, args) {
        Ok(_) => panic!("double backend must not advertise a gdbstub debug surface"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("open_gdbstub"));

    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "case.crucible",
        "--checkpoint-stride",
        "0",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = match plan_debug_invocation(&cli, args) {
        Ok(_) => panic!("zero checkpoint stride must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("non-zero"));

    let cli = Cli::parse_from(["crucible", "debug", "case.crucible", "--node", ""]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = match plan_debug_invocation(&cli, args) {
        Ok(_) => panic!("empty debug node must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("--node"));
}

#[test]
pub(super) fn cli_debug_surface_defaults_coordinate_by_target_kind() -> Result<(), Box<dyn Error>> {
    let artifact_cli = Cli::parse_from(["crucible", "debug", "case.crucible"]);
    let Commands::Debug(args) = &artifact_cli.command else {
        panic!("expected debug command");
    };
    let artifact_plan = plan_debug_invocation(&artifact_cli, args)?;
    assert!(matches!(
        artifact_plan.coordinate,
        DebugPlanCoordinate::AtFailure
    ));

    let savepoint = "blake3:1111111111111111111111111111111111111111111111111111111111111111";
    let savepoint_cli = Cli::parse_from(["crucible", "debug", savepoint]);
    let Commands::Debug(args) = &savepoint_cli.command else {
        panic!("expected debug command");
    };
    let savepoint_plan = plan_debug_invocation(&savepoint_cli, args)?;
    assert!(matches!(
        savepoint_plan.coordinate,
        DebugPlanCoordinate::AtCheckpoint(_)
    ));

    let session_cli = Cli::parse_from(["crucible", "debug", "--session", "127.0.0.1:7000"]);
    let Commands::Debug(args) = &session_cli.command else {
        panic!("expected debug command");
    };
    let session_plan = plan_debug_invocation(&session_cli, args)?;
    assert!(matches!(
        session_plan.coordinate,
        DebugPlanCoordinate::Current
    ));

    Ok(())
}

#[test]
pub(super) fn cli_replay_rejects_duplicate_singleton_lines() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = temp.path().join("duplicate.crucible");
    let artifact = mock_e2e_reproduction_artifact()?;
    let mut encoded = String::from_utf8(artifact.encode()?)?;
    encoded.push_str("seed\t9\n");
    fs::write(&path, encoded)?;

    let cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let error = match replay_reproduction_artifact(
        &cli,
        &ReplayArgs {
            artifact: path,
            to: None,
            check: None,
            bisect: None,
        },
    ) {
        Ok(_) => panic!("duplicate singleton line must fail CLI replay validation"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("duplicate singleton line"));

    Ok(())
}

#[test]
pub(super) fn cli_mock_failure_artifact_is_harness_decodable() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let bytes = mock_failure_reproduction_artifact_bytes(&cli, 0xe2e0_0010)?;
    let artifact = ReproductionArtifact::decode(&bytes)?;

    assert_eq!(artifact.seed, 0xe2e0_0010);
    assert_eq!(artifact.schema_version, REPRODUCTION_ARTIFACT_SCHEMA);

    Ok(())
}
#[path = "verify_dispatch/selftest.rs"]
mod selftest;
