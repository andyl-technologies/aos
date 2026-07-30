//! Built-in corpus and live-QEMU selftest dispatch.

use super::*;

#[test]
pub(super) fn cli_selftest_runs_builtin_example_corpus() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from(["crucible", "--quiet", "selftest"]);
    let Commands::Selftest(args) = &cli.command else {
        panic!("expected selftest command");
    };
    let report = run_selftest(&cli, args)?;

    let scenario_names = report
        .verified
        .iter()
        .map(|verified| verified.scenario_name.as_str())
        .collect::<Vec<_>>();
    let gate_names = report
        .gates
        .iter()
        .map(|gate| gate.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(report.verified.len(), 3);
    assert!(scenario_names.contains(&"happy-path.scn"));
    assert!(scenario_names.contains(&"partition-recovery.scn"));
    assert!(scenario_names.contains(&"crash-restart.scn"));
    assert!(report.verified.iter().all(|verified| verified.runs == 5));
    assert_eq!(gate_names, BUILT_IN_CORPUS_SELFTEST_GATES);
    assert!(report.gates.iter().all(|gate| {
        gate.status == SelftestGateStatus::Passed
            && gate.corpus_entries == 3
            && gate.runs_per_entry == DEFAULT_SELFTEST_RUNS
            && gate.runner == SelftestGateRunner::DoubleBackedCorpus
            && gate.qemu_build_id.is_none()
    }));
    dispatch(&cli)?;

    let selected = Cli::parse_from([
        "crucible",
        "--quiet",
        "selftest",
        "--gates",
        "gate:replay-oracle",
    ]);
    let Commands::Selftest(args) = &selected.command else {
        panic!("expected selftest command");
    };
    let selected_report = run_selftest(&selected, args)?;
    assert_eq!(
        selected_report
            .gates
            .iter()
            .map(|gate| gate.name.as_str())
            .collect::<Vec<_>>(),
        ["gate:replay-oracle"]
    );
    dispatch(&selected)?;

    let temp = TempDir::new()?;
    let manifest = temp.path().join("selftest-corpus.txt");
    fs::write(
        &manifest,
        "builtin:happy-path.scn\n# comments are ignored\ncrash-restart.scn\n",
    )?;
    let manifest_cli = Cli::parse_from([
        "crucible",
        "--quiet",
        "selftest",
        "--corpus",
        manifest.to_str().unwrap_or("."),
    ]);
    let Commands::Selftest(args) = &manifest_cli.command else {
        panic!("expected selftest command");
    };
    let manifest_report = run_selftest(&manifest_cli, args)?;
    assert_eq!(
        manifest_report
            .verified
            .iter()
            .map(|verified| verified.scenario_name.as_str())
            .collect::<Vec<_>>(),
        ["happy-path.scn", "crash-restart.scn"]
    );
    assert!(
        manifest_report
            .gates
            .iter()
            .all(|gate| gate.corpus_entries == 2)
    );
    dispatch(&manifest_cli)?;

    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let qemu_cli = Cli::parse_from([
        "crucible",
        "--quiet",
        "--qemu",
        qemu.as_str(),
        "--plugin",
        plugin.as_str(),
        "selftest",
        "--with-qemu",
    ]);
    let Commands::Selftest(args) = &qemu_cli.command else {
        panic!("expected selftest command");
    };
    let expected_qemu_build_id = content_address_bytes(b"test-qemu-build-v1");
    let expected_probe = LiveQemuProbeEvidence {
        qemu_build_id: expected_qemu_build_id.clone(),
        plugin_abi: required_qemu_plugin_abi(),
        completed_icount: 1_000,
        execution_fingerprint: content_address_bytes(b"stable-live-probe"),
    };
    let mut probe = FakeLiveQemuProbeRunner {
        reports: vec![expected_probe; REAL_QEMU_SELFTEST_GATES.len()],
        next: 0,
    };
    let qemu_report = run_selftest_with_probe(&qemu_cli, args, &mut probe)?;
    let qemu_gate_names = qemu_report
        .gates
        .iter()
        .filter(|gate| gate.runner == SelftestGateRunner::RealQemu)
        .map(|gate| gate.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(qemu_gate_names, REAL_QEMU_SELFTEST_GATES);
    assert!(qemu_report.gates.iter().all(|gate| {
        if gate.runner == SelftestGateRunner::RealQemu {
            gate.qemu_build_id.as_deref() == Some(expected_qemu_build_id.as_str())
        } else {
            gate.qemu_build_id.is_none()
        }
    }));
    assert_eq!(probe.next, REAL_QEMU_SELFTEST_GATES.len());

    let mut divergent_probe = FakeLiveQemuProbeRunner {
        reports: vec![
            LiveQemuProbeEvidence {
                qemu_build_id: expected_qemu_build_id.clone(),
                plugin_abi: required_qemu_plugin_abi(),
                completed_icount: 1_000,
                execution_fingerprint: content_address_bytes(b"first-live-probe"),
            },
            LiveQemuProbeEvidence {
                qemu_build_id: expected_qemu_build_id.clone(),
                plugin_abi: required_qemu_plugin_abi(),
                completed_icount: 1_000,
                execution_fingerprint: content_address_bytes(b"diverged-live-probe"),
            },
        ],
        next: 0,
    };
    let error = run_selftest_with_probe(&qemu_cli, args, &mut divergent_probe)
        .expect_err("divergent live-QEMU probes must fail closed");
    assert!(error.to_string().contains("probes diverged"));

    let mut mismatched_identity_probe = FakeLiveQemuProbeRunner {
        reports: vec![LiveQemuProbeEvidence {
            qemu_build_id: content_address_bytes(b"different-qemu-build"),
            plugin_abi: required_qemu_plugin_abi(),
            completed_icount: 1_000,
            execution_fingerprint: content_address_bytes(b"stable-live-probe"),
        }],
        next: 0,
    };
    let error = run_selftest_with_probe(&qemu_cli, args, &mut mismatched_identity_probe)
        .expect_err("a live-QEMU build identity mismatch must fail closed");
    assert!(error.to_string().contains("identity does not match"));

    let unknown = Cli::parse_from(["crucible", "selftest", "--gates", "gate:not-real"]);
    let Commands::Selftest(args) = &unknown.command else {
        panic!("expected selftest command");
    };
    let error = match run_selftest(&unknown, args) {
        Ok(_) => panic!("unknown selftest gate must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);

    let empty = Cli::parse_from(["crucible", "selftest", "--gates", "gate:replay-oracle,"]);
    let Commands::Selftest(args) = &empty.command else {
        panic!("expected selftest command");
    };
    let error = match run_selftest(&empty, args) {
        Ok(_) => panic!("empty selftest gate component must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);

    let duplicate = Cli::parse_from([
        "crucible",
        "selftest",
        "--gates",
        "gate:replay-oracle,gate:replay-oracle",
    ]);
    let Commands::Selftest(args) = &duplicate.command else {
        panic!("expected selftest command");
    };
    let error = match run_selftest(&duplicate, args) {
        Ok(_) => panic!("duplicate selftest gate must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);

    let unsupported = Cli::parse_from(["crucible", "selftest", "--gates", "gate:qemu-inert"]);
    let Commands::Selftest(args) = &unsupported.command else {
        panic!("expected selftest command");
    };
    let error = match run_selftest(&unsupported, args) {
        Ok(_) => panic!("real-QEMU selftest gate must require --with-qemu"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);

    Ok(())
}
