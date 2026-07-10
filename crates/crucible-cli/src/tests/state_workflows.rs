// Save, resume, fork, and search/fuzz workflow tests.
#[test]
fn cli_save_workflow_executes_local_double_and_exports_handle() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let artifact_dir = temp.path().join("artifacts");
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("9"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--label"),
        String::from("release candidate"),
    ]);
    let Commands::Save(args) = &cli.command else {
        panic!("expected save command");
    };
    let save_plan = plan_save_invocation(args, temp.path(), &cli.artifact_dir)?;
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("save should resolve a seed");
    let backend_plan = plan_backend_selection(&cli)?.expect("save should require backend");
    let mut outcome = execute_backend_routed_command(
        &plan_cli_invocation(&cli),
        &backend_plan,
        Some(&seed_plan),
        Some(&save_plan.run_plan),
        None,
        Some(&save_plan),
        &mut NullBackendCommandRunner,
    )?;
    export_savepoint_handle(&save_plan, &mut outcome)?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert!(outcome.terminal_savepoint.is_some());
    assert!(outcome.savepoint_oracle.is_some());
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-savepoint\tpolicy=always\tcheckpoint=blake3:") })
    );
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("save-oracle\tstatus=fat==thin-passed\tconfiguration=blake3:")
    }));
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("save-handle\tcheckpoint=blake3:")
                && line.contains("label=release candidate"))
    );
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("save-store\tcheckpoint=blake3:")
            && line.contains("artifact=blake3:")
            && line.contains("index=blake3:")
            && line.contains(&format!("store={}", temp.path().display()))
    }));
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "interactive_ack" && entry.summary == "create-savepoint")
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "save_oracle_validation")
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "save_export")
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "save_store_index")
    );

    let handles = fs::read_dir(&artifact_dir)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(handles.len(), 1);
    let handle_path = handles[0].path();
    assert!(
        handle_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("savepoint-release-candidate-")
                && name.ends_with(".crucible-savepoint"))
    );
    let handle = fs::read_to_string(handle_path)?;
    assert!(handle.contains(&format!("schema\t{SAVEPOINT_HANDLE_SCHEMA}\n")));
    assert!(handle.contains("label\trelease candidate\n"));
    assert!(handle.contains("checkpoint\tblake3:"));
    assert!(handle.contains("at\tquiescence\n"));
    assert!(handle.contains("materialization\tcreate-savepoint\treply\n"));
    assert!(handle.contains("oracle\tfat==thin-passed\n"));

    let saved_checkpoint = outcome
        .terminal_savepoint
        .expect("save workflow should expose a terminal savepoint");
    let saved_checkpoint_ref = format_content_hash_ref(saved_checkpoint);
    let resume_saved_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        temp.path().display().to_string(),
        String::from("resume"),
        saved_checkpoint_ref.clone(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
    ]);
    let Commands::Resume(args) = &resume_saved_cli.command else {
        panic!("expected resume command");
    };
    let resume_saved_plan = plan_resume_invocation(args, temp.path())?;
    let backend_plan =
        plan_backend_selection(&resume_saved_cli)?.expect("resume should route to backend");
    let resume_saved_outcome = run_local_double_resume_workflow(
        &plan_cli_invocation(&resume_saved_cli),
        &backend_plan,
        None,
        &resume_saved_plan,
    )?;
    assert_eq!(resume_saved_outcome.status, BackendCommandStatus::Passed);
    assert!(resume_saved_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains(&format!("checkpoint={saved_checkpoint_ref}"))
            && line.contains("final=virtual-time")
    }));

    let fork_saved_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        temp.path().display().to_string(),
        String::from("fork"),
        saved_checkpoint_ref.clone(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("from-save-store"),
    ]);
    let Commands::Fork(args) = &fork_saved_cli.command else {
        panic!("expected fork command");
    };
    let fork_saved_plan =
        plan_fork_invocation(args, None, &fork_saved_cli.artifact_dir, temp.path())?;
    let backend_plan =
        plan_backend_selection(&fork_saved_cli)?.expect("fork should route to backend");
    let fork_saved_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&fork_saved_cli),
        &backend_plan,
        None,
        &fork_saved_plan,
    )?;
    assert_eq!(fork_saved_outcome.status, BackendCommandStatus::Passed);
    assert!(fork_saved_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains(&format!("checkpoint={saved_checkpoint_ref}"))
            && line.contains("label=from-save-store")
            && line.contains("final=virtual-time")
    }));

    let explicit = temp.path().join("explicit.crucible-savepoint");
    let dispatch_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("10"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--label"),
        String::from("explicit"),
        String::from("--out"),
        explicit.display().to_string(),
    ]);
    dispatch(&dispatch_cli)?;
    assert!(fs::read_to_string(explicit)?.contains("label\texplicit\n"));

    let virtual_time_out = temp.path().join("virtual-time.crucible-savepoint");
    let virtual_time_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("12"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("at-two-ticks"),
        String::from("--out"),
        virtual_time_out.display().to_string(),
    ]);
    dispatch(&virtual_time_cli)?;
    let virtual_time_handle = fs::read_to_string(virtual_time_out)?;
    assert!(virtual_time_handle.contains("label\tat-two-ticks\n"));
    assert!(virtual_time_handle.contains("at\tvirtual-time\n"));
    assert!(virtual_time_handle.contains("oracle\tfat==thin-passed\n"));

    let property_selector_scenario = write_property_selector_scenario(&temp)?;
    let property_out = temp.path().join("property.crucible-savepoint");
    let property_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("13"),
        String::from("save"),
        property_selector_scenario.display().to_string(),
        String::from("--at"),
        String::from("property"),
        String::from("--property"),
        String::from("no-split-brain"),
        String::from("--label"),
        String::from("property-stop"),
        String::from("--out"),
        property_out.display().to_string(),
    ]);
    dispatch(&property_cli)?;
    let property_handle = fs::read_to_string(property_out)?;
    assert!(property_handle.contains("label\tproperty-stop\n"));
    assert!(property_handle.contains("at\tproperty\n"));
    assert!(property_handle.contains("oracle\tfat==thin-passed\n"));

    let split_property_out = temp.path().join("split-property.crucible-savepoint");
    let split_property_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("15"),
        String::from("save"),
        property_selector_scenario.display().to_string(),
        String::from("--at"),
        String::from("property"),
        String::from("--property"),
        String::from("split-active"),
        String::from("--label"),
        String::from("split-property-stop"),
        String::from("--out"),
        split_property_out.display().to_string(),
    ]);
    dispatch(&split_property_cli)?;
    let split_property_handle = fs::read_to_string(split_property_out)?;
    assert!(split_property_handle.contains("label\tsplit-property-stop\n"));
    assert!(split_property_handle.contains("at\tproperty\n"));
    assert!(split_property_handle.contains("oracle\tfat==thin-passed\n"));

    let marker_selector_scenario = write_marker_selector_scenario(&temp)?;
    let marker_out = temp.path().join("marker.crucible-savepoint");
    let marker_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("14"),
        String::from("save"),
        marker_selector_scenario.display().to_string(),
        String::from("--at"),
        String::from("marker"),
        String::from("--marker"),
        String::from("phase-two-marker"),
        String::from("--label"),
        String::from("marker-stop"),
        String::from("--out"),
        marker_out.display().to_string(),
    ]);
    dispatch(&marker_cli)?;
    let marker_handle = fs::read_to_string(marker_out)?;
    assert!(marker_handle.contains("label\tmarker-stop\n"));
    assert!(marker_handle.contains("at\tmarker\n"));
    assert!(marker_handle.contains("oracle\tfat==thin-passed\n"));

    let wrong_marker_out = temp.path().join("wrong-marker.crucible-savepoint");
    let wrong_marker_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("22"),
        String::from("save"),
        marker_selector_scenario.display().to_string(),
        String::from("--at"),
        String::from("marker"),
        String::from("--marker"),
        String::from("compaction-started"),
        String::from("--label"),
        String::from("wrong-marker-stop"),
        String::from("--out"),
        wrong_marker_out.display().to_string(),
    ]);
    let error = dispatch(&wrong_marker_cli)
        .expect_err("marker save must wait for the scenario-authored marker identity");
    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("did not fire"));
    assert!(!wrong_marker_out.exists());

    let no_source_marker_scenario = write_marker_selector_without_source_scenario(&temp)?;
    let no_source_marker_out = temp.path().join("no-source-marker.crucible-savepoint");
    let no_source_marker_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("16"),
        String::from("save"),
        no_source_marker_scenario.display().to_string(),
        String::from("--at"),
        String::from("marker"),
        String::from("--marker"),
        String::from("compaction-started"),
        String::from("--label"),
        String::from("no-source-marker-stop"),
        String::from("--out"),
        no_source_marker_out.display().to_string(),
    ]);
    let error = dispatch(&no_source_marker_cli)
        .expect_err("marker save must require an emitted selector event");
    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("did not fire"));
    assert!(!no_source_marker_out.exists());

    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let qemu_out = temp.path().join("qemu.crucible-savepoint");
    let qemu_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("qemu"),
        String::from("--qemu"),
        qemu.clone(),
        String::from("--plugin"),
        plugin.clone(),
        String::from("--seed"),
        String::from("11"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--label"),
        String::from("qemu-save"),
        String::from("--out"),
        qemu_out.display().to_string(),
    ]);
    let Commands::Save(args) = &qemu_cli.command else {
        panic!("expected save command");
    };
    let qemu_save_plan = plan_save_invocation(args, temp.path(), &qemu_cli.artifact_dir)?;
    let qemu_seed_plan = plan_determinism_ergonomics(
        &qemu_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("save should resolve a seed");
    let mut qemu_outcome = execute_backend_routed_command(
        &plan_cli_invocation(&qemu_cli),
        &plan_backend_selection(&qemu_cli)?.expect("save should require backend"),
        Some(&qemu_seed_plan),
        Some(&qemu_save_plan.run_plan),
        None,
        Some(&qemu_save_plan),
        &mut NullBackendCommandRunner,
    )?;
    export_savepoint_handle(&qemu_save_plan, &mut qemu_outcome)?;
    assert_eq!(qemu_outcome.status, BackendCommandStatus::Passed);
    assert!(qemu_outcome.terminal_savepoint.is_some());
    assert!(qemu_outcome.savepoint_oracle.is_some());
    assert!(qemu_outcome.stdout.iter().any(|line| {
        line.starts_with("save-qemu-runner\tmaterialization=create-savepoint-reply\tqemu_build_id=")
            && line.contains("qemu_patch_series=")
            && line.contains("plugin_abi=")
            && line.contains("shmem_abi=")
    }));
    assert!(
        qemu_outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "save_qemu_runner")
    );
    let qemu_handle = fs::read_to_string(qemu_out)?;
    assert!(qemu_handle.contains("label\tqemu-save\n"));
    assert!(qemu_handle.contains("oracle\tfat==thin-passed\n"));

    let qemu_dispatch_out = temp.path().join("qemu-dispatch.crucible-savepoint");
    let qemu_dispatch_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("qemu"),
        String::from("--qemu"),
        qemu,
        String::from("--plugin"),
        plugin,
        String::from("--seed"),
        String::from("17"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--label"),
        String::from("qemu-dispatch-save"),
        String::from("--out"),
        qemu_dispatch_out.display().to_string(),
    ]);
    dispatch(&qemu_dispatch_cli)?;
    let qemu_dispatch_handle = fs::read_to_string(qemu_dispatch_out)?;
    assert!(qemu_dispatch_handle.contains("label\tqemu-dispatch-save\n"));
    assert!(qemu_dispatch_handle.contains("oracle\tfat==thin-passed\n"));

    Ok(())
}

#[test]
fn cli_save_workflow_executes_remote_daemon_savepoint() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let daemon = spawn_production_lifecycle_server()?;
    let out = temp.path().join("remote.crucible-savepoint");
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--daemon"),
        daemon.clone(),
        String::from("--seed"),
        String::from("18"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--label"),
        String::from("remote-save"),
        String::from("--out"),
        out.display().to_string(),
    ]);
    let Commands::Save(args) = &cli.command else {
        panic!("expected save command");
    };
    let save_plan = plan_save_invocation(args, temp.path(), &cli.artifact_dir)?;
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("save should resolve a seed");
    let backend_plan = plan_backend_selection(&cli)?.expect("save should require backend");
    assert_eq!(backend_plan.target, BackendExecutionTarget::RemoteDaemon);

    let mut outcome = execute_backend_routed_command(
        &plan_cli_invocation(&cli),
        &backend_plan,
        Some(&seed_plan),
        Some(&save_plan.run_plan),
        None,
        Some(&save_plan),
        &mut NullBackendCommandRunner,
    )?;
    export_savepoint_handle(&save_plan, &mut outcome)?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.terminal_savepoint.is_some());
    assert!(outcome.savepoint_oracle.is_some());
    assert!(
        outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("save-oracle\tstatus=fat==thin-passed"))
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "save_oracle_validation")
    );
    assert!(
        !outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("save-qemu-runner\t"))
    );
    let handle = fs::read_to_string(out)?;
    assert!(handle.contains("label\tremote-save\n"));
    assert!(handle.contains("oracle\tfat==thin-passed\n"));

    let dispatch_out = temp.path().join("remote-dispatch.crucible-savepoint");
    let dispatch_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--daemon"),
        daemon.clone(),
        String::from("--seed"),
        String::from("19"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--label"),
        String::from("remote-dispatch-save"),
        String::from("--out"),
        dispatch_out.display().to_string(),
    ]);
    dispatch(&dispatch_cli)?;
    let dispatch_handle = fs::read_to_string(dispatch_out)?;
    assert!(dispatch_handle.contains("label\tremote-dispatch-save\n"));
    assert!(dispatch_handle.contains("oracle\tfat==thin-passed\n"));

    let virtual_time_out = temp.path().join("remote-virtual-time.crucible-savepoint");
    let virtual_time_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--daemon"),
        daemon,
        String::from("--seed"),
        String::from("20"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("remote-virtual-time-save"),
        String::from("--out"),
        virtual_time_out.display().to_string(),
    ]);
    dispatch(&virtual_time_cli)?;
    let virtual_time_handle = fs::read_to_string(virtual_time_out)?;
    assert!(virtual_time_handle.contains("label\tremote-virtual-time-save\n"));
    assert!(virtual_time_handle.contains("at\tvirtual-time\n"));
    assert!(virtual_time_handle.contains("oracle\tfat==thin-passed\n"));

    Ok(())
}

#[test]
fn cli_save_workflow_executes_remote_daemon_selector_savepoint() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = write_property_selector_scenario(&temp)?;
    let daemon = spawn_save_recording_lifecycle_server()?;
    let out = temp.path().join("remote-selector.crucible-savepoint");
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--daemon"),
        daemon,
        String::from("--seed"),
        String::from("21"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("property"),
        String::from("--property"),
        String::from("split-active"),
        String::from("--label"),
        String::from("remote-selector-save"),
        String::from("--out"),
        out.display().to_string(),
    ]);
    dispatch(&cli)?;
    let handle = fs::read_to_string(out)?;
    assert!(handle.contains("label\tremote-selector-save\n"));
    assert!(handle.contains("at\tproperty\n"));
    assert!(handle.contains("oracle\tfat==thin-passed\n"));

    let marker_form = marker_selector_scenario_form(::crucible::WhiteBoxPolicy::Enabled)?;
    let marker_scenario = temp.path().join("remote-marker-selector-scenario.toml");
    fs::write(&marker_scenario, marker_form.to_canonical_toml()?)?;
    let marker_daemon = spawn_save_recording_lifecycle_server()?;
    let marker_out = temp
        .path()
        .join("remote-marker-selector.crucible-savepoint");
    let marker_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--daemon"),
        marker_daemon,
        String::from("--seed"),
        String::from("22"),
        String::from("save"),
        marker_scenario.display().to_string(),
        String::from("--at"),
        String::from("marker"),
        String::from("--marker"),
        String::from("phase-two-marker"),
        String::from("--label"),
        String::from("remote-marker-selector-save"),
        String::from("--out"),
        marker_out.display().to_string(),
    ]);
    dispatch(&marker_cli)?;
    let marker_handle = fs::read_to_string(marker_out)?;
    assert!(marker_handle.contains("label\tremote-marker-selector-save\n"));
    assert!(marker_handle.contains("at\tmarker\n"));
    assert!(marker_handle.contains("oracle\tfat==thin-passed\n"));

    Ok(())
}

#[test]
fn cli_save_selector_proof_rejects_invalid_breakpoint_evidence() -> Result<(), Box<dyn Error>> {
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

    Ok(())
}

fn save_selector_test_boundary(frontier: u64, quanta: u64) -> crucible_api::SessionSummary {
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

fn save_selector_test_firing(
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
fn cli_resume_workflow_plans_handles_hashes_and_rejects_malformed_inputs()
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

    assert!(matches!(plan.savepoint, ResumeSavepointRef::Handle { .. }));
    assert_eq!(plan.savepoint.checkpoint(), checkpoint);
    assert_eq!(plan.terminal_condition, RunTerminalCondition::Quiescence);
    assert_eq!(plan.execution_mode, RunExecutionMode::Interactive);
    assert!(plan.watch_streams_live_status);
    assert_eq!(plan.startup_commands, vec![SessionCommandKind::Start]);
    assert!(
        plan.accepted_interactive_commands
            .contains(&SessionCommandKind::Continue)
    );
    let ResumeSavepointRef::Handle { handle, .. } = &plan.savepoint else {
        panic!("expected decoded handle");
    };
    assert_eq!(handle.label, "resume-source");
    assert_eq!(handle.scenario_id_hex, scenario.id().to_hex());
    assert_eq!(handle.scenario_label, "resume-scenario.toml");
    assert_eq!(handle.scenario_payload, form.to_compact_binary());
    assert_eq!(handle.schedule_payload, schedule.to_compact_binary());
    assert_eq!(handle.frontier_ticks, 1);
    assert_eq!(handle.at, SaveAtArg::Quiescence);
    assert_eq!(handle.terminal_condition, RunTerminalCondition::Quiescence);
    assert_eq!(handle.materialization, "create-savepoint:reply");
    assert_eq!(handle.oracle_status, "fat==thin-passed");
    assert_eq!(handle.canonical_log_digest, canonical_log);

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
    fs::write(&malformed, format!("schema\t{SAVEPOINT_HANDLE_SCHEMA}\n"))?;
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
fn cli_resume_workflow_executes_local_double_bare_hash_from_store() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let store_root = temp.path().join("store");
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
    write_checkpoint_closure_fixture(&store_root, &form, &schedule)?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        store_root.display().to_string(),
        String::from("resume"),
        format_content_hash_ref(checkpoint),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
    ]);
    let Commands::Resume(args) = &cli.command else {
        panic!("expected resume command");
    };
    let resume_plan = plan_resume_invocation(args, &store_root)?;
    assert!(matches!(
        resume_plan.savepoint,
        ResumeSavepointRef::CheckpointHash(_)
    ));
    let backend_plan = plan_backend_selection(&cli)?.expect("resume should route to backend");
    let outcome = run_local_double_resume_workflow(
        &plan_cli_invocation(&cli),
        &backend_plan,
        None,
        &resume_plan,
    )?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains(&format!(
                "checkpoint={}",
                format_content_hash_ref(checkpoint)
            ))
            && line.contains("final=virtual-time")
            && line.contains("frontier_ticks=2")
    }));
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("resume-oracle\t") && line.contains("status=fat==thin-passed")
    }));

    Ok(())
}

#[test]
fn cli_resume_workflow_rejects_missing_bare_hash_store_index_as_artifact()
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
            .contains(&format_content_hash_ref(checkpoint))
    );
    assert!(
        error
            .to_string()
            .contains("could not be loaded from DAG store")
    );

    Ok(())
}

#[test]
fn cli_resume_workflow_rejects_unverified_handle_evidence() -> Result<(), Box<dyn Error>> {
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
fn cli_resume_workflow_rejects_tampered_handle_frontier() -> Result<(), Box<dyn Error>> {
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
        fs::read_to_string(&handle_path)?.replace("frontier\t1\n", "frontier\t8\n"),
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
    assert!(error.to_string().contains("schedule-derived frontier"));

    Ok(())
}

#[test]
fn cli_resume_terminal_oracle_rejects_non_descendant_snapshot() -> Result<(), Box<dyn Error>> {
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
    let evidence = ResumeHandleEvidence {
        scenario_form: form,
        scenario: scenario.clone(),
        schedule: source_schedule,
        configuration: source_configuration,
        checkpoint: source_checkpoint,
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
fn cli_resume_workflow_executes_local_double_handle() -> Result<(), Box<dyn Error>> {
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
fn cli_resume_workflow_executes_remote_daemon_handle() -> Result<(), Box<dyn Error>> {
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
        "remote-resume-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &content_address_bytes(b"remote-resume-log"),
    )?;
    let daemon = spawn_resume_recording_lifecycle_server(
        ResumeRecordingFixture::None,
        VirtualTime { ticks: 1 },
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--daemon"),
        daemon.clone(),
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
    assert_eq!(backend_plan.target, BackendExecutionTarget::RemoteDaemon);

    let outcome = run_remote_resume_workflow(
        &daemon,
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
        line.starts_with("resume-oracle\t") && line.contains("status=fat==thin-passed")
    }));
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "resume_checkpoint"
                && entry.summary.contains("until=virtual-time"))
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "resume_oracle_validation")
    );

    let watch_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--daemon"),
        daemon.clone(),
        String::from("resume"),
        handle_path.display().to_string(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--watch"),
    ]);
    let Commands::Resume(args) = &watch_cli.command else {
        panic!("expected resume command");
    };
    let watch_plan = plan_resume_invocation(args, temp.path())?;
    let backend_plan = plan_backend_selection(&watch_cli)?.expect("resume should route to backend");
    let watch_outcome = run_remote_resume_workflow(
        &daemon,
        &plan_cli_invocation(&watch_cli),
        &backend_plan,
        None,
        &watch_plan,
    )?;
    assert_eq!(watch_outcome.status, BackendCommandStatus::Passed);
    assert!(watch_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains("final=virtual-time")
            && line.contains("frontier_ticks=2")
    }));
    assert!(
        watch_outcome
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-watch\tstate=paused\tfrontier_ticks=2") })
    );
    assert!(
        watch_outcome
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-watch\tstate=stopped\tfrontier_ticks=2") })
    );

    let interactive_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--daemon"),
        daemon.clone(),
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
    let interactive_outcome = run_remote_resume_workflow_with_interactive_commands(
        &daemon,
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
    let remote_interactive_final = interactive_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains("final=interactive")
            && line.contains("frontier_ticks=2")
    });
    assert!(remote_interactive_final);
    assert!(
        interactive_outcome
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-watch\tstate=paused\tfrontier_ticks=2") })
    );
    assert!(interactive_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-oracle\t") && line.contains("status=fat==thin-passed")
    }));

    let interactive_stop_outcome = run_remote_resume_workflow_with_interactive_commands(
        &daemon,
        &plan_cli_invocation(&interactive_cli),
        &backend_plan,
        None,
        &interactive_plan,
        &[SessionCommandKind::Stop],
    )?;
    assert_eq!(
        interactive_stop_outcome.status,
        BackendCommandStatus::Passed
    );
    let remote_interactive_stop_final = interactive_stop_outcome.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains("final=interactive")
            && line.contains("frontier_ticks=1")
    });
    assert!(remote_interactive_stop_final);
    assert!(
        interactive_stop_outcome
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-watch\tstate=stopped\tfrontier_ticks=1") })
    );

    let terminal_interactive = run_remote_resume_workflow_with_interactive_commands(
        &daemon,
        &plan_cli_invocation(&interactive_cli),
        &backend_plan,
        None,
        &interactive_plan,
        &[SessionCommandKind::Continue],
    )?;
    assert_eq!(terminal_interactive.status, BackendCommandStatus::Passed);
    assert!(terminal_interactive.terminal_savepoint.is_some());
    let remote_interactive_terminal_final = terminal_interactive.stdout.iter().any(|line| {
        line.starts_with("resume-session\t")
            && line.contains("final=interactive")
            && line.contains("frontier_ticks=2")
    });
    assert!(remote_interactive_terminal_final);
    assert!(terminal_interactive.stdout.iter().any(|line| {
        line.starts_with("resume-oracle\t") && line.contains("status=fat==thin-passed")
    }));
    assert!(
        terminal_interactive
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-watch\tstate=stopped\tfrontier_ticks=2") })
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(&daemon)))?;
    let sessions = runtime.block_on(client.list_sessions())?;
    assert!(
        sessions.sessions.is_empty(),
        "terminal remote interactive finalization should remove the stopped session: {:?}",
        sessions.sessions
    );

    Ok(())
}

#[test]
fn cli_resume_workflow_allows_virtual_time_beyond_ack_yield_bound() -> Result<(), Box<dyn Error>> {
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

#[test]
fn cli_fork_help_surface_lists_wip_flags() {
    let mut command = Cli::command();
    command.build();
    let help = command
        .find_subcommand_mut("fork")
        .expect("fork subcommand must be registered")
        .render_long_help()
        .to_string();
    for needle in [
        "SAVEPOINT",
        "--override <decision=value>",
        "--until <quiescence|virtual-time|property|stopped>",
        "--max-virtual-time <dur>",
        "--label <name>",
        "--interactive",
        "--watch",
    ] {
        assert!(
            help.contains(needle),
            "fork help is missing `{needle}`:\n{help}"
        );
    }
}

#[test]
fn cli_fork_workflow_plans_savepoint_overrides_and_rejects_malformed_inputs()
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
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint = configuration.id();
    let canonical_log = content_address_bytes(b"fork-log");
    let handle_path = write_savepoint_handle_fixture(
        temp.path(),
        "fork-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &canonical_log,
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--override"),
        String::from("node-a.boot=alternate"),
        String::from("--override"),
        String::from("scheduler.step=5"),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("child-a"),
        String::from("--interactive"),
        String::from("--watch"),
    ]);
    let Commands::Fork(args) = &cli.command else {
        panic!("expected fork command");
    };
    let plan = plan_fork_invocation_for_test(args, None)?;

    assert!(matches!(plan.source, ResumeSavepointRef::Handle { .. }));
    assert_eq!(plan.source.checkpoint(), checkpoint);
    assert_eq!(plan.label, "child-a");
    assert_eq!(
        plan.decision_overrides,
        vec![
            ForkDecisionOverride {
                decision: String::from("node-a.boot"),
                value: String::from("alternate"),
            },
            ForkDecisionOverride {
                decision: String::from("scheduler.step"),
                value: String::from("5"),
            },
        ]
    );
    assert_eq!(plan.fork_seed, None);
    assert_eq!(plan.terminal_condition, RunTerminalCondition::VirtualTime);
    assert_eq!(plan.max_virtual_time.as_deref(), Some("2ticks"));
    assert_eq!(plan.max_virtual_time_ticks, Some(2));
    assert_eq!(plan.execution_mode, RunExecutionMode::Interactive);
    assert!(plan.watch_streams_live_status);
    assert_eq!(plan.startup_commands, vec![SessionCommandKind::Fork]);
    assert_eq!(
        plan.initial_control_commands,
        vec![SessionCommandKind::Query]
    );
    assert!(
        plan.accepted_interactive_commands
            .contains(&SessionCommandKind::Continue)
    );

    let reference = format_content_hash_ref(checkpoint);
    let hash_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("fork"),
        reference.clone(),
        String::from("--label"),
        String::from("hash-child"),
    ]);
    let Commands::Fork(args) = &hash_cli.command else {
        panic!("expected fork command");
    };
    let hash_plan = plan_fork_invocation_for_test(args, None)?;
    assert_eq!(hash_plan.source.checkpoint(), checkpoint);
    assert_eq!(hash_plan.label, "hash-child");
    assert_eq!(hash_plan.fork_seed, None);
    assert_eq!(
        hash_plan.startup_commands,
        vec![SessionCommandKind::Fork, SessionCommandKind::Continue]
    );

    let seed_cli = Cli::parse_from(["crucible", "--seed", "2", "fork", &reference]);
    let Commands::Fork(args) = &seed_cli.command else {
        panic!("expected fork command");
    };
    let seed_plan = plan_fork_invocation_for_test(args, Some(2))?;
    assert_eq!(seed_plan.fork_seed, Some(2));

    let missing = ForkArgs::default();
    let error = match plan_fork_invocation_for_test(&missing, None) {
        Ok(_) => panic!("fork without savepoint must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("fork requires"));

    let error =
        match Cli::try_parse_from(["crucible", "fork", &reference, "--until", "virtual-time"]) {
            Ok(_) => panic!("virtual-time fork requires a duration budget"),
            Err(error) => error,
        };
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    assert_eq!(cli_parse_error_exit_code(&error), 64);

    for malformed in ["missing-equals", "=value", "decision=", "a=b=c", "a\nb=c"] {
        let args = ForkArgs {
            savepoint: Some(reference.clone()),
            overrides: vec![String::from(malformed)],
            ..ForkArgs::default()
        };
        let error = match plan_fork_invocation_for_test(&args, None) {
            Ok(_) => panic!("malformed fork override `{malformed}` must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
    }

    let seed_conflict = Cli::parse_from([
        "crucible",
        "--seed",
        "1",
        "fork",
        &reference,
        "--override",
        "decision=value",
    ]);
    let Commands::Fork(args) = &seed_conflict.command else {
        panic!("expected fork command");
    };
    let error = match plan_fork_invocation_for_test(args, Some(1)) {
        Ok(_) => panic!("fork must reject explicit seed plus override"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("--seed and --override"));

    let malformed = temp.path().join("malformed-fork.crucible-savepoint");
    fs::write(&malformed, format!("schema\t{SAVEPOINT_HANDLE_SCHEMA}\n"))?;
    let malformed_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("fork"),
        malformed.display().to_string(),
    ]);
    let Commands::Fork(args) = &malformed_cli.command else {
        panic!("expected fork command");
    };
    let error = match plan_fork_invocation_for_test(args, None) {
        Ok(_) => panic!("malformed fork savepoint handle must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Artifact(_)));
    assert_eq!(error.exit_code(), 5);

    Ok(())
}

#[test]
fn cli_fork_workflow_executes_local_double_bare_hash_from_store() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("fork-artifacts");
    let store_root = temp.path().join("store");
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let inherited_seed = seed_to_u64(form.seed());
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
    write_checkpoint_closure_fixture(&store_root, &form, &schedule)?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        store_root.display().to_string(),
        String::from("fork"),
        format_content_hash_ref(checkpoint),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("branch-a"),
    ]);
    let Commands::Fork(args) = &cli.command else {
        panic!("expected fork command");
    };
    let fork_plan = plan_fork_invocation(args, None, &cli.artifact_dir, &store_root)?;
    assert!(matches!(
        fork_plan.source,
        ResumeSavepointRef::CheckpointHash(_)
    ));
    let backend_plan = plan_backend_selection(&cli)?.expect("fork should route to backend");
    let outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&cli),
        &backend_plan,
        None,
        &fork_plan,
    )?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    let expected_checkpoint = format_content_hash_ref(checkpoint);
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains(&format!("checkpoint={expected_checkpoint}"))
            && line.contains(&format!("branch={expected_checkpoint}"))
            && line.contains("label=branch-a")
            && line.contains("final=virtual-time")
            && line.contains("frontier_ticks=2")
    }));
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("fork-oracle\t") && line.contains("status=fat==thin-passed")
    }));
    assert_fork_artifact_replays(&cli, &outcome, inherited_seed)?;

    Ok(())
}

#[test]
fn cli_fork_workflow_executes_local_double_handle() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("fork-artifacts");
    let store_root = temp.path().join("store");
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let inherited_seed = seed_to_u64(form.seed());
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
        "fork-source",
        &form,
        &schedule,
        checkpoint,
        1,
        &content_address_bytes(b"fork-log"),
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("child-a"),
    ]);
    let Commands::Fork(args) = &cli.command else {
        panic!("expected fork command");
    };
    let fork_plan = plan_fork_invocation(args, None, &cli.artifact_dir, &store_root)?;
    let backend_plan = plan_backend_selection(&cli)?.expect("fork should route to backend");
    let outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&cli),
        &backend_plan,
        None,
        &fork_plan,
    )?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.terminal_savepoint.is_some());
    assert!(outcome.savepoint_oracle.is_some());
    let expected_checkpoint = format_content_hash_ref(checkpoint);
    let fork_line = outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("fork-session\t"))
        .expect("fork workflow must emit a fork-session line");
    assert!(fork_line.contains(&format!("checkpoint={expected_checkpoint}")));
    assert!(fork_line.contains(&format!("branch={expected_checkpoint}")));
    assert!(fork_line.contains(&format!("configuration={expected_checkpoint}")));
    assert!(fork_line.contains("label=child-a"));
    assert!(fork_line.contains("final=virtual-time"));
    assert!(fork_line.contains("frontier_ticks=2"));
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("fork-oracle\t")
            && line.contains("status=fat==thin-passed")
            && line.contains("fat=blake3:")
            && line.contains("thin=blake3:")
    }));
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("fork-artifact\t")
            && line.contains("digest=crucible-hash:")
            && line.contains(&format!("seed={}", format_seed(inherited_seed)))
            && line.contains("model_artifact=blake3:")
            && line.contains("replay_state=blake3:")
    }));
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "fork_checkpoint")
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "fork_oracle_validation")
    );
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "fork_reproduction_artifact")
    );
    assert!(fs::read_dir(&artifact_dir)?.next().is_some());
    assert_fork_artifact_replays(&cli, &outcome, inherited_seed)?;

    let quiescence_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--label"),
        String::from("child-quiescent"),
    ]);
    let Commands::Fork(args) = &quiescence_cli.command else {
        panic!("expected fork command");
    };
    let quiescence_plan =
        plan_fork_invocation(args, None, &quiescence_cli.artifact_dir, &store_root)?;
    let backend_plan =
        plan_backend_selection(&quiescence_cli)?.expect("fork should route to backend");
    let quiescence_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&quiescence_cli),
        &backend_plan,
        None,
        &quiescence_plan,
    )?;
    assert_eq!(quiescence_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(quiescence_outcome.exit_code, 0);
    assert!(quiescence_outcome.terminal_savepoint.is_some());
    assert!(quiescence_outcome.savepoint_oracle.is_some());
    assert!(quiescence_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains("label=child-quiescent")
            && line.contains("final=quiescent")
    }));
    assert!(
        quiescence_outcome
            .stdout
            .iter()
            .any(|line| line.starts_with("fork-oracle\t"))
    );

    let interactive_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--interactive"),
        String::from("--watch"),
        String::from("--label"),
        String::from("child-interactive"),
    ]);
    let Commands::Fork(args) = &interactive_cli.command else {
        panic!("expected fork command");
    };
    let interactive_plan =
        plan_fork_invocation(args, None, &interactive_cli.artifact_dir, &store_root)?;
    let backend_plan =
        plan_backend_selection(&interactive_cli)?.expect("fork should route to backend");
    let interactive_outcome = run_local_double_fork_workflow_with_interactive_commands(
        &plan_cli_invocation(&interactive_cli),
        &backend_plan,
        None,
        &interactive_plan,
        &[SessionCommandKind::StepQuantum, SessionCommandKind::Query],
    )?;
    assert_eq!(interactive_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(interactive_outcome.exit_code, 0);
    assert!(interactive_outcome.terminal_savepoint.is_some());
    assert!(interactive_outcome.savepoint_oracle.is_some());
    assert!(interactive_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains("label=child-interactive")
            && line.contains("final=interactive")
    }));

    let seed_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("7"),
        String::from("fork"),
        handle_path.display().to_string(),
    ]);
    let Commands::Fork(args) = &seed_cli.command else {
        panic!("expected fork command");
    };
    let seeded_plan = plan_fork_invocation(args, Some(7), &seed_cli.artifact_dir, &store_root)?;
    let backend_plan = plan_backend_selection(&seed_cli)?.expect("fork should route to backend");
    let seeded_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&seed_cli),
        &backend_plan,
        None,
        &seeded_plan,
    )?;
    assert_eq!(seeded_outcome.status, BackendCommandStatus::Passed);
    assert!(seeded_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains(&format!("checkpoint={expected_checkpoint}"))
            && line.contains(&format!("fork_seed={}", format_seed(7)))
            && line.contains("final=quiescent")
            && line.contains("frontier_ticks=2")
            && line.contains("quanta=1")
    }));
    let seeded_fork_line = seeded_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("fork-session\t"))
        .expect("seeded fork must emit a fork-session line");
    assert!(
        seeded_fork_line.contains(&format!("branch={expected_checkpoint}")),
        "seeded fork must preserve the requested savepoint prefix"
    );
    assert!(seeded_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-artifact\t")
            && line.contains(&format!("seed={}", format_seed(inherited_seed)))
            && line.contains(&format!("fork_seed={}", format_seed(7)))
    }));
    assert!(seeded_outcome.canonical_log.iter().any(|entry| {
        entry.kind == "fork_reproduction_artifact"
            && entry
                .summary
                .contains(&format!("seed={}", format_seed(inherited_seed)))
            && entry
                .summary
                .contains(&format!("fork_seed={}", format_seed(7)))
    }));
    assert_fork_artifact_replays(&seed_cli, &seeded_outcome, inherited_seed)?;

    let seed_again_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("8"),
        String::from("fork"),
        handle_path.display().to_string(),
    ]);
    let Commands::Fork(args) = &seed_again_cli.command else {
        panic!("expected fork command");
    };
    let seed_again_plan =
        plan_fork_invocation(args, Some(8), &seed_again_cli.artifact_dir, &store_root)?;
    let backend_plan =
        plan_backend_selection(&seed_again_cli)?.expect("fork should route to backend");
    let seed_again_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&seed_again_cli),
        &backend_plan,
        None,
        &seed_again_plan,
    )?;
    assert_eq!(seed_again_outcome.status, BackendCommandStatus::Passed);
    assert_ne!(
        seeded_outcome.terminal_savepoint,
        seed_again_outcome.terminal_savepoint
    );

    let seed_virtual_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("7"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("child-seed-virtual"),
    ]);
    let Commands::Fork(args) = &seed_virtual_cli.command else {
        panic!("expected fork command");
    };
    let seed_virtual_plan =
        plan_fork_invocation(args, Some(7), &seed_virtual_cli.artifact_dir, &store_root)?;
    let backend_plan =
        plan_backend_selection(&seed_virtual_cli)?.expect("fork should route to backend");
    let seed_virtual_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&seed_virtual_cli),
        &backend_plan,
        None,
        &seed_virtual_plan,
    )?;
    assert_eq!(seed_virtual_outcome.status, BackendCommandStatus::Passed);
    assert!(seed_virtual_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains("label=child-seed-virtual")
            && line.contains(&format!("fork_seed={}", format_seed(7)))
            && line.contains("final=virtual-time")
            && line.contains("frontier_ticks=2")
            && line.contains("quanta=1")
    }));
    assert_fork_artifact_replays(&seed_virtual_cli, &seed_virtual_outcome, inherited_seed)?;

    let override_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--override"),
        String::from("decision=value"),
    ]);
    let expected_override_branch = crucible::try_step(
        &configuration,
        crucible::Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: String::from("decision"),
            },
            choice: ChoiceTag {
                name: String::from("value"),
            },
        }),
    )?;
    let expected_override_branch_ref = format_content_hash_ref(expected_override_branch.id());
    let Commands::Fork(args) = &override_cli.command else {
        panic!("expected fork command");
    };
    let override_plan = plan_fork_invocation(args, None, &override_cli.artifact_dir, &store_root)?;
    let backend_plan =
        plan_backend_selection(&override_cli)?.expect("fork should route to backend");
    let override_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&override_cli),
        &backend_plan,
        None,
        &override_plan,
    )?;
    assert_eq!(override_outcome.status, BackendCommandStatus::Passed);
    assert!(override_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains(&format!("branch={expected_override_branch_ref}"))
            && line.contains(&format!("configuration={expected_override_branch_ref}"))
    }));
    assert!(override_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-artifact\t") && line.contains("model_artifact=blake3:")
    }));
    assert_fork_artifact_replays(&override_cli, &override_outcome, inherited_seed)?;

    let override_virtual_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--override"),
        String::from("decision=value"),
        String::from("--until"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
        String::from("--label"),
        String::from("child-override-virtual"),
    ]);
    let Commands::Fork(args) = &override_virtual_cli.command else {
        panic!("expected fork command");
    };
    let override_virtual_plan =
        plan_fork_invocation(args, None, &override_virtual_cli.artifact_dir, &store_root)?;
    let backend_plan =
        plan_backend_selection(&override_virtual_cli)?.expect("fork should route to backend");
    let override_virtual_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&override_virtual_cli),
        &backend_plan,
        None,
        &override_virtual_plan,
    )?;
    assert_eq!(
        override_virtual_outcome.status,
        BackendCommandStatus::Passed
    );
    assert!(override_virtual_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains(&format!("branch={expected_override_branch_ref}"))
            && line.contains("final=virtual-time")
            && line.contains("frontier_ticks=2")
            && line.contains("quanta=0")
    }));

    let override_stopped_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--override"),
        String::from("decision=value"),
        String::from("--until"),
        String::from("stopped"),
        String::from("--label"),
        String::from("child-override-stopped"),
    ]);
    let Commands::Fork(args) = &override_stopped_cli.command else {
        panic!("expected fork command");
    };
    let override_stopped_plan =
        plan_fork_invocation(args, None, &override_stopped_cli.artifact_dir, &store_root)?;
    let backend_plan =
        plan_backend_selection(&override_stopped_cli)?.expect("fork should route to backend");
    let override_stopped_outcome = run_local_double_fork_workflow(
        &plan_cli_invocation(&override_stopped_cli),
        &backend_plan,
        None,
        &override_stopped_plan,
    )?;
    assert_eq!(
        override_stopped_outcome.status,
        BackendCommandStatus::Passed
    );
    assert!(override_stopped_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains(&format!("branch={expected_override_branch_ref}"))
            && line.contains("final=stopped")
            && line.contains("frontier_ticks=2")
            && line.contains("quanta=0")
    }));

    let override_interactive_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--override"),
        String::from("decision=value"),
        String::from("--interactive"),
        String::from("--watch"),
        String::from("--label"),
        String::from("child-override-interactive"),
    ]);
    let Commands::Fork(args) = &override_interactive_cli.command else {
        panic!("expected fork command");
    };
    let override_interactive_plan = plan_fork_invocation(
        args,
        None,
        &override_interactive_cli.artifact_dir,
        &store_root,
    )?;
    let backend_plan =
        plan_backend_selection(&override_interactive_cli)?.expect("fork should route to backend");
    let override_interactive_outcome = run_local_double_fork_workflow_with_interactive_commands(
        &plan_cli_invocation(&override_interactive_cli),
        &backend_plan,
        None,
        &override_interactive_plan,
        &[],
    )?;
    assert_eq!(
        override_interactive_outcome.status,
        BackendCommandStatus::Passed
    );
    assert!(override_interactive_outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains(&format!("branch={expected_override_branch_ref}"))
            && line.contains("final=interactive")
            && line.contains("frontier_ticks=2")
            && line.contains("quanta=0")
    }));
    assert!(
        override_interactive_outcome
            .stdout
            .iter()
            .any(|line| { line.starts_with("run-watch\t") && line.contains("frontier_ticks=2") })
    );

    Ok(())
}

#[test]
fn cli_fork_workflow_executes_local_qemu_handle_with_identity() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("qemu-fork-artifacts");
    let store_root = temp.path().join("store");
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let inherited_seed = seed_to_u64(form.seed());
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
    let fork_plan = plan_fork_invocation(args, None, &cli.artifact_dir, &store_root)?;
    let backend_plan = plan_backend_selection(&cli)?.expect("fork should route to backend");
    assert!(matches!(
        backend_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    ));
    let outcome =
        run_local_qemu_fork_workflow(&plan_cli_invocation(&cli), &backend_plan, None, &fork_plan)?;

    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.terminal_savepoint.is_some());
    assert!(outcome.savepoint_oracle.is_some());
    assert!(outcome.stdout.iter().any(|line| {
        line.starts_with("fork-session\t")
            && line.contains("label=qemu-child")
            && line.contains("final=virtual-time")
            && line.contains("frontier_ticks=2")
    }));
    let expected_qemu_build_id = content_address_bytes(b"test-qemu-build-v1");
    let expected_plugin_abi = required_qemu_plugin_abi();
    let expected_shmem_abi = crucible::SHMEM_ABI_VERSION.to_string();
    assert!(outcome.stdout.iter().any(|line| {
        line == &format!(
            "fork-qemu-runner\tmaterialization=child-session-savepoint\tqemu_build_id={expected_qemu_build_id}\tqemu_patch_series=sha256-test-qemu-patch-series\tplugin_abi={expected_plugin_abi}\tshmem_abi={expected_shmem_abi}"
        )
    }));
    assert!(
        outcome
            .canonical_log
            .iter()
            .any(|entry| entry.kind == "fork_qemu_runner")
    );
    assert_fork_artifact_replays(&cli, &outcome, inherited_seed)?;

    let dispatch_artifact_dir = temp.path().join("qemu-fork-dispatch-artifacts");
    let dispatch_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--artifact-dir"),
        dispatch_artifact_dir.display().to_string(),
        String::from("--backend"),
        String::from("qemu"),
        String::from("--qemu"),
        qemu,
        String::from("--plugin"),
        plugin,
        String::from("fork"),
        handle_path.display().to_string(),
        String::from("--label"),
        String::from("qemu-dispatch-child"),
    ]);
    dispatch(&dispatch_cli)?;
    assert!(fs::read_dir(&dispatch_artifact_dir)?.next().is_some());

    Ok(())
}

#[test]
fn cli_fork_workflow_rejects_tampered_handle_frontier() -> Result<(), Box<dyn Error>> {
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
        "fork-source",
        &form,
        &schedule,
        configuration.id(),
        1,
        &content_address_bytes(b"fork-log"),
    )?;
    let tampered_path = temp.path().join("bad-fork-frontier.crucible-savepoint");
    fs::write(
        &tampered_path,
        fs::read_to_string(&handle_path)?.replace("frontier\t1\n", "frontier\t8\n"),
    )?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("fork"),
        tampered_path.display().to_string(),
    ]);
    let error = match dispatch(&cli) {
        Ok(_) => panic!("fork must reject a tampered savepoint frontier"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Identity(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("schedule-derived frontier"));

    Ok(())
}
