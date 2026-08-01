//! CLI backend selection, evidence, and live-QEMU failure tests.

use super::*;

#[test]
pub(super) fn cli_backend_selection_auto_announces_qemu_or_double_resolution()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let double_cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let double_plan =
        plan_backend_selection(&double_cli)?.expect("run should require backend selection");
    assert_eq!(double_plan.target, BackendExecutionTarget::Local);
    assert_eq!(
        double_plan.resolved_backend,
        Some(ResolvedLocalBackend::Double)
    );
    assert_eq!(
        double_plan.reason,
        BackendSelectionReason::AutoFallbackDouble
    );
    assert!(double_plan.should_announce(false));
    assert!(double_plan.announcement().contains("backend = double"));
    assert!(double_plan.has_consistent_route());
    let mut recorder = RecordingBackendRouteRecorder::default();
    execute_backend_selection_plan(&double_plan, false, &mut recorder)?;
    assert_eq!(recorder.local_backends, vec![ResolvedLocalBackend::Double]);
    assert_eq!(recorder.announcements, vec![double_plan.announcement()]);

    let qemu_cli = Cli::parse_from([
        "crucible",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let qemu_plan =
        plan_backend_selection(&qemu_cli)?.expect("run should require backend selection");
    assert!(matches!(
        qemu_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    ));
    assert_eq!(
        qemu_plan.reason,
        BackendSelectionReason::AutoQemuArtifactsSupplied
    );
    assert!(qemu_plan.announcement().contains("backend = qemu"));
    assert!(qemu_plan.has_consistent_route());

    Ok(())
}

#[test]
pub(super) fn cli_backend_selection_honors_explicit_backend_and_qemu_failure_exit()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    let double_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "double",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let double_plan =
        plan_backend_selection(&double_cli)?.expect("run should require backend selection");
    assert_eq!(double_plan.requested_backend, Backend::Double);
    assert_eq!(
        double_plan.resolved_backend,
        Some(ResolvedLocalBackend::Double)
    );
    assert_eq!(double_plan.reason, BackendSelectionReason::ExplicitDouble);
    assert!(!double_plan.should_announce(false));
    assert!(double_plan.has_consistent_route());

    let missing_qemu = Cli::parse_from(["crucible", "--backend", "qemu", "run", TEST_SCENARIO]);
    let error = match plan_backend_selection(&missing_qemu) {
        Ok(_) => panic!("explicit qemu without artifacts must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("--qemu"));
    assert!(error.to_string().contains("--plugin"));

    let missing_files = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        temp.path()
            .join("missing-qemu")
            .to_str()
            .unwrap_or("missing-qemu"),
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let error = match plan_backend_selection(&missing_files) {
        Ok(_) => panic!("explicit qemu with an unusable artifact must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("cannot read patched QEMU"));

    let directory_artifact = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        temp.path().to_str().unwrap_or("."),
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let error = match plan_backend_selection(&directory_artifact) {
        Ok(_) => panic!("explicit qemu with a directory artifact must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("not a regular file"));

    let auto_with_unusable_artifact = Cli::parse_from([
        "crucible",
        "--qemu",
        temp.path().to_str().unwrap_or("."),
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let error = match plan_backend_selection(&auto_with_unusable_artifact) {
        Ok(_) => panic!("auto with a complete but invalid QEMU candidate pair must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("not a regular file"));

    let qemu_cli = Cli::parse_from([
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
    let qemu_plan =
        plan_backend_selection(&qemu_cli)?.expect("run should require backend selection");
    assert_eq!(qemu_plan.reason, BackendSelectionReason::ExplicitQemu);
    assert!(matches!(
        qemu_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    ));
    assert!(qemu_plan.has_consistent_route());

    Ok(())
}
