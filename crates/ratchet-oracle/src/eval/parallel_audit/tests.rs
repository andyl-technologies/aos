use super::*;

#[test]
fn parallel_runtime_audit_manifest_covers_r4_tool_matrix() {
    let manifest = validate_parallel_runtime_audit_manifest().expect("audit manifest validates");
    let expected_targets = [
        (
            ParallelRuntimeAuditTool::Loom,
            ParallelRuntimeAuditScope::ThunkCasModel,
            "loom_model_tests",
        ),
        (
            ParallelRuntimeAuditTool::Miri,
            ParallelRuntimeAuditScope::SafeTreeWalkOracle,
            "parallel_audit_safe_tree_walk_oracle_miri_smoke",
        ),
        (
            ParallelRuntimeAuditTool::Miri,
            ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
            "parallel_audit_parallel_tree_walk_miri_smoke",
        ),
        (
            ParallelRuntimeAuditTool::ThreadSanitizer,
            ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
            "parallel_audit_parallel_tree_walk_tsan_smoke",
        ),
        (
            ParallelRuntimeAuditTool::ThreadSanitizer,
            ParallelRuntimeAuditScope::ParallelTreeWalkDrvHarness,
            "parallel_audit_parallel_tree_walk_drv_tsan_smoke",
        ),
        (
            ParallelRuntimeAuditTool::ThreadSanitizer,
            ParallelRuntimeAuditScope::ParallelTreeWalkDrvStandardMatrixHarness,
            "parallel_audit_parallel_tree_walk_drv_standard_matrix_tsan_smoke",
        ),
    ];

    assert_eq!(manifest.target_count(), expected_targets.len());
    for (tool, scope, test_filter) in expected_targets {
        let target = manifest
            .target_for(tool, scope)
            .expect("required target is present");
        assert_eq!(target.package(), AUDIT_PACKAGE);
        assert_eq!(target.manifest_path(), AUDIT_MANIFEST_PATH);
        assert_eq!(target.test_filter(), test_filter);
        assert!(!target.rationale().is_empty());
    }
}

#[test]
fn parallel_runtime_audit_invocations_pin_tool_commands() {
    let invocations = parallel_runtime_audit_invocations().expect("audit invocations validate");
    assert_eq!(
        invocations.len(),
        validate_parallel_runtime_audit_manifest()
            .expect("audit manifest validates")
            .target_count()
    );

    let loom = invocation_for(
        &invocations,
        ParallelRuntimeAuditTool::Loom,
        ParallelRuntimeAuditScope::ThunkCasModel,
    );
    assert_eq!(loom.cargo_program(), "cargo");
    assert_eq!(
        loom.cargo_args(),
        &[
            "test",
            "--manifest-path",
            AUDIT_MANIFEST_PATH,
            "-p",
            AUDIT_PACKAGE,
            "loom_model_tests",
            "--",
            "--nocapture",
        ]
    );
    assert!(loom.environment().is_empty());
    assert!(!loom.requires_nightly_toolchain());

    let miri = invocation_for(
        &invocations,
        ParallelRuntimeAuditTool::Miri,
        ParallelRuntimeAuditScope::SafeTreeWalkOracle,
    );
    assert_eq!(
        miri.cargo_args(),
        &[
            NIGHTLY_CARGO_ARG,
            "miri",
            "test",
            "--manifest-path",
            AUDIT_MANIFEST_PATH,
            "-p",
            AUDIT_PACKAGE,
            "parallel_audit_safe_tree_walk_oracle_miri_smoke",
            "--",
            "--nocapture",
        ]
    );
    assert!(miri.environment().is_empty());
    assert!(miri.requires_nightly_toolchain());

    let sanitizer_raw = invocation_for(
        &invocations,
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
    );
    assert_eq!(
        sanitizer_raw.cargo_args(),
        &[
            NIGHTLY_CARGO_ARG,
            "test",
            "-Z",
            "build-std",
            "--target",
            TSAN_TARGET,
            "--manifest-path",
            AUDIT_MANIFEST_PATH,
            "-p",
            AUDIT_PACKAGE,
            "parallel_audit_parallel_tree_walk_tsan_smoke",
            "--",
            "--nocapture",
        ]
    );
    assert_eq!(
        sanitizer_raw.environment(),
        &[(RUSTFLAGS_ENV, TSAN_RUSTFLAGS)]
    );
    assert!(sanitizer_raw.requires_nightly_toolchain());

    let sanitizer_drv = invocation_for(
        &invocations,
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvHarness,
    );
    assert_eq!(
        sanitizer_drv.cargo_args(),
        &[
            NIGHTLY_CARGO_ARG,
            "test",
            "-Z",
            "build-std",
            "--target",
            TSAN_TARGET,
            "--manifest-path",
            AUDIT_MANIFEST_PATH,
            "-p",
            AUDIT_PACKAGE,
            "parallel_audit_parallel_tree_walk_drv_tsan_smoke",
            "--",
            "--nocapture",
        ]
    );
    assert_eq!(
        sanitizer_drv.environment(),
        &[(RUSTFLAGS_ENV, TSAN_RUSTFLAGS)]
    );
    assert!(sanitizer_drv.requires_nightly_toolchain());

    let sanitizer_drv_standard_matrix = invocation_for(
        &invocations,
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvStandardMatrixHarness,
    );
    assert_eq!(
        sanitizer_drv_standard_matrix.cargo_args(),
        &[
            NIGHTLY_CARGO_ARG,
            "test",
            "-Z",
            "build-std",
            "--target",
            TSAN_TARGET,
            "--manifest-path",
            AUDIT_MANIFEST_PATH,
            "-p",
            AUDIT_PACKAGE,
            "parallel_audit_parallel_tree_walk_drv_standard_matrix_tsan_smoke",
            "--",
            "--nocapture",
        ]
    );
    assert_eq!(
        sanitizer_drv_standard_matrix.environment(),
        &[(RUSTFLAGS_ENV, TSAN_RUSTFLAGS)]
    );
    assert!(sanitizer_drv_standard_matrix.requires_nightly_toolchain());
}

fn invocation_for(
    invocations: &[ParallelRuntimeAuditInvocation],
    tool: ParallelRuntimeAuditTool,
    scope: ParallelRuntimeAuditScope,
) -> &ParallelRuntimeAuditInvocation {
    invocations
        .iter()
        .find(|invocation| {
            invocation.target().tool() == tool && invocation.target().scope() == scope
        })
        .expect("audit invocation is present")
}

#[test]
fn parallel_audit_safe_tree_walk_oracle_miri_smoke() {
    let report = run_parallel_audit_safe_tree_walk_oracle_smoke()
        .expect("safe tree-walk audit smoke passes");

    assert_eq!(
        report.scope(),
        ParallelRuntimeAuditScope::SafeTreeWalkOracle
    );
    assert_eq!(report.case_count(), SAFE_TREE_WALK_CASES.len());
    assert!(report.worker_counts().is_empty());
}

#[test]
fn parallel_audit_parallel_tree_walk_miri_smoke() {
    let report = run_parallel_audit_parallel_tree_walk_raw_smoke()
        .expect("parallel tree-walk raw audit smoke passes");

    assert_eq!(
        report.scope(),
        ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness
    );
    assert_eq!(report.case_count(), PARALLEL_RAW_CASES.len());
    assert_eq!(report.worker_counts(), &AUDIT_WORKER_COUNTS);
}

#[test]
fn parallel_audit_parallel_tree_walk_tsan_smoke() {
    let report = run_parallel_audit_parallel_tree_walk_raw_smoke()
        .expect("parallel tree-walk raw audit smoke passes");

    assert_eq!(
        report.scope(),
        ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness
    );
    assert_eq!(report.case_count(), PARALLEL_RAW_CASES.len());
    assert_eq!(report.worker_counts(), &AUDIT_WORKER_COUNTS);
}

#[test]
fn parallel_audit_parallel_tree_walk_drv_tsan_smoke() {
    let report = run_parallel_audit_parallel_tree_walk_drv_smoke()
        .expect(".drv tree-walk audit smoke passes");

    assert_eq!(
        report.scope(),
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvHarness
    );
    assert_eq!(report.case_count(), PARALLEL_DRV_CASES.len());
    assert_eq!(report.worker_counts(), &AUDIT_WORKER_COUNTS);
}

#[test]
fn parallel_audit_parallel_tree_walk_drv_standard_matrix_tsan_smoke() {
    let report = run_parallel_audit_parallel_tree_walk_drv_standard_matrix_smoke()
        .expect("standard-matrix .drv tree-walk audit smoke passes");
    let expected_worker_counts = expected_standard_worker_counts_for_test();

    assert_eq!(
        report.scope(),
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvStandardMatrixHarness
    );
    assert_eq!(
        report.case_count(),
        PARALLEL_DRV_STANDARD_MATRIX_CASES.len()
    );
    assert_eq!(report.worker_counts(), expected_worker_counts.as_slice());
}

fn expected_standard_worker_counts_for_test() -> Vec<usize> {
    let mut counts = Vec::with_capacity(4);
    push_expected_worker_count(&mut counts, 1);
    push_expected_worker_count(&mut counts, 2);
    push_expected_worker_count(&mut counts, 8);
    match std::thread::available_parallelism() {
        Ok(count) => push_expected_worker_count(&mut counts, count.get()),
        Err(_) => push_expected_worker_count(&mut counts, 4),
    }
    counts
}

fn push_expected_worker_count(counts: &mut Vec<usize>, count: usize) {
    if counts.iter().all(|existing| *existing != count) {
        counts.push(count);
    }
}
