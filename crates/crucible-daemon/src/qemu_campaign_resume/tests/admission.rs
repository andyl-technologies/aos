//! Exact-resume admission rejection tests.

use super::*;

#[test]
fn resume_runner_rejects_missing_root_before_factory_invocation() {
    let calls = Arc::new(ResumeCalls::default());
    let observed = Arc::new(Mutex::new(None));
    let mut runner = resume_runner(
        Arc::clone(&calls),
        Arc::clone(&observed),
        ProductionVmLifecycleResumeState::new(
            test_configuration(),
            Vec::new(),
            0,
            0,
            VirtualTime::default(),
            SchedulerQuiescence::default(),
            None,
        ),
        Vec::new(),
    );

    let error = runner
        .execute(&test_input(), &test_context(None))
        .expect_err("resume-only runner must require an exact root");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::MissingCheckpoint
        )
    ));
    assert_eq!(calls.starts.load(Ordering::SeqCst), 0);
    assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 0);
}
