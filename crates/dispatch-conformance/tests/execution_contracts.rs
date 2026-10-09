//! Supervision of the real trusted runner with deliberately faulty native peers.

#![allow(clippy::expect_used)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use dispatch_model::{Assignment, Binding, Problem};
use dispatch_runtime::{
    CandidateClass, CloseMode, ExecutionProfile, JobStatus, RuntimeError, Session, SessionBuilder,
    SessionLimits, SolveOptions, SolveResult, Termination,
    providers::{SubprocessProvider, WorkerLaunch},
};

#[path = "support/models.rs"]
#[allow(dead_code)] // Shared fixtures expose helpers used by other test targets.
mod models;

fn runner() -> PathBuf {
    let path = match std::env::var_os("DISPATCH_TEST_WORKER") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()
            .expect("test executable path")
            .parent()
            .expect("test deps directory")
            .parent()
            .expect("target profile directory")
            .join("dispatch-worker"),
    };
    assert!(
        path.is_file(),
        "build the real dispatch-worker or set DISPATCH_TEST_WORKER: {}",
        path.display()
    );
    path
}

async fn session(mode: &str, limits: SessionLimits) -> Session {
    session_with_arguments(vec![mode.into()], limits).await
}

async fn session_with_arguments(arguments: Vec<String>, limits: SessionLimits) -> Session {
    let launch = WorkerLaunch {
        runner: runner(),
        native_backend: PathBuf::from(env!("CARGO_BIN_EXE_dispatch-test-backend")),
        native_arguments: arguments,
        session_generation: 0,
        worker_generation: 0,
        max_frame_bytes: limits.max_frame_bytes,
    };
    SessionBuilder::new(Arc::new(SubprocessProvider::new()), launch)
        .limits(limits)
        .profile(ExecutionProfile::Warm)
        .expected_backend_build("conformance-fixture-v1")
        .start()
        .await
        .expect("authorized fixture session")
}

fn options(deadline: Duration) -> SolveOptions {
    SolveOptions {
        deadline,
        ..SolveOptions::default()
    }
}

async fn wait_running(job: &dispatch_runtime::Job) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while job.status() == JobStatus::Queued {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("worker startup bounded");
    assert_eq!(job.status(), JobStatus::Running);
}

async fn wait_native_solve(path: &std::path::Path, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if std::fs::read_to_string(path).is_ok_and(|trace| trace.lines().count() >= count) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("native actually entered fixture solve");
}

fn assert_validated_binding(result: &SolveResult, problem: &Problem, deadline: Duration) {
    let validated = dispatch_model::validate(problem.clone()).expect("valid submitted model");
    let model_digest =
        dispatch_protocol::canonical::model_digest(&validated).expect("model commitment");
    let requested = dispatch_protocol::wire::SolveOptions {
        mode: dispatch_protocol::wire::SearchMode::LocalSearch as i32,
        wall_time_millis: u64::try_from(deadline.as_millis()).expect("fixture deadline"),
        threads: 1,
        ..Default::default()
    };
    let request_digest = dispatch_protocol::canonical::request_digest_for_backend(
        &validated,
        "conformance-fixture",
        &requested,
        None,
    )
    .expect("independent original-request commitment");

    assert_eq!(
        result.model_digest.as_deref(),
        Some(model_digest.as_slice())
    );
    assert_eq!(
        result.request_digest.as_deref(),
        Some(request_digest.as_slice())
    );
    assert_eq!(
        result.observation_basis.as_ref(),
        Some(&problem.observation_basis)
    );
    assert_eq!(
        result.backend_build_id.as_deref(),
        Some("conformance-fixture-v1")
    );
    assert!(result.worker_generation.is_some());
    assert_eq!(
        result
            .requested_options
            .as_ref()
            .map(|options| options.wall_time_millis),
        Some(requested.wall_time_millis),
    );
    for field in ["model_digest", "request_digest", "observation_basis"] {
        assert!(
            !result.provenance_unavailable.contains_key(field),
            "established {field} must survive a native failure: {result:?}",
        );
    }
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn runner_rejects_native_feasibility_claims_and_preserves_snapshot_commitments() {
    let session = session("invalid", SessionLimits::default()).await;
    let problem = models::problem(&[[1, 2]], &[false], &[None], &[0]);
    let validated = dispatch_model::validate(problem.clone()).expect("valid fixture");
    let digest = dispatch_protocol::canonical::model_digest(&validated).expect("model commitment");
    let job = session
        .submit(problem, options(Duration::from_secs(3)))
        .expect("accepted job");
    let result = job.wait().await.expect("terminal record");

    assert_eq!(result.termination, Termination::Completed);
    assert_eq!(result.candidate, CandidateClass::Rejected);
    assert_eq!(result.model_digest.as_deref(), Some(digest.as_slice()));
    assert!(
        result
            .evaluation
            .as_ref()
            .is_some_and(|evaluation| !evaluation.violations.is_empty())
    );
    assert_eq!(
        session
            .close(CloseMode::Drain, Duration::from_secs(2))
            .await
            .expect("close")
            .unconfirmed,
        0
    );
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn structurally_valid_unsupported_model_version_has_a_typed_capability_rejection() {
    let session = session("valid", SessionLimits::default()).await;
    let mut problem = models::problem(&[[1, 1]], &[false], &[None], &[0]);
    problem.model_version = 2;
    let job = session
        .submit(problem, options(Duration::from_secs(3)))
        .expect("accepted unsupported-version input");
    let result = job.wait().await.expect("typed version rejection");

    assert_eq!(result.termination, Termination::Rejected);
    assert_eq!(
        result.rejection,
        Some(dispatch_runtime::RejectionReason::UnsupportedModel)
    );
    assert_eq!(result.candidate, CandidateClass::Absent);
    assert!(
        result.model_digest.is_none(),
        "unsupported input has no validated semantic commitment"
    );
    assert!(result.assignment.is_none());
    session
        .close(CloseMode::Drain, Duration::from_secs(2))
        .await
        .expect("unsupported-version cleanup");
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn crash_corrupt_frames_and_wrong_generations_are_execution_failures() {
    for mode in [
        "crash",
        "oversized",
        "truncated",
        "wrong_generation",
        "wrong_model_digest",
        "wrong_request_digest",
        "forged_validation_binding",
    ] {
        let session = session(mode, SessionLimits::default()).await;
        let problem = models::problem(&[[1, 1]], &[false], &[None], &[0]);
        let deadline = Duration::from_secs(3);
        let job = session
            .submit(problem.clone(), options(deadline))
            .expect("accepted job");
        let result = tokio::time::timeout(Duration::from_secs(5), job.wait())
            .await
            .expect("fault terminal bound")
            .expect("terminal record");
        assert_eq!(
            result.termination,
            Termination::ExecutionFailed,
            "mode {mode}: {result:?}"
        );
        assert_eq!(result.candidate, CandidateClass::Absent, "mode {mode}");
        assert!(result.assignment.is_none(), "mode {mode}");
        assert_validated_binding(&result, &problem, deadline);
        if matches!(
            mode,
            "wrong_model_digest" | "wrong_request_digest" | "forged_validation_binding"
        ) {
            assert!(
                result.detail.contains("commitment"),
                "mode {mode}: {result:?}"
            );
        }
        let report = session
            .close(CloseMode::Cancel, Duration::from_secs(2))
            .await
            .expect("close");
        assert_eq!(report.unconfirmed, 0);
        assert_eq!(report.workers_unconfirmed, 0);
    }
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn deadlines_and_cancellation_terminate_uncooperative_native_work() {
    let directory = tempfile::tempdir().expect("private trace directory");
    let starts = directory.path().join("starts");
    let solves = directory.path().join("solves");
    let session = session_with_arguments(
        vec![
            "stall".into(),
            starts.to_string_lossy().into_owned(),
            solves.to_string_lossy().into_owned(),
        ],
        SessionLimits::default(),
    )
    .await;
    let problem = models::problem(&[[1, 1]], &[false], &[None], &[0]);
    let timed_deadline = Duration::from_millis(750);
    let timed = session
        .submit(problem.clone(), options(timed_deadline))
        .expect("timed job");
    wait_native_solve(&solves, 1).await;
    let result = tokio::time::timeout(Duration::from_secs(3), timed.wait())
        .await
        .expect("hard deadline bound")
        .expect("terminal deadline");
    assert_eq!(result.termination, Termination::LimitReached);
    assert_validated_binding(&result, &problem, timed_deadline);

    let cancel_deadline = Duration::from_secs(10);
    let cancelled = session
        .submit(problem.clone(), options(cancel_deadline))
        .expect("cancelled job");
    wait_running(&cancelled).await;
    wait_native_solve(&solves, 2).await;
    assert!(cancelled.cancel());
    let result = tokio::time::timeout(Duration::from_secs(3), cancelled.wait())
        .await
        .expect("hard cancellation bound")
        .expect("terminal cancellation");
    assert_eq!(result.termination, Termination::Cancelled);
    assert_validated_binding(&result, &problem, cancel_deadline);
    assert!(!cancelled.cancel());
    let report = session
        .close(CloseMode::Cancel, Duration::from_secs(2))
        .await
        .expect("close");
    assert_eq!(report.unconfirmed, 0);
    assert_eq!(report.workers_unconfirmed, 0);
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn bounded_queue_uses_submission_deadlines_and_close_applies_to_clones() {
    let limits = SessionLimits {
        max_pending: 1,
        ..SessionLimits::default()
    };
    let session = session("stall", limits).await;
    let clone = session.clone();
    let problem = models::problem(&[[1, 1]], &[false], &[None], &[0]);
    let active = session
        .submit(problem.clone(), options(Duration::from_secs(10)))
        .expect("active job");
    wait_running(&active).await;
    let queued = session
        .submit(problem.clone(), options(Duration::from_millis(100)))
        .expect("one queued job");
    assert!(matches!(
        session.submit(problem.clone(), options(Duration::from_secs(1))),
        Err(RuntimeError::Overloaded(_))
    ));
    let result = tokio::time::timeout(Duration::from_secs(2), queued.wait())
        .await
        .expect("queue deadline bound")
        .expect("queue terminal");
    assert_eq!(result.termination, Termination::LimitReached);

    let report = clone
        .close(CloseMode::Cancel, Duration::from_secs(2))
        .await
        .expect("clone closes shared session");
    assert_eq!(report.unconfirmed, 0);
    assert_eq!(
        active.wait().await.expect("active terminal").termination,
        Termination::Cancelled
    );
    assert!(matches!(
        session.submit(problem, options(Duration::from_secs(1))),
        Err(RuntimeError::Closed)
    ));
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn warm_worker_solves_use_independent_immutable_inputs_and_hint_does_not_change_baseline() {
    let directory = tempfile::tempdir().expect("private fixture directory");
    let trace = directory.path().join("native-starts");
    let session = session_with_arguments(
        vec!["valid".into(), trace.to_string_lossy().into_owned()],
        SessionLimits::default(),
    )
    .await;
    let first = models::problem(&[[1, 2]], &[false], &[None], &[0]);
    let second = models::problem(&[[3, 4]], &[false], &[Some(1)], &[4]);
    for problem in [first, second] {
        let validated = dispatch_model::validate(problem.clone()).expect("valid fixture");
        let digest = dispatch_protocol::canonical::model_digest(&validated).expect("model digest");
        let hint = Assignment {
            bindings: [(
                models::item(0),
                Binding::Target {
                    target: models::target(1),
                },
            )]
            .into(),
        };
        let options = SolveOptions {
            hint: Some(hint),
            ..options(Duration::from_secs(3))
        };
        let job = session
            .submit(problem, options)
            .expect("accepted warm solve");
        let result = job.wait().await.expect("terminal result");
        assert_eq!(result.termination, Termination::Completed, "{result:?}");
        assert_eq!(result.candidate, CandidateClass::FullyFeasible);
        assert_eq!(result.model_digest.as_deref(), Some(digest.as_slice()));
        assert!(
            result
                .request_digest
                .as_ref()
                .is_some_and(|digest| digest.len() == 32)
        );
        assert!(
            dispatch_model::verify(
                &validated,
                result.assignment.clone().expect("verified assignment")
            )
            .is_ok()
        );
    }
    assert_eq!(
        std::fs::read_to_string(trace)
            .expect("native startup trace")
            .lines()
            .count(),
        1
    );
    let report = session
        .close(CloseMode::Drain, Duration::from_secs(2))
        .await
        .expect("warm cleanup");
    assert_eq!(report.workers_unconfirmed, 0);
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn prepared_input_survives_worker_retirement_and_release_preserves_accepted_jobs() {
    let limits = SessionLimits {
        max_prepared: 1,
        ..SessionLimits::default()
    };
    let session = session("stall", limits).await;
    let problem = models::problem(&[[1, 1]], &[false], &[None], &[0]);
    let handle = session
        .prepare(problem.clone())
        .await
        .expect("validated retained input");
    assert!(matches!(
        session.prepare(problem).await,
        Err(RuntimeError::Overloaded(_))
    ));
    let first = session
        .submit_prepared(&handle, options(Duration::from_secs(10)))
        .expect("prepared solve");
    wait_running(&first).await;
    assert!(first.cancel());
    assert_eq!(
        first
            .wait()
            .await
            .expect("retired worker result")
            .termination,
        Termination::Cancelled
    );

    let second = session
        .submit_prepared(&handle, options(Duration::from_millis(150)))
        .expect("session input survives native retirement");
    session.release(&handle).expect("release caller handle");
    assert!(matches!(
        session.submit_prepared(&handle, options(Duration::from_secs(1))),
        Err(RuntimeError::StaleHandle)
    ));
    let result = tokio::time::timeout(Duration::from_secs(3), second.wait())
        .await
        .expect("accepted input retained")
        .expect("terminal result");
    assert_eq!(result.termination, Termination::LimitReached);
    let report = session
        .close(CloseMode::Cancel, Duration::from_secs(2))
        .await
        .expect("close");
    assert_eq!(report.unconfirmed, 0);
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn prepared_handles_are_scoped_to_sessions_and_invalid_preparation_releases_its_reservation()
{
    let limits = SessionLimits {
        max_prepared: 1,
        ..SessionLimits::default()
    };
    let first = session("valid", limits.clone()).await;
    let second = session("valid", limits).await;
    let mut malformed = models::problem(&[[1, 1]], &[false], &[None], &[0]);
    malformed.observed.clear();
    assert!(first.prepare(malformed).await.is_err());
    let handle = first
        .prepare(models::problem(&[[1, 1]], &[false], &[None], &[0]))
        .await
        .expect("failed preparation returned storage reservation");
    assert!(matches!(
        second.submit_prepared(&handle, options(Duration::from_secs(1))),
        Err(RuntimeError::StaleHandle)
    ));
    assert!(matches!(
        second.release(&handle),
        Err(RuntimeError::StaleHandle)
    ));
    first.release(&handle).expect("owner release");
    first
        .close(CloseMode::Drain, Duration::from_secs(2))
        .await
        .expect("first cleanup");
    second
        .close(CloseMode::Drain, Duration::from_secs(2))
        .await
        .expect("second cleanup");
}
