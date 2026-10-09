//! Requested time-policy commitments remain distinct from remaining durations.

#![allow(clippy::expect_used)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use dispatch_runtime::{
    CandidateClass, CloseMode, SessionBuilder, SolveOptions, Termination,
    providers::{SubprocessProvider, WorkerLaunch},
};

#[path = "support/models.rs"]
#[allow(dead_code)]
mod models;

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn native_receives_original_time_policy_separately_from_elapsed_transfer_time() {
    let runner = std::env::var_os("DISPATCH_TEST_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .expect("test executable path")
                .parent()
                .expect("deps directory")
                .parent()
                .expect("profile directory")
                .join("dispatch-worker")
        });
    assert!(
        runner.is_file(),
        "build the trusted worker or set DISPATCH_TEST_WORKER"
    );
    let launch = WorkerLaunch {
        runner,
        native_backend: env!("CARGO_BIN_EXE_dispatch-test-backend").into(),
        native_arguments: vec!["budget".into()],
        session_generation: 0,
        worker_generation: 0,
        max_frame_bytes: 16 * 1024 * 1024,
    };
    let session = SessionBuilder::new(Arc::new(SubprocessProvider::new()), launch)
        .start()
        .await
        .expect("real trusted runner");
    let problem = models::problem(&[[1, 2]], &[false], &[None], &[0]);
    let validated = dispatch_model::validate(problem.clone()).expect("valid snapshot");
    let options = dispatch_protocol::wire::SolveOptions {
        mode: dispatch_protocol::wire::SearchMode::LocalSearch as i32,
        wall_time_millis: 3000,
        threads: 1,
        ..Default::default()
    };
    let request_digest = dispatch_protocol::canonical::request_digest_for_backend(
        &validated,
        "conformance-fixture",
        &options,
        None,
    )
    .expect("original request time-policy commitment");
    let job = session
        .submit(
            problem,
            SolveOptions {
                deadline: Duration::from_secs(3),
                ..Default::default()
            },
        )
        .expect("accepted request");
    let result = job.wait().await.expect("terminal result");

    assert_eq!(result.termination, Termination::Completed, "{result:?}");
    assert_eq!(result.candidate, CandidateClass::FullyFeasible);
    assert_eq!(
        result.request_digest.as_deref(),
        Some(request_digest.as_slice())
    );
    session
        .close(CloseMode::Drain, Duration::from_secs(2))
        .await
        .expect("cleanup");
}
