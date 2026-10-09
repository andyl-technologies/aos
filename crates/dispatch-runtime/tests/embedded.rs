//! Embedded provider contracts exercised only through the public session API.

#![allow(clippy::expect_used)]

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use dispatch_model::{Assignment, Problem, ValidatedProblem};
use dispatch_protocol::{canonical::model_digest, wire};
use dispatch_runtime::{
    CandidateClass, CloseMode, CooperativeCancellation, EmbeddedBackend, EmbeddedProvider,
    EmbeddedSolution, ExecutionGuarantee, RejectionReason, RequiredGuarantees, RuntimeError,
    Session, SessionBuilder, SessionLimits, SolveOptions, Termination, WorkerLaunch,
};

struct Engine {
    reject: bool,
}

#[async_trait]
impl EmbeddedBackend for Engine {
    fn capabilities(&self) -> wire::Capabilities {
        wire::Capabilities {
            backend_name: "fixture".into(),
            backend_build_id: "fixture-1".into(),
            search_modes: vec![wire::SearchMode::LocalSearch as i32],
            limits: Some(wire::WireLimits::standard()),
            ..Default::default()
        }
    }

    async fn solve(
        &self,
        _problem: ValidatedProblem,
        _options: wire::SolveOptions,
        _hint: Option<Assignment>,
        _cancellation: CooperativeCancellation,
    ) -> Result<EmbeddedSolution, RuntimeError> {
        if self.reject {
            return Err(RuntimeError::Unsupported(
                "fixture compiler restriction".into(),
            ));
        }

        Ok(EmbeddedSolution {
            termination: wire::Termination::Completed,
            assignment: Some(Assignment {
                bindings: BTreeMap::new(),
            }),
            evidence: None,
            detail: String::new(),
        })
    }
}

fn problem() -> Problem {
    Problem {
        model_version: 1,
        observation_basis: BTreeMap::from([("revision".into(), "test-1".into())]),
        ..Default::default()
    }
}

fn builder(reject: bool) -> SessionBuilder {
    let provider = Arc::new(EmbeddedProvider::new(Arc::new(Engine { reject })));
    SessionBuilder::new(
        provider,
        WorkerLaunch {
            runner: PathBuf::new(),
            native_backend: PathBuf::new(),
            native_arguments: Vec::new(),
            session_generation: 0,
            worker_generation: 0,
            max_frame_bytes: 16 * 1024 * 1024,
        },
    )
}

async fn session(reject: bool) -> Session {
    builder(reject)
        .start()
        .await
        .expect("embedded session initializes")
}

#[tokio::test]
async fn invalid_limits_and_unsupported_guarantees_have_distinct_types() {
    let limits = SessionLimits {
        max_workers: 0,
        ..SessionLimits::default()
    };

    let invalid = builder(false).limits(limits).start().await;
    let unsupported = builder(false)
        .required_guarantees(RequiredGuarantees {
            independent_memory: true,
            ..RequiredGuarantees::default()
        })
        .start()
        .await;

    assert!(matches!(
        invalid,
        Err(RuntimeError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        unsupported,
        Err(RuntimeError::UnsupportedGuarantee(
            ExecutionGuarantee::IndependentMemory
        ))
    ));
}

#[tokio::test]
async fn invalid_trusted_metadata_is_configuration_failure() {
    let result = builder(false)
        .trusted_capabilities(wire::Capabilities::default())
        .start()
        .await;

    assert!(matches!(result, Err(RuntimeError::InvalidConfiguration(_))));
}

#[tokio::test]
async fn unsupported_engine_preserves_validated_bindings() {
    let session = session(true).await;
    let input = problem();
    let digest = model_digest(&dispatch_model::validate(input.clone()).expect("valid model"))
        .expect("canonical digest");

    let result = session
        .submit(input, SolveOptions::default())
        .expect("accepted")
        .wait()
        .await
        .expect("terminal record");

    assert_eq!(result.termination, Termination::Rejected);
    assert_eq!(result.rejection, Some(RejectionReason::UnsupportedModel));
    assert_eq!(result.candidate, CandidateClass::Absent);
    assert_eq!(result.model_digest.as_deref(), Some(digest.as_slice()));
    assert!(result.request_digest.is_some());
    assert_eq!(result.backend_build_id.as_deref(), Some("fixture-1"));
    assert_eq!(result.observation_basis, Some(problem().observation_basis));
    assert_eq!(
        session
            .close(CloseMode::Drain, Duration::from_secs(1))
            .await
            .expect("cleanup")
            .workers_unconfirmed,
        0
    );
}

#[tokio::test]
async fn unsupported_model_version_is_a_typed_rejection() {
    let session = session(false).await;
    let mut input = problem();
    input.model_version = 2;

    let result = session
        .submit(input, SolveOptions::default())
        .expect("accepted for validation")
        .wait()
        .await
        .expect("terminal record");

    assert_eq!(result.termination, Termination::Rejected);
    assert_eq!(result.rejection, Some(RejectionReason::UnsupportedModel));
    assert_eq!(result.candidate, CandidateClass::Absent);
    assert!(result.model_digest.is_none());
    session
        .close(CloseMode::Drain, Duration::from_secs(1))
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn preparation_release_retains_only_already_accepted_work() {
    let session = session(false).await;
    let handle = session.prepare(problem()).await.expect("prepared");

    let job = session
        .submit_prepared(&handle, SolveOptions::default())
        .expect("accepted");
    session.release(&handle).expect("released");
    assert!(matches!(
        session.submit_prepared(&handle, SolveOptions::default()),
        Err(RuntimeError::StaleHandle)
    ));
    let result = job.wait().await.expect("terminal record");

    assert_eq!(result.termination, Termination::Completed);
    assert_eq!(result.candidate, CandidateClass::FullyFeasible);
    assert!(result.evaluation.is_some());
    assert_eq!(result.model_digest.as_deref(), Some(handle.model_digest()));
    assert!(!result.grant.hard_cancellation);
    assert!(!result.grant.independent_memory);
    assert_eq!(
        session
            .close(CloseMode::Drain, Duration::from_secs(1))
            .await
            .expect("cleanup")
            .workers_unconfirmed,
        0
    );
}
