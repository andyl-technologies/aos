//! End-to-end checks of the source-built native solver and trusted Rust runner.

#![allow(clippy::expect_used)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use dispatch_model::{AccountingPhase, Binding, Constraint, ConstraintRule, Enforcement, Quantity};
use dispatch_runtime::{
    CandidateClass, CloseMode, ExecutionProfile, RejectionReason, SearchMode, Session,
    SessionBuilder, SolveOptions, Termination,
    providers::{SubprocessProvider, WorkerLaunch},
};

#[path = "support/models.rs"]
#[allow(dead_code)] // Shared fixtures expose helpers used by other test targets.
mod models;

async fn native_session() -> Session {
    let backend = PathBuf::from(
        std::env::var_os("DISPATCH_TEST_REBALANCER")
            .expect("set DISPATCH_TEST_REBALANCER to the AOS source-built native executable"),
    );
    assert!(
        backend.is_file(),
        "source-built native executable must exist"
    );
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
        native_backend: backend,
        native_arguments: Vec::new(),
        session_generation: 0,
        worker_generation: 0,
        max_frame_bytes: 16 * 1024 * 1024,
    };
    SessionBuilder::new(Arc::new(SubprocessProvider::new()), launch)
        .profile(ExecutionProfile::Warm)
        .start()
        .await
        .expect("real native capability handshake")
}

#[tokio::test]
#[ignore = "requires the AOS source-built native solver and trusted worker"]
async fn real_native_mip_produces_an_exact_snapshot_bound_capacity_assignment() {
    let session = native_session().await;
    let mut problem = models::problem(&[[3, 3]; 2], &[false; 2], &[None; 2], &[0; 2]);
    problem.constraints = vec![
        models::capacity(
            "left_ceiling",
            "left",
            AccountingPhase::Final,
            3,
            Enforcement::Hard,
        ),
        models::capacity(
            "right_ceiling",
            "right",
            AccountingPhase::Final,
            3,
            Enforcement::Hard,
        ),
    ];
    let validated = dispatch_model::validate(problem.clone()).expect("feasible finite model");
    let digest = dispatch_protocol::canonical::model_digest(&validated).expect("snapshot digest");
    let job = session
        .submit(
            problem,
            SolveOptions {
                deadline: Duration::from_secs(20),
                mode: SearchMode::Mip,
                ..Default::default()
            },
        )
        .expect("real native solve");
    let result = tokio::time::timeout(Duration::from_secs(25), job.wait())
        .await
        .expect("native solve wall bound")
        .expect("native terminal record");

    assert_eq!(result.termination, Termination::Completed, "{result:?}");
    assert_eq!(
        result.candidate,
        CandidateClass::FullyFeasible,
        "{result:?}"
    );
    assert_eq!(result.model_digest.as_deref(), Some(digest.as_slice()));
    assert!(
        result
            .request_digest
            .as_ref()
            .is_some_and(|digest| digest.len() == 32)
    );
    assert!(
        result
            .backend_build_id
            .as_ref()
            .is_some_and(|build| !build.is_empty())
    );
    let verified = dispatch_model::verify(
        &validated,
        result
            .assignment
            .clone()
            .expect("native verified placement"),
    )
    .expect("public independent recheck");
    let occupied: std::collections::BTreeSet<_> = verified
        .assignment()
        .bindings
        .values()
        .filter_map(|binding| match binding {
            dispatch_model::Binding::Target { target } => Some(target),
            dispatch_model::Binding::Deferred => None,
        })
        .collect();
    assert_eq!(occupied.len(), 2, "each target can hold exactly one item");
    let report = session
        .close(CloseMode::Drain, Duration::from_secs(3))
        .await
        .expect("native cleanup");
    assert_eq!(report.workers_unconfirmed, 0);
}

#[tokio::test]
#[ignore = "requires the AOS source-built native solver and trusted worker"]
async fn native_integer_limit_rejects_exact_input_without_rounding_or_infeasibility_claim() {
    let session = native_session().await;
    let wide = 9_007_199_254_740_992_u64;
    let mut problem = models::problem(&[[wide, wide]], &[false], &[None], &[0]);
    problem.constraints.push(models::capacity(
        "finite_limit",
        "fleet",
        AccountingPhase::Final,
        100,
        Enforcement::Hard,
    ));
    let validated = dispatch_model::validate(problem.clone()).expect("valid exact wide input");
    let digest = dispatch_protocol::canonical::model_digest(&validated)
        .expect("validated wide input commitment");
    let job = session
        .submit(
            problem,
            SolveOptions {
                deadline: Duration::from_secs(3),
                ..Default::default()
            },
        )
        .expect("exact wide input accepted for execution");
    let result = job
        .wait()
        .await
        .expect("unsupported numeric domain terminal");

    assert_eq!(result.termination, Termination::Rejected, "{result:?}");
    assert_eq!(result.rejection, Some(RejectionReason::UnsupportedModel));
    assert_eq!(result.candidate, CandidateClass::Absent);
    assert!(result.assignment.is_none());
    assert_eq!(
        result.model_digest.as_deref(),
        Some(digest.as_slice()),
        "validated input retains provenance when native compilation rejects its numeric domain"
    );
    session
        .close(CloseMode::Drain, Duration::from_secs(3))
        .await
        .expect("native cleanup");
}

#[tokio::test]
#[ignore = "requires the AOS source-built native solver and trusted worker"]
async fn real_native_combines_gang_admission_colocation_spread_and_pinned_placement() {
    let session = native_session().await;
    let mut problem = models::problem(&[[1, 1]; 3], &[true, true, false], &[None; 3], &[0; 3]);
    problem
        .groups
        .insert("gang".into(), vec![models::item(0), models::item(1)]);
    problem.constraints = vec![
        Constraint {
            id: "admit_all".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::Admission {
                group: "all".into(),
                minimum: Quantity::new(3),
                maximum: Quantity::new(3),
            },
        },
        Constraint {
            id: "atomic_pair".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::AtomicAdmission {
                group: "gang".into(),
            },
        },
        Constraint {
            id: "same_host".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::CoLocation {
                group: "gang".into(),
                family: "host".into(),
            },
        },
        Constraint {
            id: "two_hosts".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::Spread {
                group: "all".into(),
                family: "host".into(),
                minimum: Quantity::new(2),
                maximum_per_member: Some(Quantity::new(2)),
                when_admitted: false,
            },
        },
        Constraint {
            id: "pin_first".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::FixedPlacement {
                bindings: [(
                    models::item(0),
                    Binding::Target {
                        target: models::target(0),
                    },
                )]
                .into(),
            },
        },
    ];
    let validated = dispatch_model::validate(problem.clone()).expect("combined finite obligations");
    let job = session
        .submit(
            problem,
            SolveOptions {
                mode: SearchMode::Mip,
                deadline: Duration::from_secs(20),
                ..Default::default()
            },
        )
        .expect("combined native solve");
    let result = tokio::time::timeout(Duration::from_secs(25), job.wait())
        .await
        .expect("bounded combined solve")
        .expect("combined native terminal");
    assert_eq!(
        result.candidate,
        CandidateClass::FullyFeasible,
        "{result:?}"
    );
    let assignment = result
        .assignment
        .clone()
        .expect("complete native assignment");
    assert_eq!(assignment, models::assignment(&[1, 1, 2]));
    dispatch_model::verify(&validated, assignment).expect("independent combined-obligation check");
    session
        .close(CloseMode::Drain, Duration::from_secs(3))
        .await
        .expect("combined native cleanup");
}

#[tokio::test]
#[ignore = "requires the AOS source-built native solver and trusted worker"]
async fn real_native_respects_admission_before_assignment_cost_in_lexicographic_tiers() {
    let session = native_session().await;
    let mut problem = models::problem(&[[1, 1]], &[true], &[None], &[0]);
    problem.objectives = vec![
        dispatch_model::ObjectiveTier {
            id: "admit".into(),
            terms: vec![dispatch_model::ObjectiveTerm {
                id: "admit".into(),
                direction: dispatch_model::Direction::Maximize,
                weight: models::rational(1, 1),
                normalizer: models::rational(1, 1),
                metric: dispatch_model::Metric::AdmittedCount {
                    items: vec![models::item(0)],
                },
            }],
        },
        dispatch_model::ObjectiveTier {
            id: "cost".into(),
            terms: vec![dispatch_model::ObjectiveTerm {
                id: "cost".into(),
                direction: dispatch_model::Direction::Minimize,
                weight: models::rational(1, 1),
                normalizer: models::rational(1, 1),
                metric: dispatch_model::Metric::AssignmentCost {
                    costs: [(
                        models::item(0),
                        dispatch_model::AssignmentCosts {
                            default: None,
                            targets: [
                                (models::target(0), models::rational(100, 1)),
                                (models::target(1), models::rational(0, 1)),
                            ]
                            .into(),
                            deferred: models::rational(0, 1),
                        },
                    )]
                    .into(),
                },
            }],
        },
    ];
    let job = session
        .submit(
            problem,
            SolveOptions {
                mode: SearchMode::Mip,
                deadline: Duration::from_secs(20),
                ..Default::default()
            },
        )
        .expect("lexicographic native solve");
    let result = tokio::time::timeout(Duration::from_secs(25), job.wait())
        .await
        .expect("bounded lexicographic solve")
        .expect("native result");
    assert_eq!(
        result.candidate,
        CandidateClass::FullyFeasible,
        "{result:?}"
    );
    assert_eq!(
        result.assignment,
        Some(models::assignment(&[2])),
        "admission first, then the cheaper destination"
    );
    assert_eq!(
        result
            .evaluation
            .as_ref()
            .expect("exact objective report")
            .objectives,
        vec![models::rational(-1, 1), models::rational(0, 1)]
    );
    session
        .close(CloseMode::Drain, Duration::from_secs(3))
        .await
        .expect("native cleanup");
}
