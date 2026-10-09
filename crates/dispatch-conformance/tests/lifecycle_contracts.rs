//! Public execution accounting under providers that cannot confirm cleanup.
//!
//! The provider independently tracks allocated resources. Its stop operation
//! initially fails, so releasing a runtime slot cannot be mistaken for proven
//! resource reclamation. No production scheduler internals are consulted.

#![allow(clippy::expect_used)]

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use dispatch_protocol::{
    framing::{read_frame_async, write_frame_async},
    wire::{self, worker_envelope::Body},
};
use dispatch_runtime::{
    CloseMode, RuntimeError, Session, SessionBuilder, SessionLimits, SolveOptions, Termination,
    providers::{ExecutionProvider, ResourceGrant, WorkerConnection, WorkerControl, WorkerLaunch},
};
use tokio::sync::Notify;

#[path = "support/models.rs"]
#[allow(dead_code)] // Shared fixtures expose helpers used by other test targets.
mod models;

#[derive(Default)]
struct AllocationState {
    launches: AtomicUsize,
    alive: AtomicUsize,
    prepare_entered: AtomicUsize,
    stop_attempts: AtomicUsize,
    allow_stop: AtomicBool,
    stall_hello: bool,
}

struct ControlledProvider {
    state: Arc<AllocationState>,
}

#[async_trait]
impl ExecutionProvider for ControlledProvider {
    fn grant(&self) -> ResourceGrant {
        ResourceGrant {
            hard_cancellation: false,
            independent_memory: false,
            aggregate_accounting: false,
            owner_cleanup: false,
            enforced_memory_bytes: None,
            enforced_limits: None,
            description: "controlled allocation with explicit cleanup confirmation".into(),
        }
    }

    async fn launch(&self, _launch: WorkerLaunch) -> Result<WorkerConnection, RuntimeError> {
        self.state.launches.fetch_add(1, Ordering::SeqCst);
        self.state.alive.fetch_add(1, Ordering::SeqCst);
        let (owner, peer) = tokio::io::duplex(65_536);
        let control = Arc::new(ControlledWorker {
            state: self.state.clone(),
            alive: AtomicBool::new(true),
            stopped: Notify::new(),
        });
        let handler_control = control.clone();
        tokio::spawn(async move {
            let serve = serve_peer(peer, handler_control.state.clone());
            tokio::select! {
                _ = serve => {},
                _ = handler_control.stopped.notified() => {},
            }
        });
        let (reader, writer) = tokio::io::split(owner);
        Ok(WorkerConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            control,
        })
    }
}

struct ControlledWorker {
    state: Arc<AllocationState>,
    alive: AtomicBool,
    stopped: Notify,
}

#[async_trait]
impl WorkerControl for ControlledWorker {
    async fn stop(&self) -> Result<(), RuntimeError> {
        self.state.stop_attempts.fetch_add(1, Ordering::SeqCst);
        if !self.state.allow_stop.load(Ordering::SeqCst) {
            return Err(RuntimeError::Unsupported(
                "test provider cannot yet confirm cleanup".into(),
            ));
        }
        if self.alive.swap(false, Ordering::SeqCst) {
            self.state.alive.fetch_sub(1, Ordering::SeqCst);
            self.stopped.notify_one();
        }
        Ok(())
    }
}

async fn serve_peer(mut peer: tokio::io::DuplexStream, state: Arc<AllocationState>) {
    let Ok(hello) = read_frame_async(&mut peer, 65_536).await else {
        return;
    };
    if state.stall_hello {
        std::future::pending::<()>().await;
    }
    let Some(Body::Hello(request)) = hello.body.as_ref() else {
        return;
    };
    let capabilities = wire::Capabilities {
        protocol_version: hello.protocol_version,
        model_versions: request.model_versions.clone(),
        limits: Some(wire::WireLimits::standard()),
        backend_name: "controlled-resource".into(),
        backend_build_id: "controlled-v1".into(),
        search_modes: vec![wire::SearchMode::LocalSearch as i32],
        ..Default::default()
    };
    let response = wire::WorkerEnvelope {
        body: Some(Body::Capabilities(capabilities)),
        ..hello
    };
    if write_frame_async(&mut peer, &response, 65_536)
        .await
        .is_err()
    {
        return;
    }
    let Ok(request) = read_frame_async(&mut peer, 65_536).await else {
        return;
    };
    if matches!(request.body, Some(Body::Prepare(_))) {
        state.prepare_entered.fetch_add(1, Ordering::SeqCst);
    }
    // A transport disappearing does not prove that the provider allocation was
    // reclaimed. Only the explicit stop acknowledgement releases that resource.
    std::future::pending::<()>().await;
}

async fn controlled_session(state: Arc<AllocationState>) -> Session {
    controlled_session_with_limits(
        state,
        SessionLimits {
            max_workers: 1,
            cleanup_timeout: Duration::from_millis(20),
            ..Default::default()
        },
    )
    .await
}

async fn controlled_session_with_limits(
    state: Arc<AllocationState>,
    limits: SessionLimits,
) -> Session {
    let launch = WorkerLaunch {
        runner: PathBuf::from("unused-controlled-runner"),
        native_backend: PathBuf::from("unused-controlled-native"),
        native_arguments: Vec::new(),
        session_generation: 0,
        worker_generation: 0,
        max_frame_bytes: 65_536,
    };
    SessionBuilder::new(Arc::new(ControlledProvider { state }), launch)
        .expected_backend_build("controlled-v1")
        .trusted_capabilities(wire::Capabilities {
            protocol_version: Some(dispatch_protocol::WORKER_VERSION),
            model_versions: vec![dispatch_protocol::MODEL_VERSION],
            limits: Some(wire::WireLimits::standard()),
            backend_name: "controlled-resource".into(),
            backend_build_id: "controlled-v1".into(),
            search_modes: vec![wire::SearchMode::LocalSearch as i32],
            ..Default::default()
        })
        .limits(limits)
        .start()
        .await
        .expect("controlled provider session")
}

async fn wait_counter(counter: &AtomicUsize, minimum: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while counter.load(Ordering::SeqCst) < minimum {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("provider event occurs within bounded wait");
}

async fn assert_no_replacement(session: &Session, state: &AllocationState) {
    let replacement = session
        .submit(
            models::problem(&[[1, 1]], &[false], &[None], &[0]),
            SolveOptions {
                deadline: Duration::from_millis(100),
                ..Default::default()
            },
        )
        .expect("queued replacement admitted");
    assert_eq!(
        replacement
            .wait()
            .await
            .expect("replacement submission deadline")
            .termination,
        Termination::LimitReached
    );
    assert_eq!(
        state.launches.load(Ordering::SeqCst),
        1,
        "unconfirmed allocation retains the only worker slot"
    );
    assert_eq!(state.alive.load(Ordering::SeqCst), 1);
}

async fn allow_and_confirm_cleanup(session: &Session, state: &AllocationState) {
    state.allow_stop.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.alive.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("quarantined allocation is eventually reclaimed");
    let report = session
        .close(CloseMode::Cancel, Duration::from_secs(2))
        .await
        .expect("confirmed cleanup");
    assert_eq!(report.workers_unconfirmed, 0);
}

#[tokio::test]
async fn timed_out_preparation_keeps_unconfirmed_worker_allocation_charged() {
    let state = Arc::new(AllocationState::default());
    let session = controlled_session(state.clone()).await;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        session.prepare_with_deadline(
            models::problem(&[[1, 1]], &[false], &[None], &[0]),
            Duration::from_millis(100),
        ),
    )
    .await
    .expect("preparation deadline returns before unconfirmed cleanup");
    assert!(result.is_err());
    assert_eq!(state.prepare_entered.load(Ordering::SeqCst), 1);
    assert_no_replacement(&session, &state).await;
    allow_and_confirm_cleanup(&session, &state).await;
}

#[tokio::test]
async fn aborted_preparation_keeps_cleanup_supervision_and_slot_ownership() {
    let state = Arc::new(AllocationState::default());
    let session = controlled_session(state.clone()).await;
    let preparing = session.clone();
    let task = tokio::spawn(async move {
        preparing
            .prepare(models::problem(&[[1, 1]], &[false], &[None], &[0]))
            .await
    });
    wait_counter(&state.prepare_entered, 1).await;
    task.abort();
    assert!(
        task.await
            .expect_err("aborted preparation task")
            .is_cancelled()
    );
    wait_counter(&state.stop_attempts, 1).await;
    assert_no_replacement(&session, &state).await;
    allow_and_confirm_cleanup(&session, &state).await;
}

#[tokio::test]
async fn startup_timeout_keeps_provider_allocation_charged_until_cleanup_confirmation() {
    let state = Arc::new(AllocationState {
        stall_hello: true,
        ..Default::default()
    });
    let session = controlled_session(state.clone()).await;
    let job = session
        .submit(
            models::problem(&[[1, 1]], &[false], &[None], &[0]),
            SolveOptions {
                deadline: Duration::from_millis(100),
                ..Default::default()
            },
        )
        .expect("startup job");
    assert_eq!(
        job.wait().await.expect("startup terminal").termination,
        Termination::LimitReached
    );
    wait_counter(&state.stop_attempts, 1).await;
    assert_no_replacement(&session, &state).await;
    allow_and_confirm_cleanup(&session, &state).await;
}

#[tokio::test]
async fn retained_hint_bytes_are_part_of_atomic_request_admission() {
    let state = Arc::new(AllocationState {
        allow_stop: AtomicBool::new(true),
        ..Default::default()
    });
    let session = controlled_session_with_limits(
        state.clone(),
        SessionLimits {
            max_input_bytes: 4096,
            ..Default::default()
        },
    )
    .await;
    let problem = models::problem(&[[1, 1]], &[false], &[None], &[0]);
    assert!(
        serde_json::to_vec(&problem)
            .expect("small fixture encoding")
            .len()
            < 4096
    );
    let hint = dispatch_model::Assignment {
        bindings: [(
            models::item(0),
            dispatch_model::Binding::Target {
                target: "x".repeat(16_384),
            },
        )]
        .into(),
    };
    let result = session.submit(
        problem,
        SolveOptions {
            hint: Some(hint),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(RuntimeError::Overloaded(_))),
        "hint retention must obey the request byte budget"
    );
    assert_eq!(
        state.launches.load(Ordering::SeqCst),
        0,
        "over-budget requests never acquire native resources"
    );
    session
        .close(CloseMode::Cancel, Duration::from_secs(1))
        .await
        .expect("no accepted work to clean up");
}

#[tokio::test]
async fn dispatched_startup_does_not_consume_the_pending_queue_reservation() {
    let state = Arc::new(AllocationState {
        stall_hello: true,
        ..Default::default()
    });
    let session = controlled_session_with_limits(
        state.clone(),
        SessionLimits {
            max_pending: 1,
            cleanup_timeout: Duration::from_millis(20),
            ..Default::default()
        },
    )
    .await;
    let problem = models::problem(&[[1, 1]], &[false], &[None], &[0]);
    let starting = session
        .submit(
            problem.clone(),
            SolveOptions {
                deadline: Duration::from_secs(5),
                ..Default::default()
            },
        )
        .expect("dispatched startup");
    wait_counter(&state.launches, 1).await;
    assert_eq!(starting.status(), dispatch_runtime::JobStatus::Running);

    let queued = session
        .submit(
            problem,
            SolveOptions {
                deadline: Duration::from_millis(100),
                ..Default::default()
            },
        )
        .expect("the single pending reservation is available during active startup");
    assert_eq!(
        queued.wait().await.expect("queued deadline").termination,
        Termination::LimitReached
    );
    assert!(starting.cancel());
    assert_eq!(
        starting
            .wait()
            .await
            .expect("cancelled startup")
            .termination,
        Termination::Cancelled
    );
    wait_counter(&state.stop_attempts, 1).await;
    allow_and_confirm_cleanup(&session, &state).await;
}
