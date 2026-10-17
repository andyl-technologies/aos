//! Internal lifecycle control-plane regressions.

fn output_budget() -> crucible::owned_decode::DecodeBudget {
    let scope = crucible::test_support::fixture_decode_scope(64 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite API component metadata: {error}"));
    let budget = crucible::owned_decode::current_budget()
        .unwrap_or_else(|| panic!("fixture must install its finite metadata account"));
    drop(scope);
    budget
}

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::{CommandRejectionKind, InProcessLifecycleClient};
use crucible_session::StepMode;

#[test]
fn refused_diagnostic_admission_does_not_publish_quiescent_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = output_budget();
    let configuration = {
        let _scope = budget.enter();
        let scenario = crucible::crash_restart_scenario()?.scenario;
        Configuration::genesis(scenario.scenario_def())
    };
    let mut quantum_loop = QuiescentLifecycleLoop::new();

    let result = quantum_loop.drive_quantum(QuantumRequest {
        configuration,
        control: Vec::new(),
    });

    assert!(matches!(
        result,
        Err(SchedulerError::Evaluation { source })
            if matches!(source.as_ref(), EngineError::ArtifactDecodeAdmission { .. })
    ));
    assert_eq!(quantum_loop.quanta(), 0);
    assert_eq!(quantum_loop.event_log_events, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn observation_authentication_reinstalls_original_credit_on_the_blocking_thread() {
    let decoding = output_budget();
    let request = {
        let _scope = decoding.enter();
        observation_resume_request()
    };
    let caller_thread = std::thread::current().id();
    let authenticated = Arc::new(AtomicUsize::new(0));
    let factory_authenticated = Arc::clone(&authenticated);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-original-credit-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_decode_budget(decoding.clone())
    .with_resume_observation_loop_factory(move |_request, _configuration, _context| {
        assert_ne!(std::thread::current().id(), caller_thread);
        let authentication = crucible::owned_decode::require_current_child_budget()
            .map_err(LifecycleApiError::ConfigurationCopy)?;
        authentication
            .charge_bytes(1024)
            .map_err(LifecycleApiError::ConfigurationCopy)?;
        factory_authenticated.fetch_add(1, Ordering::SeqCst);
        Ok(QuiescentLifecycleLoop::new())
    });
    let client = InProcessLifecycleClient::new(control_plane);

    let resumed = client
        .resume_session(request)
        .await
        .unwrap_or_else(|error| panic!("authenticate and publish under original credit: {error}"));
    assert_eq!(authenticated.load(Ordering::SeqCst), 1);
    assert!(crucible::owned_decode::current_budget().is_none());
    decoding
        .check()
        .unwrap_or_else(|error| panic!("original account remains usable: {error}"));
    client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .unwrap_or_else(|error| panic!("original actor cleanup: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn timed_out_observation_preparation_retains_then_releases_its_permit() {
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&factory_calls);
    let (canceled_sender, canceled_receiver) = std::sync::mpsc::sync_channel(1);
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
    let release_receiver = Arc::new(Mutex::new(release_receiver));
    let factory_release = Arc::clone(&release_receiver);
    let (finished_sender, finished_receiver) = std::sync::mpsc::sync_channel(1);
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-observation-timeout-permit-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_decode_budget(crate::lifecycle::tests::output_budget())
    .with_resume_observation_loop_factory(move |_request, _configuration, context| {
        let call = counted.fetch_add(1, Ordering::SeqCst);
        if call != 0 {
            return Ok(QuiescentLifecycleLoop::new());
        }
        let canceled_sender = canceled_sender.clone();
        let _cancellation = context.cancellation().register(move || {
            let _ = canceled_sender.send(());
        });
        factory_release
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv()
            .map_err(|error| LifecycleApiError::ResumeObservationSource {
                message: format!("release timed-out factory: {error}"),
            })?;
        let _ = finished_sender.send(());
        Err(LifecycleApiError::ResumeObservationSource {
            message: String::from("timed-out factory completed after cancellation"),
        })
    })
    .with_resume_observation_preparation_capacity(1)
    .with_max_sessions(2);
    control_plane.resume_observation_preparation_timeout = Duration::from_millis(20);
    let client = InProcessLifecycleClient::new(control_plane);

    let timed_out = client.resume_session(observation_resume_request()).await;
    assert!(timed_out.is_err(), "blocked preparation should time out");
    assert!(
        canceled_receiver
            .recv_timeout(Duration::from_secs(1))
            .is_ok(),
        "timeout must synchronously signal backend cancellation",
    );
    let retained_permit = client.resume_session(observation_resume_request()).await;
    assert!(
        retained_permit.is_err(),
        "timed-out work must retain its permit until the worker exits",
    );
    assert_eq!(factory_calls.load(Ordering::SeqCst), 1);

    assert!(
        release_sender.send(()).is_ok(),
        "timed-out factory worker should accept its release signal",
    );
    assert!(
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .is_ok(),
        "timed-out factory should finish",
    );
    let mut resumed = None;
    for _ in 0..500 {
        match client.resume_session(observation_resume_request()).await {
            Ok(session) => {
                resumed = Some(session);
                break;
            }
            Err(ControlClientError::Lifecycle {
                source: LifecycleApiError::ResumeObservationSource { .. },
            }) => {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Err(error) => panic!("completed timed-out work retained its permit: {error}"),
        }
    }
    let Some(resumed) = resumed else {
        panic!("completed timed-out work should release its permit");
    };

    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    let destroyed = client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await;
    assert!(destroyed.is_ok(), "resumed session should be destroyed");
}

#[tokio::test(flavor = "current_thread")]
async fn owner_admitted_debug_session_rejects_canonical_mutation() {
    let source = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(source.scenario_def());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should build: {error}"));
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-read-only-debug-admission-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_decode_budget(crate::lifecycle::tests::output_budget());

    let admitted = control_plane
        .admit_authenticated_read_only_session(
            source.clone(),
            configuration,
            checkpoint,
            source.scenario_def().seed(),
            SessionLifetimeRetention::new(Box::new(())),
            || Ok::<_, std::convert::Infallible>(QuiescentLifecycleLoop::new()),
        )
        .unwrap_or_else(|error| panic!("owner admission should succeed: {error}"));
    let streaming = control_plane
        .streaming_session(admitted.session)
        .unwrap_or_else(|error| panic!("read-only stream should attach: {error}"));
    let control = streaming
        .control(AttachRequest::new(admitted.session))
        .unwrap_or_else(|error| panic!("read-only control stream should attach: {error}"));
    for (command_id, command) in [
        (1, SessionCommand::Pause),
        (2, SessionCommand::Continue),
        (3, SessionCommand::step(StepMode::Quantum)),
        (
            4,
            SessionCommand::Fork {
                from: CheckpointRef::Checkpoint(admitted.checkpoint),
                reply: CommandReply::discard(),
            },
        ),
    ] {
        let unary = streaming
            .send(SendRequest::new(
                admitted.session,
                command_id,
                command.clone(),
            ))
            .await
            .unwrap_or_else(|error| panic!("policy rejection should be returned: {error}"));
        assert_eq!(
            unary.result.status,
            CommandResultStatus::Rejected {
                reason: CommandRejectionKind::InvalidState
            }
        );
        let streamed = control
            .send_command(command_id + 10, command)
            .await
            .unwrap_or_else(|error| panic!("control rejection should be returned: {error}"));
        assert_eq!(
            streamed.result.status,
            CommandResultStatus::Rejected {
                reason: CommandRejectionKind::InvalidState
            }
        );
    }
    assert!(
        control
            .attached()
            .capabilities
            .contains(SessionCommandKind::Query)
    );
    assert!(
        control
            .attached()
            .capabilities
            .contains(SessionCommandKind::Stop)
    );
    assert!(
        !control
            .attached()
            .capabilities
            .contains(SessionCommandKind::Pause)
    );
    assert!(matches!(
        control_plane.debug_reposition_dispatch(admitted.session),
        Err(LifecycleApiError::ReadOnlySession { session }) if session == admitted.session
    ));

    let client = InProcessLifecycleClient::new(control_plane);
    let rejected = client
        .send_command(SendRequest::new(
            admitted.session,
            20,
            SessionCommand::step(StepMode::Quantum),
        ))
        .await;

    assert!(matches!(
        rejected,
        Err(ControlClientError::Lifecycle {
            source: LifecycleApiError::ReadOnlySession { session }
        }) if session == admitted.session
    ));
}

#[test]
fn authenticated_builder_failure_retains_typed_custody_until_last_error_clone() {
    #[derive(Debug)]
    struct NativeConstructionFailure {
        drops: Arc<AtomicUsize>,
        file: Arc<std::fs::File>,
    }

    impl std::fmt::Display for NativeConstructionFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("native construction refused")
        }
    }

    impl std::error::Error for NativeConstructionFailure {}

    impl Drop for NativeConstructionFailure {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    let source = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("source fixture should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(source.scenario_def());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("checkpoint fixture should build: {error}"));
    let drops = Arc::new(AtomicUsize::new(0));
    let file = Arc::new(
        tempfile::tempfile()
            .unwrap_or_else(|error| panic!("native descriptor fixture should open: {error}")),
    );
    let descriptor = Arc::downgrade(&file);
    let mut control_plane = LifecycleControlPlane::new(
        "typed-backend-custody-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_decode_budget(crate::lifecycle::tests::output_budget());

    let construction_drops = drops.clone();
    let error = control_plane
        .admit_authenticated_read_only_session(
            source.clone(),
            configuration,
            checkpoint,
            source.scenario_def().seed(),
            SessionLifetimeRetention::new(Box::new(())),
            move || {
                Err::<QuiescentLifecycleLoop, _>(NativeConstructionFailure {
                    drops: construction_drops,
                    file,
                })
            },
        )
        .err()
        .unwrap_or_else(|| panic!("native builder must refuse admission"));
    let LifecycleApiError::BackendConstruction { source } = &error else {
        panic!("builder failure must retain its typed source: {error}");
    };
    let cause = std::error::Error::source(source)
        .and_then(|cause| cause.downcast_ref::<NativeConstructionFailure>())
        .unwrap_or_else(|| panic!("actual native typed cause must remain inspectable"));
    assert!(cause.file.metadata().is_ok());
    let retained = error.clone();
    drop(error);
    drop(control_plane);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(descriptor.upgrade().is_some());

    drop(retained);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(descriptor.upgrade().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn durable_owner_cleanup_runs_on_destroy_but_not_control_plane_shutdown() {
    let source = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(source.scenario_def());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should build: {error}"));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));

    let mut shutdown_plane = LifecycleControlPlane::new(
        "crucible-durable-owner-shutdown-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_decode_budget(crate::lifecycle::tests::output_budget());
    let shutdown_counter = Arc::clone(&cleanup_calls);
    shutdown_plane
        .admit_authenticated_read_only_session(
            source.clone(),
            configuration.clone(),
            checkpoint.clone(),
            source.scenario_def().seed(),
            SessionLifetimeRetention::new(Box::new(())).with_destroy_callback(move || {
                shutdown_counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            || Ok::<_, std::convert::Infallible>(QuiescentLifecycleLoop::new()),
        )
        .unwrap_or_else(|error| panic!("owner admission should succeed: {error}"));
    drop(shutdown_plane);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);

    let mut destroy_plane = LifecycleControlPlane::new(
        "crucible-durable-owner-destroy-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_decode_budget(crate::lifecycle::tests::output_budget());
    let destroy_counter = Arc::clone(&cleanup_calls);
    let admitted = destroy_plane
        .admit_authenticated_read_only_session(
            source.clone(),
            configuration,
            checkpoint,
            source.scenario_def().seed(),
            SessionLifetimeRetention::new(Box::new(())).with_destroy_callback(move || {
                destroy_counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            || Ok::<_, std::convert::Infallible>(QuiescentLifecycleLoop::new()),
        )
        .unwrap_or_else(|error| panic!("owner admission should succeed: {error}"));
    destroy_plane
        .destroy_session(DestroySessionRequest::new(admitted.session))
        .await
        .unwrap_or_else(|error| panic!("owner destroy should succeed: {error}"));
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn owner_admitted_debug_session_becomes_writable_only_after_branch_provenance() {
    let source = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let scenario = source.scenario_def();
    let configuration = Configuration::genesis(scenario.clone());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should build: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            debug_genesis_checkpoint(&configuration, &source)
                .unwrap_or_else(|error| panic!("debug genesis should bake: {error}")),
        )
        .unwrap_or_else(|error| panic!("debug graph should build: {error}"));
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-writable-debug-provenance-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_decode_budget(crate::lifecycle::tests::output_budget());
    let admitted = control_plane
        .admit_authenticated_read_only_session(
            source,
            configuration.clone(),
            checkpoint,
            scenario.seed(),
            SessionLifetimeRetention::new(Box::new(())),
            || Ok::<_, std::convert::Infallible>(QuiescentLifecycleLoop::new()),
        )
        .unwrap_or_else(|error| panic!("owner admission should succeed: {error}"));

    let node = NodeId {
        name: String::from("server"),
    };
    let attach_request = crucible::DebugAttachRequest::new(
        configuration.clone(),
        node,
        "unix:/tmp/crucible-writable-debug.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )
    .unwrap_or_else(|error| panic!("debug attach request should build: {error}"));
    let attach = graph
        .debug_attach(&attach_request)
        .unwrap_or_else(|error| panic!("debug graph should attach: {error}"));
    let branch_request = crucible::DebugNonCanonicalBranchRequest::new(
        configuration,
        VirtualTime::default(),
        crucible::DebugNonCanonicalBranchTrigger::OperatorContinue,
    )
    .with_action(crucible::DebugNonCanonicalBranchAction::operator_control(
        crucible::DebugOperatorControlKind::Continue,
    ));
    let report = graph
        .debug_non_canonical_branch(&attach, &branch_request, &[])
        .unwrap_or_else(|error| panic!("non-canonical branch should build: {error}"));

    let mut foreign = report.clone();
    foreign.branch.fork_point = ContentHash::default();
    assert!(matches!(
        control_plane.commit_writable_debug_branch(admitted.session, &foreign),
        Err(LifecycleApiError::SessionCommandRejected { .. })
    ));
    assert_eq!(
        control_plane
            .writable_debug_branch(admitted.session)
            .unwrap_or_else(|error| panic!("read-only provenance should be readable: {error}")),
        None
    );

    control_plane
        .commit_writable_debug_branch(admitted.session, &report)
        .unwrap_or_else(|error| panic!("provenance transition should succeed: {error}"));

    assert_eq!(
        control_plane
            .writable_debug_branch(admitted.session)
            .unwrap_or_else(|error| panic!("branch provenance should be readable: {error}")),
        Some(report.branch.id)
    );
    assert!(
        control_plane
            .debug_reposition_dispatch(admitted.session)
            .is_ok(),
        "writable derivative should expose ordinary mutable debug dispatch"
    );
}

fn observation_resume_request() -> ResumeSessionRequest {
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    let parent = Configuration::genesis(configuration.def.clone());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        Some(&parent),
        VirtualTime { ticks: 1 },
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("observation checkpoint should build: {error}"));
    let observation_source = ResumeObservationSource::new(
        &scenario,
        &schedule,
        &checkpoint,
        1,
        b"proof".to_vec(),
        b"evidence".to_vec(),
    )
    .unwrap_or_else(|error| panic!("observation source should build: {error}"));
    let replay_closure = ResumeReplayClosure::new(
        &scenario,
        &schedule,
        &checkpoint,
        1,
        b"replay-closure".to_vec(),
    )
    .unwrap_or_else(|error| panic!("replay closure should build: {error}"));

    ResumeSessionRequest::new(
        scenario.clone(),
        schedule,
        checkpoint,
        scenario.seed(),
        observation_source,
    )
    .with_replay_closure(replay_closure)
}
