//! API-side checks for discovery and lifecycle unary methods.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, DeliveryOrderDecision,
    GdbAttachInfo, GdbListen, Icount, NodeId, QuantumLoop, QuantumOutcome, QuantumRequest,
    ScenarioDef, ScenarioDefForm, Schedule, SchedulerError, Seed, VirtualTime,
};
use crucible_api::{
    ControlClient, CreateSessionRequest, CreateSessionSource, DebugAuthorizationPolicy,
    DebugControllerAcquisition, DestroySessionRequest, HelloRequest, InProcessLifecycleClient,
    LIFECYCLE_SESSION_MAILBOX_CAPACITY, LifecycleApiError, LifecycleControlPlane,
    LifecycleLoopFactory, LifecycleServerMode, ListScenariosResponse, QuiescentLifecycleLoop,
    RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION, ResumeObservationSource, ResumeReplayClosure,
    ResumeReplayClosureValidationError, ResumeSessionRequest, RpcControlClient, RpcEndpoint,
    ScenarioCatalogEntry, SendRequest, serve_lifecycle_http2,
    serve_lifecycle_http2_with_debug_policy_until_shutdown,
};
use crucible_session::{
    DebugCapability, DebugClientId, DebugCoordinatorError, DebugRole, LiveStateKind, OutcomeKind,
    SessionCommand,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
fn lifecycle_hello_and_list_scenarios_are_side_effect_free() {
    let control_plane = lifecycle_control_plane();

    let hello = control_plane
        .hello(HelloRequest::new(
            "api-lifecycle-test",
            RPC_PROTOCOL_VERSION,
        ))
        .unwrap_or_else(|error| panic!("hello should negotiate: {error}"));
    let scenarios = control_plane.list_scenarios();

    assert_eq!(hello.version, RPC_PROTOCOL_VERSION);
    assert_eq!(hello.payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
    assert_eq!(control_plane.session_count(), 0);
    assert_eq!(
        scenarios,
        ListScenariosResponse {
            scenarios: vec![catalog_entry().summary()],
        },
    );
}

#[tokio::test(flavor = "current_thread")]
async fn create_list_destroy_session_maps_to_start_stop_and_live_mirror() {
    let mut control_plane = lifecycle_control_plane();
    let request = CreateSessionRequest::scenario_ref("api-lifecycle-scenario", Seed::from_u64(101));

    let created = control_plane
        .create_session(request)
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));

    assert_eq!(created.state, LiveStateKind::Paused);
    assert_eq!(created.session.seed, Seed::from_u64(101));
    assert_eq!(control_plane.session_count(), 1);

    let sessions = control_plane.list_sessions();
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Paused);
    assert_eq!(sessions.sessions[0].event_log_len, 0);

    let destroyed = control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("destroy session should stop actor: {error}"));
    assert!(destroyed.stopped);
    assert!(!destroyed.already_absent);
    assert_eq!(control_plane.session_count(), 0);

    let absent = control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("absent destroy should be idempotent: {error}"));
    assert!(absent.already_absent);
    assert!(!absent.stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn destroy_session_does_not_wedge_when_shutdown_is_rejected() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-rejected-shutdown-test",
        vec![catalog_entry()],
        |_scenario: &ScenarioDef, _seed| RejectShutdownLoop,
    );
    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(101),
        ))
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));

    let error = control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .expect_err("rejected shutdown must return instead of wedging destroy");

    assert!(matches!(error, LifecycleApiError::ActorFailed { .. }));
    assert!(
        error
            .to_string()
            .contains("synthetic unconsumed branch choice")
    );
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_unary_methods_are_exposed_on_control_client_trait() {
    let client = InProcessLifecycleClient::new(lifecycle_control_plane());

    let scenarios = client
        .list_scenarios()
        .await
        .unwrap_or_else(|error| panic!("trait list scenarios should succeed: {error}"));
    assert_eq!(scenarios.scenarios, vec![catalog_entry().summary()]);

    let created = client
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(105),
        ))
        .await
        .unwrap_or_else(|error| panic!("trait create session should start actor: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);

    let sessions = client
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("trait list sessions should succeed: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);

    let destroyed = client
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("trait destroy session should stop actor: {error}"));
    assert!(destroyed.stopped);
    assert_eq!(client.session_count().await, 0);

    let resume = resume_request(106);
    let resumed = client
        .resume_session(resume)
        .await
        .unwrap_or_else(|error| panic!("trait resume session should start paused actor: {error}"));
    assert_eq!(resumed.state, LiveStateKind::Paused);
    assert_eq!(client.session_count().await, 1);

    let destroyed = client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .unwrap_or_else(|error| panic!("trait destroy resumed session should stop actor: {error}"));
    assert!(destroyed.stopped);
    assert_eq!(client.session_count().await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn create_session_start_paused_false_continues_to_running() {
    let mut control_plane = lifecycle_control_plane();
    let request = CreateSessionRequest::scenario_ref("api-lifecycle-scenario", Seed::from_u64(106))
        .with_start_paused(false);

    let created = control_plane
        .create_session(request)
        .await
        .unwrap_or_else(|error| panic!("create session should continue when requested: {error}"));

    assert_eq!(created.state, LiveStateKind::Running);
    let sessions = control_plane.list_sessions();
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Running);

    control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn scenario_ref_create_materializes_the_requested_seed() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_for_factory = Arc::clone(&observed);
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-lifecycle-test-server",
        vec![catalog_entry()],
        move |scenario: &ScenarioDef, seed| {
            observed_for_factory
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((scenario.seed(), seed));
            NoopLoop
        },
    );

    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(107),
        ))
        .await
        .unwrap_or_else(|error| panic!("scenario ref should materialize request seed: {error}"));

    assert_eq!(
        observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        &[(Seed::from_u64(107), Seed::from_u64(107))],
    );

    control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn destroy_session_rejects_epoch_mismatch_without_dropping_actor() {
    let mut control_plane = lifecycle_control_plane();
    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(102),
        ))
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));
    let mut stale_ref = created.session;
    stale_ref.epoch = stale_ref.epoch.saturating_add(1);

    let error = control_plane
        .destroy_session(DestroySessionRequest::new(stale_ref))
        .await
        .expect_err("epoch mismatch should reject live session destroy");

    assert_eq!(
        error,
        LifecycleApiError::EpochMismatch {
            session_id: created.session.id,
            expected: created.session.epoch,
            actual: stale_ref.epoch,
        },
    );
    assert_eq!(control_plane.session_count(), 1);

    control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn create_session_accepts_inline_scenario_without_registry_entry() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-lifecycle-test-server",
        Vec::new(),
        |_scenario, _seed| NoopLoop,
    )
    .with_mailbox_capacity(LIFECYCLE_SESSION_MAILBOX_CAPACITY);
    let scenario = generated_scenario(103);

    let created = control_plane
        .create_session(CreateSessionRequest::inline(
            scenario.clone(),
            scenario.seed(),
        ))
        .await
        .unwrap_or_else(|error| panic!("inline scenario should create session: {error}"));

    assert_eq!(created.state, LiveStateKind::Paused);
    assert_eq!(created.session.seed, scenario.seed());

    control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn create_session_propagates_backend_factory_failure_without_side_effects() {
    let mut control_plane = LifecycleControlPlane::new_with_fallible_source_factory(
        "crucible-lifecycle-test-server",
        Vec::new(),
        |_scenario, _source, _seed| -> Result<NoopLoop, LifecycleApiError> {
            Err(LifecycleApiError::LoopFactory {
                message: String::from("synthetic launch rejection"),
            })
        },
    );
    let scenario = generated_scenario(122);

    let error = control_plane
        .create_session(CreateSessionRequest::inline(
            scenario.clone(),
            scenario.seed(),
        ))
        .await
        .expect_err("backend construction failure should reject create");

    assert_eq!(
        error,
        LifecycleApiError::LoopFactory {
            message: String::from("synthetic launch rejection"),
        },
    );
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn autonomous_actor_failure_publishes_terminal_crash_without_another_command() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-lifecycle-test-server",
        vec![catalog_entry()],
        |_scenario, _seed| FailingLoop,
    );
    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(123),
        ))
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));

    control_plane
        .send_streaming_command(SendRequest::new(
            created.session,
            1,
            SessionCommand::Continue,
        ))
        .await
        .unwrap_or_else(|error| {
            panic!("Continue should be accepted before the loop fails: {error}")
        });

    let mut crashed = None;
    for _ in 0..LIFECYCLE_SESSION_MAILBOX_CAPACITY {
        let sessions = control_plane.list_sessions();
        let summary = sessions
            .sessions
            .iter()
            .find(|summary| summary.session == created.session)
            .unwrap_or_else(|| panic!("created session should remain registered"));
        if summary.state == LiveStateKind::Stopped {
            crashed = Some(summary.clone());
            break;
        }
        tokio::task::yield_now().await;
    }
    let crashed = crashed.unwrap_or_else(|| panic!("actor failure should publish terminal state"));
    assert_eq!(crashed.outcome, Some(OutcomeKind::Crashed));
    assert!(crashed.terminal_savepoint.is_some());

    let destroyed = control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("terminal crashed session should be destroyable: {error}"));
    assert!(destroyed.stopped);
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn create_session_rejects_unknown_scenario_without_side_effects() {
    let mut control_plane = lifecycle_control_plane();

    let error = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "missing-scenario",
            Seed::from_u64(104),
        ))
        .await
        .expect_err("unknown scenario should reject create");

    assert_eq!(
        error,
        LifecycleApiError::ScenarioNotFound {
            name: String::from("missing-scenario"),
        },
    );
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn create_session_respects_live_session_limit_without_side_effects() {
    let mut control_plane = lifecycle_control_plane().with_max_sessions(1);
    let first = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(110),
        ))
        .await
        .unwrap_or_else(|error| panic!("first session should fit under cap: {error}"));

    let error = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(111),
        ))
        .await
        .expect_err("second live session should hit cap");

    assert_eq!(error, LifecycleApiError::SessionLimitReached { limit: 1 });
    assert_eq!(control_plane.session_count(), 1);

    control_plane
        .destroy_session(DestroySessionRequest::new(first.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn create_session_rejects_inline_seed_mismatch_without_side_effects() {
    let mut control_plane = lifecycle_control_plane();
    let scenario = generated_scenario(108);

    let error = control_plane
        .create_session(CreateSessionRequest::inline(
            scenario.clone(),
            Seed::from_u64(109),
        ))
        .await
        .expect_err("inline scenario seed mismatch should reject create");

    assert_eq!(
        error,
        LifecycleApiError::ScenarioSeedMismatch {
            scenario_seed: scenario.seed(),
            request_seed: Seed::from_u64(109),
        },
    );
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn create_session_rejects_inline_form_identity_mismatch_without_side_effects() {
    let mut control_plane = lifecycle_control_plane();
    let scenario_form = resume_request(120).scenario;
    let actual = scenario_form.scenario_def();
    let advertised = ScenarioDef::from_content_hash_seed_and_app_random_draw_cap(
        actual.id(),
        Seed::from_u64(121),
        actual.app_random_draw_cap(),
    );

    let error = control_plane
        .create_session(CreateSessionRequest {
            source: CreateSessionSource::Inline {
                scenario: advertised.clone(),
                scenario_form: Some(scenario_form),
            },
            seed: advertised.seed(),
            start_paused: true,
        })
        .await
        .expect_err("inline form identity mismatch should reject create");

    assert_eq!(
        error,
        LifecycleApiError::InlineScenarioIdentityMismatch {
            expected: Box::new(advertised),
            actual: Box::new(actual),
        },
    );
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn resume_session_accepts_checkpoint_closure_and_paused_live_mirror() {
    let mut control_plane = lifecycle_control_plane();
    let request = resume_request(112);
    let expected_checkpoint = request.checkpoint.id;
    let expected_scenario = request.scenario.scenario_def();
    let expected_configuration = Configuration {
        def: expected_scenario,
        schedule: request.schedule.clone(),
    };

    let resumed = control_plane
        .resume_session(request)
        .await
        .unwrap_or_else(|error| panic!("resume session should accept closure: {error}"));

    assert_eq!(resumed.state, LiveStateKind::Paused);
    assert_eq!(resumed.checkpoint, expected_checkpoint);
    assert_eq!(resumed.configuration, expected_configuration.id());
    assert_eq!(resumed.session.seed, Seed::from_u64(112));
    assert_eq!(control_plane.session_count(), 1);

    let sessions = control_plane.list_sessions();
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, resumed.session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Paused);
    assert_eq!(sessions.sessions[0].frontier, VirtualTime { ticks: 1 });

    control_plane
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop resumed actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn observation_resume_requires_factory_before_session_allocation() {
    let ordinary_allocations = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&ordinary_allocations);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-resume-missing-factory-test",
        Vec::new(),
        move |_scenario: &ScenarioDef, _seed| {
            counted.fetch_add(1, Ordering::SeqCst);
            QuiescentLifecycleLoop::new()
        },
    );
    let mut request = resume_request(142);
    let source = ResumeObservationSource::new(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        1,
        b"proof".to_vec(),
        b"evidence".to_vec(),
    )
    .expect("bounded observation source");
    request = request.with_observation_source(source);

    let client = InProcessLifecycleClient::new(control_plane);
    let error = client
        .resume_session(request)
        .await
        .expect_err("observation resume without a campaign factory must reject");

    assert!(matches!(
        error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::ResumeObservationSource { .. }
        }
    ));
    assert_eq!(ordinary_allocations.load(Ordering::SeqCst), 0);
    assert_eq!(client.session_count().await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn observation_resume_factory_finishes_before_session_publication() {
    let ordinary_allocations = Arc::new(AtomicUsize::new(0));
    let counted_ordinary = Arc::clone(&ordinary_allocations);
    let authenticated = Arc::new(AtomicUsize::new(0));
    let counted_authenticated = Arc::clone(&authenticated);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-resume-factory-test",
        Vec::new(),
        move |_scenario: &ScenarioDef, _seed| {
            counted_ordinary.fetch_add(1, Ordering::SeqCst);
            QuiescentLifecycleLoop::new()
        },
    )
    .with_resume_observation_loop_factory(move |request, configuration, _context| {
        assert!(request.observation_source.is_some());
        assert_eq!(configuration.id(), request.checkpoint.configuration);
        counted_authenticated.fetch_add(1, Ordering::SeqCst);
        Ok(QuiescentLifecycleLoop::new())
    });
    let mut request = resume_request(143);
    let source = ResumeObservationSource::new(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        1,
        b"proof".to_vec(),
        b"evidence".to_vec(),
    )
    .expect("bounded observation source");
    request = request.with_observation_source(source);

    let client = InProcessLifecycleClient::new(control_plane);
    let resumed = client
        .resume_session(request)
        .await
        .expect("campaign factory should authorize ordinary session publication");

    assert_eq!(authenticated.load(Ordering::SeqCst), 1);
    assert_eq!(ordinary_allocations.load(Ordering::SeqCst), 0);
    assert_eq!(client.session_count().await, 1);
    client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .expect("destroy resumed session");
}

#[tokio::test(flavor = "current_thread")]
async fn direct_observation_resume_route_rejects_before_factory_or_session_allocation() {
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&factory_calls);
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-observation-direct-route-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_resume_observation_loop_factory(move |_request, _configuration, _context| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(QuiescentLifecycleLoop::new())
    });

    let error = control_plane
        .resume_session(observation_resume_request(147))
        .await
        .expect_err("the synchronous control-plane route must reject observation work");

    assert!(matches!(
        error,
        LifecycleApiError::ResumeObservationSource { .. }
    ));
    assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_observation_preparation_releases_its_in_flight_permit() {
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&factory_calls);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-failed-permit-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_resume_observation_loop_factory(move |_request, _configuration, _context| {
        let call = counted.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            Err(LifecycleApiError::ResumeObservationSource {
                message: String::from("injected source authentication failure"),
            })
        } else {
            Ok(QuiescentLifecycleLoop::new())
        }
    })
    .with_resume_observation_preparation_capacity(1);
    let client = InProcessLifecycleClient::new(control_plane);

    client
        .resume_session(observation_resume_request(148))
        .await
        .expect_err("first preparation should fail");
    let resumed = client
        .resume_session(observation_resume_request(149))
        .await
        .expect("failed preparation must release its permit");

    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    assert_eq!(client.session_count().await, 1);
    client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .expect("destroy resumed session");
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
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-timeout-permit-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
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
    .with_resume_observation_preparation_timeout(Duration::from_millis(20))
    .with_resume_observation_preparation_capacity(1)
    .with_max_sessions(2);
    let client = InProcessLifecycleClient::new(control_plane);

    client
        .resume_session(observation_resume_request(150))
        .await
        .expect_err("blocked preparation should time out");
    canceled_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("timeout must synchronously signal backend cancellation");
    client
        .resume_session(observation_resume_request(151))
        .await
        .expect_err("timed-out work retains its permit until the worker exits");
    assert_eq!(factory_calls.load(Ordering::SeqCst), 1);

    release_sender
        .send(())
        .expect("release timed-out factory worker");
    finished_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("timed-out factory should finish");
    let release_deadline = observation_test_now() + Duration::from_secs(1);
    let resumed = loop {
        match client.resume_session(observation_resume_request(152)).await {
            Ok(resumed) => break resumed,
            Err(error) if observation_test_now() < release_deadline => {
                assert!(matches!(
                    error,
                    crucible_api::ControlClientError::Lifecycle {
                        source: LifecycleApiError::ResumeObservationSource { .. }
                    }
                ));
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Err(error) => panic!("completed timed-out work retained its permit: {error}"),
        }
    };

    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .expect("destroy resumed session");
}

// Monotonic host time bounds only the test harness's observation of worker
// teardown; no value enters lifecycle input or expected modeled state.
// crucible-lint: allow clippy-disallowed-method -- this is an operational test timeout only.
#[allow(clippy::disallowed_methods)]
fn observation_test_now() -> std::time::Instant {
    std::time::Instant::now()
}

#[tokio::test(flavor = "current_thread")]
async fn observation_factory_does_not_authorize_an_ordinary_typed_resume() {
    let observation_factory_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&observation_factory_calls);
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-observation-resume-closure-isolation-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_resume_observation_loop_factory(move |_request, _configuration, _context| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(QuiescentLifecycleLoop::new())
    });

    let error = control_plane
        .resume_session(selected_resume_request(144))
        .await
        .expect_err("ordinary typed resume still requires its replay closure validator");

    assert!(matches!(
        error,
        LifecycleApiError::ResumeReplayClosure { .. }
    ));
    assert_eq!(observation_factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn http_observation_preparation_releases_registry_lock_and_bounds_in_flight_work() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("observation concurrency listener");
    let address = listener.local_addr().expect("observation listener address");
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let counted_calls = Arc::clone(&factory_calls);
    let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
    let release_receiver = Arc::new(Mutex::new(release_receiver));
    let factory_release = Arc::clone(&release_receiver);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-concurrency-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_resume_observation_loop_factory(move |_request, _configuration, _context| {
        counted_calls.fetch_add(1, Ordering::SeqCst);
        started_sender
            .send(())
            .map_err(|error| LifecycleApiError::ResumeObservationSource {
                message: format!("signal blocked test factory: {error}"),
            })?;
        factory_release
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv()
            .map_err(|error| LifecycleApiError::ResumeObservationSource {
                message: format!("release blocked test factory: {error}"),
            })?;
        Ok(QuiescentLifecycleLoop::new())
    })
    .with_resume_observation_preparation_capacity(1)
    .with_max_sessions(2);
    let server = tokio::spawn(async move { serve_lifecycle_http2(listener, control_plane).await });
    let endpoint = format!("http://{address}");
    let rpc = RpcControlClient::new(RpcEndpoint::http2(endpoint.clone()))
        .expect("observation concurrency client");

    let first_request = observation_resume_request(145);
    let first_endpoint = endpoint.clone();
    let first_resume = tokio::spawn(async move {
        RpcControlClient::new(RpcEndpoint::http2(first_endpoint))
            .expect("first observation client")
            .resume_session(first_request)
            .await
    });
    tokio::task::spawn_blocking(move || {
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("observation factory should start")
    })
    .await
    .expect("factory-start waiter");

    let sessions = tokio::time::timeout(std::time::Duration::from_secs(1), rpc.list_sessions())
        .await
        .expect("list sessions must not wait for observation replay")
        .expect("list sessions during observation replay");
    assert!(sessions.sessions.is_empty());
    let second_error = rpc
        .resume_session(observation_resume_request(146))
        .await
        .expect_err("preparation capacity must reject a concurrent source replay");
    assert!(matches!(
        second_error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::ResumeObservationSource { .. }
        }
    ));
    assert_eq!(factory_calls.load(Ordering::SeqCst), 1);

    release_sender
        .send(())
        .expect("release first observation replay");
    first_resume
        .await
        .expect("first observation resume task")
        .expect("first observation resume");
    let sessions = rpc.list_sessions().await.expect("list resumed session");
    assert_eq!(sessions.sessions.len(), 1);

    server.abort();
    let _ = server.await;
}

fn observation_resume_request(seed: u64) -> ResumeSessionRequest {
    let mut request = resume_request(seed);
    let source = ResumeObservationSource::new(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        1,
        b"proof".to_vec(),
        b"evidence".to_vec(),
    )
    .expect("bounded observation source");
    request = request.with_observation_source(source);
    request
}

#[tokio::test(flavor = "current_thread")]
async fn thin_replay_resume_reaches_exact_recorded_boundary_before_publication() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-lifecycle-thin-replay-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_thin_replay_resume();
    let request = resume_request(122);
    let expected_checkpoint = request.checkpoint.id;
    let expected_configuration = Configuration {
        def: request.scenario.scenario_def(),
        schedule: request.schedule.clone(),
    };

    let resumed = control_plane
        .resume_session(request)
        .await
        .unwrap_or_else(|error| panic!("thin replay should reach the checkpoint: {error}"));

    assert_eq!(resumed.state, LiveStateKind::Paused);
    assert_eq!(resumed.checkpoint, expected_checkpoint);
    assert_eq!(resumed.configuration, expected_configuration.id());
    let sessions = control_plane.list_sessions();
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].frontier, VirtualTime { ticks: 1 });
    assert_eq!(sessions.sessions[0].quanta_stepped, 1);

    control_plane
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop replayed actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn thin_replay_resume_fails_closed_on_schedule_divergence() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-lifecycle-thin-replay-divergence-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| DivergentReplayLoop,
    )
    .with_thin_replay_resume();
    let request = resume_request(123);

    let error = control_plane
        .resume_session(request)
        .await
        .expect_err("thin replay must reject a backend that records a different decision");

    assert!(matches!(error, LifecycleApiError::ResumeCheckpoint { .. }));
    assert!(error.to_string().contains("thin replay diverged"));
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn resume_session_rejects_mismatched_checkpoint_closure_without_side_effects() {
    let mut control_plane = lifecycle_control_plane();
    let mut request = resume_request(113);
    request.schedule = request
        .schedule
        .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 2 },
            order: Vec::new(),
        }));

    let error = control_plane
        .resume_session(request)
        .await
        .expect_err("tampered resume closure should reject");

    assert!(matches!(error, LifecycleApiError::ResumeCheckpoint { .. }));
    assert!(error.to_string().contains("did not match configuration"));
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn typed_resume_requires_authenticated_replay_closure_before_allocation() {
    let allocations = Arc::new(AtomicUsize::new(0));
    let allocations_for_factory = Arc::clone(&allocations);
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-typed-resume-missing-closure-test",
        Vec::new(),
        move |_scenario: &ScenarioDef, _seed| {
            allocations_for_factory.fetch_add(1, Ordering::SeqCst);
            NoopLoop
        },
    )
    .with_resume_replay_closure_validator(|_, _, _, _| Ok(()));

    let error = control_plane
        .resume_session(selected_resume_request(130))
        .await
        .expect_err("typed resume without replay evidence must reject");

    assert!(matches!(
        error,
        LifecycleApiError::ResumeReplayClosure { .. }
    ));
    assert!(error.to_string().contains("requires authenticated"));
    assert_eq!(allocations.load(Ordering::SeqCst), 0);
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn typed_resume_rejects_unknown_closure_version_before_allocation() {
    let allocations = Arc::new(AtomicUsize::new(0));
    let allocations_for_factory = Arc::clone(&allocations);
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-typed-resume-version-test",
        Vec::new(),
        move |_scenario: &ScenarioDef, _seed| {
            allocations_for_factory.fetch_add(1, Ordering::SeqCst);
            NoopLoop
        },
    )
    .with_resume_replay_closure_validator(|_, _, _, closure| {
        if closure.schema_version() == 1 {
            Ok(())
        } else {
            Err(ResumeReplayClosureValidationError::new(format!(
                "unsupported campaign replay closure schema version {}",
                closure.schema_version()
            )))
        }
    });
    let mut request = selected_resume_request(131);
    let closure = ResumeReplayClosure::new(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        99,
        b"canonical-replay-closure".to_vec(),
    )
    .expect("bounded unknown-version closure should build");
    request = request.with_replay_closure(closure);

    let error = control_plane
        .resume_session(request)
        .await
        .expect_err("unknown replay schema must reject");

    assert!(matches!(
        error,
        LifecycleApiError::ResumeReplayClosure { .. }
    ));
    assert!(error.to_string().contains("unsupported"));
    assert_eq!(allocations.load(Ordering::SeqCst), 0);
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn typed_resume_closure_is_bound_to_exact_checkpoint_material() {
    let mut source = selected_resume_request(132);
    let closure = ResumeReplayClosure::new(
        &source.scenario,
        &source.schedule,
        &source.checkpoint,
        1,
        b"canonical-replay-closure".to_vec(),
    )
    .expect("bounded source closure should build");
    source = source.with_replay_closure(closure);

    let mut target = source;
    target.checkpoint.virtual_time = VirtualTime { ticks: 2 };
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-typed-resume-checkpoint-binding-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| NoopLoop,
    )
    .with_resume_replay_closure_validator(|_, _, _, _| Ok(()));

    let error = control_plane
        .resume_session(target)
        .await
        .expect_err("closure from another checkpoint must reject");

    assert!(matches!(
        error,
        LifecycleApiError::ResumeReplayClosure { .. }
    ));
    assert!(error.to_string().contains("exact resume source"));
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn typed_resume_accepts_validated_closure_and_preserves_paused_session_controls() {
    let validations = Arc::new(AtomicUsize::new(0));
    let validations_for_callback = Arc::clone(&validations);
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-typed-resume-accepted-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| NoopLoop,
    )
    .with_resume_replay_closure_validator(
        move |scenario, configuration, checkpoint, closure| {
            assert_eq!(scenario.scenario_def(), configuration.def);
            assert_eq!(checkpoint.configuration, configuration.id());
            assert_eq!(closure.payload(), b"canonical-replay-closure");
            validations_for_callback.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    let mut request = selected_resume_request(133);
    let expected_checkpoint = request.checkpoint.id;
    let closure = ResumeReplayClosure::new(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        1,
        b"canonical-replay-closure".to_vec(),
    )
    .expect("bounded authenticated closure should build");
    request = request.with_replay_closure(closure);

    let resumed = control_plane
        .resume_session(request)
        .await
        .expect("authenticated typed resume should start");

    assert_eq!(validations.load(Ordering::SeqCst), 1);
    assert_eq!(resumed.checkpoint, expected_checkpoint);
    assert_eq!(resumed.state, LiveStateKind::Paused);
    assert_eq!(control_plane.list_sessions().sessions.len(), 1);

    let destroyed = control_plane
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .expect("resumed typed session should retain lifecycle controls");
    assert!(destroyed.stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn direct_resume_accepts_authenticated_runtime_genesis_checkpoint_material() {
    let mut control_plane = lifecycle_control_plane();
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(scenario.scenario_def());
    let checkpoint = checkpoint_for_configuration(&configuration, VirtualTime { ticks: 1 })
        .with_execution_closure(ContentHash::from_bytes(b"runtime-genesis-closure"));

    let report = control_plane
        .resume_session(ResumeSessionRequest::new(
            scenario,
            Schedule::empty(),
            checkpoint,
            Seed::from_u64(42),
        ))
        .await
        .expect("an authenticated runtime closure may share the genesis configuration");

    assert_eq!(report.configuration, configuration.id());
    assert_eq!(control_plane.session_count(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn resume_session_rejects_tampered_zero_time_baked_genesis() {
    let mut control_plane = lifecycle_control_plane();
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(scenario.scenario_def());
    let mut checkpoint = checkpoint_for_configuration(&configuration, VirtualTime::default());
    checkpoint
        .metadata
        .labels
        .insert(String::from("tampered"), String::from("true"));

    let error = control_plane
        .resume_session(ResumeSessionRequest::new(
            scenario,
            Schedule::empty(),
            checkpoint,
            Seed::from_u64(42),
        ))
        .await
        .expect_err("tampered baked genesis checkpoint material should reject");

    assert!(matches!(error, LifecycleApiError::ResumeCheckpoint { .. }));
    assert!(error.to_string().contains("baked genesis checkpoint"));
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn thin_replay_rejects_zero_time_genesis_with_injected_runtime_material() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-zero-time-genesis-tamper-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| RuntimeOnlyReplayLoop::new(),
    )
    .with_thin_replay_resume();
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(scenario.scenario_def());
    let mut checkpoint = checkpoint_for_configuration(&configuration, VirtualTime::default());
    checkpoint.node_icounts.insert(
        NodeId {
            name: String::from("injected"),
        },
        Icount { retired: 1 },
    );

    let error = control_plane
        .resume_session(ResumeSessionRequest::new(
            scenario,
            Schedule::empty(),
            checkpoint,
            Seed::from_u64(42),
        ))
        .await
        .expect_err("zero-time injected runtime material should reject");

    assert!(matches!(error, LifecycleApiError::ResumeCheckpoint { .. }));
    assert!(error.to_string().contains("baked genesis checkpoint"));
    assert_eq!(control_plane.session_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn thin_replay_resume_reaches_runtime_only_genesis_frontier() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-runtime-only-genesis-replay-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| RuntimeOnlyReplayLoop::new(),
    )
    .with_thin_replay_resume();
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(scenario.scenario_def());
    let checkpoint = checkpoint_for_configuration(&configuration, VirtualTime { ticks: 2 })
        .with_materialized_state(None);

    let resumed = control_plane
        .resume_session(ResumeSessionRequest::new(
            scenario,
            Schedule::empty(),
            checkpoint,
            Seed::from_u64(42),
        ))
        .await
        .unwrap_or_else(|error| panic!("runtime-only thin replay should resume: {error}"));

    assert_eq!(resumed.state, LiveStateKind::Paused);
    let summary = &control_plane.list_sessions().sessions[0];
    assert_eq!(summary.frontier, VirtualTime { ticks: 2 });
    assert_eq!(summary.quanta_stepped, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn thin_replay_resume_rejects_runtime_only_frontier_overshoot() {
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-runtime-only-genesis-overshoot-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| RuntimeOnlyReplayLoop::with_step(2),
    )
    .with_thin_replay_resume();
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(scenario.scenario_def());
    let checkpoint = checkpoint_for_configuration(&configuration, VirtualTime { ticks: 1 })
        .with_materialized_state(None);

    let error = control_plane
        .resume_session(ResumeSessionRequest::new(
            scenario,
            Schedule::empty(),
            checkpoint,
            Seed::from_u64(42),
        ))
        .await
        .expect_err("runtime-only thin replay must reject frontier overshoot");

    assert!(matches!(error, LifecycleApiError::ResumeCheckpoint { .. }));
    assert!(error.to_string().contains("thin replay diverged"));
    assert_eq!(control_plane.session_count(), 0);
}

#[path = "gate_lifecycle_unary/debugger_access.rs"]
mod debugger_access;
#[path = "gate_lifecycle_unary/replay_closure_rpc.rs"]
mod replay_closure_rpc;
#[path = "gate_lifecycle_unary/support.rs"]
mod support;

use support::*;
