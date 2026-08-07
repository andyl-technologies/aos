//! API-side checks for discovery and lifecycle unary methods.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, Decision, DeliveryOrderDecision, GdbAttachInfo,
    GdbListen, Icount, NodeId, QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef,
    ScenarioDefForm, Schedule, SchedulerError, Seed, VirtualTime,
};
use crucible_api::{
    ControlClient, CreateSessionRequest, CreateSessionSource, DebugAuthorizationPolicy,
    DestroySessionRequest, HelloRequest, InProcessLifecycleClient,
    LIFECYCLE_SESSION_MAILBOX_CAPACITY, LifecycleApiError, LifecycleControlPlane,
    LifecycleLoopFactory, LifecycleServerMode, ListScenariosResponse, QuiescentLifecycleLoop,
    RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION, ResumeSessionRequest, RpcControlClient,
    RpcEndpoint, ScenarioCatalogEntry, SendRequest,
    serve_lifecycle_http2_with_debug_policy_until_shutdown,
};
use crucible_session::{
    DebugCapability, DebugClientId, DebugCoordinatorError, DebugRole, LiveStateKind, OutcomeKind,
    SessionCommand,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

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
async fn debugger_access_is_session_owned_and_generation_guarded() {
    let mut control_plane = lifecycle_control_plane();
    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(151),
        ))
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));
    let controller = DebugClientId::new("x509-sha256:controller")
        .unwrap_or_else(|error| panic!("controller identity should be valid: {error}"));
    let other = DebugClientId::new("x509-sha256:other")
        .unwrap_or_else(|error| panic!("other identity should be valid: {error}"));
    let controller_role = DebugRole::new([
        DebugCapability::Observe,
        DebugCapability::Control,
        DebugCapability::Mutate,
    ]);

    let lease = control_plane
        .acquire_debug_controller(created.session, controller.clone(), &controller_role)
        .unwrap_or_else(|error| panic!("controller should acquire lease: {error}"));
    let retry = control_plane
        .acquire_debug_controller(created.session, controller, &controller_role)
        .unwrap_or_else(|error| panic!("same controller retry should be idempotent: {error}"));
    assert_eq!(lease, retry);
    control_plane
        .authorize_debug_controller_operation(
            created.session,
            &lease,
            &controller_role,
            DebugCapability::Mutate,
        )
        .unwrap_or_else(|error| panic!("current lease should authorize mutate: {error}"));

    let busy = control_plane
        .acquire_debug_controller(created.session, other, &controller_role)
        .expect_err("a second controller must be rejected");
    assert!(matches!(
        busy,
        LifecycleApiError::DebugAccess {
            source: DebugCoordinatorError::ControllerBusy { .. }
        }
    ));

    control_plane
        .release_debug_controller(created.session, &lease)
        .unwrap_or_else(|error| panic!("current lease should release: {error}"));
    let stale = control_plane
        .release_debug_controller(created.session, &lease)
        .expect_err("released generation must be stale");
    assert!(matches!(
        stale,
        LifecycleApiError::DebugAccess {
            source: DebugCoordinatorError::StaleControllerLease
        }
    ));

    control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn trusted_http2_debug_controller_uses_server_side_identity_and_lease() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test listener should bind: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("test listener should have an address: {error}"));
    let mut policy = DebugAuthorizationPolicy::deny_all();
    policy.grant_trusted_unauthenticated_role(DebugRole::new([
        DebugCapability::Observe,
        DebugCapability::Control,
    ]));
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_lifecycle_http2_with_debug_policy_until_shutdown(
        listener,
        lifecycle_control_plane(),
        LifecycleServerMode::read_write(),
        policy,
        async move {
            let _ = shutdown_receiver.await;
        },
    ));
    let client = RpcControlClient::new(RpcEndpoint::http2(format!("http://{address}")))
        .unwrap_or_else(|error| panic!("test RPC client should build: {error}"));
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy-path scenario should build: {error}"))
        .scenario;
    let created = client
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC create should start session: {error}"));

    let lease = client
        .acquire_debug_controller(created.session)
        .await
        .unwrap_or_else(|error| panic!("trusted controller should acquire lease: {error}"));
    assert_eq!(lease.client.as_str(), "trusted-unauthenticated");
    assert_eq!(
        client
            .acquire_debug_controller(created.session)
            .await
            .unwrap_or_else(|error| panic!("lease retry should be idempotent: {error}")),
        lease
    );
    client
        .attach_debugger(
            created.session,
            &lease,
            &NodeId {
                name: String::from("server"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("controller should attach debugger: {error}"));
    client
        .attach_debugger(
            created.session,
            &lease,
            &NodeId {
                name: String::from("server"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("debug attach retry should be idempotent: {error}"));
    assert!(
        client
            .attach_debugger(
                created.session,
                &lease,
                &NodeId {
                    name: String::from("different-node"),
                },
            )
            .await
            .is_err(),
        "an attached debugger must reject a retry for a different node"
    );
    let repositioned = client
        .debug_goto(
            created.session,
            &lease,
            &crucible::DebugCoordinate::virtual_time(VirtualTime::default()),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("authenticated goto must dispatch through the actor: {error}")
        });
    assert_eq!(repositioned.landed.configuration.len(), 64);
    assert_eq!(repositioned.landed.runtime_state.len(), 64);
    assert_eq!(repositioned.landed.requested_coordinate, "virtual-time:0");
    assert_eq!(repositioned.landed.virtual_time_ticks, 0);
    assert_eq!(repositioned.landed.schedule_prefix_len, 0);
    assert_eq!(repositioned.landed.gateway_generation, 2);
    assert_eq!(repositioned.landed.retired_world_cleanup, "reaped");
    assert_eq!(repositioned.target_event_sequence, None);
    client
        .release_debug_controller(created.session, &lease)
        .await
        .unwrap_or_else(|error| panic!("current RPC lease should release: {error}"));
    assert!(
        client
            .release_debug_controller(created.session, &lease)
            .await
            .is_err(),
        "a released generation must be rejected as stale"
    );

    let _ = shutdown_sender.send(());
    server
        .await
        .unwrap_or_else(|error| panic!("server task should join: {error}"))
        .unwrap_or_else(|error| panic!("server should shut down cleanly: {error}"));
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
async fn direct_resume_rejects_runtime_only_genesis_checkpoint_material() {
    let mut control_plane = lifecycle_control_plane();
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    let configuration = Configuration::genesis(scenario.scenario_def());
    let checkpoint = checkpoint_for_configuration(&configuration, VirtualTime { ticks: 1 });

    let error = control_plane
        .resume_session(ResumeSessionRequest::new(
            scenario,
            Schedule::empty(),
            checkpoint,
            Seed::from_u64(42),
        ))
        .await
        .expect_err("direct resume must retain the true baked genesis root");

    assert!(matches!(error, LifecycleApiError::ResumeCheckpoint { .. }));
    assert!(error.to_string().contains("baked genesis checkpoint"));
    assert_eq!(control_plane.session_count(), 0);
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

#[path = "gate_lifecycle_unary/support.rs"]
mod support;

use support::*;
