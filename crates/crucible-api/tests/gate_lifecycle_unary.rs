//! API-side checks for discovery and lifecycle unary methods.

#![forbid(unsafe_code)]

use crucible::{QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef, SchedulerError, Seed};
use crucible_api::{
    ControlClient, CreateSessionRequest, DestroySessionRequest, HelloRequest,
    InProcessLifecycleClient, LIFECYCLE_SESSION_MAILBOX_CAPACITY, LifecycleApiError,
    LifecycleControlPlane, ListScenariosResponse, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION,
    ScenarioCatalogEntry,
};
use crucible_session::LiveStateKind;
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

fn lifecycle_control_plane()
-> LifecycleControlPlane<NoopLoop, impl Fn(&ScenarioDef, Seed) -> NoopLoop> {
    LifecycleControlPlane::new(
        "crucible-lifecycle-test-server",
        vec![catalog_entry()],
        |_scenario, _seed| NoopLoop,
    )
    .with_mailbox_capacity(LIFECYCLE_SESSION_MAILBOX_CAPACITY)
}

fn catalog_entry() -> ScenarioCatalogEntry {
    ScenarioCatalogEntry::from_canonical_material(
        "api-lifecycle-scenario",
        "Lifecycle unary API scenario",
        "test://api-lifecycle-scenario",
        "crucible.api.gate-lifecycle-unary.scenario",
        "scenario=api-lifecycle",
    )
}

struct NoopLoop;

impl QuantumLoop for NoopLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        panic!("lifecycle unary gate keeps sessions paused before any quantum")
    }
}

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.api.gate-lifecycle-unary.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}
