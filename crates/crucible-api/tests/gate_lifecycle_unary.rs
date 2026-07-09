//! API-side checks for discovery and lifecycle unary methods.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, Decision, DeliveryOrderDecision, QuantumLoop,
    QuantumOutcome, QuantumRequest, ScenarioDef, ScenarioDefForm, Schedule, SchedulerError, Seed,
    VirtualTime,
};
use crucible_api::{
    ControlClient, CreateSessionRequest, CreateSessionSource, DestroySessionRequest, HelloRequest,
    InProcessLifecycleClient, LIFECYCLE_SESSION_MAILBOX_CAPACITY, LifecycleApiError,
    LifecycleControlPlane, LifecycleLoopFactory, ListScenariosResponse, RPC_OPEN_SET_PAYLOAD_KINDS,
    RPC_PROTOCOL_VERSION, ResumeSessionRequest, ScenarioCatalogEntry,
};
use crucible_session::LiveStateKind;
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
async fn resume_session_rejects_non_baked_genesis_checkpoint_material() {
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
        .expect_err("non-baked genesis checkpoint material should reject");

    assert!(matches!(error, LifecycleApiError::ResumeCheckpoint { .. }));
    assert!(error.to_string().contains("baked genesis checkpoint"));
    assert_eq!(control_plane.session_count(), 0);
}

fn lifecycle_control_plane() -> LifecycleControlPlane<NoopLoop, LifecycleLoopFactory<NoopLoop>> {
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

fn resume_request(seed: u64) -> ResumeSessionRequest {
    let mut scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    if scenario.seed() != Seed::from_u64(seed) {
        scenario = scenario_with_seed(&scenario, Seed::from_u64(seed));
    }
    let scenario_def = scenario.scenario_def();
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let configuration = Configuration {
        def: scenario_def,
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_configuration(&configuration, VirtualTime { ticks: 1 });
    ResumeSessionRequest::new(scenario, schedule, checkpoint, Seed::from_u64(seed))
}

fn scenario_with_seed(scenario: &ScenarioDefForm, seed: Seed) -> ScenarioDefForm {
    ScenarioDefForm::from_components_with_app_random_draw_cap(
        scenario.world(),
        scenario.plan(),
        scenario.properties(),
        seed,
        scenario.app_random_draw_cap(),
    )
    .unwrap_or_else(|error| panic!("test scenario should rebuild with seed: {error}"))
}

fn checkpoint_for_configuration(
    configuration: &Configuration,
    frontier: VirtualTime,
) -> Checkpoint {
    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        let prefix = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .unwrap_or_else(|error| panic!("test schedule prefix should exist: {error}"));
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: prefix,
        })
    };
    Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        frontier,
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("test checkpoint should record configuration: {error}"))
}
