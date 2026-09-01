//! Reference-client conformance helpers and wire-model assertions.

use super::*;

pub(super) fn assert_control_client_trait<C: ControlClient>(client: &C) {
    assert_eq!(client.wire_model(), ControlWireModel::current());
}

pub(super) fn assert_rpc_snapshot(name: &str, actual: &str, expected: &str) {
    assert_eq!(actual, expected, "RPC wire snapshot `{name}` drifted");
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReferenceClientConformanceReport {
    pub(super) backend: &'static str,
    pub(super) transport: ControlTransportKind,
    pub(super) command_statuses: Vec<CommandResultStatus>,
    pub(super) state_updates: Vec<LiveStateKind>,
    pub(super) reproduction_commands: Vec<SessionCommandKind>,
    pub(super) lifecycle: Vec<&'static str>,
}

impl ReferenceClientConformanceReport {
    pub(super) fn normalized(&self) -> ReferenceClientConformanceProjection {
        ReferenceClientConformanceProjection {
            command_statuses: self.command_statuses.clone(),
            state_updates: self.state_updates.clone(),
            reproduction_commands: self.reproduction_commands.clone(),
            lifecycle: self.lifecycle.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReferenceClientConformanceProjection {
    pub(super) command_statuses: Vec<CommandResultStatus>,
    pub(super) state_updates: Vec<LiveStateKind>,
    pub(super) reproduction_commands: Vec<SessionCommandKind>,
    pub(super) lifecycle: Vec<&'static str>,
}

pub(super) async fn run_reference_client_conformance<C>(
    client: &C,
    backend: &'static str,
) -> ReferenceClientConformanceReport
where
    C: ControlClient,
{
    let mut report = ReferenceClientConformanceReport {
        backend,
        transport: client.transport(),
        command_statuses: Vec::new(),
        state_updates: Vec::new(),
        reproduction_commands: Vec::new(),
        lifecycle: Vec::new(),
    };

    let hello = client
        .hello(HelloRequest::new(
            "api-control-client-test",
            RPC_PROTOCOL_VERSION,
        ))
        .await
        .unwrap_or_else(|error| panic!("{backend}: Hello should succeed: {error}"));
    assert_eq!(hello.version, RPC_PROTOCOL_VERSION);
    assert_eq!(hello.payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
    report.lifecycle.push("hello");

    let scenarios = client
        .list_scenarios()
        .await
        .unwrap_or_else(|error| panic!("{backend}: ListScenarios should succeed: {error}"));
    let scenario = scenarios
        .scenarios
        .first()
        .unwrap_or_else(|| panic!("{backend}: scenario catalog should not be empty"));
    report.lifecycle.push("list-scenarios");

    let seed = Seed::from_u64(13_013);
    let created = client
        .create_session(CreateSessionRequest::scenario_ref(&scenario.name, seed))
        .await
        .unwrap_or_else(|error| panic!("{backend}: CreateSession should succeed: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);
    let session = created.session;
    report.lifecycle.push("create-session-ref");

    let sessions = client
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("{backend}: ListSessions should succeed: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Paused);
    report.lifecycle.push("list-sessions");

    let mut control = client
        .control_attach(
            AttachRequest::new(session)
                .with_expected_epoch(session.epoch)
                .with_client_name(format!("reference-control-{backend}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{backend}: Control attach should succeed: {error}"));
    assert_eq!(control.attached().session, session);
    assert_eq!(control.attached().state, LiveStateKind::Paused);
    assert!(control.attached().snapshot.is_some());
    report.lifecycle.push("control-attach");

    let mut watch = client
        .watch_attach(
            AttachRequest::new(session)
                .with_expected_epoch(session.epoch)
                .with_client_name(format!("reference-watch-{backend}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{backend}: Watch attach should succeed: {error}"));
    assert_eq!(watch.attached().session, session);
    assert_eq!(watch.attached().state, LiveStateKind::Paused);
    assert_eq!(
        watch.attached().capabilities,
        control.attached().capabilities,
    );
    report.lifecycle.push("watch-attach");

    let continued = control
        .send_command(1, SessionCommand::Continue)
        .await
        .unwrap_or_else(|error| panic!("{backend}: Control Continue should succeed: {error}"));
    record_accepted_command(&mut report, &continued, Some(LiveStateKind::Running));
    report
        .state_updates
        .push(recv_control_state_update(&mut control, LiveStateKind::Running).await);
    report
        .state_updates
        .push(recv_watch_state_update(&mut watch, LiveStateKind::Running).await);

    let paused = client
        .send_command(SendRequest::new(session, 2, SessionCommand::Pause))
        .await
        .unwrap_or_else(|error| panic!("{backend}: Send Pause should succeed: {error}"));
    record_accepted_command(&mut report, &paused, Some(LiveStateKind::Paused));
    report
        .state_updates
        .push(recv_control_state_update(&mut control, LiveStateKind::Paused).await);
    report
        .state_updates
        .push(recv_watch_state_update(&mut watch, LiveStateKind::Paused).await);

    let step = client
        .send_command(SendRequest::new(
            session,
            3,
            representative_command(SessionCommandKind::StepQuantum),
        ))
        .await
        .unwrap_or_else(|error| panic!("{backend}: Send StepQuantum should succeed: {error}"));
    record_accepted_command(&mut report, &step, Some(LiveStateKind::Running));

    let settle = control
        .send_command(4, SessionCommand::Pause)
        .await
        .unwrap_or_else(|error| {
            panic!("{backend}: Control Pause after Step should succeed: {error}")
        });
    record_accepted_command(&mut report, &settle, None);

    let running = client
        .send_command(SendRequest::new(session, 5, SessionCommand::Continue))
        .await
        .unwrap_or_else(|error| {
            panic!("{backend}: Continue before controls should succeed: {error}")
        });
    record_accepted_command(&mut report, &running, Some(LiveStateKind::Running));

    for (command_id, command_kind) in [
        (6, SessionCommandKind::SetBreakpoint),
        (7, SessionCommandKind::RemoveBreakpoint),
        (8, SessionCommandKind::CreateSavepoint),
        (9, SessionCommandKind::Query),
    ] {
        let response = client
            .send_command(SendRequest::new(
                session,
                command_id,
                representative_command(command_kind),
            ))
            .await
            .unwrap_or_else(|error| {
                panic!("{backend}: Send {command_kind:?} should succeed: {error}")
            });
        record_accepted_command(&mut report, &response, None);
    }

    let fork = client
        .send_command(SendRequest::new(
            session,
            10,
            representative_command(SessionCommandKind::Fork),
        ))
        .await
        .unwrap_or_else(|error| panic!("{backend}: Send Fork should succeed: {error}"));
    record_accepted_command(&mut report, &fork, Some(LiveStateKind::Paused));

    let reproduction = client
        .get_reproduction(GetReproductionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| panic!("{backend}: GetReproduction should succeed: {error}"));
    report.reproduction_commands = reproduction
        .commands
        .iter()
        .map(|record| record.payload.command)
        .collect();
    for required in [
        SessionCommandKind::Pause,
        SessionCommandKind::SetBreakpoint,
        SessionCommandKind::RemoveBreakpoint,
        SessionCommandKind::CreateSavepoint,
        SessionCommandKind::Fork,
    ] {
        assert!(
            report.reproduction_commands.contains(&required),
            "{backend}: reproduction context should contain {required:?}"
        );
    }
    for excluded in [
        SessionCommandKind::Continue,
        SessionCommandKind::StepQuantum,
        SessionCommandKind::Query,
    ] {
        assert!(
            !report.reproduction_commands.contains(&excluded),
            "{backend}: reproduction context should exclude non-boundary/read-only {excluded:?}"
        );
    }
    report.lifecycle.push("get-reproduction");

    let stale_epoch = session.epoch.saturating_add(1);
    let stale_error = client
        .get_reproduction(GetReproductionRequest::new(session).with_expected_epoch(stale_epoch))
        .await
        .expect_err("stale reproduction epoch should reject");
    assert!(matches!(
        stale_error,
        ControlClientError::Lifecycle {
            source: LifecycleApiError::EpochMismatch { .. }
        }
    ));
    report.lifecycle.push("epoch-guard-rejection");

    let inline = generated_scenario(13_014);
    let inline_created = client
        .create_session(CreateSessionRequest::inline(inline.clone(), inline.seed()))
        .await
        .unwrap_or_else(|error| panic!("{backend}: inline CreateSession should succeed: {error}"));
    assert_eq!(inline_created.state, LiveStateKind::Paused);
    let inline_destroyed = client
        .destroy_session(
            DestroySessionRequest::new(inline_created.session)
                .with_expected_epoch(inline_created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("{backend}: inline DestroySession should succeed: {error}"));
    assert!(inline_destroyed.stopped);
    report.lifecycle.push("create-session-inline");

    let inline_form = resume_session_request(13_015).scenario;
    let inline_form_created = client
        .create_session(CreateSessionRequest::inline_form(
            inline_form.clone(),
            inline_form.seed(),
        ))
        .await
        .unwrap_or_else(|error| {
            panic!("{backend}: inline form CreateSession should succeed: {error}")
        });
    assert_eq!(inline_form_created.state, LiveStateKind::Paused);
    assert_eq!(inline_form_created.session.seed, inline_form.seed());
    let inline_form_destroyed = client
        .destroy_session(
            DestroySessionRequest::new(inline_form_created.session)
                .with_expected_epoch(inline_form_created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("{backend}: inline form DestroySession should succeed: {error}")
        });
    assert!(inline_form_destroyed.stopped);
    report.lifecycle.push("create-session-inline-form");

    drop(control);
    drop(watch);

    let destroyed = client
        .destroy_session(DestroySessionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| panic!("{backend}: DestroySession should succeed: {error}"));
    assert_eq!(destroyed.session, session);
    assert!(destroyed.stopped || destroyed.already_absent);
    report.lifecycle.push("destroy-session");

    let absent_destroy = client
        .destroy_session(DestroySessionRequest::new(session))
        .await
        .unwrap_or_else(|error| {
            panic!("{backend}: idempotent DestroySession should succeed: {error}")
        });
    assert!(absent_destroy.already_absent);
    report.lifecycle.push("destroy-session-idempotent");

    report
}

pub(super) fn record_accepted_command(
    report: &mut ReferenceClientConformanceReport,
    response: &SendResponse,
    expected_update: Option<LiveStateKind>,
) {
    assert_eq!(response.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        response.state_update.map(|update| update.state),
        expected_update
    );
    report.command_statuses.push(response.result.status);
}

pub(super) fn representative_command(command: SessionCommandKind) -> SessionCommand {
    if command == SessionCommandKind::Query {
        return query_state_command();
    }
    command
        .representative_command()
        .unwrap_or_else(|| panic!("{command:?} should have a representative command"))
}

pub(super) fn query_state_command() -> SessionCommand {
    SessionCommand::Query {
        kind: QueryKind::State,
        reply: CommandReply::discard(),
    }
}

pub(super) async fn recv_control_state_update(
    stream: &mut ClientControlStream,
    expected: LiveStateKind,
) -> LiveStateKind {
    for _ in 0..8 {
        let frame = tokio::time::timeout(Duration::from_millis(100), stream.recv_state_update())
            .await
            .unwrap_or_else(|_| panic!("Control state update {expected:?} should arrive"))
            .unwrap_or_else(|error| panic!("Control state update should decode: {error}"))
            .unwrap_or_else(|| panic!("Control state-update stream should remain open"));
        if frame.update.state == expected {
            return frame.update.state;
        }
    }
    panic!("Control state-update stream did not report {expected:?}");
}

pub(super) async fn recv_watch_state_update(
    stream: &mut ClientWatchStream,
    expected: LiveStateKind,
) -> LiveStateKind {
    for _ in 0..8 {
        let frame = tokio::time::timeout(Duration::from_millis(100), stream.recv_state_update())
            .await
            .unwrap_or_else(|_| panic!("Watch state update {expected:?} should arrive"))
            .unwrap_or_else(|error| panic!("Watch state update should decode: {error}"))
            .unwrap_or_else(|| panic!("Watch state-update stream should remain open"));
        if frame.update.state == expected {
            return frame.update.state;
        }
    }
    panic!("Watch state-update stream did not report {expected:?}");
}

pub(super) fn assert_reference_conformance_equivalent(
    left: &ReferenceClientConformanceReport,
    right: &ReferenceClientConformanceReport,
) {
    assert_eq!(
        left.normalized(),
        right.normalized(),
        "reference-client conformance diverged between {} and {}",
        left.backend,
        right.backend,
    );
}

pub(super) fn reference_lifecycle_control_plane<L, F>(
    server_name: &'static str,
    loop_factory: F,
) -> LifecycleControlPlane<L, LifecycleLoopFactory<L>>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Seed) -> L + Send + Sync + 'static,
{
    LifecycleControlPlane::new(
        server_name,
        vec![ScenarioCatalogEntry::from_canonical_material(
            "api-reference-conformance",
            "Reference client conformance scenario",
            "test://api-reference-conformance",
            "crucible.api.reference-conformance.scenario",
            "scenario=api-reference-conformance",
        )],
        loop_factory,
    )
}

pub(super) fn assert_qemu_node_implements_simulation_backend_contract() {
    fn assert_backend<T: SimulationBackend>() {}
    assert_backend::<crucible_qemu::QemuNode>();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ApiDeterminismTraffic {
    Quiet,
    Noisy,
}

impl ApiDeterminismTraffic {
    const fn is_noisy(self) -> bool {
        matches!(self, Self::Noisy)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ApiDeterminismProjection {
    pub(super) transport: ControlTransportKind,
    pub(super) final_state: LiveStateKind,
    pub(super) final_event_count: u64,
    pub(super) causal_event_count: u64,
    pub(super) observational_event_count: u64,
    pub(super) last_sequence: Option<u64>,
    pub(super) reproduction: Vec<ReproductionCommandRecord>,
    pub(super) mutating_results: Vec<ApiMutatingCommandResult>,
}

impl ApiDeterminismProjection {
    pub(super) fn normalized(&self) -> ApiDeterminismNormalizedProjection {
        ApiDeterminismNormalizedProjection {
            final_state: self.final_state,
            final_event_count: self.final_event_count,
            causal_event_count: self.causal_event_count,
            observational_event_count: self.observational_event_count,
            last_sequence: self.last_sequence,
            reproduction: self.reproduction.clone(),
            mutating_results: self.mutating_results.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ApiDeterminismNormalizedProjection {
    final_state: LiveStateKind,
    final_event_count: u64,
    causal_event_count: u64,
    observational_event_count: u64,
    last_sequence: Option<u64>,
    reproduction: Vec<ReproductionCommandRecord>,
    mutating_results: Vec<ApiMutatingCommandResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ApiMutatingCommandResult {
    command_id: u64,
    command: SessionCommandKind,
    status: CommandResultStatus,
    state_update: Option<LiveStateKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ApiCausalSubsequenceProjection {
    final_state: LiveStateKind,
    event_count: u64,
    causal_event_count: u64,
    observational_event_count: u64,
    last_sequence: Option<u64>,
    pub(super) causal_events: Vec<ApiCausalEventProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ApiCausalEventProjection {
    sequence: u64,
    virtual_time_ticks: u64,
    kind: String,
    source: String,
}

pub(super) async fn drive_api_nondeterminism_projection<C>(
    client: &C,
    traffic: ApiDeterminismTraffic,
) -> ApiDeterminismProjection
where
    C: ControlClient,
{
    let hello = client
        .hello(HelloRequest::new(
            "api-control-client-test",
            RPC_PROTOCOL_VERSION,
        ))
        .await
        .unwrap_or_else(|error| panic!("nondeterminism Hello should succeed: {error}"));
    assert_eq!(hello.version, RPC_PROTOCOL_VERSION);

    let scenarios = client
        .list_scenarios()
        .await
        .unwrap_or_else(|error| panic!("nondeterminism ListScenarios should succeed: {error}"));
    let scenario = scenarios
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "api-control-client-scenario")
        .unwrap_or_else(|| panic!("nondeterminism scenario should be registered"));
    let created = client
        .create_session(CreateSessionRequest::scenario_ref(
            &scenario.name,
            Seed::from_u64(30_014),
        ))
        .await
        .unwrap_or_else(|error| panic!("nondeterminism CreateSession should succeed: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);
    let session = created.session;

    let mut observer_controls = Vec::new();
    let mut observer_watches = Vec::new();
    if traffic.is_noisy() {
        attach_observer_load(
            client,
            session,
            &mut observer_controls,
            &mut observer_watches,
        )
        .await;
        assert_read_only_traffic_is_schedule_neutral(client, session, "before mutating controls")
            .await;
        simulate_wall_clock_gap_without_scheduler_input().await;
    }

    let before = read_api_determinism_observation(client, session, "before commands").await;
    assert_eq!(before.final_state, LiveStateKind::Paused);
    assert!(before.reproduction.is_empty());

    let mut mutating_results = Vec::new();
    for (command_id, command_kind) in [
        (10, SessionCommandKind::SetBreakpoint),
        (11, SessionCommandKind::CreateSavepoint),
    ] {
        if traffic.is_noisy() {
            assert_read_only_traffic_is_schedule_neutral(
                client,
                session,
                "between mutating controls",
            )
            .await;
            simulate_wall_clock_gap_without_scheduler_input().await;
        }

        let response = client
            .send_command(
                SendRequest::new(session, command_id, representative_command(command_kind))
                    .with_expected_epoch(session.epoch),
            )
            .await
            .unwrap_or_else(|error| {
                panic!("nondeterminism Send {command_kind:?} should succeed: {error}")
            });
        assert_eq!(response.result.command_id, command_id);
        assert_eq!(response.result.command_kind, command_kind);
        assert_eq!(response.result.status, CommandResultStatus::Accepted);
        mutating_results.push(ApiMutatingCommandResult {
            command_id,
            command: command_kind,
            status: response.result.status,
            state_update: response.state_update.map(|update| update.state),
        });
    }

    assert_read_only_traffic_is_schedule_neutral(client, session, "after mutating controls").await;
    let final_observation =
        read_api_determinism_observation(client, session, "after commands").await;
    assert_eq!(final_observation.final_state, LiveStateKind::Paused);
    assert!(
        final_observation.reproduction.is_empty(),
        "paused observation and savepoint-cache commands must not enter the running-boundary reproduction schedule"
    );
    for excluded in [
        SessionCommandKind::Query,
        SessionCommandKind::Start,
        SessionCommandKind::Continue,
        SessionCommandKind::SetBreakpoint,
        SessionCommandKind::CreateSavepoint,
    ] {
        assert!(
            !final_observation
                .reproduction
                .iter()
                .any(|record| record.payload.command == excluded),
            "read-only/non-boundary {excluded:?} must not enter reproduction"
        );
    }

    drop(observer_controls);
    drop(observer_watches);
    let destroyed = client
        .destroy_session(DestroySessionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| panic!("nondeterminism DestroySession should succeed: {error}"));
    assert_eq!(destroyed.session, session);
    assert!(destroyed.stopped || destroyed.already_absent);

    ApiDeterminismProjection {
        transport: client.transport(),
        final_state: final_observation.final_state,
        final_event_count: final_observation.final_event_count,
        causal_event_count: final_observation.causal_event_count,
        observational_event_count: final_observation.observational_event_count,
        last_sequence: final_observation.last_sequence,
        reproduction: final_observation.reproduction,
        mutating_results,
    }
}

pub(super) async fn drive_streaming_causal_subsequence_projection(
    traffic: ApiDeterminismTraffic,
) -> ApiCausalSubsequenceProjection {
    let (streaming, actor, session) =
        streaming_session_fixture(ServerQuantumLoop { quanta: 0 }, 30_115);
    let event_log_hub = actor.event_log();
    let actor_task = tokio::spawn(async move { actor.run().await });

    let mut observer_controls = Vec::new();
    let mut observer_watches = Vec::new();
    if traffic.is_noisy() {
        for index in 0..3 {
            observer_watches.push(
                streaming
                    .watch(
                        AttachRequest::new(session)
                            .with_cursor(EventLogCursor::new(0))
                            .with_client_name(format!("streaming-causal-watch-{index}")),
                    )
                    .unwrap_or_else(|error| {
                        panic!("streaming causal Watch observer should attach: {error}")
                    }),
            );
        }
        for index in 0..2 {
            observer_controls.push(
                streaming
                    .control(
                        AttachRequest::new(session)
                            .with_cursor(EventLogCursor::new(0))
                            .with_client_name(format!("streaming-causal-control-{index}")),
                    )
                    .unwrap_or_else(|error| {
                        panic!("streaming causal Control observer should attach: {error}")
                    }),
            );
        }
        let query = streaming
            .send(SendRequest::new(session, 7_900, query_state_command()))
            .await
            .unwrap_or_else(|error| panic!("streaming causal query should succeed: {error}"));
        assert_eq!(query.result.command_kind, SessionCommandKind::Query);
        assert_eq!(query.result.status, CommandResultStatus::Accepted);
    }

    let entries = event_burst(0, 7_000, 8);
    append_event_log_entries_for_test(&event_log_hub, &entries);
    let projection = capture_streaming_causal_projection(&streaming, session).await;

    drop(observer_controls);
    drop(observer_watches);
    stop_streaming_actor(streaming, session, 7_999, actor_task).await;
    projection
}

pub(super) async fn capture_streaming_causal_projection(
    streaming: &InProcessStreamingSession,
    session: SessionRef,
) -> ApiCausalSubsequenceProjection {
    let mut replay = streaming
        .watch(
            AttachRequest::new(session)
                .with_cursor(EventLogCursor::new(0))
                .with_client_name("streaming-causal-projection"),
        )
        .unwrap_or_else(|error| panic!("streaming causal replay should attach: {error}"));
    let attached = replay.attached().clone();
    let snapshot = attached
        .snapshot
        .as_ref()
        .unwrap_or_else(|| panic!("streaming causal replay should include a snapshot"));
    assert!(
        snapshot.causal_event_count > 0,
        "streaming causal projection should be non-vacuous"
    );

    let mut causal_events = Vec::new();
    for _ in 0..snapshot.event_count {
        let frame = tokio::time::timeout(Duration::from_millis(100), replay.recv_event())
            .await
            .unwrap_or_else(|_| panic!("streaming causal replay event should arrive"))
            .unwrap_or_else(|error| panic!("streaming causal replay event should decode: {error}"))
            .unwrap_or_else(|| panic!("streaming causal replay stream should stay open"));
        if !frame.event.observational {
            causal_events.push(ApiCausalEventProjection {
                sequence: frame.event.sequence,
                virtual_time_ticks: frame.event.at.virtual_time_ticks,
                kind: frame.event.payload.kind,
                source: format!("{:?}", frame.event.source),
            });
        }
    }
    assert_eq!(
        u64::try_from(causal_events.len()).unwrap_or(u64::MAX),
        snapshot.causal_event_count,
    );
    ApiCausalSubsequenceProjection {
        final_state: attached.state,
        event_count: snapshot.event_count,
        causal_event_count: snapshot.causal_event_count,
        observational_event_count: snapshot.observational_event_count,
        last_sequence: snapshot.last_sequence,
        causal_events,
    }
}

pub(super) async fn drive_rpc_arrival_permutation_projection(
    client: &RpcControlClient,
    server: &Http2LifecycleServer,
) -> ApiDeterminismProjection {
    let hello = client
        .hello(HelloRequest::new(
            "api-control-client-test",
            RPC_PROTOCOL_VERSION,
        ))
        .await
        .unwrap_or_else(|error| panic!("arrival-order Hello should succeed: {error}"));
    assert_eq!(hello.version, RPC_PROTOCOL_VERSION);
    let scenarios = client
        .list_scenarios()
        .await
        .unwrap_or_else(|error| panic!("arrival-order ListScenarios should succeed: {error}"));
    let scenario = scenarios
        .scenarios
        .first()
        .unwrap_or_else(|| panic!("arrival-order scenario should be registered"));
    let created = client
        .create_session(CreateSessionRequest::scenario_ref(
            &scenario.name,
            Seed::from_u64(30_014),
        ))
        .await
        .unwrap_or_else(|error| panic!("arrival-order CreateSession should succeed: {error}"));
    let session = created.session;

    let mut observer_controls = Vec::new();
    let mut observer_watches = Vec::new();
    attach_observer_load(
        client,
        session,
        &mut observer_controls,
        &mut observer_watches,
    )
    .await;

    let _ = server.take_arrivals().await;
    let read_before = client
        .clone()
        .get_reproduction(GetReproductionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| {
            panic!("arrival-order read-before-mutate GetReproduction should succeed: {error}")
        });
    assert!(read_before.commands.is_empty());
    let first_mutation = client
        .clone()
        .send_command(
            SendRequest::new(
                session,
                10,
                representative_command(SessionCommandKind::SetBreakpoint),
            )
            .with_expected_epoch(session.epoch),
        )
        .await;
    assert_eq!(
        first_mutation
            .unwrap_or_else(|error| panic!("arrival-order mutation should succeed: {error}"))
            .result
            .status,
        CommandResultStatus::Accepted,
    );
    assert_eq!(
        server.take_arrivals().await,
        vec!["get-reproduction", "send"],
        "RPC server should observe read-before-mutate order",
    );

    let hello_client = client.clone();
    let list_client = client.clone();
    let (hello, list_scenarios) = tokio::join!(
        hello_client.hello(HelloRequest::new(
            "api-control-client-test",
            RPC_PROTOCOL_VERSION,
        )),
        list_client.list_scenarios(),
    );
    assert_eq!(
        hello
            .unwrap_or_else(|error| panic!(
                "arrival-order concurrent Hello should succeed: {error}"
            ))
            .version,
        RPC_PROTOCOL_VERSION,
    );
    assert!(
        !list_scenarios
            .unwrap_or_else(|error| {
                panic!("arrival-order concurrent ListScenarios should succeed: {error}")
            })
            .scenarios
            .is_empty()
    );
    let _ = server.take_arrivals().await;

    let second_mutation = client
        .clone()
        .send_command(
            SendRequest::new(
                session,
                11,
                representative_command(SessionCommandKind::CreateSavepoint),
            )
            .with_expected_epoch(session.epoch),
        )
        .await;
    let read_after = client
        .clone()
        .get_reproduction(GetReproductionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| {
            panic!("arrival-order mutate-before-read GetReproduction should succeed: {error}")
        });
    assert!(
        read_after.commands.is_empty(),
        "paused observation and savepoint-cache commands must stay out of reproduction"
    );
    assert_eq!(
        server.take_arrivals().await,
        vec!["send", "get-reproduction"],
        "RPC server should observe mutate-before-read order",
    );

    let list_sessions_client = client.clone();
    let watch_client = client.clone();
    let query_client = client.clone();
    let (list_sessions, watch, query) = tokio::join!(
        list_sessions_client.list_sessions(),
        watch_client.watch_attach(
            AttachRequest::new(session)
                .with_expected_epoch(session.epoch)
                .with_client_name("arrival-order-watch"),
        ),
        query_client.send_command(
            SendRequest::new(session, 9_100, query_state_command())
                .with_expected_epoch(session.epoch),
        ),
    );
    assert_eq!(
        second_mutation
            .unwrap_or_else(|error| panic!("arrival-order mutation should succeed: {error}"))
            .result
            .status,
        CommandResultStatus::Accepted,
    );
    assert!(
        list_sessions
            .unwrap_or_else(|error| {
                panic!("arrival-order concurrent ListSessions should succeed: {error}")
            })
            .sessions
            .iter()
            .any(|summary| summary.session == session)
    );
    assert_eq!(
        watch
            .unwrap_or_else(|error| {
                panic!("arrival-order concurrent Watch should attach: {error}")
            })
            .attached()
            .session,
        session,
    );
    assert_eq!(
        query
            .unwrap_or_else(|error| panic!("arrival-order query should succeed: {error}"))
            .result
            .command_kind,
        SessionCommandKind::Query,
    );

    let final_observation =
        read_api_determinism_observation(client, session, "arrival-order final").await;
    let destroyed = client
        .destroy_session(DestroySessionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| panic!("arrival-order DestroySession should succeed: {error}"));
    assert_eq!(destroyed.session, session);

    ApiDeterminismProjection {
        transport: client.transport(),
        final_state: final_observation.final_state,
        final_event_count: final_observation.final_event_count,
        causal_event_count: final_observation.causal_event_count,
        observational_event_count: final_observation.observational_event_count,
        last_sequence: final_observation.last_sequence,
        reproduction: final_observation.reproduction,
        mutating_results: vec![
            ApiMutatingCommandResult {
                command_id: 10,
                command: SessionCommandKind::SetBreakpoint,
                status: CommandResultStatus::Accepted,
                state_update: None,
            },
            ApiMutatingCommandResult {
                command_id: 11,
                command: SessionCommandKind::CreateSavepoint,
                status: CommandResultStatus::Accepted,
                state_update: None,
            },
        ],
    }
}

pub(super) async fn attach_observer_load<C>(
    client: &C,
    session: SessionRef,
    observer_controls: &mut Vec<ClientControlStream>,
    observer_watches: &mut Vec<ClientWatchStream>,
) where
    C: ControlClient,
{
    for index in 0..3 {
        observer_watches.push(
            client
                .watch_attach(
                    AttachRequest::new(session)
                        .with_expected_epoch(session.epoch)
                        .with_cursor(EventLogCursor::new(0))
                        .with_client_name(format!("nondeterminism-watch-{index}")),
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("nondeterminism Watch observer should attach: {error}")
                }),
        );
    }
    for index in 0..2 {
        observer_controls.push(
            client
                .control_attach(
                    AttachRequest::new(session)
                        .with_expected_epoch(session.epoch)
                        .with_cursor(EventLogCursor::new(0))
                        .with_client_name(format!("nondeterminism-control-{index}")),
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("nondeterminism Control observer should attach: {error}")
                }),
        );
    }
}

pub(super) async fn assert_read_only_traffic_is_schedule_neutral<C>(
    client: &C,
    session: SessionRef,
    phase: &'static str,
) where
    C: ControlClient,
{
    let before = read_api_determinism_observation(client, session, phase).await;
    let hello = client
        .hello(HelloRequest::new(
            "api-control-client-test",
            RPC_PROTOCOL_VERSION,
        ))
        .await
        .unwrap_or_else(|error| panic!("{phase}: Hello should succeed: {error}"));
    assert_eq!(hello.version, RPC_PROTOCOL_VERSION);
    let scenarios = client
        .list_scenarios()
        .await
        .unwrap_or_else(|error| panic!("{phase}: ListScenarios should succeed: {error}"));
    assert!(
        scenarios
            .scenarios
            .iter()
            .any(|scenario| scenario.name == "api-control-client-scenario"),
        "{phase}: ListScenarios should observe the registered scenario"
    );
    let sessions = client
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("{phase}: ListSessions should succeed: {error}"));
    assert!(
        sessions
            .sessions
            .iter()
            .any(|summary| summary.session == session),
        "{phase}: ListSessions should observe the live session"
    );
    let query = client
        .send_command(
            SendRequest::new(
                session,
                9_000 + before.reproduction.len() as u64,
                query_state_command(),
            )
            .with_expected_epoch(session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("{phase}: query-class Send should succeed: {error}"));
    assert_eq!(query.result.command_kind, SessionCommandKind::Query);
    assert_eq!(query.result.status, CommandResultStatus::Accepted);
    assert!(query.state_update.is_none());

    let after = read_api_determinism_observation(client, session, phase).await;
    assert_eq!(
        before, after,
        "{phase}: read-only API traffic must not change state, event-log cursor, or reproduction"
    );
}

pub(super) async fn read_api_determinism_observation<C>(
    client: &C,
    session: SessionRef,
    phase: &'static str,
) -> ApiDeterminismProjection
where
    C: ControlClient,
{
    let sessions = client
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("{phase}: ListSessions should succeed: {error}"));
    let summary = sessions
        .sessions
        .iter()
        .find(|summary| summary.session == session)
        .unwrap_or_else(|| panic!("{phase}: live session should be listed"));
    let reproduction = client
        .get_reproduction(GetReproductionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| panic!("{phase}: GetReproduction should succeed: {error}"));
    let attached = client
        .watch_attach(
            AttachRequest::new(session)
                .with_expected_epoch(session.epoch)
                .with_cursor(EventLogCursor::new(u64::MAX))
                .with_client_name(format!("nondeterminism-snapshot-{phase}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{phase}: Watch snapshot should attach: {error}"))
        .attached()
        .clone();
    let snapshot = attached
        .snapshot
        .as_ref()
        .unwrap_or_else(|| panic!("{phase}: attach snapshot should be present"));
    assert_eq!(attached.session, session);
    assert_eq!(attached.event_log_len, summary.event_log_len);
    assert_eq!(snapshot.event_count, summary.event_log_len);
    assert_eq!(snapshot.reproduction, reproduction.commands);

    ApiDeterminismProjection {
        transport: client.transport(),
        final_state: summary.state,
        final_event_count: snapshot.event_count,
        causal_event_count: snapshot.causal_event_count,
        observational_event_count: snapshot.observational_event_count,
        last_sequence: snapshot.last_sequence,
        reproduction: reproduction.commands,
        mutating_results: Vec::new(),
    }
}

pub(super) async fn simulate_wall_clock_gap_without_scheduler_input() {
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
}

pub(super) fn assert_command_rejection_taxonomy_is_closed() {
    let mappings = [
        (
            CommandRejectionKind::InvalidState,
            RpcStatusCode::InvalidState,
        ),
        (CommandRejectionKind::NotFound, RpcStatusCode::NotFound),
        (
            CommandRejectionKind::InvalidArgument,
            RpcStatusCode::InvalidArgument,
        ),
        (
            CommandRejectionKind::Unsupported,
            RpcStatusCode::Unsupported,
        ),
        (CommandRejectionKind::Internal, RpcStatusCode::Internal),
    ];
    for (reason, status) in mappings {
        assert_eq!(reason.rpc_status(), status);
        assert_eq!(CommandRejectionKind::try_from(status), Ok(reason));
    }
    assert!(CommandRejectionKind::try_from(RpcStatusCode::Ok).is_err());
}

pub(super) fn raw_send_body(session: SessionRef, command_id: u64, command: &str) -> String {
    format!(
        "crucible.rpc/send-request\nsession-id={}\nepoch={}\nseed={}\nexpected-epoch=none\ncommand-id={}\ncommand={}\n",
        session.id.value,
        session.epoch,
        session.seed.to_hex(),
        command_id,
        command,
    )
}

pub(super) async fn assert_raw_send_error(
    endpoint: &str,
    body: String,
    expected_status: &str,
    expected_reason: &str,
) {
    let http = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap_or_else(|error| panic!("raw RPC client should build: {error}"));
    let response = http
        .post(format!(
            "{}/crucible.rpc/send",
            endpoint.trim_end_matches('/')
        ))
        .body(body)
        .send()
        .await
        .unwrap_or_else(|error| panic!("raw send request should complete: {error}"));
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let text = response
        .text()
        .await
        .unwrap_or_else(|error| panic!("raw send error body should decode: {error}"));
    assert!(text.starts_with("crucible.rpc/error\n"));
    assert!(text.contains(&format!("status={expected_status}\n")));
    assert!(text.contains(&format!("reason={expected_reason}\n")));
}

pub(super) async fn assert_raw_send_rejection(
    endpoint: &str,
    body: String,
    expected_command: &str,
    expected_status: &str,
) {
    let http = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap_or_else(|error| panic!("raw RPC client should build: {error}"));
    let response = http
        .post(format!(
            "{}/crucible.rpc/send",
            endpoint.trim_end_matches('/')
        ))
        .body(body)
        .send()
        .await
        .unwrap_or_else(|error| panic!("raw send request should complete: {error}"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let text = response
        .text()
        .await
        .unwrap_or_else(|error| panic!("raw send response body should decode: {error}"));
    assert!(text.starts_with("crucible.rpc/send-response\n"));
    assert!(text.contains(&format!("command={expected_command}\n")));
    assert!(text.contains(&format!("status=rejected:{expected_status}\n")));
    assert!(text.contains("state-update=none\n"));
}

pub(super) async fn assert_raw_send_accepted(endpoint: &str, body: String, expected_command: &str) {
    let http = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap_or_else(|error| panic!("raw RPC client should build: {error}"));
    let response = http
        .post(format!(
            "{}/crucible.rpc/send",
            endpoint.trim_end_matches('/')
        ))
        .body(body)
        .send()
        .await
        .unwrap_or_else(|error| panic!("raw send request should complete: {error}"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let text = response
        .text()
        .await
        .unwrap_or_else(|error| panic!("raw send response body should decode: {error}"));
    assert!(text.starts_with("crucible.rpc/send-response\n"));
    assert!(text.contains(&format!("command={expected_command}\n")));
    assert!(text.contains("status=accepted\n"));
    assert!(text.contains("breakpoint-id=none\n"));
    assert!(text.contains("savepoint-info=none\n"));
}

pub(super) fn assert_reproduction_pause_record(
    record: &ReproductionCommandRecord,
    at_sequence: u64,
) {
    assert_eq!(record.sequence, 1);
    assert_eq!(record.payload.command, SessionCommandKind::Pause);
    assert!(
        record
            .payload
            .command_payload
            .contains("payload=command-kind")
    );
    assert!(record.payload.command_payload.contains("command=Pause"));
    assert_eq!(record.payload.scheduler_batch, 0);
    assert!(record.payload.scheduler_control.is_none());
    assert_eq!(record.at_sequence, at_sequence);
    assert_eq!(record.result, ReproductionCommandResult::Accepted);
    assert_eq!(record.observational_order, record.sequence);
}

pub(super) async fn recv_rpc_control_event(
    stream: &mut crucible_api::ClientControlStream,
) -> StreamingEventFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_event())
        .await
        .unwrap_or_else(|_| panic!("RPC Control event should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Control event should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Control event stream should remain open"))
}

pub(super) async fn recv_rpc_control_state_update(
    stream: &mut crucible_api::ClientControlStream,
) -> StreamingStateUpdateFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_state_update())
        .await
        .unwrap_or_else(|_| panic!("RPC Control state update should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Control state update should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Control state update stream should remain open"))
}

pub(super) async fn recv_rpc_watch_event(
    stream: &mut crucible_api::ClientWatchStream,
) -> StreamingEventFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_event())
        .await
        .unwrap_or_else(|_| panic!("RPC Watch event should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Watch event should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Watch event stream should remain open"))
}

pub(super) async fn recv_rpc_watch_state_update(
    stream: &mut crucible_api::ClientWatchStream,
) -> StreamingStateUpdateFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_state_update())
        .await
        .unwrap_or_else(|_| panic!("RPC Watch state update should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Watch state update should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Watch state update stream should remain open"))
}
