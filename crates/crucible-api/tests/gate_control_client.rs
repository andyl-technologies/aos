//! API-side checks for the shared `ControlClient` trait.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use crucible::test_support::condition_payload_entry_for_test;
use crucible::{
    BackendError, Checkpoint, CheckpointKind, Configuration, ContentHash, ControlOperationKind,
    Decision, DeliveryOrderDecision, EventAttributeValue, EventDiagnosticPayload, EventLevel,
    EventLogOffset, GdbAttachInfo, GdbListen, GenesisCheckpoint, NodeId, QuantumLoop,
    QuantumOutcome, QuantumRequest, RngDecision, RngStreamId, ScenarioDef, ScenarioDefForm,
    Schedule, SchedulerError, SchedulerEventLogEntry, SchedulerEventLogPayload, Seed, SimDouble,
    SimDoubleConfig, SimulationBackend, TemporalGraph, VirtualTime,
};
use crucible_api::{
    API_COMMAND_MAPPINGS, AttachRequest, AttachSnapshot, Attached, ClientControlStream,
    ClientWatchStream, CommandRejectionKind, CommandResult, CommandResultStatus, ControlClient,
    ControlClientError, ControlPlaneEventLog, ControlStream, ControlTransportKind,
    ControlWireModel, CreateSessionRequest, CreateSessionResponse, DestroySessionRequest,
    DestroySessionResponse, EventLogCursor, GOLDEN_RPC_VECTORS, GetReproductionRequest,
    GetReproductionResponse, HelloRequest, InProcessControlClient, InProcessLifecycleClient,
    InProcessStreamingSession, LifecycleApiError, LifecycleControlPlane, LifecycleLoopFactory,
    LifecycleServerMode, ListScenariosResponse, ListSessionsResponse, OpenSetAttributeValue,
    OpenSetEventEnvelope, OpenSetEventSource, OpenSetEventTime, OpenSetPayload,
    QuiescentLifecycleLoop, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION,
    ReproductionCommandPayload, ReproductionCommandRecord, ReproductionCommandResult,
    ResumeSessionRequest, ResumeSessionResponse, RpcControlClient, RpcEndpoint, RpcStatusCode,
    RpcTransportProtocol, ScenarioCatalogEntry, ScenarioSummary, SendRequest, SendResponse,
    SessionId, SessionRef, SessionSummary, StateUpdate, StreamingApiError, StreamingCapabilitySet,
    StreamingEventFrame, StreamingFrame, StreamingStateUpdateFrame, WatchStream,
    assert_shared_wire_model, encode_rpc_hello_request, encode_rpc_hello_response,
    open_set_command_kind, rpc_status_code_wire_name, serve_lifecycle_http2,
    serve_lifecycle_http2_with_mode_until_shutdown, session_command_for_open_set_command_kind,
};
use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
use crucible_session::test_support::append_event_log_entries_for_test;
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, BreakpointSpec, CheckpointRef, CommandReply, Engine,
    EngineState, LifecycleStateKind, LiveStateKind, OutcomeKind, QueryKind, QueryResult,
    SessionActor, SessionCommand, SessionCommandKind, SessionError, SessionRunReport,
};
use futures_util::stream;
use tokio::sync::{Mutex, mpsc, oneshot};

#[tokio::test(flavor = "current_thread")]
async fn control_client_trait_is_transport_agnostic_over_in_process_and_rpc() {
    let (in_process, _actor) = in_process_client_fixture();
    let rpc_server = spawn_http2_hello_server().await;
    let rpc = RpcControlClient::new(RpcEndpoint::http2(rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("HTTP/2 RPC client should build: {error}"));

    assert_control_client_trait(&in_process);
    assert_control_client_trait(&rpc);
    assert_eq!(in_process.transport(), ControlTransportKind::InProcess);
    assert_eq!(rpc.transport(), ControlTransportKind::Http2Rpc);
    assert_eq!(rpc.endpoint().protocol(), RpcTransportProtocol::Http2);
    assert!(in_process.reaches_same_process_actor_without_serialization());

    let shared_model = assert_shared_wire_model(&in_process, &rpc)
        .unwrap_or_else(|error| panic!("client transports should share one wire model: {error}"));
    assert_eq!(shared_model, ControlWireModel::current());

    let request = HelloRequest::new("api-control-client-test", RPC_PROTOCOL_VERSION);
    assert_eq!(
        shared_model.encode_hello_request(&request),
        encode_rpc_hello_request("api-control-client-test", RPC_PROTOCOL_VERSION)
    );
    let in_process_hello = in_process
        .hello(request.clone())
        .await
        .unwrap_or_else(|error| panic!("in-process hello should negotiate: {error}"));
    let rpc_hello = rpc
        .hello(request)
        .await
        .unwrap_or_else(|error| panic!("RPC hello should negotiate: {error}"));

    assert_eq!(in_process_hello.version, RPC_PROTOCOL_VERSION);
    assert_eq!(rpc_hello.version, RPC_PROTOCOL_VERSION);
    assert_eq!(in_process_hello.payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
    assert_eq!(rpc_hello.payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
    assert_eq!(
        shared_model.encode_hello_response(&rpc_hello),
        encode_rpc_hello_response(
            &rpc_hello.server_name,
            RPC_PROTOCOL_VERSION,
            RPC_OPEN_SET_PAYLOAD_KINDS,
        )
    );
    let scenarios = rpc
        .list_scenarios()
        .await
        .unwrap_or_else(|error| panic!("RPC list scenarios should decode: {error}"));
    assert_eq!(scenarios.scenarios.len(), 1);
    assert_eq!(scenarios.scenarios[0].name, "api-control-client-scenario");
    assert_command_rejection_taxonomy_is_closed();

    let missing_scenario_error = rpc
        .create_session(CreateSessionRequest::scenario_ref(
            "missing-api-control-client-scenario",
            Seed::from_u64(77),
        ))
        .await
        .expect_err("RPC unknown scenario should decode as typed NOT_FOUND");
    assert_eq!(
        missing_scenario_error,
        ControlClientError::Lifecycle {
            source: LifecycleApiError::ScenarioNotFound {
                name: String::from("missing-api-control-client-scenario"),
            },
        },
    );

    let created = rpc
        .create_session(
            CreateSessionRequest::scenario_ref("api-control-client-scenario", Seed::from_u64(77))
                .with_start_paused(false),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC create session should decode: {error}"));
    assert_eq!(created.state, LiveStateKind::Running);
    assert_eq!(created.session.id.value, 1);
    assert_eq!(created.session.epoch, 1);
    assert_eq!(created.session.seed, Seed::from_u64(77));
    assert_raw_send_error(
        rpc_server.endpoint(),
        raw_send_body(created.session, 901, "crucible.cmd.no-such-command"),
        "unsupported",
        "unsupported",
    )
    .await;
    assert_raw_send_error(
        rpc_server.endpoint(),
        String::from(
            "crucible.rpc/send-request\nsession-id=not-an-integer\nepoch=1\nseed=00\nexpected-epoch=none\ncommand-id=902\ncommand=crucible.cmd.continue\n",
        ),
        "invalid-argument",
        "invalid-argument",
    )
    .await;

    let sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC list sessions should decode: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Running);

    let pre_attach_paused = rpc
        .send_command(SendRequest::new(
            created.session,
            100,
            SessionCommand::Pause,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC pre-attach Pause should decode: {error}"));
    assert_eq!(
        pre_attach_paused.result.status,
        CommandResultStatus::Accepted
    );
    assert_eq!(
        pre_attach_paused.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused),
    );
    let paused_sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC paused list sessions should decode: {error}"));
    assert_eq!(paused_sessions.sessions[0].state, LiveStateKind::Paused);
    let control_replay_start = paused_sessions.sessions[0].event_log_len;
    let reproduction = rpc
        .get_reproduction(
            GetReproductionRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC GetReproduction should decode: {error}"));
    assert_eq!(reproduction.session, created.session);
    assert_eq!(reproduction.commands.len(), 1);
    assert_reproduction_pause_record(&reproduction.commands[0], control_replay_start);
    rpc_server
        .append_session_events(created.session, &event_pair(control_replay_start, 301))
        .await;

    let mut control = rpc
        .control_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_cursor(EventLogCursor::new(control_replay_start)),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC Control attach should decode: {error}"));
    let control_attached = control.attached().clone();
    assert_eq!(control_attached.session, created.session);
    assert_eq!(control_attached.state, LiveStateKind::Paused);
    assert_eq!(
        control_attached.event_log_len,
        control_replay_start.saturating_add(2),
    );
    assert_eq!(
        control_attached
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.event_count),
        Some(control_replay_start.saturating_add(2)),
    );
    assert_eq!(
        control_attached
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.reproduction.clone()),
        Some(reproduction.commands.clone()),
    );
    assert_eq!(
        control_attached.capabilities.commands.len(),
        SessionCommandKind::ALL.len(),
    );
    let control_replay = recv_rpc_control_event(&mut control).await;
    assert_eq!(
        control_replay.cursor,
        EventLogCursor::new(control_replay_start)
    );
    assert_eq!(control_replay.event.payload.kind, "crucible.event.rng_draw",);
    assert!(!control_replay.event.observational);
    let control_replay_observational = recv_rpc_control_event(&mut control).await;
    assert_eq!(
        control_replay_observational.cursor,
        EventLogCursor::new(control_replay_start.saturating_add(1)),
    );
    assert!(control_replay_observational.event.observational);
    let control_live_start = control_attached.event_log_len;
    rpc_server
        .append_session_events(created.session, &event_pair(control_live_start, 302))
        .await;
    let control_live = recv_rpc_control_event(&mut control).await;
    assert_eq!(control_live.cursor, EventLogCursor::new(control_live_start));
    assert_eq!(control_live.event.sequence, control_live_start);

    let control_continued = rpc
        .control_send(SendRequest::new(
            created.session,
            101,
            SessionCommand::Continue,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Control send should decode: {error}"));
    assert_eq!(control_continued.result.command_id, 101);
    assert_eq!(
        control_continued.result.status,
        CommandResultStatus::Accepted
    );
    assert_eq!(
        control_continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running),
    );
    let control_running_update = recv_rpc_control_state_update(&mut control).await;
    assert_eq!(control_running_update.update.session, created.session);
    assert_eq!(control_running_update.update.state, LiveStateKind::Running);

    let control_paused = rpc
        .control_send(SendRequest::new(
            created.session,
            102,
            SessionCommand::Pause,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Control Pause should decode: {error}"));
    assert_eq!(control_paused.result.command_id, 102);
    assert_eq!(control_paused.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        control_paused.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused),
    );
    let control_paused_update = recv_rpc_control_state_update(&mut control).await;
    assert_eq!(control_paused_update.update.session, created.session);
    assert_eq!(control_paused_update.update.state, LiveStateKind::Paused);
    assert!(
        control_paused_update.sequence > control_running_update.sequence,
        "Control state updates should be monotone",
    );

    let watch_replay_start = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC list before Watch attach should decode: {error}"))
        .sessions[0]
        .event_log_len;
    let mut watch = rpc
        .watch_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_cursor(EventLogCursor::new(watch_replay_start)),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC Watch attach should decode: {error}"));
    let watch_attached = watch.attached().clone();
    assert_eq!(watch_attached.session, created.session);
    assert_eq!(watch_attached.state, LiveStateKind::Paused);
    assert_eq!(watch_attached.capabilities, control_attached.capabilities);
    assert_eq!(watch_attached.event_log_len, watch_replay_start);
    let quiet_watch = tokio::time::timeout(Duration::from_millis(10), watch.recv_event()).await;
    assert!(
        quiet_watch.is_err(),
        "Watch cursor at tail should not replay"
    );
    rpc_server
        .append_session_events(created.session, &event_pair(watch_replay_start, 303))
        .await;
    let watch_live = recv_rpc_watch_event(&mut watch).await;
    assert_eq!(watch_live.cursor, EventLogCursor::new(watch_replay_start));
    assert_eq!(watch_live.event.payload.kind, "crucible.event.rng_draw");
    let watch_burst_start = watch_replay_start.saturating_add(2);
    rpc_server
        .append_session_events(created.session, &event_burst(watch_burst_start, 304, 10))
        .await;

    let send_continued = rpc
        .send_command(SendRequest::new(
            created.session,
            103,
            SessionCommand::Continue,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Send should decode: {error}"));
    assert_eq!(send_continued.result.command_id, 103);
    assert_eq!(send_continued.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        send_continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running),
    );
    let watch_running_update = recv_rpc_watch_state_update(&mut watch).await;
    assert_eq!(watch_running_update.update.session, created.session);
    assert_eq!(watch_running_update.update.state, LiveStateKind::Running);

    let rejected_start = rpc
        .send_command(SendRequest::new(
            created.session,
            104,
            SessionCommand::Start,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Send rejection should decode: {error}"));
    assert_eq!(
        rejected_start.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::InvalidState,
        },
    );
    assert!(rejected_start.state_update.is_none());

    let rejected_remove = rpc
        .send_command(SendRequest::new(
            created.session,
            105,
            SessionCommandKind::RemoveBreakpoint
                .representative_command()
                .unwrap_or_else(|| panic!("RemoveBreakpoint has a representative payload")),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Send RemoveBreakpoint should decode: {error}"));
    assert_eq!(
        rejected_remove.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::NotFound,
        },
    );
    assert!(rejected_remove.state_update.is_none());
    assert_raw_send_rejection(
        rpc_server.endpoint(),
        raw_send_body(created.session, 106, "crucible.cmd.remove-breakpoint"),
        "crucible.cmd.remove-breakpoint",
        "not-found",
    )
    .await;

    let stream_stopped = rpc
        .send_command(SendRequest::new(created.session, 107, SessionCommand::Stop))
        .await
        .unwrap_or_else(|error| panic!("RPC Send Stop should decode: {error}"));
    assert_eq!(stream_stopped.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        stream_stopped.state_update.map(|update| update.state),
        Some(LiveStateKind::Stopped),
    );

    let destroyed = rpc
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("RPC destroy after streaming Stop should decode: {error}"));
    assert_eq!(destroyed.session, created.session);
    assert!(!destroyed.stopped);
    assert!(destroyed.already_absent);

    let missing_reproduction_error = rpc
        .get_reproduction(GetReproductionRequest::new(created.session))
        .await
        .expect_err("RPC GetReproduction on absent session should decode as typed NOT_FOUND");
    assert_eq!(
        missing_reproduction_error,
        ControlClientError::Lifecycle {
            source: LifecycleApiError::SessionNotFound {
                session: created.session,
            },
        },
    );
    let missing_watch_error = match rpc.watch_attach(AttachRequest::new(created.session)).await {
        Ok(_) => panic!("RPC Watch on absent session should reject"),
        Err(error) => error,
    };
    assert_eq!(
        missing_watch_error,
        ControlClientError::Streaming {
            source: StreamingApiError::SessionNotFound {
                session: created.session,
            },
        },
    );

    let inline_scenario = generated_scenario(78);
    let inline_created = rpc
        .create_session(CreateSessionRequest::inline(
            inline_scenario.clone(),
            inline_scenario.seed(),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC inline create session should decode: {error}"));
    assert_eq!(inline_created.state, LiveStateKind::Paused);
    assert_eq!(inline_created.session.id.value, 2);
    assert_eq!(inline_created.session.epoch, 2);
    assert_eq!(inline_created.session.seed, inline_scenario.seed());

    let inline_sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC inline list sessions should decode: {error}"));
    assert_eq!(inline_sessions.sessions.len(), 1);
    assert_eq!(inline_sessions.sessions[0].session, inline_created.session);
    assert_eq!(inline_sessions.sessions[0].state, LiveStateKind::Paused);

    let resume_request = resume_session_request(79);
    let expected_resume_checkpoint = resume_request.checkpoint.id;
    let expected_resume_scenario = resume_request.scenario.scenario_def();
    let expected_resume_configuration = Configuration {
        def: expected_resume_scenario,
        schedule: resume_request.schedule.clone(),
    }
    .id();
    let resumed = rpc
        .resume_session(resume_request)
        .await
        .unwrap_or_else(|error| panic!("RPC resume session should decode: {error}"));
    assert_eq!(resumed.state, LiveStateKind::Paused);
    assert_eq!(resumed.checkpoint, expected_resume_checkpoint);
    assert_eq!(resumed.configuration, expected_resume_configuration);
    assert_eq!(resumed.session.id.value, 3);
    assert_eq!(resumed.session.epoch, 3);
    assert_eq!(resumed.session.seed, Seed::from_u64(79));
    let resume_sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC resume list sessions should decode: {error}"));
    assert!(
        resume_sessions
            .sessions
            .iter()
            .any(|summary| summary.session == resumed.session
                && summary.state == LiveStateKind::Paused
                && summary.frontier == VirtualTime { ticks: 1 })
    );
    let resumed_destroyed = rpc
        .destroy_session(
            DestroySessionRequest::new(resumed.session).with_expected_epoch(resumed.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC resumed destroy session should decode: {error}"));
    assert!(resumed_destroyed.stopped);

    let injected_fault = rpc
        .send_command(SendRequest::new(
            inline_created.session,
            198,
            SessionCommandKind::InjectFault
                .representative_command()
                .expect("InjectFault has a representative payload"),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC InjectFault should decode: {error}"));
    assert_eq!(injected_fault.result.status, CommandResultStatus::Accepted);
    let healed_fault = rpc
        .send_command(SendRequest::new(
            inline_created.session,
            199,
            SessionCommandKind::HealFault
                .representative_command()
                .expect("HealFault has a representative payload"),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC HealFault should decode: {error}"));
    assert_eq!(healed_fault.result.status, CommandResultStatus::Accepted);
    let fault_reproduction = rpc
        .get_reproduction(GetReproductionRequest::new(inline_created.session))
        .await
        .unwrap_or_else(|error| panic!("RPC fault reproduction should decode: {error}"));
    assert_eq!(fault_reproduction.commands.len(), 2);
    assert_fault_reproduction_records(&fault_reproduction.commands);

    let stale_epoch = inline_created.session.epoch.saturating_add(1);
    let stale_watch_error = match rpc
        .watch_attach(AttachRequest::new(inline_created.session).with_expected_epoch(stale_epoch))
        .await
    {
        Ok(_) => panic!("RPC Watch attach stale epoch should be typed"),
        Err(error) => error,
    };
    assert_eq!(
        stale_watch_error,
        crucible_api::ControlClientError::Streaming {
            source: StreamingApiError::EpochMismatch {
                expected: stale_epoch,
                actual: inline_created.session.epoch,
            },
        },
    );

    let stale_send_error = rpc
        .send_command(
            SendRequest::new(inline_created.session, 200, SessionCommand::Continue)
                .with_expected_epoch(stale_epoch),
        )
        .await
        .expect_err("RPC Send stale epoch should be typed");
    assert_eq!(
        stale_send_error,
        crucible_api::ControlClientError::Streaming {
            source: StreamingApiError::EpochMismatch {
                expected: stale_epoch,
                actual: inline_created.session.epoch,
            },
        },
    );

    let stale_destroy_error = rpc
        .destroy_session(
            DestroySessionRequest::new(inline_created.session).with_expected_epoch(stale_epoch),
        )
        .await
        .expect_err("RPC DestroySession stale epoch should be typed");
    assert_eq!(
        stale_destroy_error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::EpochMismatch {
                session_id: inline_created.session.id,
                expected: inline_created.session.epoch,
                actual: stale_epoch,
            },
        },
    );

    let stale_reproduction_error = rpc
        .get_reproduction(
            GetReproductionRequest::new(inline_created.session).with_expected_epoch(stale_epoch),
        )
        .await
        .expect_err("RPC GetReproduction stale epoch should be typed");
    assert_eq!(
        stale_reproduction_error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::EpochMismatch {
                session_id: inline_created.session.id,
                expected: inline_created.session.epoch,
                actual: stale_epoch,
            },
        },
    );

    let inline_destroyed = rpc
        .destroy_session(
            DestroySessionRequest::new(inline_created.session)
                .with_expected_epoch(inline_created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC inline destroy session should decode: {error}"));
    assert_eq!(inline_destroyed.session, inline_created.session);
    assert!(inline_destroyed.stopped);
    assert!(!inline_destroyed.already_absent);

    let mismatch_error = rpc
        .create_session(CreateSessionRequest::inline(
            generated_scenario(108),
            Seed::from_u64(109),
        ))
        .await
        .expect_err("RPC inline seed mismatch should reject");
    assert!(matches!(
        mismatch_error,
        ControlClientError::RpcStatus {
            status: RpcStatusCode::InvalidArgument,
            ref message,
        } if message.contains("scenario seed mismatch")
    ));
    let sessions_after_rejected_inline = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC list after rejected inline should decode: {error}"));
    assert!(sessions_after_rejected_inline.sessions.is_empty());

    assert!(rpc_server.saw_http2_request().await);
    assert_eq!(
        in_process.live_snapshot().read().event_log_len,
        in_process.event_log().current_cursor().next_sequence
    );
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_lifecycle_control_stream_stop_cleans_registry() {
    let client = InProcessLifecycleClient::new(lifecycle_control_plane());
    let created = client
        .create_session(
            CreateSessionRequest::scenario_ref(
                "api-control-client-scenario",
                Seed::from_u64(30_516),
            )
            .with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("in-process CreateSession should succeed: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);

    let control = client
        .control_attach(
            AttachRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("in-process Control attach should succeed: {error}"));
    let stopped = control
        .send_command(30_517, SessionCommand::Stop)
        .await
        .unwrap_or_else(|error| panic!("in-process Control Stop should clean up: {error}"));
    assert_eq!(stopped.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        stopped.state_update.map(|update| update.state),
        Some(LiveStateKind::Stopped),
    );

    let sessions = client.list_sessions().await.unwrap_or_else(|error| {
        panic!("in-process list after Control Stop should succeed: {error}")
    });
    assert!(
        sessions.sessions.is_empty(),
        "accepted in-process Control Stop should remove session: {:?}",
        sessions.sessions
    );
    let destroyed = client
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| {
            panic!("idempotent destroy after Control Stop should succeed: {error}")
        });
    assert_eq!(destroyed.session, created.session);
    assert!(destroyed.already_absent);
    assert!(!destroyed.stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn production_http2_lifecycle_server_hosts_rpc_control_surface() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 listener should bind: {error}"));
    let addr = listener.local_addr().unwrap_or_else(|error| {
        panic!("production HTTP/2 listener should report address: {error}")
    });
    let control_plane = LifecycleControlPlane::new(
        "production-http2-lifecycle-server",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let server = tokio::spawn(async move { serve_lifecycle_http2(listener, control_plane).await });

    let rpc = RpcControlClient::new(RpcEndpoint::http2(format!("http://{addr}")))
        .unwrap_or_else(|error| panic!("production HTTP/2 RPC client should build: {error}"));
    let hello = rpc
        .hello(HelloRequest::new(
            "production-http2-lifecycle-client",
            RPC_PROTOCOL_VERSION,
        ))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 hello should decode: {error}"));
    assert_eq!(hello.server_name, "production-http2-lifecycle-server");

    let scenario = generated_scenario(91);
    let created = rpc
        .create_session(
            CreateSessionRequest::inline(scenario.clone(), scenario.seed()).with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 create should decode: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);

    let control = rpc
        .control_attach(
            AttachRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 control attach should decode: {error}"));
    assert_eq!(control.attached().session, created.session);
    let query = control
        .send_command(1, query_state_command())
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 control send should decode: {error}"));
    assert_eq!(query.result.status, CommandResultStatus::Accepted);
    assert_raw_send_accepted(
        &format!("http://{addr}"),
        format!(
            "{}query=snapshot\n",
            raw_send_body(created.session, 2, "crucible.cmd.query")
        ),
        "crucible.cmd.query",
    )
    .await;
    assert_raw_send_accepted(
        &format!("http://{addr}"),
        format!(
            "{}query=breakpoint-firings\n",
            raw_send_body(created.session, 3, "crucible.cmd.query")
        ),
        "crucible.cmd.query",
    )
    .await;

    let sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 list sessions should decode: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Paused);

    let destroyed = rpc
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 destroy should decode: {error}"));
    assert!(destroyed.stopped);
    server.abort();
    match server.await {
        Err(error) if error.is_cancelled() => {}
        other => panic!("production HTTP/2 server task should abort cleanly: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_http2_lifecycle_server_admits_concurrent_watch_and_query_clients() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 listener should bind: {error}"));
    let addr = listener.local_addr().unwrap_or_else(|error| {
        panic!("production HTTP/2 listener should report address: {error}")
    });
    let control_plane = LifecycleControlPlane::new(
        "production-http2-multi-client-server",
        Vec::new(),
        test_loop_factory as fn(&ScenarioDef, Seed) -> ServerQuantumLoop,
    );
    let server = tokio::spawn(async move { serve_lifecycle_http2(listener, control_plane).await });

    let endpoint = RpcEndpoint::http2(format!("http://{addr}"));
    let rpc = RpcControlClient::new(endpoint)
        .unwrap_or_else(|error| panic!("production HTTP/2 RPC client should build: {error}"));
    let scenario = generated_scenario(92);
    let created = rpc
        .create_session(
            CreateSessionRequest::inline(scenario.clone(), scenario.seed()).with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 create should decode: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);

    let control = rpc
        .control_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_client_name("production-http2-control-client"),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 control attach should decode: {error}"));
    assert_eq!(control.attached().session, created.session);

    let watch_a_client = rpc.clone();
    let watch_b_client = rpc.clone();
    let query_client = rpc.clone();
    let watch_a = watch_a_client.watch_attach(
        AttachRequest::new(created.session)
            .with_expected_epoch(created.session.epoch)
            .with_client_name("production-http2-watch-a"),
    );
    let watch_b = watch_b_client.watch_attach(
        AttachRequest::new(created.session)
            .with_expected_epoch(created.session.epoch)
            .with_client_name("production-http2-watch-b"),
    );
    let paused_query =
        query_client.send_command(SendRequest::new(created.session, 1, query_state_command()));
    let (watch_a, watch_b, paused_query) = tokio::join!(watch_a, watch_b, paused_query);
    let mut watch_a =
        watch_a.unwrap_or_else(|error| panic!("first concurrent Watch should attach: {error}"));
    let mut watch_b =
        watch_b.unwrap_or_else(|error| panic!("second concurrent Watch should attach: {error}"));
    let paused_query =
        paused_query.unwrap_or_else(|error| panic!("concurrent Query should decode: {error}"));
    assert_eq!(paused_query.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        paused_query.query_result,
        Some(QueryResult::State(LifecycleStateKind::Paused)),
    );

    for attached in [watch_a.attached(), watch_b.attached()] {
        assert_eq!(attached.session, created.session);
        assert_eq!(attached.state, LiveStateKind::Paused);
        assert!(attached.snapshot.is_some());
    }

    let continued = control
        .send_command(2, SessionCommand::Continue)
        .await
        .unwrap_or_else(|error| panic!("Control Continue should decode: {error}"));
    assert_eq!(continued.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running),
    );

    let running_query_client = rpc.clone();
    let watch_a_running = recv_watch_state_update(&mut watch_a, LiveStateKind::Running);
    let watch_b_running = recv_watch_state_update(&mut watch_b, LiveStateKind::Running);
    let running_query = running_query_client.send_command(SendRequest::new(
        created.session,
        3,
        query_state_command(),
    ));
    let (watch_a_state, watch_b_state, running_query) =
        tokio::join!(watch_a_running, watch_b_running, running_query);
    assert_eq!(watch_a_state, LiveStateKind::Running);
    assert_eq!(watch_b_state, LiveStateKind::Running);
    let running_query =
        running_query.unwrap_or_else(|error| panic!("running Query should decode: {error}"));
    assert_eq!(running_query.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        running_query.query_result,
        Some(QueryResult::State(LifecycleStateKind::Running)),
    );

    let stopped = control
        .send_command(4, SessionCommand::Stop)
        .await
        .unwrap_or_else(|error| panic!("Control Stop should decode: {error}"));
    assert_eq!(stopped.result.status, CommandResultStatus::Accepted);
    let destroyed = rpc
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 destroy should decode: {error}"));
    assert_eq!(destroyed.session, created.session);
    server.abort();
    match server.await {
        Err(error) if error.is_cancelled() => {}
        other => panic!("production HTTP/2 server task should abort cleanly: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_http2_lifecycle_server_shutdown_completes_with_active_watch_stream() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 listener should bind: {error}"));
    let addr = listener.local_addr().unwrap_or_else(|error| {
        panic!("production HTTP/2 listener should report address: {error}")
    });
    let control_plane = LifecycleControlPlane::new(
        "production-http2-active-watch-shutdown-server",
        Vec::new(),
        test_loop_factory as fn(&ScenarioDef, Seed) -> ServerQuantumLoop,
    );
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        serve_lifecycle_http2_with_mode_until_shutdown(
            listener,
            control_plane,
            LifecycleServerMode::read_write(),
            async move {
                let _ = shutdown_receiver.await;
            },
        )
        .await
    });

    let rpc = RpcControlClient::new(RpcEndpoint::http2(format!("http://{addr}")))
        .unwrap_or_else(|error| panic!("production HTTP/2 RPC client should build: {error}"));
    let scenario = generated_scenario(93);
    let created = rpc
        .create_session(
            CreateSessionRequest::inline(scenario.clone(), scenario.seed()).with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 create should decode: {error}"));
    let mut watch = rpc
        .watch_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_client_name("production-http2-active-watch"),
        )
        .await
        .unwrap_or_else(|error| panic!("active Watch should attach before shutdown: {error}"));
    assert_eq!(watch.attached().session, created.session);

    shutdown_sender
        .send(())
        .unwrap_or_else(|_| panic!("shutdown receiver should still be active"));
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap_or_else(|_| panic!("server should finish after shutdown with active Watch"))
        .unwrap_or_else(|error| panic!("server task should join after shutdown: {error}"))
        .unwrap_or_else(|error| panic!("server should not fail during shutdown: {error}"));
    let stream_end = tokio::time::timeout(Duration::from_millis(100), watch.recv_state_update())
        .await
        .unwrap_or_else(|_| panic!("Watch stream should close after server shutdown"))
        .unwrap_or_else(|error| panic!("Watch stream should close cleanly: {error}"));
    assert!(stream_end.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_rejections_use_closed_status_taxonomy_without_closing_stream() {
    let (streaming, actor, session) =
        streaming_session_fixture(ServerQuantumLoop { quanta: 0 }, 90);
    let actor_task = tokio::spawn(actor.run());

    let started = streaming
        .send(SendRequest::new(session, 1, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("initial Start should be accepted: {error}"));
    assert_eq!(started.result.status, CommandResultStatus::Accepted);

    assert_rejected_send(
        &streaming,
        session,
        2,
        SessionCommand::Start,
        CommandRejectionKind::InvalidState,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 3).await;

    let reproduction_before_missing_remove = streaming.reproduction_log().snapshot();
    let event_tail_before_missing_remove = streaming.event_log().current_cursor();
    assert_rejected_send(
        &streaming,
        session,
        4,
        SessionCommand::RemoveBreakpoint {
            id: 404,
            reply: CommandReply::discard(),
        },
        CommandRejectionKind::NotFound,
    )
    .await;
    assert_eq!(
        streaming.reproduction_log().snapshot(),
        reproduction_before_missing_remove,
        "running missing-breakpoint rejection must not record reproduction control",
    );
    assert_eq!(
        streaming.event_log().current_cursor(),
        event_tail_before_missing_remove,
        "running missing-breakpoint rejection must not append event-log control",
    );
    assert_accepted_query_after_rejection(&streaming, session, 5).await;

    let paused = streaming
        .send(SendRequest::new(session, 6, SessionCommand::Pause))
        .await
        .unwrap_or_else(|error| panic!("Pause after rejected Start should be accepted: {error}"));
    assert_eq!(paused.result.status, CommandResultStatus::Accepted);

    assert_rejected_send(
        &streaming,
        session,
        7,
        SessionCommand::RemoveBreakpoint {
            id: 404,
            reply: CommandReply::discard(),
        },
        CommandRejectionKind::NotFound,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 8).await;

    let missing_checkpoint = ContentHash::from_bytes(b"missing-api-command-status-checkpoint");
    assert_rejected_send(
        &streaming,
        session,
        9,
        SessionCommand::Fork {
            from: CheckpointRef::Checkpoint(missing_checkpoint),
            reply: CommandReply::discard(),
        },
        CommandRejectionKind::NotFound,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 10).await;

    assert_rejected_send(
        &streaming,
        session,
        11,
        attach_gdb_command("taxonomy-unsupported"),
        CommandRejectionKind::Unsupported,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 12).await;

    stop_streaming_actor(streaming, session, 13, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_maps_backend_rejections_to_invalid_argument() {
    let (streaming, actor, session) = streaming_session_fixture(RejectingGdbLoop { quanta: 0 }, 91);
    let actor_task = tokio::spawn(actor.run());
    start_and_pause_streaming_actor(&streaming, session).await;

    assert_rejected_send(
        &streaming,
        session,
        3,
        attach_gdb_command("taxonomy-invalid-argument"),
        CommandRejectionKind::InvalidArgument,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 4).await;

    stop_streaming_actor(streaming, session, 5, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_maps_internal_command_failures_without_closing_stream() {
    let (streaming, actor, session) = streaming_session_fixture(InternalGdbLoop { quanta: 0 }, 92);
    let actor_task = tokio::spawn(actor.run());
    start_and_pause_streaming_actor(&streaming, session).await;

    assert_rejected_send(
        &streaming,
        session,
        3,
        attach_gdb_command("taxonomy-internal"),
        CommandRejectionKind::Internal,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 4).await;

    stop_streaming_actor(streaming, session, 5, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_observes_payload_free_actor_failures() {
    let (streaming, actor, session) = streaming_session_fixture(
        RejectingOnceShutdownLoop {
            quanta: 0,
            shutdown_rejections: 1,
        },
        93,
    );
    let actor_task = tokio::spawn(actor.run());
    start_and_pause_streaming_actor(&streaming, session).await;

    assert_rejected_send(
        &streaming,
        session,
        3,
        SessionCommand::Stop,
        CommandRejectionKind::InvalidArgument,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 4).await;

    stop_streaming_actor(streaming, session, 5, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_send_decodes_all_rejection_statuses_and_golden_error_bytes() {
    let session = SessionRef::new(SessionId::new(77), 3, Seed::from_u64(7700));
    for reason in [
        CommandRejectionKind::InvalidState,
        CommandRejectionKind::NotFound,
        CommandRejectionKind::InvalidArgument,
        CommandRejectionKind::Unsupported,
        CommandRejectionKind::Internal,
    ] {
        let server = spawn_scripted_send_server(vec![
            scripted_send_response(
                axum::http::StatusCode::OK,
                send_response_body(
                    1,
                    SessionCommandKind::Start,
                    CommandResultStatus::Rejected { reason },
                ),
            ),
            scripted_send_response(
                axum::http::StatusCode::OK,
                send_response_body(2, SessionCommandKind::Query, CommandResultStatus::Accepted),
            ),
        ])
        .await;
        let client = RpcControlClient::new(RpcEndpoint::http2(server.endpoint()))
            .unwrap_or_else(|error| panic!("scripted RPC client should build: {error}"));
        let rejected = client
            .send_command(SendRequest::new(session, 1, SessionCommand::Start))
            .await
            .unwrap_or_else(|error| panic!("scripted rejected send should decode: {error}"));
        assert_eq!(
            rejected.result.status,
            CommandResultStatus::Rejected { reason },
        );
        let accepted = client
            .send_command(SendRequest::new(session, 2, query_state_command()))
            .await
            .unwrap_or_else(|error| panic!("scripted send after rejection should decode: {error}"));
        assert_eq!(accepted.result.status, CommandResultStatus::Accepted);
    }

    let golden_rejection = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        String::from_utf8(golden_vector_bytes("send-response-rejected-not-found").to_vec())
            .unwrap_or_else(|error| panic!("golden send response should be UTF-8: {error}")),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(golden_rejection.endpoint()))
        .unwrap_or_else(|error| panic!("golden rejection RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(session, 9002, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("golden rejected send should decode: {error}"));
    assert_eq!(
        decoded.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::NotFound,
        },
    );

    let query_result_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        String::from(
            "crucible.rpc/send-response\ncommand-id=12\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=state|paused\n",
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(query_result_server.endpoint()))
        .unwrap_or_else(|error| panic!("query-result RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(session, 12, query_state_command()))
        .await
        .unwrap_or_else(|error| panic!("query-result send should decode: {error}"));
    assert_eq!(
        decoded.query_result,
        Some(QueryResult::State(LifecycleStateKind::Paused)),
    );

    let scenario = generated_scenario(9013);
    let config = Configuration::genesis(scenario.clone());
    let snapshot_result_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        format!(
            "crucible.rpc/send-response\ncommand-id=13\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=snapshot|paused:user-requested|0|0|0|{}|{}|{}|{}|none\n",
            scenario.id().to_hex(),
            scenario.seed().to_hex(),
            scenario.app_random_draw_cap(),
            hex_encode(&config.schedule.to_compact_binary()),
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(snapshot_result_server.endpoint()))
        .unwrap_or_else(|error| panic!("snapshot result RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(
            session,
            13,
            SessionCommand::query_snapshot(),
        ))
        .await
        .unwrap_or_else(|error| panic!("snapshot query-result send should decode: {error}"));
    let Some(QueryResult::Snapshot(snapshot)) = decoded.query_result else {
        panic!("snapshot query should decode to an engine snapshot");
    };
    assert_eq!(
        snapshot.state,
        EngineState::Paused {
            reason: crucible_session::PauseReason::UserRequested,
        }
    );
    assert_eq!(snapshot.frontier, VirtualTime { ticks: 0 });
    assert_eq!(snapshot.event_log_len, 0);
    assert_eq!(snapshot.quanta, 0);
    assert_eq!(snapshot.configuration.def.id(), scenario.id());
    assert_eq!(snapshot.configuration.def.seed(), scenario.seed());
    assert_eq!(
        snapshot.configuration.def.app_random_draw_cap(),
        scenario.app_random_draw_cap(),
    );
    assert_eq!(snapshot.configuration.schedule, config.schedule);
    assert!(snapshot.terminal_savepoint.is_none());

    let firing_predicate =
        crucible::Predicate::guest_marker(crucible::MarkerId::from_name("rpc-save-marker"));
    let action_disposition = crucible::Action::pass();
    let scheduler_control = ControlOperationKind::Pause;
    let breakpoint_result_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        format!(
            "crucible.rpc/send-response\ncommand-id=14\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=breakpoint-firings|2|7|11|2|3|{}|suspend|0|8|12|4|5|{}|action:{}|1|{}\nbreakpoint-id=none\nsavepoint-info=none\n",
            hex_encode(&firing_predicate.to_compact_binary()),
            hex_encode(&firing_predicate.to_compact_binary()),
            hex_encode(&action_disposition.to_compact_binary()),
            hex_encode(&scheduler_control.to_compact_binary()),
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(breakpoint_result_server.endpoint()))
        .unwrap_or_else(|error| panic!("breakpoint result RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(
            session,
            14,
            SessionCommand::query_breakpoint_firings(),
        ))
        .await
        .unwrap_or_else(|error| panic!("breakpoint query-result send should decode: {error}"));
    let Some(QueryResult::BreakpointFirings(firings)) = decoded.query_result else {
        panic!("breakpoint query should decode firing records");
    };
    assert_eq!(firings.len(), 2);
    assert_eq!(firings[0].sequence, 7);
    assert_eq!(firings[0].id, 11);
    assert_eq!(firings[0].frontier, VirtualTime { ticks: 2 });
    assert_eq!(firings[0].quanta, 3);
    assert_eq!(firings[0].predicate, firing_predicate);
    assert_eq!(firings[0].disposition, BreakpointDisposition::Suspend);
    assert!(firings[0].scheduler_controls.is_empty());
    assert_eq!(firings[1].sequence, 8);
    assert_eq!(firings[1].id, 12);
    assert_eq!(
        firings[1].disposition,
        BreakpointDisposition::Action(action_disposition),
    );
    assert_eq!(firings[1].scheduler_controls, vec![scheduler_control]);

    let excessive_firing_count_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        format!(
            "crucible.rpc/send-response\ncommand-id=16\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=breakpoint-firings|{}\nbreakpoint-id=none\nsavepoint-info=none\n",
            usize::MAX,
        ),
    )])
    .await;
    let client =
        RpcControlClient::new(RpcEndpoint::http2(excessive_firing_count_server.endpoint()))
            .unwrap_or_else(|error| {
                panic!("excessive firing count RPC client should build: {error}")
            });
    let error = client
        .send_command(SendRequest::new(
            session,
            16,
            SessionCommand::query_breakpoint_firings(),
        ))
        .await
        .expect_err("excessive breakpoint firing count should reject without panicking");
    assert!(
        format!("{error:?}").contains("breakpoint firing count is too large"),
        "unexpected excessive count error: {error:?}"
    );

    let breakpoint_id_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        String::from(
            "crucible.rpc/send-response\ncommand-id=17\ncommand=crucible.cmd.set-breakpoint\nstatus=accepted\nstate-update=none\nquery-result=none\nbreakpoint-id=44\nsavepoint-info=none\n",
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(breakpoint_id_server.endpoint()))
        .unwrap_or_else(|error| panic!("breakpoint id RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(
            session,
            17,
            SessionCommand::SetBreakpoint {
                spec: crucible_session::BreakpointSpec::suspend_once(
                    crucible::Predicate::quiescent(),
                ),
                reply: CommandReply::discard(),
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("breakpoint id send should decode: {error}"));
    assert_eq!(decoded.breakpoint_id, Some(44));

    let golden_error = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::PRECONDITION_FAILED,
        String::from_utf8(golden_vector_bytes("rpc-error-invalid-state").to_vec())
            .unwrap_or_else(|error| panic!("golden error response should be UTF-8: {error}")),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(golden_error.endpoint()))
        .unwrap_or_else(|error| panic!("golden error RPC client should build: {error}"));
    let error = client
        .send_command(SendRequest::new(session, 8, SessionCommand::Start))
        .await
        .expect_err("golden invalid-state RPC error should decode");
    assert_eq!(
        error,
        ControlClientError::Streaming {
            source: StreamingApiError::EpochMismatch {
                expected: 8,
                actual: 7,
            },
        },
    );
}

#[test]
fn rpc_wire_contract_snapshots_cover_lifecycle_and_streaming_message_variants() {
    let session = SessionRef::new(SessionId::new(42), 7, Seed::from_u64(42));
    let seed_hex = session.seed.to_hex();
    let inline_id = ContentHash { bytes: [0x11; 32] };
    let inline_seed = Seed::from_u64(77);
    let inline =
        ScenarioDef::from_content_hash_seed_and_app_random_draw_cap(inline_id, inline_seed, 5);
    let reproduction = ReproductionCommandRecord {
        sequence: 1,
        payload: ReproductionCommandPayload {
            command: SessionCommandKind::Pause,
            command_payload: String::from("payload=command-kind\ncommand=Pause\n"),
            scheduler_batch: 0,
            scheduler_control: None,
        },
        virtual_time: VirtualTime { ticks: 5 },
        quanta: 4,
        at_sequence: 3,
        result: ReproductionCommandResult::Accepted,
        observational_order: 1,
    };

    let hello = String::from_utf8(encode_rpc_hello_request(
        "contract-client",
        RPC_PROTOCOL_VERSION,
    ))
    .unwrap_or_else(|error| panic!("hello request should be UTF-8: {error}"));
    assert_rpc_snapshot(
        "hello-request",
        &hello,
        "crucible.rpc/hello-request\nversion=4.0.0+crucible-rpc-abi-v4\nclient=contract-client\n",
    );
    assert_rpc_snapshot(
        "list-scenarios-request",
        "crucible.rpc/list-scenarios-request\n",
        "crucible.rpc/list-scenarios-request\n",
    );

    let create_ref = format!(
        "crucible.rpc/create-session-request\nsource=scenario-ref\nname=contract-scenario\nseed={seed_hex}\nstart-paused=false\n"
    );
    assert_eq!(
        parse_create_session_request(create_ref.as_bytes())
            .unwrap_or_else(|error| panic!("scenario-ref request should parse: {error}")),
        CreateSessionRequest::scenario_ref("contract-scenario", session.seed)
            .with_start_paused(false),
    );
    assert_rpc_snapshot("create-session-ref-request", &create_ref, &create_ref);

    let create_inline = format!(
        "crucible.rpc/create-session-request\nsource=inline\nscenario-id={}\nscenario-seed={}\napp-random-draw-cap=5\nseed={seed_hex}\nstart-paused=true\n",
        inline_id.to_hex(),
        inline_seed.to_hex(),
    );
    assert_eq!(
        parse_create_session_request(create_inline.as_bytes())
            .unwrap_or_else(|error| panic!("inline request should parse: {error}")),
        CreateSessionRequest::inline(inline, session.seed),
    );
    assert_rpc_snapshot(
        "create-session-inline-request",
        &create_inline,
        &create_inline,
    );

    let inline_form = resume_session_request(80).scenario;
    let inline_form_scenario = inline_form.scenario_def();
    let create_inline_form = format!(
        "crucible.rpc/create-session-request\nsource=inline\nscenario-id={}\nscenario-seed={}\napp-random-draw-cap={}\nscenario-payload={}\nseed={seed_hex}\nstart-paused=true\n",
        inline_form_scenario.id().to_hex(),
        inline_form.seed().to_hex(),
        inline_form.app_random_draw_cap(),
        hex_encode(&inline_form.to_compact_binary()),
    );
    assert!(
        create_inline_form.contains("\nscenario-payload="),
        "form-bearing inline create-session must transfer source payload"
    );
    assert_eq!(
        parse_create_session_request(create_inline_form.as_bytes())
            .unwrap_or_else(|error| panic!("inline form request should parse: {error}")),
        CreateSessionRequest::inline_form(inline_form, session.seed),
    );
    assert_rpc_snapshot(
        "create-session-inline-form-request",
        &create_inline_form,
        &create_inline_form,
    );

    let resume_request = resume_session_request(78);
    let resume_wire = format!(
        "crucible.rpc/resume-session-request\nscenario-id={}\nscenario-seed={}\napp-random-draw-cap={}\nscenario-payload={}\nseed={}\nschedule={}\ncheckpoint={}\n",
        resume_request.scenario.id().to_hex(),
        resume_request.scenario.seed().to_hex(),
        resume_request.scenario.app_random_draw_cap(),
        hex_encode(&resume_request.scenario.to_compact_binary()),
        resume_request.seed.to_hex(),
        hex_encode(&resume_request.schedule.to_compact_binary()),
        hex_encode(&resume_request.checkpoint.to_compact_binary()),
    );
    assert_eq!(
        parse_resume_session_request(resume_wire.as_bytes())
            .unwrap_or_else(|error| panic!("resume request should parse: {error}")),
        resume_request,
    );
    assert_rpc_snapshot("resume-session-request", &resume_wire, &resume_wire);

    assert_rpc_snapshot(
        "list-sessions-request",
        "crucible.rpc/list-sessions-request\n",
        "crucible.rpc/list-sessions-request\n",
    );
    let destroy = format!(
        "crucible.rpc/destroy-session-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\n"
    );
    assert_eq!(
        parse_destroy_session_request(destroy.as_bytes())
            .unwrap_or_else(|error| panic!("destroy request should parse: {error}")),
        DestroySessionRequest::new(session).with_expected_epoch(7),
    );
    assert_rpc_snapshot("destroy-session-request", &destroy, &destroy);

    let get_reproduction = format!(
        "crucible.rpc/get-reproduction-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\n"
    );
    assert_eq!(
        parse_get_reproduction_request(get_reproduction.as_bytes())
            .unwrap_or_else(|error| panic!("get-reproduction request should parse: {error}")),
        GetReproductionRequest::new(session).with_expected_epoch(7),
    );
    assert_rpc_snapshot(
        "get-reproduction-request",
        &get_reproduction,
        &get_reproduction,
    );

    let attach = format!(
        "crucible.rpc/attach-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\nfrom-seq=3\nclient-name=contract-watch\n"
    );
    assert_eq!(
        parse_attach_request(attach.as_bytes())
            .unwrap_or_else(|error| panic!("attach request should parse: {error}")),
        AttachRequest::new(session)
            .with_expected_epoch(7)
            .with_cursor(EventLogCursor::new(3))
            .with_client_name("contract-watch"),
    );
    assert_rpc_snapshot("attach-request", &attach, &attach);

    let send = format!(
        "crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\ncommand-id=99\ncommand=crucible.cmd.pause\n"
    );
    assert_eq!(
        parse_send_request(send.as_bytes())
            .unwrap_or_else(|error| panic!("send request should parse: {error}")),
        SendRequest::new(session, 99, SessionCommand::Pause).with_expected_epoch(7),
    );
    assert_rpc_snapshot("send-request", &send, &send);

    let savepoint_request = format!(
        "crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\ncommand-id=100\ncommand=crucible.cmd.create-savepoint\nsavepoint-label=636f6e74726163742d73617665\n"
    );
    let parsed_savepoint = parse_send_request(savepoint_request.as_bytes())
        .unwrap_or_else(|error| panic!("savepoint send request should parse: {error}"));
    assert_eq!(
        parsed_savepoint,
        SendRequest::new(
            session,
            100,
            SessionCommand::CreateSavepoint {
                label: String::from("contract-save"),
                reply: CommandReply::discard(),
            },
        )
        .with_expected_epoch(7),
    );
    assert_rpc_snapshot(
        "send-request-savepoint",
        &savepoint_request,
        &savepoint_request,
    );

    let hello_response = String::from_utf8(encode_rpc_hello_response(
        "contract-server",
        RPC_PROTOCOL_VERSION,
        RPC_OPEN_SET_PAYLOAD_KINDS,
    ))
    .unwrap_or_else(|error| panic!("hello response should be UTF-8: {error}"));
    assert_rpc_snapshot(
        "hello-response",
        &hello_response,
        "crucible.rpc/hello-response\nversion=4.0.0+crucible-rpc-abi-v4\nserver=contract-server\npayload-kinds=crucible.cmd.*,crucible.bp.*,crucible.fault.*,crucible.event.*\n",
    );
    assert_rpc_snapshot(
        "list-scenarios-response",
        &encode_list_scenarios_response(&ListScenariosResponse {
            scenarios: vec![ScenarioSummary {
                name: String::from("contract-scenario"),
                description: String::from("Contract scenario"),
                source_id: String::from("test://contract"),
            }],
        }),
        "crucible.rpc/list-scenarios-response\nscenario=contract-scenario|Contract scenario|test://contract\n",
    );
    assert_rpc_snapshot(
        "create-session-response",
        &encode_create_session_response(&CreateSessionResponse {
            session,
            state: LiveStateKind::Paused,
        }),
        &format!(
            "crucible.rpc/create-session-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nstate=paused\n"
        ),
    );
    let resume_checkpoint = ContentHash { bytes: [0x33; 32] };
    let resume_configuration = ContentHash { bytes: [0x44; 32] };
    assert_rpc_snapshot(
        "resume-session-response",
        &encode_resume_session_response(&ResumeSessionResponse {
            session,
            state: LiveStateKind::Paused,
            checkpoint: resume_checkpoint,
            configuration: resume_configuration,
        }),
        &format!(
            "crucible.rpc/resume-session-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nstate=paused\ncheckpoint={}\nconfiguration={}\n",
            resume_checkpoint.to_hex(),
            resume_configuration.to_hex(),
        ),
    );
    assert_rpc_snapshot(
        "list-sessions-response",
        &encode_list_sessions_response(&ListSessionsResponse {
            sessions: vec![SessionSummary {
                session,
                state: LiveStateKind::Running,
                outcome: None,
                terminal_savepoint: None,
                frontier: VirtualTime { ticks: 8 },
                event_log_len: 12,
                quanta_stepped: 4,
            }],
        }),
        &format!(
            "crucible.rpc/list-sessions-response\nsession=42|7|{seed_hex}|running|12|8|4|none|none\n"
        ),
    );
    assert_rpc_snapshot(
        "destroy-session-response",
        &encode_destroy_session_response(&DestroySessionResponse {
            session,
            already_absent: false,
            stopped: true,
        }),
        &format!(
            "crucible.rpc/destroy-session-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nalready-absent=false\nstopped=true\n"
        ),
    );
    assert_rpc_snapshot(
        "get-reproduction-response",
        &encode_get_reproduction_response(&GetReproductionResponse {
            session,
            commands: vec![reproduction.clone()],
        }),
        &format!(
            "crucible.rpc/get-reproduction-response\nsession-id=42\nepoch=7\nseed={seed_hex}\ncommand=1|crucible.cmd.pause|5|4|3|accepted|1|0|none|7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\n"
        ),
    );
    assert_rpc_snapshot(
        "attached-response",
        &encode_attached_response(&Attached {
            session,
            event_log_len: 9,
            state: LiveStateKind::Paused,
            version: RPC_PROTOCOL_VERSION,
            capabilities: StreamingCapabilitySet {
                commands: Vec::new(),
                snapshot_on_attach: true,
            },
            snapshot: Some(AttachSnapshot {
                through: EventLogCursor::new(9),
                event_count: 2,
                causal_event_count: 1,
                observational_event_count: 1,
                last_sequence: Some(8),
                reproduction: vec![reproduction],
            }),
        }),
        &format!(
            "crucible.rpc/attached-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nevent-log-len=9\nstate=paused\nversion=4.0.0+crucible-rpc-abi-v4\ncommands=\nsnapshot=9|2|1|1|8\nreproduction=1|crucible.cmd.pause|5|4|3|accepted|1|0|none|7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\n"
        ),
    );
    assert_rpc_snapshot(
        "send-response-accepted",
        &encode_send_response(&SendResponse {
            result: CommandResult {
                command_id: 99,
                command_kind: SessionCommandKind::Pause,
                status: CommandResultStatus::Accepted,
            },
            state_update: Some(StateUpdate {
                session,
                state: LiveStateKind::Paused,
            }),
            query_result: None,
            breakpoint_id: None,
            savepoint_info: None,
        }),
        &format!(
            "crucible.rpc/send-response\ncommand-id=99\ncommand=crucible.cmd.pause\nstatus=accepted\nstate-update=42|7|{seed_hex}|paused\nquery-result=none\nbreakpoint-id=none\nsavepoint-info=none\n"
        ),
    );
    assert_rpc_snapshot(
        "send-response-rejected",
        &encode_send_response(&SendResponse {
            result: CommandResult {
                command_id: 100,
                command_kind: SessionCommandKind::RemoveBreakpoint,
                status: CommandResultStatus::Rejected {
                    reason: CommandRejectionKind::NotFound,
                },
            },
            state_update: None,
            query_result: None,
            breakpoint_id: None,
            savepoint_info: None,
        }),
        "crucible.rpc/send-response\ncommand-id=100\ncommand=crucible.cmd.remove-breakpoint\nstatus=rejected:not-found\nstate-update=none\nquery-result=none\nbreakpoint-id=none\nsavepoint-info=none\n",
    );

    let mut attributes = BTreeMap::new();
    attributes.insert(String::from("ok"), OpenSetAttributeValue::Bool(true));
    assert_rpc_snapshot(
        "event-frame",
        &encode_streaming_frame(&StreamingFrame::Event(StreamingEventFrame {
            generation: 2,
            cursor: EventLogCursor::new(3),
            next_cursor: EventLogCursor::new(4),
            event: OpenSetEventEnvelope {
                sequence: 3,
                at: OpenSetEventTime {
                    virtual_time_ticks: 5,
                    icount_retired: 6,
                    icount_node: Some(String::from("node-a")),
                },
                source: OpenSetEventSource::Command { command_id: 99 },
                level: EventLevel::Info,
                observational: false,
                payload: OpenSetPayload::new("crucible.event.contract", attributes),
            },
        })),
        "crucible.rpc/event-frame\ngeneration=2\ncursor=3\nnext-cursor=4\nsequence=3\nvirtual-time-ticks=5\nicount-retired=6\nicount-node=6e6f64652d61\nsource=command|99\nlevel=info\nobservational=false\nkind=crucible.event.contract\nattribute=6f6b|bool|true\n",
    );
    assert_rpc_snapshot(
        "state-update-frame",
        &encode_streaming_frame(&StreamingFrame::StateUpdate(StreamingStateUpdateFrame {
            sequence: 11,
            update: StateUpdate {
                session,
                state: LiveStateKind::Running,
            },
        })),
        &format!(
            "crucible.rpc/state-update-frame\nsequence=11\nstate-update=42|7|{seed_hex}|running\n"
        ),
    );
    assert_rpc_snapshot(
        "rpc-error",
        "crucible.rpc/error\nstatus=invalid-state\nreason=streaming-epoch-mismatch\nexpected=8\nactual=7\n",
        "crucible.rpc/error\nstatus=invalid-state\nreason=streaming-epoch-mismatch\nexpected=8\nactual=7\n",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn reference_client_conformance_drives_full_lifecycle_across_transports_with_simdouble_backend()
 {
    assert_qemu_node_implements_simulation_backend_contract();

    let sim_double_client = InProcessLifecycleClient::new(reference_lifecycle_control_plane(
        "crucible-reference-simdouble",
        |_scenario, _seed| ReferenceSimDoubleLoop::new(),
    ));
    let rpc_server = spawn_http2_lifecycle_server().await;
    let rpc_client = RpcControlClient::new(RpcEndpoint::http2(rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("reference RPC client should build: {error}"));

    let sim_double = run_reference_client_conformance(&sim_double_client, "SimDouble").await;
    let rpc = run_reference_client_conformance(&rpc_client, "HTTP2-RPC").await;

    assert_reference_conformance_equivalent(&sim_double, &rpc);
    assert_eq!(sim_double.transport, ControlTransportKind::InProcess);
    assert_eq!(rpc.transport, ControlTransportKind::Http2Rpc);
}

#[tokio::test(flavor = "current_thread")]
async fn api_nondeterminism_gate_proves_transport_observers_wall_clock_and_read_only_traffic_do_not_perturb_state()
 {
    let quiet_in_process = InProcessLifecycleClient::new(lifecycle_control_plane());
    let noisy_in_process = InProcessLifecycleClient::new(lifecycle_control_plane());
    let quiet_rpc_server = spawn_http2_lifecycle_server().await;
    let quiet_rpc = RpcControlClient::new(RpcEndpoint::http2(quiet_rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("quiet nondeterminism RPC client should build: {error}"));
    let rpc_server = spawn_http2_lifecycle_server().await;
    let noisy_rpc = RpcControlClient::new(RpcEndpoint::http2(rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("nondeterminism RPC client should build: {error}"));
    let arrival_rpc_server = spawn_http2_lifecycle_server().await;
    let arrival_rpc = RpcControlClient::new(RpcEndpoint::http2(arrival_rpc_server.endpoint()))
        .unwrap_or_else(|error| {
            panic!("arrival-order nondeterminism RPC client should build: {error}")
        });
    let baseline =
        drive_api_nondeterminism_projection(&quiet_in_process, ApiDeterminismTraffic::Quiet).await;
    let noisy_in_process =
        drive_api_nondeterminism_projection(&noisy_in_process, ApiDeterminismTraffic::Noisy).await;
    let quiet_rpc =
        drive_api_nondeterminism_projection(&quiet_rpc, ApiDeterminismTraffic::Quiet).await;
    let noisy_rpc =
        drive_api_nondeterminism_projection(&noisy_rpc, ApiDeterminismTraffic::Noisy).await;
    let arrival_rpc =
        drive_rpc_arrival_permutation_projection(&arrival_rpc, &arrival_rpc_server).await;
    let quiet_causal =
        drive_streaming_causal_subsequence_projection(ApiDeterminismTraffic::Quiet).await;
    let noisy_causal =
        drive_streaming_causal_subsequence_projection(ApiDeterminismTraffic::Noisy).await;

    assert_eq!(baseline.transport, ControlTransportKind::InProcess);
    assert_eq!(noisy_in_process.transport, ControlTransportKind::InProcess);
    assert_eq!(quiet_rpc.transport, ControlTransportKind::Http2Rpc);
    assert_eq!(noisy_rpc.transport, ControlTransportKind::Http2Rpc);
    assert_eq!(arrival_rpc.transport, ControlTransportKind::Http2Rpc);
    assert_eq!(
        baseline.normalized(),
        noisy_in_process.normalized(),
        "in-process read-only traffic, observer load, and scheduling gaps must not perturb State",
    );
    assert_eq!(
        baseline.normalized(),
        quiet_rpc.normalized(),
        "quiet RPC transport must match the quiet in-process projection",
    );
    assert_eq!(
        baseline.normalized(),
        noisy_rpc.normalized(),
        "RPC transport and independent observer/request arrival order must not perturb State",
    );
    assert_eq!(
        baseline.normalized(),
        arrival_rpc.normalized(),
        "server-observed RPC read/mutate order permutations must not perturb the boundary command projection",
    );
    assert_eq!(
        quiet_causal, noisy_causal,
        "read-only traffic and undrained observers must not perturb the causal event projection",
    );
    assert!(
        !quiet_causal.causal_events.is_empty(),
        "causal projection must be non-vacuous"
    );
}

#[test]
fn control_client_rejects_rpc_major_version_mismatch_on_both_transports() {
    let (in_process, _actor) = in_process_client_fixture();
    let rpc = RpcControlClient::new(RpcEndpoint::http2("http://127.0.0.1:65535"))
        .unwrap_or_else(|error| panic!("HTTP/2 RPC client should build: {error}"));
    let incompatible = HelloRequest::new(
        "api-control-client-test",
        crucible_api::ProtocolVersion {
            major: RPC_PROTOCOL_VERSION.major.saturating_add(1),
            minor: RPC_PROTOCOL_VERSION.minor,
            patch: RPC_PROTOCOL_VERSION.patch,
            build: RPC_PROTOCOL_VERSION.build,
        },
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("current-thread runtime should build: {error}"));
    let in_process_error = runtime
        .block_on(in_process.hello(incompatible.clone()))
        .expect_err("in-process client should reject major mismatch");
    let rpc_error = runtime
        .block_on(rpc.hello(incompatible))
        .expect_err("RPC client should reject major mismatch");

    assert_eq!(in_process_error, rpc_error);
}

fn assert_control_client_trait<C: ControlClient>(client: &C) {
    assert_eq!(client.wire_model(), ControlWireModel::current());
}

fn assert_rpc_snapshot(name: &str, actual: &str, expected: &str) {
    assert_eq!(actual, expected, "RPC wire snapshot `{name}` drifted");
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReferenceClientConformanceReport {
    backend: &'static str,
    transport: ControlTransportKind,
    command_statuses: Vec<CommandResultStatus>,
    state_updates: Vec<LiveStateKind>,
    reproduction_commands: Vec<SessionCommandKind>,
    lifecycle: Vec<&'static str>,
}

impl ReferenceClientConformanceReport {
    fn normalized(&self) -> ReferenceClientConformanceProjection {
        ReferenceClientConformanceProjection {
            command_statuses: self.command_statuses.clone(),
            state_updates: self.state_updates.clone(),
            reproduction_commands: self.reproduction_commands.clone(),
            lifecycle: self.lifecycle.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReferenceClientConformanceProjection {
    command_statuses: Vec<CommandResultStatus>,
    state_updates: Vec<LiveStateKind>,
    reproduction_commands: Vec<SessionCommandKind>,
    lifecycle: Vec<&'static str>,
}

async fn run_reference_client_conformance<C>(
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

    for (command_id, command_kind) in [
        (11, SessionCommandKind::InjectFault),
        (12, SessionCommandKind::HealFault),
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
        SessionCommandKind::InjectFault,
        SessionCommandKind::HealFault,
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

fn record_accepted_command(
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

fn representative_command(command: SessionCommandKind) -> SessionCommand {
    if command == SessionCommandKind::Query {
        return query_state_command();
    }
    command
        .representative_command()
        .unwrap_or_else(|| panic!("{command:?} should have a representative command"))
}

fn query_state_command() -> SessionCommand {
    SessionCommand::Query {
        kind: QueryKind::State,
        reply: CommandReply::discard(),
    }
}

async fn recv_control_state_update(
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

async fn recv_watch_state_update(
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

fn assert_reference_conformance_equivalent(
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

fn reference_lifecycle_control_plane<L, F>(
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

fn assert_qemu_node_implements_simulation_backend_contract() {
    fn assert_backend<T: SimulationBackend>() {}
    assert_backend::<crucible_qemu::QemuNode>();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApiDeterminismTraffic {
    Quiet,
    Noisy,
}

impl ApiDeterminismTraffic {
    const fn is_noisy(self) -> bool {
        matches!(self, Self::Noisy)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApiDeterminismProjection {
    transport: ControlTransportKind,
    final_state: LiveStateKind,
    final_event_count: u64,
    causal_event_count: u64,
    observational_event_count: u64,
    last_sequence: Option<u64>,
    reproduction: Vec<ReproductionCommandRecord>,
    mutating_results: Vec<ApiMutatingCommandResult>,
}

impl ApiDeterminismProjection {
    fn normalized(&self) -> ApiDeterminismNormalizedProjection {
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
struct ApiDeterminismNormalizedProjection {
    final_state: LiveStateKind,
    final_event_count: u64,
    causal_event_count: u64,
    observational_event_count: u64,
    last_sequence: Option<u64>,
    reproduction: Vec<ReproductionCommandRecord>,
    mutating_results: Vec<ApiMutatingCommandResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApiMutatingCommandResult {
    command_id: u64,
    command: SessionCommandKind,
    status: CommandResultStatus,
    state_update: Option<LiveStateKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApiCausalSubsequenceProjection {
    final_state: LiveStateKind,
    event_count: u64,
    causal_event_count: u64,
    observational_event_count: u64,
    last_sequence: Option<u64>,
    causal_events: Vec<ApiCausalEventProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApiCausalEventProjection {
    sequence: u64,
    virtual_time_ticks: u64,
    kind: String,
    source: String,
}

async fn drive_api_nondeterminism_projection<C>(
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
        (10, SessionCommandKind::InjectFault),
        (11, SessionCommandKind::HealFault),
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
    assert_eq!(
        final_observation.reproduction.len(),
        mutating_results.len(),
        "only boundary-mutating commands should enter reproduction"
    );
    for excluded in [
        SessionCommandKind::Query,
        SessionCommandKind::Start,
        SessionCommandKind::Continue,
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

async fn drive_streaming_causal_subsequence_projection(
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

async fn capture_streaming_causal_projection(
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

async fn drive_rpc_arrival_permutation_projection(
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
    let inject = client
        .clone()
        .send_command(
            SendRequest::new(
                session,
                10,
                representative_command(SessionCommandKind::InjectFault),
            )
            .with_expected_epoch(session.epoch),
        )
        .await;
    assert_eq!(
        inject
            .unwrap_or_else(|error| panic!("arrival-order InjectFault should succeed: {error}"))
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

    let heal = client
        .clone()
        .send_command(
            SendRequest::new(
                session,
                11,
                representative_command(SessionCommandKind::HealFault),
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
    assert_eq!(read_after.commands.len(), 2);
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
        heal.unwrap_or_else(|error| panic!("arrival-order HealFault should succeed: {error}"))
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
                command: SessionCommandKind::InjectFault,
                status: CommandResultStatus::Accepted,
                state_update: None,
            },
            ApiMutatingCommandResult {
                command_id: 11,
                command: SessionCommandKind::HealFault,
                status: CommandResultStatus::Accepted,
                state_update: None,
            },
        ],
    }
}

async fn attach_observer_load<C>(
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

async fn assert_read_only_traffic_is_schedule_neutral<C>(
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

async fn read_api_determinism_observation<C>(
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

async fn simulate_wall_clock_gap_without_scheduler_input() {
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
}

fn assert_command_rejection_taxonomy_is_closed() {
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

fn raw_send_body(session: SessionRef, command_id: u64, command: &str) -> String {
    format!(
        "crucible.rpc/send-request\nsession-id={}\nepoch={}\nseed={}\nexpected-epoch=none\ncommand-id={}\ncommand={}\n",
        session.id.value,
        session.epoch,
        session.seed.to_hex(),
        command_id,
        command,
    )
}

async fn assert_raw_send_error(
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

async fn assert_raw_send_rejection(
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

async fn assert_raw_send_accepted(endpoint: &str, body: String, expected_command: &str) {
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

fn assert_reproduction_pause_record(record: &ReproductionCommandRecord, at_sequence: u64) {
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

fn assert_fault_reproduction_records(records: &[ReproductionCommandRecord]) {
    let [inject, heal] = records else {
        panic!("expected inject/heal reproduction pair, got {records:?}");
    };
    assert_eq!(inject.payload.command, SessionCommandKind::InjectFault);
    assert!(
        inject
            .payload
            .command_payload
            .contains("payload=inject-fault")
    );
    assert!(inject.payload.command_payload.contains("fault-material="));
    assert!(matches!(
        &inject.payload.scheduler_control,
        Some(material)
            if material.contains("control=inject-fault")
                && material.contains("fault-material=")
    ));
    assert_eq!(heal.payload.command, SessionCommandKind::HealFault);
    assert!(heal.payload.command_payload.contains("payload=heal-fault"));
    assert_eq!(
        heal.payload.scheduler_control,
        Some(String::from(
            "control=heal-fault\ntag=6c6966656379636c652d6d6f64656c\n"
        )),
    );
}

async fn recv_rpc_control_event(
    stream: &mut crucible_api::ClientControlStream,
) -> StreamingEventFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_event())
        .await
        .unwrap_or_else(|_| panic!("RPC Control event should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Control event should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Control event stream should remain open"))
}

async fn recv_rpc_control_state_update(
    stream: &mut crucible_api::ClientControlStream,
) -> StreamingStateUpdateFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_state_update())
        .await
        .unwrap_or_else(|_| panic!("RPC Control state update should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Control state update should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Control state update stream should remain open"))
}

async fn recv_rpc_watch_event(stream: &mut crucible_api::ClientWatchStream) -> StreamingEventFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_event())
        .await
        .unwrap_or_else(|_| panic!("RPC Watch event should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Watch event should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Watch event stream should remain open"))
}

async fn recv_rpc_watch_state_update(
    stream: &mut crucible_api::ClientWatchStream,
) -> StreamingStateUpdateFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_state_update())
        .await
        .unwrap_or_else(|_| panic!("RPC Watch state update should arrive before timeout"))
        .unwrap_or_else(|error| panic!("RPC Watch state update should decode: {error}"))
        .unwrap_or_else(|| panic!("RPC Watch state update stream should remain open"))
}

struct Http2LifecycleServer {
    endpoint: String,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    arrival_log: std::sync::Arc<Mutex<Vec<&'static str>>>,
}

impl Http2LifecycleServer {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn saw_http2_request(&self) -> bool {
        for _ in 0..128 {
            if self.saw_http2.load(std::sync::atomic::Ordering::SeqCst) {
                return true;
            }
            tokio::task::yield_now().await;
        }
        false
    }

    async fn append_session_events(&self, session: SessionRef, entries: &[SchedulerEventLogEntry]) {
        let streaming = self
            .control_plane
            .lock()
            .await
            .streaming_session(session)
            .unwrap_or_else(|error| panic!("streaming session should exist: {error}"));
        let hub = streaming.event_log().clone().into_inner();
        append_event_log_entries_for_test(&hub, entries);
        if let Some(last) = entries.last() {
            assert_eq!(
                hub.current_cursor().next_sequence,
                last.sequence().saturating_add(1),
            );
        }
    }

    async fn take_arrivals(&self) -> Vec<&'static str> {
        let mut arrivals = self.arrival_log.lock().await;
        let snapshot = arrivals.clone();
        arrivals.clear();
        snapshot
    }
}

#[derive(Clone)]
struct ScriptedSendResponse {
    status: axum::http::StatusCode,
    body: String,
}

struct ScriptedSendServer {
    endpoint: String,
}

impl ScriptedSendServer {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

fn scripted_send_response(status: axum::http::StatusCode, body: String) -> ScriptedSendResponse {
    ScriptedSendResponse { status, body }
}

async fn spawn_scripted_send_server(responses: Vec<ScriptedSendResponse>) -> ScriptedSendServer {
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("scripted send listener should bind: {error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("scripted send listener should report address: {error}"));
    let saw_http2 = Arc::new(AtomicBool::new(false));
    let responses = Arc::new(Mutex::new(std::collections::VecDeque::from(responses)));
    let responses_for_send = Arc::clone(&responses);
    let saw_http2_for_send = Arc::clone(&saw_http2);
    let app = Router::new().route(
        "/crucible.rpc/send",
        post(move |request: Request<Body>| {
            let responses = Arc::clone(&responses_for_send);
            let saw_http2 = Arc::clone(&saw_http2_for_send);
            async move {
                let _ = read_rpc_body(request, saw_http2).await;
                match responses.lock().await.pop_front() {
                    Some(response) => http2_response(response.status, response.body),
                    None => typed_rpc_status_response(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        RpcStatusCode::Internal,
                        "internal",
                        "scripted send response exhausted",
                    ),
                }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|error| panic!("scripted send server should run: {error}"));
    });
    ScriptedSendServer {
        endpoint: format!("http://{addr}"),
    }
}

fn send_response_body(
    command_id: u64,
    command: SessionCommandKind,
    status: CommandResultStatus,
) -> String {
    let mut output = String::from("crucible.rpc/send-response\n");
    push_wire_line(&mut output, "command-id", &command_id.to_string());
    push_wire_line(&mut output, "command", &command_name(command));
    push_wire_line(&mut output, "status", &command_status_wire(status));
    push_wire_line(&mut output, "state-update", "none");
    push_wire_line(&mut output, "query-result", "none");
    push_wire_line(&mut output, "breakpoint-id", "none");
    push_wire_line(&mut output, "savepoint-info", "none");
    output
}

fn golden_vector_bytes(name: &str) -> &'static [u8] {
    GOLDEN_RPC_VECTORS
        .iter()
        .find(|vector| vector.name == name)
        .unwrap_or_else(|| panic!("missing RPC golden vector {name}"))
        .bytes
}

type TestLifecyclePlane =
    LifecycleControlPlane<ServerQuantumLoop, LifecycleLoopFactory<ServerQuantumLoop>>;

fn test_loop_factory(_: &ScenarioDef, _: Seed) -> ServerQuantumLoop {
    ServerQuantumLoop { quanta: 0 }
}

fn lifecycle_control_plane() -> TestLifecyclePlane {
    LifecycleControlPlane::new(
        "crucible-http2-test-server",
        vec![ScenarioCatalogEntry::from_canonical_material(
            "api-control-client-scenario",
            "Control client scenario",
            "test://api-control-client-scenario",
            "crucible.api.gate-control-client.scenario",
            "scenario=api-control-client",
        )],
        test_loop_factory as fn(&ScenarioDef, Seed) -> ServerQuantumLoop,
    )
}

async fn spawn_http2_lifecycle_server() -> Http2LifecycleServer {
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("HTTP/2 test listener should bind: {error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("HTTP/2 test listener should report address: {error}"));
    let saw_http2 = Arc::new(AtomicBool::new(false));
    let control_plane = Arc::new(Mutex::new(lifecycle_control_plane()));
    let arrival_log = Arc::new(Mutex::new(Vec::new()));
    let saw_http2_for_hello = Arc::clone(&saw_http2);
    let saw_http2_for_list_scenarios = Arc::clone(&saw_http2);
    let saw_http2_for_create_session = Arc::clone(&saw_http2);
    let saw_http2_for_resume_session = Arc::clone(&saw_http2);
    let saw_http2_for_list_sessions = Arc::clone(&saw_http2);
    let saw_http2_for_destroy_session = Arc::clone(&saw_http2);
    let saw_http2_for_get_reproduction = Arc::clone(&saw_http2);
    let saw_http2_for_control_attach = Arc::clone(&saw_http2);
    let saw_http2_for_control_send = Arc::clone(&saw_http2);
    let saw_http2_for_watch_attach = Arc::clone(&saw_http2);
    let saw_http2_for_send_command = Arc::clone(&saw_http2);
    let control_plane_for_hello = Arc::clone(&control_plane);
    let control_plane_for_list_scenarios = Arc::clone(&control_plane);
    let control_plane_for_create_session = Arc::clone(&control_plane);
    let control_plane_for_resume_session = Arc::clone(&control_plane);
    let control_plane_for_list_sessions = Arc::clone(&control_plane);
    let control_plane_for_destroy_session = Arc::clone(&control_plane);
    let control_plane_for_get_reproduction = Arc::clone(&control_plane);
    let control_plane_for_control_attach = Arc::clone(&control_plane);
    let control_plane_for_control_send = Arc::clone(&control_plane);
    let control_plane_for_watch_attach = Arc::clone(&control_plane);
    let control_plane_for_send_command = Arc::clone(&control_plane);
    let arrival_log_for_hello = Arc::clone(&arrival_log);
    let arrival_log_for_list_scenarios = Arc::clone(&arrival_log);
    let arrival_log_for_create_session = Arc::clone(&arrival_log);
    let arrival_log_for_resume_session = Arc::clone(&arrival_log);
    let arrival_log_for_list_sessions = Arc::clone(&arrival_log);
    let arrival_log_for_destroy_session = Arc::clone(&arrival_log);
    let arrival_log_for_get_reproduction = Arc::clone(&arrival_log);
    let arrival_log_for_control_attach = Arc::clone(&arrival_log);
    let arrival_log_for_control_send = Arc::clone(&arrival_log);
    let arrival_log_for_watch_attach = Arc::clone(&arrival_log);
    let arrival_log_for_send_command = Arc::clone(&arrival_log);
    let app = Router::new()
        .route(
            "/crucible.rpc/hello",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_hello);
                let saw_http2 = Arc::clone(&saw_http2_for_hello);
                let arrival_log = Arc::clone(&arrival_log_for_hello);
                async move {
                    record_rpc_arrival(arrival_log, "hello").await;
                    handle_rpc_hello(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/list-scenarios",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_list_scenarios);
                let saw_http2 = Arc::clone(&saw_http2_for_list_scenarios);
                let arrival_log = Arc::clone(&arrival_log_for_list_scenarios);
                async move {
                    record_rpc_arrival(arrival_log, "list-scenarios").await;
                    handle_list_scenarios(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/create-session",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_create_session);
                let saw_http2 = Arc::clone(&saw_http2_for_create_session);
                let arrival_log = Arc::clone(&arrival_log_for_create_session);
                async move {
                    record_rpc_arrival(arrival_log, "create-session").await;
                    handle_create_session(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/resume-session",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_resume_session);
                let saw_http2 = Arc::clone(&saw_http2_for_resume_session);
                let arrival_log = Arc::clone(&arrival_log_for_resume_session);
                async move {
                    record_rpc_arrival(arrival_log, "resume-session").await;
                    handle_resume_session(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/list-sessions",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_list_sessions);
                let saw_http2 = Arc::clone(&saw_http2_for_list_sessions);
                let arrival_log = Arc::clone(&arrival_log_for_list_sessions);
                async move {
                    record_rpc_arrival(arrival_log, "list-sessions").await;
                    handle_list_sessions(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/destroy-session",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_destroy_session);
                let saw_http2 = Arc::clone(&saw_http2_for_destroy_session);
                let arrival_log = Arc::clone(&arrival_log_for_destroy_session);
                async move {
                    record_rpc_arrival(arrival_log, "destroy-session").await;
                    handle_destroy_session(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/get-reproduction",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_get_reproduction);
                let saw_http2 = Arc::clone(&saw_http2_for_get_reproduction);
                let arrival_log = Arc::clone(&arrival_log_for_get_reproduction);
                async move {
                    record_rpc_arrival(arrival_log, "get-reproduction").await;
                    handle_get_reproduction(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/control/attach",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_control_attach);
                let saw_http2 = Arc::clone(&saw_http2_for_control_attach);
                let arrival_log = Arc::clone(&arrival_log_for_control_attach);
                async move {
                    record_rpc_arrival(arrival_log, "control-attach").await;
                    handle_control_attach(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/control/send",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_control_send);
                let saw_http2 = Arc::clone(&saw_http2_for_control_send);
                let arrival_log = Arc::clone(&arrival_log_for_control_send);
                async move {
                    record_rpc_arrival(arrival_log, "control-send").await;
                    handle_control_send(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/watch",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_watch_attach);
                let saw_http2 = Arc::clone(&saw_http2_for_watch_attach);
                let arrival_log = Arc::clone(&arrival_log_for_watch_attach);
                async move {
                    record_rpc_arrival(arrival_log, "watch").await;
                    handle_watch_attach(request, control_plane, saw_http2).await
                }
            }),
        )
        .route(
            "/crucible.rpc/send",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_send_command);
                let saw_http2 = Arc::clone(&saw_http2_for_send_command);
                let arrival_log = Arc::clone(&arrival_log_for_send_command);
                async move {
                    record_rpc_arrival(arrival_log, "send").await;
                    handle_send_command(request, control_plane, saw_http2).await
                }
            }),
        );
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            panic!("HTTP/2 test server should serve: {error}");
        }
    });

    Http2LifecycleServer {
        endpoint: format!("http://{addr}"),
        saw_http2,
        control_plane,
        arrival_log,
    }
}

async fn spawn_http2_hello_server() -> Http2LifecycleServer {
    spawn_http2_lifecycle_server().await
}

async fn record_rpc_arrival(
    arrival_log: std::sync::Arc<Mutex<Vec<&'static str>>>,
    label: &'static str,
) {
    arrival_log.lock().await.push(label);
}

async fn handle_rpc_hello(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    if body != encode_rpc_hello_request("api-control-client-test", RPC_PROTOCOL_VERSION) {
        return http2_response(
            axum::http::StatusCode::BAD_REQUEST,
            "unexpected hello request",
        );
    }

    let hello = match control_plane.lock().await.hello(HelloRequest::new(
        "api-control-client-test",
        RPC_PROTOCOL_VERSION,
    )) {
        Ok(hello) => hello,
        Err(error) => {
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_rpc_hello_response(&hello.server_name, hello.version, hello.payload_kinds),
    )
}

async fn handle_list_scenarios(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    if body.as_slice() != b"crucible.rpc/list-scenarios-request\n" {
        return http2_response(
            axum::http::StatusCode::BAD_REQUEST,
            "unexpected list scenarios request",
        );
    }

    let response = control_plane.lock().await.list_scenarios();
    http2_response(
        axum::http::StatusCode::OK,
        encode_list_scenarios_response(&response),
    )
}

async fn handle_create_session(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    let create = match parse_create_session_request(&body) {
        Ok(create) => create,
        Err(error) => return http2_response(axum::http::StatusCode::BAD_REQUEST, error),
    };

    let response = match control_plane.lock().await.create_session(create).await {
        Ok(response) => response,
        Err(error) => {
            return lifecycle_error_response(error);
        }
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_create_session_response(&response),
    )
}

async fn handle_resume_session(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    let resume = match parse_resume_session_request(&body) {
        Ok(resume) => resume,
        Err(error) => return http2_response(axum::http::StatusCode::BAD_REQUEST, error),
    };

    let response = match control_plane.lock().await.resume_session(resume).await {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_resume_session_response(&response),
    )
}

async fn handle_list_sessions(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    if body.as_slice() != b"crucible.rpc/list-sessions-request\n" {
        return http2_response(
            axum::http::StatusCode::BAD_REQUEST,
            "unexpected list sessions request",
        );
    }

    let response = control_plane.lock().await.list_sessions();
    http2_response(
        axum::http::StatusCode::OK,
        encode_list_sessions_response(&response),
    )
}

async fn handle_destroy_session(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    let destroy = match parse_destroy_session_request(&body) {
        Ok(destroy) => destroy,
        Err(error) => return http2_response(axum::http::StatusCode::BAD_REQUEST, error),
    };

    let response = match control_plane.lock().await.destroy_session(destroy).await {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_destroy_session_response(&response),
    )
}

async fn handle_get_reproduction(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    let get_reproduction = match parse_get_reproduction_request(&body) {
        Ok(get_reproduction) => get_reproduction,
        Err(error) => return http2_response(axum::http::StatusCode::BAD_REQUEST, error),
    };

    let response = match control_plane
        .lock()
        .await
        .get_reproduction(get_reproduction)
    {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_get_reproduction_response(&response),
    )
}

async fn handle_control_attach(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    let attach = match parse_attach_request(&body) {
        Ok(attach) => attach,
        Err(error) => return http2_response(axum::http::StatusCode::BAD_REQUEST, error),
    };
    let streaming = match control_plane.lock().await.streaming_session(attach.session) {
        Ok(streaming) => streaming,
        Err(error) => return streaming_error_response(error),
    };
    let control = match streaming.control(attach) {
        Ok(control) => control,
        Err(error) => return streaming_error_response(error),
    };
    http2_stream_response(control_event_body(control))
}

async fn handle_control_send(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    handle_streaming_send(request, control_plane, saw_http2).await
}

async fn handle_watch_attach(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    let attach = match parse_attach_request(&body) {
        Ok(attach) => attach,
        Err(error) => return http2_response(axum::http::StatusCode::BAD_REQUEST, error),
    };
    let streaming = match control_plane.lock().await.streaming_session(attach.session) {
        Ok(streaming) => streaming,
        Err(error) => return streaming_error_response(error),
    };
    let watch = match streaming.watch(attach) {
        Ok(watch) => watch,
        Err(error) => return streaming_error_response(error),
    };
    http2_stream_response(watch_event_body(watch))
}

async fn handle_send_command(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    handle_streaming_send(request, control_plane, saw_http2).await
}

async fn handle_streaming_send(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    let Ok(body) = read_rpc_body(request, saw_http2).await else {
        return http2_response(axum::http::StatusCode::BAD_REQUEST, "invalid request body");
    };
    let send = match parse_send_request(&body) {
        Ok(send) => send,
        Err(error) => return send_parse_error_response(&error),
    };
    let response = match control_plane
        .lock()
        .await
        .send_streaming_command(send)
        .await
    {
        Ok(response) => response,
        Err(ControlClientError::Streaming { source }) => return streaming_error_response(source),
        Err(error) => {
            return typed_rpc_status_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                crucible_api::RpcStatusCode::Internal,
                "internal",
                &error.to_string(),
            );
        }
    };
    http2_response(axum::http::StatusCode::OK, encode_send_response(&response))
}

fn send_parse_error_response(error: &str) -> axum::response::Response {
    let (status, reason) = if error.starts_with("unknown command")
        || error.contains("has no representative payload")
    {
        (crucible_api::RpcStatusCode::Unsupported, "unsupported")
    } else {
        (
            crucible_api::RpcStatusCode::InvalidArgument,
            "invalid-argument",
        )
    };
    typed_rpc_status_response(axum::http::StatusCode::BAD_REQUEST, status, reason, error)
}

async fn read_rpc_body(
    request: axum::http::Request<axum::body::Body>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<Vec<u8>, axum::Error> {
    if request.version() == axum::http::Version::HTTP_2 {
        saw_http2.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map(|body| body.to_vec())
}

fn encode_list_scenarios_response(response: &ListScenariosResponse) -> String {
    let mut output = String::from("crucible.rpc/list-scenarios-response\n");
    for scenario in &response.scenarios {
        output.push_str("scenario=");
        output.push_str(&scenario.name);
        output.push('|');
        output.push_str(&scenario.description);
        output.push('|');
        output.push_str(&scenario.source_id);
        output.push('\n');
    }
    output
}

fn encode_create_session_response(response: &CreateSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/create-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    output
}

fn encode_resume_session_response(response: &ResumeSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/resume-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    push_wire_line(&mut output, "checkpoint", &response.checkpoint.to_hex());
    push_wire_line(
        &mut output,
        "configuration",
        &response.configuration.to_hex(),
    );
    output
}

fn encode_list_sessions_response(response: &ListSessionsResponse) -> String {
    let mut output = String::from("crucible.rpc/list-sessions-response\n");
    for session in &response.sessions {
        output.push_str("session=");
        output.push_str(&session.session.id.value.to_string());
        output.push('|');
        output.push_str(&session.session.epoch.to_string());
        output.push('|');
        output.push_str(&session.session.seed.to_hex());
        output.push('|');
        output.push_str(state_wire_name(session.state));
        output.push('|');
        output.push_str(&session.event_log_len.to_string());
        output.push('|');
        output.push_str(&session.frontier.ticks.to_string());
        output.push('|');
        output.push_str(&session.quanta_stepped.to_string());
        output.push('|');
        output.push_str(outcome_wire_name(session.outcome));
        output.push('|');
        output.push_str(&content_hash_option_wire(session.terminal_savepoint));
        output.push('\n');
    }
    output
}

fn encode_destroy_session_response(response: &DestroySessionResponse) -> String {
    let mut output = String::from("crucible.rpc/destroy-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(
        &mut output,
        "already-absent",
        if response.already_absent {
            "true"
        } else {
            "false"
        },
    );
    push_wire_line(
        &mut output,
        "stopped",
        if response.stopped { "true" } else { "false" },
    );
    output
}

fn encode_get_reproduction_response(response: &GetReproductionResponse) -> String {
    let mut output = String::from("crucible.rpc/get-reproduction-response\n");
    push_session_ref(&mut output, response.session);
    for command in &response.commands {
        push_wire_line(&mut output, "command", &reproduction_record_wire(command));
    }
    output
}

fn lifecycle_error_response(error: LifecycleApiError) -> axum::response::Response {
    match error {
        LifecycleApiError::EpochMismatch {
            session_id,
            expected,
            actual,
        } => lifecycle_epoch_mismatch_response(session_id, expected, actual),
        LifecycleApiError::ScenarioNotFound { name } => {
            let mut output = String::from("crucible.rpc/error\n");
            push_wire_line(&mut output, "status", "not-found");
            push_wire_line(&mut output, "reason", "scenario-not-found");
            push_wire_line(&mut output, "name", &hex_encode(name.as_bytes()));
            http2_response(axum::http::StatusCode::NOT_FOUND, output)
        }
        LifecycleApiError::SessionNotFound { session } => {
            lifecycle_session_not_found_response(session)
        }
        LifecycleApiError::SessionLimitReached { .. } => typed_rpc_status_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            crucible_api::RpcStatusCode::InvalidState,
            "session-limit",
            &error.to_string(),
        ),
        LifecycleApiError::ScenarioSeedMismatch { .. }
        | LifecycleApiError::InlineScenarioIdentityMismatch { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        LifecycleApiError::ResumeCheckpoint { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        LifecycleApiError::RpcAbi { .. }
        | LifecycleApiError::GenesisGraph { .. }
        | LifecycleApiError::CommandChannelClosed { .. }
        | LifecycleApiError::StateDidNotAdvance { .. }
        | LifecycleApiError::ActorJoin { .. }
        | LifecycleApiError::ActorFailed { .. } => typed_rpc_status_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            crucible_api::RpcStatusCode::Internal,
            "internal",
            &error.to_string(),
        ),
    }
}

fn streaming_error_response(error: StreamingApiError) -> axum::response::Response {
    match error {
        StreamingApiError::EpochMismatch { expected, actual } => {
            streaming_epoch_mismatch_response(expected, actual)
        }
        StreamingApiError::SessionNotFound { session } => {
            streaming_session_not_found_response(session)
        }
        StreamingApiError::SessionMismatch { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        StreamingApiError::CommandChannelClosed { .. }
        | StreamingApiError::StateDidNotAdvance { .. }
        | StreamingApiError::EventStreamLagged { .. }
        | StreamingApiError::StateUpdateStreamLagged { .. } => typed_rpc_status_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            crucible_api::RpcStatusCode::Internal,
            "internal",
            &error.to_string(),
        ),
    }
}

fn lifecycle_epoch_mismatch_response(
    session_id: SessionId,
    expected: u64,
    actual: u64,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "invalid-state");
    push_wire_line(&mut output, "reason", "epoch-mismatch");
    push_wire_line(&mut output, "session-id", &session_id.value.to_string());
    push_wire_line(&mut output, "expected", &expected.to_string());
    push_wire_line(&mut output, "actual", &actual.to_string());
    http2_response(axum::http::StatusCode::PRECONDITION_FAILED, output)
}

fn lifecycle_session_not_found_response(session: SessionRef) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "lifecycle-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(axum::http::StatusCode::NOT_FOUND, output)
}

fn streaming_session_not_found_response(session: SessionRef) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "streaming-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(axum::http::StatusCode::NOT_FOUND, output)
}

fn streaming_epoch_mismatch_response(expected: u64, actual: u64) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "invalid-state");
    push_wire_line(&mut output, "reason", "streaming-epoch-mismatch");
    push_wire_line(&mut output, "expected", &expected.to_string());
    push_wire_line(&mut output, "actual", &actual.to_string());
    http2_response(axum::http::StatusCode::PRECONDITION_FAILED, output)
}

fn typed_rpc_status_response(
    http_status: axum::http::StatusCode,
    status: crucible_api::RpcStatusCode,
    reason: &'static str,
    message: &str,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", rpc_status_code_wire_name(status));
    push_wire_line(&mut output, "reason", reason);
    push_wire_line(&mut output, "message", &hex_encode(message.as_bytes()));
    http2_response(http_status, output)
}

fn encode_attached_response(attached: &Attached) -> String {
    let mut output = String::from("crucible.rpc/attached-response\n");
    push_session_ref(&mut output, attached.session);
    push_wire_line(
        &mut output,
        "event-log-len",
        &attached.event_log_len.to_string(),
    );
    push_wire_line(&mut output, "state", state_wire_name(attached.state));
    push_wire_line(
        &mut output,
        "version",
        &format!(
            "{}.{}.{}+{}",
            attached.version.major,
            attached.version.minor,
            attached.version.patch,
            attached.version.build
        ),
    );
    let commands = attached
        .capabilities
        .commands
        .iter()
        .map(|capability| {
            open_set_command_kind(capability.command_kind)
                .unwrap_or_else(|| format!("crucible.cmd.{}", capability.command_name))
        })
        .collect::<Vec<_>>()
        .join(",");
    push_wire_line(&mut output, "commands", &commands);
    push_wire_line(&mut output, "snapshot", &snapshot_wire(attached));
    let reproduction = attached
        .snapshot
        .as_ref()
        .map(|snapshot| reproduction_records_wire(&snapshot.reproduction))
        .unwrap_or_else(|| String::from("none"));
    push_wire_line(&mut output, "reproduction", &reproduction);
    output
}

fn snapshot_wire(attached: &Attached) -> String {
    let Some(snapshot) = &attached.snapshot else {
        return String::from("none");
    };
    let last = snapshot
        .last_sequence
        .map(|sequence| sequence.to_string())
        .unwrap_or_else(|| String::from("none"));
    format!(
        "{}|{}|{}|{}|{}",
        snapshot.through.next_sequence,
        snapshot.event_count,
        snapshot.causal_event_count,
        snapshot.observational_event_count,
        last,
    )
}

fn reproduction_records_wire(commands: &[ReproductionCommandRecord]) -> String {
    if commands.is_empty() {
        return String::from("none");
    }
    commands
        .iter()
        .map(reproduction_record_wire)
        .collect::<Vec<_>>()
        .join(";")
}

fn reproduction_record_wire(command: &ReproductionCommandRecord) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        command.sequence,
        command_name(command.payload.command),
        command.virtual_time.ticks,
        command.quanta,
        command.at_sequence,
        match command.result {
            ReproductionCommandResult::Accepted => "accepted",
        },
        command.observational_order,
        command.payload.scheduler_batch,
        scheduler_control_wire(command.payload.scheduler_control.as_ref()),
        command_payload_material_wire(&command.payload.command_payload),
    )
}

fn command_payload_material_wire(material: &str) -> String {
    hex_encode(material.as_bytes())
}

fn scheduler_control_wire(control: Option<&String>) -> String {
    control
        .map(|material| hex_encode(material.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

fn encode_send_response(response: &SendResponse) -> String {
    let mut output = String::from("crucible.rpc/send-response\n");
    push_wire_line(
        &mut output,
        "command-id",
        &response.result.command_id.to_string(),
    );
    push_wire_line(
        &mut output,
        "command",
        &command_name(response.result.command_kind),
    );
    push_wire_line(
        &mut output,
        "status",
        &command_status_wire(response.result.status),
    );
    match response.state_update {
        Some(update) => push_wire_line(&mut output, "state-update", &state_update_wire(update)),
        None => push_wire_line(&mut output, "state-update", "none"),
    }
    push_wire_line(&mut output, "query-result", "none");
    push_wire_line(
        &mut output,
        "breakpoint-id",
        &response
            .breakpoint_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| String::from("none")),
    );
    push_wire_line(&mut output, "savepoint-info", "none");
    output
}

fn command_status_wire(status: CommandResultStatus) -> String {
    match status {
        CommandResultStatus::Accepted => String::from("accepted"),
        CommandResultStatus::Rejected { reason } => {
            format!(
                "rejected:{}",
                rpc_status_code_wire_name(reason.rpc_status())
            )
        }
    }
}

fn parse_create_session_request(body: &[u8]) -> Result<CreateSessionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/create-session-request")?;
    match parse_wire_line(lines.next(), "source=")? {
        "scenario-ref" => {
            let name = parse_wire_line(lines.next(), "name=")?.to_owned();
            let seed = parse_seed_line(lines.next(), "seed=")?;
            let start_paused = parse_bool_line(lines.next(), "start-paused=")?;
            reject_extra_line(lines.next())?;
            Ok(CreateSessionRequest::scenario_ref(name, seed).with_start_paused(start_paused))
        }
        "inline" => {
            let id = parse_content_hash_line(lines.next(), "scenario-id=")?;
            let scenario_seed = parse_seed_line(lines.next(), "scenario-seed=")?;
            let app_random_draw_cap = parse_u64_line(lines.next(), "app-random-draw-cap=")?;
            let next = lines.next();
            let (scenario_form, seed_line) = if let Some(line) = next {
                if line.starts_with("scenario-payload=") {
                    let scenario = parse_scenario_form_line(Some(line), "scenario-payload=")?;
                    let scenario_def = scenario.scenario_def();
                    if scenario_def.id() != id {
                        return Err(format!(
                            "scenario payload id {} did not match request scenario id {}",
                            scenario_def.id().to_hex(),
                            id.to_hex()
                        ));
                    }
                    if scenario.seed() != scenario_seed {
                        return Err(format!(
                            "scenario payload seed {} did not match request scenario seed {}",
                            scenario.seed().to_hex(),
                            scenario_seed.to_hex()
                        ));
                    }
                    if scenario.app_random_draw_cap() != app_random_draw_cap {
                        return Err(format!(
                            "scenario payload app-random draw cap {} did not match request cap {}",
                            scenario.app_random_draw_cap(),
                            app_random_draw_cap
                        ));
                    }
                    (Some(scenario), lines.next())
                } else {
                    (None, Some(line))
                }
            } else {
                (None, None)
            };
            let seed = parse_seed_line(seed_line, "seed=")?;
            let start_paused = parse_bool_line(lines.next(), "start-paused=")?;
            reject_extra_line(lines.next())?;
            let scenario = ScenarioDef::from_content_hash_seed_and_app_random_draw_cap(
                id,
                scenario_seed,
                app_random_draw_cap,
            );
            let request = if let Some(scenario_form) = scenario_form {
                CreateSessionRequest::inline_form(scenario_form, seed)
            } else {
                CreateSessionRequest::inline(scenario, seed)
            };
            Ok(request.with_start_paused(start_paused))
        }
        source => Err(format!("unexpected create-session source `{source}`")),
    }
}

fn parse_resume_session_request(body: &[u8]) -> Result<ResumeSessionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/resume-session-request")?;
    let id = parse_content_hash_line(lines.next(), "scenario-id=")?;
    let scenario_seed = parse_seed_line(lines.next(), "scenario-seed=")?;
    let app_random_draw_cap = parse_u64_line(lines.next(), "app-random-draw-cap=")?;
    let scenario = parse_scenario_form_line(lines.next(), "scenario-payload=")?;
    let scenario_def = scenario.scenario_def();
    if scenario_def.id() != id {
        return Err(format!(
            "scenario payload id {} did not match request scenario id {}",
            scenario_def.id().to_hex(),
            id.to_hex()
        ));
    }
    if scenario.seed() != scenario_seed {
        return Err(format!(
            "scenario payload seed {} did not match request scenario seed {}",
            scenario.seed().to_hex(),
            scenario_seed.to_hex()
        ));
    }
    if scenario.app_random_draw_cap() != app_random_draw_cap {
        return Err(format!(
            "scenario payload app-random draw cap {} did not match request cap {}",
            scenario.app_random_draw_cap(),
            app_random_draw_cap
        ));
    }
    let seed = parse_seed_line(lines.next(), "seed=")?;
    let schedule = parse_schedule_line(lines.next(), "schedule=")?;
    let checkpoint = parse_checkpoint_line(lines.next(), "checkpoint=")?;
    reject_extra_line(lines.next())?;
    Ok(ResumeSessionRequest::new(
        scenario, schedule, checkpoint, seed,
    ))
}

fn parse_destroy_session_request(body: &[u8]) -> Result<DestroySessionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/destroy-session-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    reject_extra_line(lines.next())?;
    let mut request = DestroySessionRequest::new(session);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn parse_get_reproduction_request(body: &[u8]) -> Result<GetReproductionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/get-reproduction-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    reject_extra_line(lines.next())?;
    let mut request = GetReproductionRequest::new(session);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn parse_attach_request(body: &[u8]) -> Result<AttachRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/attach-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    let from = EventLogCursor::new(parse_u64_line(lines.next(), "from-seq=")?);
    let client_name = parse_wire_line(lines.next(), "client-name=")?.to_owned();
    reject_extra_line(lines.next())?;
    let mut request = AttachRequest::new(session)
        .with_cursor(from)
        .with_client_name(client_name);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn parse_send_request(body: &[u8]) -> Result<SendRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/send-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    let command_id = parse_u64_line(lines.next(), "command-id=")?;
    let command_line = lines.next();
    let mut query_line = None;
    let mut savepoint_label_line = None;
    let mut step_duration_line = None;
    let mut breakpoint_predicate_line = None;
    let mut breakpoint_disposition_line = None;
    let mut breakpoint_policy_line = None;
    for line in lines {
        if line.starts_with("query=") {
            set_unique_payload_line(&mut query_line, line, "query")?;
        } else if line.starts_with("savepoint-label=") {
            set_unique_payload_line(&mut savepoint_label_line, line, "savepoint label")?;
        } else if line.starts_with("step-duration-nanos=") {
            set_unique_payload_line(&mut step_duration_line, line, "step duration")?;
        } else if line.starts_with("breakpoint-predicate=") {
            set_unique_payload_line(&mut breakpoint_predicate_line, line, "breakpoint predicate")?;
        } else if line.starts_with("breakpoint-disposition=") {
            set_unique_payload_line(
                &mut breakpoint_disposition_line,
                line,
                "breakpoint disposition",
            )?;
        } else if line.starts_with("breakpoint-policy=") {
            set_unique_payload_line(&mut breakpoint_policy_line, line, "breakpoint policy")?;
        } else {
            return Err(format!("unexpected trailing RPC request field `{line}`"));
        }
    }
    let command = parse_session_command(
        command_line,
        "command=",
        query_line,
        savepoint_label_line,
        step_duration_line,
        breakpoint_predicate_line,
        breakpoint_disposition_line,
        breakpoint_policy_line,
    )?;
    let mut request = SendRequest::new(session, command_id, command);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn set_unique_payload_line<'a>(
    slot: &mut Option<&'a str>,
    line: &'a str,
    label: &'static str,
) -> Result<(), String> {
    if slot.replace(line).is_some() {
        return Err(format!("duplicate {label} payload"));
    }
    Ok(())
}

fn parse_session_ref<'a, I>(lines: &mut I) -> Result<SessionRef, String>
where
    I: Iterator<Item = &'a str>,
{
    let id = parse_u64_line(lines.next(), "session-id=")?;
    let epoch = parse_u64_line(lines.next(), "epoch=")?;
    let seed = parse_seed_line(lines.next(), "seed=")?;
    Ok(SessionRef::new(SessionId::new(id), epoch, seed))
}

fn parse_u64_line(line: Option<&str>, prefix: &'static str) -> Result<u64, String> {
    let value = parse_wire_line(line, prefix)?;
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid integer `{value}` for `{prefix}`: {error}"))
}

fn parse_optional_epoch_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<Option<u64>, String> {
    let value = parse_wire_line(line, prefix)?;
    if value == "none" {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|error| format!("invalid integer `{value}` for `{prefix}`: {error}"))
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn parse_session_command(
    line: Option<&str>,
    prefix: &'static str,
    query_line: Option<&str>,
    savepoint_label_line: Option<&str>,
    step_duration_line: Option<&str>,
    breakpoint_predicate_line: Option<&str>,
    breakpoint_disposition_line: Option<&str>,
    breakpoint_policy_line: Option<&str>,
) -> Result<SessionCommand, String> {
    let command_kind_wire = parse_wire_line(line, prefix)?;
    let command_kind = session_command_for_open_set_command_kind(command_kind_wire)
        .ok_or_else(|| format!("unknown command `{command_kind_wire}`"))?;
    if command_kind == SessionCommandKind::Query {
        if savepoint_label_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a savepoint label"
            ));
        }
        if step_duration_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a step duration"
            ));
        }
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        let query_line = query_line
            .ok_or_else(|| format!("command `{command_kind_wire}` requires a query payload"))?;
        return Ok(SessionCommand::Query {
            kind: parse_query_kind_line(Some(query_line))?,
            reply: CommandReply::discard(),
        });
    } else if command_kind == SessionCommandKind::CreateSavepoint {
        if query_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a query payload"
            ));
        }
        if step_duration_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a step duration"
            ));
        }
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        let label = match savepoint_label_line {
            Some(line) => parse_hex_string_field(
                Some(parse_wire_line(Some(line), "savepoint-label=")?),
                "savepoint label",
            )?,
            None => String::from("lifecycle-model"),
        };
        return Ok(SessionCommand::CreateSavepoint {
            label,
            reply: CommandReply::discard(),
        });
    } else if command_kind == SessionCommandKind::StepDuration {
        if query_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a query payload"
            ));
        }
        if savepoint_label_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a savepoint label"
            ));
        }
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        let nanos = match step_duration_line {
            Some(line) => parse_u64_line(Some(line), "step-duration-nanos=")?,
            None => crucible_session::StepMode::DEFAULT_DURATION.nanos,
        };
        return Ok(SessionCommand::Step {
            mode: crucible_session::StepMode::Duration(crucible::SimDuration { nanos }),
        });
    } else if command_kind == SessionCommandKind::SetBreakpoint {
        if query_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a query payload"
            ));
        }
        if savepoint_label_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a savepoint label"
            ));
        }
        if step_duration_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a step duration"
            ));
        }
        let spec = parse_breakpoint_spec_lines(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        return Ok(SessionCommand::SetBreakpoint {
            spec,
            reply: CommandReply::discard(),
        });
    } else if query_line.is_some() {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a query payload"
        ));
    } else if savepoint_label_line.is_some() {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a savepoint label"
        ));
    } else if step_duration_line.is_some() {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a step duration"
        ));
    } else {
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
    }
    command_kind
        .representative_command()
        .ok_or_else(|| format!("command `{command_kind_wire}` has no representative payload"))
}

fn reject_breakpoint_payload_fields(
    command_kind_wire: &str,
    breakpoint_predicate_line: Option<&str>,
    breakpoint_disposition_line: Option<&str>,
    breakpoint_policy_line: Option<&str>,
) -> Result<(), String> {
    if breakpoint_predicate_line.is_some()
        || breakpoint_disposition_line.is_some()
        || breakpoint_policy_line.is_some()
    {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a breakpoint payload"
        ));
    }
    Ok(())
}

fn parse_breakpoint_spec_lines(
    command_kind_wire: &str,
    predicate_line: Option<&str>,
    disposition_line: Option<&str>,
    policy_line: Option<&str>,
) -> Result<BreakpointSpec, String> {
    let predicate_line = predicate_line
        .ok_or_else(|| format!("command `{command_kind_wire}` requires a breakpoint predicate"))?;
    let disposition_line = disposition_line.ok_or_else(|| {
        format!("command `{command_kind_wire}` requires a breakpoint disposition")
    })?;
    let policy_line = policy_line
        .ok_or_else(|| format!("command `{command_kind_wire}` requires a breakpoint policy"))?;
    let predicate = parse_breakpoint_predicate_line(Some(predicate_line))?;
    let disposition = parse_breakpoint_disposition_line(Some(disposition_line))?;
    let policy = parse_breakpoint_policy_line(Some(policy_line))?;
    Ok(BreakpointSpec {
        predicate,
        disposition,
        policy,
    })
}

fn parse_breakpoint_predicate_line(line: Option<&str>) -> Result<crucible::Predicate, String> {
    let value = parse_wire_line(line, "breakpoint-predicate=")?;
    let bytes = parse_hex_bytes(value)?;
    crucible::Predicate::from_compact_binary(&bytes)
        .map_err(|error| format!("invalid breakpoint predicate: {error}"))
}

fn parse_breakpoint_disposition_line(line: Option<&str>) -> Result<BreakpointDisposition, String> {
    let value = parse_wire_line(line, "breakpoint-disposition=")?;
    if value == "suspend" {
        return Ok(BreakpointDisposition::Suspend);
    }
    if value == "trace" {
        return Ok(BreakpointDisposition::Trace);
    }
    let Some(action) = value.strip_prefix("action:") else {
        return Err(format!("invalid breakpoint disposition `{value}`"));
    };
    let bytes = parse_hex_bytes(action)?;
    let action = crucible::Action::from_compact_binary(&bytes)
        .map_err(|error| format!("invalid breakpoint action disposition: {error}"))?;
    Ok(BreakpointDisposition::Action(action))
}

fn parse_breakpoint_policy_line(line: Option<&str>) -> Result<BreakpointPolicy, String> {
    match parse_wire_line(line, "breakpoint-policy=")? {
        "one-shot" => Ok(BreakpointPolicy::OneShot),
        "repeatable" => Ok(BreakpointPolicy::Repeatable),
        value => Err(format!("invalid breakpoint policy `{value}`")),
    }
}

fn parse_query_kind_line(line: Option<&str>) -> Result<QueryKind, String> {
    let value = parse_wire_line(line, "query=")?;
    let mut fields = value.split('|');
    match fields
        .next()
        .ok_or_else(|| String::from("missing query kind"))?
    {
        "snapshot" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::Snapshot)
        }
        "breakpoint-firings" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::BreakpointFirings)
        }
        "state" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::State)
        }
        "event-log-length" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::EventLogLength)
        }
        "execution-fingerprint" => {
            let node = parse_hex_string_field(fields.next(), "query fingerprint node")?;
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::ExecutionFingerprint {
                node: NodeId { name: node },
            })
        }
        kind => Err(format!("unknown query kind `{kind}`")),
    }
}

fn reject_extra_query_field(field: Option<&str>) -> Result<(), String> {
    if field.is_some() {
        return Err(String::from("unexpected extra query fields"));
    }
    Ok(())
}

fn parse_seed_line(line: Option<&str>, prefix: &'static str) -> Result<Seed, String> {
    let value = parse_wire_line(line, prefix)?;
    Ok(Seed::from_bytes(parse_hex_32(value, "seed")?))
}

fn parse_content_hash_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<ContentHash, String> {
    let value = parse_wire_line(line, prefix)?;
    Ok(ContentHash {
        bytes: parse_hex_32(value, "content hash")?,
    })
}

fn parse_schedule_line(line: Option<&str>, prefix: &'static str) -> Result<Schedule, String> {
    let value = parse_wire_line(line, prefix)?;
    Schedule::from_compact_binary(&parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid compact schedule: {error}"))
}

fn parse_scenario_form_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<ScenarioDefForm, String> {
    let value = parse_wire_line(line, prefix)?;
    ScenarioDefForm::from_compact_binary(&parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid compact scenario form: {error}"))
}

fn parse_checkpoint_line(line: Option<&str>, prefix: &'static str) -> Result<Checkpoint, String> {
    let value = parse_wire_line(line, prefix)?;
    Checkpoint::from_compact_binary(&parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid compact checkpoint: {error}"))
}

fn parse_hex_string_field(value: Option<&str>, label: &'static str) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("missing {label}"))?;
    String::from_utf8(parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid UTF-8 {label}: {error}"))
}

fn parse_hex_32(value: &str, label: &'static str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} hex has length {}", value.len()));
    }

    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        let pair = &value[start..start + 2];
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|error| format!("invalid {label} hex `{pair}`: {error}"))?;
    }
    Ok(bytes)
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", value.len()));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let pair = &value[index..index + 2];
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|error| format!("invalid hex byte `{pair}`: {error}"))?,
        );
    }
    Ok(bytes)
}

fn parse_bool_line(line: Option<&str>, prefix: &'static str) -> Result<bool, String> {
    match parse_wire_line(line, prefix)? {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(format!("invalid bool `{value}` for `{prefix}`")),
    }
}

fn expect_wire_header(line: Option<&str>, expected: &'static str) -> Result<(), String> {
    match line {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("unexpected RPC message header `{actual}`")),
        None => Err(String::from("empty RPC request")),
    }
}

fn parse_wire_line<'a>(line: Option<&'a str>, prefix: &'static str) -> Result<&'a str, String> {
    let line = line.ok_or_else(|| format!("missing `{prefix}` line"))?;
    line.strip_prefix(prefix)
        .ok_or_else(|| format!("expected `{prefix}` line, got `{line}`"))
}

fn reject_extra_line(line: Option<&str>) -> Result<(), String> {
    if line.is_some() {
        return Err(String::from("unexpected trailing RPC request fields"));
    }
    Ok(())
}

fn push_session_ref(output: &mut String, session: SessionRef) {
    push_wire_line(output, "session-id", &session.id.value.to_string());
    push_wire_line(output, "epoch", &session.epoch.to_string());
    push_wire_line(output, "seed", &session.seed.to_hex());
}

fn push_wire_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

fn state_wire_name(state: LiveStateKind) -> &'static str {
    match state {
        LiveStateKind::Loaded => "loaded",
        LiveStateKind::Paused => "paused",
        LiveStateKind::Running => "running",
        LiveStateKind::Stopped => "stopped",
    }
}

fn outcome_wire_name(outcome: Option<OutcomeKind>) -> &'static str {
    match outcome {
        Some(OutcomeKind::Passed) => "passed",
        Some(OutcomeKind::Failed) => "failed",
        Some(OutcomeKind::Timeout) => "timeout",
        Some(OutcomeKind::Crashed) => "crashed",
        Some(OutcomeKind::Stopped) => "stopped",
        None => "none",
    }
}

fn content_hash_option_wire(hash: Option<ContentHash>) -> String {
    match hash {
        Some(hash) => hash.to_hex(),
        None => String::from("none"),
    }
}

fn command_name(command: SessionCommandKind) -> String {
    open_set_command_kind(command).unwrap_or_else(|| {
        let command_name = API_COMMAND_MAPPINGS
            .iter()
            .find(|mapping| mapping.command_kind == command)
            .map(|mapping| mapping.command_name)
            .unwrap_or("unknown");
        format!("crucible.cmd.{command_name}")
    })
}

fn state_update_wire(update: StateUpdate) -> String {
    format!(
        "{}|{}|{}|{}",
        update.session.id.value,
        update.session.epoch,
        update.session.seed.to_hex(),
        state_wire_name(update.state),
    )
}

fn control_event_body(
    control: ControlStream,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::convert::Infallible>> {
    let attached = framed_rpc_message(encode_attached_response(control.attached()));
    stream::unfold(
        (control, Some(attached)),
        |(mut control, pending)| async move {
            if let Some(message) = pending {
                return Some((Ok(message), (control, None)));
            }
            let frame = match control.recv_frame().await {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(_) => return None,
            };
            Some((
                Ok(framed_rpc_message(encode_streaming_frame(&frame))),
                (control, None),
            ))
        },
    )
}

fn watch_event_body(
    watch: WatchStream,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::convert::Infallible>> {
    let attached = framed_rpc_message(encode_attached_response(watch.attached()));
    stream::unfold((watch, Some(attached)), |(mut watch, pending)| async move {
        if let Some(message) = pending {
            return Some((Ok(message), (watch, None)));
        }
        let frame = match watch.recv_frame().await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => return None,
        };
        Some((
            Ok(framed_rpc_message(encode_streaming_frame(&frame))),
            (watch, None),
        ))
    })
}

fn framed_rpc_message(message: String) -> axum::body::Bytes {
    let mut message = message;
    message.push('\n');
    axum::body::Bytes::from(message)
}

fn encode_streaming_frame(frame: &StreamingFrame) -> String {
    match frame {
        StreamingFrame::Event(frame) => encode_streaming_event_frame(frame),
        StreamingFrame::StateUpdate(frame) => encode_streaming_state_update_frame(*frame),
    }
}

fn encode_streaming_event_frame(frame: &StreamingEventFrame) -> String {
    let mut output = String::from("crucible.rpc/event-frame\n");
    push_wire_line(&mut output, "generation", &frame.generation.to_string());
    push_wire_line(
        &mut output,
        "cursor",
        &frame.cursor.next_sequence.to_string(),
    );
    push_wire_line(
        &mut output,
        "next-cursor",
        &frame.next_cursor.next_sequence.to_string(),
    );
    push_wire_line(&mut output, "sequence", &frame.event.sequence.to_string());
    push_wire_line(
        &mut output,
        "virtual-time-ticks",
        &frame.event.at.virtual_time_ticks.to_string(),
    );
    push_wire_line(
        &mut output,
        "icount-retired",
        &frame.event.at.icount_retired.to_string(),
    );
    push_wire_line(
        &mut output,
        "icount-node",
        &optional_string_wire(frame.event.at.icount_node.as_deref()),
    );
    push_wire_line(
        &mut output,
        "source",
        &event_source_wire(&frame.event.source),
    );
    push_wire_line(&mut output, "level", event_level_wire(frame.event.level));
    push_wire_line(
        &mut output,
        "observational",
        if frame.event.observational {
            "true"
        } else {
            "false"
        },
    );
    push_wire_line(&mut output, "kind", &frame.event.payload.kind);
    for (name, value) in &frame.event.payload.attributes {
        push_wire_line(
            &mut output,
            "attribute",
            &format!("{}|{}", hex_encode(name.as_bytes()), attribute_wire(value)),
        );
    }
    output
}

fn encode_streaming_state_update_frame(frame: StreamingStateUpdateFrame) -> String {
    let mut output = String::from("crucible.rpc/state-update-frame\n");
    push_wire_line(&mut output, "sequence", &frame.sequence.to_string());
    push_wire_line(
        &mut output,
        "state-update",
        &state_update_wire(frame.update),
    );
    output
}

fn optional_string_wire(value: Option<&str>) -> String {
    value
        .map(|value| hex_encode(value.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

fn event_source_wire(source: &OpenSetEventSource) -> String {
    match source {
        OpenSetEventSource::Scenario { event } => {
            format!("scenario|{}", hex_encode(event.as_bytes()))
        }
        OpenSetEventSource::Engine => String::from("engine"),
        OpenSetEventSource::Node { node } => format!("node|{}", hex_encode(node.as_bytes())),
        OpenSetEventSource::Guest { node } => format!("guest|{}", hex_encode(node.as_bytes())),
        OpenSetEventSource::Command { command_id } => format!("command|{command_id}"),
    }
}

fn event_level_wire(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

fn attribute_wire(value: &OpenSetAttributeValue) -> String {
    match value {
        OpenSetAttributeValue::Bool(value) => {
            format!("bool|{}", if *value { "true" } else { "false" })
        }
        OpenSetAttributeValue::Int(value) => format!("int|{value}"),
        OpenSetAttributeValue::Uint(value) => format!("uint|{value}"),
        OpenSetAttributeValue::Uint128(value) => format!("uint128|{value}"),
        OpenSetAttributeValue::Float64Bits(value) => format!("float64bits|{value}"),
        OpenSetAttributeValue::String(value) => format!("string|{}", hex_encode(value.as_bytes())),
        OpenSetAttributeValue::Bytes(value) => format!("bytes|{}", hex_encode(value)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn http2_stream_response(
    body: impl futures_util::Stream<Item = Result<axum::body::Bytes, std::convert::Infallible>>
    + Send
    + 'static,
) -> axum::response::Response {
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .body(axum::body::Body::from_stream(body))
        .unwrap_or_else(|error| panic!("HTTP/2 test streaming response should build: {error}"))
}

fn http2_response(
    status: axum::http::StatusCode,
    body: impl Into<axum::body::Body>,
) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .body(body.into())
        .unwrap_or_else(|error| panic!("HTTP/2 test response should build: {error}"))
}

fn in_process_client_fixture() -> (InProcessControlClient, SessionActor<NoopLoop>) {
    let scenario = generated_scenario(1);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, NoopLoop);
    let (sender, receiver) = mpsc::channel::<SessionCommand>(4);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let event_log = ControlPlaneEventLog::new(actor.event_log());
    let client = InProcessControlClient::new(sender, live, event_log);
    (client, actor)
}

fn streaming_session_fixture<L>(
    quantum_loop: L,
    seed: u64,
) -> (InProcessStreamingSession, SessionActor<L>, SessionRef)
where
    L: QuantumLoop + Send + 'static,
{
    let scenario = generated_scenario(seed);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, quantum_loop);
    let (sender, receiver) = mpsc::channel::<SessionCommand>(16);
    let actor = SessionActor::new(engine, receiver);
    let session = SessionRef::new(SessionId::new(1), 1, scenario.seed());
    let streaming = InProcessStreamingSession::new(
        session,
        sender,
        actor.live_snapshot(),
        ControlPlaneEventLog::new(actor.event_log()),
        actor.reproduction_log(),
        actor.state_transition_bus(),
    );
    (streaming, actor, session)
}

async fn start_and_pause_streaming_actor(
    streaming: &InProcessStreamingSession,
    session: SessionRef,
) {
    let started = streaming
        .send(SendRequest::new(session, 1, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("Start should be accepted: {error}"));
    assert_eq!(started.result.status, CommandResultStatus::Accepted);
    let paused = streaming
        .send(SendRequest::new(session, 2, SessionCommand::Pause))
        .await
        .unwrap_or_else(|error| panic!("Pause should be accepted: {error}"));
    assert_eq!(paused.result.status, CommandResultStatus::Accepted);
}

async fn stop_streaming_actor(
    streaming: InProcessStreamingSession,
    session: SessionRef,
    command_id: u64,
    actor_task: tokio::task::JoinHandle<Result<SessionRunReport, SessionError>>,
) {
    let stopped = streaming
        .send(SendRequest::new(session, command_id, SessionCommand::Stop))
        .await
        .unwrap_or_else(|error| panic!("Stop should be accepted after rejection: {error}"));
    assert_eq!(stopped.result.status, CommandResultStatus::Accepted);
    let report = actor_task
        .await
        .unwrap_or_else(|error| panic!("actor task should join: {error}"))
        .unwrap_or_else(|error| panic!("actor should stop cleanly: {error}"));
    assert!(matches!(
        report.final_snapshot.state,
        crucible_session::EngineState::Stopped { .. }
    ));
}

async fn assert_rejected_send(
    streaming: &InProcessStreamingSession,
    session: SessionRef,
    command_id: u64,
    command: SessionCommand,
    reason: CommandRejectionKind,
) {
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        streaming.send(SendRequest::new(session, command_id, command)),
    )
    .await
    .unwrap_or_else(|_| panic!("send should not hang waiting for command acknowledgement"))
    .unwrap_or_else(|error| panic!("send should return typed rejection: {error}"));
    assert_eq!(response.result.command_id, command_id);
    assert_eq!(
        response.result.status,
        CommandResultStatus::Rejected { reason }
    );
    assert!(response.state_update.is_none());
}

async fn assert_accepted_query_after_rejection(
    streaming: &InProcessStreamingSession,
    session: SessionRef,
    command_id: u64,
) {
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        streaming.send(SendRequest::new(session, command_id, query_state_command())),
    )
    .await
    .unwrap_or_else(|_| panic!("query after rejected command should not hang"))
    .unwrap_or_else(|error| panic!("query after rejected command should succeed: {error}"));
    assert_eq!(response.result.status, CommandResultStatus::Accepted);
    assert!(response.state_update.is_none());
}

fn attach_gdb_command(node_name: &str) -> SessionCommand {
    SessionCommand::AttachGdb {
        node: NodeId {
            name: node_name.to_owned(),
        },
        listen: GdbListen::new("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("test gdb listen should be valid: {error}")),
        reply: CommandReply::discard(),
    }
}

fn event_pair(first_sequence: u64, quantum: u64) -> Vec<SchedulerEventLogEntry> {
    let frontier = VirtualTime { ticks: quantum };
    let causal = condition_payload_entry_for_test(
        first_sequence,
        frontier,
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(format!("rpc-{quantum}")),
            value: quantum,
        })),
    );

    let mut details = BTreeMap::new();
    details.insert(String::from("quantum"), EventAttributeValue::U64(quantum));
    let observational = condition_payload_entry_for_test(
        first_sequence.saturating_add(1),
        frontier,
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            format!("rpc-diagnostic-{quantum}"),
            EventLevel::Info,
            details,
        )),
    );
    vec![causal, observational]
}

fn event_burst(first_sequence: u64, first_quantum: u64, pairs: u64) -> Vec<SchedulerEventLogEntry> {
    let mut entries = Vec::new();
    for offset in 0..pairs {
        entries.extend(event_pair(
            first_sequence.saturating_add(offset.saturating_mul(2)),
            first_quantum.saturating_add(offset),
        ));
    }
    entries
}

struct ServerQuantumLoop {
    quanta: u64,
}

impl QuantumLoop for ServerQuantumLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }
}

struct ReferenceSimDoubleLoop {
    backend: SimDouble,
    quanta: u64,
    event_log_events: u64,
}

impl ReferenceSimDoubleLoop {
    fn new() -> Self {
        Self {
            backend: ready_reference_sim_double(),
            quanta: 0,
            event_log_events: 0,
        }
    }
}

impl QuantumLoop for ReferenceSimDoubleLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let observation =
            SimulationBackend::step_to(&mut self.backend, VirtualTime { ticks: self.quanta })?;
        assert_eq!(observation.reached, VirtualTime { ticks: self.quanta });
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: observation.reached,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: self.reference_event_log_entries(),
            event_log_segment_bytes: vec![b's'],
            event_log_segment_text: String::from("simdouble-reference"),
            event_log_segment_hash: Some(ContentHash::from_bytes(b"simdouble-reference")),
            event_log_offset: EventLogOffset::new(Default::default(), 0, self.event_log_events),
            scheduler_quiescence: None,
        })
    }

    fn shutdown(&mut self) -> Result<(), SchedulerError> {
        SimulationBackend::shutdown(&mut self.backend).map_err(Into::into)
    }
}

impl ReferenceSimDoubleLoop {
    fn reference_event_log_entries(&mut self) -> Vec<SchedulerEventLogEntry> {
        let base = self.event_log_events;
        let entries = vec![condition_payload_entry_for_test(
            base,
            VirtualTime { ticks: self.quanta },
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "api.reference.conformance.simdouble",
                EventLevel::Debug,
                BTreeMap::new(),
            )),
        )];
        self.event_log_events = self
            .event_log_events
            .saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        entries
    }
}

fn ready_reference_sim_double() -> SimDouble {
    let mut backend = SimDouble::new(SimDoubleConfig::default())
        .unwrap_or_else(|error| panic!("reference SimDouble backend should build: {error}"));
    complete_reference_sim_double_setup(&mut backend);
    backend
}

fn complete_reference_sim_double_setup(backend: &mut SimDouble) {
    let hello_ack = control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: backend.shmem_header_snapshot().abi_version,
        slot_index: 0,
        node_count: backend.shmem_layout().node_count,
    });
    if let Err(error) = backend.accept_host_control_frame(&hello_ack) {
        panic!("reference SimDouble hello acknowledgement should succeed: {error}");
    }

    let setup = control_encode_host_msg(&HostMsg::Setup {
        region_len: backend.shmem_layout().region_size,
    });
    match backend.accept_host_control_frame(&setup) {
        Ok(Some(_setup_ack)) => {}
        Ok(None) => panic!("reference SimDouble setup should return a setup acknowledgement"),
        Err(error) => panic!("reference SimDouble setup should succeed: {error}"),
    }
}

struct RejectingGdbLoop {
    quanta: u64,
}

impl QuantumLoop for RejectingGdbLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn open_gdbstub(
        &mut self,
        _node: NodeId,
        _listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        Err(BackendError::Rejected {
            message: String::from("test backend rejected gdb attach"),
        }
        .into())
    }
}

struct InternalGdbLoop {
    quanta: u64,
}

impl QuantumLoop for InternalGdbLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn open_gdbstub(
        &mut self,
        _node: NodeId,
        _listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("test internal command failure"),
        })
    }
}

struct RejectingOnceShutdownLoop {
    quanta: u64,
    shutdown_rejections: u64,
}

impl QuantumLoop for RejectingOnceShutdownLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn shutdown(&mut self) -> Result<(), SchedulerError> {
        if self.shutdown_rejections == 0 {
            return Ok(());
        }
        self.shutdown_rejections = self.shutdown_rejections.saturating_sub(1);
        Err(BackendError::Rejected {
            message: String::from("test backend rejected shutdown"),
        }
        .into())
    }
}

struct NoopLoop;

impl QuantumLoop for NoopLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        panic!("control-client fixture should not drive scheduler quanta")
    }
}

fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    let genesis = Configuration::genesis(scenario.clone());
    match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(&genesis)) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    }
}

fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should be recorded-shaped: {error}"));
    GenesisCheckpoint { checkpoint }
}

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.api.gate-control-client.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

fn resume_session_request(seed: u64) -> ResumeSessionRequest {
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
