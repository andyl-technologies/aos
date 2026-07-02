//! API-side checks for the shared `ControlClient` trait.

#![forbid(unsafe_code)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, EventLogOffset, GenesisCheckpoint,
    QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef, SchedulerError, Seed, TemporalGraph,
    VirtualTime,
};
use crucible_api::{
    API_COMMAND_MAPPINGS, AttachRequest, Attached, CommandRejectionKind, CommandResultStatus,
    ControlClient, ControlPlaneEventLog, ControlTransportKind, ControlWireModel,
    CreateSessionRequest, CreateSessionResponse, DestroySessionRequest, DestroySessionResponse,
    EventLogCursor, HelloRequest, InProcessControlClient, LifecycleControlPlane,
    ListScenariosResponse, ListSessionsResponse, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION,
    RpcControlClient, RpcEndpoint, RpcTransportProtocol, ScenarioCatalogEntry, SendRequest,
    SendResponse, SessionId, SessionRef, StateUpdate, assert_shared_wire_model,
    encode_rpc_hello_request, encode_rpc_hello_response, open_set_command_kind,
    session_command_for_open_set_command_kind,
};
use crucible_session::{Engine, LiveStateKind, SessionActor, SessionCommand, SessionCommandKind};
use tokio::sync::{Mutex, mpsc};

#[tokio::test(flavor = "current_thread")]
async fn control_client_trait_is_transport_agnostic_over_in_process_and_rpc() {
    let (in_process, _actor) = in_process_client_fixture();
    let rpc_server = spawn_http2_lifecycle_server().await;
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

    let sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC list sessions should decode: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Running);

    let control_attached = rpc
        .control_attach(
            AttachRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC Control attach should decode: {error}"));
    assert_eq!(control_attached.session, created.session);
    assert_eq!(control_attached.state, LiveStateKind::Running);
    assert_eq!(
        control_attached.capabilities.commands.len(),
        SessionCommandKind::ALL.len(),
    );

    let control_paused = rpc
        .control_send(SendRequest::new(
            created.session,
            101,
            SessionCommand::Pause,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Control send should decode: {error}"));
    assert_eq!(control_paused.result.command_id, 101);
    assert_eq!(control_paused.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        control_paused.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused),
    );

    let watch_attached = rpc
        .watch_attach(
            AttachRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC Watch attach should decode: {error}"));
    assert_eq!(watch_attached.session, created.session);
    assert_eq!(watch_attached.state, LiveStateKind::Paused);
    assert_eq!(watch_attached.capabilities, control_attached.capabilities);

    let send_continued = rpc
        .send_command(SendRequest::new(
            created.session,
            102,
            SessionCommand::Continue,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Send should decode: {error}"));
    assert_eq!(send_continued.result.command_id, 102);
    assert_eq!(send_continued.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        send_continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running),
    );

    let rejected_start = rpc
        .send_command(SendRequest::new(
            created.session,
            103,
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

    let stream_stopped = rpc
        .send_command(SendRequest::new(created.session, 104, SessionCommand::Stop))
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

    let inline_destroyed = rpc
        .destroy_session(DestroySessionRequest::new(inline_created.session))
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
    assert_eq!(
        mismatch_error,
        crucible_api::ControlClientError::HttpStatus { status: 400 }
    );
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

struct Http2LifecycleServer {
    endpoint: String,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
}

type TestLifecyclePlane =
    LifecycleControlPlane<ServerQuantumLoop, fn(&ScenarioDef, Seed) -> ServerQuantumLoop>;

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
    let saw_http2_for_hello = Arc::clone(&saw_http2);
    let saw_http2_for_list_scenarios = Arc::clone(&saw_http2);
    let saw_http2_for_create_session = Arc::clone(&saw_http2);
    let saw_http2_for_list_sessions = Arc::clone(&saw_http2);
    let saw_http2_for_destroy_session = Arc::clone(&saw_http2);
    let saw_http2_for_control_attach = Arc::clone(&saw_http2);
    let saw_http2_for_control_send = Arc::clone(&saw_http2);
    let saw_http2_for_watch_attach = Arc::clone(&saw_http2);
    let saw_http2_for_send_command = Arc::clone(&saw_http2);
    let control_plane_for_hello = Arc::clone(&control_plane);
    let control_plane_for_list_scenarios = Arc::clone(&control_plane);
    let control_plane_for_create_session = Arc::clone(&control_plane);
    let control_plane_for_list_sessions = Arc::clone(&control_plane);
    let control_plane_for_destroy_session = Arc::clone(&control_plane);
    let control_plane_for_control_attach = Arc::clone(&control_plane);
    let control_plane_for_control_send = Arc::clone(&control_plane);
    let control_plane_for_watch_attach = Arc::clone(&control_plane);
    let control_plane_for_send_command = Arc::clone(&control_plane);
    let app = Router::new()
        .route(
            "/crucible.rpc/hello",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_hello);
                let saw_http2 = Arc::clone(&saw_http2_for_hello);
                async move { handle_rpc_hello(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/list-scenarios",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_list_scenarios);
                let saw_http2 = Arc::clone(&saw_http2_for_list_scenarios);
                async move { handle_list_scenarios(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/create-session",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_create_session);
                let saw_http2 = Arc::clone(&saw_http2_for_create_session);
                async move { handle_create_session(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/list-sessions",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_list_sessions);
                let saw_http2 = Arc::clone(&saw_http2_for_list_sessions);
                async move { handle_list_sessions(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/destroy-session",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_destroy_session);
                let saw_http2 = Arc::clone(&saw_http2_for_destroy_session);
                async move { handle_destroy_session(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/control/attach",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_control_attach);
                let saw_http2 = Arc::clone(&saw_http2_for_control_attach);
                async move { handle_control_attach(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/control/send",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_control_send);
                let saw_http2 = Arc::clone(&saw_http2_for_control_send);
                async move { handle_control_send(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/watch",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_watch_attach);
                let saw_http2 = Arc::clone(&saw_http2_for_watch_attach);
                async move { handle_watch_attach(request, control_plane, saw_http2).await }
            }),
        )
        .route(
            "/crucible.rpc/send",
            post(move |request: Request<Body>| {
                let control_plane = Arc::clone(&control_plane_for_send_command);
                let saw_http2 = Arc::clone(&saw_http2_for_send_command);
                async move { handle_send_command(request, control_plane, saw_http2).await }
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
    }
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
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_create_session_response(&response),
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
        Err(error) => {
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_destroy_session_response(&response),
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
        Err(error) => {
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    let control = match streaming.control(attach) {
        Ok(control) => control,
        Err(error) => {
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_attached_response(control.attached()),
    )
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
        Err(error) => {
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    let watch = match streaming.watch(attach) {
        Ok(watch) => watch,
        Err(error) => {
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    http2_response(
        axum::http::StatusCode::OK,
        encode_attached_response(watch.attached()),
    )
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
        Err(error) => return http2_response(axum::http::StatusCode::BAD_REQUEST, error),
    };
    let response = match control_plane
        .lock()
        .await
        .send_streaming_command(send)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return http2_response(axum::http::StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    http2_response(axum::http::StatusCode::OK, encode_send_response(&response))
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
    output
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
        match response.result.status {
            CommandResultStatus::Accepted => "accepted",
            CommandResultStatus::Rejected {
                reason: CommandRejectionKind::InvalidState,
            } => "rejected:invalid-state",
        },
    );
    match response.state_update {
        Some(update) => push_wire_line(&mut output, "state-update", &state_update_wire(update)),
        None => push_wire_line(&mut output, "state-update", "none"),
    }
    output
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
            let seed = parse_seed_line(lines.next(), "seed=")?;
            let start_paused = parse_bool_line(lines.next(), "start-paused=")?;
            reject_extra_line(lines.next())?;
            let scenario = ScenarioDef::from_content_hash_seed_and_app_random_draw_cap(
                id,
                scenario_seed,
                app_random_draw_cap,
            );
            Ok(CreateSessionRequest::inline(scenario, seed).with_start_paused(start_paused))
        }
        source => Err(format!("unexpected create-session source `{source}`")),
    }
}

fn parse_destroy_session_request(body: &[u8]) -> Result<DestroySessionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/destroy-session-request")?;
    let session = parse_session_ref(&mut lines)?;
    reject_extra_line(lines.next())?;
    Ok(DestroySessionRequest::new(session))
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
    let command = parse_session_command(lines.next(), "command=")?;
    reject_extra_line(lines.next())?;
    let mut request = SendRequest::new(session, command_id, command);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
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

fn parse_session_command(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<SessionCommand, String> {
    let command_kind_wire = parse_wire_line(line, prefix)?;
    let command_kind = session_command_for_open_set_command_kind(command_kind_wire)
        .ok_or_else(|| format!("unknown command `{command_kind_wire}`"))?;
    command_kind
        .representative_command()
        .ok_or_else(|| format!("command `{command_kind_wire}` has no representative payload"))
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
