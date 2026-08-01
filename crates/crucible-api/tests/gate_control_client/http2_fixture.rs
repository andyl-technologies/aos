//! HTTP/2 lifecycle-server fixtures for control-client tests.

use super::*;

pub(super) struct Http2LifecycleServer {
    endpoint: String,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    arrival_log: std::sync::Arc<Mutex<Vec<&'static str>>>,
}

impl Http2LifecycleServer {
    pub(super) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(super) async fn saw_http2_request(&self) -> bool {
        for _ in 0..128 {
            if self.saw_http2.load(std::sync::atomic::Ordering::SeqCst) {
                return true;
            }
            tokio::task::yield_now().await;
        }
        false
    }

    pub(super) async fn append_session_events(
        &self,
        session: SessionRef,
        entries: &[SchedulerEventLogEntry],
    ) {
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

    pub(super) async fn take_arrivals(&self) -> Vec<&'static str> {
        let mut arrivals = self.arrival_log.lock().await;
        let snapshot = arrivals.clone();
        arrivals.clear();
        snapshot
    }
}

#[derive(Clone)]
pub(super) struct ScriptedSendResponse {
    status: axum::http::StatusCode,
    body: String,
}

pub(super) struct ScriptedSendServer {
    endpoint: String,
}

impl ScriptedSendServer {
    pub(super) fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

pub(super) fn scripted_send_response(
    status: axum::http::StatusCode,
    body: String,
) -> ScriptedSendResponse {
    ScriptedSendResponse { status, body }
}

pub(super) async fn spawn_scripted_send_server(
    responses: Vec<ScriptedSendResponse>,
) -> ScriptedSendServer {
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

pub(super) fn send_response_body(
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

pub(super) fn golden_vector_bytes(name: &str) -> &'static [u8] {
    GOLDEN_RPC_VECTORS
        .iter()
        .find(|vector| vector.name == name)
        .unwrap_or_else(|| panic!("missing RPC golden vector {name}"))
        .bytes
}

pub(super) type TestLifecyclePlane =
    LifecycleControlPlane<ServerQuantumLoop, LifecycleLoopFactory<ServerQuantumLoop>>;

pub(super) fn test_loop_factory(_: &ScenarioDef, _: Seed) -> ServerQuantumLoop {
    ServerQuantumLoop { quanta: 0 }
}

pub(super) fn lifecycle_control_plane() -> TestLifecyclePlane {
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

pub(super) async fn spawn_http2_lifecycle_server() -> Http2LifecycleServer {
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

pub(super) async fn spawn_http2_hello_server() -> Http2LifecycleServer {
    spawn_http2_lifecycle_server().await
}

pub(super) async fn record_rpc_arrival(
    arrival_log: std::sync::Arc<Mutex<Vec<&'static str>>>,
    label: &'static str,
) {
    arrival_log.lock().await.push(label);
}

pub(super) async fn handle_rpc_hello(
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

pub(super) async fn handle_list_scenarios(
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

pub(super) async fn handle_create_session(
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

pub(super) async fn handle_resume_session(
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

pub(super) async fn handle_list_sessions(
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

pub(super) async fn handle_destroy_session(
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

pub(super) async fn handle_get_reproduction(
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

pub(super) async fn handle_control_attach(
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

pub(super) async fn handle_control_send(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    handle_streaming_send(request, control_plane, saw_http2).await
}

pub(super) async fn handle_watch_attach(
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

pub(super) async fn handle_send_command(
    request: axum::http::Request<axum::body::Body>,
    control_plane: std::sync::Arc<Mutex<TestLifecyclePlane>>,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> axum::response::Response {
    handle_streaming_send(request, control_plane, saw_http2).await
}

pub(super) async fn handle_streaming_send(
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

pub(super) fn send_parse_error_response(error: &str) -> axum::response::Response {
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

pub(super) async fn read_rpc_body(
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

pub(super) fn encode_list_scenarios_response(response: &ListScenariosResponse) -> String {
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

pub(super) fn encode_create_session_response(response: &CreateSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/create-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    output
}

pub(super) fn encode_resume_session_response(response: &ResumeSessionResponse) -> String {
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

pub(super) fn encode_list_sessions_response(response: &ListSessionsResponse) -> String {
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

pub(super) fn encode_destroy_session_response(response: &DestroySessionResponse) -> String {
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

pub(super) fn encode_get_reproduction_response(response: &GetReproductionResponse) -> String {
    let mut output = String::from("crucible.rpc/get-reproduction-response\n");
    push_session_ref(&mut output, response.session);
    for command in &response.commands {
        push_wire_line(&mut output, "command", &reproduction_record_wire(command));
    }
    output
}

pub(super) fn lifecycle_error_response(error: LifecycleApiError) -> axum::response::Response {
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
        | LifecycleApiError::ActorFailed { .. }
        | LifecycleApiError::LoopFactory { .. } => typed_rpc_status_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            crucible_api::RpcStatusCode::Internal,
            "internal",
            &error.to_string(),
        ),
    }
}

pub(super) fn streaming_error_response(error: StreamingApiError) -> axum::response::Response {
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

pub(super) fn lifecycle_epoch_mismatch_response(
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

pub(super) fn lifecycle_session_not_found_response(
    session: SessionRef,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "lifecycle-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(axum::http::StatusCode::NOT_FOUND, output)
}

pub(super) fn streaming_session_not_found_response(
    session: SessionRef,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "streaming-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(axum::http::StatusCode::NOT_FOUND, output)
}

pub(super) fn streaming_epoch_mismatch_response(
    expected: u64,
    actual: u64,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "invalid-state");
    push_wire_line(&mut output, "reason", "streaming-epoch-mismatch");
    push_wire_line(&mut output, "expected", &expected.to_string());
    push_wire_line(&mut output, "actual", &actual.to_string());
    http2_response(axum::http::StatusCode::PRECONDITION_FAILED, output)
}

pub(super) fn typed_rpc_status_response(
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

pub(super) fn encode_attached_response(attached: &Attached) -> String {
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

pub(super) fn snapshot_wire(attached: &Attached) -> String {
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

pub(super) fn reproduction_records_wire(commands: &[ReproductionCommandRecord]) -> String {
    if commands.is_empty() {
        return String::from("none");
    }
    commands
        .iter()
        .map(reproduction_record_wire)
        .collect::<Vec<_>>()
        .join(";")
}

pub(super) fn reproduction_record_wire(command: &ReproductionCommandRecord) -> String {
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

pub(super) fn command_payload_material_wire(material: &str) -> String {
    hex_encode(material.as_bytes())
}

pub(super) fn scheduler_control_wire(control: Option<&String>) -> String {
    control
        .map(|material| hex_encode(material.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

pub(super) fn encode_send_response(response: &SendResponse) -> String {
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

pub(super) fn command_status_wire(status: CommandResultStatus) -> String {
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

pub(super) fn parse_create_session_request(body: &[u8]) -> Result<CreateSessionRequest, String> {
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

pub(super) fn parse_resume_session_request(body: &[u8]) -> Result<ResumeSessionRequest, String> {
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

pub(super) fn parse_destroy_session_request(body: &[u8]) -> Result<DestroySessionRequest, String> {
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

pub(super) fn parse_get_reproduction_request(
    body: &[u8],
) -> Result<GetReproductionRequest, String> {
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

pub(super) fn parse_attach_request(body: &[u8]) -> Result<AttachRequest, String> {
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

pub(super) fn parse_send_request(body: &[u8]) -> Result<SendRequest, String> {
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

pub(super) fn set_unique_payload_line<'a>(
    slot: &mut Option<&'a str>,
    line: &'a str,
    label: &'static str,
) -> Result<(), String> {
    if slot.replace(line).is_some() {
        return Err(format!("duplicate {label} payload"));
    }
    Ok(())
}

pub(super) fn parse_session_ref<'a, I>(lines: &mut I) -> Result<SessionRef, String>
where
    I: Iterator<Item = &'a str>,
{
    let id = parse_u64_line(lines.next(), "session-id=")?;
    let epoch = parse_u64_line(lines.next(), "epoch=")?;
    let seed = parse_seed_line(lines.next(), "seed=")?;
    Ok(SessionRef::new(SessionId::new(id), epoch, seed))
}

pub(super) fn parse_u64_line(line: Option<&str>, prefix: &'static str) -> Result<u64, String> {
    let value = parse_wire_line(line, prefix)?;
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid integer `{value}` for `{prefix}`: {error}"))
}

pub(super) fn parse_optional_epoch_line(
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
pub(super) fn parse_session_command(
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

pub(super) fn reject_breakpoint_payload_fields(
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

pub(super) fn parse_breakpoint_spec_lines(
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

pub(super) fn parse_breakpoint_predicate_line(
    line: Option<&str>,
) -> Result<crucible::Predicate, String> {
    let value = parse_wire_line(line, "breakpoint-predicate=")?;
    let bytes = parse_hex_bytes(value)?;
    crucible::Predicate::from_compact_binary(&bytes)
        .map_err(|error| format!("invalid breakpoint predicate: {error}"))
}

pub(super) fn parse_breakpoint_disposition_line(
    line: Option<&str>,
) -> Result<BreakpointDisposition, String> {
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

pub(super) fn parse_breakpoint_policy_line(line: Option<&str>) -> Result<BreakpointPolicy, String> {
    match parse_wire_line(line, "breakpoint-policy=")? {
        "one-shot" => Ok(BreakpointPolicy::OneShot),
        "repeatable" => Ok(BreakpointPolicy::Repeatable),
        value => Err(format!("invalid breakpoint policy `{value}`")),
    }
}

pub(super) fn parse_query_kind_line(line: Option<&str>) -> Result<QueryKind, String> {
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
        "search-frontier" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::SearchFrontier)
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

pub(super) fn reject_extra_query_field(field: Option<&str>) -> Result<(), String> {
    if field.is_some() {
        return Err(String::from("unexpected extra query fields"));
    }
    Ok(())
}

pub(super) fn parse_seed_line(line: Option<&str>, prefix: &'static str) -> Result<Seed, String> {
    let value = parse_wire_line(line, prefix)?;
    Ok(Seed::from_bytes(parse_hex_32(value, "seed")?))
}

pub(super) fn parse_content_hash_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<ContentHash, String> {
    let value = parse_wire_line(line, prefix)?;
    Ok(ContentHash {
        bytes: parse_hex_32(value, "content hash")?,
    })
}

pub(super) fn parse_schedule_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<Schedule, String> {
    let value = parse_wire_line(line, prefix)?;
    Schedule::from_compact_binary(&parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid compact schedule: {error}"))
}

pub(super) fn parse_scenario_form_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<ScenarioDefForm, String> {
    let value = parse_wire_line(line, prefix)?;
    ScenarioDefForm::from_compact_binary(&parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid compact scenario form: {error}"))
}

pub(super) fn parse_checkpoint_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<Checkpoint, String> {
    let value = parse_wire_line(line, prefix)?;
    Checkpoint::from_compact_binary(&parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid compact checkpoint: {error}"))
}

pub(super) fn parse_hex_string_field(
    value: Option<&str>,
    label: &'static str,
) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("missing {label}"))?;
    String::from_utf8(parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid UTF-8 {label}: {error}"))
}

pub(super) fn parse_hex_32(value: &str, label: &'static str) -> Result<[u8; 32], String> {
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

pub(super) fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
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

pub(super) fn parse_bool_line(line: Option<&str>, prefix: &'static str) -> Result<bool, String> {
    match parse_wire_line(line, prefix)? {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(format!("invalid bool `{value}` for `{prefix}`")),
    }
}

pub(super) fn expect_wire_header(line: Option<&str>, expected: &'static str) -> Result<(), String> {
    match line {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("unexpected RPC message header `{actual}`")),
        None => Err(String::from("empty RPC request")),
    }
}

pub(super) fn parse_wire_line<'a>(
    line: Option<&'a str>,
    prefix: &'static str,
) -> Result<&'a str, String> {
    let line = line.ok_or_else(|| format!("missing `{prefix}` line"))?;
    line.strip_prefix(prefix)
        .ok_or_else(|| format!("expected `{prefix}` line, got `{line}`"))
}

pub(super) fn reject_extra_line(line: Option<&str>) -> Result<(), String> {
    if line.is_some() {
        return Err(String::from("unexpected trailing RPC request fields"));
    }
    Ok(())
}

pub(super) fn push_session_ref(output: &mut String, session: SessionRef) {
    push_wire_line(output, "session-id", &session.id.value.to_string());
    push_wire_line(output, "epoch", &session.epoch.to_string());
    push_wire_line(output, "seed", &session.seed.to_hex());
}

pub(super) fn push_wire_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

pub(super) fn state_wire_name(state: LiveStateKind) -> &'static str {
    match state {
        LiveStateKind::Loaded => "loaded",
        LiveStateKind::Paused => "paused",
        LiveStateKind::Running => "running",
        LiveStateKind::Stopped => "stopped",
    }
}

pub(super) fn outcome_wire_name(outcome: Option<OutcomeKind>) -> &'static str {
    match outcome {
        Some(OutcomeKind::Passed) => "passed",
        Some(OutcomeKind::Failed) => "failed",
        Some(OutcomeKind::Timeout) => "timeout",
        Some(OutcomeKind::Crashed) => "crashed",
        Some(OutcomeKind::Stopped) => "stopped",
        None => "none",
    }
}

pub(super) fn content_hash_option_wire(hash: Option<ContentHash>) -> String {
    match hash {
        Some(hash) => hash.to_hex(),
        None => String::from("none"),
    }
}

pub(super) fn command_name(command: SessionCommandKind) -> String {
    open_set_command_kind(command).unwrap_or_else(|| {
        let command_name = API_COMMAND_MAPPINGS
            .iter()
            .find(|mapping| mapping.command_kind == command)
            .map(|mapping| mapping.command_name)
            .unwrap_or("unknown");
        format!("crucible.cmd.{command_name}")
    })
}

pub(super) fn state_update_wire(update: StateUpdate) -> String {
    format!(
        "{}|{}|{}|{}",
        update.session.id.value,
        update.session.epoch,
        update.session.seed.to_hex(),
        state_wire_name(update.state),
    )
}

pub(super) fn control_event_body(
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

pub(super) fn watch_event_body(
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

pub(super) fn framed_rpc_message(message: String) -> axum::body::Bytes {
    let mut message = message;
    message.push('\n');
    axum::body::Bytes::from(message)
}

pub(super) fn encode_streaming_frame(frame: &StreamingFrame) -> String {
    match frame {
        StreamingFrame::Event(frame) => encode_streaming_event_frame(frame),
        StreamingFrame::StateUpdate(frame) => encode_streaming_state_update_frame(*frame),
    }
}

pub(super) fn encode_streaming_event_frame(frame: &StreamingEventFrame) -> String {
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

pub(super) fn encode_streaming_state_update_frame(frame: StreamingStateUpdateFrame) -> String {
    let mut output = String::from("crucible.rpc/state-update-frame\n");
    push_wire_line(&mut output, "sequence", &frame.sequence.to_string());
    push_wire_line(
        &mut output,
        "state-update",
        &state_update_wire(frame.update),
    );
    output
}

pub(super) fn optional_string_wire(value: Option<&str>) -> String {
    value
        .map(|value| hex_encode(value.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

pub(super) fn event_source_wire(source: &OpenSetEventSource) -> String {
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

pub(super) fn event_level_wire(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

pub(super) fn attribute_wire(value: &OpenSetAttributeValue) -> String {
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

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn http2_stream_response(
    body: impl futures_util::Stream<Item = Result<axum::body::Bytes, std::convert::Infallible>>
    + Send
    + 'static,
) -> axum::response::Response {
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .body(axum::body::Body::from_stream(body))
        .unwrap_or_else(|error| panic!("HTTP/2 test streaming response should build: {error}"))
}

pub(super) fn http2_response(
    status: axum::http::StatusCode,
    body: impl Into<axum::body::Body>,
) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .body(body.into())
        .unwrap_or_else(|error| panic!("HTTP/2 test response should build: {error}"))
}

pub(super) fn in_process_client_fixture() -> (InProcessControlClient, SessionActor<NoopLoop>) {
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

pub(super) fn streaming_session_fixture<L>(
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

pub(super) async fn start_and_pause_streaming_actor(
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

pub(super) async fn stop_streaming_actor(
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

pub(super) async fn assert_rejected_send(
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

pub(super) async fn assert_accepted_query_after_rejection(
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

pub(super) fn attach_gdb_command(node_name: &str) -> SessionCommand {
    SessionCommand::AttachGdb {
        node: NodeId {
            name: node_name.to_owned(),
        },
        listen: GdbListen::new("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("test gdb listen should be valid: {error}")),
        reply: CommandReply::discard(),
    }
}

pub(super) fn event_pair(first_sequence: u64, quantum: u64) -> Vec<SchedulerEventLogEntry> {
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

pub(super) fn event_burst(
    first_sequence: u64,
    first_quantum: u64,
    pairs: u64,
) -> Vec<SchedulerEventLogEntry> {
    let mut entries = Vec::new();
    for offset in 0..pairs {
        entries.extend(event_pair(
            first_sequence.saturating_add(offset.saturating_mul(2)),
            first_quantum.saturating_add(offset),
        ));
    }
    entries
}

pub(super) struct ServerQuantumLoop {
    pub(super) quanta: u64,
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

pub(super) struct ReferenceSimDoubleLoop {
    backend: SimDouble,
    quanta: u64,
    event_log_events: u64,
}

impl ReferenceSimDoubleLoop {
    pub(super) fn new() -> Self {
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

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        SimulationBackend::shutdown(&mut self.backend)
            .map(|()| Vec::new())
            .map_err(Into::into)
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

pub(super) fn ready_reference_sim_double() -> SimDouble {
    let mut backend = SimDouble::new(SimDoubleConfig::default())
        .unwrap_or_else(|error| panic!("reference SimDouble backend should build: {error}"));
    complete_reference_sim_double_setup(&mut backend);
    backend
}

pub(super) fn complete_reference_sim_double_setup(backend: &mut SimDouble) {
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

pub(super) struct RejectingGdbLoop {
    pub(super) quanta: u64,
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

pub(super) struct InternalGdbLoop {
    pub(super) quanta: u64,
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

pub(super) struct RejectingOnceShutdownLoop {
    pub(super) quanta: u64,
    pub(super) shutdown_rejections: u64,
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

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if self.shutdown_rejections == 0 {
            return Ok(Vec::new());
        }
        self.shutdown_rejections = self.shutdown_rejections.saturating_sub(1);
        Err(BackendError::Rejected {
            message: String::from("test backend rejected shutdown"),
        }
        .into())
    }
}

pub(super) struct NoopLoop;

impl QuantumLoop for NoopLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        panic!("control-client fixture should not drive scheduler quanta")
    }
}

pub(super) fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    let genesis = Configuration::genesis(scenario.clone());
    match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(&genesis)) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    }
}

pub(super) fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
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

pub(super) fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.api.gate-control-client.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

#[path = "http2_fixture/scenario.rs"]
mod scenario;

pub(crate) use scenario::*;
