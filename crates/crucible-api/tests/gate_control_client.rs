//! API-side checks for the shared `ControlClient` trait.

#![forbid(unsafe_code)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, GenesisCheckpoint, QuantumLoop, QuantumOutcome,
    QuantumRequest, ScenarioDef, SchedulerError, Seed, TemporalGraph, VirtualTime,
};
use crucible_api::{
    ControlClient, ControlPlaneEventLog, ControlTransportKind, ControlWireModel, HelloRequest,
    InProcessControlClient, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION, RpcControlClient,
    RpcEndpoint, RpcTransportProtocol, assert_shared_wire_model, encode_rpc_hello_request,
    encode_rpc_hello_response,
};
use crucible_session::{Engine, SessionActor, SessionCommand};
use tokio::sync::mpsc;

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

struct Http2HelloServer {
    endpoint: String,
    saw_http2: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Http2HelloServer {
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

async fn spawn_http2_hello_server() -> Http2HelloServer {
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, Version};
    use axum::response::Response;
    use axum::routing::post;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("HTTP/2 test listener should bind: {error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("HTTP/2 test listener should report address: {error}"));
    let saw_http2 = Arc::new(AtomicBool::new(false));
    let saw_http2_for_handler = Arc::clone(&saw_http2);
    let app = Router::new().route(
        "/crucible.rpc/hello",
        post(move |request: Request<Body>| {
            let saw_http2 = Arc::clone(&saw_http2_for_handler);
            async move {
                if request.version() == Version::HTTP_2 {
                    saw_http2.store(true, Ordering::SeqCst);
                }
                let bytes = to_bytes(request.into_body(), usize::MAX).await;
                let Ok(body) = bytes else {
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("invalid request body"))
                        .unwrap_or_else(|error| {
                            panic!("HTTP/2 test response should build: {error}")
                        });
                };
                if body != encode_rpc_hello_request("api-control-client-test", RPC_PROTOCOL_VERSION)
                {
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("unexpected hello request"))
                        .unwrap_or_else(|error| {
                            panic!("HTTP/2 test response should build: {error}")
                        });
                }
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(encode_rpc_hello_response(
                        "crucible-http2-test-server",
                        RPC_PROTOCOL_VERSION,
                        RPC_OPEN_SET_PAYLOAD_KINDS,
                    )))
                    .unwrap_or_else(|error| panic!("HTTP/2 test response should build: {error}"))
            }
        }),
    );
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            panic!("HTTP/2 test server should serve: {error}");
        }
    });

    Http2HelloServer {
        endpoint: format!("http://{addr}"),
        saw_http2,
    }
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
