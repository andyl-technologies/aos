//! Transport-agnostic control client trait and client handles.
//!
//! This module owns the RFC-0010 file 21.1 boundary: callers use one typed
//! [`ControlClient`] trait while implementations choose either the same-process
//! session actor path or the HTTP/2 RPC path. The two paths intentionally share
//! [`ControlWireModel`], which is backed by the frozen RPC ABI message encoder.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crucible::Seed;
use crucible_session::{LiveSnapshot, LiveStateKind, SessionCommand};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::event_log_stream::ControlPlaneEventLog;
use crate::lifecycle::{
    CreateSessionRequest, CreateSessionResponse, CreateSessionSource, DestroySessionRequest,
    DestroySessionResponse, LifecycleApiError, ListScenariosResponse, ListSessionsResponse,
    ScenarioSummary, SessionId, SessionRef, SessionSummary,
};
use crate::rpc_abi::{
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION, RpcAbiError,
    encode_rpc_hello_request, encode_rpc_hello_response, negotiate_rpc_protocol,
};

const HELLO_RPC_PATH: &str = "/crucible.rpc/hello";
const LIST_SCENARIOS_RPC_PATH: &str = "/crucible.rpc/list-scenarios";
const CREATE_SESSION_RPC_PATH: &str = "/crucible.rpc/create-session";
const LIST_SESSIONS_RPC_PATH: &str = "/crucible.rpc/list-sessions";
const DESTROY_SESSION_RPC_PATH: &str = "/crucible.rpc/destroy-session";
const RPC_CONTENT_TYPE: &str = "application/vnd.crucible.rpc";

/// Boxed asynchronous result returned by [`ControlClient`] methods.
pub type ControlClientFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ControlClientError>> + Send + 'a>>;

/// Transport used by one [`ControlClient`] implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlTransportKind {
    /// Same-process client over a `crucible-session` actor mailbox.
    InProcess,
    /// Out-of-process client over the HTTP/2 RPC surface.
    Http2Rpc,
}

/// Shared serialized message model used by every control client transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlWireModel {
    /// RPC protocol version used to serialize typed API messages.
    pub protocol_version: ProtocolVersion,
    /// Open-set payload kinds advertised by the API.
    pub payload_kinds: &'static [&'static str],
}

impl ControlWireModel {
    /// Builds the current control API wire model.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            protocol_version: RPC_PROTOCOL_VERSION,
            payload_kinds: RPC_OPEN_SET_PAYLOAD_KINDS,
        }
    }

    /// Encodes one typed [`HelloRequest`] using the shared canonical ABI encoder.
    #[must_use]
    pub fn encode_hello_request(self, request: &HelloRequest) -> Vec<u8> {
        encode_rpc_hello_request(&request.client_name, request.version)
    }

    /// Encodes one typed [`HelloResponse`] using the shared canonical ABI encoder.
    #[must_use]
    pub fn encode_hello_response(self, response: &HelloResponse) -> Vec<u8> {
        let _ = self;
        encode_rpc_hello_response(
            &response.server_name,
            response.version,
            response.payload_kinds,
        )
    }
}

/// Request sent by a client to discover protocol compatibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloRequest {
    /// Client implementation name.
    pub client_name: String,
    /// Highest protocol version offered by the client.
    pub version: ProtocolVersion,
}

impl HelloRequest {
    /// Builds a typed `Hello` request.
    #[must_use]
    pub fn new(client_name: impl Into<String>, version: ProtocolVersion) -> Self {
        Self {
            client_name: client_name.into(),
            version,
        }
    }
}

/// Discovery response returned by any [`ControlClient`] implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloResponse {
    /// Server or transport implementation name.
    pub server_name: String,
    /// Negotiated protocol version.
    pub version: ProtocolVersion,
    /// Payload kinds understood by this endpoint.
    pub payload_kinds: &'static [&'static str],
    /// Transport that produced the response.
    pub transport: ControlTransportKind,
}

impl HelloResponse {
    /// Builds a typed `Hello` response.
    #[must_use]
    pub fn new(
        server_name: impl Into<String>,
        version: ProtocolVersion,
        payload_kinds: &'static [&'static str],
        transport: ControlTransportKind,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            version,
            payload_kinds,
            transport,
        }
    }
}

/// Error returned by transport-agnostic control clients.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ControlClientError {
    /// Protocol negotiation failed.
    #[error("control client RPC ABI negotiation failed: {source}")]
    RpcAbi {
        /// Underlying RPC ABI error.
        #[from]
        source: RpcAbiError,
    },
    /// Lifecycle unary API operation failed.
    #[error("control client lifecycle operation failed: {source}")]
    Lifecycle {
        /// Underlying lifecycle API error.
        #[from]
        source: LifecycleApiError,
    },
    /// This client handle does not implement a lifecycle unary method.
    #[error("control client does not support lifecycle method {method}")]
    UnsupportedLifecycleMethod {
        /// Unsupported lifecycle method name.
        method: &'static str,
    },
    /// Two client transports do not expose the same serialized wire model.
    #[error("control client wire models differ: left={left:?} right={right:?}")]
    WireModelMismatch {
        /// Wire model exposed by the left client.
        left: ControlWireModel,
        /// Wire model exposed by the right client.
        right: ControlWireModel,
    },
    /// The HTTP/2 client could not be built.
    #[error("failed to build HTTP/2 control client: {message}")]
    HttpClientBuild {
        /// Deterministic client-build failure detail.
        message: String,
    },
    /// An HTTP/2 request failed.
    #[error("HTTP/2 control request failed: {message}")]
    HttpRequest {
        /// Deterministic request failure detail.
        message: String,
    },
    /// The HTTP/2 endpoint returned a non-success status.
    #[error("HTTP/2 control request returned status {status}")]
    HttpStatus {
        /// Numeric HTTP status code.
        status: u16,
    },
    /// The RPC response body could not be decoded.
    #[error("failed to decode control RPC response: {message}")]
    RpcDecode {
        /// Deterministic decode failure detail.
        message: String,
    },
}

/// Typed, asynchronous control-plane client shared by in-process and RPC paths.
pub trait ControlClient {
    /// Returns the transport used by this client.
    #[must_use]
    fn transport(&self) -> ControlTransportKind;

    /// Returns the serialized message model used by this client.
    #[must_use]
    fn wire_model(&self) -> ControlWireModel;

    /// Negotiates protocol compatibility and returns endpoint capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError::RpcAbi`] when the client offers an
    /// incompatible protocol major version.
    fn hello(&self, request: HelloRequest) -> ControlClientFuture<'_, HelloResponse>;

    /// Lists scenarios known by the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request or
    /// when this client handle does not implement lifecycle discovery.
    fn list_scenarios(&self) -> ControlClientFuture<'_, ListScenariosResponse> {
        Box::pin(async move {
            Err(ControlClientError::UnsupportedLifecycleMethod {
                method: "ListScenarios",
            })
        })
    }

    /// Creates a session through the lifecycle unary API.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request,
    /// the lifecycle server rejects the scenario, or this client handle does not
    /// implement lifecycle creation.
    fn create_session(
        &self,
        _request: CreateSessionRequest,
    ) -> ControlClientFuture<'_, CreateSessionResponse> {
        Box::pin(async move {
            Err(ControlClientError::UnsupportedLifecycleMethod {
                method: "CreateSession",
            })
        })
    }

    /// Lists sessions from the lifecycle registry and live mirrors.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request or
    /// when this client handle does not implement lifecycle listing.
    fn list_sessions(&self) -> ControlClientFuture<'_, ListSessionsResponse> {
        Box::pin(async move {
            Err(ControlClientError::UnsupportedLifecycleMethod {
                method: "ListSessions",
            })
        })
    }

    /// Destroys a session through the lifecycle unary API.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request,
    /// the lifecycle server rejects the epoch, or this client handle does not
    /// implement lifecycle destruction.
    fn destroy_session(
        &self,
        _request: DestroySessionRequest,
    ) -> ControlClientFuture<'_, DestroySessionResponse> {
        Box::pin(async move {
            Err(ControlClientError::UnsupportedLifecycleMethod {
                method: "DestroySession",
            })
        })
    }
}

/// Verifies that two client transports expose the same serialized wire model.
///
/// # Errors
///
/// Returns [`ControlClientError::WireModelMismatch`] when the two clients would
/// serialize typed API messages differently.
pub fn assert_shared_wire_model<A, B>(
    left: &A,
    right: &B,
) -> Result<ControlWireModel, ControlClientError>
where
    A: ControlClient,
    B: ControlClient,
{
    let left_model = left.wire_model();
    let right_model = right.wire_model();
    if left_model != right_model {
        return Err(ControlClientError::WireModelMismatch {
            left: left_model,
            right: right_model,
        });
    }
    let request = HelloRequest::new("crucible-api-wire-model-check", left_model.protocol_version);
    let left_request = left_model.encode_hello_request(&request);
    let right_request = right_model.encode_hello_request(&request);
    if left_request != right_request {
        return Err(ControlClientError::WireModelMismatch {
            left: left_model,
            right: right_model,
        });
    }
    let response = HelloResponse::new(
        "crucible-api-wire-model-check",
        left_model.protocol_version,
        left_model.payload_kinds,
        left.transport(),
    );
    let left_response = left_model.encode_hello_response(&response);
    let right_response = right_model.encode_hello_response(&response);
    if left_response != right_response {
        return Err(ControlClientError::WireModelMismatch {
            left: left_model,
            right: right_model,
        });
    }
    Ok(left_model)
}

/// Same-process client over a live `crucible-session` actor.
#[derive(Clone)]
pub struct InProcessControlClient {
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    event_log: ControlPlaneEventLog,
    wire_model: ControlWireModel,
}

impl InProcessControlClient {
    /// Builds an in-process client from actor-owned session handles.
    #[must_use]
    pub fn new(
        sender: mpsc::Sender<SessionCommand>,
        live: Arc<LiveSnapshot>,
        event_log: ControlPlaneEventLog,
    ) -> Self {
        Self {
            sender,
            live,
            event_log,
            wire_model: ControlWireModel::current(),
        }
    }

    /// Returns the actor mailbox used by this in-process client.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<SessionCommand> {
        self.sender.clone()
    }

    /// Returns the lock-free live session mirror used by this client.
    #[must_use]
    pub fn live_snapshot(&self) -> Arc<LiveSnapshot> {
        Arc::clone(&self.live)
    }

    /// Returns the event-log facade used by this client.
    #[must_use]
    pub const fn event_log(&self) -> &ControlPlaneEventLog {
        &self.event_log
    }

    /// Returns whether this client reaches the actor without serialization.
    #[must_use]
    pub const fn reaches_same_process_actor_without_serialization(&self) -> bool {
        true
    }
}

impl ControlClient for InProcessControlClient {
    fn transport(&self) -> ControlTransportKind {
        ControlTransportKind::InProcess
    }

    fn wire_model(&self) -> ControlWireModel {
        self.wire_model
    }

    fn hello(&self, request: HelloRequest) -> ControlClientFuture<'_, HelloResponse> {
        Box::pin(async move {
            let version = negotiate_rpc_protocol(request.version)?;
            Ok(HelloResponse::new(
                "crucible-in-process-session",
                version,
                self.wire_model.payload_kinds,
                self.transport(),
            ))
        })
    }
}

/// RPC transport protocol used by [`RpcControlClient`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcTransportProtocol {
    /// HTTP/2 transport for the gRPC/Connect-style surface.
    Http2,
}

/// Endpoint used by the out-of-process RPC client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcEndpoint {
    uri: String,
    protocol: RpcTransportProtocol,
}

impl RpcEndpoint {
    /// Builds an HTTP/2 RPC endpoint.
    #[must_use]
    pub fn http2(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            protocol: RpcTransportProtocol::Http2,
        }
    }

    /// Returns the endpoint URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Returns the endpoint transport protocol.
    #[must_use]
    pub const fn protocol(&self) -> RpcTransportProtocol {
        self.protocol
    }

    fn rpc_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.uri.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

/// Out-of-process control client over the HTTP/2 RPC surface.
#[derive(Clone)]
pub struct RpcControlClient {
    endpoint: RpcEndpoint,
    http: reqwest::Client,
    wire_model: ControlWireModel,
}

impl RpcControlClient {
    /// Builds an RPC client for `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError::HttpClientBuild`] when the HTTP/2 client
    /// cannot be initialized.
    pub fn new(endpoint: RpcEndpoint) -> Result<Self, ControlClientError> {
        let http = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .map_err(|error| ControlClientError::HttpClientBuild {
                message: error.to_string(),
            })?;
        Ok(Self {
            endpoint,
            http,
            wire_model: ControlWireModel::current(),
        })
    }

    /// Returns the configured RPC endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &RpcEndpoint {
        &self.endpoint
    }

    async fn post_rpc_body(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ControlClientError> {
        let response = self
            .http
            .post(self.endpoint.rpc_url(path))
            .header(reqwest::header::CONTENT_TYPE, RPC_CONTENT_TYPE)
            .body(body)
            .send()
            .await
            .map_err(|error| ControlClientError::HttpRequest {
                message: error.to_string(),
            })?;
        if !response.status().is_success() {
            return Err(ControlClientError::HttpStatus {
                status: response.status().as_u16(),
            });
        }
        response
            .bytes()
            .await
            .map(|body| body.to_vec())
            .map_err(|error| ControlClientError::HttpRequest {
                message: error.to_string(),
            })
    }
}

impl ControlClient for RpcControlClient {
    fn transport(&self) -> ControlTransportKind {
        ControlTransportKind::Http2Rpc
    }

    fn wire_model(&self) -> ControlWireModel {
        self.wire_model
    }

    fn hello(&self, request: HelloRequest) -> ControlClientFuture<'_, HelloResponse> {
        Box::pin(async move {
            let _version = negotiate_rpc_protocol(request.version)?;
            let body = self
                .post_rpc_body(
                    HELLO_RPC_PATH,
                    self.wire_model.encode_hello_request(&request),
                )
                .await?;
            decode_hello_response(&body, self.transport())
        })
    }

    fn list_scenarios(&self) -> ControlClientFuture<'_, ListScenariosResponse> {
        Box::pin(async move {
            let body = self
                .post_rpc_body(
                    LIST_SCENARIOS_RPC_PATH,
                    b"crucible.rpc/list-scenarios-request\n".to_vec(),
                )
                .await?;
            decode_list_scenarios_response(&body)
        })
    }

    fn create_session(
        &self,
        request: CreateSessionRequest,
    ) -> ControlClientFuture<'_, CreateSessionResponse> {
        Box::pin(async move {
            let body = self
                .post_rpc_body(
                    CREATE_SESSION_RPC_PATH,
                    encode_create_session_request(&request),
                )
                .await?;
            decode_create_session_response(&body)
        })
    }

    fn list_sessions(&self) -> ControlClientFuture<'_, ListSessionsResponse> {
        Box::pin(async move {
            let body = self
                .post_rpc_body(
                    LIST_SESSIONS_RPC_PATH,
                    b"crucible.rpc/list-sessions-request\n".to_vec(),
                )
                .await?;
            decode_list_sessions_response(&body)
        })
    }

    fn destroy_session(
        &self,
        request: DestroySessionRequest,
    ) -> ControlClientFuture<'_, DestroySessionResponse> {
        Box::pin(async move {
            let body = self
                .post_rpc_body(
                    DESTROY_SESSION_RPC_PATH,
                    encode_destroy_session_request(&request),
                )
                .await?;
            decode_destroy_session_response(&body)
        })
    }
}

fn decode_hello_response(
    body: &[u8],
    transport: ControlTransportKind,
) -> Result<HelloResponse, ControlClientError> {
    let text = std::str::from_utf8(body).map_err(|error| ControlClientError::RpcDecode {
        message: error.to_string(),
    })?;
    let mut lines = text.lines();
    match lines.next() {
        Some("crucible.rpc/hello-response") => {}
        Some(header) => {
            return Err(ControlClientError::RpcDecode {
                message: format!("unexpected RPC message header `{header}`"),
            });
        }
        None => {
            return Err(ControlClientError::RpcDecode {
                message: String::from("empty RPC response"),
            });
        }
    }

    let version = parse_current_version_line(lines.next())?;
    let server_name = parse_prefixed_line(lines.next(), "server=")?;
    let payload_kinds = parse_payload_kinds_line(lines.next())?;
    if lines.next().is_some() {
        return Err(ControlClientError::RpcDecode {
            message: String::from("unexpected trailing fields in hello response"),
        });
    }

    Ok(HelloResponse::new(
        server_name,
        version,
        payload_kinds,
        transport,
    ))
}

fn encode_create_session_request(request: &CreateSessionRequest) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("crucible.rpc/create-session-request\n");
    match &request.source {
        CreateSessionSource::ScenarioRef { name } => {
            push_line(&mut output, "source", "scenario-ref");
            push_line(&mut output, "name", name);
        }
        CreateSessionSource::Inline { scenario } => {
            push_line(&mut output, "source", "inline");
            push_line(&mut output, "scenario-id", &scenario.id().to_hex());
            push_line(&mut output, "scenario-seed", &scenario.seed().to_hex());
            push_line(
                &mut output,
                "app-random-draw-cap",
                &scenario.app_random_draw_cap().to_string(),
            );
        }
    }
    push_line(&mut output, "seed", &request.seed.to_hex());
    push_line(
        &mut output,
        "start-paused",
        if request.start_paused {
            "true"
        } else {
            "false"
        },
    );
    output.into_bytes()
}

fn encode_destroy_session_request(request: &DestroySessionRequest) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("crucible.rpc/destroy-session-request\n");
    push_session_ref(&mut output, request.session);
    output.into_bytes()
}

fn decode_list_scenarios_response(
    body: &[u8],
) -> Result<ListScenariosResponse, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), "crucible.rpc/list-scenarios-response")?;
    let mut scenarios = Vec::new();
    for line in lines {
        let value = parse_prefixed_line(Some(line), "scenario=")?;
        let mut fields = value.splitn(3, '|');
        let name = fields
            .next()
            .ok_or_else(|| rpc_decode("missing scenario name"))?;
        let description = fields
            .next()
            .ok_or_else(|| rpc_decode("missing scenario description"))?;
        let source_id = fields
            .next()
            .ok_or_else(|| rpc_decode("missing scenario source id"))?;
        scenarios.push(ScenarioSummary {
            name: name.to_owned(),
            description: description.to_owned(),
            source_id: source_id.to_owned(),
        });
    }
    Ok(ListScenariosResponse { scenarios })
}

fn decode_create_session_response(
    body: &[u8],
) -> Result<CreateSessionResponse, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), "crucible.rpc/create-session-response")?;
    let session = parse_session_ref(&mut lines)?;
    let state = parse_state_line(lines.next())?;
    reject_trailing(lines.next())?;
    Ok(CreateSessionResponse { session, state })
}

fn decode_list_sessions_response(body: &[u8]) -> Result<ListSessionsResponse, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), "crucible.rpc/list-sessions-response")?;
    let mut sessions = Vec::new();
    for line in lines {
        let value = parse_prefixed_line(Some(line), "session=")?;
        let mut fields = value.split('|');
        let id = parse_u64_field(fields.next(), "session id")?;
        let epoch = parse_u64_field(fields.next(), "session epoch")?;
        let seed = parse_seed_field(fields.next(), "session seed")?;
        let state = parse_state_field(fields.next(), "session state")?;
        let event_log_len = parse_u64_field(fields.next(), "event log length")?;
        if fields.next().is_some() {
            return Err(rpc_decode("unexpected extra session summary fields"));
        }
        sessions.push(SessionSummary {
            session: SessionRef::new(SessionId::new(id), epoch, seed),
            state,
            event_log_len,
        });
    }
    Ok(ListSessionsResponse { sessions })
}

fn decode_destroy_session_response(
    body: &[u8],
) -> Result<DestroySessionResponse, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), "crucible.rpc/destroy-session-response")?;
    let session = parse_session_ref(&mut lines)?;
    let already_absent = parse_bool_line(lines.next(), "already-absent=")?;
    let stopped = parse_bool_line(lines.next(), "stopped=")?;
    reject_trailing(lines.next())?;
    Ok(DestroySessionResponse {
        session,
        already_absent,
        stopped,
    })
}

fn response_text(body: &[u8]) -> Result<&str, ControlClientError> {
    std::str::from_utf8(body).map_err(|error| ControlClientError::RpcDecode {
        message: error.to_string(),
    })
}

fn expect_header(line: Option<&str>, expected: &'static str) -> Result<(), ControlClientError> {
    match line {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(rpc_decode(format!(
            "unexpected RPC message header `{actual}`"
        ))),
        None => Err(rpc_decode("empty RPC response")),
    }
}

fn parse_session_ref<'a, I>(lines: &mut I) -> Result<SessionRef, ControlClientError>
where
    I: Iterator<Item = &'a str>,
{
    let id = parse_u64_line(lines.next(), "session-id=")?;
    let epoch = parse_u64_line(lines.next(), "epoch=")?;
    let seed = parse_seed_line(lines.next(), "seed=")?;
    Ok(SessionRef::new(SessionId::new(id), epoch, seed))
}

fn parse_u64_line(line: Option<&str>, prefix: &'static str) -> Result<u64, ControlClientError> {
    let value = parse_prefixed_line(line, prefix)?;
    value
        .parse::<u64>()
        .map_err(|error| rpc_decode(format!("invalid integer `{value}` for `{prefix}`: {error}")))
}

fn parse_u64_field(value: Option<&str>, label: &'static str) -> Result<u64, ControlClientError> {
    let value = value.ok_or_else(|| rpc_decode(format!("missing {label}")))?;
    value
        .parse::<u64>()
        .map_err(|error| rpc_decode(format!("invalid {label} `{value}`: {error}")))
}

fn parse_seed_line(line: Option<&str>, prefix: &'static str) -> Result<Seed, ControlClientError> {
    let value = parse_prefixed_line(line, prefix)?;
    parse_seed_hex(value)
}

fn parse_seed_field(value: Option<&str>, label: &'static str) -> Result<Seed, ControlClientError> {
    let value = value.ok_or_else(|| rpc_decode(format!("missing {label}")))?;
    parse_seed_hex(value)
}

fn parse_seed_hex(value: &str) -> Result<Seed, ControlClientError> {
    if value.len() != 64 {
        return Err(rpc_decode(format!("seed hex has length {}", value.len())));
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        let pair = &value[start..start + 2];
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|error| rpc_decode(format!("invalid seed hex `{pair}`: {error}")))?;
    }
    Ok(Seed::from_bytes(bytes))
}

fn parse_state_line(line: Option<&str>) -> Result<LiveStateKind, ControlClientError> {
    parse_state_field(Some(parse_prefixed_line(line, "state=")?), "state")
}

fn parse_state_field(
    value: Option<&str>,
    label: &'static str,
) -> Result<LiveStateKind, ControlClientError> {
    match value.ok_or_else(|| rpc_decode(format!("missing {label}")))? {
        "loaded" => Ok(LiveStateKind::Loaded),
        "running" => Ok(LiveStateKind::Running),
        "paused" => Ok(LiveStateKind::Paused),
        "stopped" => Ok(LiveStateKind::Stopped),
        value => Err(rpc_decode(format!("invalid {label} `{value}`"))),
    }
}

fn parse_bool_line(line: Option<&str>, prefix: &'static str) -> Result<bool, ControlClientError> {
    match parse_prefixed_line(line, prefix)? {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(rpc_decode(format!("invalid bool `{value}` for `{prefix}`"))),
    }
}

fn reject_trailing(line: Option<&str>) -> Result<(), ControlClientError> {
    if line.is_some() {
        return Err(rpc_decode("unexpected trailing fields in RPC response"));
    }
    Ok(())
}

fn push_session_ref(output: &mut String, session: SessionRef) {
    push_line(output, "session-id", &session.id.value.to_string());
    push_line(output, "epoch", &session.epoch.to_string());
    push_line(output, "seed", &session.seed.to_hex());
}

fn push_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

fn rpc_decode(message: impl Into<String>) -> ControlClientError {
    ControlClientError::RpcDecode {
        message: message.into(),
    }
}

fn parse_current_version_line(line: Option<&str>) -> Result<ProtocolVersion, ControlClientError> {
    let value = parse_prefixed_line(line, "version=")?;
    let expected = format!(
        "{}.{}.{}+{}",
        RPC_PROTOCOL_VERSION.major,
        RPC_PROTOCOL_VERSION.minor,
        RPC_PROTOCOL_VERSION.patch,
        RPC_PROTOCOL_VERSION.build
    );
    if value != expected {
        return Err(ControlClientError::RpcDecode {
            message: format!("unsupported hello version `{value}`"),
        });
    }
    Ok(RPC_PROTOCOL_VERSION)
}

fn parse_payload_kinds_line(
    line: Option<&str>,
) -> Result<&'static [&'static str], ControlClientError> {
    let value = parse_prefixed_line(line, "payload-kinds=")?;
    let expected = RPC_OPEN_SET_PAYLOAD_KINDS.join(",");
    if value != expected {
        return Err(ControlClientError::RpcDecode {
            message: format!("unsupported payload kind set `{value}`"),
        });
    }
    Ok(RPC_OPEN_SET_PAYLOAD_KINDS)
}

fn parse_prefixed_line<'a>(
    line: Option<&'a str>,
    prefix: &'static str,
) -> Result<&'a str, ControlClientError> {
    let Some(line) = line else {
        return Err(ControlClientError::RpcDecode {
            message: format!("missing `{prefix}` line"),
        });
    };
    line.strip_prefix(prefix)
        .ok_or_else(|| ControlClientError::RpcDecode {
            message: format!("expected `{prefix}` line, got `{line}`"),
        })
}
