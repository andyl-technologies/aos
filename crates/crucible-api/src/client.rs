//! Transport-agnostic control client trait and client handles.
//!
//! This module owns the RFC-0010 file 21.1 boundary: callers use one typed
//! [`ControlClient`] trait while implementations choose either the same-process
//! session actor path or the HTTP/2 RPC path. The two paths intentionally share
//! [`ControlWireModel`], which is backed by the frozen RPC ABI message encoder.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use crucible::{EventLevel, Seed};
use crucible_session::{LiveSnapshot, LiveStateKind, SessionCommand, SessionCommandKind};
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use thiserror::Error;
use tokio::sync::mpsc;

use crate::event_log_stream::{ControlPlaneEventLog, EventLogCursor};
use crate::lifecycle::{
    CreateSessionRequest, CreateSessionResponse, CreateSessionSource, DestroySessionRequest,
    DestroySessionResponse, LifecycleApiError, ListScenariosResponse, ListSessionsResponse,
    ScenarioSummary, SessionId, SessionRef, SessionSummary,
};
use crate::open_set::{
    OpenSetAttributeValue, OpenSetEventEnvelope, OpenSetEventSource, OpenSetEventTime,
    OpenSetPayload, open_set_command_kind, session_command_for_open_set_command_kind,
};
use crate::rpc_abi::{
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION, RpcAbiError,
    encode_rpc_hello_request, encode_rpc_hello_response, negotiate_rpc_protocol,
};
use crate::session_mapping::{API_COMMAND_MAPPINGS, api_command_for_session_command};
use crate::streaming::{
    AttachRequest, AttachSnapshot, Attached, CommandRejectionKind, CommandResult,
    CommandResultStatus, SendRequest, SendResponse, StateUpdate, StreamingApiError,
    StreamingCapabilitySet, StreamingCommandCapability, StreamingEventFrame,
};

const HELLO_RPC_PATH: &str = "/crucible.rpc/hello";
const LIST_SCENARIOS_RPC_PATH: &str = "/crucible.rpc/list-scenarios";
const CREATE_SESSION_RPC_PATH: &str = "/crucible.rpc/create-session";
const LIST_SESSIONS_RPC_PATH: &str = "/crucible.rpc/list-sessions";
const DESTROY_SESSION_RPC_PATH: &str = "/crucible.rpc/destroy-session";
const CONTROL_ATTACH_RPC_PATH: &str = "/crucible.rpc/control/attach";
const CONTROL_SEND_RPC_PATH: &str = "/crucible.rpc/control/send";
const WATCH_ATTACH_RPC_PATH: &str = "/crucible.rpc/watch";
const SEND_COMMAND_RPC_PATH: &str = "/crucible.rpc/send";
const RPC_CONTENT_TYPE: &str = "application/vnd.crucible.rpc";
const RPC_STREAM_EVENT_CHANNEL_CAPACITY: usize = 16;

/// Boxed asynchronous result returned by [`ControlClient`] methods.
pub type ControlClientFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ControlClientError>> + Send + 'a>>;

/// Attached bidirectional `Control` stream returned by a [`ControlClient`].
pub enum ClientControlStream {
    /// Same-process stream over the session actor mailbox and event-log hub.
    InProcess(crate::streaming::ControlStream),
    /// HTTP/2 RPC stream.
    Rpc(RpcControlStream),
}

impl ClientControlStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub fn attached(&self) -> &Attached {
        match self {
            Self::InProcess(stream) => stream.attached(),
            Self::Rpc(stream) => stream.attached(),
        }
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the underlying transport fails, the
    /// RPC event frame is malformed, or the in-process event-log stream lags.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        match self {
            Self::InProcess(stream) => stream.recv_event().await.map_err(ControlClientError::from),
            Self::Rpc(stream) => stream.recv_event().await,
        }
    }

    /// Dispatches one command envelope through this control stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when command dispatch is rejected by the
    /// streaming layer or by the RPC transport.
    pub async fn send_command(
        &self,
        command_id: u64,
        command: SessionCommand,
    ) -> Result<SendResponse, ControlClientError> {
        match self {
            Self::InProcess(stream) => stream
                .send_command(command_id, command)
                .await
                .map_err(ControlClientError::from),
            Self::Rpc(stream) => stream.send_command(command_id, command).await,
        }
    }
}

/// Attached read-only `Watch` stream returned by a [`ControlClient`].
pub enum ClientWatchStream {
    /// Same-process stream over the session event-log hub.
    InProcess(crate::streaming::WatchStream),
    /// HTTP/2 RPC stream.
    Rpc(RpcWatchStream),
}

impl ClientWatchStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub fn attached(&self) -> &Attached {
        match self {
            Self::InProcess(stream) => stream.attached(),
            Self::Rpc(stream) => stream.attached(),
        }
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the underlying transport fails, the
    /// RPC event frame is malformed, or the in-process event-log stream lags.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        match self {
            Self::InProcess(stream) => stream.recv_event().await.map_err(ControlClientError::from),
            Self::Rpc(stream) => stream.recv_event().await,
        }
    }
}

/// Attached HTTP/2 RPC `Control` stream.
pub struct RpcControlStream {
    attached: Attached,
    events: RpcStreamingEventReceiver,
    client: RpcControlClient,
}

impl RpcControlStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub const fn attached(&self) -> &Attached {
        &self.attached
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the HTTP/2 response stream fails or
    /// the next event frame cannot be decoded.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        self.events.recv_event().await
    }

    /// Dispatches one command envelope over the RPC control stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the RPC command endpoint rejects the
    /// request or the response cannot be decoded.
    pub async fn send_command(
        &self,
        command_id: u64,
        command: SessionCommand,
    ) -> Result<SendResponse, ControlClientError> {
        self.client
            .control_send(SendRequest::new(self.attached.session, command_id, command))
            .await
    }
}

/// Attached HTTP/2 RPC `Watch` stream.
pub struct RpcWatchStream {
    attached: Attached,
    events: RpcStreamingEventReceiver,
}

impl RpcWatchStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub const fn attached(&self) -> &Attached {
        &self.attached
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the HTTP/2 response stream fails or
    /// the next event frame cannot be decoded.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        self.events.recv_event().await
    }
}

struct RpcStreamingEventReceiver {
    frames: mpsc::Receiver<Result<StreamingEventFrame, ControlClientError>>,
}

impl RpcStreamingEventReceiver {
    async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        match self.frames.recv().await {
            Some(Ok(frame)) => Ok(Some(frame)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }
}

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
    /// Streaming API operation failed.
    #[error("control client streaming operation failed: {source}")]
    Streaming {
        /// Underlying streaming API error.
        #[from]
        source: StreamingApiError,
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

    /// Attaches the bidirectional `Control` stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request or
    /// when this client handle does not implement streaming attach.
    fn control_attach(
        &self,
        _request: AttachRequest,
    ) -> ControlClientFuture<'_, ClientControlStream> {
        Box::pin(async move {
            Err(ControlClientError::UnsupportedLifecycleMethod { method: "Control" })
        })
    }

    /// Dispatches one command envelope over the bidirectional `Control` stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request or
    /// when this client handle does not implement streaming command dispatch.
    fn control_send(&self, _request: SendRequest) -> ControlClientFuture<'_, SendResponse> {
        Box::pin(async move {
            Err(ControlClientError::UnsupportedLifecycleMethod {
                method: "Control.Send",
            })
        })
    }

    /// Attaches the read-only `Watch` stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request or
    /// when this client handle does not implement watch attach.
    fn watch_attach(&self, _request: AttachRequest) -> ControlClientFuture<'_, ClientWatchStream> {
        Box::pin(
            async move { Err(ControlClientError::UnsupportedLifecycleMethod { method: "Watch" }) },
        )
    }

    /// Dispatches one unary `Send` command.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the transport rejects the request or
    /// when this client handle does not implement unary command dispatch.
    fn send_command(&self, _request: SendRequest) -> ControlClientFuture<'_, SendResponse> {
        Box::pin(
            async move { Err(ControlClientError::UnsupportedLifecycleMethod { method: "Send" }) },
        )
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

    async fn post_rpc_stream(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, ControlClientError> {
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
        Ok(response)
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

    fn control_attach(
        &self,
        request: AttachRequest,
    ) -> ControlClientFuture<'_, ClientControlStream> {
        Box::pin(async move {
            let response = self
                .post_rpc_stream(CONTROL_ATTACH_RPC_PATH, encode_attach_request(&request))
                .await?;
            let (attached, events) = decode_attached_stream_response(response).await?;
            Ok(ClientControlStream::Rpc(RpcControlStream {
                attached,
                events,
                client: self.clone(),
            }))
        })
    }

    fn control_send(&self, request: SendRequest) -> ControlClientFuture<'_, SendResponse> {
        Box::pin(async move {
            let body = self
                .post_rpc_body(CONTROL_SEND_RPC_PATH, encode_send_request(&request))
                .await?;
            decode_send_response(&body)
        })
    }

    fn watch_attach(&self, request: AttachRequest) -> ControlClientFuture<'_, ClientWatchStream> {
        Box::pin(async move {
            let response = self
                .post_rpc_stream(WATCH_ATTACH_RPC_PATH, encode_attach_request(&request))
                .await?;
            let (attached, events) = decode_attached_stream_response(response).await?;
            Ok(ClientWatchStream::Rpc(RpcWatchStream { attached, events }))
        })
    }

    fn send_command(&self, request: SendRequest) -> ControlClientFuture<'_, SendResponse> {
        Box::pin(async move {
            let body = self
                .post_rpc_body(SEND_COMMAND_RPC_PATH, encode_send_request(&request))
                .await?;
            decode_send_response(&body)
        })
    }
}

async fn decode_attached_stream_response(
    response: reqwest::Response,
) -> Result<(Attached, RpcStreamingEventReceiver), ControlClientError> {
    let mut stream = response.bytes_stream().boxed();
    let mut buffer = Vec::new();
    let attached_message = read_next_framed_rpc_message(&mut stream, &mut buffer)
        .await?
        .ok_or_else(|| rpc_decode("empty RPC stream attach response"))?;
    let attached = decode_attached_response(&attached_message)?;
    let (sender, receiver) = mpsc::channel(RPC_STREAM_EVENT_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        pump_rpc_event_frames(stream, buffer, sender).await;
    });
    Ok((attached, RpcStreamingEventReceiver { frames: receiver }))
}

async fn pump_rpc_event_frames(
    mut stream: BoxStream<'static, Result<Bytes, reqwest::Error>>,
    mut buffer: Vec<u8>,
    sender: mpsc::Sender<Result<StreamingEventFrame, ControlClientError>>,
) {
    loop {
        let message = match read_next_framed_rpc_message(&mut stream, &mut buffer).await {
            Ok(Some(message)) => message,
            Ok(None) => return,
            Err(error) => {
                let _send_result = sender.send(Err(error)).await;
                return;
            }
        };
        let frame = decode_streaming_event_frame(&message);
        if sender.send(frame).await.is_err() {
            return;
        }
    }
}

async fn read_next_framed_rpc_message(
    stream: &mut BoxStream<'static, Result<Bytes, reqwest::Error>>,
    buffer: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, ControlClientError> {
    loop {
        if let Some(position) = rpc_message_separator(buffer) {
            let message = buffer[..position].to_vec();
            buffer.drain(..position.saturating_add(2));
            if message.is_empty() {
                continue;
            }
            return Ok(Some(message));
        }

        let Some(chunk) = stream.next().await else {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Ok(Some(std::mem::take(buffer)));
        };
        let chunk = chunk.map_err(|error| ControlClientError::HttpRequest {
            message: error.to_string(),
        })?;
        buffer.extend_from_slice(&chunk);
    }
}

fn rpc_message_separator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\n\n")
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

fn encode_attach_request(request: &AttachRequest) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("crucible.rpc/attach-request\n");
    push_session_ref(&mut output, request.session);
    match request.expected_epoch {
        Some(epoch) => push_line(&mut output, "expected-epoch", &epoch.to_string()),
        None => push_line(&mut output, "expected-epoch", "none"),
    }
    push_line(
        &mut output,
        "from-seq",
        &request.from.next_sequence.to_string(),
    );
    push_line(&mut output, "client-name", &request.client_name);
    output.into_bytes()
}

fn encode_send_request(request: &SendRequest) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("crucible.rpc/send-request\n");
    push_session_ref(&mut output, request.session);
    match request.expected_epoch {
        Some(epoch) => push_line(&mut output, "expected-epoch", &epoch.to_string()),
        None => push_line(&mut output, "expected-epoch", "none"),
    }
    push_line(&mut output, "command-id", &request.command_id.to_string());
    let command_kind = SessionCommandKind::from(&request.command);
    let command_kind = open_set_command_kind(command_kind)
        .unwrap_or_else(|| format!("crucible.cmd.{}", command_kind_name(command_kind)));
    push_line(&mut output, "command", &command_kind);
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

fn decode_attached_response(body: &[u8]) -> Result<Attached, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), "crucible.rpc/attached-response")?;
    let session = parse_session_ref(&mut lines)?;
    let event_log_len = parse_u64_line(lines.next(), "event-log-len=")?;
    let state = parse_state_line(lines.next())?;
    let version = parse_current_version_line(lines.next())?;
    let capabilities = parse_capabilities_line(lines.next())?;
    let snapshot = parse_attach_snapshot_line(lines.next())?;
    reject_trailing(lines.next())?;
    Ok(Attached {
        session,
        event_log_len,
        state,
        version,
        capabilities,
        snapshot,
    })
}

fn decode_send_response(body: &[u8]) -> Result<SendResponse, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), "crucible.rpc/send-response")?;
    let command_id = parse_u64_line(lines.next(), "command-id=")?;
    let command_kind = parse_command_kind_line(lines.next(), "command=")?;
    let status = parse_command_status_line(lines.next())?;
    let state_update = parse_state_update_line(lines.next())?;
    reject_trailing(lines.next())?;
    Ok(SendResponse {
        result: CommandResult {
            command_id,
            command_kind,
            status,
        },
        state_update,
    })
}

fn decode_streaming_event_frame(body: &[u8]) -> Result<StreamingEventFrame, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), "crucible.rpc/event-frame")?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let cursor = EventLogCursor::new(parse_u64_line(lines.next(), "cursor=")?);
    let next_cursor = EventLogCursor::new(parse_u64_line(lines.next(), "next-cursor=")?);
    let sequence = parse_u64_line(lines.next(), "sequence=")?;
    let virtual_time_ticks = parse_u64_line(lines.next(), "virtual-time-ticks=")?;
    let icount_retired = parse_u64_line(lines.next(), "icount-retired=")?;
    let icount_node = parse_optional_hex_string_line(lines.next(), "icount-node=")?;
    let source = parse_event_source_line(lines.next())?;
    let level = parse_event_level_line(lines.next())?;
    let observational = parse_bool_line(lines.next(), "observational=")?;
    let kind = parse_prefixed_line(lines.next(), "kind=")?.to_owned();
    let attributes = parse_event_attributes(lines)?;
    Ok(StreamingEventFrame {
        generation,
        cursor,
        next_cursor,
        event: OpenSetEventEnvelope {
            sequence,
            at: OpenSetEventTime {
                virtual_time_ticks,
                icount_retired,
                icount_node,
            },
            source,
            level,
            observational,
            payload: OpenSetPayload::new(kind, attributes),
        },
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

fn parse_optional_hex_string_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<Option<String>, ControlClientError> {
    match parse_prefixed_line(line, prefix)? {
        "none" => Ok(None),
        value => parse_hex_string(value).map(Some),
    }
}

fn parse_event_source_line(line: Option<&str>) -> Result<OpenSetEventSource, ControlClientError> {
    let value = parse_prefixed_line(line, "source=")?;
    let mut fields = value.split('|');
    let source = match fields
        .next()
        .ok_or_else(|| rpc_decode("missing event source tag"))?
    {
        "engine" => OpenSetEventSource::Engine,
        "scenario" => OpenSetEventSource::Scenario {
            event: parse_event_source_string(fields.next(), "scenario event")?,
        },
        "node" => OpenSetEventSource::Node {
            node: parse_event_source_string(fields.next(), "node")?,
        },
        "guest" => OpenSetEventSource::Guest {
            node: parse_event_source_string(fields.next(), "guest node")?,
        },
        "command" => OpenSetEventSource::Command {
            command_id: parse_u64_field(fields.next(), "command id")?,
        },
        tag => return Err(rpc_decode(format!("unknown event source tag `{tag}`"))),
    };
    if fields.next().is_some() {
        return Err(rpc_decode("unexpected extra event source fields"));
    }
    Ok(source)
}

fn parse_event_source_string(
    value: Option<&str>,
    label: &'static str,
) -> Result<String, ControlClientError> {
    let value = value.ok_or_else(|| rpc_decode(format!("missing {label}")))?;
    parse_hex_string(value)
}

fn parse_event_level_line(line: Option<&str>) -> Result<EventLevel, ControlClientError> {
    match parse_prefixed_line(line, "level=")? {
        "trace" => Ok(EventLevel::Trace),
        "debug" => Ok(EventLevel::Debug),
        "info" => Ok(EventLevel::Info),
        "warn" => Ok(EventLevel::Warn),
        "error" => Ok(EventLevel::Error),
        value => Err(rpc_decode(format!("unknown event level `{value}`"))),
    }
}

fn parse_event_attributes<'a, I>(
    lines: I,
) -> Result<BTreeMap<String, OpenSetAttributeValue>, ControlClientError>
where
    I: Iterator<Item = &'a str>,
{
    let mut attributes = BTreeMap::new();
    for line in lines {
        let value = parse_prefixed_line(Some(line), "attribute=")?;
        let (name, attribute) = parse_event_attribute(value)?;
        attributes.insert(name, attribute);
    }
    Ok(attributes)
}

fn parse_event_attribute(
    value: &str,
) -> Result<(String, OpenSetAttributeValue), ControlClientError> {
    let mut fields = value.split('|');
    let name = parse_hex_field(fields.next(), "attribute name")?;
    let type_name = fields
        .next()
        .ok_or_else(|| rpc_decode("missing attribute type"))?;
    let wire_value = fields
        .next()
        .ok_or_else(|| rpc_decode("missing attribute value"))?;
    if fields.next().is_some() {
        return Err(rpc_decode("unexpected extra attribute fields"));
    }
    let attribute = match type_name {
        "bool" => OpenSetAttributeValue::Bool(parse_bool_field(wire_value, "attribute bool")?),
        "int" => OpenSetAttributeValue::Int(parse_i64_field(wire_value, "attribute int")?),
        "uint" => OpenSetAttributeValue::Uint(parse_u64_field(Some(wire_value), "attribute uint")?),
        "uint128" => {
            OpenSetAttributeValue::Uint128(parse_u128_field(wire_value, "attribute uint128")?)
        }
        "float64bits" => OpenSetAttributeValue::Float64Bits(parse_u64_field(
            Some(wire_value),
            "attribute float64bits",
        )?),
        "string" => OpenSetAttributeValue::String(parse_hex_string(wire_value)?),
        "bytes" => OpenSetAttributeValue::Bytes(parse_hex_bytes(wire_value)?),
        value => return Err(rpc_decode(format!("unknown attribute type `{value}`"))),
    };
    Ok((name, attribute))
}

fn parse_hex_field(value: Option<&str>, label: &'static str) -> Result<String, ControlClientError> {
    let value = value.ok_or_else(|| rpc_decode(format!("missing {label}")))?;
    parse_hex_string(value)
}

fn parse_bool_field(value: &str, label: &'static str) -> Result<bool, ControlClientError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(rpc_decode(format!("invalid {label} `{value}`"))),
    }
}

fn parse_i64_field(value: &str, label: &'static str) -> Result<i64, ControlClientError> {
    value
        .parse::<i64>()
        .map_err(|error| rpc_decode(format!("invalid {label} `{value}`: {error}")))
}

fn parse_u128_field(value: &str, label: &'static str) -> Result<u128, ControlClientError> {
    value
        .parse::<u128>()
        .map_err(|error| rpc_decode(format!("invalid {label} `{value}`: {error}")))
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

fn parse_capabilities_line(
    line: Option<&str>,
) -> Result<StreamingCapabilitySet, ControlClientError> {
    let value = parse_prefixed_line(line, "commands=")?;
    if value.is_empty() {
        return Ok(StreamingCapabilitySet {
            commands: Vec::new(),
            snapshot_on_attach: true,
        });
    }

    let mut commands = Vec::new();
    for command_kind_wire in value.split(',') {
        let command_kind = session_command_for_open_set_command_kind(command_kind_wire)
            .ok_or_else(|| {
                rpc_decode(format!("unknown command capability `{command_kind_wire}`"))
            })?;
        commands.push(StreamingCommandCapability {
            command_name: command_name_from_open_set_kind(command_kind_wire)?,
            command_kind,
        });
    }
    Ok(StreamingCapabilitySet {
        commands,
        snapshot_on_attach: true,
    })
}

fn parse_attach_snapshot_line(
    line: Option<&str>,
) -> Result<Option<AttachSnapshot>, ControlClientError> {
    let value = parse_prefixed_line(line, "snapshot=")?;
    if value == "none" {
        return Ok(None);
    }
    let mut fields = value.split('|');
    let through = parse_snapshot_u64(fields.next(), "snapshot.through")?;
    let event_count = parse_snapshot_u64(fields.next(), "snapshot.events")?;
    let causal_event_count = parse_snapshot_u64(fields.next(), "snapshot.causal")?;
    let observational_event_count = parse_snapshot_u64(fields.next(), "snapshot.observational")?;
    let last_sequence =
        match fields
            .next()
            .ok_or_else(|| rpc_decode("missing snapshot.last"))?
        {
            "none" => None,
            value => Some(value.parse::<u64>().map_err(|error| {
                rpc_decode(format!("invalid snapshot.last `{value}`: {error}"))
            })?),
        };
    if fields.next().is_some() {
        return Err(rpc_decode("trailing snapshot fields"));
    }
    Ok(Some(AttachSnapshot {
        through: EventLogCursor::new(through),
        event_count,
        causal_event_count,
        observational_event_count,
        last_sequence,
    }))
}

fn parse_snapshot_u64(value: Option<&str>, field: &'static str) -> Result<u64, ControlClientError> {
    let value = value.ok_or_else(|| rpc_decode(format!("missing {field}")))?;
    value
        .parse::<u64>()
        .map_err(|error| rpc_decode(format!("invalid {field} `{value}`: {error}")))
}

fn parse_command_kind_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<SessionCommandKind, ControlClientError> {
    let command_kind = parse_prefixed_line(line, prefix)?;
    session_command_for_open_set_command_kind(command_kind)
        .ok_or_else(|| rpc_decode(format!("unknown command `{command_kind}`")))
}

fn parse_command_status_line(
    line: Option<&str>,
) -> Result<CommandResultStatus, ControlClientError> {
    match parse_prefixed_line(line, "status=")? {
        "accepted" => Ok(CommandResultStatus::Accepted),
        "rejected:invalid-state" => Ok(CommandResultStatus::Rejected {
            reason: CommandRejectionKind::InvalidState,
        }),
        value => Err(rpc_decode(format!("unknown command status `{value}`"))),
    }
}

fn parse_state_update_line(line: Option<&str>) -> Result<Option<StateUpdate>, ControlClientError> {
    let value = parse_prefixed_line(line, "state-update=")?;
    if value == "none" {
        return Ok(None);
    }
    let mut fields = value.split('|');
    let id = parse_u64_field(fields.next(), "state update session id")?;
    let epoch = parse_u64_field(fields.next(), "state update session epoch")?;
    let seed = parse_seed_field(fields.next(), "state update session seed")?;
    let state = parse_state_field(fields.next(), "state update state")?;
    if fields.next().is_some() {
        return Err(rpc_decode("unexpected extra state update fields"));
    }
    Ok(Some(StateUpdate {
        session: SessionRef::new(SessionId::new(id), epoch, seed),
        state,
    }))
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

fn command_kind_name(command: SessionCommandKind) -> &'static str {
    api_command_for_session_command(command)
        .map(|mapping| mapping.command_name)
        .unwrap_or("unknown")
}

fn command_name_from_static(value: &str) -> Result<&'static str, ControlClientError> {
    API_COMMAND_MAPPINGS
        .iter()
        .find(|mapping| mapping.command_name == value)
        .map(|mapping| mapping.command_name)
        .ok_or_else(|| rpc_decode(format!("unknown command name `{value}`")))
}

fn command_name_from_open_set_kind(value: &str) -> Result<&'static str, ControlClientError> {
    let Some(command_name) = value.strip_prefix("crucible.cmd.") else {
        return Err(rpc_decode(format!("unknown command kind `{value}`")));
    };
    command_name_from_static(command_name)
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

fn parse_hex_string(value: &str) -> Result<String, ControlClientError> {
    String::from_utf8(parse_hex_bytes(value)?)
        .map_err(|error| rpc_decode(format!("invalid UTF-8 hex string: {error}")))
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, ControlClientError> {
    if value.len() % 2 != 0 {
        return Err(rpc_decode(format!(
            "hex string has odd length {}",
            value.len()
        )));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let pair = &value[index..index + 2];
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|error| rpc_decode(format!("invalid hex byte `{pair}`: {error}")))?,
        );
    }
    Ok(bytes)
}
