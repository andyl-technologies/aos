//! Transport-agnostic control client trait and client handles.
//!
//! This module owns the RFC-0010 file 21.1 boundary: callers use one typed
//! [`ControlClient`] trait while implementations choose either the same-process
//! session actor path or the HTTP/2 RPC path. The two paths intentionally share
//! [`ControlWireModel`], which is backed by the frozen RPC ABI message encoder.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crucible_session::{LiveSnapshot, SessionCommand};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::event_log_stream::ControlPlaneEventLog;
use crate::rpc_abi::{
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION, RpcAbiError,
    encode_rpc_hello_request, encode_rpc_hello_response, negotiate_rpc_protocol,
};

const HELLO_RPC_PATH: &str = "/crucible.rpc/hello";
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
            let response = self
                .http
                .post(self.endpoint.rpc_url(HELLO_RPC_PATH))
                .header(reqwest::header::CONTENT_TYPE, RPC_CONTENT_TYPE)
                .body(self.wire_model.encode_hello_request(&request))
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
            let body = response
                .bytes()
                .await
                .map_err(|error| ControlClientError::HttpRequest {
                    message: error.to_string(),
                })?;
            decode_hello_response(&body, self.transport())
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
