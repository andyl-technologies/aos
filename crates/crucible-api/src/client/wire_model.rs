//! Shared control-client hello messages and transport identity.

use super::*;

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
