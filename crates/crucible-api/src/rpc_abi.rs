//! Versioned control-plane RPC ABI and frozen golden vectors.
//!
//! The current corpus is the ABI-conformance seed for RFC-0010 file 21. It
//! deliberately freezes a small canonical envelope vocabulary before the full
//! reference client lands: explicit `Hello` version negotiation, `Attached`
//! version echoing, one mutating request/response pair, one event, and the
//! open-set payload-kind catalog.
//!
//! Wire-format sketch:
//!
//! ```text
//! crucible.rpc/<message-name>\n
//! key=value\n
//! ...
//! ```

use thiserror::Error;

/// RPC protocol major version for wire-incompatible changes.
pub const RPC_PROTOCOL_MAJOR: u16 = 1;
/// RPC protocol minor version for backward-compatible additions.
pub const RPC_PROTOCOL_MINOR: u16 = 0;
/// RPC protocol patch version for compatible fixes.
pub const RPC_PROTOCOL_PATCH: u16 = 0;
/// RPC protocol build identifier recorded in `Hello` and `Attached`.
pub const RPC_PROTOCOL_BUILD: &str = "crucible-rpc-abi-v1";

/// Current control-plane RPC protocol version.
pub const RPC_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: RPC_PROTOCOL_MAJOR,
    minor: RPC_PROTOCOL_MINOR,
    patch: RPC_PROTOCOL_PATCH,
    build: RPC_PROTOCOL_BUILD,
};

/// RPC protocol version for which the golden-vector corpus was generated.
pub const GOLDEN_VECTOR_RPC_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 0,
    patch: 0,
    build: "crucible-rpc-abi-v1",
};

/// Regeneration rule for the RPC golden-vector corpus.
pub const GOLDEN_VECTOR_RPC_REGENERATION_RULE: &str =
    "Regenerate every RPC golden vector whenever RPC_PROTOCOL_VERSION changes.";

/// Open-set payload kinds advertised through `Hello`.
pub const RPC_OPEN_SET_PAYLOAD_KINDS: &[&str] = &[
    "command.continue",
    "event.fault-injected",
    "state.update",
    "session.closed",
];

/// Semantic control-plane RPC protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolVersion {
    /// Major version, bumped for wire-incompatible changes.
    pub major: u16,
    /// Minor version, bumped for backward-compatible additions.
    pub minor: u16,
    /// Patch version, bumped for compatible fixes.
    pub patch: u16,
    /// Build identifier carried alongside the semantic version.
    pub build: &'static str,
}

/// A frozen control-plane RPC golden vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcGoldenVector {
    /// Stable corpus name.
    pub name: &'static str,
    /// RPC protocol version the vector belongs to.
    pub protocol_version: ProtocolVersion,
    /// Structured RPC message represented by the vector.
    pub message: RpcGoldenVectorMessage,
    /// Complete canonical bytes for the message.
    pub bytes: &'static [u8],
}

/// Structured RPC message represented by a golden vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcGoldenVectorMessage {
    /// Client-to-server `Hello` request.
    HelloRequest {
        /// Client implementation identifier.
        client_name: &'static str,
        /// Highest RPC protocol version offered by the client.
        version: ProtocolVersion,
    },
    /// Server-to-client `Hello` response.
    HelloResponse {
        /// Server implementation identifier.
        server_name: &'static str,
        /// Current RPC protocol version returned by the server.
        version: ProtocolVersion,
        /// Open-set payload kinds advertised by the server.
        payload_kinds: &'static [&'static str],
    },
    /// Stream attachment acknowledgement.
    Attached {
        /// Stable session identifier assigned by the control plane.
        session_id: u64,
        /// Server-monotonic session epoch.
        session_epoch: u64,
        /// Attachment stream mode.
        mode: RpcAttachMode,
        /// Current RPC protocol version echoed by the stream.
        version: ProtocolVersion,
    },
    /// Mutating session command request.
    CommandRequest {
        /// Client request identifier.
        request_id: u64,
        /// Expected server-monotonic session epoch.
        session_epoch: u64,
        /// Open-set command kind.
        command_kind: &'static str,
    },
    /// Mutating session command response.
    CommandResponse {
        /// Client request identifier being answered.
        request_id: u64,
        /// Typed RPC status for the command.
        status: RpcStatusCode,
    },
    /// Event-log or observational stream event.
    Event {
        /// Deterministic event sequence number.
        seq: u64,
        /// Event class advertised by the event log.
        class: RpcEventClass,
        /// Open-set payload kind for the event body.
        payload_kind: &'static str,
    },
}

/// Stream mode acknowledged by an `Attached` message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcAttachMode {
    /// Bidirectional control stream.
    Control,
    /// Read-only watch stream.
    Watch,
}

/// Typed status code returned by control-plane command responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcStatusCode {
    /// Command completed successfully.
    Ok,
    /// Command is invalid in the session's current state.
    InvalidState,
    /// Referenced object was not found.
    NotFound,
    /// Request arguments failed validation.
    InvalidArgument,
    /// Requested operation is unsupported by the current backend.
    Unsupported,
    /// Internal server failure.
    Internal,
}

/// Event class advertised by the RPC stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcEventClass {
    /// Deterministic state transition.
    State,
    /// Fault injection or healing event.
    Fault,
    /// Observational entry that does not enter the deterministic state.
    Observation,
}

/// RPC ABI negotiation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RpcAbiError {
    /// A peer offered an incompatible major protocol version.
    #[error("RPC protocol major version mismatch: expected {expected}, actual {actual}")]
    MajorVersionMismatch {
        /// Local RPC major version.
        expected: u16,
        /// Peer RPC major version.
        actual: u16,
    },
}

/// Frozen RPC golden-vector corpus in stable ABI-conformance order.
pub const GOLDEN_RPC_VECTORS: [RpcGoldenVector; 6] = [
    RpcGoldenVector {
        name: "hello-request",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::HelloRequest {
            client_name: "crucible-api-golden-client",
            version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        },
        bytes: b"crucible.rpc/hello-request\nversion=1.0.0+crucible-rpc-abi-v1\nclient=crucible-api-golden-client\n",
    },
    RpcGoldenVector {
        name: "hello-response",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::HelloResponse {
            server_name: "crucible-session",
            version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
            payload_kinds: RPC_OPEN_SET_PAYLOAD_KINDS,
        },
        bytes: b"crucible.rpc/hello-response\nversion=1.0.0+crucible-rpc-abi-v1\nserver=crucible-session\npayload-kinds=command.continue,event.fault-injected,state.update,session.closed\n",
    },
    RpcGoldenVector {
        name: "attached",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::Attached {
            session_id: 42,
            session_epoch: 7,
            mode: RpcAttachMode::Control,
            version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        },
        bytes: b"crucible.rpc/attached\nversion=1.0.0+crucible-rpc-abi-v1\nsession-id=42\nsession-epoch=7\nmode=control\n",
    },
    RpcGoldenVector {
        name: "send-command-request",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandRequest {
            request_id: 9001,
            session_epoch: 7,
            command_kind: "command.continue",
        },
        bytes: b"crucible.rpc/send-command-request\nrequest-id=9001\nsession-epoch=7\ncommand-kind=command.continue\n",
    },
    RpcGoldenVector {
        name: "send-command-response",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandResponse {
            request_id: 9001,
            status: RpcStatusCode::Ok,
        },
        bytes: b"crucible.rpc/send-command-response\nrequest-id=9001\nstatus=ok\n",
    },
    RpcGoldenVector {
        name: "event-fault-injected",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::Event {
            seq: 1234,
            class: RpcEventClass::Fault,
            payload_kind: "event.fault-injected",
        },
        bytes: b"crucible.rpc/event\nseq=1234\nclass=fault\npayload-kind=event.fault-injected\n",
    },
];

/// Negotiates the local RPC protocol version with a peer version.
///
/// Backward-compatible minor and patch differences are accepted within the
/// current major version. A major-version difference is rejected before any
/// message-specific decoding can proceed.
///
/// # Errors
///
/// Returns [`RpcAbiError::MajorVersionMismatch`] when `peer.major` differs
/// from [`RPC_PROTOCOL_VERSION`].
pub const fn negotiate_rpc_protocol(peer: ProtocolVersion) -> Result<ProtocolVersion, RpcAbiError> {
    if peer.major != RPC_PROTOCOL_VERSION.major {
        return Err(RpcAbiError::MajorVersionMismatch {
            expected: RPC_PROTOCOL_VERSION.major,
            actual: peer.major,
        });
    }
    Ok(RPC_PROTOCOL_VERSION)
}

/// Encodes one structured RPC message into its canonical ABI bytes.
#[must_use]
pub fn encode_rpc_message(message: RpcGoldenVectorMessage) -> Vec<u8> {
    let mut output = String::new();
    match message {
        RpcGoldenVectorMessage::HelloRequest {
            client_name,
            version,
        } => {
            output.push_str("crucible.rpc/hello-request\n");
            push_version_line(&mut output, "version", version);
            push_str_line(&mut output, "client", client_name);
        }
        RpcGoldenVectorMessage::HelloResponse {
            server_name,
            version,
            payload_kinds,
        } => {
            output.push_str("crucible.rpc/hello-response\n");
            push_version_line(&mut output, "version", version);
            push_str_line(&mut output, "server", server_name);
            push_payload_kinds_line(&mut output, payload_kinds);
        }
        RpcGoldenVectorMessage::Attached {
            session_id,
            session_epoch,
            mode,
            version,
        } => {
            output.push_str("crucible.rpc/attached\n");
            push_version_line(&mut output, "version", version);
            push_u64_line(&mut output, "session-id", session_id);
            push_u64_line(&mut output, "session-epoch", session_epoch);
            push_str_line(&mut output, "mode", attach_mode_wire_name(mode));
        }
        RpcGoldenVectorMessage::CommandRequest {
            request_id,
            session_epoch,
            command_kind,
        } => {
            output.push_str("crucible.rpc/send-command-request\n");
            push_u64_line(&mut output, "request-id", request_id);
            push_u64_line(&mut output, "session-epoch", session_epoch);
            push_str_line(&mut output, "command-kind", command_kind);
        }
        RpcGoldenVectorMessage::CommandResponse { request_id, status } => {
            output.push_str("crucible.rpc/send-command-response\n");
            push_u64_line(&mut output, "request-id", request_id);
            push_str_line(&mut output, "status", status_code_wire_name(status));
        }
        RpcGoldenVectorMessage::Event {
            seq,
            class,
            payload_kind,
        } => {
            output.push_str("crucible.rpc/event\n");
            push_u64_line(&mut output, "seq", seq);
            push_str_line(&mut output, "class", event_class_wire_name(class));
            push_str_line(&mut output, "payload-kind", payload_kind);
        }
    }
    output.into_bytes()
}

fn push_version_line(output: &mut String, key: &str, version: ProtocolVersion) {
    output.push_str(key);
    output.push('=');
    output.push_str(&format!(
        "{}.{}.{}+{}",
        version.major, version.minor, version.patch, version.build
    ));
    output.push('\n');
}

fn push_u64_line(output: &mut String, key: &str, value: u64) {
    output.push_str(key);
    output.push('=');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn push_str_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

fn push_payload_kinds_line(output: &mut String, payload_kinds: &[&str]) {
    output.push_str("payload-kinds=");
    for (index, kind) in payload_kinds.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(kind);
    }
    output.push('\n');
}

fn attach_mode_wire_name(mode: RpcAttachMode) -> &'static str {
    match mode {
        RpcAttachMode::Control => "control",
        RpcAttachMode::Watch => "watch",
    }
}

fn status_code_wire_name(status: RpcStatusCode) -> &'static str {
    match status {
        RpcStatusCode::Ok => "ok",
        RpcStatusCode::InvalidState => "invalid-state",
        RpcStatusCode::NotFound => "not-found",
        RpcStatusCode::InvalidArgument => "invalid-argument",
        RpcStatusCode::Unsupported => "unsupported",
        RpcStatusCode::Internal => "internal",
    }
}

fn event_class_wire_name(class: RpcEventClass) -> &'static str {
    match class {
        RpcEventClass::State => "state",
        RpcEventClass::Fault => "fault",
        RpcEventClass::Observation => "observation",
    }
}

const _: () = assert!(GOLDEN_VECTOR_RPC_PROTOCOL_VERSION.major == RPC_PROTOCOL_VERSION.major);
const _: () = assert!(GOLDEN_VECTOR_RPC_PROTOCOL_VERSION.minor == RPC_PROTOCOL_VERSION.minor);
const _: () = assert!(GOLDEN_VECTOR_RPC_PROTOCOL_VERSION.patch == RPC_PROTOCOL_VERSION.patch);
