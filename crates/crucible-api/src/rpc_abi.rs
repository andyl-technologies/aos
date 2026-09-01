//! Versioned control-plane RPC ABI and frozen golden vectors.
//!
//! The current corpus is the ABI-conformance seed for RFC-0010 file 21. It
//! deliberately freezes a small canonical envelope vocabulary before the full
//! reference client lands: explicit `Hello` version negotiation, `Attached`
//! version echoing, mutating request/response pairs including breakpoint
//! payloads, one reproduction context request/response pair, one
//! reproduction-bearing attach, one event, and the open-set payload-kind
//! catalog.
//!
//! Wire-format sketch:
//!
//! ```text
//! crucible.rpc/<message-name>\n
//! key=value\n
//! ...
//! ```

use thiserror::Error;

use crate::open_set::OPEN_SET_CAPABILITY_CATEGORIES;

/// RPC protocol major version for wire-incompatible changes.
pub const RPC_PROTOCOL_MAJOR: u16 = 5;
/// RPC protocol minor version for backward-compatible additions.
pub const RPC_PROTOCOL_MINOR: u16 = 1;
/// RPC protocol patch version for compatible fixes.
pub const RPC_PROTOCOL_PATCH: u16 = 0;
/// RPC protocol build identifier recorded in `Hello` and `Attached`.
pub const RPC_PROTOCOL_BUILD: &str = "crucible-rpc-abi-v5";

/// Current control-plane RPC protocol version.
pub const RPC_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: RPC_PROTOCOL_MAJOR,
    minor: RPC_PROTOCOL_MINOR,
    patch: RPC_PROTOCOL_PATCH,
    build: RPC_PROTOCOL_BUILD,
};

/// RPC protocol version for which the golden-vector corpus was generated.
pub const GOLDEN_VECTOR_RPC_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: 5,
    minor: 1,
    patch: 0,
    build: "crucible-rpc-abi-v5",
};

/// Regeneration rule for the RPC golden-vector corpus.
pub const GOLDEN_VECTOR_RPC_REGENERATION_RULE: &str =
    "Regenerate every RPC golden vector whenever RPC_PROTOCOL_VERSION changes.";

/// Open-set payload categories advertised through `Hello`.
pub const RPC_OPEN_SET_PAYLOAD_KINDS: &[&str] = OPEN_SET_CAPABILITY_CATEGORIES;

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
    /// Stream attachment acknowledgement carrying a reproduction snapshot.
    AttachedWithReproduction {
        /// Stable session identifier assigned by the control plane.
        session_id: u64,
        /// Server-monotonic session epoch.
        session_epoch: u64,
        /// Attachment stream mode.
        mode: RpcAttachMode,
        /// Current RPC protocol version echoed by the stream.
        version: ProtocolVersion,
        /// Recorded reproduction command sequence.
        command_sequence: u64,
        /// Open-set command kind recorded for reproduction.
        command_kind: &'static str,
        /// Hex-encoded stable command payload material.
        command_payload: &'static str,
        /// Hex-encoded stable scheduler-control material, or `none`.
        scheduler_control: &'static str,
    },
    /// Deterministic reproduction-context request.
    GetReproductionRequest {
        /// Stable session identifier assigned by the control plane.
        session_id: u64,
        /// Server-monotonic session epoch.
        session_epoch: u64,
        /// Expected epoch guard supplied by the caller.
        expected_epoch: u64,
    },
    /// Deterministic reproduction-context response.
    GetReproductionResponse {
        /// Stable session identifier assigned by the control plane.
        session_id: u64,
        /// Server-monotonic session epoch.
        session_epoch: u64,
        /// Recorded reproduction command sequence.
        command_sequence: u64,
        /// Open-set command kind recorded for reproduction.
        command_kind: &'static str,
        /// Hex-encoded stable command payload material.
        command_payload: &'static str,
        /// Hex-encoded stable scheduler-control material, or `none`.
        scheduler_control: &'static str,
    },
    /// Mutating session command request.
    CommandRequest {
        /// Stable session identifier assigned by the control plane.
        session_id: u64,
        /// Server-monotonic session epoch.
        session_epoch: u64,
        /// Hex-encoded deterministic session seed.
        seed: &'static str,
        /// Expected epoch guard supplied by the caller.
        expected_epoch: u64,
        /// Client command correlation identifier.
        command_id: u64,
        /// Open-set command kind.
        command_kind: &'static str,
    },
    /// Mutating session command request with additional payload fields.
    CommandRequestWithPayload {
        /// Stable session identifier assigned by the control plane.
        session_id: u64,
        /// Server-monotonic session epoch.
        session_epoch: u64,
        /// Hex-encoded deterministic session seed.
        seed: &'static str,
        /// Expected epoch guard supplied by the caller.
        expected_epoch: u64,
        /// Client command correlation identifier.
        command_id: u64,
        /// Open-set command kind.
        command_kind: &'static str,
        /// Canonical `key=value` payload lines emitted after `command`.
        payload_lines: &'static [&'static str],
    },
    /// Mutating session command response.
    CommandResponse {
        /// Client command correlation identifier being answered.
        command_id: u64,
        /// Open-set command kind being answered.
        command_kind: &'static str,
        /// Typed RPC status for the command result.
        status: RpcStatusCode,
        /// Encoded state update payload, or `none`.
        state_update: &'static str,
    },
    /// Mutating session command response with explicit result fields.
    CommandResponseWithPayload {
        /// Client command correlation identifier being answered.
        command_id: u64,
        /// Open-set command kind being answered.
        command_kind: &'static str,
        /// Typed RPC status for the command result.
        status: RpcStatusCode,
        /// Encoded state update payload, or `none`.
        state_update: &'static str,
        /// Encoded query result payload, or `none`.
        query_result: &'static str,
        /// Encoded breakpoint identifier, or `none`.
        breakpoint_id: &'static str,
        /// Encoded savepoint payload, or `none`.
        savepoint_info: &'static str,
    },
    /// Typed non-success RPC error response.
    RpcError {
        /// Closed status code returned by the endpoint.
        status: RpcStatusCode,
        /// Stable machine-readable error reason.
        reason: &'static str,
        /// Stable detail lines following the reason.
        details: &'static [&'static str],
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
#[path = "rpc_abi/golden.rs"]
mod golden;
pub use golden::GOLDEN_RPC_VECTORS;

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
    match message {
        RpcGoldenVectorMessage::HelloRequest {
            client_name,
            version,
        } => encode_rpc_hello_request(client_name, version),
        RpcGoldenVectorMessage::HelloResponse {
            server_name,
            version,
            payload_kinds,
        } => encode_rpc_hello_response(server_name, version, payload_kinds),
        RpcGoldenVectorMessage::Attached {
            session_id,
            session_epoch,
            mode,
            version,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/attached\n");
            push_version_line(&mut output, "version", version);
            push_u64_line(&mut output, "session-id", session_id);
            push_u64_line(&mut output, "session-epoch", session_epoch);
            push_str_line(&mut output, "mode", attach_mode_wire_name(mode));
            output.into_bytes()
        }
        RpcGoldenVectorMessage::AttachedWithReproduction {
            session_id,
            session_epoch,
            mode,
            version,
            command_sequence,
            command_kind,
            command_payload,
            scheduler_control,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/attached-with-reproduction\n");
            push_version_line(&mut output, "version", version);
            push_u64_line(&mut output, "session-id", session_id);
            push_u64_line(&mut output, "session-epoch", session_epoch);
            push_str_line(&mut output, "mode", attach_mode_wire_name(mode));
            push_reproduction_command_lines(
                &mut output,
                "reproduction-",
                command_sequence,
                command_kind,
                command_payload,
                scheduler_control,
            );
            output.into_bytes()
        }
        RpcGoldenVectorMessage::GetReproductionRequest {
            session_id,
            session_epoch,
            expected_epoch,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/get-reproduction-request\n");
            push_u64_line(&mut output, "session-id", session_id);
            push_u64_line(&mut output, "session-epoch", session_epoch);
            push_u64_line(&mut output, "expected-epoch", expected_epoch);
            output.into_bytes()
        }
        RpcGoldenVectorMessage::GetReproductionResponse {
            session_id,
            session_epoch,
            command_sequence,
            command_kind,
            command_payload,
            scheduler_control,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/get-reproduction-response\n");
            push_u64_line(&mut output, "session-id", session_id);
            push_u64_line(&mut output, "session-epoch", session_epoch);
            push_reproduction_command_lines(
                &mut output,
                "",
                command_sequence,
                command_kind,
                command_payload,
                scheduler_control,
            );
            push_str_line(&mut output, "result", "accepted");
            output.into_bytes()
        }
        RpcGoldenVectorMessage::CommandRequest {
            session_id,
            session_epoch,
            seed,
            expected_epoch,
            command_id,
            command_kind,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/send-request\n");
            push_u64_line(&mut output, "session-id", session_id);
            push_u64_line(&mut output, "epoch", session_epoch);
            push_str_line(&mut output, "seed", seed);
            push_u64_line(&mut output, "expected-epoch", expected_epoch);
            push_u64_line(&mut output, "command-id", command_id);
            push_str_line(&mut output, "command", command_kind);
            output.into_bytes()
        }
        RpcGoldenVectorMessage::CommandRequestWithPayload {
            session_id,
            session_epoch,
            seed,
            expected_epoch,
            command_id,
            command_kind,
            payload_lines,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/send-request\n");
            push_u64_line(&mut output, "session-id", session_id);
            push_u64_line(&mut output, "epoch", session_epoch);
            push_str_line(&mut output, "seed", seed);
            push_u64_line(&mut output, "expected-epoch", expected_epoch);
            push_u64_line(&mut output, "command-id", command_id);
            push_str_line(&mut output, "command", command_kind);
            for line in payload_lines {
                output.push_str(line);
                output.push('\n');
            }
            output.into_bytes()
        }
        RpcGoldenVectorMessage::CommandResponse {
            command_id,
            command_kind,
            status,
            state_update,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/send-response\n");
            push_u64_line(&mut output, "command-id", command_id);
            push_str_line(&mut output, "command", command_kind);
            let status = if status == RpcStatusCode::Ok {
                String::from("accepted")
            } else {
                format!("rejected:{}", rpc_status_code_wire_name(status))
            };
            push_str_line(&mut output, "status", &status);
            push_str_line(&mut output, "state-update", state_update);
            push_str_line(&mut output, "query-result", "none");
            push_str_line(&mut output, "breakpoint-id", "none");
            push_str_line(&mut output, "savepoint-info", "none");
            output.into_bytes()
        }
        RpcGoldenVectorMessage::CommandResponseWithPayload {
            command_id,
            command_kind,
            status,
            state_update,
            query_result,
            breakpoint_id,
            savepoint_info,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/send-response\n");
            push_u64_line(&mut output, "command-id", command_id);
            push_str_line(&mut output, "command", command_kind);
            let status = if status == RpcStatusCode::Ok {
                String::from("accepted")
            } else {
                format!("rejected:{}", rpc_status_code_wire_name(status))
            };
            push_str_line(&mut output, "status", &status);
            push_str_line(&mut output, "state-update", state_update);
            push_str_line(&mut output, "query-result", query_result);
            push_str_line(&mut output, "breakpoint-id", breakpoint_id);
            push_str_line(&mut output, "savepoint-info", savepoint_info);
            output.into_bytes()
        }
        RpcGoldenVectorMessage::RpcError {
            status,
            reason,
            details,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/error\n");
            push_str_line(&mut output, "status", rpc_status_code_wire_name(status));
            push_str_line(&mut output, "reason", reason);
            for detail in details {
                output.push_str(detail);
                output.push('\n');
            }
            output.into_bytes()
        }
        RpcGoldenVectorMessage::Event {
            seq,
            class,
            payload_kind,
        } => {
            let mut output = String::new();
            output.push_str("crucible.rpc/event\n");
            push_u64_line(&mut output, "seq", seq);
            push_str_line(&mut output, "class", event_class_wire_name(class));
            push_str_line(&mut output, "payload-kind", payload_kind);
            output.into_bytes()
        }
    }
}

/// Encodes a typed `Hello` request into canonical RPC ABI bytes.
#[must_use]
pub fn encode_rpc_hello_request(client_name: &str, version: ProtocolVersion) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("crucible.rpc/hello-request\n");
    push_version_line(&mut output, "version", version);
    push_str_line(&mut output, "client", client_name);
    output.into_bytes()
}

/// Encodes a typed `Hello` response into canonical RPC ABI bytes.
#[must_use]
pub fn encode_rpc_hello_response(
    server_name: &str,
    version: ProtocolVersion,
    payload_kinds: &[&str],
) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("crucible.rpc/hello-response\n");
    push_version_line(&mut output, "version", version);
    push_str_line(&mut output, "server", server_name);
    push_payload_kinds_line(&mut output, payload_kinds);
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

fn push_reproduction_command_lines(
    output: &mut String,
    prefix: &str,
    sequence: u64,
    command_kind: &str,
    command_payload: &str,
    scheduler_control: &str,
) {
    let sequence_key = if prefix.is_empty() {
        String::from("command-sequence")
    } else {
        format!("{prefix}sequence")
    };
    push_u64_line(output, &sequence_key, sequence);
    push_str_line(output, &format!("{prefix}command-kind"), command_kind);
    push_str_line(output, &format!("{prefix}command-payload"), command_payload);
    push_str_line(
        output,
        &format!("{prefix}scheduler-control"),
        scheduler_control,
    );
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

/// Returns the stable wire spelling for an RPC status code.
#[must_use]
pub const fn rpc_status_code_wire_name(status: RpcStatusCode) -> &'static str {
    match status {
        RpcStatusCode::Ok => "ok",
        RpcStatusCode::InvalidState => "invalid-state",
        RpcStatusCode::NotFound => "not-found",
        RpcStatusCode::InvalidArgument => "invalid-argument",
        RpcStatusCode::Unsupported => "unsupported",
        RpcStatusCode::Internal => "internal",
    }
}

/// Parses a stable RPC status-code wire spelling.
#[must_use]
pub fn rpc_status_code_from_wire_name(value: &str) -> Option<RpcStatusCode> {
    match value {
        "ok" => Some(RpcStatusCode::Ok),
        "invalid-state" => Some(RpcStatusCode::InvalidState),
        "not-found" => Some(RpcStatusCode::NotFound),
        "invalid-argument" => Some(RpcStatusCode::InvalidArgument),
        "unsupported" => Some(RpcStatusCode::Unsupported),
        "internal" => Some(RpcStatusCode::Internal),
        _ => None,
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
