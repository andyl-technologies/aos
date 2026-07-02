//! `crucible-api` owns the versioned programmatic API surface.
//!
//! Spec index: RFC-0010 files 21.
//!
//! This L4 crate will define the session lifecycle, stepping, query, and
//! temporal-graph API types described by RFC-0010 file 21. It is a
//! safe boundary over versioned data and dispatch shapes.
//!
//! Module map: [`client`] owns the transport-agnostic [`ControlClient`] trait
//! and its in-process/RPC implementations; [`rpc_abi`] owns the versioned RPC
//! boundary constants and frozen golden vectors; [`control_responsive`] owns the
//! quantum-counted acknowledgement contract used by `gate:control-responsive`;
//! [`event_log_stream`] owns the cursor-backed live event-log subscription facade.
//! Later modules will split by lifecycle, query, and temporal-graph surfaces as
//! those APIs land.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod client;
pub mod control_responsive;
pub mod event_log_stream;
pub mod rpc_abi;

pub use client::{
    ControlClient, ControlClientError, ControlClientFuture, ControlTransportKind, ControlWireModel,
    HelloRequest, HelloResponse, InProcessControlClient, RpcControlClient, RpcEndpoint,
    RpcTransportProtocol, assert_shared_wire_model,
};
pub use control_responsive::{
    CONTROL_RESPONSIVE_QUANTUM_BOUND, CONTROL_RESPONSIVE_REQUIRED_OPERATIONS,
    ControlAcknowledgementStatus, ControlOperationAcknowledgement, ControlOperationKind,
    ControlResponsiveReport, ControlResponsiveSessionProbe, ControlResponsivenessError,
    ControlSessionState, validate_control_responsiveness,
};
pub use event_log_stream::{
    ControlPlaneEventLog, EventLogCursor, SESSION_EVENT_LOG_BROADCAST_CAPACITY,
    SESSION_EVENT_LOG_REPLAY_BATCH_SIZE, SessionEventLogFrame, SessionEventLogHub,
    SessionEventLogStream, SessionEventLogStreamError,
};
pub use rpc_abi::{
    GOLDEN_RPC_VECTORS, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION, GOLDEN_VECTOR_RPC_REGENERATION_RULE,
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR,
    RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH, RPC_PROTOCOL_VERSION, RpcAbiError, RpcAttachMode,
    RpcEventClass, RpcGoldenVector, RpcGoldenVectorMessage, RpcStatusCode,
    encode_rpc_hello_request, encode_rpc_hello_response, encode_rpc_message,
    negotiate_rpc_protocol,
};
