//! `crucible-api` owns the versioned programmatic API surface.
//!
//! Implementation contract: Session lifecycle, versioned control transport, and host operational contracts.
//!
//! This L4 crate defines the session lifecycle, stepping, query, and
//! temporal-graph API types. It is a
//! safe boundary over versioned data and dispatch shapes.
//!
//! Module map: [`client`] owns the transport-agnostic [`ControlClient`] trait
//! and its in-process/RPC implementations; [`rpc_abi`] owns the versioned RPC
//! boundary constants and frozen golden vectors; [`control_responsive`] owns the
//! quantum-counted acknowledgement contract used by `gate:control-responsive`;
//! [`event_log_stream`] owns the cursor-backed live event-log subscription facade;
//! [`session_mapping`] owns the API-to-session thin-wrapper contract; [`lifecycle`]
//! owns the unary discovery and lifecycle API; [`streaming`] owns the typed
//! `Control` and `Watch`+`Send` attach-and-command facade; [`server`] owns the
//! HTTP/2 daemon transport; [`open_set`] owns the dotted-kind plus
//! typed-attribute payload model; [`cleanup_owner`] defines backend-owned
//! cleanup operations and physical observations; [`debug_gateway`] owns the Apache-side Unix
//! control client for the separate GPL debugger gateway process;
//! [`transport_security`] owns remote mutual-TLS authentication;
//! [`host_operational`] owns bounded target, policy, resource, and deadline
//! contracts outside modeled guest state.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod admitted_output;
pub use admitted_output::{AdmittedOutput, AdmittedShared};

pub mod cleanup_owner;
pub mod client;
pub mod control_responsive;
pub mod debug_access;
pub mod debug_gateway;
mod debug_holders;
pub mod debug_relay;
pub mod event_log_stream;
pub mod host_operational;
pub mod lifecycle;
pub mod open_set;
pub mod rpc_abi;
pub mod server;
pub mod session_mapping;
pub mod streaming;
pub mod transport_security;
pub use cleanup_owner::{
    ProductionVmCleanupHandoff, ProductionVmCleanupOwner, ProductionVmCleanupReservation,
    ProductionVmCleanupStage,
};
pub use client::{
    ClientControlStream, ClientWatchStream, ControlClient, ControlClientError, ControlClientFuture,
    ControlTransportKind, ControlWireModel, DebugControllerAccess, DebugControllerAcquisition,
    HelloRequest, HelloResponse, InProcessControlClient, InProcessLifecycleControlStream,
    RpcControlClient, RpcControlStream, RpcEndpoint, RpcMutualTlsConfig, RpcTransportProtocol,
    RpcWatchStream, WritableDebugBranch, assert_shared_wire_model,
};
pub use control_responsive::{
    CONTROL_RESPONSIVE_QUANTUM_BOUND, CONTROL_RESPONSIVE_REQUIRED_OPERATIONS,
    ControlAcknowledgementStatus, ControlOperationAcknowledgement, ControlOperationKind,
    ControlResponsiveReport, ControlResponsiveSessionProbe, ControlResponsivenessError,
    ControlSessionState, validate_control_responsiveness,
};
pub use debug_access::{DebugAuthorizationPolicy, DebugAuthorizationPolicyError};
pub use debug_gateway::{
    DEBUG_GATEWAY_STARTUP_TIMEOUT, DEBUG_GATEWAY_V1_CAPABILITY, DebugGatewayClientError,
    DebugGatewayControlClient, DebugGatewayProcess,
};
pub use debug_relay::{
    DEBUG_RELAY_CHUNK_MAX_BYTES, DebugRelayChunk, DebugRelayError, DebugRelayId,
};
pub use event_log_stream::{
    ControlPlaneEventLog, EventLogCursor, SESSION_EVENT_LOG_BROADCAST_CAPACITY,
    SessionEventLogFrame, SessionEventLogHub, SessionEventLogSnapshot, SessionEventLogStream,
    SessionEventLogStreamError,
};
pub use lifecycle::{
    CreateSessionRequest, CreateSessionResponse, CreateSessionSource, DebugLandedRuntimeCoordinate,
    DebugRepositionDispatch, DebugRepositionResult, DestroySessionRequest, DestroySessionResponse,
    GetReproductionRequest, GetReproductionResponse, GuestIntrospectionDispatch,
    InProcessLifecycleClient, LIFECYCLE_SESSION_MAILBOX_CAPACITY,
    LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS, LifecycleApiError,
    LifecycleBackendConstructionError, LifecycleControlPlane, LifecycleLoopFactory,
    LifecycleResourceLimit, ListScenariosResponse, ListSessionsResponse, QuiescentLifecycleLoop,
    RESUME_OBSERVATION_PREPARATION_CAPACITY, RESUME_OBSERVATION_PREPARATION_TIMEOUT,
    RESUME_OBSERVATION_SOURCE_MAX_BYTES, RESUME_REPLAY_CLOSURE_MAX_BYTES,
    ReproductionCommandDecodeError, ReproductionCommandPayload, ReproductionCommandRecord,
    ReproductionCommandRecordFields, ReproductionCommandResult, ResumeObservationCancellation,
    ResumeObservationCancellationRegistration, ResumeObservationLoopFactory,
    ResumeObservationPreparationContext, ResumeObservationSource, ResumeReplayClosure,
    ResumeReplayClosureValidationError, ResumeReplayClosureValidator, ResumeSessionRequest,
    ResumeSessionResponse, ScenarioCatalogEntry, ScenarioCatalogSource, ScenarioSummary, SessionId,
    SessionLifetimeRetention, SessionRef, SessionRetentionUpdateError, SessionSummary,
    admit_future, spawn_admitted_session_actor,
};
pub use open_set::{
    OPEN_SET_BREAKPOINT_KIND_PREFIX, OPEN_SET_CAPABILITY_CATEGORIES, OPEN_SET_COMMAND_KIND_PREFIX,
    OPEN_SET_EVENT_KIND_PREFIX, OpenSetAttributeValue, OpenSetCapabilities, OpenSetEventEnvelope,
    OpenSetEventSource, OpenSetEventTime, OpenSetKindSchema, OpenSetPayload,
    OpenSetPayloadCategory, OpenSetPayloadError, ReceivedOpenSetEventPayload,
    current_open_set_capabilities, open_set_breakpoint_kind, open_set_command_kind,
    open_set_event_envelope_from_entry, open_set_payload_for_breakpoint,
    open_set_payload_from_event_payload, receive_open_set_event_payload,
    session_command_for_open_set_command_kind, validate_open_set_send_payload,
};
pub use rpc_abi::{
    GOLDEN_RPC_VECTORS, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION, GOLDEN_VECTOR_RPC_REGENERATION_RULE,
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR,
    RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH, RPC_PROTOCOL_VERSION, RpcAbiError, RpcAttachMode,
    RpcEventClass, RpcGoldenVector, RpcGoldenVectorMessage, RpcStatusCode,
    encode_rpc_hello_request, encode_rpc_hello_response, encode_rpc_message,
    negotiate_rpc_protocol, rpc_status_code_from_wire_name, rpc_status_code_wire_name,
};
// Re-exported so control-plane clients (e.g. the CLI) record the *shared*
// guest-host protocol version in a reproduction artifact's provenance triple
// without reaching past the control plane into `crucible-protocol` directly
// (control-plane boundary): the CLI depends on `crucible-api`, which legally
// depends on `crucible-protocol`.
pub use crucible_protocol::CONTROL_PROTOCOL_VERSION;
pub use crucible_protocol::SELECTABLE_PROTOCOL_VERSION;
pub use crucible_protocol::guest_introspection::{
    GuestIntrospectionFailureCode, GuestIntrospectionMessage, GuestIntrospectionRecord,
    GuestOutputStream,
};
pub use server::{
    LifecycleServerMode, serve_lifecycle_http2,
    serve_lifecycle_http2_mtls_with_mode_until_shutdown,
    serve_lifecycle_http2_with_debug_policy_until_shutdown, serve_lifecycle_http2_with_mode,
    serve_lifecycle_http2_with_mode_until_shutdown,
    serve_shared_lifecycle_http2_mtls_with_mode_until_shutdown,
    serve_shared_lifecycle_http2_with_debug_policy_until_shutdown,
};
pub use session_mapping::{
    API_COMMAND_MAPPINGS, API_METHOD_MAPPINGS, ApiCommandMapping, ApiDispatch, ApiMappingError,
    ApiMethod, ApiMethodMapping, ApiRequestShape, CommandDispatchCardinality,
    api_command_for_session_command, method_mapping, session_command_for_api_command,
    validate_thin_api_mapping,
};
pub use streaming::{
    AttachRequest, AttachSnapshot, Attached, CommandRejectionKind, CommandResult,
    CommandResultStatus, ControlStream, InProcessStreamingSession,
    STREAMING_COMMAND_MAX_ACTOR_YIELDS, SendRequest, SendResponse, StateUpdate, StreamingApiError,
    StreamingCapabilitySet, StreamingCommandCapability, StreamingEquivalenceError,
    StreamingEquivalenceReport, StreamingEventFrame, StreamingFrame, StreamingStateUpdateFrame,
    WatchStream, validate_control_watch_send_equivalence,
};
pub use transport_security::{
    DebugTransportIdentity, MutualTlsServerConfigError, mutual_tls_acceptor_from_pem,
};
