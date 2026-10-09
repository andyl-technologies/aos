//! Native transport-independent Crucible control contracts, encodings, and compatibility rules.
//!
//! Spec index: RFC-0010 files 21.
//!
//! Module map: lifecycle and streaming own request/response values; rpc_abi
//! owns frozen encodings; open_set and session_mapping own capability vocabulary.
//! The crate does not start servers, instantiate actors, or launch QEMU.
//!
//! Native clients and services reuse session command, debugger, and event-log
//! value contracts here. The existing session and engine dependencies still
//! carry Tokio and native host support. This dependency graph is validated on
//! Linux; WASM reuse requires separating those upstream contracts from their
//! runtime implementations. Live event-log hubs and subscriptions are exposed
//! by crucible-control-server and crucible-session.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod control_responsive;
pub use control_responsive::{
    CONTROL_RESPONSIVE_QUANTUM_BOUND, CONTROL_RESPONSIVE_REQUIRED_OPERATIONS,
    ControlAcknowledgementStatus, ControlOperationAcknowledgement, ControlOperationKind,
    ControlResponsiveReport, ControlResponsivenessError, ControlSessionState,
    validate_control_responsiveness,
};
pub mod debug_relay;
pub use debug_relay::{
    DEBUG_RELAY_CHUNK_MAX_BYTES, DebugRelayChunk, DebugRelayError, DebugRelayId,
};
pub mod event_log_stream;
pub use event_log_stream::{
    EventLogCursor, SESSION_EVENT_LOG_BROADCAST_CAPACITY, SESSION_EVENT_LOG_REPLAY_BATCH_SIZE,
    SessionEventLogFrame, SessionEventLogSnapshot, SessionEventLogStreamError,
};
pub mod lifecycle;
pub use lifecycle::{
    CreateSessionRequest, CreateSessionResponse, CreateSessionSource, DebugLandedRuntimeCoordinate,
    DebugRepositionResult, DestroySessionRequest, DestroySessionResponse, GetReproductionRequest,
    GetReproductionResponse, LIFECYCLE_SESSION_MAILBOX_CAPACITY,
    LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS, LifecycleApiError, LifecycleResourceLimit,
    ListScenariosResponse, ListSessionsResponse, RESUME_OBSERVATION_PREPARATION_CAPACITY,
    RESUME_OBSERVATION_PREPARATION_TIMEOUT, RESUME_OBSERVATION_SOURCE_MAX_BYTES,
    RESUME_REPLAY_CLOSURE_MAX_BYTES, ReproductionCommandDecodeError, ReproductionCommandPayload,
    ReproductionCommandRecord, ReproductionCommandResult, ResumeObservationSource,
    ResumeReplayClosure, ResumeSessionRequest, ResumeSessionResponse, ScenarioCatalogEntry,
    ScenarioCatalogSource, ScenarioSummary, SessionId, SessionRef, SessionRetentionUpdateError,
    SessionSummary,
};
pub mod open_set;
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
pub mod rpc_abi;
pub use rpc_abi::{
    GOLDEN_RPC_VECTORS, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION, GOLDEN_VECTOR_RPC_REGENERATION_RULE,
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR,
    RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH, RPC_PROTOCOL_VERSION, RpcAbiError, RpcAttachMode,
    RpcEventClass, RpcGoldenVector, RpcGoldenVectorMessage, RpcStatusCode,
    encode_rpc_hello_request, encode_rpc_hello_response, encode_rpc_message,
    negotiate_rpc_protocol, rpc_status_code_from_wire_name, rpc_status_code_wire_name,
};
pub mod session_mapping;
pub use session_mapping::{
    API_COMMAND_MAPPINGS, API_METHOD_MAPPINGS, ApiCommandMapping, ApiDispatch, ApiMappingError,
    ApiMethod, ApiMethodMapping, ApiRequestShape, CommandDispatchCardinality,
    api_command_for_session_command, method_mapping, session_command_for_api_command,
    validate_thin_api_mapping,
};
pub mod streaming;
pub use streaming::{
    AttachRequest, AttachSnapshot, Attached, CommandRejectionKind, CommandResult,
    CommandResultStatus, STREAMING_COMMAND_MAX_ACTOR_YIELDS, SendRequest, SendResponse,
    StateUpdate, StreamingApiError, StreamingCapabilitySet, StreamingCommandCapability,
    StreamingEquivalenceError, StreamingEquivalenceReport, StreamingEventFrame, StreamingFrame,
    StreamingStateUpdateFrame, validate_control_watch_send_equivalence,
};
pub mod wire_model;
pub use wire_model::{ControlTransportKind, ControlWireModel, HelloRequest, HelloResponse};

pub use crucible_qemu_protocol::guest_introspection::{
    GuestIntrospectionFailureCode, GuestIntrospectionMessage, GuestIntrospectionRecord,
    GuestOutputStream,
};
pub use crucible_qemu_protocol::{CONTROL_PROTOCOL_VERSION, SELECTABLE_PROTOCOL_VERSION};
