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
//! [`event_log_stream`] owns the cursor-backed live event-log subscription facade;
//! [`session_mapping`] owns the API-to-session thin-wrapper contract; [`lifecycle`]
//! owns the unary discovery and lifecycle API; [`streaming`] owns the typed
//! `Control` and `Watch`+`Send` attach-and-command facade; [`server`] owns the
//! HTTP/2 daemon transport; [`open_set`] owns the dotted-kind plus
//! typed-attribute payload model; [`vm_lifecycle`] owns production local-VM
//! loop construction; [`vm_resume`] owns the process-local VM resume realization
//! bridge used by thin CLI callers; [`debug_gateway`] owns the Apache-side Unix
//! control client for the separate GPL debugger gateway process;
//! [`transport_security`] owns remote mutual-TLS authentication.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod client;
pub mod control_responsive;
pub mod debug_access;
pub mod debug_gateway;
mod debug_holders;
pub mod debug_relay;
pub mod event_log_stream;
pub mod lifecycle;
pub mod open_set;
pub mod rpc_abi;
pub mod server;
pub mod session_mapping;
pub mod streaming;
pub mod transport_security;
pub mod vm_lifecycle;
#[path = "vm_resume.rs"]
pub mod vm_resume;

pub use client::{
    ClientControlStream, ClientWatchStream, ControlClient, ControlClientError, ControlClientFuture,
    ControlTransportKind, ControlWireModel, DebugControllerAccess, DebugControllerAcquisition,
    HelloRequest, HelloResponse, InProcessControlClient, InProcessLifecycleControlStream,
    RpcControlClient, RpcControlStream, RpcEndpoint, RpcMutualTlsConfig, RpcTransportProtocol,
    RpcWatchStream, assert_shared_wire_model,
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
    SESSION_EVENT_LOG_REPLAY_BATCH_SIZE, SessionEventLogFrame, SessionEventLogHub,
    SessionEventLogSnapshot, SessionEventLogStream, SessionEventLogStreamError,
};
pub use lifecycle::{
    CreateSessionRequest, CreateSessionResponse, CreateSessionSource, DebugLandedRuntimeCoordinate,
    DebugRepositionDispatch, DebugRepositionResult, DestroySessionRequest, DestroySessionResponse,
    GetReproductionRequest, GetReproductionResponse, GuestIntrospectionDispatch,
    InProcessLifecycleClient, LIFECYCLE_SESSION_MAILBOX_CAPACITY,
    LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS, LifecycleApiError, LifecycleControlPlane,
    LifecycleLoopFactory, ListScenariosResponse, ListSessionsResponse, QuiescentLifecycleLoop,
    ReproductionCommandPayload, ReproductionCommandRecord, ReproductionCommandResult,
    ResumeSessionRequest, ResumeSessionResponse, ScenarioCatalogEntry, ScenarioCatalogSource,
    ScenarioSummary, SessionId, SessionRef, SessionSummary,
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
pub use vm_lifecycle::{
    ProductionBlockFaultEvidence, ProductionFaultEvidenceSnapshot, ProductionNetworkOutageEvidence,
    ProductionNetworkQueueEvidence, ProductionNodeFaultEvidence, ProductionVmLifecycleConfig,
    ProductionVmLifecycleLoop, ProductionVmNodeCheckpointArtifact, ProductionVmNodeGeneration,
    ProductionVmNodeLaunch, ProductionVmNodeLaunchKind, ProductionVmNodeLaunchRequest,
    ProductionVmNodeLauncher, ProductionVmNodeLease, ProductionVmNodePreparationKind,
    build_production_vm_lifecycle_loop, build_production_vm_lifecycle_loop_from_checkpoint,
    build_production_vm_lifecycle_loop_from_checkpoint_with_launcher,
    build_production_vm_lifecycle_loop_with_launcher, collect_signal_artifact_objects,
    production_vm_search_frontier,
};
// Re-exported so control-plane clients (e.g. the CLI) record the *shared*
// guest-host protocol version in a reproduction artifact's provenance triple
// without reaching past the control plane into `crucible-protocol` directly
// (control-plane boundary): the CLI depends on `crucible-api`, which legally
// depends on `crucible-protocol`.
pub use crucible_protocol::CONTROL_PROTOCOL_VERSION;
pub use crucible_protocol::guest_introspection::{
    GuestIntrospectionFailureCode, GuestIntrospectionMessage, GuestIntrospectionRecord,
    GuestOutputStream,
};
// Re-exported with backend-neutral names so process-local control clients can
// launch and attest the production backend without depending on its
// implementation crate directly.
pub use server::{
    LifecycleServerMode, serve_lifecycle_http2,
    serve_lifecycle_http2_mtls_with_mode_until_shutdown,
    serve_lifecycle_http2_with_debug_policy_until_shutdown, serve_lifecycle_http2_with_mode,
    serve_lifecycle_http2_with_mode_until_shutdown,
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
pub use vm_resume::{
    ModelCheckpointVmResumeRealizationProof, VmResumeRealizationError,
    realize_model_checkpoint_vm_resume_from_savepoint,
};
pub use vm_resume::{
    ProductionGuestArchitecture, ProductionPluginInstallConfig, ProductionPluginInstallError,
    ProductionPluginInstallReport, ProductionPluginSwitch, ProductionRootImageFormat,
    run_production_plugin_install_gate,
};
