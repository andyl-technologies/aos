//! API-side checks for the shared `ControlClient` trait.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use crucible::test_support::condition_payload_entry_for_test;
use crucible::{
    BackendError, Checkpoint, CheckpointKind, Configuration, ContentHash, ControlOperationKind,
    Decision, DeliveryOrderDecision, EventAttributeValue, EventDiagnosticPayload, EventLevel,
    EventLogOffset, GdbAttachInfo, GdbListen, GenesisCheckpoint, NodeId, QuantumLoop,
    QuantumOutcome, QuantumRequest, RngDecision, RngStreamId, ScenarioDef, ScenarioDefForm,
    Schedule, SchedulerError, SchedulerEventLogEntry, SchedulerEventLogPayload, Seed, SimDouble,
    SimDoubleConfig, SimulationBackend, TemporalGraph, VirtualTime,
};
use crucible_api::{
    API_COMMAND_MAPPINGS, AttachRequest, AttachSnapshot, Attached, ClientControlStream,
    ClientWatchStream, CommandRejectionKind, CommandResult, CommandResultStatus, ControlClient,
    ControlClientError, ControlPlaneEventLog, ControlStream, ControlTransportKind,
    ControlWireModel, CreateSessionRequest, CreateSessionResponse, DestroySessionRequest,
    DestroySessionResponse, EventLogCursor, GOLDEN_RPC_VECTORS, GetReproductionRequest,
    GetReproductionResponse, HelloRequest, InProcessControlClient, InProcessLifecycleClient,
    InProcessStreamingSession, LifecycleApiError, LifecycleControlPlane, LifecycleLoopFactory,
    LifecycleServerMode, ListScenariosResponse, ListSessionsResponse, OpenSetAttributeValue,
    OpenSetEventEnvelope, OpenSetEventSource, OpenSetEventTime, OpenSetPayload,
    QuiescentLifecycleLoop, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION,
    ReproductionCommandPayload, ReproductionCommandRecord, ReproductionCommandResult,
    ResumeSessionRequest, ResumeSessionResponse, RpcControlClient, RpcEndpoint, RpcStatusCode,
    RpcTransportProtocol, ScenarioCatalogEntry, ScenarioSummary, SendRequest, SendResponse,
    SessionId, SessionRef, SessionSummary, StateUpdate, StreamingApiError, StreamingCapabilitySet,
    StreamingEventFrame, StreamingFrame, StreamingStateUpdateFrame, WatchStream,
    assert_shared_wire_model, encode_rpc_hello_request, encode_rpc_hello_response,
    open_set_command_kind, rpc_status_code_wire_name, serve_lifecycle_http2,
    serve_lifecycle_http2_with_mode_until_shutdown, session_command_for_open_set_command_kind,
};
use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
use crucible_session::test_support::append_event_log_entries_for_test;
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, BreakpointSpec, CheckpointRef, CommandReply, Engine,
    EngineState, LifecycleStateKind, LiveStateKind, OutcomeKind, QueryKind, QueryResult,
    SessionActor, SessionCommand, SessionCommandKind, SessionError, SessionRunReport,
};
use futures_util::stream;
use tokio::sync::{Mutex, mpsc, oneshot};

include!("gate_control_client/contract_tests.rs");
include!("gate_control_client/conformance.rs");
include!("gate_control_client/http2_fixture.rs");
