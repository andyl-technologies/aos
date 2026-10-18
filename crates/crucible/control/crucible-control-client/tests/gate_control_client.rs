//! API-side checks for the shared `ControlClient` trait.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use crucible_control_api::{
    API_COMMAND_MAPPINGS, AttachRequest, AttachSnapshot, Attached, CommandRejectionKind,
    CommandResult, CommandResultStatus, ControlTransportKind, ControlWireModel,
    CreateSessionRequest, CreateSessionResponse, DestroySessionRequest, DestroySessionResponse,
    EventLogCursor, GOLDEN_RPC_VECTORS, GetReproductionRequest, GetReproductionResponse,
    HelloRequest, LifecycleApiError, ListScenariosResponse, ListSessionsResponse,
    OpenSetAttributeValue, OpenSetEventEnvelope, OpenSetEventSource, OpenSetEventTime,
    OpenSetPayload, RESUME_OBSERVATION_SOURCE_MAX_BYTES, RESUME_REPLAY_CLOSURE_MAX_BYTES,
    RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_VERSION, ReproductionCommandPayload,
    ReproductionCommandRecord, ReproductionCommandResult, ResumeObservationSource,
    ResumeReplayClosure, ResumeSessionRequest, ResumeSessionResponse, RpcStatusCode,
    ScenarioCatalogEntry, ScenarioSummary, SendRequest, SendResponse, SessionId, SessionRef,
    SessionSummary, StateUpdate, StreamingApiError, StreamingCapabilitySet, StreamingEventFrame,
    StreamingFrame, StreamingStateUpdateFrame, encode_rpc_hello_request, encode_rpc_hello_response,
    open_set_command_kind, rpc_status_code_wire_name, session_command_for_open_set_command_kind,
};
use crucible_control_client::{
    ClientControlStream, ClientWatchStream, ControlClient, ControlClientError, RpcControlClient,
    RpcEndpoint, RpcTransportProtocol, assert_shared_wire_model,
};
use crucible_control_server::{
    ControlPlaneEventLog, ControlStream, InProcessControlClient, InProcessLifecycleClient,
    InProcessStreamingSession, LifecycleControlPlane, LifecycleLoopFactory, LifecycleServerMode,
    QuiescentLifecycleLoop, ResumeReplayClosureValidationError, WatchStream, serve_lifecycle_http2,
    serve_lifecycle_http2_with_mode_until_shutdown,
};
use crucible_engine::test_support::condition_payload_entry_for_test;
use crucible_engine::{
    BackendError, Checkpoint, CheckpointKind, Configuration, ContentHash, ControlOperationKind,
    Decision, DeliveryOrderDecision, EventAttributeValue, EventDiagnosticPayload, EventLevel,
    EventLogOffset, GdbAttachInfo, GdbListen, GenesisCheckpoint, NodeId, QuantumLoop,
    QuantumOutcome, QuantumRequest, RngDecision, RngStreamId, ScenarioDef, ScenarioDefForm,
    Schedule, SchedulerError, SchedulerEventLogEntry, SchedulerEventLogPayload, Seed, SimDouble,
    SimDoubleConfig, SimulationBackend, TemporalGraph, VirtualTime,
};
use crucible_qemu_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
use crucible_session::test_support::append_event_log_entries_for_test;
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, BreakpointSpec, CheckpointRef, CommandReply, Engine,
    EngineState, LifecycleStateKind, LiveStateKind, OutcomeKind, QueryKind, QueryResult,
    SessionActor, SessionCommand, SessionCommandKind, SessionError, SessionRunReport, StepMode,
};
use futures_util::stream;
use tokio::sync::{Mutex, mpsc, oneshot};

#[path = "gate_control_client/conformance.rs"]
mod conformance;
#[path = "gate_control_client/contract_tests.rs"]
mod contract_tests;
#[path = "gate_control_client/http2_fixture.rs"]
mod http2_fixture;

use conformance::*;
use http2_fixture::*;
