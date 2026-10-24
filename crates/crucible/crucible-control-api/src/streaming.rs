//! Shared attach, command, event, and state-update contracts.
//!
//! These values describe the frozen control surface without allocating actors
//! or starting a transport.

use crucible_session::{
    BreakpointId, LiveQueryKind, LiveStateKind, QueryResult, SavepointInfo, SessionCommand,
    SessionCommandKind,
};
use thiserror::Error;

use crate::lifecycle::{ReproductionCommandRecord, SessionRef};
use crate::open_set::{OpenSetEventEnvelope, open_set_event_envelope_from_entry};
use crate::rpc_abi::{ProtocolVersion, RpcStatusCode};
use crate::session_mapping::{
    API_COMMAND_MAPPINGS, ApiDispatch, ApiMethod, CommandDispatchCardinality, method_mapping,
};
use crucible_session::{EventLogCursor, SessionEventLogFrame, SessionEventLogSnapshot};

/// Default actor-yield budget used while waiting for command state updates.
pub const STREAMING_COMMAND_MAX_ACTOR_YIELDS: u64 = 128;

#[path = "streaming/equivalence.rs"]
mod equivalence;
pub use equivalence::*;
/// Validates that `Control` and `Watch`+`Send` expose equivalent command capabilities.
///
/// # Errors
///
/// Returns [`StreamingEquivalenceError`] if the method mapping table no longer
/// models `Control`, `Watch`, and `Send` as thin streaming wrappers or if the
/// command capability sets diverge.
pub fn validate_control_watch_send_equivalence()
-> Result<StreamingEquivalenceReport, StreamingEquivalenceError> {
    require_control_mapping()?;
    require_watch_mapping()?;
    require_send_mapping()?;

    let control_capabilities = StreamingCapabilitySet::current();
    let send_capabilities = StreamingCapabilitySet::current();
    if control_capabilities != send_capabilities {
        return Err(StreamingEquivalenceError::CapabilityMismatch);
    }

    for command in SessionCommandKind::ALL {
        if !control_capabilities.contains(command) || !send_capabilities.contains(command) {
            return Err(StreamingEquivalenceError::MissingCommandCapability { command });
        }
    }

    Ok(StreamingEquivalenceReport {
        command_count: control_capabilities.commands.len(),
        control_capabilities,
        send_capabilities,
    })
}

/// Attach request shared by `Control` and `Watch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachRequest {
    /// Session the client wants to attach to.
    pub session: SessionRef,
    /// Optional epoch guard supplied by the client.
    pub expected_epoch: Option<u64>,
    /// Event-log cursor requested by the client.
    pub from: EventLogCursor,
    /// Operator-facing client name for diagnostics.
    pub client_name: String,
}

impl AttachRequest {
    /// Builds an attach request for `session`.
    #[must_use]
    pub fn new(session: SessionRef) -> Self {
        Self {
            session,
            expected_epoch: None,
            from: EventLogCursor::default(),
            client_name: String::from("crucible-api-client"),
        }
    }

    /// Sets the optional expected epoch guard.
    #[must_use]
    pub const fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }

    /// Sets the requested event-log cursor.
    #[must_use]
    pub const fn with_cursor(mut self, from: EventLogCursor) -> Self {
        self.from = from;
        self
    }

    /// Sets the client name reported in attach metadata.
    #[must_use]
    pub fn with_client_name(mut self, client_name: impl Into<String>) -> Self {
        self.client_name = client_name.into();
        self
    }
}

/// Metadata returned when a streaming client attaches to a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attached {
    /// Attached session reference.
    pub session: SessionRef,
    /// Event-log length observed at attach time.
    pub event_log_len: u64,
    /// Run-state observed from the lock-free live mirror at attach time.
    pub state: LiveStateKind,
    /// Protocol version used by this API surface.
    pub version: ProtocolVersion,
    /// Command capabilities available after attach.
    pub capabilities: StreamingCapabilitySet,
    /// Optional log-derived snapshot captured at attach time.
    pub snapshot: Option<AttachSnapshot>,
}

/// Log-derived snapshot summary included in `Attached`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachSnapshot {
    /// Cursor through which the snapshot was folded.
    pub through: EventLogCursor,
    /// Number of event-log entries folded into the snapshot.
    pub event_count: u64,
    /// Number of causal entries folded into the snapshot.
    pub causal_event_count: u64,
    /// Number of observational entries folded into the snapshot.
    pub observational_event_count: u64,
    /// Last sequence folded into the snapshot, when any entry was present.
    pub last_sequence: Option<u64>,
    /// Recorded command stream captured for deterministic reproduction.
    pub reproduction: Vec<ReproductionCommandRecord>,
}

impl AttachSnapshot {
    /// Builds an attach snapshot from the retained event-log summary.
    #[must_use]
    pub fn from_event_log(
        value: SessionEventLogSnapshot,
        reproduction: Vec<ReproductionCommandRecord>,
    ) -> Self {
        Self {
            through: value.through,
            event_count: value.event_count,
            causal_event_count: value.causal_count,
            observational_event_count: value.observational_count,
            last_sequence: value.last_sequence,
            reproduction,
        }
    }
}

/// API event frame delivered by `Control` and `Watch`.
#[derive(Clone, Debug, PartialEq)]
pub struct StreamingEventFrame {
    /// Event-log stream generation that produced this frame.
    pub generation: u64,
    /// Cursor position of this entry.
    pub cursor: EventLogCursor,
    /// Cursor position immediately after this entry.
    pub next_cursor: EventLogCursor,
    /// Open-set API event envelope.
    pub event: OpenSetEventEnvelope,
}

impl From<SessionEventLogFrame> for StreamingEventFrame {
    fn from(value: SessionEventLogFrame) -> Self {
        Self {
            generation: value.generation,
            cursor: value.cursor,
            next_cursor: value.next_cursor,
            event: open_set_event_envelope_from_entry(&value.entry),
        }
    }
}

/// Streaming frame delivered by `Control` and `Watch`.
#[derive(Clone, Debug, PartialEq)]
pub enum StreamingFrame {
    /// Open-set event-log frame.
    Event(StreamingEventFrame),
    /// Live run-state update frame.
    StateUpdate(StreamingStateUpdateFrame),
}

/// Run-state update returned beside a command result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StateUpdate {
    /// Session whose state changed.
    pub session: SessionRef,
    /// New state read from the lock-free live mirror.
    pub state: LiveStateKind,
}

/// Monotone run-state update delivered by `Control` and `Watch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamingStateUpdateFrame {
    /// Monotone actor-local state-transition sequence.
    pub sequence: u64,
    /// State update payload.
    pub update: StateUpdate,
}

/// Rejection class for a command result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandRejectionKind {
    /// The command is not valid in the session's current lifecycle state.
    InvalidState,
    /// The command referenced an absent checkpoint, breakpoint, fault, or session object.
    NotFound,
    /// The command payload was malformed or failed schema validation.
    InvalidArgument,
    /// The command, fault, or breakpoint kind is not advertised by capabilities.
    Unsupported,
    /// The backend or oracle failed while evaluating the command.
    Internal,
}

impl CommandRejectionKind {
    /// Returns the closed RPC status code corresponding to this rejection.
    #[must_use]
    pub const fn rpc_status(self) -> RpcStatusCode {
        match self {
            Self::InvalidState => RpcStatusCode::InvalidState,
            Self::NotFound => RpcStatusCode::NotFound,
            Self::InvalidArgument => RpcStatusCode::InvalidArgument,
            Self::Unsupported => RpcStatusCode::Unsupported,
            Self::Internal => RpcStatusCode::Internal,
        }
    }
}

impl TryFrom<RpcStatusCode> for CommandRejectionKind {
    type Error = ();

    fn try_from(value: RpcStatusCode) -> Result<Self, Self::Error> {
        match value {
            RpcStatusCode::InvalidState => Ok(Self::InvalidState),
            RpcStatusCode::NotFound => Ok(Self::NotFound),
            RpcStatusCode::InvalidArgument => Ok(Self::InvalidArgument),
            RpcStatusCode::Unsupported => Ok(Self::Unsupported),
            RpcStatusCode::Internal => Ok(Self::Internal),
            RpcStatusCode::Ok => Err(()),
        }
    }
}

/// Terminal status for a command result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandResultStatus {
    /// The command was accepted for actor dispatch.
    Accepted,
    /// The command was rejected before actor dispatch.
    Rejected {
        /// Reason the command was rejected.
        reason: CommandRejectionKind,
    },
}

/// Result returned for one streamed or unary command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommandResult {
    /// Client-supplied command correlation identifier.
    pub command_id: u64,
    /// Session command kind carried by the request.
    pub command_kind: SessionCommandKind,
    /// Terminal command status.
    pub status: CommandResultStatus,
}

/// Unary `Send` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRequest {
    /// Session the command targets.
    pub session: SessionRef,
    /// Optional epoch guard supplied by the client.
    pub expected_epoch: Option<u64>,
    /// Client-supplied command correlation identifier.
    pub command_id: u64,
    /// Existing session command to dispatch.
    pub command: SessionCommand,
}

impl SendRequest {
    /// Builds a unary send request.
    #[must_use]
    pub fn new(session: SessionRef, command_id: u64, command: SessionCommand) -> Self {
        Self {
            session,
            expected_epoch: None,
            command_id,
            command,
        }
    }

    /// Sets the optional expected epoch guard.
    #[must_use]
    pub const fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }
}

/// Response returned by unary `Send` and by a `Control` command envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendResponse {
    /// Command result.
    pub result: CommandResult,
    /// State update observed for commands that changed run-state.
    pub state_update: Option<StateUpdate>,
    /// Query payload returned by accepted read-only commands or by a lifecycle
    /// `Stop` that captures its terminal snapshot before cleanup.
    pub query_result: Option<QueryResult>,
    /// Breakpoint identifier returned by accepted breakpoint commands on typed transports.
    pub breakpoint_id: Option<BreakpointId>,
    /// Savepoint payload returned by accepted savepoint commands on typed transports.
    pub savepoint_info: Option<SavepointInfo>,
}

/// Error returned by streaming API operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StreamingApiError {
    /// The requested session is not present in the live registry.
    #[error("streaming session {session:?} was not found")]
    SessionNotFound {
        /// Requested session.
        session: SessionRef,
    },
    /// The request targeted a different session than this handle owns.
    #[error("streaming request targeted {requested:?}, but handle owns {actual:?}")]
    SessionMismatch {
        /// Requested session.
        requested: SessionRef,
        /// Actual session owned by the handle.
        actual: SessionRef,
    },
    /// The supplied expected epoch did not match the live session epoch.
    #[error("streaming epoch mismatch: expected {expected}, actual {actual}")]
    EpochMismatch {
        /// Caller-supplied epoch.
        expected: u64,
        /// Actual live epoch.
        actual: u64,
    },
    /// The actor command channel closed before the command could be sent or acknowledged.
    #[error("streaming command channel closed for {command:?}")]
    CommandChannelClosed {
        /// Command kind that could not be sent or acknowledged.
        command: SessionCommandKind,
    },
    /// An accepted command omitted the response payload required by its contract.
    #[error("streaming command {command:?} returned no required response payload")]
    CommandResponseMissing {
        /// Command kind whose response payload was missing.
        command: SessionCommandKind,
    },
    /// The live mirror did not publish the expected state in the yield budget.
    #[error("streaming command {command:?} did not reach state {expected:?}")]
    StateDidNotAdvance {
        /// Command kind whose expected state was not observed.
        command: SessionCommandKind,
        /// Expected state.
        expected: LiveStateKind,
    },
    /// The subscriber fell behind the bounded event-log tail.
    #[error("streaming event-log subscriber lagged by {skipped} frames")]
    EventStreamLagged {
        /// Number of skipped frames reported by the event-log stream.
        skipped: u64,
    },
}

fn require_control_mapping() -> Result<(), StreamingEquivalenceError> {
    match method_mapping(ApiMethod::Control).map(|mapping| mapping.dispatch) {
        Some(ApiDispatch::ControlStream {
            cardinality: CommandDispatchCardinality::OneSessionCommandPerEnvelope,
        }) => Ok(()),
        Some(_) => Err(StreamingEquivalenceError::UnexpectedDispatch {
            method: ApiMethod::Control,
        }),
        None => Err(StreamingEquivalenceError::MissingMethod {
            method: ApiMethod::Control,
        }),
    }
}

fn require_watch_mapping() -> Result<(), StreamingEquivalenceError> {
    match method_mapping(ApiMethod::Watch).map(|mapping| mapping.dispatch) {
        Some(ApiDispatch::WatchStream {
            attach_query: LiveQueryKind::Status,
        }) => Ok(()),
        Some(_) => Err(StreamingEquivalenceError::UnexpectedDispatch {
            method: ApiMethod::Watch,
        }),
        None => Err(StreamingEquivalenceError::MissingMethod {
            method: ApiMethod::Watch,
        }),
    }
}

fn require_send_mapping() -> Result<(), StreamingEquivalenceError> {
    match method_mapping(ApiMethod::Send).map(|mapping| mapping.dispatch) {
        Some(ApiDispatch::SendEnvelope {
            cardinality: CommandDispatchCardinality::OneSessionCommandPerEnvelope,
        }) => Ok(()),
        Some(_) => Err(StreamingEquivalenceError::UnexpectedDispatch {
            method: ApiMethod::Send,
        }),
        None => Err(StreamingEquivalenceError::MissingMethod {
            method: ApiMethod::Send,
        }),
    }
}
