//! Streaming `Control` and `Watch`+`Send` API facade.
//!
//! RFC-0010 T-API-4 introduces the typed attach-and-drive shape shared by the
//! bidirectional `Control` stream and the `Watch` plus unary `Send` pair. This
//! module keeps the surface intentionally thin: both command paths advertise the
//! same session command set and dispatch accepted commands through the same
//! `crucible-session` actor mailbox.

use std::sync::Arc;

use crucible::{
    BackendError, DebugAttachReport, DebugGotoReport, DebugNonCanonicalBranchReport,
    DebugReverseContinueReport, DebugReverseStepReport, EngineError, FaultTag, SchedulerError,
};
use crucible_session::{
    BreakpointId, CommandReply, LifecycleStateKind, LifecycleTransition, LiveQueryKind,
    LiveSnapshot, LiveSnapshotView, LiveStateKind, QueryResult, SavepointInfo, SessionCommand,
    SessionCommandKind, SessionError, SessionEventLogStream, SessionHandle, SessionReproductionLog,
    SessionStateTransitionBus, SessionStateTransitionFrame, SessionStateTransitionStream,
    lifecycle_transition,
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::event_log_stream::{
    ControlPlaneEventLog, EventLogCursor, SessionEventLogFrame, SessionEventLogSnapshot,
    SessionEventLogStreamError,
};
use crate::lifecycle::{ReproductionCommandRecord, SessionRef};
use crate::open_set::{OpenSetEventEnvelope, open_set_event_envelope_from_entry};
use crate::rpc_abi::{ProtocolVersion, RPC_PROTOCOL_VERSION, RpcStatusCode};
use crate::session_mapping::{
    API_COMMAND_MAPPINGS, ApiDispatch, ApiMethod, CommandDispatchCardinality, method_mapping,
};

/// Default actor-yield budget used while waiting for command state updates.
pub const STREAMING_COMMAND_MAX_ACTOR_YIELDS: u64 = 128;

/// One command kind advertised by a streaming command path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamingCommandCapability {
    /// Programmatic command name accepted by the API.
    pub command_name: &'static str,
    /// Existing session command kind reached by that name.
    pub command_kind: SessionCommandKind,
}

/// Command capabilities advertised by one streaming command path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingCapabilitySet {
    /// Command kinds accepted by the path.
    pub commands: Vec<StreamingCommandCapability>,
    /// Whether `Attached` carries a log-derived snapshot summary.
    pub snapshot_on_attach: bool,
}

impl StreamingCapabilitySet {
    /// Builds the current command capability set from the thin mapping table.
    #[must_use]
    pub fn current() -> Self {
        Self {
            commands: API_COMMAND_MAPPINGS
                .iter()
                .map(|mapping| StreamingCommandCapability {
                    command_name: mapping.command_name,
                    command_kind: mapping.command_kind,
                })
                .collect(),
            snapshot_on_attach: true,
        }
    }

    /// Returns whether `command` is advertised by this capability set.
    #[must_use]
    pub fn contains(&self, command: SessionCommandKind) -> bool {
        self.commands
            .iter()
            .any(|capability| capability.command_kind == command)
    }
}

/// Successful evidence that `Control` and `Watch`+`Send` expose the same command set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingEquivalenceReport {
    /// Number of command kinds exposed by each command path.
    pub command_count: usize,
    /// Capabilities advertised by the bidirectional `Control` stream.
    pub control_capabilities: StreamingCapabilitySet,
    /// Capabilities advertised by unary `Send`.
    pub send_capabilities: StreamingCapabilitySet,
}

/// Error returned when `Control` and `Watch`+`Send` are not equivalent.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StreamingEquivalenceError {
    /// A required API method is not present in the thin mapping table.
    #[error("streaming method {method:?} is missing from the API mapping table")]
    MissingMethod {
        /// Missing method.
        method: ApiMethod,
    },
    /// A required API method has the wrong dispatch class.
    #[error("streaming method {method:?} has an unexpected dispatch mapping")]
    UnexpectedDispatch {
        /// Misconfigured method.
        method: ApiMethod,
    },
    /// A session command kind is not advertised by both command paths.
    #[error("streaming command capability {command:?} is missing")]
    MissingCommandCapability {
        /// Missing command kind.
        command: SessionCommandKind,
    },
    /// The bidirectional and unary command capability sets differ.
    #[error("Control and Send command capability sets differ")]
    CapabilityMismatch,
}

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
    fn from_event_log(
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

enum CommandReplyObserver {
    FaultTag(oneshot::Receiver<Result<FaultTag, SessionError>>),
    Unit(oneshot::Receiver<Result<(), SessionError>>),
    BreakpointId(oneshot::Receiver<Result<BreakpointId, SessionError>>),
    BreakpointRemoval(oneshot::Receiver<Result<bool, SessionError>>),
    Savepoint(oneshot::Receiver<Result<SavepointInfo, SessionError>>),
    Fork(oneshot::Receiver<Result<SessionHandle, SessionError>>),
    Query(oneshot::Receiver<Result<QueryResult, SessionError>>),
    DebugAttach(oneshot::Receiver<Result<DebugAttachReport, SessionError>>),
    DebugGoto(oneshot::Receiver<Result<DebugGotoReport, SessionError>>),
    DebugReverseStep(oneshot::Receiver<Result<DebugReverseStepReport, SessionError>>),
    DebugReverseContinue(oneshot::Receiver<Result<DebugReverseContinueReport, SessionError>>),
    DebugForkNonCanonical(oneshot::Receiver<Result<DebugNonCanonicalBranchReport, SessionError>>),
}

impl CommandReplyObserver {
    async fn observe(
        self,
        command: SessionCommandKind,
    ) -> Result<
        (
            CommandResultStatus,
            Option<QueryResult>,
            Option<BreakpointId>,
            Option<SavepointInfo>,
        ),
        StreamingApiError,
    > {
        let rejected = match self {
            Self::FaultTag(receiver) => rejected_from_reply(receiver, command).await?,
            Self::Unit(receiver) => rejected_from_reply(receiver, command).await?,
            Self::BreakpointId(receiver) => match await_reply(receiver, command).await? {
                Ok(id) => return Ok((CommandResultStatus::Accepted, None, Some(id), None)),
                Err(error) => Some(session_error_rejection_kind(&error)),
            },
            Self::BreakpointRemoval(receiver) => match await_reply(receiver, command).await? {
                Ok(true) => None,
                Ok(false) => Some(CommandRejectionKind::NotFound),
                Err(error) => Some(session_error_rejection_kind(&error)),
            },
            Self::Savepoint(receiver) => match await_reply(receiver, command).await? {
                Ok(savepoint) => {
                    return Ok((CommandResultStatus::Accepted, None, None, Some(savepoint)));
                }
                Err(error) => Some(session_error_rejection_kind(&error)),
            },
            Self::Fork(receiver) => rejected_from_reply(receiver, command).await?,
            Self::Query(receiver) => match await_reply(receiver, command).await? {
                Ok(result) => return Ok((CommandResultStatus::Accepted, Some(result), None, None)),
                Err(error) => Some(session_error_rejection_kind(&error)),
            },
            Self::DebugAttach(receiver) => rejected_from_reply(receiver, command).await?,
            Self::DebugGoto(receiver) => rejected_from_reply(receiver, command).await?,
            Self::DebugReverseStep(receiver) => rejected_from_reply(receiver, command).await?,
            Self::DebugReverseContinue(receiver) => rejected_from_reply(receiver, command).await?,
            Self::DebugForkNonCanonical(receiver) => rejected_from_reply(receiver, command).await?,
        };
        Ok((
            match rejected {
                Some(reason) => CommandResultStatus::Rejected { reason },
                None => CommandResultStatus::Accepted,
            },
            None,
            None,
            None,
        ))
    }
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
    /// A legacy peer reported state-update lag instead of coalescing it.
    ///
    /// Current in-process and RPC receivers retain this variant for wire and
    /// source compatibility but recover to their newest available state.
    #[error("streaming state-update subscriber lagged by {skipped} frames")]
    StateUpdateStreamLagged {
        /// Number of skipped frames reported by the state-transition stream.
        skipped: u64,
    },
}

/// In-process streaming API handle for one live session.
#[derive(Clone)]
pub struct InProcessStreamingSession {
    session: SessionRef,
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    event_log: ControlPlaneEventLog,
    reproduction_log: SessionReproductionLog,
    state_transitions: SessionStateTransitionBus,
    max_actor_yields: u64,
}

impl InProcessStreamingSession {
    /// Builds a streaming API handle from actor-owned session handles.
    #[must_use]
    pub fn new(
        session: SessionRef,
        sender: mpsc::Sender<SessionCommand>,
        live: Arc<LiveSnapshot>,
        event_log: ControlPlaneEventLog,
        reproduction_log: SessionReproductionLog,
        state_transitions: SessionStateTransitionBus,
    ) -> Self {
        Self {
            session,
            sender,
            live,
            event_log,
            reproduction_log,
            state_transitions,
            max_actor_yields: STREAMING_COMMAND_MAX_ACTOR_YIELDS,
        }
    }

    /// Returns a copy of this handle with an explicit actor-yield wait budget.
    #[must_use]
    pub const fn with_max_actor_yields(mut self, max_actor_yields: u64) -> Self {
        self.max_actor_yields = max_actor_yields;
        self
    }

    /// Returns the event-log facade used for cursor-backed attach streams.
    #[must_use]
    pub const fn event_log(&self) -> &ControlPlaneEventLog {
        &self.event_log
    }

    /// Returns the reproduction-log snapshot handle used for attach metadata.
    #[must_use]
    pub const fn reproduction_log(&self) -> &SessionReproductionLog {
        &self.reproduction_log
    }

    /// Returns the state-transition bus used for live run-state updates.
    #[must_use]
    pub const fn state_transitions(&self) -> &SessionStateTransitionBus {
        &self.state_transitions
    }

    /// Attaches a bidirectional `Control` stream.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError`] if the request targets a different session
    /// or if the optional expected epoch does not match.
    pub fn control(&self, request: AttachRequest) -> Result<ControlStream, StreamingApiError> {
        let (attached, events, state_updates) = self.attach_stream(&request)?;
        Ok(ControlStream {
            session: self.session,
            sender: self.sender.clone(),
            live: Arc::clone(&self.live),
            attached,
            events,
            state_updates,
            max_actor_yields: self.max_actor_yields,
        })
    }

    /// Attaches a read-only `Watch` stream.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError`] if the request targets a different session
    /// or if the optional expected epoch does not match.
    pub fn watch(&self, request: AttachRequest) -> Result<WatchStream, StreamingApiError> {
        let (attached, events, state_updates) = self.attach_stream(&request)?;
        Ok(WatchStream {
            session: self.session,
            attached,
            events,
            state_updates,
        })
    }

    /// Dispatches one unary `Send` command.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError`] if the request targets a different session,
    /// the optional expected epoch does not match, the actor channel closes, or
    /// an expected state update is not observed.
    pub async fn send(&self, request: SendRequest) -> Result<SendResponse, StreamingApiError> {
        self.validate_session(request.session, request.expected_epoch)?;
        dispatch_command(
            self.session,
            &self.sender,
            &self.live,
            self.max_actor_yields,
            request.command_id,
            request.command,
        )
        .await
    }

    fn attach_stream(
        &self,
        request: &AttachRequest,
    ) -> Result<
        (
            Attached,
            SessionEventLogStream,
            SessionStateTransitionStream,
        ),
        StreamingApiError,
    > {
        self.validate_session(request.session, request.expected_epoch)?;
        let mut state_updates = self.state_transitions.subscribe();
        let (attach_tail, events) = self.event_log.subscribe_with_replay_tail(request.from);
        let reproduction = self
            .reproduction_log
            .snapshot()
            .into_iter()
            .map(ReproductionCommandRecord::from)
            .filter(|record| record.at_sequence <= attach_tail.next_sequence)
            .collect();
        let snapshot = AttachSnapshot::from_event_log(
            self.event_log.snapshot_through(attach_tail),
            reproduction,
        );
        let live = self.live.read();
        state_updates.set_sequence_floor(live.state_transition_sequence);
        Ok((
            Attached {
                session: self.session,
                event_log_len: attach_tail.next_sequence,
                state: live.state_kind,
                version: RPC_PROTOCOL_VERSION,
                capabilities: StreamingCapabilitySet::current(),
                snapshot: Some(snapshot),
            },
            events,
            state_updates,
        ))
    }

    fn validate_session(
        &self,
        requested: SessionRef,
        expected_epoch: Option<u64>,
    ) -> Result<(), StreamingApiError> {
        if requested != self.session {
            return Err(StreamingApiError::SessionMismatch {
                requested,
                actual: self.session,
            });
        }
        if let Some(expected) = expected_epoch
            && expected != self.session.epoch
        {
            return Err(StreamingApiError::EpochMismatch {
                expected,
                actual: self.session.epoch,
            });
        }
        Ok(())
    }
}

/// Attached bidirectional `Control` stream handle.
pub struct ControlStream {
    session: SessionRef,
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    attached: Attached,
    events: SessionEventLogStream,
    state_updates: SessionStateTransitionStream,
    max_actor_yields: u64,
}

impl ControlStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub const fn attached(&self) -> &Attached {
        &self.attached
    }

    /// Returns the event stream backing the control response tail.
    #[must_use]
    pub fn event_stream(&mut self) -> &mut SessionEventLogStream {
        &mut self.events
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError::EventStreamLagged`] if the subscriber falls
    /// behind the bounded live tail.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, StreamingApiError> {
        recv_api_event(&mut self.events).await
    }

    /// Receives the next live run-state update.
    ///
    /// Superseded updates may be coalesced when the subscriber falls behind the
    /// bounded state-update tail. The returned sequence remains monotone.
    ///
    /// # Errors
    ///
    /// This method currently has no recoverable error condition. Its result
    /// remains fallible for compatibility with the combined streaming API.
    pub async fn recv_state_update(
        &mut self,
    ) -> Result<Option<StreamingStateUpdateFrame>, StreamingApiError> {
        recv_api_state_update(self.session, &mut self.state_updates).await
    }

    /// Receives the next event or state-update frame.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError::EventStreamLagged`] if the canonical event
    /// subscriber falls behind. Superseded state updates are coalesced.
    pub async fn recv_frame(&mut self) -> Result<Option<StreamingFrame>, StreamingApiError> {
        recv_api_frame(self.session, &mut self.events, &mut self.state_updates).await
    }

    /// Dispatches one command envelope through the control stream.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError`] if the actor channel closes or an expected
    /// state update is not observed.
    pub async fn send_command(
        &self,
        command_id: u64,
        command: SessionCommand,
    ) -> Result<SendResponse, StreamingApiError> {
        dispatch_command(
            self.session,
            &self.sender,
            &self.live,
            self.max_actor_yields,
            command_id,
            command,
        )
        .await
    }
}

/// Attached read-only `Watch` stream handle.
pub struct WatchStream {
    session: SessionRef,
    attached: Attached,
    events: SessionEventLogStream,
    state_updates: SessionStateTransitionStream,
}

impl WatchStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub const fn attached(&self) -> &Attached {
        &self.attached
    }

    /// Returns the event stream backing the watch response tail.
    #[must_use]
    pub fn event_stream(&mut self) -> &mut SessionEventLogStream {
        &mut self.events
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError::EventStreamLagged`] if the subscriber falls
    /// behind the bounded live tail.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, StreamingApiError> {
        recv_api_event(&mut self.events).await
    }

    /// Receives the next live run-state update.
    ///
    /// Superseded updates may be coalesced when the subscriber falls behind the
    /// bounded state-update tail. The returned sequence remains monotone.
    ///
    /// # Errors
    ///
    /// This method currently has no recoverable error condition. Its result
    /// remains fallible for compatibility with the combined streaming API.
    pub async fn recv_state_update(
        &mut self,
    ) -> Result<Option<StreamingStateUpdateFrame>, StreamingApiError> {
        recv_api_state_update(self.session, &mut self.state_updates).await
    }

    /// Receives the next event or state-update frame.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError::EventStreamLagged`] if the canonical event
    /// subscriber falls behind. Superseded state updates are coalesced.
    pub async fn recv_frame(&mut self) -> Result<Option<StreamingFrame>, StreamingApiError> {
        recv_api_frame(self.session, &mut self.events, &mut self.state_updates).await
    }
}

async fn recv_api_event(
    events: &mut SessionEventLogStream,
) -> Result<Option<StreamingEventFrame>, StreamingApiError> {
    events
        .recv()
        .await
        .map(|frame| frame.map(StreamingEventFrame::from))
        .map_err(stream_error)
}

fn stream_error(error: SessionEventLogStreamError) -> StreamingApiError {
    match error {
        SessionEventLogStreamError::Lagged { skipped } => {
            StreamingApiError::EventStreamLagged { skipped }
        }
    }
}

fn command_with_reply_observer(
    command: SessionCommand,
) -> (SessionCommand, Option<CommandReplyObserver>) {
    let (command, observer) = match command {
        SessionCommand::InjectFault { spec, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::InjectFault { spec, reply },
                Some(CommandReplyObserver::FaultTag(receiver)),
            )
        }
        SessionCommand::HealFault { tag, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::HealFault { tag, reply },
                Some(CommandReplyObserver::Unit(receiver)),
            )
        }
        SessionCommand::SetBreakpoint { spec, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::SetBreakpoint { spec, reply },
                Some(CommandReplyObserver::BreakpointId(receiver)),
            )
        }
        SessionCommand::RemoveBreakpoint { id, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::RemoveBreakpoint { id, reply },
                Some(CommandReplyObserver::BreakpointRemoval(receiver)),
            )
        }
        SessionCommand::CreateSavepoint { label, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::CreateSavepoint { label, reply },
                Some(CommandReplyObserver::Savepoint(receiver)),
            )
        }
        SessionCommand::Fork { from, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::Fork { from, reply },
                Some(CommandReplyObserver::Fork(receiver)),
            )
        }
        SessionCommand::Query { kind, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::Query { kind, reply },
                Some(CommandReplyObserver::Query(receiver)),
            )
        }
        SessionCommand::AttachGdb {
            node,
            listen,
            debug_genesis,
            ..
        } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::AttachGdb {
                    node,
                    listen,
                    debug_genesis,
                    reply,
                },
                Some(CommandReplyObserver::DebugAttach(receiver)),
            )
        }
        SessionCommand::DebugGoto { request, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::DebugGoto { request, reply },
                Some(CommandReplyObserver::DebugGoto(receiver)),
            )
        }
        SessionCommand::DebugReverseStep { request, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::DebugReverseStep { request, reply },
                Some(CommandReplyObserver::DebugReverseStep(receiver)),
            )
        }
        SessionCommand::DebugReverseContinue { request, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::DebugReverseContinue { request, reply },
                Some(CommandReplyObserver::DebugReverseContinue(receiver)),
            )
        }
        SessionCommand::DebugForkNonCanonical { request, .. } => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::DebugForkNonCanonical { request, reply },
                Some(CommandReplyObserver::DebugForkNonCanonical(receiver)),
            )
        }
        command => (command, None),
    };
    match observer {
        Some(observer) => (
            SessionCommand::acknowledged(command, CommandReply::discard()),
            Some(observer),
        ),
        None => {
            let (reply, receiver) = CommandReply::channel();
            (
                SessionCommand::acknowledged(command, reply),
                Some(CommandReplyObserver::Unit(receiver)),
            )
        }
    }
}

async fn rejected_from_reply<T>(
    receiver: oneshot::Receiver<Result<T, SessionError>>,
    command: SessionCommandKind,
) -> Result<Option<CommandRejectionKind>, StreamingApiError> {
    match await_reply(receiver, command).await? {
        Ok(_) => Ok(None),
        Err(error) => Ok(Some(session_error_rejection_kind(&error))),
    }
}

async fn await_reply<T>(
    receiver: oneshot::Receiver<Result<T, SessionError>>,
    command: SessionCommandKind,
) -> Result<Result<T, SessionError>, StreamingApiError> {
    receiver
        .await
        .map_err(|_| StreamingApiError::CommandChannelClosed { command })
}

fn session_error_rejection_kind(error: &SessionError) -> CommandRejectionKind {
    match error {
        SessionError::InvalidTransition { .. }
        | SessionError::InvalidEngineState { .. }
        | SessionError::DebugAttachRequired { .. }
        | SessionError::DebugNonCanonicalBranchRequired { .. }
        | SessionError::GuestIntrospectionNotAuthorized { .. }
        | SessionError::DebugHistoryUnavailable { .. } => CommandRejectionKind::InvalidState,
        SessionError::BreakpointNotFound { .. } => CommandRejectionKind::NotFound,
        SessionError::BreakpointConditionPrefix { .. } => CommandRejectionKind::InvalidArgument,
        SessionError::UnsupportedBreakpointAction { .. }
        | SessionError::UnsupportedBreakpointFault { .. } => CommandRejectionKind::Unsupported,
        SessionError::Engine(error) => engine_error_rejection_kind(error),
        SessionError::Scheduler(error) => scheduler_error_rejection_kind(error),
        SessionError::ChannelClosed
        | SessionError::EventLogOffsetRegression { .. }
        | SessionError::EventLogOffsetMismatch { .. }
        | SessionError::ControlReplayBoundaryMismatch { .. }
        | SessionError::ControlReplayFrontierMismatch { .. }
        | SessionError::ControlReplayBatchMismatch { .. }
        | SessionError::ControlReplayFinalSnapshotMismatch { .. }
        | SessionError::DebugRuntimeRepositionMismatch(_) => CommandRejectionKind::Internal,
    }
}

fn engine_error_rejection_kind(error: &EngineError) -> CommandRejectionKind {
    match error {
        EngineError::CheckpointNotRecorded { .. }
        | EngineError::MissingBakedGenesis { .. }
        | EngineError::PlanFaultUnknownNode { .. }
        | EngineError::PlanFaultUnknownLink { .. }
        | EngineError::PlanFaultUnknownLinkId { .. }
        | EngineError::PlanFaultUnknownDevice { .. }
        | EngineError::PlanHealUnknownTag { .. }
        | EngineError::PropertyPredicateUnknownNode { .. }
        | EngineError::PropertyPredicateUnknownAssertion { .. }
        | EngineError::DebugAttachUnknownNode { .. }
        | EngineError::DebugTargetResolverFailureNotFound { .. }
        | EngineError::DebugTimeTravelCoordinateNotFound { .. }
        | EngineError::DebugTimeTravelUnknownNode { .. } => CommandRejectionKind::NotFound,
        EngineError::NotImplemented { .. }
        | EngineError::WorldNodeUnsupportedWorkload { .. }
        | EngineError::WorldNodeUnsupportedWorkloadConfigTree { .. }
        | EngineError::WorldNodeUnsupportedWorkloadPattern { .. }
        | EngineError::WorldNodeUnsupportedWorkloadSpikeMode { .. }
        | EngineError::WorldNodeUnsupportedWorkloadTimeSource { .. }
        | EngineError::PlanFaultUnsupportedParam { .. }
        | EngineError::DebugBreakpointRequiresAllowMutate { .. }
        | EngineError::EventLogReplayUnsupported { .. } => CommandRejectionKind::Unsupported,
        EngineError::SchedulePrefix(error) => schedule_error_rejection_kind(error),
        _ => CommandRejectionKind::Internal,
    }
}

fn schedule_error_rejection_kind(error: &crucible::ScheduleError) -> CommandRejectionKind {
    let _ = error;
    CommandRejectionKind::InvalidArgument
}

fn scheduler_error_rejection_kind(error: &SchedulerError) -> CommandRejectionKind {
    match error {
        SchedulerError::NotImplemented { .. } => CommandRejectionKind::Unsupported,
        SchedulerError::Backend(error) => backend_error_rejection_kind(error),
        SchedulerError::BoundaryViolation { .. } => CommandRejectionKind::Internal,
        SchedulerError::TimeConversion(_) | SchedulerError::TopologyActivationInPast { .. } => {
            CommandRejectionKind::InvalidArgument
        }
    }
}

const fn backend_error_rejection_kind(error: &BackendError) -> CommandRejectionKind {
    match error {
        BackendError::NotImplemented { .. } | BackendError::Unsupported { .. } => {
            CommandRejectionKind::Unsupported
        }
        BackendError::Rejected { .. } => CommandRejectionKind::InvalidArgument,
    }
}

async fn recv_api_state_update(
    session: SessionRef,
    state_updates: &mut SessionStateTransitionStream,
) -> Result<Option<StreamingStateUpdateFrame>, StreamingApiError> {
    Ok(state_updates
        .recv_latest()
        .await
        .map(|frame| state_update_frame(session, frame)))
}

async fn recv_api_frame(
    session: SessionRef,
    events: &mut SessionEventLogStream,
    state_updates: &mut SessionStateTransitionStream,
) -> Result<Option<StreamingFrame>, StreamingApiError> {
    // crucible-lint: allow unordered-select -- API stream multiplexing preserves per-source ordering.
    tokio::select! {
        event = recv_api_event(events) => event.map(|frame| frame.map(StreamingFrame::Event)),
        state_update = recv_api_state_update(session, state_updates) => {
            state_update.map(|frame| frame.map(StreamingFrame::StateUpdate))
        }
    }
}

fn state_update_frame(
    session: SessionRef,
    frame: SessionStateTransitionFrame,
) -> StreamingStateUpdateFrame {
    StreamingStateUpdateFrame {
        sequence: frame.sequence,
        update: StateUpdate {
            session,
            state: frame.to.state_kind,
        },
    }
}

async fn dispatch_command(
    session: SessionRef,
    sender: &mpsc::Sender<SessionCommand>,
    live: &Arc<LiveSnapshot>,
    max_actor_yields: u64,
    command_id: u64,
    command: SessionCommand,
) -> Result<SendResponse, StreamingApiError> {
    let before = live.read();
    let before_state = before.state_kind;
    let command_kind = SessionCommandKind::from(&command);
    let transition = lifecycle_transition(lifecycle_state(before_state), command_kind);
    if let LifecycleTransition::Rejected = transition {
        return Ok(SendResponse {
            result: CommandResult {
                command_id,
                command_kind,
                status: CommandResultStatus::Rejected {
                    reason: CommandRejectionKind::InvalidState,
                },
            },
            state_update: None,
            query_result: None,
            breakpoint_id: None,
            savepoint_info: None,
        });
    }

    let (command, reply_observer) = command_with_reply_observer(command);

    sender
        .send(command)
        .await
        .map_err(|_| StreamingApiError::CommandChannelClosed {
            command: command_kind,
        })?;

    let (status, query_result, breakpoint_id, savepoint_info) = match reply_observer {
        Some(observer) => observer.observe(command_kind).await?,
        None => (CommandResultStatus::Accepted, None, None, None),
    };
    let result = CommandResult {
        command_id,
        command_kind,
        status,
    };

    let state_update = match (transition, result.status) {
        (LifecycleTransition::Accepted { to }, CommandResultStatus::Accepted) => {
            let expected = live_state(to);
            if expected == before_state {
                None
            } else {
                let state = if command_requires_stable_state_ack(command_kind) {
                    wait_for_streaming_state(
                        live,
                        command_kind,
                        expected,
                        before.state_transition_sequence,
                        max_actor_yields,
                    )
                    .await?
                } else {
                    expected
                };
                Some(StateUpdate { session, state })
            }
        }
        (LifecycleTransition::Rejected, _) => None,
        (_, CommandResultStatus::Rejected { .. }) => None,
    };
    Ok(SendResponse {
        result,
        state_update,
        query_result,
        breakpoint_id,
        savepoint_info,
    })
}

async fn wait_for_streaming_state(
    live: &LiveSnapshot,
    command: SessionCommandKind,
    expected: LiveStateKind,
    before_transition_sequence: u64,
    max_actor_yields: u64,
) -> Result<LiveStateKind, StreamingApiError> {
    let observed = live.read();
    if streaming_state_satisfies_ack(command, expected, &observed, before_transition_sequence) {
        return Ok(observed.state_kind);
    }
    for _ in 0..max_actor_yields {
        tokio::task::yield_now().await;
        let observed = live.read();
        if streaming_state_satisfies_ack(command, expected, &observed, before_transition_sequence) {
            return Ok(observed.state_kind);
        }
    }
    Err(StreamingApiError::StateDidNotAdvance { command, expected })
}

fn streaming_state_satisfies_ack(
    command: SessionCommandKind,
    expected: LiveStateKind,
    observed: &LiveSnapshotView,
    before_transition_sequence: u64,
) -> bool {
    observed.state_kind == expected
        || (matches!(
            (command, expected, observed.state_kind),
            (
                SessionCommandKind::Continue,
                LiveStateKind::Running,
                LiveStateKind::Paused | LiveStateKind::Stopped
            )
        ) && observed.state_transition_sequence > before_transition_sequence)
}

const fn command_requires_stable_state_ack(command: SessionCommandKind) -> bool {
    !matches!(
        command,
        SessionCommandKind::StepQuantum
            | SessionCommandKind::StepEvent
            | SessionCommandKind::StepAssertion
            | SessionCommandKind::StepTimer
            | SessionCommandKind::StepDuration
    )
}

const fn lifecycle_state(state: LiveStateKind) -> LifecycleStateKind {
    match state {
        LiveStateKind::Loaded => LifecycleStateKind::Loaded,
        LiveStateKind::Running => LifecycleStateKind::Running,
        LiveStateKind::Paused => LifecycleStateKind::Paused,
        LiveStateKind::Stopped => LifecycleStateKind::Stopped,
    }
}

const fn live_state(state: LifecycleStateKind) -> LiveStateKind {
    match state {
        LifecycleStateKind::Loaded => LiveStateKind::Loaded,
        LifecycleStateKind::Running => LiveStateKind::Running,
        LifecycleStateKind::Paused => LiveStateKind::Paused,
        LifecycleStateKind::Stopped => LiveStateKind::Stopped,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continue_acknowledges_an_immediate_breakpoint_pause() {
        let mut observed = LiveSnapshotView {
            state_kind: LiveStateKind::Paused,
            outcome: None,
            terminal_savepoint: None,
            configuration: crucible::ContentHash::default(),
            virtual_time: crucible::VirtualTime::default(),
            event_log_len: 0,
            quanta_stepped: 0,
            control_acknowledgements: 0,
            state_transition_sequence: 7,
        };
        assert!(!streaming_state_satisfies_ack(
            SessionCommandKind::Continue,
            LiveStateKind::Running,
            &observed,
            7,
        ));
        observed.state_transition_sequence = 9;
        assert!(streaming_state_satisfies_ack(
            SessionCommandKind::Continue,
            LiveStateKind::Running,
            &observed,
            7,
        ));
    }
}
