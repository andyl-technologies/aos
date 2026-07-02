//! Streaming `Control` and `Watch`+`Send` API facade.
//!
//! RFC-0010 T-API-4 introduces the typed attach-and-drive shape shared by the
//! bidirectional `Control` stream and the `Watch` plus unary `Send` pair. This
//! module keeps the surface intentionally thin: both command paths advertise the
//! same session command set and dispatch accepted commands through the same
//! `crucible-session` actor mailbox.

use std::sync::Arc;

use crucible_session::{
    LifecycleStateKind, LifecycleTransition, LiveQueryKind, LiveSnapshot, LiveStateKind,
    SessionCommand, SessionCommandKind, SessionEventLogStream, lifecycle_transition,
};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::event_log_stream::{ControlPlaneEventLog, EventLogCursor};
use crate::lifecycle::SessionRef;
use crate::rpc_abi::{ProtocolVersion, RPC_PROTOCOL_VERSION};
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
}

/// Run-state update returned beside a command result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StateUpdate {
    /// Session whose state changed.
    pub session: SessionRef,
    /// New state read from the lock-free live mirror.
    pub state: LiveStateKind,
}

/// Rejection class for a command result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandRejectionKind {
    /// The command is not valid in the session's current lifecycle state.
    InvalidState,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SendResponse {
    /// Command result.
    pub result: CommandResult,
    /// State update observed for commands that changed run-state.
    pub state_update: Option<StateUpdate>,
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
    /// The actor command channel closed before the command could be sent.
    #[error("streaming command channel closed for {command:?}")]
    CommandChannelClosed {
        /// Command kind that could not be sent.
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
}

/// In-process streaming API handle for one live session.
#[derive(Clone)]
pub struct InProcessStreamingSession {
    session: SessionRef,
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    event_log: ControlPlaneEventLog,
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
    ) -> Self {
        Self {
            session,
            sender,
            live,
            event_log,
            max_actor_yields: STREAMING_COMMAND_MAX_ACTOR_YIELDS,
        }
    }

    /// Returns a copy of this handle with an explicit actor-yield wait budget.
    #[must_use]
    pub const fn with_max_actor_yields(mut self, max_actor_yields: u64) -> Self {
        self.max_actor_yields = max_actor_yields;
        self
    }

    /// Attaches a bidirectional `Control` stream.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError`] if the request targets a different session
    /// or if the optional expected epoch does not match.
    pub fn control(&self, request: AttachRequest) -> Result<ControlStream, StreamingApiError> {
        let attached = self.attached(&request)?;
        let events = self.event_log.subscribe(request.from);
        Ok(ControlStream {
            session: self.session,
            sender: self.sender.clone(),
            live: Arc::clone(&self.live),
            attached,
            events,
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
        let attached = self.attached(&request)?;
        let events = self.event_log.subscribe(request.from);
        Ok(WatchStream { attached, events })
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

    fn attached(&self, request: &AttachRequest) -> Result<Attached, StreamingApiError> {
        self.validate_session(request.session, request.expected_epoch)?;
        let live = self.live.read();
        Ok(Attached {
            session: self.session,
            event_log_len: live.event_log_len,
            state: live.state_kind,
            version: RPC_PROTOCOL_VERSION,
            capabilities: StreamingCapabilitySet::current(),
        })
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
        if let Some(expected) = expected_epoch {
            if expected != self.session.epoch {
                return Err(StreamingApiError::EpochMismatch {
                    expected,
                    actual: self.session.epoch,
                });
            }
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
    attached: Attached,
    events: SessionEventLogStream,
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
}

async fn dispatch_command(
    session: SessionRef,
    sender: &mpsc::Sender<SessionCommand>,
    live: &Arc<LiveSnapshot>,
    max_actor_yields: u64,
    command_id: u64,
    command: SessionCommand,
) -> Result<SendResponse, StreamingApiError> {
    let before = live.read().state_kind;
    let command_kind = SessionCommandKind::from(&command);
    let transition = lifecycle_transition(lifecycle_state(before), command_kind);
    let result = match transition {
        LifecycleTransition::Accepted { .. } => CommandResult {
            command_id,
            command_kind,
            status: CommandResultStatus::Accepted,
        },
        LifecycleTransition::Rejected => {
            return Ok(SendResponse {
                result: CommandResult {
                    command_id,
                    command_kind,
                    status: CommandResultStatus::Rejected {
                        reason: CommandRejectionKind::InvalidState,
                    },
                },
                state_update: None,
            });
        }
    };

    sender
        .send(command)
        .await
        .map_err(|_| StreamingApiError::CommandChannelClosed {
            command: command_kind,
        })?;

    let state_update = match transition {
        LifecycleTransition::Accepted { to } => {
            let expected = live_state(to);
            if expected == before {
                None
            } else {
                Some(wait_for_state(session, live, command_kind, expected, max_actor_yields).await?)
            }
        }
        LifecycleTransition::Rejected => None,
    };

    Ok(SendResponse {
        result,
        state_update,
    })
}

async fn wait_for_state(
    session: SessionRef,
    live: &Arc<LiveSnapshot>,
    command: SessionCommandKind,
    expected: LiveStateKind,
    max_actor_yields: u64,
) -> Result<StateUpdate, StreamingApiError> {
    for _ in 0..max_actor_yields {
        let state = live.read().state_kind;
        if state == expected {
            return Ok(StateUpdate { session, state });
        }
        tokio::task::yield_now().await;
    }
    Err(StreamingApiError::StateDidNotAdvance { command, expected })
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
