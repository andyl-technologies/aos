//! Session command payloads, replies, and breakpoint specifications.

use super::*;
use crucible::GenesisCheckpoint;

/// Actor-local breakpoint identifier.
pub type BreakpointId = u64;

/// Reply channel carried by commands that return data to their caller.
///
/// The reply transport is deliberately not part of command equality or hashing:
/// it routes completion back to the caller, but it is not model state.
pub(super) type CommandReplySender<T> =
    Arc<Mutex<Option<oneshot::Sender<Result<T, SessionError>>>>>;

/// Reply channel carried by commands that return data to their caller.
///
/// The reply transport is deliberately not part of command equality or hashing:
/// it routes completion back to the caller, but it is not model state.
pub struct CommandReply<T> {
    inner: Option<CommandReplySender<T>>,
}

impl<T> CommandReply<T> {
    /// Builds a reply wrapper that discards completions.
    #[must_use]
    pub const fn discard() -> Self {
        Self { inner: None }
    }

    /// Builds a reply wrapper and its receiving end.
    #[must_use]
    pub fn channel() -> (Self, oneshot::Receiver<Result<T, SessionError>>) {
        let (sender, receiver) = oneshot::channel();
        (
            Self {
                inner: Some(Arc::new(Mutex::new(Some(sender)))),
            },
            receiver,
        )
    }

    pub(super) fn complete(&self, result: Result<T, SessionError>) {
        let Some(inner) = &self.inner else {
            return;
        };
        let Ok(mut sender) = inner.lock() else {
            return;
        };
        if let Some(sender) = sender.take() {
            let _ = sender.send(result);
        }
    }
}

impl<T> Clone for CommandReply<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> fmt::Debug for CommandReply<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandReply")
            .field("expects_reply", &self.inner.is_some())
            .finish()
    }
}

impl<T> PartialEq for CommandReply<T> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<T> Eq for CommandReply<T> {}

impl<T> Hash for CommandReply<T> {
    fn hash<H: Hasher>(&self, _state: &mut H) {}
}

/// Breakpoint fire policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum BreakpointPolicy {
    /// Auto-remove after the first fire.
    #[default]
    OneShot,
    /// Persist and fire on each false-to-true transition.
    Repeatable,
}

/// What a firing breakpoint does at its deterministic boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BreakpointDisposition {
    /// Suspend the run.
    Suspend,
    /// Record a deterministic control-plane marker and keep running.
    Trace,
    /// Apply a bounded event-graph action at the firing boundary.
    Action(Action),
}

/// Actor-owned breakpoint specification.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BreakpointSpec {
    /// Shared 17a predicate vocabulary evaluated over the event log.
    pub predicate: Condition,
    /// Effect of a firing breakpoint.
    pub disposition: BreakpointDisposition,
    /// Whether the breakpoint persists after firing.
    pub policy: BreakpointPolicy,
}

impl BreakpointSpec {
    /// Builds a suspending one-shot breakpoint over a shared 17a predicate.
    #[must_use]
    pub fn suspend_once(predicate: Condition) -> Self {
        Self {
            predicate,
            disposition: BreakpointDisposition::Suspend,
            policy: BreakpointPolicy::OneShot,
        }
    }

    /// Builds a one-shot property-failure breakpoint.
    #[must_use]
    pub fn fail_once(predicate: Condition, reason: impl Into<String>) -> Self {
        Self {
            predicate,
            disposition: BreakpointDisposition::Action(Action::Fail {
                reason: reason.into(),
            }),
            policy: BreakpointPolicy::OneShot,
        }
    }
}

/// Checkpoint reference accepted by a fork command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointRef {
    /// Use the session's current boundary configuration.
    Current,
    /// Use a named temporal-graph checkpoint.
    Checkpoint(ContentHash),
}

/// Cloneable transport for an independently forked child session.
#[derive(Clone)]
pub struct SessionChildHandle {
    /// Command sender for the child session actor.
    pub sender: mpsc::Sender<SessionCommand>,
    /// Lock-free live mirror published by the child session actor.
    pub live: Arc<LiveSnapshot>,
}

impl fmt::Debug for SessionChildHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionChildHandle")
            .field("live", &self.live.read())
            .finish_non_exhaustive()
    }
}

/// Handle returned for a forked session request.
#[derive(Clone, Debug)]
pub struct SessionHandle {
    /// Deterministic handle id for the child session request.
    pub id: ContentHash,
    /// Checkpoint used as the fork base.
    pub checkpoint: ContentHash,
    /// Configuration denoted by the fork checkpoint.
    pub configuration: ContentHash,
    /// Live child transport when the command path spawned an actor.
    pub child: Option<SessionChildHandle>,
}

impl SessionHandle {
    pub(super) fn new(parent: ContentHash, checkpoint: &Checkpoint) -> Self {
        Self {
            id: fork_session_handle_id(parent, checkpoint.id),
            checkpoint: checkpoint.id,
            configuration: checkpoint.configuration,
            child: None,
        }
    }

    pub(super) fn with_child(mut self, child: SessionChildHandle) -> Self {
        self.child = Some(child);
        self
    }

    /// Returns the child actor command sender, when the fork command spawned one.
    #[must_use]
    pub fn child_sender(&self) -> Option<mpsc::Sender<SessionCommand>> {
        self.child.as_ref().map(|child| child.sender.clone())
    }

    /// Returns the child actor live mirror, when the fork command spawned one.
    #[must_use]
    pub fn child_live_snapshot(&self) -> Option<Arc<LiveSnapshot>> {
        self.child.as_ref().map(|child| Arc::clone(&child.live))
    }
}

impl PartialEq for SessionHandle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.checkpoint == other.checkpoint
            && self.configuration == other.configuration
    }
}

impl Eq for SessionHandle {}

impl Hash for SessionHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.checkpoint.hash(state);
        self.configuration.hash(state);
    }
}

/// Input supplied to a session actor's fork-loop factory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionForkRequest {
    /// Deterministic child session handle id.
    pub id: ContentHash,
    /// Checkpoint selected as the fork source.
    pub checkpoint: ContentHash,
    /// Recorded configuration denoted by `checkpoint`.
    pub configuration: ContentHash,
}

pub(super) type SessionForkLoopFactory<L> = Arc<dyn Fn(SessionForkRequest) -> L + Send + Sync>;

/// Information returned after materializing a savepoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SavepointInfo {
    /// Operator label carried by the savepoint command.
    pub label: String,
    /// Configuration that was materialized.
    pub configuration: ContentHash,
    /// Fat checkpoint returned by the temporal graph.
    pub checkpoint: Checkpoint,
}

/// Read-only query kind served through the actor.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum QueryKind {
    /// Return the complete boundary snapshot.
    Snapshot,
    /// Return the deterministic breakpoint-firing log.
    BreakpointFirings,
    /// Return the compact lifecycle state.
    State,
    /// Return the canonical event-log length.
    EventLogLength,
    /// Return scheduler-derived choices available at the current boundary.
    SearchFrontier,
    /// Return one deterministic execution-fingerprint sample for a node.
    ExecutionFingerprint {
        /// Node whose backend fingerprint should be sampled.
        node: NodeId,
    },
    /// Return the active stable operator-facing GDB endpoint, when attached.
    DebugOperatorEndpoint,
}

/// Result returned by a read-only query command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryResult {
    /// Complete boundary snapshot.
    Snapshot(Box<EngineSnapshot>),
    /// Deterministic breakpoint-firing log.
    BreakpointFirings(Vec<BreakpointFiring>),
    /// Compact lifecycle state.
    State(LifecycleStateKind),
    /// Canonical event-log length.
    EventLogLength(usize),
    /// Scheduler-derived choices available at the current boundary.
    SearchFrontier {
        /// Runtime RESOLVE frontiers captured in execution order.
        frontiers: Vec<crucible::SearchRuntimeFrontier>,
        /// Explorer-forced choices that have not reached their RESOLVE point.
        pending_branch_choices: usize,
    },
    /// Deterministic execution-fingerprint sample for one node.
    ExecutionFingerprint(FingerprintSample),
    /// Attached node and stable operator-facing GDB endpoint, or none before attach.
    DebugOperatorEndpoint(Option<(NodeId, DebugGdbEndpoint)>),
}

/// Read-only query kind served directly from the lock-free live snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveQueryKind {
    /// Return the complete atomic status view.
    Status,
    /// Return the compact lifecycle state.
    State,
    /// Return the canonical event-log length mirrored by the actor.
    EventLogLength,
}

/// Result returned by a lock-free live query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveQueryResult {
    /// Complete atomic status view.
    Status(LiveSnapshotView),
    /// Compact lifecycle state.
    State(LifecycleStateKind),
    /// Canonical event-log length mirrored by the actor.
    EventLogLength(u64),
}

/// A control command consumed by the session actor.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionCommand {
    /// Instantiate the loaded configuration.
    Start,
    /// Continue stepping bounded quanta.
    Continue,
    /// Pause at the current quantum boundary.
    Pause,
    /// Advance a bounded step and pause.
    Step {
        /// The requested bounded step mode.
        mode: StepMode,
    },
    /// Capture a boundary snapshot.
    Snapshot,
    /// Inject a deterministic control-plane fault at the next boundary.
    Inject,
    /// Add a predicate-based breakpoint.
    SetBreakpoint {
        /// Breakpoint predicate, disposition, and fire policy.
        spec: BreakpointSpec,
        /// Completion route returning the actor-owned breakpoint id.
        reply: CommandReply<BreakpointId>,
    },
    /// Remove a breakpoint by id.
    RemoveBreakpoint {
        /// Breakpoint id to remove.
        id: BreakpointId,
        /// Completion route returning whether a breakpoint was removed.
        reply: CommandReply<bool>,
    },
    /// Materialize the current configuration as a savepoint.
    CreateSavepoint {
        /// Stable operator label.
        label: String,
        /// Completion route returning the materialized savepoint handle.
        reply: CommandReply<SavepointInfo>,
    },
    /// Fork from a deterministic checkpoint or boundary.
    Fork {
        /// Fork source checkpoint.
        from: CheckpointRef,
        /// Completion route returning the child session handle.
        reply: CommandReply<SessionHandle>,
    },
    /// Transition to a terminal operator-stopped state.
    Stop,
    /// Transition to a terminal timeout after an observed budget is exhausted.
    ExhaustBudget,
    /// Read the current boundary state without mutation.
    Query {
        /// Query payload.
        kind: QueryKind,
        /// Completion route returning the query result.
        reply: CommandReply<QueryResult>,
    },
    /// Attach the debugger gdbstub to the current boundary.
    AttachGdb {
        /// Node whose backend gdbstub should be exposed.
        node: NodeId,
        /// Operator-facing gdb-protocol listener.
        listen: GdbListen,
        /// Optional source-world genesis used only when the ordinary lifecycle
        /// graph carries identity-only checkpoint material.
        debug_genesis: Option<Box<GenesisCheckpoint>>,
        /// Completion route returning the debug attach report.
        reply: CommandReply<DebugAttachReport>,
    },
    /// Move the attached debugger to another coordinate.
    DebugGoto {
        /// Restore-plus-replay request.
        request: DebugGotoRequest,
        /// Completion route returning the goto report.
        reply: CommandReply<DebugGotoReport>,
    },
    /// Reverse-step the attached debugger by one supported grain.
    DebugReverseStep {
        /// Reverse-step request.
        request: DebugReverseStepRequest,
        /// Completion route returning the reverse-step report.
        reply: CommandReply<DebugReverseStepReport>,
    },
    /// Reverse-continue the attached debugger to a prior matching prefix.
    DebugReverseContinue {
        /// Reverse-continue request.
        request: DebugReverseContinueRequest,
        /// Completion route returning the reverse-continue report.
        reply: CommandReply<DebugReverseContinueReport>,
    },
    /// Mark forward or mutating debugger use as a non-canonical debug branch.
    DebugForkNonCanonical {
        /// Non-canonical branch request with operator evidence.
        request: DebugNonCanonicalBranchRequest,
        /// Completion route returning the branch report.
        reply: CommandReply<DebugNonCanonicalBranchReport>,
    },
    /// Exchanges one bounded record with a node's debug guest agent.
    GuestIntrospection {
        /// Node whose guest agent owns the channel.
        node: NodeId,
        /// Opaque channel whose response is requested.
        channel_id: u64,
        /// Host request to send, or `None` to poll one available response.
        request: Option<GuestIntrospectionRecord>,
        /// Completion route returning one available guest response.
        reply: CommandReply<Option<GuestIntrospectionRecord>>,
    },
    /// Apply an inner command and acknowledge actor-level completion.
    Acknowledge {
        /// Inner command whose command kind, payload, and side effects are preserved.
        command: Box<SessionCommand>,
        /// Completion route for the actor-level acknowledgement.
        reply: CommandReply<()>,
    },
}

impl SessionCommand {
    /// Builds a discard-reply query for the complete boundary snapshot.
    #[must_use]
    pub fn query_snapshot() -> Self {
        Self::Query {
            kind: QueryKind::Snapshot,
            reply: CommandReply::discard(),
        }
    }

    /// Builds a discard-reply query for the deterministic breakpoint-firing log.
    #[must_use]
    pub fn query_breakpoint_firings() -> Self {
        Self::Query {
            kind: QueryKind::BreakpointFirings,
            reply: CommandReply::discard(),
        }
    }

    /// Builds a discard-reply fork request from the current boundary.
    #[must_use]
    pub fn fork_current() -> Self {
        Self::Fork {
            from: CheckpointRef::Current,
            reply: CommandReply::discard(),
        }
    }

    /// Builds a bounded [`SessionCommand::Step`] for the given step mode.
    ///
    /// Call sites that advance a session by a bounded step use this constructor
    /// instead of the struct-literal form so the debug CLI surface never issues
    /// raw step delegation directly.
    #[must_use]
    pub const fn step(mode: StepMode) -> Self {
        Self::Step { mode }
    }

    /// Wraps a command with an actor-level completion acknowledgement.
    #[must_use]
    pub fn acknowledged(command: Self, reply: CommandReply<()>) -> Self {
        Self::Acknowledge {
            command: Box::new(command),
            reply,
        }
    }

    /// Returns whether the command is observation-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.is_read_only(),
            Self::Query { .. }
            | Self::Snapshot
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. } => true,
            Self::Start
            | Self::Continue
            | Self::Pause
            | Self::Step { .. }
            | Self::Inject
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CreateSavepoint { .. }
            | Self::Fork { .. }
            | Self::Stop
            | Self::ExhaustBudget
            | Self::DebugForkNonCanonical { .. } => false,
            Self::GuestIntrospection { .. } => false,
        }
    }

    pub(super) const fn is_terminal_accepted(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.is_terminal_accepted(),
            Self::Snapshot | Self::Fork { .. } | Self::Query { .. } => true,
            Self::Start
            | Self::Continue
            | Self::Pause
            | Self::Step { .. }
            | Self::Inject
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CreateSavepoint { .. }
            | Self::Stop
            | Self::ExhaustBudget
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => false,
            Self::GuestIntrospection { .. } => false,
        }
    }

    pub(super) const fn is_control_acknowledged(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.is_control_acknowledged(),
            Self::Pause
            | Self::Snapshot
            | Self::Fork { .. }
            | Self::Inject
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CreateSavepoint { .. }
            | Self::Query { .. }
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => true,
            Self::GuestIntrospection { .. } => true,
            Self::Start | Self::Continue | Self::Step { .. } | Self::Stop | Self::ExhaustBudget => {
                false
            }
        }
    }

    pub(super) const fn requires_running_quantum_ack(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.requires_running_quantum_ack(),
            Self::Snapshot | Self::Query { .. } => true,
            Self::Start
            | Self::Continue
            | Self::Pause
            | Self::Step { .. }
            | Self::Inject
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CreateSavepoint { .. }
            | Self::Fork { .. }
            | Self::Stop
            | Self::ExhaustBudget
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => false,
            Self::GuestIntrospection { .. } => false,
        }
    }

    pub(super) const fn requires_non_canonical_debug_branch(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.requires_non_canonical_debug_branch(),
            Self::Continue
            | Self::Step { .. }
            | Self::Inject
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::GuestIntrospection { .. } => true,
            Self::Start
            | Self::Pause
            | Self::Snapshot
            | Self::CreateSavepoint { .. }
            | Self::Fork { .. }
            | Self::Stop
            | Self::ExhaustBudget
            | Self::Query { .. }
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => false,
        }
    }

    pub(super) fn complete_error(&self, error: SessionError) {
        match self {
            Self::SetBreakpoint { reply, .. } => reply.complete(Err(error)),
            Self::RemoveBreakpoint { reply, .. } => reply.complete(Err(error)),
            Self::CreateSavepoint { reply, .. } => reply.complete(Err(error)),
            Self::Fork { reply, .. } => reply.complete(Err(error)),
            Self::Query { reply, .. } => reply.complete(Err(error)),
            Self::AttachGdb { reply, .. } => reply.complete(Err(error)),
            Self::DebugGoto { reply, .. } => reply.complete(Err(error)),
            Self::DebugReverseStep { reply, .. } => reply.complete(Err(error)),
            Self::DebugReverseContinue { reply, .. } => reply.complete(Err(error)),
            Self::DebugForkNonCanonical { reply, .. } => reply.complete(Err(error)),
            Self::GuestIntrospection { reply, .. } => reply.complete(Err(error)),
            Self::Acknowledge { command, reply } => {
                command.complete_error(error.clone());
                reply.complete(Err(error));
            }
            Self::Start
            | Self::Continue
            | Self::Pause
            | Self::Step { .. }
            | Self::Stop
            | Self::ExhaustBudget => {}
            Self::Snapshot | Self::Inject => {}
        }
    }
}

/// Payload-free command kind used by the lifecycle transition model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionCommandKind {
    /// Instantiate the loaded configuration.
    Start,
    /// Continue a paused session.
    Continue,
    /// Pause a running or already-paused session.
    Pause,
    /// Execute a supported quantum step.
    StepQuantum,
    /// Execute an event-boundary step.
    StepEvent,
    /// Execute an assertion-boundary step.
    StepAssertion,
    /// Execute a timer-boundary step.
    StepTimer,
    /// Execute a virtual-duration step.
    StepDuration,
    /// Transition to a terminal operator-stopped state.
    Stop,
    /// Transition to a terminal timeout after budget exhaustion.
    ExhaustBudget,
    /// Inject legacy deterministic control.
    Inject,
    /// Add a predicate breakpoint.
    SetBreakpoint,
    /// Remove a predicate breakpoint.
    RemoveBreakpoint,
    /// Materialize a savepoint at a boundary.
    CreateSavepoint,
    /// Fork at a valid boundary.
    Fork,
    /// Query the session.
    Query,
    /// Capture a boundary snapshot through the current implementation shim.
    Snapshot,
    /// Attach an out-of-band debugger gdbstub.
    AttachGdb,
    /// Move an attached debugger to a coordinate.
    DebugGoto,
    /// Reverse-step an attached debugger.
    DebugReverseStep,
    /// Reverse-continue an attached debugger.
    DebugReverseContinue,
    /// Mark a non-canonical debug branch before forward or mutating debug use.
    DebugForkNonCanonical,
    /// Exchange a bounded request or response with a debug guest agent.
    GuestIntrospection,
}

impl SessionCommandKind {
    /// The lifecycle command-kind set.
    ///
    /// This covers the RFC §4 command surface plus the current implementation's
    /// legacy `Inject` and boundary `Snapshot` shims. T-SESS-4 replaces those
    /// shims with the reply-carrying command payloads.
    pub const ALL: [Self; 23] = [
        Self::Start,
        Self::Continue,
        Self::Pause,
        Self::StepQuantum,
        Self::StepEvent,
        Self::StepAssertion,
        Self::StepTimer,
        Self::StepDuration,
        Self::Stop,
        Self::ExhaustBudget,
        Self::Inject,
        Self::SetBreakpoint,
        Self::RemoveBreakpoint,
        Self::CreateSavepoint,
        Self::Fork,
        Self::Query,
        Self::Snapshot,
        Self::AttachGdb,
        Self::DebugGoto,
        Self::DebugReverseStep,
        Self::DebugReverseContinue,
        Self::DebugForkNonCanonical,
        Self::GuestIntrospection,
    ];

    pub(super) const fn operation_name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Continue => "continue",
            Self::Pause => "pause",
            Self::StepQuantum => "step-quantum",
            Self::StepEvent => "step-event",
            Self::StepAssertion => "step-assertion",
            Self::StepTimer => "step-timer",
            Self::StepDuration => "step-duration",
            Self::Stop => "stop",
            Self::ExhaustBudget => "exhaust-budget",
            Self::Inject => "inject",
            Self::SetBreakpoint => "set-breakpoint",
            Self::RemoveBreakpoint => "remove-breakpoint",
            Self::CreateSavepoint => "create-savepoint",
            Self::Fork => "fork",
            Self::Query => "query",
            Self::Snapshot => "snapshot",
            Self::AttachGdb => "attach-gdb",
            Self::DebugGoto => "debug-goto",
            Self::DebugReverseStep => "debug-reverse-step",
            Self::DebugReverseContinue => "debug-reverse-continue",
            Self::DebugForkNonCanonical => "debug-fork-non-canonical",
            Self::GuestIntrospection => "guest-introspection",
        }
    }

    /// Returns a representative engine command for kinds implemented by the
    /// current [`SessionCommand`] enum.
    ///
    /// The representative carries discard replies for reply-bearing commands so
    /// lifecycle tests can exercise the actor command mapping without awaiting a
    /// caller channel.
    #[must_use]
    pub fn representative_command(self) -> Option<SessionCommand> {
        let command = match self {
            Self::Start => SessionCommand::Start,
            Self::Continue => SessionCommand::Continue,
            Self::Pause => SessionCommand::Pause,
            Self::StepQuantum => SessionCommand::Step {
                mode: StepMode::Quantum,
            },
            Self::StepEvent => SessionCommand::Step {
                mode: StepMode::Event,
            },
            Self::StepAssertion => SessionCommand::Step {
                mode: StepMode::Assertion,
            },
            Self::StepTimer => SessionCommand::Step {
                mode: StepMode::Timer,
            },
            Self::StepDuration => SessionCommand::Step {
                mode: StepMode::Duration(StepMode::DEFAULT_DURATION),
            },
            Self::Stop => SessionCommand::Stop,
            Self::ExhaustBudget => SessionCommand::ExhaustBudget,
            Self::Inject => SessionCommand::Inject,
            Self::SetBreakpoint => SessionCommand::SetBreakpoint {
                spec: BreakpointSpec::suspend_once(Condition::Quiescent),
                reply: CommandReply::discard(),
            },
            Self::RemoveBreakpoint => SessionCommand::RemoveBreakpoint {
                id: 1,
                reply: CommandReply::discard(),
            },
            Self::CreateSavepoint => SessionCommand::CreateSavepoint {
                label: String::from("lifecycle-model"),
                reply: CommandReply::discard(),
            },
            Self::Fork => SessionCommand::fork_current(),
            Self::Query => SessionCommand::query_snapshot(),
            Self::Snapshot => SessionCommand::Snapshot,
            Self::AttachGdb
            | Self::DebugGoto
            | Self::DebugReverseStep
            | Self::DebugReverseContinue
            | Self::DebugForkNonCanonical => return None,
            Self::GuestIntrospection => return None,
        };
        Some(command)
    }
}

/// Pure lifecycle-model decision for one `(state, command)` pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LifecycleTransition {
    /// The command is accepted and moves, or remains in, a lifecycle state.
    Accepted {
        /// Lifecycle state after applying the command.
        to: LifecycleStateKind,
    },
    /// The command is rejected and leaves the lifecycle state unchanged.
    Rejected,
}

/// Evaluates the total lifecycle transition table for command kinds.
#[must_use]
pub const fn lifecycle_transition(
    state: LifecycleStateKind,
    command: SessionCommandKind,
) -> LifecycleTransition {
    use LifecycleStateKind as State;
    use LifecycleTransition::{Accepted, Rejected};
    use SessionCommandKind as Command;

    match (state, command) {
        (State::Loaded, Command::Start) => Accepted { to: State::Paused },
        (
            State::Loaded,
            Command::SetBreakpoint | Command::RemoveBreakpoint | Command::Query | Command::Snapshot,
        ) => Accepted { to: State::Loaded },
        (State::Loaded, Command::Stop | Command::ExhaustBudget) => Accepted { to: State::Stopped },
        (
            State::Loaded,
            Command::Continue
            | Command::Pause
            | Command::StepQuantum
            | Command::StepEvent
            | Command::StepAssertion
            | Command::StepTimer
            | Command::StepDuration
            | Command::Inject
            | Command::CreateSavepoint
            | Command::Fork
            | Command::AttachGdb
            | Command::DebugGoto
            | Command::DebugReverseStep
            | Command::DebugReverseContinue
            | Command::DebugForkNonCanonical
            | Command::GuestIntrospection,
        ) => Rejected,

        (
            State::Running,
            Command::StepQuantum
            | Command::StepEvent
            | Command::StepAssertion
            | Command::StepTimer
            | Command::StepDuration,
        ) => Accepted { to: State::Running },
        (State::Running, Command::Pause) => Accepted { to: State::Paused },
        (
            State::Paused,
            Command::Continue
            | Command::StepQuantum
            | Command::StepEvent
            | Command::StepAssertion
            | Command::StepTimer
            | Command::StepDuration,
        ) => Accepted { to: State::Running },
        (
            State::Paused,
            Command::Pause
            | Command::Snapshot
            | Command::Fork
            | Command::Inject
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Query
            | Command::AttachGdb
            | Command::DebugGoto
            | Command::DebugReverseStep
            | Command::DebugReverseContinue
            | Command::DebugForkNonCanonical
            | Command::GuestIntrospection,
        ) => Accepted { to: State::Paused },
        (State::Running, Command::GuestIntrospection) => Accepted { to: State::Running },
        (State::Running, Command::Stop | Command::ExhaustBudget) => Accepted { to: State::Stopped },
        (
            State::Running,
            Command::AttachGdb
            | Command::DebugGoto
            | Command::DebugReverseStep
            | Command::DebugReverseContinue
            | Command::DebugForkNonCanonical,
        ) => Accepted { to: State::Paused },
        (
            State::Running,
            Command::Snapshot
            | Command::Inject
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Query,
        ) => Accepted { to: State::Running },
        (State::Running, Command::Fork) => Accepted { to: State::Paused },
        (State::Running, Command::Start | Command::Continue) => Rejected,

        (State::Paused, Command::Stop | Command::ExhaustBudget) => Accepted { to: State::Stopped },
        (State::Paused, Command::Start) => Rejected,

        (State::Stopped, Command::Snapshot | Command::Fork | Command::Query) => {
            Accepted { to: State::Stopped }
        }
        (
            State::Stopped,
            Command::Start
            | Command::Continue
            | Command::Pause
            | Command::StepQuantum
            | Command::StepEvent
            | Command::StepAssertion
            | Command::StepTimer
            | Command::StepDuration
            | Command::Inject
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Stop
            | Command::ExhaustBudget
            | Command::AttachGdb
            | Command::DebugGoto
            | Command::DebugReverseStep
            | Command::DebugReverseContinue
            | Command::DebugForkNonCanonical
            | Command::GuestIntrospection,
        ) => Rejected,
    }
}
#[path = "commands/kind_conversion.rs"]
mod kind_conversion;
