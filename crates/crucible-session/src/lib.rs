//! `crucible-session` owns the live session actor.
//!
//! Spec index: RFC-0010 files 20.
//!
//! This L4 crate will drive one live runtime state, accept control requests at
//! quantum boundaries, and expose the session semantics specified by RFC-0010
//! file 20. It contains no raw QEMU or shared-memory access.
//!
//! Module map: the crate root owns [`SessionDriver`], the thin L4 adapter over
//! the engine [`QuantumLoop`], plus the initial [`Engine`] and [`SessionActor`]
//! state-machine surface.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    Action, Checkpoint, Condition, Configuration, ContentHash, ControlOperation,
    ControlOperationKind, DebugReverseStepGrain, Decision, EngineError, Fault, FaultTag,
    QuantumLoop, QuantumOutcome, QuantumRequest, RuntimeState, Schedule, SchedulerError,
    SchedulerEventLogEntry, TemporalGraph, VirtualTime, instantiate,
};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;

/// Number of live event-log frames retained by the broadcast tail.
pub const SESSION_EVENT_LOG_BROADCAST_CAPACITY: usize = 1024;

/// Maximum number of retained event-log frames cloned by one stream receive.
pub const SESSION_EVENT_LOG_REPLAY_BATCH_SIZE: usize = 64;

/// Default mailbox capacity for a newly forked child session actor.
pub const SESSION_FORK_MAILBOX_CAPACITY: usize = 8;

/// Drives the engine quantum loop from the L4 session boundary.
///
/// `SessionDriver` is deliberately thin: it owns no backend advancement API and
/// delegates every unit of virtual-time progress to the L3 [`QuantumLoop`].
pub struct SessionDriver<L> {
    quantum_loop: L,
}

impl<L> SessionDriver<L> {
    /// Creates a session driver around an engine quantum loop.
    #[must_use]
    pub fn new(quantum_loop: L) -> Self {
        Self { quantum_loop }
    }

    /// Returns the wrapped quantum loop.
    #[must_use]
    pub fn into_inner(self) -> L {
        self.quantum_loop
    }
}

impl<L: QuantumLoop> SessionDriver<L> {
    /// Drives exactly one engine quantum through the L3 scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the engine quantum loop rejects the
    /// request or cannot complete the quantum.
    pub fn drive_quantum(
        &mut self,
        request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.quantum_loop.drive_quantum(request)
    }
}

/// Explicit run state for the Crucible engine.
///
/// The closed state set is the control-plane contract from RFC-0010 §10:
/// configuration loaded, actively running bounded quanta, paused at a quantum
/// boundary, or terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineState {
    /// Configuration is loaded, but no runtime has been instantiated yet.
    Loaded,
    /// The actor is actively stepping the scheduler in bounded quanta.
    Running,
    /// The engine is idle at a quantum boundary.
    Paused {
        /// The resumable cause that stopped execution.
        reason: PauseReason,
    },
    /// The engine reached a terminal state.
    Stopped {
        /// The final run outcome.
        outcome: Outcome,
    },
}

/// Compact run-state kind stored in the lock-free live snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LiveStateKind {
    /// Configuration is loaded, but no runtime has been instantiated yet.
    Loaded = 1,
    /// The actor is actively stepping bounded scheduler quanta.
    Running = 2,
    /// The engine is idle at a quantum boundary.
    Paused = 3,
    /// The engine reached a terminal state.
    Stopped = 4,
}

impl LiveStateKind {
    fn from_engine_state(state: &EngineState) -> Self {
        match state {
            EngineState::Loaded => Self::Loaded,
            EngineState::Running => Self::Running,
            EngineState::Paused { .. } => Self::Paused,
            EngineState::Stopped { .. } => Self::Stopped,
        }
    }

    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Loaded,
            2 => Self::Running,
            3 => Self::Paused,
            _ => Self::Stopped,
        }
    }
}

/// Closed run-state kind used by the lifecycle transition model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LifecycleStateKind {
    /// Configuration is loaded, but no runtime has been instantiated yet.
    Loaded,
    /// The actor is actively stepping bounded scheduler quanta.
    Running,
    /// The actor is idle at a quantum boundary.
    Paused,
    /// The actor reached a terminal state.
    Stopped,
}

impl LifecycleStateKind {
    /// The closed lifecycle state set.
    pub const ALL: [Self; 4] = [Self::Loaded, Self::Running, Self::Paused, Self::Stopped];
}

impl From<&EngineState> for LifecycleStateKind {
    fn from(state: &EngineState) -> Self {
        match state {
            EngineState::Loaded => Self::Loaded,
            EngineState::Running => Self::Running,
            EngineState::Paused { .. } => Self::Paused,
            EngineState::Stopped { .. } => Self::Stopped,
        }
    }
}

/// Why a session paused at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PauseReason {
    /// The runtime was just instantiated.
    Instantiated,
    /// A user control command requested the pause.
    UserRequested,
    /// A breakpoint suspended the run.
    Breakpoint {
        /// The breakpoint identifier.
        id: u64,
    },
    /// A bounded step command completed.
    StepComplete {
        /// The completed step mode.
        mode: StepMode,
    },
}

/// Closed pause-reason kind set used by lifecycle model checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PauseReasonKind {
    /// Runtime was instantiated.
    Instantiated,
    /// User requested a pause.
    UserRequested,
    /// Breakpoint suspended the run.
    Breakpoint,
    /// Bounded step completed.
    StepComplete,
}

impl PauseReasonKind {
    /// The closed pause-reason vocabulary.
    pub const ALL: [Self; 4] = [
        Self::Instantiated,
        Self::UserRequested,
        Self::Breakpoint,
        Self::StepComplete,
    ];
}

impl From<&PauseReason> for PauseReasonKind {
    fn from(reason: &PauseReason) -> Self {
        match reason {
            PauseReason::Instantiated => Self::Instantiated,
            PauseReason::UserRequested => Self::UserRequested,
            PauseReason::Breakpoint { .. } => Self::Breakpoint,
            PauseReason::StepComplete { .. } => Self::StepComplete,
        }
    }
}

/// Actor-owned breakpoint registry for a live session.
///
/// This type is intentionally only a registry at the T-SESS-1 layer. Later
/// command tasks define how breakpoint specifications are added, removed, and
/// evaluated at deterministic event-log boundaries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BreakpointSet {
    specs: BTreeMap<BreakpointId, BreakpointSpec>,
    next_id: BreakpointId,
}

impl BreakpointSet {
    /// Creates an empty breakpoint set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether the set contains no breakpoints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Returns the number of actor-owned breakpoint handles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// Registers a breakpoint specification and returns its actor-owned handle.
    pub fn insert(&mut self, spec: BreakpointSpec) -> BreakpointId {
        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        self.specs.insert(id, spec);
        id
    }

    /// Removes a breakpoint by id and reports whether it was present.
    pub fn remove(&mut self, id: BreakpointId) -> bool {
        self.specs.remove(&id).is_some()
    }

    /// Returns the breakpoint specification for `id`, when present.
    #[must_use]
    pub fn get(&self, id: BreakpointId) -> Option<&BreakpointSpec> {
        self.specs.get(&id)
    }
}

/// Terminal outcome for an engine run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The run completed successfully.
    Passed,
    /// One or more properties failed.
    Failed {
        /// Deterministic violation identifiers or messages.
        violations: Vec<String>,
    },
    /// The run hit its configured budget.
    Timeout,
    /// The backend crashed outside the modeled fault vocabulary.
    Crashed {
        /// Deterministic crash detail.
        detail: String,
    },
    /// The operator stopped the run.
    Stopped,
}

/// Closed terminal-outcome kind set used by lifecycle model checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutcomeKind {
    /// Run completed successfully.
    Passed,
    /// One or more properties failed.
    Failed,
    /// Run hit its configured budget.
    Timeout,
    /// Backend crashed outside modeled faults.
    Crashed,
    /// Operator stopped the run.
    Stopped,
}

impl OutcomeKind {
    /// The closed terminal-outcome vocabulary.
    pub const ALL: [Self; 5] = [
        Self::Passed,
        Self::Failed,
        Self::Timeout,
        Self::Crashed,
        Self::Stopped,
    ];
}

impl From<&Outcome> for OutcomeKind {
    fn from(outcome: &Outcome) -> Self {
        match outcome {
            Outcome::Passed => Self::Passed,
            Outcome::Failed { .. } => Self::Failed,
            Outcome::Timeout => Self::Timeout,
            Outcome::Crashed { .. } => Self::Crashed,
            Outcome::Stopped => Self::Stopped,
        }
    }
}

/// A bounded step mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepMode {
    /// Advance to the next instruction-scale coordinate.
    Instruction,
    /// Advance exactly one scheduler quantum.
    Quantum,
    /// Advance to the next scheduler event coordinate.
    Event,
    /// Advance to the next assertion-state coordinate.
    Assertion,
    /// Advance to the next timer coordinate.
    Timer,
}

impl StepMode {
    /// The closed forward step-mode set mirrored by debug reverse-step.
    pub const ALL: [Self; 5] = [
        Self::Instruction,
        Self::Quantum,
        Self::Event,
        Self::Assertion,
        Self::Timer,
    ];

    /// Returns the reverse-step grain that mirrors this forward mode.
    #[must_use]
    pub const fn reverse_grain(self) -> DebugReverseStepGrain {
        match self {
            Self::Instruction => DebugReverseStepGrain::Instruction,
            Self::Quantum => DebugReverseStepGrain::Quantum,
            Self::Event => DebugReverseStepGrain::Event,
            Self::Assertion => DebugReverseStepGrain::Assertion,
            Self::Timer => DebugReverseStepGrain::Timer,
        }
    }
}

/// Actor-local breakpoint identifier.
pub type BreakpointId = u64;

/// Reply channel carried by commands that return data to their caller.
///
/// The reply transport is deliberately not part of command equality or hashing:
/// it routes completion back to the caller, but it is not model state.
pub struct CommandReply<T> {
    inner: Option<Arc<Mutex<Option<oneshot::Sender<Result<T, SessionError>>>>>>,
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

    fn complete(&self, result: Result<T, SessionError>) {
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

/// Fault injection request payload for the RFC §4 command set.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FaultSpec {
    /// Stable handle used for later healing.
    pub tag: FaultTag,
    /// Full fault taxonomy value to activate.
    pub fault: Fault,
}

impl FaultSpec {
    /// Creates a typed fault-control payload.
    #[must_use]
    pub fn new(tag: FaultTag, fault: Fault) -> Self {
        Self { tag, fault }
    }
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
    /// Emit an observational marker and keep running.
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
}

/// Checkpoint reference accepted by a fork command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointRef {
    /// Use the session's current boundary configuration.
    Current,
    /// Use a named temporal-graph checkpoint.
    Checkpoint(ContentHash),
}

/// Handle returned for a forked session request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionHandle {
    /// Deterministic handle id for the child session request.
    pub id: ContentHash,
    /// Checkpoint used as the fork base.
    pub checkpoint: ContentHash,
}

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryKind {
    /// Return the complete boundary snapshot.
    Snapshot,
    /// Return the compact lifecycle state.
    State,
    /// Return the canonical event-log length.
    EventLogLength,
}

/// Result returned by a read-only query command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryResult {
    /// Complete boundary snapshot.
    Snapshot(EngineSnapshot),
    /// Compact lifecycle state.
    State(LifecycleStateKind),
    /// Canonical event-log length.
    EventLogLength(usize),
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
    /// Inject or replace a full-taxonomy fault at the next boundary.
    InjectFault {
        /// Fault activation payload.
        spec: FaultSpec,
        /// Completion route returning the stable fault tag.
        reply: CommandReply<FaultTag>,
    },
    /// Heal a full-taxonomy fault at the next boundary.
    HealFault {
        /// Stable handle naming the active fault.
        tag: FaultTag,
        /// Completion route for the heal acknowledgement.
        reply: CommandReply<()>,
    },
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
    /// Read the current boundary state without mutation.
    Query {
        /// Query payload.
        kind: QueryKind,
        /// Completion route returning the query result.
        reply: CommandReply<QueryResult>,
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

    /// Builds a discard-reply fork request from the current boundary.
    #[must_use]
    pub fn fork_current() -> Self {
        Self::Fork {
            from: CheckpointRef::Current,
            reply: CommandReply::discard(),
        }
    }

    /// Builds a discard-reply typed fault-injection command.
    #[must_use]
    pub fn inject_fault(tag: FaultTag, fault: Fault) -> Self {
        Self::InjectFault {
            spec: FaultSpec::new(tag, fault),
            reply: CommandReply::discard(),
        }
    }

    /// Builds a discard-reply typed fault-heal command.
    #[must_use]
    pub fn heal_fault(tag: FaultTag) -> Self {
        Self::HealFault {
            tag,
            reply: CommandReply::discard(),
        }
    }

    /// Returns whether the command is observation-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Self::Query { .. } | Self::Snapshot)
    }

    const fn is_terminal_accepted(&self) -> bool {
        matches!(
            self,
            Self::Snapshot
                | Self::Fork { .. }
                | Self::SetBreakpoint { .. }
                | Self::RemoveBreakpoint { .. }
                | Self::Query { .. }
        )
    }

    const fn is_control_acknowledged(&self) -> bool {
        matches!(
            self,
            Self::Pause
                | Self::Snapshot
                | Self::Fork { .. }
                | Self::Inject
                | Self::InjectFault { .. }
                | Self::HealFault { .. }
                | Self::SetBreakpoint { .. }
                | Self::RemoveBreakpoint { .. }
                | Self::CreateSavepoint { .. }
                | Self::Query { .. }
        )
    }

    const fn requires_running_quantum_ack(&self) -> bool {
        matches!(
            self,
            Self::Snapshot
                | Self::Inject
                | Self::InjectFault { .. }
                | Self::HealFault { .. }
                | Self::Query { .. }
        )
    }

    fn complete_error(&self, error: SessionError) {
        match self {
            Self::InjectFault { reply, .. } => reply.complete(Err(error)),
            Self::HealFault { reply, .. } => reply.complete(Err(error)),
            Self::SetBreakpoint { reply, .. } => reply.complete(Err(error)),
            Self::RemoveBreakpoint { reply, .. } => reply.complete(Err(error)),
            Self::CreateSavepoint { reply, .. } => reply.complete(Err(error)),
            Self::Fork { reply, .. } => reply.complete(Err(error)),
            Self::Query { reply, .. } => reply.complete(Err(error)),
            Self::Start | Self::Continue | Self::Pause | Self::Step { .. } | Self::Stop => {}
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
    /// Execute a step mode whose executor is intentionally pending.
    StepUnsupported,
    /// Transition to a terminal operator-stopped state.
    Stop,
    /// Inject legacy deterministic control.
    Inject,
    /// Inject a typed fault.
    InjectFault,
    /// Heal a typed fault.
    HealFault,
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
}

impl SessionCommandKind {
    /// The lifecycle command-kind set.
    ///
    /// This covers the RFC §4 command surface plus the current implementation's
    /// legacy `Inject` and boundary `Snapshot` shims. T-SESS-4 replaces those
    /// shims with the reply-carrying command payloads.
    pub const ALL: [Self; 15] = [
        Self::Start,
        Self::Continue,
        Self::Pause,
        Self::StepQuantum,
        Self::StepUnsupported,
        Self::Stop,
        Self::Inject,
        Self::InjectFault,
        Self::HealFault,
        Self::SetBreakpoint,
        Self::RemoveBreakpoint,
        Self::CreateSavepoint,
        Self::Fork,
        Self::Query,
        Self::Snapshot,
    ];

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
            Self::StepUnsupported => SessionCommand::Step {
                mode: StepMode::Instruction,
            },
            Self::Stop => SessionCommand::Stop,
            Self::Inject => SessionCommand::Inject,
            Self::InjectFault => SessionCommand::InjectFault {
                spec: FaultSpec::new(
                    FaultTag::from_name("lifecycle-model"),
                    Fault::Node(crucible::NodeFault::Crash {
                        node: crucible::NodeId {
                            name: String::from("node-a"),
                        },
                        restart: crucible::RestartPolicy::StayDown,
                    }),
                ),
                reply: CommandReply::discard(),
            },
            Self::HealFault => SessionCommand::heal_fault(FaultTag::from_name("lifecycle-model")),
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
        };
        Some(command)
    }
}

impl From<&SessionCommand> for SessionCommandKind {
    fn from(command: &SessionCommand) -> Self {
        match command {
            SessionCommand::Start => Self::Start,
            SessionCommand::Continue => Self::Continue,
            SessionCommand::Pause => Self::Pause,
            SessionCommand::Step {
                mode: StepMode::Quantum,
            } => Self::StepQuantum,
            SessionCommand::Step { .. } => Self::StepUnsupported,
            SessionCommand::Snapshot => Self::Snapshot,
            SessionCommand::Fork { .. } => Self::Fork,
            SessionCommand::Inject => Self::Inject,
            SessionCommand::InjectFault { .. } => Self::InjectFault,
            SessionCommand::HealFault { .. } => Self::HealFault,
            SessionCommand::SetBreakpoint { .. } => Self::SetBreakpoint,
            SessionCommand::RemoveBreakpoint { .. } => Self::RemoveBreakpoint,
            SessionCommand::CreateSavepoint { .. } => Self::CreateSavepoint,
            SessionCommand::Stop => Self::Stop,
            SessionCommand::Query { .. } => Self::Query,
        }
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
        (State::Loaded, Command::Stop) => Accepted { to: State::Stopped },
        (
            State::Loaded,
            Command::Continue
            | Command::Pause
            | Command::StepQuantum
            | Command::StepUnsupported
            | Command::Inject
            | Command::InjectFault
            | Command::HealFault
            | Command::CreateSavepoint
            | Command::Fork,
        ) => Rejected,

        (State::Running, Command::Pause | Command::StepQuantum) => Accepted { to: State::Paused },
        (State::Running, Command::Stop) => Accepted { to: State::Stopped },
        (
            State::Running,
            Command::Snapshot
            | Command::Inject
            | Command::InjectFault
            | Command::HealFault
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Query,
        ) => Accepted { to: State::Running },
        (
            State::Running,
            Command::Start | Command::Continue | Command::StepUnsupported | Command::Fork,
        ) => Rejected,

        (State::Paused, Command::Continue) => Accepted { to: State::Running },
        (
            State::Paused,
            Command::Pause
            | Command::StepQuantum
            | Command::Snapshot
            | Command::Fork
            | Command::Inject
            | Command::InjectFault
            | Command::HealFault
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Query,
        ) => Accepted { to: State::Paused },
        (State::Paused, Command::Stop) => Accepted { to: State::Stopped },
        (State::Paused, Command::Start | Command::StepUnsupported) => Rejected,

        (
            State::Stopped,
            Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::Snapshot
            | Command::Fork
            | Command::Query,
        ) => Accepted { to: State::Stopped },
        (
            State::Stopped,
            Command::Start
            | Command::Continue
            | Command::Pause
            | Command::StepQuantum
            | Command::StepUnsupported
            | Command::Inject
            | Command::InjectFault
            | Command::HealFault
            | Command::CreateSavepoint
            | Command::Stop,
        ) => Rejected,
    }
}

/// Maximum lifecycle acknowledgement latency accepted for exploration drivers.
pub const EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA: u64 = 1;

/// Default actor-yield budget for lifecycle command acknowledgement polling.
pub const EXPLORATION_LIFECYCLE_MAX_ACTOR_YIELDS: u64 = 128;

/// A lifecycle command issued by an exploration driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExplorationLifecycleCommand {
    /// Pause the running branch at the next quantum boundary.
    Pause,
    /// Continue a branch paused at a quantum boundary.
    Resume,
    /// Stop the branch cleanly at a quantum boundary.
    Stop,
}

/// Evidence that an exploration lifecycle command was acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExplorationLifecycleAcknowledgement {
    /// Lifecycle command that was issued.
    pub command: ExplorationLifecycleCommand,
    /// Live state observed before the command was sent.
    pub requested_state: LiveStateKind,
    /// Live state observed when the command was acknowledged.
    pub acknowledged_state: LiveStateKind,
    /// Scheduler quantum count visible before the command was sent.
    pub requested_at_quantum: u64,
    /// Scheduler quantum count visible when the command was acknowledged.
    pub acknowledged_at_quantum: u64,
    /// Canonical event-log length visible before the command was sent.
    pub requested_event_log_len: u64,
    /// Canonical event-log length visible when the command was acknowledged.
    pub acknowledged_event_log_len: u64,
}

impl ExplorationLifecycleAcknowledgement {
    /// Returns the acknowledgement latency measured in scheduler quanta.
    #[must_use]
    pub fn acknowledgement_delta_quanta(&self) -> Option<u64> {
        self.acknowledged_at_quantum
            .checked_sub(self.requested_at_quantum)
    }
}

/// Error returned by [`ExplorationLifecycleDriver`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExplorationLifecycleError {
    /// The command was issued against a state where it is not valid.
    #[error("exploration lifecycle command {command:?} was issued against {requested_state:?}")]
    InvalidState {
        /// Lifecycle command that was issued.
        command: ExplorationLifecycleCommand,
        /// State observed before issuing the command.
        requested_state: LiveStateKind,
    },
    /// The session command channel closed before the command was accepted.
    #[error("exploration lifecycle command {command:?} could not be sent")]
    CommandChannelClosed {
        /// Lifecycle command whose session message could not be sent.
        command: ExplorationLifecycleCommand,
    },
    /// The command was not acknowledged within the actor-yield budget.
    #[error(
        "exploration lifecycle command {command:?} was not acknowledged after {max_actor_yields} actor yields"
    )]
    AcknowledgementTimeout {
        /// Lifecycle command that timed out.
        command: ExplorationLifecycleCommand,
        /// Scheduler quantum count visible before issuing the command.
        requested_at_quantum: u64,
        /// Actor-yield budget used while waiting.
        max_actor_yields: u64,
    },
    /// The command acknowledgement exceeded the accepted quantum bound.
    #[error(
        "exploration lifecycle command {command:?} took {observed_delta_quanta} quanta, exceeding bound {bound_quanta}"
    )]
    AcknowledgementExceededBound {
        /// Lifecycle command whose acknowledgement exceeded the bound.
        command: ExplorationLifecycleCommand,
        /// Observed acknowledgement latency in scheduler quanta.
        observed_delta_quanta: u64,
        /// Accepted acknowledgement bound in scheduler quanta.
        bound_quanta: u64,
    },
}

/// Session-command lifecycle adapter used by exploration drivers.
///
/// This driver deliberately owns only a session mailbox sender and a lock-free
/// [`LiveSnapshot`]. Search and fuzz drivers using this type can pause, resume,
/// and stop a branch without direct access to the engine, scheduler, or backend.
#[derive(Clone)]
pub struct ExplorationLifecycleDriver {
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    max_actor_yields: u64,
    bound_quanta: u64,
}

impl ExplorationLifecycleDriver {
    /// Creates a lifecycle driver over a session actor mailbox.
    #[must_use]
    pub fn new(sender: mpsc::Sender<SessionCommand>, live: Arc<LiveSnapshot>) -> Self {
        Self {
            sender,
            live,
            max_actor_yields: EXPLORATION_LIFECYCLE_MAX_ACTOR_YIELDS,
            bound_quanta: EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA,
        }
    }

    /// Returns a copy of this driver with an explicit actor-yield wait budget.
    #[must_use]
    pub fn with_max_actor_yields(mut self, max_actor_yields: u64) -> Self {
        self.max_actor_yields = max_actor_yields;
        self
    }

    /// Returns a copy of this driver with an explicit quantum response bound.
    #[must_use]
    pub fn with_bound_quanta(mut self, bound_quanta: u64) -> Self {
        self.bound_quanta = bound_quanta;
        self
    }

    /// Pauses a running exploration branch at the next quantum boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ExplorationLifecycleError`] when the session is not running,
    /// the actor mailbox closes, or the pause does not take effect within the
    /// configured quantum/yield bounds.
    pub async fn pause(
        &self,
    ) -> Result<ExplorationLifecycleAcknowledgement, ExplorationLifecycleError> {
        self.issue(
            ExplorationLifecycleCommand::Pause,
            SessionCommand::Pause,
            LiveStateKind::Running,
            LiveStateKind::Paused,
        )
        .await
    }

    /// Resumes a paused exploration branch.
    ///
    /// # Errors
    ///
    /// Returns [`ExplorationLifecycleError`] when the session is not paused, the
    /// actor mailbox closes, or resume is not acknowledged within the configured
    /// quantum/yield bounds.
    pub async fn resume(
        &self,
    ) -> Result<ExplorationLifecycleAcknowledgement, ExplorationLifecycleError> {
        self.issue(
            ExplorationLifecycleCommand::Resume,
            SessionCommand::Continue,
            LiveStateKind::Paused,
            LiveStateKind::Running,
        )
        .await
    }

    /// Stops an exploration branch cleanly.
    ///
    /// # Errors
    ///
    /// Returns [`ExplorationLifecycleError`] when the session is loaded or
    /// already stopped, the actor mailbox closes, or stop is not acknowledged
    /// within the configured quantum/yield bounds.
    pub async fn stop(
        &self,
    ) -> Result<ExplorationLifecycleAcknowledgement, ExplorationLifecycleError> {
        let before = self.live.read();
        if !matches!(
            before.state_kind,
            LiveStateKind::Running | LiveStateKind::Paused
        ) {
            return Err(ExplorationLifecycleError::InvalidState {
                command: ExplorationLifecycleCommand::Stop,
                requested_state: before.state_kind,
            });
        }
        self.issue_from(
            ExplorationLifecycleCommand::Stop,
            SessionCommand::Stop,
            before,
            LiveStateKind::Stopped,
        )
        .await
    }

    async fn issue(
        &self,
        command: ExplorationLifecycleCommand,
        session_command: SessionCommand,
        required_state: LiveStateKind,
        acknowledged_state: LiveStateKind,
    ) -> Result<ExplorationLifecycleAcknowledgement, ExplorationLifecycleError> {
        let before = self.live.read();
        if before.state_kind != required_state {
            return Err(ExplorationLifecycleError::InvalidState {
                command,
                requested_state: before.state_kind,
            });
        }
        self.issue_from(command, session_command, before, acknowledged_state)
            .await
    }

    async fn issue_from(
        &self,
        command: ExplorationLifecycleCommand,
        session_command: SessionCommand,
        before: LiveSnapshotView,
        acknowledged_state: LiveStateKind,
    ) -> Result<ExplorationLifecycleAcknowledgement, ExplorationLifecycleError> {
        self.sender
            .send(session_command)
            .await
            .map_err(|_| ExplorationLifecycleError::CommandChannelClosed { command })?;

        for _ in 0..self.max_actor_yields {
            tokio::task::yield_now().await;
            let after = self.live.read();
            if after.state_kind == acknowledged_state {
                let acknowledgement =
                    lifecycle_acknowledgement(command, before, after, acknowledged_state);
                let Some(delta) = acknowledgement.acknowledgement_delta_quanta() else {
                    return Err(ExplorationLifecycleError::AcknowledgementExceededBound {
                        command,
                        observed_delta_quanta: u64::MAX,
                        bound_quanta: self.bound_quanta,
                    });
                };
                if delta > self.bound_quanta {
                    return Err(ExplorationLifecycleError::AcknowledgementExceededBound {
                        command,
                        observed_delta_quanta: delta,
                        bound_quanta: self.bound_quanta,
                    });
                }
                return Ok(acknowledgement);
            }
        }

        Err(ExplorationLifecycleError::AcknowledgementTimeout {
            command,
            requested_at_quantum: before.quanta_stepped,
            max_actor_yields: self.max_actor_yields,
        })
    }
}

fn lifecycle_acknowledgement(
    command: ExplorationLifecycleCommand,
    before: LiveSnapshotView,
    after: LiveSnapshotView,
    acknowledged_state: LiveStateKind,
) -> ExplorationLifecycleAcknowledgement {
    ExplorationLifecycleAcknowledgement {
        command,
        requested_state: before.state_kind,
        acknowledged_state,
        requested_at_quantum: before.quanta_stepped,
        acknowledged_at_quantum: after.quanta_stepped,
        requested_event_log_len: before.event_log_len,
        acknowledged_event_log_len: after.event_log_len,
    }
}

/// A snapshot of state visible at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineSnapshot {
    /// The current engine state.
    pub state: EngineState,
    /// The source-of-truth execution configuration.
    pub configuration: Configuration,
    /// The most recent scheduler frontier.
    pub frontier: VirtualTime,
    /// Number of canonical event-log entries observed through scheduler output.
    pub event_log_len: usize,
    /// Number of scheduler quanta driven by this engine.
    pub quanta: u64,
}

/// Reproducible record for a session-level fork operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionForkRecord {
    /// Checkpoint/configuration where the branch was forked.
    pub from_checkpoint: ContentHash,
    /// Checkpoint recorded for the forked branch.
    pub branch_checkpoint: ContentHash,
    /// Decisions appended after `from_checkpoint` to create the branch.
    pub schedule_delta: Schedule,
}

/// Result of creating an independent child session from a fork point.
///
/// The child is an ordinary [`SessionActor`] loaded at the forked branch
/// configuration. Starting the child actor realizes that configuration through
/// the same [`instantiate`] path used by start and resume.
pub struct SessionFork<L> {
    /// Parent engine state observed while servicing the fork.
    pub parent_state: EngineState,
    /// Configuration id used as the fork point.
    pub base_configuration: ContentHash,
    /// Branch configuration produced by appending the fork decisions.
    pub branch_configuration: Configuration,
    /// Thin checkpoint recorded for the branch in the temporal graph.
    pub branch_checkpoint: Checkpoint,
    /// Structural record of the fork point and branch delta.
    pub record: SessionForkRecord,
    /// Command sender for the independent child session actor.
    pub child_sender: mpsc::Sender<SessionCommand>,
    /// Independent child session actor loaded at `branch_configuration`.
    pub child_actor: SessionActor<L>,
}

/// Lock-free mirror of live session state.
///
/// The session actor is the only writer. Observers clone an [`Arc`] handle and
/// call [`LiveSnapshot::read`] without entering the actor mailbox or taking an
/// engine lock.
#[derive(Debug)]
pub struct LiveSnapshot {
    epoch: AtomicU64,
    state_kind: AtomicU8,
    virtual_time_ticks: AtomicU64,
    event_log_len: AtomicU64,
    quanta_stepped: AtomicU64,
    control_acknowledgements: AtomicU64,
}

/// Copy-out view of [`LiveSnapshot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveSnapshotView {
    /// Compact state kind visible to observers.
    pub state_kind: LiveStateKind,
    /// The latest scheduler virtual-time frontier.
    pub virtual_time: VirtualTime,
    /// Canonical event-log length observed by the session actor.
    pub event_log_len: u64,
    /// Monotone count of scheduler quanta stepped by the session actor.
    pub quanta_stepped: u64,
    /// Monotone count of actor-acknowledged control commands.
    pub control_acknowledgements: u64,
}

impl LiveSnapshot {
    /// Builds a live snapshot initialized from an engine boundary snapshot.
    #[must_use]
    pub fn new(initial: &EngineSnapshot) -> Self {
        let snapshot = Self {
            epoch: AtomicU64::new(0),
            state_kind: AtomicU8::new(LiveStateKind::Loaded as u8),
            virtual_time_ticks: AtomicU64::new(0),
            event_log_len: AtomicU64::new(0),
            quanta_stepped: AtomicU64::new(0),
            control_acknowledgements: AtomicU64::new(0),
        };
        snapshot.publish(initial, 0);
        snapshot
    }

    /// Reads a lock-free point-in-time view.
    ///
    /// This method uses atomic loads only. If it races a writer, it retries
    /// until it observes one complete actor-published boundary snapshot.
    #[must_use]
    pub fn read(&self) -> LiveSnapshotView {
        loop {
            let start_epoch = self.epoch.load(Ordering::Acquire);
            if !start_epoch.is_multiple_of(2) {
                std::hint::spin_loop();
                continue;
            }

            let state_kind = self.state_kind.load(Ordering::Acquire);
            let virtual_time_ticks = self.virtual_time_ticks.load(Ordering::Acquire);
            let event_log_len = self.event_log_len.load(Ordering::Acquire);
            let quanta_stepped = self.quanta_stepped.load(Ordering::Acquire);
            let control_acknowledgements = self.control_acknowledgements.load(Ordering::Acquire);
            let end_epoch = self.epoch.load(Ordering::Acquire);

            if start_epoch == end_epoch && end_epoch.is_multiple_of(2) {
                return LiveSnapshotView {
                    state_kind: LiveStateKind::from_raw(state_kind),
                    virtual_time: VirtualTime {
                        ticks: virtual_time_ticks,
                    },
                    event_log_len,
                    quanta_stepped,
                    control_acknowledgements,
                };
            }

            std::hint::spin_loop();
        }
    }

    fn publish(&self, snapshot: &EngineSnapshot, control_acknowledgements: u64) {
        let write_epoch = self.epoch.load(Ordering::Relaxed).wrapping_add(1) | 1;
        self.epoch.store(write_epoch, Ordering::Release);
        self.state_kind.store(
            LiveStateKind::from_engine_state(&snapshot.state) as u8,
            Ordering::Release,
        );
        self.virtual_time_ticks
            .store(snapshot.frontier.ticks, Ordering::Release);
        self.event_log_len
            .store(usize_to_u64(snapshot.event_log_len), Ordering::Release);
        self.quanta_stepped
            .store(snapshot.quanta, Ordering::Release);
        self.control_acknowledgements
            .store(control_acknowledgements, Ordering::Release);
        self.epoch
            .store(write_epoch.wrapping_add(1), Ordering::Release);
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn u64_to_usize(value: u64) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}

fn fork_session_handle_id(parent: ContentHash, checkpoint: ContentHash) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.session.fork-handle.v1",
        &format!(
            "parent={}\ncheckpoint={}\n",
            parent.to_hex(),
            checkpoint.to_hex()
        ),
    )
}

/// Cursor into a session event-log stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventLogCursor {
    /// Next dense event-log sequence number to deliver.
    pub next_sequence: u64,
}

impl EventLogCursor {
    /// Builds a cursor at `next_sequence`.
    #[must_use]
    pub const fn new(next_sequence: u64) -> Self {
        Self { next_sequence }
    }
}

/// One event-log entry delivered to a control-plane subscriber.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEventLogFrame {
    /// Cursor position of this entry.
    pub cursor: EventLogCursor,
    /// Cursor position immediately after this entry.
    pub next_cursor: EventLogCursor,
    /// Full causal or observational event-log entry.
    pub entry: SchedulerEventLogEntry,
}

impl SessionEventLogFrame {
    fn new(entry: SchedulerEventLogEntry) -> Self {
        let sequence = entry.sequence();
        Self {
            cursor: EventLogCursor::new(sequence),
            next_cursor: EventLogCursor::new(sequence.saturating_add(1)),
            entry,
        }
    }
}

/// Error returned while reading a live event-log stream.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SessionEventLogStreamError {
    /// The subscriber lagged behind the bounded live tail.
    #[error("session event-log stream skipped {skipped} frames")]
    Lagged {
        /// Number of skipped broadcast frames reported by the live tail.
        skipped: u64,
    },
}

/// Session-owned event-log hub used by the control plane.
#[derive(Clone, Debug)]
pub struct SessionEventLog {
    inner: Arc<SessionEventLogInner>,
}

#[derive(Debug)]
struct SessionEventLogInner {
    entries: Mutex<Vec<SchedulerEventLogEntry>>,
    tail: broadcast::Sender<SessionEventLogFrame>,
}

impl SessionEventLog {
    /// Builds an empty event-log hub.
    #[must_use]
    pub fn new() -> Self {
        let (tail, _) = broadcast::channel(SESSION_EVENT_LOG_BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(SessionEventLogInner {
                entries: Mutex::new(Vec::new()),
                tail,
            }),
        }
    }

    /// Returns the number of retained event-log entries.
    #[must_use]
    pub fn len(&self) -> u64 {
        usize_to_u64(self.lock_entries().len())
    }

    /// Returns whether no event-log entries are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock_entries().is_empty()
    }

    /// Returns a cursor positioned at the retained log tail.
    #[must_use]
    pub fn current_cursor(&self) -> EventLogCursor {
        let entries = self.lock_entries();
        Self::current_cursor_for(&entries)
    }

    /// Subscribes to entries from `cursor` onward.
    ///
    /// The returned stream first drains a cursor snapshot from the retained log,
    /// then continues with the live broadcast tail. Subscribing does not enqueue
    /// a session command and does not await the scheduler.
    #[must_use]
    pub fn subscribe(&self, cursor: EventLogCursor) -> SessionEventLogStream {
        let current_tail = self.current_cursor();
        let next_cursor = EventLogCursor::new(cursor.next_sequence.min(current_tail.next_sequence));
        let receiver = self.inner.tail.subscribe();
        SessionEventLogStream {
            hub: self.clone(),
            next_cursor,
            replay_exhausted: false,
            backlog: VecDeque::new(),
            receiver,
        }
    }

    fn append_entries(&self, entries: &[SchedulerEventLogEntry]) {
        if entries.is_empty() {
            return;
        }

        let frames = entries
            .iter()
            .cloned()
            .map(SessionEventLogFrame::new)
            .collect::<Vec<_>>();
        self.lock_entries().extend(entries.iter().cloned());
        for frame in frames {
            let _ = self.inner.tail.send(frame);
        }
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, Vec<SchedulerEventLogEntry>> {
        match self.inner.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn current_cursor_for(entries: &[SchedulerEventLogEntry]) -> EventLogCursor {
        entries
            .last()
            .map(|entry| EventLogCursor::new(entry.sequence().saturating_add(1)))
            .unwrap_or_default()
    }

    fn replay_batch_from(&self, cursor: EventLogCursor) -> VecDeque<SessionEventLogFrame> {
        let entries = self.lock_entries();
        let start = entries.partition_point(|entry| entry.sequence() < cursor.next_sequence);
        entries
            .iter()
            .skip(start)
            .take(SESSION_EVENT_LOG_REPLAY_BATCH_SIZE)
            .cloned()
            .map(SessionEventLogFrame::new)
            .collect()
    }
}

impl Default for SessionEventLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Cursor-backed event-log stream for one subscriber.
#[derive(Debug)]
pub struct SessionEventLogStream {
    hub: SessionEventLog,
    next_cursor: EventLogCursor,
    replay_exhausted: bool,
    backlog: VecDeque<SessionEventLogFrame>,
    receiver: broadcast::Receiver<SessionEventLogFrame>,
}

impl SessionEventLogStream {
    /// Returns the next cursor position expected by this stream.
    #[must_use]
    pub const fn cursor(&self) -> EventLogCursor {
        self.next_cursor
    }

    /// Receives the next event-log frame.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEventLogStreamError::Lagged`] when this subscriber falls
    /// behind the bounded live broadcast tail.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<SessionEventLogFrame>, SessionEventLogStreamError> {
        loop {
            if self.backlog.is_empty() && !self.replay_exhausted {
                self.backlog = self.hub.replay_batch_from(self.next_cursor);
                self.replay_exhausted = self.backlog.is_empty();
            }

            if let Some(frame) = self.backlog.pop_front() {
                if frame.cursor.next_sequence < self.next_cursor.next_sequence {
                    continue;
                }
                self.next_cursor = frame.next_cursor;
                return Ok(Some(frame));
            }

            match self.receiver.recv().await {
                Ok(frame) if frame.cursor.next_sequence < self.next_cursor.next_sequence => {}
                Ok(frame) => {
                    self.next_cursor = frame.next_cursor;
                    return Ok(Some(frame));
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(None),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    return Err(SessionEventLogStreamError::Lagged { skipped });
                }
            }
        }
    }
}

/// Host-side engine state machine owned by the session actor.
///
/// The engine owns the source-of-truth [`Configuration`], a rebuildable runtime
/// cache, the temporal graph used for instantiation and checkpoints, the
/// breakpoint registry, and the single [`QuantumLoop`] boundary that performs
/// virtual-time advancement.
///
/// `Engine` is a lower-level state-machine value. Once it is moved into a
/// [`SessionActor`], the actor's private field ownership prevents external
/// mutable access; live session interaction goes through the actor mailbox.
pub struct Engine<L> {
    configuration: Configuration,
    runtime: Option<RuntimeState>,
    runtime_instantiated: bool,
    state: EngineState,
    graph: TemporalGraph,
    breakpoints: BreakpointSet,
    quantum_loop: L,
    frontier: VirtualTime,
    event_log_len: usize,
    quanta: u64,
    pending_control: Vec<ControlOperation>,
    pending_event_log_entries: Vec<SchedulerEventLogEntry>,
    next_control_sequence: u64,
}

impl<L> Engine<L> {
    /// Creates a loaded engine from a configuration, temporal graph, and quantum loop.
    #[must_use]
    pub fn new(configuration: Configuration, graph: TemporalGraph, quantum_loop: L) -> Self {
        Self {
            configuration,
            runtime: None,
            runtime_instantiated: false,
            state: EngineState::Loaded,
            graph,
            breakpoints: BreakpointSet::new(),
            quantum_loop,
            frontier: VirtualTime::default(),
            event_log_len: 0,
            quanta: 0,
            pending_control: Vec::new(),
            pending_event_log_entries: Vec::new(),
            next_control_sequence: 0,
        }
    }

    /// Returns the current engine state.
    #[must_use]
    pub fn state(&self) -> &EngineState {
        &self.state
    }

    /// Returns the source-of-truth configuration.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the cached runtime, if instantiated.
    #[must_use]
    pub fn runtime(&self) -> Option<&RuntimeState> {
        self.runtime.as_ref()
    }

    /// Returns the actor-owned breakpoint registry.
    #[must_use]
    pub fn breakpoints(&self) -> &BreakpointSet {
        &self.breakpoints
    }

    /// Returns the current scheduler frontier.
    #[must_use]
    pub fn frontier(&self) -> VirtualTime {
        self.frontier
    }

    /// Returns the canonical event-log length observed so far.
    #[must_use]
    pub fn event_log_len(&self) -> usize {
        self.event_log_len
    }

    /// Returns the number of scheduler quanta driven by this engine.
    #[must_use]
    pub fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Creates an independent child session from `base` plus divergent decisions.
    ///
    /// The fork is recorded through [`TemporalGraph::fork`], which realizes
    /// `base` via [`instantiate`], appends the supplied [`Decision`] values with
    /// the execution-model step operation, and records the branch as a thin
    /// checkpoint. The returned child is a normal loaded [`SessionActor`] with
    /// its own mailbox and live snapshot; starting it realizes the branch
    /// through the same path as any other session start or resume.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when called while the parent
    /// is loaded or running. A running parent must first pause at a quantum
    /// boundary. Returns [`SessionError::Engine`] when the temporal graph cannot
    /// realize `base` or record the fork branch.
    pub fn fork_child<C, I>(
        &mut self,
        base: &Configuration,
        decisions: I,
        child_quantum_loop: C,
    ) -> Result<SessionFork<C>, SessionError>
    where
        I: IntoIterator<Item = Decision>,
    {
        let parent_state = self.state.clone();
        if !matches!(
            parent_state,
            EngineState::Paused { .. } | EngineState::Stopped { .. }
        ) {
            return Err(SessionError::InvalidEngineState {
                state: parent_state,
                operation: "fork_child",
            });
        }

        let fork = self.graph.fork(base, decisions)?;
        let child_graph = self.graph.clone();
        let branch_configuration = fork.branch.clone();
        let branch_checkpoint = fork.branch_checkpoint.clone();
        let record = SessionForkRecord {
            from_checkpoint: fork.base.checkpoint,
            branch_checkpoint: branch_checkpoint.id,
            schedule_delta: branch_checkpoint.schedule_delta.clone(),
        };
        let child_engine = Engine::new(
            branch_configuration.clone(),
            child_graph,
            child_quantum_loop,
        );
        let (child_sender, receiver) = mpsc::channel(SESSION_FORK_MAILBOX_CAPACITY);
        let child_actor = SessionActor::new(child_engine, receiver);

        Ok(SessionFork {
            parent_state,
            base_configuration: fork.base.configuration,
            branch_configuration,
            branch_checkpoint,
            record,
            child_sender,
            child_actor,
        })
    }

    /// Returns a boundary snapshot of the engine state.
    #[must_use]
    pub fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            state: self.state.clone(),
            configuration: self.configuration.clone(),
            frontier: self.frontier,
            event_log_len: self.event_log_len,
            quanta: self.quanta,
        }
    }

    /// Consumes the engine and returns the wrapped quantum loop.
    #[must_use]
    pub fn into_quantum_loop(self) -> L {
        self.quantum_loop
    }

    fn invalid_transition(&self, command: SessionCommand) -> SessionError {
        SessionError::InvalidTransition {
            state: self.state.clone(),
            command,
        }
    }

    fn invalid_engine_state(&self, operation: &'static str) -> SessionError {
        SessionError::InvalidEngineState {
            state: self.state.clone(),
            operation,
        }
    }

    fn admit_control_operation(&mut self, kind: ControlOperationKind) {
        self.next_control_sequence = self.next_control_sequence.saturating_add(1);
        self.pending_control.push(ControlOperation {
            sequence: self.next_control_sequence,
            kind,
        });
    }

    fn pending_control_len(&self) -> usize {
        self.pending_control.len()
    }

    fn drain_event_log_entries(&mut self) -> Vec<SchedulerEventLogEntry> {
        std::mem::take(&mut self.pending_event_log_entries)
    }

    fn resolve_fork_checkpoint(&mut self, from: CheckpointRef) -> Result<Checkpoint, SessionError> {
        match from {
            CheckpointRef::Current => Ok(self.graph.save_checkpoint(&self.configuration)?),
            CheckpointRef::Checkpoint(checkpoint) => self
                .graph
                .checkpoint_node(checkpoint)
                .cloned()
                .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                    checkpoint,
                })),
        }
    }
}

impl<L: QuantumLoop> Engine<L> {
    /// Instantiates the engine runtime from its source-of-truth configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when the engine is not
    /// loaded. Returns [`SessionError::Engine`] when the execution model cannot
    /// instantiate the current configuration from the temporal graph.
    pub fn instantiate_runtime(&mut self) -> Result<EngineSnapshot, SessionError> {
        if !matches!(self.state, EngineState::Loaded) {
            return Err(self.invalid_engine_state("instantiate_runtime"));
        }

        let runtime = instantiate(&self.graph, &self.configuration)?;
        self.runtime = Some(runtime);
        self.runtime_instantiated = true;
        self.state = EngineState::Paused {
            reason: PauseReason::Instantiated,
        };
        Ok(self.snapshot())
    }

    /// Drops the cached runtime while preserving the source-of-truth state.
    ///
    /// The runtime is a rebuildable cache. Evicting it must not change the
    /// engine's boundary snapshot, configuration, frontier, log length, or
    /// quantum count.
    pub fn evict_runtime_cache(&mut self) -> EngineSnapshot {
        self.runtime = None;
        self.snapshot()
    }

    /// Rebuilds the cached runtime from the source-of-truth configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when the runtime has not
    /// been initially instantiated. Returns [`SessionError::Engine`] when the
    /// execution model cannot instantiate the current configuration from the
    /// temporal graph.
    pub fn reinstantiate_runtime_cache(&mut self) -> Result<EngineSnapshot, SessionError> {
        if !self.runtime_instantiated {
            return Err(self.invalid_engine_state("reinstantiate_runtime_cache"));
        }

        let runtime = instantiate(&self.graph, &self.configuration)?;
        self.runtime = Some(runtime);
        Ok(self.snapshot())
    }

    /// Drops and rebuilds the cached runtime at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when the runtime has not
    /// been initially instantiated. Returns [`SessionError::Engine`] when the
    /// execution model cannot instantiate the current configuration from the
    /// temporal graph.
    pub fn refresh_runtime_cache(&mut self) -> Result<EngineSnapshot, SessionError> {
        if !self.runtime_instantiated {
            return Err(self.invalid_engine_state("refresh_runtime_cache"));
        }

        let runtime = instantiate(&self.graph, &self.configuration)?;
        self.runtime = None;
        self.runtime = Some(runtime);
        Ok(self.snapshot())
    }

    /// Applies one actor-owned command at a state-machine boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] if the command is not valid
    /// in the current state. Returns [`SessionError::Engine`] or
    /// [`SessionError::Scheduler`] if the model or scheduler boundary fails.
    pub fn apply_command(
        &mut self,
        command: SessionCommand,
    ) -> Result<EngineSnapshot, SessionError> {
        match &command {
            SessionCommand::Start => {
                if matches!(self.state, EngineState::Loaded) {
                    self.instantiate_runtime()
                } else {
                    Err(self.invalid_transition(command.clone()))
                }
            }
            SessionCommand::Continue => {
                if matches!(self.state, EngineState::Paused { .. }) {
                    self.state = EngineState::Running;
                    Ok(self.snapshot())
                } else {
                    Err(self.invalid_transition(command.clone()))
                }
            }
            SessionCommand::Pause => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.state = EngineState::Paused {
                        reason: PauseReason::UserRequested,
                    };
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::Step { mode } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if *mode != StepMode::Quantum {
                        return Err(SessionError::UnsupportedStepMode {
                            state: self.state.clone(),
                            mode: *mode,
                        });
                    }
                    let previous = self.state.clone();
                    self.state = EngineState::Running;
                    if let Err(error) = self.step_quantum() {
                        self.state = previous;
                        return Err(error);
                    }
                    self.state = EngineState::Paused {
                        reason: PauseReason::StepComplete { mode: *mode },
                    };
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::Snapshot => {
                if matches!(self.state, EngineState::Running) {
                    self.admit_control_operation(ControlOperationKind::Snapshot);
                }
                Ok(self.snapshot())
            }
            SessionCommand::Fork { from, reply } => match self.state {
                EngineState::Paused { .. } | EngineState::Stopped { .. } => {
                    let checkpoint = self.resolve_fork_checkpoint(*from)?;
                    let handle = SessionHandle {
                        id: fork_session_handle_id(self.configuration.id(), checkpoint.id),
                        checkpoint: checkpoint.id,
                    };
                    reply.complete(Ok(handle));
                    Ok(self.snapshot())
                }
                EngineState::Running | EngineState::Loaded => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::Inject => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.admit_control_operation(ControlOperationKind::Inject);
                    }
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::InjectFault { spec, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.admit_control_operation(ControlOperationKind::InjectFault {
                            tag: spec.tag.clone(),
                            fault: spec.fault.clone(),
                        });
                    }
                    reply.complete(Ok(spec.tag.clone()));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::HealFault { tag, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.admit_control_operation(ControlOperationKind::HealFault {
                            tag: tag.clone(),
                        });
                    }
                    reply.complete(Ok(()));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::SetBreakpoint { spec, reply } => {
                let id = self.breakpoints.insert(spec.clone());
                reply.complete(Ok(id));
                Ok(self.snapshot())
            }
            SessionCommand::RemoveBreakpoint { id, reply } => {
                let removed = self.breakpoints.remove(*id);
                reply.complete(Ok(removed));
                Ok(self.snapshot())
            }
            SessionCommand::CreateSavepoint { label, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let checkpoint = self.graph.save_checkpoint(&self.configuration)?;
                    reply.complete(Ok(SavepointInfo {
                        label: label.clone(),
                        configuration: self.configuration.id(),
                        checkpoint,
                    }));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::Stop => {
                if matches!(self.state, EngineState::Stopped { .. }) {
                    Err(self.invalid_transition(command.clone()))
                } else {
                    self.state = EngineState::Stopped {
                        outcome: Outcome::Stopped,
                    };
                    Ok(self.snapshot())
                }
            }
            SessionCommand::Query { kind, reply } => {
                if matches!(self.state, EngineState::Running) {
                    self.admit_control_operation(ControlOperationKind::Query);
                }
                let snapshot = self.snapshot();
                let result = match kind {
                    QueryKind::Snapshot => QueryResult::Snapshot(snapshot.clone()),
                    QueryKind::State => {
                        QueryResult::State(LifecycleStateKind::from(&snapshot.state))
                    }
                    QueryKind::EventLogLength => {
                        QueryResult::EventLogLength(snapshot.event_log_len)
                    }
                };
                reply.complete(Ok(result));
                Ok(snapshot)
            }
        }
    }

    /// Advances exactly one bounded scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] if the engine is not
    /// running. Returns [`SessionError::Scheduler`] if the quantum loop rejects
    /// the boundary request. Returns [`SessionError::EventLogOffsetRegression`]
    /// or [`SessionError::EventLogOffsetMismatch`] if the scheduler's emitted
    /// entries do not match its returned event-log offset. Returns
    /// [`SessionError::Engine`] if the resulting configuration cannot be
    /// re-instantiated.
    pub fn step_quantum(&mut self) -> Result<QuantumOutcome, SessionError> {
        if !matches!(self.state, EngineState::Running) {
            return Err(self.invalid_engine_state("step_quantum"));
        }

        let outcome = self.quantum_loop.drive_quantum(QuantumRequest {
            configuration: self.configuration.clone(),
            control: std::mem::take(&mut self.pending_control),
        })?;
        let current_event_log_len = usize_to_u64(self.event_log_len);
        let emitted_event_log_entries = usize_to_u64(outcome.event_log_entries.len());
        let expected_event_log_len = current_event_log_len
            .checked_add(emitted_event_log_entries)
            .ok_or(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: emitted_event_log_entries,
                next: outcome.event_log_offset.events,
            })?;
        if outcome.event_log_offset.events < current_event_log_len {
            return Err(SessionError::EventLogOffsetRegression {
                current: current_event_log_len,
                next: outcome.event_log_offset.events,
            });
        }
        if outcome.event_log_offset.events != expected_event_log_len {
            return Err(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: emitted_event_log_entries,
                next: outcome.event_log_offset.events,
            });
        }
        let runtime = instantiate(&self.graph, &outcome.configuration)?;

        self.configuration = outcome.configuration.clone();
        self.runtime = Some(runtime);
        self.runtime_instantiated = true;
        self.frontier = outcome.frontier;
        self.event_log_len = u64_to_usize(outcome.event_log_offset.events);
        self.quanta = self.quanta.saturating_add(1);
        self.pending_event_log_entries
            .extend(outcome.event_log_entries.iter().cloned());

        Ok(outcome)
    }
}

/// Error returned by the session actor or engine state machine.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    /// The command mailbox closed before the actor reached a terminal state.
    #[error("session command mailbox closed")]
    ChannelClosed,
    /// A command was not valid in the current state.
    #[error("session command is invalid in the current engine state")]
    InvalidTransition {
        /// The state that rejected the command.
        state: EngineState,
        /// The command that was rejected.
        command: SessionCommand,
    },
    /// A direct engine operation was called in the wrong state.
    #[error("engine operation {operation} is invalid in the current state")]
    InvalidEngineState {
        /// The state that rejected the operation.
        state: EngineState,
        /// The rejected engine operation.
        operation: &'static str,
    },
    /// The execution model failed while instantiating or replaying state.
    #[error("execution model failed under session control: {0}")]
    Engine(#[from] EngineError),
    /// The scheduler boundary failed while driving a bounded quantum.
    #[error("scheduler failed under session control: {0}")]
    Scheduler(#[from] SchedulerError),
    /// The scheduler returned an event-log offset older than the current session mirror.
    #[error("scheduler event-log offset regressed from {current} to {next}")]
    EventLogOffsetRegression {
        /// Current session event-log entry count.
        current: u64,
        /// Event-log entry count returned by the scheduler.
        next: u64,
    },
    /// The scheduler returned an event-log offset that does not match its emitted entries.
    #[error("scheduler event-log offset mismatch: current={current} emitted={emitted} next={next}")]
    EventLogOffsetMismatch {
        /// Current session event-log entry count.
        current: u64,
        /// Number of entries emitted by the scheduler outcome.
        emitted: u64,
        /// Event-log entry count returned by the scheduler.
        next: u64,
    },
    /// A forward step mode is part of the debug vocabulary but has no executor yet.
    #[error("step mode {mode:?} is not implemented by the forward session executor in {state:?}")]
    UnsupportedStepMode {
        /// The state that rejected the step mode.
        state: EngineState,
        /// Step mode that cannot be executed by the forward session actor yet.
        mode: StepMode,
    },
}

/// Evidence returned when a session actor exits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRunReport {
    /// Final boundary snapshot.
    pub final_snapshot: EngineSnapshot,
    /// Number of commands the actor applied successfully.
    pub commands_applied: u64,
    /// Number of scheduler quanta driven.
    pub quanta: u64,
    /// Number of quanta after which the actor yielded cooperatively.
    pub yielded_after_quanta: u64,
}

/// The single owning session actor.
///
/// `SessionActor` owns the [`Engine`], polls the command mailbox at state
/// boundaries, drives at most one scheduler quantum per running-loop iteration,
/// and yields after each applied command or scheduler quantum.
pub struct SessionActor<L> {
    engine: Engine<L>,
    mailbox: mpsc::Receiver<SessionCommand>,
    live: Arc<LiveSnapshot>,
    event_log: SessionEventLog,
    commands_applied: u64,
    yielded_after_quanta: u64,
    control_acknowledgements: u64,
}

impl<L> SessionActor<L> {
    /// Creates a session actor from an engine and command mailbox.
    #[must_use]
    pub fn new(engine: Engine<L>, mailbox: mpsc::Receiver<SessionCommand>) -> Self {
        let live = Arc::new(LiveSnapshot::new(&engine.snapshot()));
        Self {
            engine,
            mailbox,
            live,
            event_log: SessionEventLog::new(),
            commands_applied: 0,
            yielded_after_quanta: 0,
            control_acknowledgements: 0,
        }
    }

    /// Returns the actor-owned engine.
    #[must_use]
    pub fn engine(&self) -> &Engine<L> {
        &self.engine
    }

    /// Returns a lock-free live snapshot handle for observers.
    #[must_use]
    pub fn live_snapshot(&self) -> Arc<LiveSnapshot> {
        Arc::clone(&self.live)
    }

    /// Returns a cloneable event-log hub for cursor subscribers.
    #[must_use]
    pub fn event_log(&self) -> SessionEventLog {
        self.event_log.clone()
    }

    /// Subscribes to session event-log entries from `cursor` onward.
    #[must_use]
    pub fn event_log_stream(&self, cursor: EventLogCursor) -> SessionEventLogStream {
        self.event_log.subscribe(cursor)
    }

    /// Returns the number of commands applied by the actor.
    #[must_use]
    pub fn commands_applied(&self) -> u64 {
        self.commands_applied
    }

    /// Returns the number of post-quantum cooperative yields.
    #[must_use]
    pub fn yielded_after_quanta(&self) -> u64 {
        self.yielded_after_quanta
    }

    /// Returns the number of control commands acknowledged by the actor.
    #[must_use]
    pub fn control_acknowledgements(&self) -> u64 {
        self.control_acknowledgements
    }

    fn report(&self) -> SessionRunReport {
        SessionRunReport {
            final_snapshot: self.engine.snapshot(),
            commands_applied: self.commands_applied,
            quanta: self.engine.quanta(),
            yielded_after_quanta: self.yielded_after_quanta,
        }
    }

    fn publish_live_snapshot(&self) {
        self.live
            .publish(&self.engine.snapshot(), self.control_acknowledgements);
    }
}

impl<L: QuantumLoop> SessionActor<L> {
    /// Runs the actor until it reaches [`EngineState::Stopped`].
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::ChannelClosed`] if the mailbox closes before a
    /// terminal state. Returns other [`SessionError`] variants if a command,
    /// model operation, or scheduler quantum fails.
    pub async fn run(mut self) -> Result<SessionRunReport, SessionError> {
        loop {
            if matches!(self.engine.state(), EngineState::Stopped { .. }) {
                self.drain_terminal_commands().await?;
                return Ok(self.report());
            }
            self.run_once().await?;
        }
    }

    async fn run_once(&mut self) -> Result<(), SessionError> {
        match self.engine.state().clone() {
            EngineState::Running => {
                if let Some(command) = self.next_boundary_command()? {
                    self.apply_command(command).await?;
                    return Ok(());
                }

                let pending_control = self.engine.pending_control_len() as u64;
                self.engine.step_quantum()?;
                let entries = self.engine.drain_event_log_entries();
                self.event_log.append_entries(&entries);
                self.control_acknowledgements = self
                    .control_acknowledgements
                    .saturating_add(pending_control);
                self.publish_live_snapshot();
                self.yielded_after_quanta = self.yielded_after_quanta.saturating_add(1);
                tokio::task::yield_now().await;
                Ok(())
            }
            EngineState::Loaded | EngineState::Paused { .. } => {
                let command = self
                    .mailbox
                    .recv()
                    .await
                    .ok_or(SessionError::ChannelClosed)?;
                self.apply_command(command).await
            }
            EngineState::Stopped { .. } => {
                self.drain_terminal_commands().await?;
                Ok(())
            }
        }
    }

    fn next_boundary_command(&mut self) -> Result<Option<SessionCommand>, SessionError> {
        match self.mailbox.try_recv() {
            Ok(command) => Ok(Some(command)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(SessionError::ChannelClosed),
        }
    }

    async fn apply_command(&mut self, command: SessionCommand) -> Result<(), SessionError> {
        let quanta_before = self.engine.quanta();
        let pending_control_before = self.engine.pending_control_len() as u64;
        let quantum_ack = matches!(self.engine.state(), EngineState::Running)
            && command.requires_running_quantum_ack();
        let control_acknowledged = command.is_control_acknowledged();
        if let Err(error) = self.engine.apply_command(command.clone()) {
            command.complete_error(error.clone());
            return Err(error);
        }
        let entries = self.engine.drain_event_log_entries();
        self.event_log.append_entries(&entries);
        let pending_control_after = self.engine.pending_control_len() as u64;
        if self.engine.quanta() > quanta_before && pending_control_after < pending_control_before {
            self.control_acknowledgements = self
                .control_acknowledgements
                .saturating_add(pending_control_before - pending_control_after);
        }
        if control_acknowledged && !quantum_ack {
            self.control_acknowledgements = self.control_acknowledgements.saturating_add(1);
        }
        self.publish_live_snapshot();
        if self.engine.quanta() > quanta_before {
            self.yielded_after_quanta = self
                .yielded_after_quanta
                .saturating_add(self.engine.quanta() - quanta_before);
        }
        self.commands_applied = self.commands_applied.saturating_add(1);
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn drain_terminal_commands(&mut self) -> Result<(), SessionError> {
        loop {
            match self.mailbox.try_recv() {
                Ok(command) if command.is_terminal_accepted() => {
                    self.apply_command(command).await?;
                }
                Ok(command) => {
                    let error = self.engine.invalid_transition(command.clone());
                    command.complete_error(error);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{
        Checkpoint, CheckpointKind, DebugReverseStepGrain, Decision, DeliveryOrderDecision,
        EventKey, GenesisCheckpoint, NodeId, ScenarioDef, SchedulerNodeId, SchedulingNodeKind,
        Seed, VirtualTime, step,
    };

    #[test]
    fn step_modes_mirror_debug_reverse_grains() {
        let reverse = StepMode::ALL
            .into_iter()
            .map(StepMode::reverse_grain)
            .collect::<Vec<_>>();

        assert_eq!(
            reverse,
            Vec::from(DebugReverseStepGrain::ALL),
            "forward and reverse debug step vocabularies must stay in lockstep"
        );
    }

    #[test]
    fn non_quantum_step_modes_are_vocabulary_until_forward_executors_exist() {
        let scenario = generated_scenario(22);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        let before = engine.snapshot();

        for mode in [
            StepMode::Instruction,
            StepMode::Event,
            StepMode::Assertion,
            StepMode::Timer,
        ] {
            let error = match engine.apply_command(SessionCommand::Step { mode }) {
                Ok(_) => panic!("unsupported step mode should not execute as a quantum"),
                Err(error) => error,
            };
            assert_eq!(engine.snapshot(), before);
            assert_eq!(
                error,
                SessionError::UnsupportedStepMode {
                    state: before.state.clone(),
                    mode,
                }
            );
        }
    }

    #[test]
    fn lifecycle_state_reason_outcome_and_command_sets_are_closed() {
        assert_eq!(
            LifecycleStateKind::ALL,
            [
                LifecycleStateKind::Loaded,
                LifecycleStateKind::Running,
                LifecycleStateKind::Paused,
                LifecycleStateKind::Stopped,
            ]
        );
        assert_eq!(
            PauseReasonKind::ALL,
            [
                PauseReasonKind::Instantiated,
                PauseReasonKind::UserRequested,
                PauseReasonKind::Breakpoint,
                PauseReasonKind::StepComplete,
            ]
        );
        assert_eq!(
            OutcomeKind::ALL,
            [
                OutcomeKind::Passed,
                OutcomeKind::Failed,
                OutcomeKind::Timeout,
                OutcomeKind::Crashed,
                OutcomeKind::Stopped,
            ]
        );
        assert_eq!(
            SessionCommandKind::ALL,
            [
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Pause,
                SessionCommandKind::StepQuantum,
                SessionCommandKind::StepUnsupported,
                SessionCommandKind::Stop,
                SessionCommandKind::Inject,
                SessionCommandKind::InjectFault,
                SessionCommandKind::HealFault,
                SessionCommandKind::SetBreakpoint,
                SessionCommandKind::RemoveBreakpoint,
                SessionCommandKind::CreateSavepoint,
                SessionCommandKind::Fork,
                SessionCommandKind::Query,
                SessionCommandKind::Snapshot,
            ]
        );
        assert_eq!(
            PauseReasonKind::from(&PauseReason::Breakpoint { id: 7 }),
            PauseReasonKind::Breakpoint
        );
        assert_eq!(
            PauseReasonKind::from(&PauseReason::StepComplete {
                mode: StepMode::Quantum,
            }),
            PauseReasonKind::StepComplete
        );
        assert_eq!(
            OutcomeKind::from(&Outcome::Failed {
                violations: vec![String::from("v")]
            }),
            OutcomeKind::Failed
        );
        assert_eq!(
            OutcomeKind::from(&Outcome::Crashed {
                detail: String::from("crash")
            }),
            OutcomeKind::Crashed
        );
    }

    #[test]
    fn lifecycle_transition_model_is_total_for_representative_commands() {
        for state in LifecycleStateKind::ALL {
            for command in SessionCommandKind::ALL {
                match lifecycle_transition(state, command) {
                    LifecycleTransition::Accepted { to } => {
                        assert!(LifecycleStateKind::ALL.contains(&to));
                    }
                    LifecycleTransition::Rejected => {}
                }
            }
        }
    }

    #[test]
    fn lifecycle_transition_model_matches_rfc_section_table_cells() {
        assert_eq!(
            lifecycle_transition(LifecycleStateKind::Loaded, SessionCommandKind::Start),
            LifecycleTransition::Accepted {
                to: LifecycleStateKind::Paused,
            }
        );
        assert_eq!(
            lifecycle_transition(LifecycleStateKind::Running, SessionCommandKind::StepQuantum),
            LifecycleTransition::Accepted {
                to: LifecycleStateKind::Paused,
            }
        );
        assert_eq!(
            lifecycle_transition(LifecycleStateKind::Running, SessionCommandKind::Fork),
            LifecycleTransition::Rejected
        );
        assert_eq!(
            lifecycle_transition(
                LifecycleStateKind::Running,
                SessionCommandKind::CreateSavepoint
            ),
            LifecycleTransition::Accepted {
                to: LifecycleStateKind::Running,
            }
        );
        assert_eq!(
            lifecycle_transition(
                LifecycleStateKind::Paused,
                SessionCommandKind::SetBreakpoint
            ),
            LifecycleTransition::Accepted {
                to: LifecycleStateKind::Paused,
            }
        );
        assert_eq!(
            lifecycle_transition(
                LifecycleStateKind::Stopped,
                SessionCommandKind::RemoveBreakpoint
            ),
            LifecycleTransition::Accepted {
                to: LifecycleStateKind::Stopped,
            }
        );
        assert_eq!(
            lifecycle_transition(
                LifecycleStateKind::Loaded,
                SessionCommandKind::CreateSavepoint
            ),
            LifecycleTransition::Rejected
        );
    }

    #[test]
    fn lifecycle_transition_model_command_sequences_never_wedge() {
        let mut frontier = LifecycleStateKind::ALL.to_vec();
        for _ in 0..5 {
            let mut next_frontier = Vec::new();
            for state in frontier {
                for command in SessionCommandKind::ALL {
                    let next = match lifecycle_transition(state, command) {
                        LifecycleTransition::Accepted { to } => to,
                        LifecycleTransition::Rejected => state,
                    };
                    assert!(LifecycleStateKind::ALL.contains(&next));
                    next_frontier.push(next);
                }
            }
            frontier = next_frontier;
        }
    }

    #[test]
    fn scheduler_liveness_generated_command_streams_exercise_lifecycle_table() {
        let mut state = LifecycleStateKind::Loaded;
        for seed in 0..64_u64 {
            for step in 0..128_u64 {
                let index = deterministic_command_index(seed, step);
                let command = SessionCommandKind::ALL[index];
                let next = match lifecycle_transition(state, command) {
                    LifecycleTransition::Accepted { to } => to,
                    LifecycleTransition::Rejected => state,
                };
                assert!(LifecycleStateKind::ALL.contains(&next));
                state = next;
            }
            state = LifecycleStateKind::ALL[seed as usize % LifecycleStateKind::ALL.len()];
        }
    }

    #[test]
    fn engine_transition_table_matches_lifecycle_model_for_current_commands() {
        for state in LifecycleStateKind::ALL {
            for command_kind in SessionCommandKind::ALL {
                let Some(command) = command_kind.representative_command() else {
                    continue;
                };
                let mut engine = engine_with_lifecycle_state(state);
                let before = engine.snapshot();
                let model = lifecycle_transition(state, command_kind);
                let result = engine.apply_command(command.clone());

                match model {
                    LifecycleTransition::Accepted { to } => {
                        let snapshot = match result {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                panic!("{state:?} + {command_kind:?} should be accepted: {error}");
                            }
                        };
                        assert_eq!(LifecycleStateKind::from(&snapshot.state), to);
                        assert_eq!(LifecycleStateKind::from(engine.state()), to);
                    }
                    LifecycleTransition::Rejected => {
                        let error = match result {
                            Ok(snapshot) => {
                                panic!(
                                    "{state:?} + {command_kind:?} should reject, got {:?}",
                                    snapshot.state
                                );
                            }
                            Err(error) => error,
                        };
                        assert_eq!(engine.snapshot(), before);
                        assert_rejection_names_state_and_command(error, before.state, command);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn rfc_command_payloads_return_replies_through_engine_boundary() {
        let scenario = generated_scenario(26);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime before command replies: {error}");
        }

        let (state_reply, state_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::Query {
            kind: QueryKind::State,
            reply: state_reply,
        }) {
            panic!("state query should complete at a paused boundary: {error}");
        }
        assert_eq!(
            receive_reply(state_receiver).await,
            QueryResult::State(LifecycleStateKind::Paused)
        );

        let breakpoint = BreakpointSpec::suspend_once(Condition::Quiescent);
        let (breakpoint_reply, breakpoint_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint.clone(),
            reply: breakpoint_reply,
        }) {
            panic!("set breakpoint should return an actor-owned id: {error}");
        }
        let breakpoint_id = receive_reply(breakpoint_receiver).await;
        assert_eq!(engine.breakpoints().get(breakpoint_id), Some(&breakpoint));

        let (remove_reply, remove_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::RemoveBreakpoint {
            id: breakpoint_id,
            reply: remove_reply,
        }) {
            panic!("remove breakpoint should return removal status: {error}");
        }
        assert!(receive_reply(remove_receiver).await);
        assert!(engine.breakpoints().is_empty());

        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter the running command boundary: {error}");
        }
        let fault_tag = FaultTag::from_name("rfc-command-payload");
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        let (inject_reply, inject_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::InjectFault {
            spec: FaultSpec::new(fault_tag.clone(), fault),
            reply: inject_reply,
        }) {
            panic!("inject fault should return its stable tag: {error}");
        }
        assert_eq!(receive_reply(inject_receiver).await, fault_tag);
        assert_eq!(engine.pending_control_len(), 1);

        let (heal_reply, heal_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::HealFault {
            tag: fault_tag.clone(),
            reply: heal_reply,
        }) {
            panic!("heal fault should complete its acknowledgement: {error}");
        }
        receive_reply(heal_receiver).await;
        assert_eq!(engine.pending_control_len(), 2);

        let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::CreateSavepoint {
            label: String::from("rfc-command-savepoint"),
            reply: savepoint_reply,
        }) {
            panic!("create savepoint should materialize through the temporal graph: {error}");
        }
        let savepoint = receive_reply(savepoint_receiver).await;
        assert_eq!(savepoint.label, "rfc-command-savepoint");
        assert_eq!(savepoint.configuration, engine.configuration().id());
        assert_eq!(
            savepoint.checkpoint.configuration,
            engine.configuration().id()
        );

        let (query_reply, query_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::Query {
            kind: QueryKind::EventLogLength,
            reply: query_reply,
        }) {
            panic!("event-log query should complete at a running boundary: {error}");
        }
        assert_eq!(
            receive_reply(query_receiver).await,
            QueryResult::EventLogLength(0)
        );
        assert_eq!(engine.pending_control_len(), 3);

        if let Err(error) = engine.apply_command(SessionCommand::Pause) {
            panic!("pause should return to a forkable boundary: {error}");
        }
        let (fork_reply, fork_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::Fork {
            from: CheckpointRef::Current,
            reply: fork_reply,
        }) {
            panic!("fork should resolve through the current graph checkpoint: {error}");
        }
        let fork = receive_reply(fork_receiver).await;
        assert_eq!(fork.checkpoint, engine.configuration().id());
    }

    #[tokio::test]
    async fn rfc_command_rejections_complete_reply_oneshots_without_side_effects() {
        let scenario = generated_scenario(27);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, StubLoop);
        let (_sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);
        let before = actor.engine().snapshot();
        let (reply, reply_receiver) = CommandReply::channel();
        let command = SessionCommand::Fork {
            from: CheckpointRef::Current,
            reply,
        };

        let error = actor
            .apply_command(command.clone())
            .await
            .expect_err("loaded fork must reject through actor boundary");
        assert_eq!(
            receive_reply_error::<SessionHandle>(reply_receiver).await,
            error
        );
        assert_eq!(actor.engine().snapshot(), before);
        assert_rejection_names_state_and_command(error, before.state, command);
    }

    #[tokio::test]
    async fn rfc_command_terminal_drain_completes_queued_replies() {
        let scenario = generated_scenario(28);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, StubLoop);
        let (sender, receiver) = mpsc::channel(8);
        let (fork_reply, fork_receiver) = CommandReply::channel();
        let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
        let rejected_savepoint = SessionCommand::CreateSavepoint {
            label: String::from("terminal-savepoint"),
            reply: savepoint_reply,
        };

        for command in [
            SessionCommand::Start,
            SessionCommand::Stop,
            SessionCommand::Fork {
                from: CheckpointRef::Current,
                reply: fork_reply,
            },
            rejected_savepoint.clone(),
        ] {
            if let Err(error) = sender.send(command).await {
                panic!("terminal-drain command should enqueue: {error}");
            }
        }

        let report = match SessionActor::new(engine, receiver).run().await {
            Ok(report) => report,
            Err(error) => panic!("actor should report after draining terminal commands: {error}"),
        };

        let fork = receive_reply(fork_receiver).await;
        assert_eq!(fork.checkpoint, report.final_snapshot.configuration.id());
        let error = receive_reply_error::<SavepointInfo>(savepoint_receiver).await;
        assert_rejection_names_state_and_command(
            error,
            report.final_snapshot.state,
            rejected_savepoint,
        );
    }

    #[tokio::test]
    async fn rfc_command_running_actor_acknowledges_local_boundary_replies_immediately() {
        let scenario = generated_scenario(29);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        let breakpoint = BreakpointSpec::suspend_once(Condition::Quiescent);
        let (set_reply, set_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::SetBreakpoint {
                spec: breakpoint,
                reply: set_reply,
            })
            .await
        {
            panic!("set-breakpoint command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running set-breakpoint should complete locally: {error}");
        }
        let breakpoint_id = receive_reply(set_receiver).await;
        assert_eq!(actor.control_acknowledgements(), 1);
        assert_eq!(actor.engine().quanta(), 0);

        let (remove_reply, remove_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::RemoveBreakpoint {
                id: breakpoint_id,
                reply: remove_reply,
            })
            .await
        {
            panic!("remove-breakpoint command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running remove-breakpoint should complete locally: {error}");
        }
        assert!(receive_reply(remove_receiver).await);
        assert_eq!(actor.control_acknowledgements(), 2);
        assert_eq!(actor.engine().quanta(), 0);

        let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::CreateSavepoint {
                label: String::from("running-local-savepoint"),
                reply: savepoint_reply,
            })
            .await
        {
            panic!("savepoint command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running savepoint should complete locally: {error}");
        }
        let savepoint = receive_reply(savepoint_receiver).await;
        assert_eq!(savepoint.label, "running-local-savepoint");
        assert_eq!(actor.control_acknowledgements(), 3);
        assert_eq!(actor.engine().quanta(), 0);
        assert_eq!(actor.engine().pending_control_len(), 0);
    }

    #[test]
    fn session_driver_delegates_to_quantum_loop() {
        let config = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.session.quantum-loop",
            "scenario=stub",
        ));
        let request = QuantumRequest {
            configuration: config.clone(),
            control: Vec::new(),
        };
        let mut driver = SessionDriver::new(StubLoop);

        let outcome = driver.drive_quantum(request);

        assert_eq!(
            outcome.as_ref().map(|outcome| &outcome.configuration),
            Ok(&config)
        );
    }

    #[test]
    fn engine_start_instantiates_runtime_and_pauses() {
        let scenario = generated_scenario(11);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config.clone(), graph, StubLoop);

        let snapshot = match engine.apply_command(SessionCommand::Start) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("start should instantiate runtime: {error}"),
        };

        assert_eq!(
            snapshot.state,
            EngineState::Paused {
                reason: PauseReason::Instantiated
            }
        );
        assert_eq!(
            engine.runtime().map(|runtime| runtime.configuration),
            Some(config.id())
        );
    }

    #[test]
    fn session_actor_owns_breakpoint_set_with_runtime_state() {
        let scenario = generated_scenario(10);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, StubLoop);
        let (_sender, receiver) = mpsc::channel(4);
        let actor = SessionActor::new(engine, receiver);

        assert!(actor.engine().breakpoints().is_empty());
        assert_eq!(actor.engine().breakpoints().len(), 0);
    }

    #[test]
    fn session_actor_source_does_not_lock_engine_across_run() {
        let source = include_str!("lib.rs");
        let actor_struct = source_section(
            source,
            "pub struct SessionActor<L> {",
            "\n}\n\nimpl<L> SessionActor<L>",
        );
        let actor_impl = source_section(
            source,
            "impl<L> SessionActor<L> {",
            "\nimpl<L: QuantumLoop> SessionActor<L>",
        );
        let actor_quantum_impl = source_section(
            source,
            "impl<L: QuantumLoop> SessionActor<L> {",
            "\n#[cfg(test)]",
        );
        let actor_engine_field = ["engine", ": Engine<L>"].concat();
        let actor_mailbox_field = ["mailbox", ": mpsc::Receiver<SessionCommand>"].concat();
        let actor_event_log_field = ["event_log", ": SessionEventLog"].concat();
        assert!(actor_struct.contains(&actor_engine_field));
        assert!(actor_struct.contains(&actor_mailbox_field));
        assert!(actor_struct.contains(&actor_event_log_field));
        let Some((_, actor_fields)) = actor_struct.split_once('{') else {
            panic!("SessionActor source should contain a field body");
        };
        assert!(!actor_fields.contains("pub "));

        for forbidden in [
            ["engine", ": Arc<"].concat(),
            ["engine", ": std::sync::Arc<"].concat(),
            ["engine", ": Mutex<"].concat(),
            ["engine", ": std::sync::Mutex<"].concat(),
            ["engine", ": RwLock<"].concat(),
            ["engine", ": std::sync::RwLock<"].concat(),
            ["Arc<", "Mutex<", "Engine"].concat(),
            ["Arc<", "std::sync::Mutex<", "Engine"].concat(),
            ["Arc<", "RwLock<", "Engine"].concat(),
            ["Arc<", "std::sync::RwLock<", "Engine"].concat(),
            ["tokio::sync::", "Mutex"].concat(),
            ["tokio::sync::", "RwLock"].concat(),
            ["parking_lot::", "Mutex"].concat(),
            ["parking_lot::", "RwLock"].concat(),
        ] {
            assert!(
                !actor_struct.contains(&forbidden),
                "session-owned engine state must remain actor-owned by value, not locked: {forbidden}"
            );
        }

        for forbidden in [
            ["pub fn ", "engine_mut"].concat(),
            ["pub fn ", "defer_boundary_command"].concat(),
            ["pub fn ", "run_once"].concat(),
        ] {
            assert!(
                !actor_impl.contains(&forbidden),
                "live session actor must not expose direct mutation outside the mailbox: {forbidden}"
            );
        }

        for forbidden in [
            ["pub fn ", "apply_command"].concat(),
            ["pub fn ", "step_quantum"].concat(),
            ["pub fn ", "run_once"].concat(),
            ["pub fn ", "next_boundary_command"].concat(),
            ["pub fn ", "drain_read_only_commands"].concat(),
        ] {
            assert!(
                !actor_quantum_impl.contains(&forbidden),
                "live session actor must not expose direct mutation outside the mailbox: {forbidden}"
            );
        }
    }

    fn source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let Some(start_index) = source.find(start) else {
            panic!("source should contain section start {start}");
        };
        let tail = &source[start_index..];
        let Some(end_index) = tail.find(end) else {
            panic!("source should contain section end {end}");
        };
        &tail[..end_index]
    }

    fn deterministic_command_index(seed: u64, step: u64) -> usize {
        let mixed = seed
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(step.wrapping_mul(0xbf58_476d_1ce4_e5b9));
        (mixed as usize) % SessionCommandKind::ALL.len()
    }

    fn engine_with_lifecycle_state(state: LifecycleStateKind) -> Engine<AppendingLoop> {
        let seed = match state {
            LifecycleStateKind::Loaded => 9_001,
            LifecycleStateKind::Running => 9_002,
            LifecycleStateKind::Paused => 9_003,
            LifecycleStateKind::Stopped => 9_004,
        };
        let scenario = generated_scenario(seed);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, AppendingLoop::default());
        engine.state = match state {
            LifecycleStateKind::Loaded => EngineState::Loaded,
            LifecycleStateKind::Running => EngineState::Running,
            LifecycleStateKind::Paused => EngineState::Paused {
                reason: PauseReason::Instantiated,
            },
            LifecycleStateKind::Stopped => EngineState::Stopped {
                outcome: Outcome::Stopped,
            },
        };
        engine.runtime_instantiated = !matches!(state, LifecycleStateKind::Loaded);
        engine
    }

    async fn receive_reply<T: fmt::Debug>(
        receiver: oneshot::Receiver<Result<T, SessionError>>,
    ) -> T {
        match receiver.await {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => panic!("reply should succeed: {error}"),
            Err(error) => panic!("reply sender should complete: {error}"),
        }
    }

    async fn receive_reply_error<T: fmt::Debug>(
        receiver: oneshot::Receiver<Result<T, SessionError>>,
    ) -> SessionError {
        match receiver.await {
            Ok(Ok(value)) => panic!("reply should fail, got {value:?}"),
            Ok(Err(error)) => error,
            Err(error) => panic!("reply sender should complete: {error}"),
        }
    }

    fn assert_rejection_names_state_and_command(
        error: SessionError,
        expected_state: EngineState,
        expected_command: SessionCommand,
    ) {
        match error {
            SessionError::InvalidTransition { state, command } => {
                assert_eq!(state, expected_state);
                assert_eq!(command, expected_command);
            }
            SessionError::UnsupportedStepMode { state, mode } => {
                assert_eq!(state, expected_state);
                assert_eq!(
                    expected_command,
                    SessionCommand::Step { mode },
                    "unsupported step rejection should name the rejected command mode"
                );
            }
            other => panic!("unexpected rejection type: {other}"),
        }
    }

    #[test]
    fn engine_rejects_invalid_transition_without_changing_state() {
        let scenario = generated_scenario(12);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);

        let error = match engine.apply_command(SessionCommand::Continue) {
            Ok(_) => panic!("continue from loaded should be rejected"),
            Err(error) => error,
        };

        assert_eq!(engine.state(), &EngineState::Loaded);
        assert!(matches!(
            error,
            SessionError::InvalidTransition {
                state: EngineState::Loaded,
                command: SessionCommand::Continue,
            }
        ));
    }

    #[test]
    fn engine_instantiate_runtime_cannot_bypass_state_transitions() {
        let scenario = generated_scenario(15);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }

        let running_error = match engine.instantiate_runtime() {
            Ok(_) => panic!("direct instantiate should be rejected while running"),
            Err(error) => error,
        };
        assert_eq!(engine.state(), &EngineState::Running);
        assert!(matches!(
            running_error,
            SessionError::InvalidEngineState {
                state: EngineState::Running,
                operation: "instantiate_runtime",
            }
        ));

        if let Err(error) = engine.apply_command(SessionCommand::Stop) {
            panic!("stop should enter terminal state: {error}");
        }
        let stopped_error = match engine.instantiate_runtime() {
            Ok(_) => panic!("direct instantiate should be rejected while stopped"),
            Err(error) => error,
        };
        assert_eq!(
            engine.state(),
            &EngineState::Stopped {
                outcome: Outcome::Stopped
            }
        );
        assert!(matches!(
            stopped_error,
            SessionError::InvalidEngineState {
                state: EngineState::Stopped {
                    outcome: Outcome::Stopped
                },
                operation: "instantiate_runtime",
            }
        ));
    }

    #[test]
    fn engine_runtime_cache_reinstantiates_without_observable_change_at_pause_boundary() {
        let scenario = generated_scenario(19);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        let before_snapshot = engine.snapshot();
        let before_runtime = match engine.runtime().cloned() {
            Some(runtime) => runtime,
            None => panic!("started engine should have a runtime cache"),
        };

        let evicted_snapshot = engine.evict_runtime_cache();

        assert_eq!(evicted_snapshot, before_snapshot);
        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), None);

        let rebuilt_snapshot = match engine.reinstantiate_runtime_cache() {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("runtime cache should reinstantiate at pause boundary: {error}"),
        };

        assert_eq!(rebuilt_snapshot, before_snapshot);
        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), Some(&before_runtime));

        let refreshed_snapshot = match engine.refresh_runtime_cache() {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("runtime cache should refresh at pause boundary: {error}"),
        };

        assert_eq!(refreshed_snapshot, before_snapshot);
        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), Some(&before_runtime));
    }

    #[test]
    fn engine_runtime_cache_reinstantiates_after_running_quantum_boundary() {
        let scenario = generated_scenario(20);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, AppendingLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        if let Err(error) = engine.step_quantum() {
            panic!("running engine should complete a quantum: {error}");
        }
        let before_snapshot = engine.snapshot();
        let before_runtime = match engine.runtime().cloned() {
            Some(runtime) => runtime,
            None => panic!("running engine should have a runtime cache"),
        };

        let evicted_snapshot = engine.evict_runtime_cache();

        assert_eq!(before_snapshot.state, EngineState::Running);
        assert_eq!(before_snapshot.configuration.schedule.len(), 1);
        assert_eq!(evicted_snapshot, before_snapshot);
        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), None);

        let rebuilt_snapshot = match engine.reinstantiate_runtime_cache() {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("runtime cache should reinstantiate after quantum: {error}"),
        };

        assert_eq!(rebuilt_snapshot, before_snapshot);
        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), Some(&before_runtime));
    }

    #[test]
    fn engine_runtime_cache_reinstantiate_rejects_loaded_state_without_mutation() {
        let scenario = generated_scenario(21);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        let before_snapshot = engine.snapshot();

        let rebuild_error = match engine.reinstantiate_runtime_cache() {
            Ok(_) => panic!("loaded engine should reject runtime cache reinstantiate"),
            Err(error) => error,
        };

        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), None);
        assert!(matches!(
            rebuild_error,
            SessionError::InvalidEngineState {
                state: EngineState::Loaded,
                operation: "reinstantiate_runtime_cache",
            }
        ));

        let refresh_error = match engine.refresh_runtime_cache() {
            Ok(_) => panic!("loaded engine should reject runtime cache refresh"),
            Err(error) => error,
        };

        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), None);
        assert!(matches!(
            refresh_error,
            SessionError::InvalidEngineState {
                state: EngineState::Loaded,
                operation: "refresh_runtime_cache",
            }
        ));
    }

    #[test]
    fn engine_runtime_cache_reinstantiate_rejects_never_instantiated_stopped_state() {
        let scenario = generated_scenario(22);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Stop) {
            panic!("loaded engine should stop without instantiating runtime: {error}");
        }
        let before_snapshot = engine.snapshot();

        let rebuild_error = match engine.reinstantiate_runtime_cache() {
            Ok(_) => panic!("never-instantiated stopped engine should reject cache rebuild"),
            Err(error) => error,
        };

        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), None);
        assert!(matches!(
            rebuild_error,
            SessionError::InvalidEngineState {
                state: EngineState::Stopped {
                    outcome: Outcome::Stopped
                },
                operation: "reinstantiate_runtime_cache",
            }
        ));
    }

    #[test]
    fn engine_runtime_cache_refresh_preserves_cache_when_reinstantiate_fails() {
        let scenario = generated_scenario(23);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        let before_snapshot = engine.snapshot();
        let before_runtime = match engine.runtime().cloned() {
            Some(runtime) => runtime,
            None => panic!("started engine should have a runtime cache"),
        };
        engine.graph = TemporalGraph::empty();

        let refresh_error = match engine.refresh_runtime_cache() {
            Ok(_) => panic!("runtime refresh should fail without a replay source"),
            Err(error) => error,
        };

        assert!(matches!(refresh_error, SessionError::Engine(_)));
        assert_eq!(engine.snapshot(), before_snapshot);
        assert_eq!(engine.runtime(), Some(&before_runtime));
    }

    #[tokio::test]
    async fn session_actor_services_pending_command_before_quantum() {
        let scenario = generated_scenario(13);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, CountingLoop::default());
        let (sender, receiver) = mpsc::channel(8);
        for command in [
            SessionCommand::Start,
            SessionCommand::Continue,
            SessionCommand::Pause,
            SessionCommand::Stop,
        ] {
            if let Err(error) = sender.send(command).await {
                panic!("command should enqueue: {error}");
            }
        }

        let report = match SessionActor::new(engine, receiver).run().await {
            Ok(report) => report,
            Err(error) => panic!("actor should stop cleanly: {error}"),
        };

        assert_eq!(report.quanta, 0);
        assert_eq!(report.commands_applied, 4);
        assert_eq!(
            report.final_snapshot.state,
            EngineState::Stopped {
                outcome: Outcome::Stopped
            }
        );
    }

    #[tokio::test]
    async fn session_actor_steps_one_quantum_then_yields() {
        let scenario = generated_scenario(14);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, AppendingLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("running actor iteration should step: {error}");
        }
        if let Err(error) = sender.send(SessionCommand::Stop).await {
            panic!("stop should enqueue after first yield: {error}");
        }
        let report = match actor.run().await {
            Ok(report) => report,
            Err(error) => panic!("actor should stop after yielded quantum: {error}"),
        };

        assert_eq!(report.quanta, 1);
        assert_eq!(report.yielded_after_quanta, 1);
        assert_eq!(report.final_snapshot.configuration.schedule.len(), 1);
    }

    #[tokio::test]
    async fn session_actor_yields_after_command_driven_step() {
        let scenario = generated_scenario(16);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, AppendingLoop::default());
        let (sender, receiver) = mpsc::channel(4);
        for command in [
            SessionCommand::Start,
            SessionCommand::Step {
                mode: StepMode::Quantum,
            },
            SessionCommand::Stop,
        ] {
            if let Err(error) = sender.send(command).await {
                panic!("command should enqueue: {error}");
            }
        }

        let report = match SessionActor::new(engine, receiver).run().await {
            Ok(report) => report,
            Err(error) => panic!("actor should stop after command-driven step: {error}"),
        };

        assert_eq!(report.quanta, 1);
        assert_eq!(report.yielded_after_quanta, 1);
        assert_eq!(
            report.final_snapshot.state,
            EngineState::Stopped {
                outcome: Outcome::Stopped
            }
        );
    }

    #[tokio::test]
    async fn session_actor_command_driven_step_acknowledges_preexisting_running_controls() {
        let scenario = generated_scenario(24);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, AppendingLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = sender.send(SessionCommand::Snapshot).await {
            panic!("snapshot should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("snapshot command should be accepted while running: {error}");
        }
        assert_eq!(actor.control_acknowledgements(), 0);
        assert_eq!(actor.engine().pending_control_len(), 1);

        if let Err(error) = sender
            .send(SessionCommand::Step {
                mode: StepMode::Quantum,
            })
            .await
        {
            panic!("quantum step should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running quantum step should drain pending control: {error}");
        }

        assert_eq!(actor.control_acknowledgements(), 1);
        assert_eq!(actor.engine().pending_control_len(), 0);
        assert_eq!(actor.engine().quanta(), 1);
        assert!(matches!(
            actor.engine().state(),
            EngineState::Paused {
                reason: PauseReason::StepComplete {
                    mode: StepMode::Quantum
                }
            }
        ));
    }

    #[tokio::test]
    async fn session_actor_paused_step_acknowledges_preexisting_running_controls() {
        let scenario = generated_scenario(25);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, AppendingLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = sender.send(SessionCommand::Snapshot).await {
            panic!("snapshot should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("snapshot command should be accepted while running: {error}");
        }
        assert_eq!(actor.control_acknowledgements(), 0);
        assert_eq!(actor.engine().pending_control_len(), 1);

        if let Err(error) = sender.send(SessionCommand::Pause).await {
            panic!("pause should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("pause command should be accepted while running: {error}");
        }
        assert_eq!(actor.control_acknowledgements(), 1);
        assert_eq!(actor.engine().pending_control_len(), 1);
        assert!(matches!(
            actor.engine().state(),
            EngineState::Paused {
                reason: PauseReason::UserRequested
            }
        ));

        if let Err(error) = sender
            .send(SessionCommand::Step {
                mode: StepMode::Quantum,
            })
            .await
        {
            panic!("quantum step should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("paused quantum step should drain pending control: {error}");
        }

        assert_eq!(actor.control_acknowledgements(), 2);
        assert_eq!(actor.engine().pending_control_len(), 0);
        assert_eq!(actor.engine().quanta(), 1);
        assert!(matches!(
            actor.engine().state(),
            EngineState::Paused {
                reason: PauseReason::StepComplete {
                    mode: StepMode::Quantum
                }
            }
        ));
    }

    #[test]
    fn session_actor_live_snapshot_starts_as_loaded_without_mailbox() {
        let scenario = generated_scenario(17);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, AppendingLoop::default());
        let (_sender, receiver) = mpsc::channel(4);
        let actor = SessionActor::new(engine, receiver);
        let live = actor.live_snapshot();

        let view = live.read();

        assert_eq!(view.state_kind, LiveStateKind::Loaded);
        assert_eq!(view.virtual_time, VirtualTime { ticks: 0 });
        assert_eq!(view.event_log_len, 0);
        assert_eq!(view.quanta_stepped, 0);
    }

    #[tokio::test]
    async fn session_actor_live_snapshot_publishes_monotone_progress() {
        let scenario = generated_scenario(18);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, AppendingLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);
        let live = actor.live_snapshot();
        let before = live.read();

        if let Err(error) = actor.run_once().await {
            panic!("running actor iteration should step: {error}");
        }
        let after = live.read();

        assert_eq!(before.state_kind, LiveStateKind::Running);
        assert_eq!(before.quanta_stepped, 0);
        assert_eq!(after.state_kind, LiveStateKind::Running);
        assert!(after.quanta_stepped > before.quanta_stepped);
        assert!(after.virtual_time >= before.virtual_time);
    }

    #[test]
    fn engine_rejects_event_log_offset_mismatch() {
        let scenario = generated_scenario(19);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, InvalidEventLogLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }

        let error = engine
            .step_quantum()
            .expect_err("invalid event-log offset must be rejected");

        assert!(matches!(
            error,
            SessionError::EventLogOffsetMismatch {
                current: 0,
                emitted: 0,
                next: 1,
            }
        ));
    }

    #[test]
    fn engine_rejects_event_log_offset_regression() {
        let scenario = generated_scenario(20);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, RegressingEventLogLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }

        engine
            .step_quantum()
            .expect("first event-log offset should be accepted");
        let error = engine
            .step_quantum()
            .expect_err("regressed event-log offset must be rejected");

        assert!(matches!(
            error,
            SessionError::EventLogOffsetRegression {
                current: 1,
                next: 0,
            }
        ));
    }

    struct StubLoop;

    impl QuantumLoop for StubLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: 0 },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: Default::default(),
            })
        }
    }

    #[derive(Default)]
    struct CountingLoop {
        quanta: u64,
    }

    impl QuantumLoop for CountingLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            self.quanta = self.quanta.saturating_add(1);
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: self.quanta },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: Default::default(),
            })
        }
    }

    #[derive(Default)]
    struct AppendingLoop {
        quanta: u64,
    }

    struct InvalidEventLogLoop;

    impl QuantumLoop for InvalidEventLogLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: 1 },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 1),
            })
        }
    }

    #[derive(Default)]
    struct RegressingEventLogLoop {
        quanta: u64,
    }

    impl QuantumLoop for RegressingEventLogLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            self.quanta = self.quanta.saturating_add(1);
            let (entries, offset) = if self.quanta == 1 {
                (
                    vec![test_event_log_entry(0)],
                    crucible::EventLogOffset::new(Default::default(), 0, 1),
                )
            } else {
                (Vec::new(), crucible::EventLogOffset::default())
            };
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: self.quanta },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: entries,
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: offset,
            })
        }
    }

    impl QuantumLoop for AppendingLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            self.quanta = self.quanta.saturating_add(1);
            let decision = generated_decision(self.quanta);
            let configuration = step(&request.configuration, decision.clone());
            Ok(QuantumOutcome {
                configuration,
                frontier: VirtualTime { ticks: self.quanta },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: vec![decision],
                event_log_entries: vec![test_event_log_entry(self.quanta - 1)],
                event_log_segment_bytes: vec![b'x'],
                event_log_segment_text: String::from("x"),
                event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
                event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, self.quanta),
            })
        }
    }

    fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
        let genesis = Configuration::genesis(scenario.clone());
        match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(&genesis)) {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        }
    }

    fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
        let checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            None,
            VirtualTime::default(),
            std::collections::BTreeMap::new(),
            CheckpointKind::Fat,
            std::collections::BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("genesis checkpoint should be recorded-shaped: {error}"));
        GenesisCheckpoint { checkpoint }
    }

    fn generated_scenario(seed: u64) -> ScenarioDef {
        ScenarioDef::from_canonical_material_with_seed(
            "crucible.session.test.scenario",
            &format!("seed={seed}"),
            Seed::from_u64(seed),
        )
    }

    fn test_event_log_entry(sequence: u64) -> crucible::SchedulerEventLogEntry {
        crucible::test_support::condition_boundary_entry_for_test(
            sequence,
            VirtualTime { ticks: sequence },
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        )
    }

    fn generated_decision(seed: u64) -> Decision {
        let node = scheduler_node("control-plane");
        Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: seed },
            order: vec![EventKey::new(
                VirtualTime { ticks: seed },
                node.clone(),
                node,
                seed,
            )],
        })
    }

    fn scheduler_node(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: NodeId {
                name: name.to_owned(),
            },
            kind: SchedulingNodeKind::ControlPlane,
        }
    }
}
