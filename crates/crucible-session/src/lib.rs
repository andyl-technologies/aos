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

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    Configuration, ControlOperation, ControlOperationKind, EngineError, Fault, FaultTag,
    QuantumLoop, QuantumOutcome, QuantumRequest, RuntimeState, SchedulerError,
    SchedulerEventLogEntry, TemporalGraph, VirtualTime, instantiate,
};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

/// Number of live event-log frames retained by the broadcast tail.
pub const SESSION_EVENT_LOG_BROADCAST_CAPACITY: usize = 1024;

/// Maximum number of retained event-log frames cloned by one stream receive.
pub const SESSION_EVENT_LOG_REPLAY_BATCH_SIZE: usize = 64;

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

/// A bounded step mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepMode {
    /// Advance exactly one scheduler quantum.
    Quantum,
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
    /// Fork from the current boundary configuration.
    Fork,
    /// Inject a deterministic control-plane fault at the next boundary.
    Inject,
    /// Inject or replace a full-taxonomy fault at the next boundary.
    InjectFault {
        /// Stable handle used for later healing.
        tag: FaultTag,
        /// Full fault taxonomy value to activate.
        fault: Fault,
    },
    /// Heal a full-taxonomy fault at the next boundary.
    HealFault {
        /// Stable handle naming the active fault.
        tag: FaultTag,
    },
    /// Transition to a terminal operator-stopped state.
    Stop,
    /// Read the current boundary state without mutation.
    Query,
}

impl SessionCommand {
    /// Returns whether the command is observation-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Self::Query | Self::Snapshot)
    }

    const fn is_control_acknowledged(&self) -> bool {
        matches!(
            self,
            Self::Pause
                | Self::Snapshot
                | Self::Fork
                | Self::Inject
                | Self::InjectFault { .. }
                | Self::HealFault { .. }
                | Self::Query
        )
    }

    const fn requires_running_quantum_ack(&self) -> bool {
        matches!(
            self,
            Self::Snapshot
                | Self::Fork
                | Self::Inject
                | Self::InjectFault { .. }
                | Self::HealFault { .. }
                | Self::Query
        )
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
/// cache, the temporal graph used for instantiation and checkpoints, and the
/// single [`QuantumLoop`] boundary that performs virtual-time advancement.
pub struct Engine<L> {
    configuration: Configuration,
    runtime: Option<RuntimeState>,
    runtime_instantiated: bool,
    state: EngineState,
    graph: TemporalGraph,
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
            SessionCommand::Step {
                mode: StepMode::Quantum,
            } => {
                if matches!(self.state, EngineState::Paused { .. }) {
                    let previous = self.state.clone();
                    self.state = EngineState::Running;
                    if let Err(error) = self.step_quantum() {
                        self.state = previous;
                        return Err(error);
                    }
                    self.state = EngineState::Paused {
                        reason: PauseReason::StepComplete {
                            mode: StepMode::Quantum,
                        },
                    };
                    Ok(self.snapshot())
                } else {
                    Err(self.invalid_transition(command.clone()))
                }
            }
            SessionCommand::Snapshot => {
                if matches!(self.state, EngineState::Running) {
                    self.admit_control_operation(ControlOperationKind::Snapshot);
                }
                Ok(self.snapshot())
            }
            SessionCommand::Fork => match self.state {
                EngineState::Running | EngineState::Paused { .. } | EngineState::Stopped { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.admit_control_operation(ControlOperationKind::Fork);
                    }
                    Ok(self.snapshot())
                }
                EngineState::Loaded => Err(self.invalid_transition(command.clone())),
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
            SessionCommand::InjectFault { tag, fault } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.admit_control_operation(ControlOperationKind::InjectFault {
                            tag: tag.clone(),
                            fault: fault.clone(),
                        });
                    }
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::HealFault { tag } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.admit_control_operation(ControlOperationKind::HealFault {
                            tag: tag.clone(),
                        });
                    }
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
            SessionCommand::Query => {
                if matches!(self.state, EngineState::Running) {
                    self.admit_control_operation(ControlOperationKind::Query);
                }
                Ok(self.snapshot())
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
    deferred: VecDeque<SessionCommand>,
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
            deferred: VecDeque::new(),
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

    /// Queues a command to be applied before the next running quantum.
    pub fn defer_boundary_command(&mut self, command: SessionCommand) {
        self.deferred.push_back(command);
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
                self.drain_read_only_commands().await?;
                Ok(())
            }
        }
    }

    fn next_boundary_command(&mut self) -> Result<Option<SessionCommand>, SessionError> {
        if let Some(command) = self.deferred.pop_front() {
            return Ok(Some(command));
        }

        match self.mailbox.try_recv() {
            Ok(command) => Ok(Some(command)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(SessionError::ChannelClosed),
        }
    }

    async fn apply_command(&mut self, command: SessionCommand) -> Result<(), SessionError> {
        let quanta_before = self.engine.quanta();
        let quantum_ack = matches!(self.engine.state(), EngineState::Running)
            && command.requires_running_quantum_ack();
        let control_acknowledged = command.is_control_acknowledged();
        self.engine.apply_command(command)?;
        let entries = self.engine.drain_event_log_entries();
        self.event_log.append_entries(&entries);
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

    async fn drain_read_only_commands(&mut self) -> Result<(), SessionError> {
        loop {
            match self.mailbox.try_recv() {
                Ok(command) if command.is_read_only() => self.apply_command(command).await?,
                Ok(_) | Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{
        Checkpoint, CheckpointKind, Decision, DeliveryOrderDecision, EventKey, GenesisCheckpoint,
        NodeId, ScenarioDef, SchedulerNodeId, SchedulingNodeKind, Seed, VirtualTime, step,
    };

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
