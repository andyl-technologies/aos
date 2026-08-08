//! Asynchronous session actor, mailbox scheduling, and live state mirrors.

use super::*;
use std::time::Duration;

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
        state: Box<EngineState>,
        /// The command that was rejected.
        command: Box<SessionCommand>,
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
    /// A replay artifact named a control boundary before the replay position.
    #[error(
        "control replay boundary mismatch: current quanta={current_quanta} recorded quanta={recorded_quanta}"
    )]
    ControlReplayBoundaryMismatch {
        /// Current replay quantum boundary.
        current_quanta: u64,
        /// Quantum boundary recorded in the replay artifact.
        recorded_quanta: u64,
    },
    /// A replay artifact control entry did not match the current frontier.
    #[error("control replay frontier mismatch: current={current:?} recorded={recorded:?}")]
    ControlReplayFrontierMismatch {
        /// Current replay virtual-time frontier.
        current: VirtualTime,
        /// Virtual-time frontier recorded in the replay artifact.
        recorded: VirtualTime,
    },
    /// A replay artifact has an invalid scheduler-control batch shape.
    #[error("control replay batch mismatch: sequence={sequence} scheduler_batch={scheduler_batch}")]
    ControlReplayBatchMismatch {
        /// Control-log sequence where the invalid batch shape was observed.
        sequence: u64,
        /// Scheduler batch identifier recorded on the invalid entry.
        scheduler_batch: u64,
    },
    /// Replay reached a different final boundary snapshot than the artifact recorded.
    #[error("control replay final snapshot mismatch: expected={expected:?} actual={actual:?}")]
    ControlReplayFinalSnapshotMismatch {
        /// Final boundary snapshot recorded in the replay artifact.
        expected: Box<EngineSnapshot>,
        /// Final boundary snapshot produced by replay.
        actual: Box<EngineSnapshot>,
    },
    /// Breakpoint condition evaluation could not build a checked log prefix.
    #[error("breakpoint condition prefix is invalid: {reason}")]
    BreakpointConditionPrefix {
        /// Stable debug description of the prefix validation failure.
        reason: String,
    },
    /// A breakpoint action used an event-graph action variant the session does not support.
    #[error("unsupported breakpoint action {action}")]
    UnsupportedBreakpointAction {
        /// Stable action kind label.
        action: &'static str,
    },
    /// A breakpoint fault action cannot be mapped into a boundary scheduler control.
    #[error("unsupported breakpoint fault for action {action}: {reason}")]
    UnsupportedBreakpointFault {
        /// Stable action kind label.
        action: &'static str,
        /// Stable reason for rejecting the fault action.
        reason: &'static str,
    },
    /// A command referenced a breakpoint id that is not registered.
    #[error("breakpoint {id} is not registered")]
    BreakpointNotFound {
        /// Missing breakpoint id.
        id: BreakpointId,
    },
    /// A debug command that needs an active gdb attach was issued before attach.
    #[error("debug operation {operation} requires an active gdb attach")]
    DebugAttachRequired {
        /// Debug operation that requires an attach.
        operation: &'static str,
    },
    /// A command would advance or mutate from a repositioned debug coordinate.
    #[error("debug operation {operation} requires a NON-CANONICAL debug branch first")]
    DebugNonCanonicalBranchRequired {
        /// Operation blocked until branch metadata is recorded.
        operation: &'static str,
    },
    /// Guest introspection targeted a node without explicit white-box opt-in.
    #[error("guest introspection is not authorized for node `{node}`")]
    GuestIntrospectionNotAuthorized {
        /// Node whose authored policy did not enable white-box access.
        node: String,
    },
    /// Fork-time activation did not produce a valid feature advertisement.
    #[error("guest introspection activation failed for node `{node}`: {reason}")]
    GuestIntrospectionActivation {
        /// Node whose dormant agent was activated.
        node: String,
        /// Stable activation or negotiation failure detail.
        reason: String,
    },
    /// A guest request requires a capability that the activated agent did not advertise.
    #[error("guest introspection capability `{capability}` is unavailable for node `{node}`")]
    GuestIntrospectionCapabilityUnavailable {
        /// Target guest node.
        node: String,
        /// Stable protocol capability label.
        capability: &'static str,
    },
    /// Opening another guest channel would exceed the negotiated per-node limit.
    #[error("guest introspection channel limit {max_channels} is exhausted for node `{node}`")]
    GuestIntrospectionChannelLimit {
        /// Target guest node.
        node: String,
        /// Agent-advertised maximum concurrent channels.
        max_channels: u16,
    },
    /// A resumed session does not carry event history before its checkpoint boundary.
    #[error(
        "debug operation {operation} reached the resumed event-history floor at sequence {floor}"
    )]
    DebugHistoryUnavailable {
        /// Debug operation that requires unavailable pre-resume history.
        operation: &'static str,
        /// First scheduler event sequence observable by this actor.
        floor: u64,
    },
    /// The runtime reported success for a different debug target than requested.
    #[error("debug runtime reposition evidence mismatch: {0}")]
    DebugRuntimeRepositionMismatch(Box<DebugRuntimeRepositionEvidenceMismatch>),
}

/// Expected and actual identities from a mismatched runtime replacement report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRuntimeRepositionEvidenceMismatch {
    /// Node required by the session transaction.
    pub expected_node: NodeId,
    /// Current configuration required by the session transaction.
    pub expected_previous_configuration: ContentHash,
    /// Target configuration required by the session transaction.
    pub expected_configuration: ContentHash,
    /// Target checkpoint required by the session transaction.
    pub expected_checkpoint: ContentHash,
    /// Previous private QEMU endpoint that must not remain selected.
    pub expected_previous_qemu_gdbstub: DebugGdbEndpoint,
    /// Node claimed by the backend.
    pub actual_node: NodeId,
    /// Current configuration claimed by the backend.
    pub actual_previous_configuration: ContentHash,
    /// Target configuration claimed by the backend.
    pub actual_configuration: ContentHash,
    /// Checkpoint claimed by the backend.
    pub actual_checkpoint: ContentHash,
    /// Private QEMU endpoint claimed by the backend.
    pub actual_qemu_gdbstub: DebugGdbEndpoint,
    /// Gateway generation claimed by the backend.
    pub actual_gateway_generation: u64,
}

impl fmt::Display for DebugRuntimeRepositionEvidenceMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "expected node={:?} previous={:?} configuration={:?} checkpoint={:?} previous_qemu_gdbstub={:?}, actual node={:?} previous={:?} configuration={:?} checkpoint={:?} qemu_gdbstub={:?} gateway_generation={}",
            self.expected_node,
            self.expected_previous_configuration,
            self.expected_configuration,
            self.expected_checkpoint,
            self.expected_previous_qemu_gdbstub,
            self.actual_node,
            self.actual_previous_configuration,
            self.actual_configuration,
            self.actual_checkpoint,
            self.actual_qemu_gdbstub,
            self.actual_gateway_generation,
        )
    }
}

#[path = "actor/recoverability.rs"]
mod recoverability;

pub(super) use recoverability::*;
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

/// Deterministic record of a command applied at a session boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionControlLogEntry {
    /// Monotone session-local control-log sequence.
    pub sequence: u64,
    /// Payload-free command kind applied at the boundary.
    pub command: SessionCommandKind,
    /// Command payload admitted at the boundary, excluding reply routes.
    pub payload: SessionControlPayload,
    /// Virtual-time frontier where the command was applied.
    pub frontier: VirtualTime,
    /// Number of scheduler quanta completed before the command was applied.
    pub quanta: u64,
    /// Event-log sequence immediately after the causal prefix visible to the command.
    pub event_log_sequence_before: u64,
    /// Terminal result recorded for the boundary-control entry.
    pub result: SessionControlResult,
    /// Scheduler-control batch identifier, or zero when no scheduler payload was applied.
    pub scheduler_batch: u64,
    /// Scheduler control payload admitted by this command, when any.
    pub scheduler_control: Option<ControlOperationKind>,
}

/// Result recorded for a deterministic boundary-control log entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionControlResult {
    /// The command was accepted and included in the deterministic reproduction stream.
    Accepted,
}

/// Reply-free command payload recorded in the deterministic control log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionControlPayload {
    /// A command kind without additional stable payload.
    CommandKind {
        /// Recorded command kind.
        command: SessionCommandKind,
    },
    /// Fork payload naming the source checkpoint selection.
    Fork {
        /// Fork source checkpoint.
        from: CheckpointRef,
    },
    /// Full fault injection payload.
    InjectFault {
        /// Fault activation payload.
        spec: FaultSpec,
    },
    /// Fault heal payload.
    HealFault {
        /// Stable fault handle to heal.
        tag: FaultTag,
    },
    /// Breakpoint registration payload.
    SetBreakpoint {
        /// Breakpoint specification.
        spec: BreakpointSpec,
    },
    /// Breakpoint removal payload.
    RemoveBreakpoint {
        /// Breakpoint id to remove.
        id: BreakpointId,
    },
    /// Savepoint creation payload.
    CreateSavepoint {
        /// Stable operator label.
        label: String,
    },
}

impl SessionControlPayload {
    pub(super) fn from(command: &SessionCommand) -> Self {
        match command {
            SessionCommand::Acknowledge { command, .. } => Self::from(command),
            SessionCommand::Fork { from, .. } => Self::Fork { from: *from },
            SessionCommand::InjectFault { spec, .. } => Self::InjectFault { spec: spec.clone() },
            SessionCommand::HealFault { tag, .. } => Self::HealFault { tag: tag.clone() },
            SessionCommand::SetBreakpoint { spec, .. } => {
                Self::SetBreakpoint { spec: spec.clone() }
            }
            SessionCommand::RemoveBreakpoint { id, .. } => Self::RemoveBreakpoint { id: *id },
            SessionCommand::CreateSavepoint { label, .. } => Self::CreateSavepoint {
                label: label.clone(),
            },
            command => Self::CommandKind {
                command: SessionCommandKind::from(command),
            },
        }
    }

    pub(super) fn from_control_or_kind(
        command: SessionCommandKind,
        control: Option<&ControlOperationKind>,
    ) -> Self {
        match control {
            Some(ControlOperationKind::InjectFault { tag, fault }) => Self::InjectFault {
                spec: FaultSpec::new(tag.clone(), fault.clone()),
            },
            Some(ControlOperationKind::HealFault { tag }) => Self::HealFault { tag: tag.clone() },
            _ => Self::CommandKind { command },
        }
    }
}

/// Deterministic record of one breakpoint firing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakpointFiring {
    /// Monotone session-local breakpoint-firing sequence.
    pub sequence: u64,
    /// Actor-owned breakpoint identifier that fired.
    pub id: BreakpointId,
    /// Shared 17a condition that evaluated true.
    pub predicate: Condition,
    /// Disposition applied at the boundary.
    pub disposition: BreakpointDisposition,
    /// Virtual-time frontier where the breakpoint fired.
    pub frontier: VirtualTime,
    /// Number of scheduler quanta completed before the firing was applied.
    pub quanta: u64,
    /// Scheduler control payloads applied by an action disposition, when any.
    pub scheduler_controls: Vec<ControlOperationKind>,
}

/// The single owning session actor.
///
/// `SessionActor` owns the [`Engine`], polls the command mailbox at state
/// boundaries, drives at most one scheduler quantum per running-loop iteration,
/// and yields after each applied command or scheduler quantum.
pub struct SessionActor<L> {
    pub(super) engine: Engine<L>,
    pub(super) mailbox: mpsc::Receiver<SessionCommand>,
    pub(super) live: Arc<LiveSnapshot>,
    pub(super) event_log: SessionEventLog,
    pub(super) reproduction_log: SessionReproductionLog,
    pub(super) state_transitions: SessionStateTransitionBus,
    pub(super) last_published_state: EngineState,
    pub(super) fork_loop_factory: Option<SessionForkLoopFactory<L>>,
    pub(super) condition_event_log: Vec<SchedulerEventLogEntry>,
    pub(super) debug_event_coordinates: BTreeMap<u64, Configuration>,
    pub(super) debug_history_floor: u64,
    pub(super) debug_index_configuration: Configuration,
    pub(super) commands_applied: u64,
    pub(super) yielded_after_quanta: u64,
    pub(super) control_acknowledgements: u64,
    pub(super) state_transition_sequence: u64,
    pub(super) terminal_command_keepalive: bool,
    pub(super) terminal_shutdown_requested: bool,
    pub(super) gdb_run_control_stop: Option<Vec<u8>>,
}

impl<L> SessionActor<L> {
    /// Creates a session actor from an engine and command mailbox.
    #[must_use]
    pub fn new(engine: Engine<L>, mailbox: mpsc::Receiver<SessionCommand>) -> Self {
        Self::new_with_optional_fork_loop_factory(engine, mailbox, None)
    }

    /// Creates a session actor with a child-loop factory for fork commands.
    ///
    /// The factory is called only after the fork source checkpoint has been
    /// resolved. It must return the [`QuantumLoop`] that the independently spawned
    /// child actor should use.
    #[must_use]
    pub fn new_with_fork_loop_factory<F>(
        engine: Engine<L>,
        mailbox: mpsc::Receiver<SessionCommand>,
        factory: F,
    ) -> Self
    where
        F: Fn(SessionForkRequest) -> L + Send + Sync + 'static,
    {
        Self::new_with_optional_fork_loop_factory(engine, mailbox, Some(Arc::new(factory)))
    }

    fn new_with_optional_fork_loop_factory(
        engine: Engine<L>,
        mailbox: mpsc::Receiver<SessionCommand>,
        fork_loop_factory: Option<SessionForkLoopFactory<L>>,
    ) -> Self {
        let last_published_state = engine.state().clone();
        let debug_history_floor = u64::try_from(engine.event_log_len()).unwrap_or(u64::MAX);
        let debug_index_configuration = engine.snapshot().configuration;
        let live = Arc::new(LiveSnapshot::new(&engine.snapshot()));
        Self {
            engine,
            mailbox,
            live,
            event_log: SessionEventLog::new(),
            reproduction_log: SessionReproductionLog::new(),
            state_transitions: SessionStateTransitionBus::new(),
            last_published_state,
            fork_loop_factory,
            condition_event_log: Vec::new(),
            debug_event_coordinates: BTreeMap::new(),
            debug_history_floor,
            debug_index_configuration,
            commands_applied: 0,
            yielded_after_quanta: 0,
            control_acknowledgements: 0,
            state_transition_sequence: 0,
            terminal_command_keepalive: false,
            terminal_shutdown_requested: false,
            gdb_run_control_stop: None,
        }
    }

    /// Keeps a terminal actor alive to accept terminal observation commands.
    ///
    /// When enabled, [`SessionActor::run`] waits for an acknowledged `Stop`
    /// command after reaching `Stopped` instead of returning as soon as the
    /// already-queued terminal commands have been drained.
    #[must_use]
    pub const fn with_terminal_command_keepalive(mut self, enabled: bool) -> Self {
        self.terminal_command_keepalive = enabled;
        self
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

    /// Reads the actor's lock-free live status mirror.
    #[must_use]
    pub fn live_status(&self) -> LiveSnapshotView {
        self.live.read()
    }

    /// Returns a cloneable event-log hub for cursor subscribers.
    #[must_use]
    pub fn event_log(&self) -> SessionEventLog {
        self.event_log.clone()
    }

    /// Returns a cloneable snapshot handle for the deterministic command stream.
    #[must_use]
    pub fn reproduction_log(&self) -> SessionReproductionLog {
        self.reproduction_log.clone()
    }

    /// Subscribes to session event-log entries from `cursor` onward.
    #[must_use]
    pub fn event_log_stream(&self, cursor: EventLogCursor) -> SessionEventLogStream {
        self.event_log.subscribe(cursor)
    }

    /// Returns a cloneable state-transition bus for subscribers.
    #[must_use]
    pub fn state_transition_bus(&self) -> SessionStateTransitionBus {
        self.state_transitions.clone()
    }

    /// Subscribes to future state transitions.
    #[must_use]
    pub fn state_transition_stream(&self) -> SessionStateTransitionStream {
        self.state_transitions.subscribe()
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

    fn publish_live_snapshot(&mut self) {
        let before_state = self.last_published_state.clone();
        let before = self.live.read();
        let snapshot = self.engine.snapshot();
        let after_state = snapshot.state.clone();
        let state_changed = before_state != after_state;
        let state_transition_sequence = if state_changed {
            self.state_transition_sequence.saturating_add(1)
        } else {
            self.state_transition_sequence
        };
        self.live.publish(
            &snapshot,
            self.control_acknowledgements,
            state_transition_sequence,
        );
        let after = self.live.read();
        if state_changed {
            self.state_transition_sequence = state_transition_sequence;
            self.state_transitions.publish(SessionStateTransitionFrame {
                sequence: self.state_transition_sequence,
                from_state: before_state,
                to_state: after_state.clone(),
                from: before,
                to: after,
            });
        }
        self.last_published_state = after_state;
    }

    pub(super) fn append_event_log_entries(
        &mut self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SessionError> {
        self.append_event_log_entries_with_history_policy(entries, false)
    }

    pub(super) fn append_event_log_entries_preserving_debug_history(
        &mut self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SessionError> {
        self.append_event_log_entries_with_history_policy(entries, true)
    }

    fn append_event_log_entries_with_history_policy(
        &mut self,
        entries: &[SchedulerEventLogEntry],
        preserve_debug_history: bool,
    ) -> Result<(), SessionError> {
        let base_len = self.engine.event_log_len().saturating_sub(entries.len());
        self.event_log.truncate_to_len(base_len);
        let base_sequence = u64::try_from(base_len).unwrap_or(u64::MAX);
        if !preserve_debug_history && !entries.is_empty() {
            self.condition_event_log
                .retain(|entry| entry.sequence() < base_sequence);
            self.debug_event_coordinates
                .retain(|sequence, _| *sequence < base_sequence);
        }
        self.event_log.append_entries(entries);
        let current = self.engine.snapshot().configuration;
        if preserve_debug_history {
            self.debug_index_configuration = current;
            return Ok(());
        }
        self.condition_event_log.extend(entries.iter().cloned());
        let mut coordinate = self.debug_index_configuration.clone();
        for entry in entries {
            if let SchedulerEventLogPayload::Decision(decision) = entry.payload()
                && current.schedule.decisions().get(coordinate.schedule.len()) == Some(decision)
            {
                coordinate = Configuration {
                    def: current.def.clone(),
                    schedule: current
                        .schedule
                        .prefix(coordinate.schedule.len().saturating_add(1))
                        .map_err(EngineError::SchedulePrefix)?,
                };
            }
            if matches!(
                entry.payload(),
                SchedulerEventLogPayload::EvaluationBoundary(
                    SchedulerEvaluationBoundaryKind::Quantum
                )
            ) {
                coordinate = current.clone();
            }
            self.debug_event_coordinates
                .insert(entry.sequence(), coordinate.clone());
        }
        self.debug_index_configuration = current;
        Ok(())
    }

    pub(super) fn debug_current_event_limit(&self, current: &Configuration) -> Option<u64> {
        let _ = current;
        self.engine
            .debug_event_cursor()
            .or_else(|| u64::try_from(self.engine.event_log_len()).ok())
    }

    fn condition_event_log_prefix(&self) -> Vec<SchedulerEventLogEntry> {
        self.condition_event_log
            .iter()
            .take(self.engine.event_log_len())
            .cloned()
            .collect()
    }

    fn sync_reproduction_log(&self) {
        self.reproduction_log
            .sync_from_boundary_log(self.engine.boundary_control_log());
    }

    fn terminalize_actor_error(&mut self, error: &SessionError) {
        self.engine.stop_after_actor_crash(error.to_string());
        self.sync_reproduction_log();
        self.publish_live_snapshot();
    }
}

pub(super) fn split_acknowledged_command(
    command: SessionCommand,
) -> (SessionCommand, Option<CommandReply<()>>) {
    match command {
        SessionCommand::Acknowledge { command, reply } => (*command, Some(reply)),
        command => (command, None),
    }
}

fn gdb_run_control_command(packet: &[u8]) -> Option<SessionCommand> {
    if packet == [0x03] {
        return Some(SessionCommand::Pause);
    }
    if packet == b"c" {
        return Some(SessionCommand::Continue);
    }
    if packet == b"s" {
        return Some(SessionCommand::Step {
            mode: StepMode::Quantum,
        });
    }
    let actions = packet.strip_prefix(b"vCont;")?.split(|byte| *byte == b';');
    let mut saw_continue = false;
    let mut saw_step = false;
    for action in actions {
        let operation = match action.iter().position(|byte| *byte == b':') {
            Some(separator) if separator + 1 < action.len() => &action[..separator],
            Some(_) => return None,
            None => action,
        };
        match operation {
            b"c" => saw_continue = true,
            b"s" => saw_step = true,
            _ => return None,
        }
    }
    if saw_step {
        // In all-stop mode GDB asks the selected thread to step and all other
        // threads to continue. The deterministic scheduler implements that
        // request as one quantum followed by a correlated all-stop reply.
        Some(SessionCommand::Step {
            mode: StepMode::Quantum,
        })
    } else if saw_continue {
        Some(SessionCommand::Continue)
    } else {
        None
    }
}

pub(super) fn acknowledged_stop_command(command: &SessionCommand) -> bool {
    matches!(
        command,
        SessionCommand::Acknowledge { command, .. } if matches!(command.as_ref(), SessionCommand::Stop)
    )
}

pub(super) fn complete_acknowledgement(
    acknowledgement: Option<CommandReply<()>>,
    result: &Result<(), SessionError>,
) {
    let Some(reply) = acknowledgement else {
        return;
    };
    match result {
        Ok(()) => reply.complete(Ok(())),
        Err(error) => reply.complete(Err(error.clone())),
    }
}

impl<L> SessionActor<L>
where
    L: QuantumLoop + Send + 'static,
{
    /// Runs the actor until its terminal drain policy completes.
    ///
    /// By default, the actor returns after reaching [`EngineState::Stopped`]
    /// and draining commands that were already queued. Actors configured with
    /// [`SessionActor::with_terminal_command_keepalive`] keep serving terminal
    /// observation commands until an acknowledged `Stop` shutdown command
    /// arrives.
    ///
    /// # Errors
    ///
    /// Autonomous execution failures become a terminal crashed outcome. Returns
    /// an error when command processing fails or terminal command service fails.
    pub async fn run(mut self) -> Result<SessionRunReport, SessionError> {
        loop {
            if matches!(self.engine.state(), EngineState::Stopped { .. }) {
                if self.terminal_command_keepalive && !self.terminal_shutdown_requested {
                    self.serve_terminal_commands_until_shutdown().await?;
                } else {
                    self.drain_terminal_commands().await?;
                }
                return Ok(self.report());
            }
            if let Err(error) = self.run_once().await {
                if is_autonomous_actor_error(&error) {
                    self.terminalize_actor_error(&error);
                } else {
                    return Err(error);
                }
            }
        }
    }

    /// Runs a forked child actor to its terminal state without spawning any
    /// further forks, so the child remains a deterministic leaf of the
    /// exploration tree bound to canonical replay rather than a free-running
    /// live process.
    async fn run_leaf_child(mut self) -> Result<SessionRunReport, SessionError> {
        loop {
            if matches!(self.engine.state(), EngineState::Stopped { .. }) {
                self.drain_terminal_commands_without_spawning_forks()
                    .await?;
                return Ok(self.report());
            }
            if let Err(error) = self.run_once_without_spawning_forks().await {
                if is_autonomous_actor_error(&error) {
                    self.terminalize_actor_error(&error);
                } else {
                    return Err(error);
                }
            }
        }
    }

    pub(super) async fn run_once(&mut self) -> Result<(), SessionError> {
        let result = self.run_once_inner().await;
        if result.is_err() {
            self.fail_pending_gdb_run_control();
        }
        result
    }

    async fn run_once_inner(&mut self) -> Result<(), SessionError> {
        match self.engine.state().clone() {
            EngineState::Running => {
                if self.poll_gdb_run_control().await? {
                    self.publish_live_snapshot();
                    self.complete_pending_gdb_run_control()?;
                    return Ok(());
                }
                if let Some(command) = self.next_boundary_command()? {
                    self.apply_command_or_recover(command).await?;
                    return Ok(());
                }

                let pending_control = self.engine.pending_control_len() as u64;
                let _outcome = match self.engine.step_quantum() {
                    Ok(outcome) => outcome,
                    Err(SessionError::Scheduler(SchedulerError::Backend(error))) => {
                        self.engine.fail_pending_guest_activation(format!(
                            "backend failed while activating guest agent: {error}"
                        ));
                        self.engine.stop_after_backend_crash(error.to_string())?;
                        self.publish_live_snapshot();
                        self.complete_pending_gdb_run_control()?;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let entries = self.engine.drain_event_log_entries();
                let emitted_event_log_entries = entries.len();
                self.append_event_log_entries(&entries)?;
                self.engine
                    .evaluate_breakpoints(&self.condition_event_log, emitted_event_log_entries)?;
                self.sync_reproduction_log();
                let breakpoint_entries = self.engine.drain_event_log_entries();
                self.append_event_log_entries(&breakpoint_entries)?;
                self.engine.poll_pending_guest_activation()?;
                self.engine.stop_on_continuous_quiescence()?;
                let shutdown_entries = self.engine.drain_event_log_entries();
                self.append_event_log_entries(&shutdown_entries)?;
                self.control_acknowledgements = self
                    .control_acknowledgements
                    .saturating_add(pending_control);
                self.publish_live_snapshot();
                self.complete_pending_gdb_run_control()?;
                self.yielded_after_quanta = self.yielded_after_quanta.saturating_add(1);
                tokio::task::yield_now().await;
                Ok(())
            }
            EngineState::Loaded | EngineState::Paused { .. } => {
                match tokio::time::timeout(Duration::from_millis(10), self.mailbox.recv()).await {
                    Ok(Some(command)) => self.apply_command_or_recover(command).await,
                    Ok(None) => Err(SessionError::ChannelClosed),
                    Err(_) => self.poll_gdb_run_control().await.map(|_| ()),
                }
            }
            EngineState::Stopped { .. } => {
                if self.terminal_command_keepalive && !self.terminal_shutdown_requested {
                    self.serve_terminal_commands_until_shutdown().await?;
                } else {
                    self.drain_terminal_commands().await?;
                }
                Ok(())
            }
        }
    }

    async fn run_once_without_spawning_forks(&mut self) -> Result<(), SessionError> {
        match self.engine.state().clone() {
            EngineState::Running => {
                if self.poll_gdb_run_control().await? {
                    self.publish_live_snapshot();
                    self.complete_pending_gdb_run_control()?;
                    return Ok(());
                }
                if let Some(command) = self.next_boundary_command()? {
                    self.apply_command_without_spawning_forks_or_recover(command)
                        .await?;
                    return Ok(());
                }

                let pending_control = self.engine.pending_control_len() as u64;
                let _outcome = match self.engine.step_quantum() {
                    Ok(outcome) => outcome,
                    Err(SessionError::Scheduler(SchedulerError::Backend(error))) => {
                        self.engine.fail_pending_guest_activation(format!(
                            "backend failed while activating guest agent: {error}"
                        ));
                        self.engine.stop_after_backend_crash(error.to_string())?;
                        self.publish_live_snapshot();
                        self.complete_pending_gdb_run_control()?;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let entries = self.engine.drain_event_log_entries();
                let emitted_event_log_entries = entries.len();
                self.append_event_log_entries(&entries)?;
                self.engine
                    .evaluate_breakpoints(&self.condition_event_log, emitted_event_log_entries)?;
                self.sync_reproduction_log();
                let breakpoint_entries = self.engine.drain_event_log_entries();
                self.append_event_log_entries(&breakpoint_entries)?;
                self.engine.poll_pending_guest_activation()?;
                self.engine.stop_on_continuous_quiescence()?;
                let shutdown_entries = self.engine.drain_event_log_entries();
                self.append_event_log_entries(&shutdown_entries)?;
                self.control_acknowledgements = self
                    .control_acknowledgements
                    .saturating_add(pending_control);
                self.publish_live_snapshot();
                self.complete_pending_gdb_run_control()?;
                self.yielded_after_quanta = self.yielded_after_quanta.saturating_add(1);
                tokio::task::yield_now().await;
                Ok(())
            }
            EngineState::Loaded | EngineState::Paused { .. } => {
                match tokio::time::timeout(Duration::from_millis(10), self.mailbox.recv()).await {
                    Ok(Some(command)) => {
                        self.apply_command_without_spawning_forks_or_recover(command)
                            .await
                    }
                    Ok(None) => Err(SessionError::ChannelClosed),
                    Err(_) => self.poll_gdb_run_control().await.map(|_| ()),
                }
            }
            EngineState::Stopped { .. } => {
                self.drain_terminal_commands_without_spawning_forks()
                    .await?;
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

    async fn poll_gdb_run_control(&mut self) -> Result<bool, SessionError> {
        let Some(packet) = self.engine.quantum_loop.poll_gdb_run_control()? else {
            return Ok(false);
        };
        let command = match gdb_run_control_command(&packet) {
            Some(command) => command,
            None => {
                self.engine.quantum_loop.complete_gdb_run_control(b"E01")?;
                return Ok(true);
            }
        };
        let stop = if packet == [0x03] { b"T02" } else { b"T05" };
        match self.apply_command_without_spawning_forks(command).await {
            Ok(()) => {
                self.gdb_run_control_stop = Some(stop.to_vec());
                Ok(true)
            }
            Err(error @ SessionError::DebugNonCanonicalBranchRequired { .. }) => {
                self.engine.quantum_loop.complete_gdb_run_control(b"E31")?;
                let _ = error;
                Ok(true)
            }
            Err(error) => {
                self.engine.quantum_loop.complete_gdb_run_control(b"E31")?;
                Err(error)
            }
        }
    }

    fn complete_pending_gdb_run_control(&mut self) -> Result<(), SessionError> {
        if !matches!(self.engine.state(), EngineState::Running)
            && let Some(stop) = self.gdb_run_control_stop.as_ref()
        {
            self.engine.quantum_loop.complete_gdb_run_control(stop)?;
            self.gdb_run_control_stop = None;
        }
        Ok(())
    }

    fn fail_pending_gdb_run_control(&mut self) {
        if self.gdb_run_control_stop.take().is_some() {
            let _ = self.engine.quantum_loop.complete_gdb_run_control(b"E31");
        }
    }

    pub(super) async fn apply_command(
        &mut self,
        command: SessionCommand,
    ) -> Result<(), SessionError> {
        let shutdown_requested = acknowledged_stop_command(&command);
        let (command, acknowledgement) = split_acknowledged_command(command);
        if matches!(command, SessionCommand::Fork { .. }) && self.fork_loop_factory.is_some() {
            let result = self.apply_spawned_fork_command(command).await;
            self.record_terminal_shutdown_request(shutdown_requested, &result);
            complete_acknowledgement(acknowledgement, &result);
            return result;
        }

        let result = self.apply_command_without_spawning_forks(command).await;
        self.record_terminal_shutdown_request(shutdown_requested, &result);
        complete_acknowledgement(acknowledgement, &result);
        result
    }

    fn record_terminal_shutdown_request(
        &mut self,
        shutdown_requested: bool,
        result: &Result<(), SessionError>,
    ) {
        if shutdown_requested
            && result.is_ok()
            && matches!(self.engine.state(), EngineState::Stopped { .. })
        {
            self.terminal_shutdown_requested = true;
        }
    }

    async fn apply_command_or_recover(
        &mut self,
        command: SessionCommand,
    ) -> Result<(), SessionError> {
        let command_for_recovery = command.clone();
        match self.apply_command(command).await {
            Err(error) if is_recoverable_command_rejection(&command_for_recovery, &error) => Ok(()),
            result => result,
        }
    }

    async fn apply_command_without_spawning_forks_or_recover(
        &mut self,
        command: SessionCommand,
    ) -> Result<(), SessionError> {
        let command_for_recovery = command.clone();
        match self.apply_command_without_spawning_forks(command).await {
            Err(error) if is_recoverable_command_rejection(&command_for_recovery, &error) => Ok(()),
            result => result,
        }
    }

    pub(super) async fn apply_command_without_spawning_forks(
        &mut self,
        command: SessionCommand,
    ) -> Result<(), SessionError> {
        let (command, acknowledgement) = split_acknowledged_command(command);
        let quanta_before = self.engine.quanta();
        let pending_control_before = self.engine.pending_control_len() as u64;
        let quantum_ack = matches!(self.engine.state(), EngineState::Running)
            && command.requires_running_quantum_ack();
        let control_acknowledged = command.is_control_acknowledged();
        let condition_event_log = self.condition_event_log_prefix();
        let mut command = command;
        match &mut command {
            SessionCommand::DebugGoto { request, .. } => {
                request.current = self.engine.snapshot().configuration;
                request.event_coordinates = self.debug_event_coordinates.clone();
            }
            SessionCommand::DebugReverseStep { request, .. } => {
                request.current = self.engine.snapshot().configuration;
                request.event_log.clone_from(&condition_event_log);
                request.event_coordinates = self.debug_event_coordinates.clone();
                if let Some(sequence) = self.debug_current_event_limit(&request.current) {
                    request.current_event_sequence = Some(sequence);
                }
            }
            SessionCommand::DebugReverseContinue { request, .. } => {
                request.current = self.engine.snapshot().configuration;
                request.event_log.clone_from(&condition_event_log);
                request.event_coordinates = self.debug_event_coordinates.clone();
                if let Some(sequence) = self.debug_current_event_limit(&request.current) {
                    request.current_event_sequence = Some(sequence);
                }
            }
            _ => {}
        }
        let history_operation = match &command {
            SessionCommand::DebugReverseStep { request, .. }
                if self.debug_history_floor > 0
                    && request.grain != DebugReverseStepGrain::Instruction
                    && request
                        .current_event_sequence
                        .is_some_and(|sequence| sequence <= self.debug_history_floor) =>
            {
                Some("debug-reverse-step")
            }
            SessionCommand::DebugReverseContinue { request, .. }
                if self.debug_history_floor > 0
                    && request
                        .current_event_sequence
                        .is_some_and(|sequence| sequence <= self.debug_history_floor) =>
            {
                Some("debug-reverse-continue")
            }
            _ => None,
        };
        if let Some(operation) = history_operation {
            let error = SessionError::DebugHistoryUnavailable {
                operation,
                floor: self.debug_history_floor,
            };
            command.complete_error(error.clone());
            complete_acknowledgement(acknowledgement, &Err(error.clone()));
            return Err(error);
        }
        if let Err(error) = self
            .engine
            .apply_command_with_event_log(command.clone(), &condition_event_log)
        {
            command.complete_error(error.clone());
            complete_acknowledgement(acknowledgement, &Err(error.clone()));
            return Err(error);
        }
        let preserve_debug_history = matches!(
            command,
            SessionCommand::DebugGoto { .. }
                | SessionCommand::DebugReverseStep { .. }
                | SessionCommand::DebugReverseContinue { .. }
        );
        let entries = self.engine.drain_event_log_entries();
        if preserve_debug_history {
            self.append_event_log_entries_preserving_debug_history(&entries)?;
        } else {
            self.append_event_log_entries(&entries)?;
        }
        self.sync_reproduction_log();
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
        complete_acknowledgement(acknowledgement, &Ok(()));
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn apply_spawned_fork_command(
        &mut self,
        command: SessionCommand,
    ) -> Result<(), SessionError> {
        let SessionCommand::Fork { from, reply } = command.clone() else {
            return Err(self.engine.invalid_transition(command));
        };
        let Some(factory) = self.fork_loop_factory.clone() else {
            let error = self.engine.invalid_transition(command);
            reply.complete(Err(error.clone()));
            return Err(error);
        };

        let parent_state = self.engine.state.clone();
        let checkpoint = match parent_state {
            EngineState::Running | EngineState::Paused { .. } | EngineState::Stopped { .. } => {
                match self.engine.resolve_fork_checkpoint(from) {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        reply.complete(Err(error.clone()));
                        return Err(error);
                    }
                }
            }
            EngineState::Loaded => {
                let error = self.engine.invalid_transition(command.clone());
                command.complete_error(error.clone());
                return Err(error);
            }
        };
        let mut handle = SessionHandle::new(self.engine.configuration.id(), &checkpoint);
        let request = SessionForkRequest {
            id: handle.id,
            checkpoint: checkpoint.id,
            configuration: checkpoint.configuration,
        };
        let child_quantum_loop = factory(request);
        let fork = match self.engine.build_checkpoint_child(
            parent_state.clone(),
            checkpoint.id,
            child_quantum_loop,
        ) {
            Ok(fork) => fork,
            Err(error) => {
                reply.complete(Err(error.clone()));
                return Err(error);
            }
        };

        if matches!(parent_state, EngineState::Running) {
            self.engine.record_boundary_control(&command, None);
            self.engine.active_step = None;
            self.engine.state = EngineState::Paused {
                reason: PauseReason::UserRequested,
            };
        }

        let child_live = fork.child_actor.live_snapshot();
        let child_sender = fork.child_sender.clone();
        std::mem::drop(tokio::spawn(async move {
            let _ = fork.child_actor.run_leaf_child().await;
        }));
        handle = handle.with_child(SessionChildHandle {
            sender: child_sender,
            live: child_live,
        });
        reply.complete(Ok(handle));
        self.sync_reproduction_log();
        self.publish_live_snapshot();
        self.control_acknowledgements = self.control_acknowledgements.saturating_add(1);
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

    async fn serve_terminal_commands_until_shutdown(&mut self) -> Result<(), SessionError> {
        loop {
            match self.mailbox.recv().await {
                Some(SessionCommand::Acknowledge { command, reply })
                    if matches!(*command, SessionCommand::Stop) =>
                {
                    reply.complete(Ok(()));
                    return Ok(());
                }
                Some(command) if command.is_terminal_accepted() => {
                    self.apply_command(command).await?;
                }
                Some(command) => {
                    let error = self.engine.invalid_transition(command.clone());
                    command.complete_error(error);
                }
                None => return Ok(()),
            }
        }
    }

    async fn drain_terminal_commands_without_spawning_forks(&mut self) -> Result<(), SessionError> {
        loop {
            match self.mailbox.try_recv() {
                Ok(command) if command.is_terminal_accepted() => {
                    self.apply_command_without_spawning_forks(command).await?;
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
mod gdb_run_control_tests {
    use super::*;

    #[test]
    fn parser_accepts_gdb_all_stop_scheduler_semantics() {
        assert!(matches!(
            gdb_run_control_command(b"c"),
            Some(SessionCommand::Continue)
        ));
        assert!(matches!(
            gdb_run_control_command(b"vCont;s"),
            Some(SessionCommand::Step {
                mode: StepMode::Quantum
            })
        ));
        assert!(matches!(
            gdb_run_control_command(b"vCont;s;s"),
            Some(SessionCommand::Step {
                mode: StepMode::Quantum
            })
        ));
        assert!(matches!(
            gdb_run_control_command(b"vCont;s:p1.1;c:p1.-1"),
            Some(SessionCommand::Step {
                mode: StepMode::Quantum
            })
        ));
        assert!(matches!(
            gdb_run_control_command(&[0x03]),
            Some(SessionCommand::Pause)
        ));
        assert!(matches!(
            gdb_run_control_command(b"vCont;s:1"),
            Some(SessionCommand::Step {
                mode: StepMode::Quantum
            })
        ));
        assert!(gdb_run_control_command(b"vCont;s:").is_none());
        assert!(gdb_run_control_command(b"vCont;c;bogus").is_none());
    }
}
