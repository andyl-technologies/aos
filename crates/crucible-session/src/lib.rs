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
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crucible::{
    Configuration, EngineError, QuantumLoop, QuantumOutcome, QuantumRequest, RuntimeState,
    SchedulerError, TemporalGraph, VirtualTime, instantiate,
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
    /// Transition to a terminal operator-stopped state.
    Stop,
    /// Read the current boundary state without mutation.
    Query,
}

impl SessionCommand {
    /// Returns whether the command is observation-only.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::Query)
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
        };
        snapshot.publish(initial);
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
            let end_epoch = self.epoch.load(Ordering::Acquire);

            if start_epoch == end_epoch && end_epoch.is_multiple_of(2) {
                return LiveSnapshotView {
                    state_kind: LiveStateKind::from_raw(state_kind),
                    virtual_time: VirtualTime {
                        ticks: virtual_time_ticks,
                    },
                    event_log_len,
                    quanta_stepped,
                };
            }

            std::hint::spin_loop();
        }
    }

    fn publish(&self, snapshot: &EngineSnapshot) {
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
        self.epoch
            .store(write_epoch.wrapping_add(1), Ordering::Release);
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
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
        match command {
            SessionCommand::Start => {
                if matches!(self.state, EngineState::Loaded) {
                    self.instantiate_runtime()
                } else {
                    Err(self.invalid_transition(command))
                }
            }
            SessionCommand::Continue => {
                if matches!(self.state, EngineState::Paused { .. }) {
                    self.state = EngineState::Running;
                    Ok(self.snapshot())
                } else {
                    Err(self.invalid_transition(command))
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
                    Err(self.invalid_transition(command))
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
                    Err(self.invalid_transition(command))
                }
            }
            SessionCommand::Stop => {
                if matches!(self.state, EngineState::Stopped { .. }) {
                    Err(self.invalid_transition(command))
                } else {
                    self.state = EngineState::Stopped {
                        outcome: Outcome::Stopped,
                    };
                    Ok(self.snapshot())
                }
            }
            SessionCommand::Query => Ok(self.snapshot()),
        }
    }

    /// Advances exactly one bounded scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] if the engine is not
    /// running. Returns [`SessionError::Scheduler`] if the quantum loop rejects
    /// the boundary request. Returns [`SessionError::Engine`] if the resulting
    /// configuration cannot be re-instantiated.
    pub fn step_quantum(&mut self) -> Result<QuantumOutcome, SessionError> {
        if !matches!(self.state, EngineState::Running) {
            return Err(self.invalid_engine_state("step_quantum"));
        }

        let outcome = self.quantum_loop.drive_quantum(QuantumRequest {
            configuration: self.configuration.clone(),
            control: Vec::new(),
        })?;
        let runtime = instantiate(&self.graph, &outcome.configuration)?;

        self.configuration = outcome.configuration.clone();
        self.runtime = Some(runtime);
        self.runtime_instantiated = true;
        self.frontier = outcome.frontier;
        self.event_log_len = self
            .event_log_len
            .saturating_add(outcome.resolved_events.len());
        self.quanta = self.quanta.saturating_add(1);

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
/// and yields after each quantum.
pub struct SessionActor<L> {
    engine: Engine<L>,
    mailbox: mpsc::Receiver<SessionCommand>,
    deferred: VecDeque<SessionCommand>,
    live: Arc<LiveSnapshot>,
    commands_applied: u64,
    yielded_after_quanta: u64,
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
            commands_applied: 0,
            yielded_after_quanta: 0,
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

    fn report(&self) -> SessionRunReport {
        SessionRunReport {
            final_snapshot: self.engine.snapshot(),
            commands_applied: self.commands_applied,
            quanta: self.engine.quanta(),
            yielded_after_quanta: self.yielded_after_quanta,
        }
    }

    fn publish_live_snapshot(&self) {
        self.live.publish(&self.engine.snapshot());
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

                self.engine.step_quantum()?;
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
        self.engine.apply_command(command)?;
        self.publish_live_snapshot();
        if self.engine.quanta() > quanta_before {
            self.yielded_after_quanta = self
                .yielded_after_quanta
                .saturating_add(self.engine.quanta() - quanta_before);
            tokio::task::yield_now().await;
        }
        self.commands_applied = self.commands_applied.saturating_add(1);
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
        Checkpoint, CheckpointKind, ContentHash, Decision, DeliveryOrderDecision, EventKey,
        GenesisCheckpoint, ScenarioDef, VirtualTime, step,
    };

    #[test]
    fn session_driver_delegates_to_quantum_loop() {
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
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
            })
        }
    }

    #[derive(Default)]
    struct AppendingLoop {
        quanta: u64,
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
        GenesisCheckpoint {
            checkpoint: Checkpoint::new(
                ContentHash::from_canonical_material(
                    "crucible.session.test.baked-genesis",
                    &format!("{:?}", configuration.id().bytes),
                ),
                configuration.id(),
                CheckpointKind::Fat,
            ),
        }
    }

    fn generated_scenario(seed: u64) -> ScenarioDef {
        ScenarioDef::from_canonical_material(
            "crucible.session.test.scenario",
            &format!("seed={seed}"),
        )
    }

    fn generated_decision(seed: u64) -> Decision {
        Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: seed },
            order: vec![EventKey { sequence: seed }],
        })
    }
}
