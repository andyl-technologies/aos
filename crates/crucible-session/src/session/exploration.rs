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
    /// Terminal savepoint materialized when the engine reached an outcome.
    pub terminal_savepoint: Option<Checkpoint>,
    /// The most recent scheduler frontier.
    pub frontier: VirtualTime,
    /// Number of canonical event-log entries observed through scheduler output.
    pub event_log_len: usize,
    /// Number of scheduler quanta driven by this engine.
    pub quanta: u64,
}

/// Session-level replay artifact for deterministic boundary-control operations.
///
/// This artifact captures the session's initial configuration, final boundary
/// snapshot, and deterministic control log. Replaying it applies every recorded
/// scheduler-control payload at the same virtual-time/quanta boundary, proving
/// that operator wall-clock timing is not an input to scheduler-owned state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionControlReplayArtifact {
    /// Configuration from which the interactive session started.
    pub initial_configuration: Configuration,
    /// Boundary snapshot reached by the producer run.
    pub final_snapshot: EngineSnapshot,
    /// Deterministic control log emitted by the producer run.
    pub control_log: Vec<SessionControlLogEntry>,
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
/// The child is an ordinary [`SessionActor`] paused at the forked branch
/// checkpoint. Continuing it advances from the same realized-checkpoint path
/// used by resume.
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
    /// Independent child session actor paused at `branch_configuration`.
    pub child_actor: SessionActor<L>,
}

/// Result of resuming an independent session from a recorded checkpoint.
///
/// The actor is an ordinary session actor already landed at
/// [`PauseReason::Instantiated`]. Continuing it advances the supplied
/// [`QuantumLoop`] from the checkpoint's recorded configuration; no restored
/// session state or fork-specific realization path is introduced.
pub struct SessionResume<L> {
    /// Checkpoint used as the resume source.
    pub checkpoint: ContentHash,
    /// Recorded configuration denoted by `checkpoint`.
    pub configuration: Configuration,
    /// Runtime realized through [`TemporalGraph::resume_checkpoint`].
    pub runtime: RuntimeState,
    /// Command sender for the independent resumed session actor.
    pub session_sender: mpsc::Sender<SessionCommand>,
    /// Independent session actor resumed from `checkpoint`.
    pub session_actor: SessionActor<L>,
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
    outcome_kind: AtomicU8,
    terminal_savepoint_present: AtomicU8,
    terminal_savepoint_words: [AtomicU64; 4],
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
    /// Terminal outcome kind when the engine has stopped.
    pub outcome: Option<OutcomeKind>,
    /// Terminal savepoint checkpoint id materialized for the outcome.
    pub terminal_savepoint: Option<ContentHash>,
    /// The latest scheduler virtual-time frontier.
    pub virtual_time: VirtualTime,
    /// Canonical event-log length observed by the session actor.
    pub event_log_len: u64,
    /// Monotone count of scheduler quanta stepped by the session actor.
    pub quanta_stepped: u64,
    /// Monotone count of actor-acknowledged control commands.
    pub control_acknowledgements: u64,
}

impl LiveSnapshotView {
    /// Returns the lifecycle state kind represented by this live view.
    #[must_use]
    pub const fn lifecycle_state(&self) -> LifecycleStateKind {
        match self.state_kind {
            LiveStateKind::Loaded => LifecycleStateKind::Loaded,
            LiveStateKind::Running => LifecycleStateKind::Running,
            LiveStateKind::Paused => LifecycleStateKind::Paused,
            LiveStateKind::Stopped => LifecycleStateKind::Stopped,
        }
    }
}

impl LiveSnapshot {
    /// Builds a live snapshot initialized from an engine boundary snapshot.
    #[must_use]
    pub fn new(initial: &EngineSnapshot) -> Self {
        let snapshot = Self {
            epoch: AtomicU64::new(0),
            state_kind: AtomicU8::new(LiveStateKind::Loaded as u8),
            outcome_kind: AtomicU8::new(0),
            terminal_savepoint_present: AtomicU8::new(0),
            terminal_savepoint_words: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
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
            let outcome_kind = self.outcome_kind.load(Ordering::Acquire);
            let terminal_savepoint_present =
                self.terminal_savepoint_present.load(Ordering::Acquire);
            let terminal_savepoint_words = [
                self.terminal_savepoint_words[0].load(Ordering::Acquire),
                self.terminal_savepoint_words[1].load(Ordering::Acquire),
                self.terminal_savepoint_words[2].load(Ordering::Acquire),
                self.terminal_savepoint_words[3].load(Ordering::Acquire),
            ];
            let virtual_time_ticks = self.virtual_time_ticks.load(Ordering::Acquire);
            let event_log_len = self.event_log_len.load(Ordering::Acquire);
            let quanta_stepped = self.quanta_stepped.load(Ordering::Acquire);
            let control_acknowledgements = self.control_acknowledgements.load(Ordering::Acquire);
            let end_epoch = self.epoch.load(Ordering::Acquire);

            if start_epoch == end_epoch && end_epoch.is_multiple_of(2) {
                return LiveSnapshotView {
                    state_kind: LiveStateKind::from_raw(state_kind),
                    outcome: outcome_kind_from_raw(outcome_kind),
                    terminal_savepoint: content_hash_from_words(
                        terminal_savepoint_present,
                        terminal_savepoint_words,
                    ),
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

    /// Answers a point-in-time status query from the lock-free mirror.
    ///
    /// This method performs only the atomic loads used by [`LiveSnapshot::read`].
    /// It does not enter the session actor mailbox or read the owned engine.
    #[must_use]
    pub fn query(&self, kind: LiveQueryKind) -> LiveQueryResult {
        let view = self.read();
        match kind {
            LiveQueryKind::Status => LiveQueryResult::Status(view),
            LiveQueryKind::State => LiveQueryResult::State(view.lifecycle_state()),
            LiveQueryKind::EventLogLength => LiveQueryResult::EventLogLength(view.event_log_len),
        }
    }

    fn publish(&self, snapshot: &EngineSnapshot, control_acknowledgements: u64) {
        let write_epoch = self.epoch.load(Ordering::Relaxed).wrapping_add(1) | 1;
        self.epoch.store(write_epoch, Ordering::Release);
        self.state_kind.store(
            LiveStateKind::from_engine_state(&snapshot.state) as u8,
            Ordering::Release,
        );
        self.outcome_kind.store(
            outcome_kind_to_raw(outcome_kind_from_engine_state(&snapshot.state)),
            Ordering::Release,
        );
        let terminal_savepoint = snapshot.terminal_savepoint.as_ref().map(|value| value.id);
        let terminal_savepoint_words = terminal_savepoint
            .map(content_hash_to_words)
            .unwrap_or([0, 0, 0, 0]);
        self.terminal_savepoint_present
            .store(u8::from(terminal_savepoint.is_some()), Ordering::Release);
        for (word, value) in self
            .terminal_savepoint_words
            .iter()
            .zip(terminal_savepoint_words)
        {
            word.store(value, Ordering::Release);
        }
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

#[derive(Clone, Copy, Debug, Default)]
struct NoBreakpointLeaves;

impl ConditionLeafOracle for NoBreakpointLeaves {
    fn leaf_is_true(&mut self, _leaf: ConditionLeaf<'_>) -> bool {
        false
    }
}

fn breakpoint_action_kind(action: &Action) -> &'static str {
    match action {
        Action::InjectFault { .. } => "inject-fault",
        Action::HealFault { .. } => "heal-fault",
        Action::ArmTimer { .. } => "arm-timer",
        Action::CancelTimer { .. } => "cancel-timer",
        Action::StartNode { .. } => "start-node",
        Action::StopNode { .. } => "stop-node",
        Action::CreateSavepoint { .. } => "create-savepoint",
        Action::Fork { .. } => "fork",
        Action::Pass => "pass",
        Action::Fail { .. } => "fail",
        Action::Log { .. } => "log",
        Action::Group(_) => "group",
    }
}

fn control_operation_command_kind(control: &ControlOperationKind) -> Option<SessionCommandKind> {
    match control {
        ControlOperationKind::InjectFault { .. } => Some(SessionCommandKind::InjectFault),
        ControlOperationKind::HealFault { .. } => Some(SessionCommandKind::HealFault),
        ControlOperationKind::Inject
        | ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Step
        | ControlOperationKind::Snapshot
        | ControlOperationKind::Fork
        | ControlOperationKind::Query => None,
    }
}
