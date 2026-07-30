//! Session constants, lifecycle vocabulary, snapshots, and command results.

use super::*;

/// Number of live event-log frames retained by the broadcast tail.
pub const SESSION_EVENT_LOG_BROADCAST_CAPACITY: usize = 1024;

/// Maximum number of retained event-log frames cloned by one stream receive.
pub const SESSION_EVENT_LOG_REPLAY_BATCH_SIZE: usize = 64;

/// Number of live state-transition frames retained by the broadcast tail.
pub const SESSION_STATE_BROADCAST_CAPACITY: usize = 256;

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
    pub(super) fn from_engine_state(state: &EngineState) -> Self {
        match state {
            EngineState::Loaded => Self::Loaded,
            EngineState::Running => Self::Running,
            EngineState::Paused { .. } => Self::Paused,
            EngineState::Stopped { .. } => Self::Stopped,
        }
    }

    pub(super) fn from_raw(raw: u8) -> Self {
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
    last_truth: BTreeMap<BreakpointId, bool>,
    once_latches: BTreeMap<BreakpointId, Vec<Condition>>,
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
        self.last_truth.insert(id, false);
        self.once_latches.insert(id, Vec::new());
        id
    }

    /// Removes a breakpoint by id and reports whether it was present.
    pub fn remove(&mut self, id: BreakpointId) -> bool {
        self.last_truth.remove(&id);
        self.once_latches.remove(&id);
        self.specs.remove(&id).is_some()
    }

    /// Returns the breakpoint specification for `id`, when present.
    #[must_use]
    pub fn get(&self, id: BreakpointId) -> Option<&BreakpointSpec> {
        self.specs.get(&id)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (BreakpointId, &BreakpointSpec, bool)> {
        self.specs
            .iter()
            .map(|(id, spec)| (*id, spec, self.last_truth.get(id).copied().unwrap_or(false)))
    }

    pub(super) fn set_last_truth(&mut self, id: BreakpointId, value: bool) {
        if self.specs.contains_key(&id) {
            self.last_truth.insert(id, value);
        }
    }

    pub(super) fn once_latches(&self, id: BreakpointId) -> Vec<Condition> {
        self.once_latches.get(&id).cloned().unwrap_or_default()
    }

    pub(super) fn set_once_latches(&mut self, id: BreakpointId, once_latches: Vec<Condition>) {
        if self.specs.contains_key(&id) {
            self.once_latches.insert(id, once_latches);
        }
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

pub(super) fn outcome_kind_from_raw(raw: u8) -> Option<OutcomeKind> {
    match raw {
        1 => Some(OutcomeKind::Passed),
        2 => Some(OutcomeKind::Failed),
        3 => Some(OutcomeKind::Timeout),
        4 => Some(OutcomeKind::Crashed),
        5 => Some(OutcomeKind::Stopped),
        _ => None,
    }
}

pub(super) fn outcome_kind_to_raw(kind: Option<OutcomeKind>) -> u8 {
    match kind {
        Some(OutcomeKind::Passed) => 1,
        Some(OutcomeKind::Failed) => 2,
        Some(OutcomeKind::Timeout) => 3,
        Some(OutcomeKind::Crashed) => 4,
        Some(OutcomeKind::Stopped) => 5,
        None => 0,
    }
}

pub(super) fn outcome_kind_from_engine_state(state: &EngineState) -> Option<OutcomeKind> {
    match state {
        EngineState::Stopped { outcome } => Some(OutcomeKind::from(outcome)),
        EngineState::Loaded | EngineState::Running | EngineState::Paused { .. } => None,
    }
}

pub(super) fn content_hash_to_words(hash: ContentHash) -> [u64; 4] {
    let mut words = [0_u64; 4];
    for (index, chunk) in hash.bytes.chunks_exact(8).enumerate() {
        let mut word = [0_u8; 8];
        word.copy_from_slice(chunk);
        words[index] = u64::from_be_bytes(word);
    }
    words
}

pub(super) fn content_hash_from_words(present: u8, words: [u64; 4]) -> Option<ContentHash> {
    if present == 0 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    bytes[0..8].copy_from_slice(&words[0].to_be_bytes());
    bytes[8..16].copy_from_slice(&words[1].to_be_bytes());
    bytes[16..24].copy_from_slice(&words[2].to_be_bytes());
    bytes[24..32].copy_from_slice(&words[3].to_be_bytes());
    Some(ContentHash { bytes })
}

pub(super) fn content_hash_from_required_words(words: [u64; 4]) -> ContentHash {
    let mut bytes = [0_u8; 32];
    bytes[0..8].copy_from_slice(&words[0].to_be_bytes());
    bytes[8..16].copy_from_slice(&words[1].to_be_bytes());
    bytes[16..24].copy_from_slice(&words[2].to_be_bytes());
    bytes[24..32].copy_from_slice(&words[3].to_be_bytes());
    ContentHash { bytes }
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
    /// Advance exactly one scheduler quantum.
    Quantum,
    /// Advance to the next scheduler event coordinate.
    Event,
    /// Advance to the next assertion-state coordinate.
    Assertion,
    /// Advance to the next timer coordinate.
    Timer,
    /// Advance to the first quantum boundary at or past the virtual duration.
    Duration(SimDuration),
}

impl StepMode {
    /// Default deterministic duration used to include [`Self::Duration`] in
    /// closed-vocabulary tests.
    pub const DEFAULT_DURATION: SimDuration = SimDuration { nanos: 1 };

    /// The closed forward step-mode set.
    pub const ALL: [Self; 5] = [
        Self::Quantum,
        Self::Event,
        Self::Assertion,
        Self::Timer,
        Self::Duration(Self::DEFAULT_DURATION),
    ];

    /// Returns the reverse-step grain that mirrors this forward mode, when the
    /// debug vocabulary has an exact grain.
    #[must_use]
    pub const fn reverse_grain(self) -> Option<DebugReverseStepGrain> {
        match self {
            Self::Quantum => Some(DebugReverseStepGrain::Quantum),
            Self::Event => Some(DebugReverseStepGrain::Event),
            Self::Assertion => Some(DebugReverseStepGrain::Assertion),
            Self::Timer => Some(DebugReverseStepGrain::Timer),
            Self::Duration(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ActiveStep {
    pub(super) mode: StepMode,
    pub(super) target_frontier: Option<VirtualTime>,
    pub(super) breakpoint: BreakpointSpec,
}

impl ActiveStep {
    pub(super) fn new(mode: StepMode, start_frontier: VirtualTime) -> Self {
        let target_frontier = match mode {
            StepMode::Duration(duration) => Some(VirtualTime {
                ticks: start_frontier.ticks.saturating_add(duration.nanos),
            }),
            StepMode::Quantum | StepMode::Event | StepMode::Assertion | StepMode::Timer => None,
        };
        let breakpoint = BreakpointSpec::suspend_once(Self::stop_condition(mode, target_frontier));
        Self {
            mode,
            target_frontier,
            breakpoint,
        }
    }

    fn stop_condition(mode: StepMode, target_frontier: Option<VirtualTime>) -> Condition {
        match mode {
            StepMode::Quantum => Condition::Named {
                name: String::from("session.step.quantum"),
                nodes: Vec::new(),
            },
            StepMode::Event => Condition::Named {
                name: String::from("session.step.event"),
                nodes: Vec::new(),
            },
            StepMode::Assertion => Condition::Named {
                name: String::from("session.step.assertion"),
                nodes: Vec::new(),
            },
            StepMode::Timer => Condition::Named {
                name: String::from("session.step.timer"),
                nodes: Vec::new(),
            },
            StepMode::Duration(_) => Condition::At {
                at: target_frontier.unwrap_or_default(),
            },
        }
    }

    pub(super) fn is_complete(
        &self,
        outcome: &QuantumOutcome,
        event_log_len_before: u64,
    ) -> Result<bool, ConditionEvaluationError> {
        let prefix = if outcome.event_log_entries.is_empty() {
            ConditionEventLogPrefix::from_evaluation_boundary(
                event_log_len_before,
                outcome.frontier,
                SchedulerEvaluationBoundaryKind::Quantum,
            )?
        } else {
            ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base_sequence(
                outcome.event_log_entries.clone(),
                event_log_len_before,
            )?
        };
        let mut pass = ConditionEvaluationPass::from_log_prefix(
            prefix,
            StepConditionLeaves::from_outcome(outcome),
        );
        Ok(pass.evaluate_assertion_condition(&self.breakpoint.predicate))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct StepConditionLeaves {
    quantum: bool,
    event: bool,
    assertion: bool,
    timer: bool,
}

impl StepConditionLeaves {
    fn from_outcome(outcome: &QuantumOutcome) -> Self {
        Self {
            quantum: true,
            event: outcome
                .event_log_entries
                .iter()
                .any(entry_is_resolved_external_event),
            assertion: outcome
                .event_log_entries
                .iter()
                .any(entry_is_assertion_state_change),
            timer: outcome.event_log_entries.iter().any(entry_is_timer_fire),
        }
    }
}

impl ConditionLeafOracle for StepConditionLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        let ConditionLeaf::Named { name, .. } = leaf else {
            return false;
        };
        match name {
            "session.step.quantum" => self.quantum,
            "session.step.event" => self.event,
            "session.step.assertion" => self.assertion,
            "session.step.timer" => self.timer,
            _ => false,
        }
    }
}

pub(super) fn entry_is_resolved_external_event(entry: &SchedulerEventLogEntry) -> bool {
    match entry.payload() {
        SchedulerEventLogPayload::ResolvedHappening(event) => matches!(
            &event.payload,
            ScheduledEventPayload::BackendInput(_)
                | ScheduledEventPayload::IoCompletion(_)
                | ScheduledEventPayload::FaultActivation(_)
                | ScheduledEventPayload::ProbabilisticFault(_)
        ),
        SchedulerEventLogPayload::Observable(ObservableEventPayload::NetworkDelivered {
            ..
        })
        | SchedulerEventLogPayload::Observable(ObservableEventPayload::IoCompletion { .. }) => true,
        _ => false,
    }
}

pub(super) fn entry_is_assertion_state_change(entry: &SchedulerEventLogEntry) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged { .. })
    )
}

pub(super) fn entry_is_timer_fire(entry: &SchedulerEventLogEntry) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::TriggerFired(firing)
            if condition_summary_is_timer_fire(firing.condition_summary())
    )
}

pub(super) fn condition_summary_is_timer_fire(summary: &str) -> bool {
    summary.lines().any(|line| line.trim() == "predicate=timer")
}
