//! `crucible-session` owns the live session actor.
//!
//! Spec index: RFC-0010 files 20.
//!
//! This L4 crate will drive one live runtime state, accept control requests at quantum boundaries, and expose the session semantics specified by RFC-0010 file 20. It contains no raw QEMU or shared-memory access.
//!
//! Module map: the crate root owns [`SessionDriver`], [`Engine`], and [`SessionActor`]; [`validation`] owns replay and validation DAG adapters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// Engine vocabulary exposed through the session boundary for control-plane clients.
pub mod engine {
    pub use crucible::{
        AssertionId, AssertionPhase, AssertionQuantifierKind, BlackBoxHostOracle,
        CRASH_RESTART_SCENARIO_NAME, Checkpoint, CheckpointKind, ChoiceTag,
        ConditionEventLogPrefix, Configuration, ContentAddressedBlobRef, ContentHash,
        CoverageGuidedCorpusConfig, CoverageGuidedCorpusRun, CoverageGuidedFuzzConfig,
        CoverageGuidedFuzzRun, DagStore, DagStoreError, DebugCheckpointStride,
        DebugCliSurfaceContract, DebugCoordinate, DebugFailureFooterCommand, DebugGdbEndpoint,
        DebugReverseStepGrain, Decision, DeliveryOrderDecision, EngineError, EventAttributeValue,
        EventDiagnosticPayload, EventLevel, EventLogOffset, ExampleCorpusError,
        ExampleScenarioVerifyReport, ExecutionFingerprint, FAULT_CAMPAIGN_FAMILY_NAME,
        FailureClusterFinding, FailureClusterReport, FailureClusterReportFailure,
        FailureClusterReportFormat, FailureClusterReportSet, FailureClusteringResult,
        FailureFindingsLedger, FailurePropertyViolationRecord, FailureRecordedEventLog,
        FailureSignature, FailureSignatureNormalization,
        FailureSignaturePreservingMinimizationResult, FailureSignaturePreservingMinimizationRun,
        FailureTriageResult, FailureTriageSignatureSelfCheck, FailureTriageSignatureSelfCheckInput,
        FailureTriageStoredArtifact, FamilySpace, FaultDensity, FaultDensityRange, FaultTag,
        FindingDiscoveryPath, FindingReproductionArtifact, FingerprintSample, GenesisCheckpoint,
        HAPPY_PATH_SCENARIO_NAME, HostAssertionEvaluator, HostAssertionOutcomeKind,
        HostAssertionViolation, Icount, LocalDagStore, MarkerId, MaterializationPolicy,
        MaterializationTrigger, MemoryDagStore, MinimizationConfig, MinimizationRun, NodeId,
        NodeTemplate, OverrideDecision, PARTITION_RECOVERY_SCENARIO_NAME, Predicate, QuantumLoop,
        QuantumOutcome, QuantumRequest, ReadyPoint, RecordedAssertionLog, ReplayOracleCheck,
        ReproductionArtifact, RngDecision, RngStreamId, SHMEM_ABI_VERSION, ScenarioDef,
        ScenarioDefForm, ScenarioFamily, Schedule, SchedulerError, SchedulerEventLogEntry,
        SchedulerQuiescence, SchedulingPoint, SearchBudget, SearchDiscoveredFailure,
        SearchFailureOracle, SearchReplayOracleSamplingConfig, SearchReplayOracleSamplingReport,
        SearchRetainedLogAssertionEvidence, SearchScheduleNamedPredicateKey,
        SearchScheduleNamedPredicateTruths, SearchStrategy, Seed, SeedSpace, SignaturePolicy,
        SignaturePolicyLevel, SimBackend, SimDuration, SimulationBackend, TemporalGraph,
        TemporalGraphSampledSearchRun, TemporalGraphStoreError, TopologyShape, TopologySizeRange,
        UnifiedGraphOperationEvidence, UnifiedGraphOperationKind, UnifiedGraphOperationReport,
        VirtualTime, VmArchitecture, WhiteBoxPolicy, World, built_in_example_corpus,
        crash_restart_scenario, fault_campaign_family, happy_path_scenario,
        partition_recovery_scenario, run_fault_campaign_example, try_step,
        verify_example_scenario_runs,
    };
}

/// Session-owned replay and validation DAG adapters.
pub mod validation;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    Action, BackendError, Checkpoint, Condition, ConditionEvaluationError, ConditionEvaluationPass,
    ConditionEventLogPrefix, ConditionLeaf, ConditionLeafOracle, Configuration, ContentHash,
    ControlOperation, ControlOperationKind, DebugAttachReport, DebugAttachRequest, DebugGotoReport,
    DebugGotoRequest, DebugNonCanonicalBranchReport, DebugNonCanonicalBranchRequest,
    DebugReverseContinueReport, DebugReverseContinueRequest, DebugReverseStepGrain,
    DebugReverseStepReport, DebugReverseStepRequest, Decision, EngineError, Fault, FaultTag,
    FingerprintSample, GdbListen, NodeId, ObservableEventPayload, QuantumLoop, QuantumOutcome,
    QuantumRequest, RuntimeState, Schedule, ScheduledEventPayload, SchedulerError,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogClass, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerQuiescence, SimDuration, TemporalGraph, VirtualTime,
    WhiteBoxPolicy, World,
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

    fn iter(&self) -> impl Iterator<Item = (BreakpointId, &BreakpointSpec, bool)> {
        self.specs
            .iter()
            .map(|(id, spec)| (*id, spec, self.last_truth.get(id).copied().unwrap_or(false)))
    }

    fn set_last_truth(&mut self, id: BreakpointId, value: bool) {
        if self.specs.contains_key(&id) {
            self.last_truth.insert(id, value);
        }
    }

    fn once_latches(&self, id: BreakpointId) -> Vec<Condition> {
        self.once_latches.get(&id).cloned().unwrap_or_default()
    }

    fn set_once_latches(&mut self, id: BreakpointId, once_latches: Vec<Condition>) {
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

fn outcome_kind_from_raw(raw: u8) -> Option<OutcomeKind> {
    match raw {
        1 => Some(OutcomeKind::Passed),
        2 => Some(OutcomeKind::Failed),
        3 => Some(OutcomeKind::Timeout),
        4 => Some(OutcomeKind::Crashed),
        5 => Some(OutcomeKind::Stopped),
        _ => None,
    }
}

fn outcome_kind_to_raw(kind: Option<OutcomeKind>) -> u8 {
    match kind {
        Some(OutcomeKind::Passed) => 1,
        Some(OutcomeKind::Failed) => 2,
        Some(OutcomeKind::Timeout) => 3,
        Some(OutcomeKind::Crashed) => 4,
        Some(OutcomeKind::Stopped) => 5,
        None => 0,
    }
}

fn outcome_kind_from_engine_state(state: &EngineState) -> Option<OutcomeKind> {
    match state {
        EngineState::Stopped { outcome } => Some(OutcomeKind::from(outcome)),
        EngineState::Loaded | EngineState::Running | EngineState::Paused { .. } => None,
    }
}

fn content_hash_to_words(hash: ContentHash) -> [u64; 4] {
    let mut words = [0_u64; 4];
    for (index, chunk) in hash.bytes.chunks_exact(8).enumerate() {
        let mut word = [0_u8; 8];
        word.copy_from_slice(chunk);
        words[index] = u64::from_be_bytes(word);
    }
    words
}

fn content_hash_from_words(present: u8, words: [u64; 4]) -> Option<ContentHash> {
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
struct ActiveStep {
    mode: StepMode,
    target_frontier: Option<VirtualTime>,
    breakpoint: BreakpointSpec,
}

impl ActiveStep {
    fn new(mode: StepMode, start_frontier: VirtualTime) -> Self {
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

    fn is_complete(
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
struct StepConditionLeaves {
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

fn entry_is_resolved_external_event(entry: &SchedulerEventLogEntry) -> bool {
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

fn entry_is_assertion_state_change(entry: &SchedulerEventLogEntry) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged { .. })
    )
}

fn entry_is_timer_fire(entry: &SchedulerEventLogEntry) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::TriggerFired(firing)
            if condition_summary_is_timer_fire(firing.condition_summary())
    )
}

fn condition_summary_is_timer_fire(summary: &str) -> bool {
    summary.lines().any(|line| line.trim() == "predicate=timer")
}

/// Actor-local breakpoint identifier.
pub type BreakpointId = u64;

/// Reply channel carried by commands that return data to their caller.
///
/// The reply transport is deliberately not part of command equality or hashing:
/// it routes completion back to the caller, but it is not model state.
type CommandReplySender<T> = Arc<Mutex<Option<oneshot::Sender<Result<T, SessionError>>>>>;

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
    fn new(parent: ContentHash, checkpoint: &Checkpoint) -> Self {
        Self {
            id: fork_session_handle_id(parent, checkpoint.id),
            checkpoint: checkpoint.id,
            configuration: checkpoint.configuration,
            child: None,
        }
    }

    fn with_child(mut self, child: SessionChildHandle) -> Self {
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

type SessionForkLoopFactory<L> = Arc<dyn Fn(SessionForkRequest) -> L + Send + Sync>;

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
    /// Return one deterministic execution-fingerprint sample for a node.
    ExecutionFingerprint {
        /// Node whose backend fingerprint should be sampled.
        node: NodeId,
    },
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
    /// Deterministic execution-fingerprint sample for one node.
    ExecutionFingerprint(FingerprintSample),
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
    /// Attach the debugger gdbstub to the current boundary.
    AttachGdb {
        /// Node whose backend gdbstub should be exposed.
        node: NodeId,
        /// Operator-facing gdb-protocol listener.
        listen: GdbListen,
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
            | Self::InjectFault { .. }
            | Self::HealFault { .. }
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CreateSavepoint { .. }
            | Self::Fork { .. }
            | Self::Stop
            | Self::DebugForkNonCanonical { .. } => false,
        }
    }

    const fn is_terminal_accepted(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.is_terminal_accepted(),
            Self::Snapshot | Self::Fork { .. } | Self::Query { .. } => true,
            Self::Start
            | Self::Continue
            | Self::Pause
            | Self::Step { .. }
            | Self::Inject
            | Self::InjectFault { .. }
            | Self::HealFault { .. }
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CreateSavepoint { .. }
            | Self::Stop
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => false,
        }
    }

    const fn is_control_acknowledged(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.is_control_acknowledged(),
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
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => true,
            Self::Start | Self::Continue | Self::Step { .. } | Self::Stop => false,
        }
    }

    const fn requires_running_quantum_ack(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.requires_running_quantum_ack(),
            Self::Snapshot | Self::Query { .. } => true,
            Self::Start
            | Self::Continue
            | Self::Pause
            | Self::Step { .. }
            | Self::Inject
            | Self::InjectFault { .. }
            | Self::HealFault { .. }
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CreateSavepoint { .. }
            | Self::Fork { .. }
            | Self::Stop
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => false,
        }
    }

    const fn requires_non_canonical_debug_branch(&self) -> bool {
        match self {
            Self::Acknowledge { command, .. } => command.requires_non_canonical_debug_branch(),
            Self::Continue
            | Self::Step { .. }
            | Self::Inject
            | Self::InjectFault { .. }
            | Self::HealFault { .. }
            | Self::SetBreakpoint { .. }
            | Self::RemoveBreakpoint { .. } => true,
            Self::Start
            | Self::Pause
            | Self::Snapshot
            | Self::CreateSavepoint { .. }
            | Self::Fork { .. }
            | Self::Stop
            | Self::Query { .. }
            | Self::AttachGdb { .. }
            | Self::DebugGoto { .. }
            | Self::DebugReverseStep { .. }
            | Self::DebugReverseContinue { .. }
            | Self::DebugForkNonCanonical { .. } => false,
        }
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
            Self::AttachGdb { reply, .. } => reply.complete(Err(error)),
            Self::DebugGoto { reply, .. } => reply.complete(Err(error)),
            Self::DebugReverseStep { reply, .. } => reply.complete(Err(error)),
            Self::DebugReverseContinue { reply, .. } => reply.complete(Err(error)),
            Self::DebugForkNonCanonical { reply, .. } => reply.complete(Err(error)),
            Self::Acknowledge { command, reply } => {
                command.complete_error(error.clone());
                reply.complete(Err(error));
            }
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
        Self::Inject,
        Self::InjectFault,
        Self::HealFault,
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
    ];

    const fn operation_name(self) -> &'static str {
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
            Self::Inject => "inject",
            Self::InjectFault => "inject-fault",
            Self::HealFault => "heal-fault",
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
            Self::AttachGdb
            | Self::DebugGoto
            | Self::DebugReverseStep
            | Self::DebugReverseContinue
            | Self::DebugForkNonCanonical => return None,
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
            SessionCommand::Step {
                mode: StepMode::Event,
            } => Self::StepEvent,
            SessionCommand::Step {
                mode: StepMode::Assertion,
            } => Self::StepAssertion,
            SessionCommand::Step {
                mode: StepMode::Timer,
            } => Self::StepTimer,
            SessionCommand::Step {
                mode: StepMode::Duration(_),
            } => Self::StepDuration,
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
            SessionCommand::AttachGdb { .. } => Self::AttachGdb,
            SessionCommand::DebugGoto { .. } => Self::DebugGoto,
            SessionCommand::DebugReverseStep { .. } => Self::DebugReverseStep,
            SessionCommand::DebugReverseContinue { .. } => Self::DebugReverseContinue,
            SessionCommand::DebugForkNonCanonical { .. } => Self::DebugForkNonCanonical,
            SessionCommand::Acknowledge { command, .. } => Self::from(command.as_ref()),
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
            | Command::StepEvent
            | Command::StepAssertion
            | Command::StepTimer
            | Command::StepDuration
            | Command::Inject
            | Command::InjectFault
            | Command::HealFault
            | Command::CreateSavepoint
            | Command::Fork
            | Command::AttachGdb
            | Command::DebugGoto
            | Command::DebugReverseStep
            | Command::DebugReverseContinue
            | Command::DebugForkNonCanonical,
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
            | Command::InjectFault
            | Command::HealFault
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Query
            | Command::AttachGdb
            | Command::DebugGoto
            | Command::DebugReverseStep
            | Command::DebugReverseContinue
            | Command::DebugForkNonCanonical,
        ) => Accepted { to: State::Paused },
        (State::Running, Command::Stop) => Accepted { to: State::Stopped },
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
            | Command::InjectFault
            | Command::HealFault
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Query,
        ) => Accepted { to: State::Running },
        (State::Running, Command::Fork) => Accepted { to: State::Paused },
        (State::Running, Command::Start | Command::Continue) => Rejected,

        (State::Paused, Command::Stop) => Accepted { to: State::Stopped },
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
            | Command::InjectFault
            | Command::HealFault
            | Command::SetBreakpoint
            | Command::RemoveBreakpoint
            | Command::CreateSavepoint
            | Command::Stop
            | Command::AttachGdb
            | Command::DebugGoto
            | Command::DebugReverseStep
            | Command::DebugReverseContinue
            | Command::DebugForkNonCanonical,
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
    /// Event-log stream generation that produced this frame.
    pub generation: u64,
    /// Cursor position of this entry.
    pub cursor: EventLogCursor,
    /// Cursor position immediately after this entry.
    pub next_cursor: EventLogCursor,
    /// Full causal or observational event-log entry.
    pub entry: SchedulerEventLogEntry,
}

impl SessionEventLogFrame {
    fn new(entry: SchedulerEventLogEntry, generation: u64) -> Self {
        let sequence = entry.sequence();
        Self {
            generation,
            cursor: EventLogCursor::new(sequence),
            next_cursor: EventLogCursor::new(sequence.saturating_add(1)),
            entry,
        }
    }
}

/// Log-derived summary captured at stream attach time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEventLogSnapshot {
    /// Cursor through which the snapshot was folded.
    pub through: EventLogCursor,
    /// Number of event-log entries folded into the snapshot.
    pub event_count: u64,
    /// Number of causal entries folded into the snapshot.
    pub causal_count: u64,
    /// Number of observational entries folded into the snapshot.
    pub observational_count: u64,
    /// Last sequence folded into the snapshot, when any entry was present.
    pub last_sequence: Option<u64>,
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
    generation: AtomicU64,
    generation_start: AtomicU64,
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
                generation: AtomicU64::new(0),
                generation_start: AtomicU64::new(0),
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
        let (_current_tail, stream) = self.subscribe_with_replay_tail(cursor);
        stream
    }

    /// Subscribes and returns the replay tail captured for the attach response.
    ///
    /// The returned cursor is the retained log tail observed by the attach path;
    /// the stream starts with replay from `cursor` up to that tail and then
    /// continues with the live broadcast tail.
    #[must_use]
    pub fn subscribe_with_replay_tail(
        &self,
        cursor: EventLogCursor,
    ) -> (EventLogCursor, SessionEventLogStream) {
        let receiver = self.inner.tail.subscribe();
        let current_tail = self.current_cursor();
        let next_cursor = EventLogCursor::new(cursor.next_sequence.min(current_tail.next_sequence));
        (
            current_tail,
            SessionEventLogStream {
                hub: self.clone(),
                generation: self.generation(),
                next_cursor,
                replay_tail: current_tail,
                replay_exhausted: false,
                backlog: VecDeque::new(),
                receiver,
            },
        )
    }

    /// Returns a log-derived snapshot summary through `cursor`.
    #[must_use]
    pub fn snapshot_through(&self, cursor: EventLogCursor) -> SessionEventLogSnapshot {
        let entries = self.lock_entries();
        let mut event_count = 0_u64;
        let mut causal_count = 0_u64;
        let mut observational_count = 0_u64;
        let mut last_sequence = None;
        for entry in entries
            .iter()
            .take_while(|entry| entry.sequence() < cursor.next_sequence)
        {
            event_count = event_count.saturating_add(1);
            match entry.class() {
                SchedulerEventLogClass::Causal => causal_count = causal_count.saturating_add(1),
                SchedulerEventLogClass::Observational => {
                    observational_count = observational_count.saturating_add(1);
                }
            }
            last_sequence = Some(entry.sequence());
        }
        SessionEventLogSnapshot {
            through: cursor,
            event_count,
            causal_count,
            observational_count,
            last_sequence,
        }
    }

    fn append_entries(&self, entries: &[SchedulerEventLogEntry]) {
        if entries.is_empty() {
            return;
        }

        let generation = self.generation();
        let frames = entries
            .iter()
            .cloned()
            .map(|entry| SessionEventLogFrame::new(entry, generation))
            .collect::<Vec<_>>();
        self.lock_entries().extend(entries.iter().cloned());
        for frame in frames {
            let _ = self.inner.tail.send(frame);
        }
    }

    fn truncate_to_len(&self, len: usize) {
        let mut entries = self.lock_entries();
        if entries.len() > len {
            entries.truncate(len);
            self.inner
                .generation_start
                .store(usize_to_u64(len), Ordering::Release);
            self.inner.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    fn generation_start_cursor(&self) -> EventLogCursor {
        EventLogCursor::new(self.inner.generation_start.load(Ordering::Acquire))
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

    fn replay_batch_from(
        &self,
        cursor: EventLogCursor,
        replay_tail: EventLogCursor,
        generation: u64,
    ) -> VecDeque<SessionEventLogFrame> {
        let entries = self.lock_entries();
        let start = entries.partition_point(|entry| entry.sequence() < cursor.next_sequence);
        entries
            .iter()
            .skip(start)
            .take_while(|entry| entry.sequence() < replay_tail.next_sequence)
            .take(SESSION_EVENT_LOG_REPLAY_BATCH_SIZE)
            .cloned()
            .map(|entry| SessionEventLogFrame::new(entry, generation))
            .collect()
    }
}

impl Default for SessionEventLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable snapshot of the deterministic command stream recorded for replay.
#[derive(Clone, Debug)]
pub struct SessionReproductionLog {
    inner: Arc<Mutex<Vec<SessionControlLogEntry>>>,
}

impl SessionReproductionLog {
    /// Builds an empty reproduction-log snapshot handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a point-in-time copy of the recorded command stream.
    #[must_use]
    pub fn snapshot(&self) -> Vec<SessionControlLogEntry> {
        self.lock_entries().clone()
    }

    /// Returns the number of recorded boundary controls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_entries().len()
    }

    /// Returns whether no boundary controls have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock_entries().is_empty()
    }

    fn sync_from_boundary_log(&self, entries: &[SessionControlLogEntry]) {
        let mut current = self.lock_entries();
        if current.as_slice() == entries {
            return;
        }
        current.clear();
        current.extend_from_slice(entries);
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, Vec<SessionControlLogEntry>> {
        match self.inner.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Default for SessionReproductionLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(debug_assertions, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    //! Test-support helpers for integration tests.

    use crucible::SchedulerEventLogEntry;

    use crate::SessionEventLog;

    /// Appends event-log entries to a session event-log hub for integration tests.
    pub fn append_event_log_entries_for_test(
        hub: &SessionEventLog,
        entries: &[SchedulerEventLogEntry],
    ) {
        hub.append_entries(entries);
    }

    /// Truncates a session event-log hub to `len` entries for integration tests.
    pub fn truncate_event_log_for_test(hub: &SessionEventLog, len: usize) {
        hub.truncate_to_len(len);
    }
}

/// Cursor-backed event-log stream for one subscriber.
#[derive(Debug)]
pub struct SessionEventLogStream {
    hub: SessionEventLog,
    generation: u64,
    next_cursor: EventLogCursor,
    replay_tail: EventLogCursor,
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
            if let Some(frame) = self.take_ready_backlog_frame() {
                return Ok(Some(frame));
            }
            match self.receiver.recv().await {
                Ok(frame) => {
                    if let Some(frame) = self.deliver_frame(frame) {
                        return Ok(Some(frame));
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(None),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    return Err(SessionEventLogStreamError::Lagged { skipped });
                }
            }
        }
    }

    /// Polls for the next frame without awaiting, returning `Ok(None)` when no
    /// frame is immediately available.
    ///
    /// This is a deterministic, wall-clock-free probe: it drains any replay
    /// backlog and reads at most one already-buffered broadcast frame, never
    /// parking the task on a timer.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEventLogStreamError::Lagged`] when this subscriber has
    /// fallen behind the bounded live broadcast tail.
    pub fn try_recv(&mut self) -> Result<Option<SessionEventLogFrame>, SessionEventLogStreamError> {
        loop {
            if let Some(frame) = self.take_ready_backlog_frame() {
                return Ok(Some(frame));
            }
            match self.receiver.try_recv() {
                Ok(frame) => {
                    if let Some(frame) = self.deliver_frame(frame) {
                        return Ok(Some(frame));
                    }
                }
                Err(broadcast::error::TryRecvError::Empty)
                | Err(broadcast::error::TryRecvError::Closed) => return Ok(None),
                Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                    return Err(SessionEventLogStreamError::Lagged { skipped });
                }
            }
        }
    }

    /// Advances stream state for a broadcast frame, returning it to deliver or `None` when stale.
    fn deliver_frame(&mut self, frame: SessionEventLogFrame) -> Option<SessionEventLogFrame> {
        if frame.generation < self.generation {
            return None;
        }
        if frame.generation > self.generation {
            self.generation = frame.generation;
            self.replay_exhausted = true;
            self.backlog.clear();
        } else if frame.cursor.next_sequence < self.next_cursor.next_sequence {
            return None;
        }
        self.next_cursor = frame.next_cursor;
        Some(frame)
    }

    /// Refills the drained replay backlog and pops the next non-stale frame,
    /// returning `None` when it is exhausted and the tail should be consulted.
    fn take_ready_backlog_frame(&mut self) -> Option<SessionEventLogFrame> {
        loop {
            let hub_generation = self.hub.generation();
            if hub_generation > self.generation {
                self.generation = hub_generation;
                self.next_cursor = self.next_cursor.min(self.hub.generation_start_cursor());
                self.replay_tail = self.hub.current_cursor();
                self.replay_exhausted = false;
                self.backlog.clear();
            }
            if self.backlog.is_empty() && !self.replay_exhausted {
                self.backlog =
                    self.hub
                        .replay_batch_from(self.next_cursor, self.replay_tail, self.generation);
                self.replay_exhausted = self.backlog.is_empty();
            }
            let frame = self.backlog.pop_front()?;
            if frame.generation < self.generation
                || frame.cursor.next_sequence < self.next_cursor.next_sequence
            {
                continue;
            }
            self.next_cursor = frame.next_cursor;
            return Some(frame);
        }
    }
}

/// One run-state transition delivered to a control-plane subscriber.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStateTransitionFrame {
    /// Monotone actor-local transition sequence.
    pub sequence: u64,
    /// Full actor state observed before the transition was published.
    pub from_state: EngineState,
    /// Full actor state observed after the transition was published.
    pub to_state: EngineState,
    /// Lock-free snapshot observed before the transition was published.
    pub from: LiveSnapshotView,
    /// Lock-free snapshot observed after the transition was published.
    pub to: LiveSnapshotView,
}

/// Error returned while reading a live state-transition stream.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SessionStateTransitionStreamError {
    /// The subscriber lagged behind the bounded live tail.
    #[error("session state-transition stream skipped {skipped} frames")]
    Lagged {
        /// Number of skipped broadcast frames reported by the live tail.
        skipped: u64,
    },
}

/// Session-owned state-transition hub used by the control plane.
#[derive(Clone, Debug)]
pub struct SessionStateTransitionBus {
    tail: broadcast::Sender<SessionStateTransitionFrame>,
}

impl SessionStateTransitionBus {
    /// Builds an empty state-transition bus.
    #[must_use]
    pub fn new() -> Self {
        let (tail, _) = broadcast::channel(SESSION_STATE_BROADCAST_CAPACITY);
        Self { tail }
    }

    /// Subscribes to future state transitions.
    ///
    /// Subscribing clones only a broadcast receiver. It does not enqueue a
    /// session command, take an engine lock, or await the scheduler.
    #[must_use]
    pub fn subscribe(&self) -> SessionStateTransitionStream {
        SessionStateTransitionStream {
            receiver: self.tail.subscribe(),
        }
    }

    fn publish(&self, frame: SessionStateTransitionFrame) {
        let _ = self.tail.send(frame);
    }
}

impl Default for SessionStateTransitionBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Live state-transition stream for one subscriber.
#[derive(Debug)]
pub struct SessionStateTransitionStream {
    receiver: broadcast::Receiver<SessionStateTransitionFrame>,
}

impl SessionStateTransitionStream {
    /// Receives the next state-transition frame.
    ///
    /// # Errors
    ///
    /// Returns [`SessionStateTransitionStreamError::Lagged`] when this
    /// subscriber falls behind the bounded live broadcast tail.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<SessionStateTransitionFrame>, SessionStateTransitionStreamError> {
        match self.receiver.recv().await {
            Ok(frame) => Ok(Some(frame)),
            Err(broadcast::error::RecvError::Closed) => Ok(None),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                Err(SessionStateTransitionStreamError::Lagged { skipped })
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
    terminal_savepoint: Option<Checkpoint>,
    active_step: Option<ActiveStep>,
    graph: TemporalGraph,
    breakpoints: BreakpointSet,
    quantum_loop: L,
    frontier: VirtualTime,
    event_log_len: usize,
    quanta: u64,
    pending_control: Vec<ControlOperation>,
    pending_event_log_entries: Vec<SchedulerEventLogEntry>,
    debug_attach: Option<DebugAttachReport>,
    debug_branch_required: bool,
    next_control_sequence: u64,
    boundary_control_log: Vec<SessionControlLogEntry>,
    next_boundary_control_sequence: u64,
    next_boundary_control_batch: u64,
    scheduler_quiescence: Option<SchedulerQuiescence>,
    breakpoint_firings: Vec<BreakpointFiring>,
    next_breakpoint_firing_sequence: u64,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
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
            terminal_savepoint: None,
            active_step: None,
            graph,
            breakpoints: BreakpointSet::new(),
            quantum_loop,
            frontier: VirtualTime::default(),
            event_log_len: 0,
            quanta: 0,
            pending_control: Vec::new(),
            pending_event_log_entries: Vec::new(),
            debug_attach: None,
            debug_branch_required: false,
            next_control_sequence: 0,
            boundary_control_log: Vec::new(),
            next_boundary_control_sequence: 0,
            next_boundary_control_batch: 0,
            scheduler_quiescence: None,
            breakpoint_firings: Vec::new(),
            next_breakpoint_firing_sequence: 0,
            white_box_policies: BTreeMap::new(),
        }
    }

    /// Adds authoritative white-box opt-in policies for guest-marker breakpoints.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    fn from_realized_checkpoint(
        configuration: Configuration,
        graph: TemporalGraph,
        quantum_loop: L,
        runtime: RuntimeState,
        checkpoint: &Checkpoint,
    ) -> Self {
        Self {
            configuration,
            runtime: Some(runtime.clone()),
            runtime_instantiated: true,
            state: EngineState::Paused {
                reason: PauseReason::Instantiated,
            },
            terminal_savepoint: None,
            active_step: None,
            graph,
            breakpoints: BreakpointSet::new(),
            quantum_loop,
            frontier: checkpoint.virtual_time,
            event_log_len: u64_to_usize(runtime.event_log.events),
            quanta: 0,
            pending_control: Vec::new(),
            pending_event_log_entries: Vec::new(),
            debug_attach: None,
            debug_branch_required: false,
            next_control_sequence: 0,
            boundary_control_log: Vec::new(),
            next_boundary_control_sequence: 0,
            next_boundary_control_batch: 0,
            scheduler_quiescence: None,
            breakpoint_firings: Vec::new(),
            next_breakpoint_firing_sequence: 0,
            white_box_policies: BTreeMap::new(),
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

    /// Returns the deterministic boundary-control log.
    #[must_use]
    pub fn boundary_control_log(&self) -> &[SessionControlLogEntry] {
        &self.boundary_control_log
    }

    /// Captures a replay artifact for deterministic session control operations.
    ///
    /// The caller supplies the initial configuration because sessions may start
    /// from genesis, a resumed checkpoint, or a forked prefix. The captured
    /// artifact is sufficient to replay the recorded scheduler-control payloads
    /// at their original virtual-time/quanta boundaries with a fresh
    /// [`QuantumLoop`].
    #[must_use]
    pub fn control_replay_artifact(
        &self,
        initial_configuration: Configuration,
    ) -> SessionControlReplayArtifact {
        SessionControlReplayArtifact {
            initial_configuration,
            final_snapshot: self.snapshot(),
            control_log: self.boundary_control_log.clone(),
        }
    }

    /// Returns the deterministic breakpoint-firing log.
    #[must_use]
    pub fn breakpoint_firings(&self) -> &[BreakpointFiring] {
        &self.breakpoint_firings
    }

    /// Returns the active debug attach, if one is open.
    #[must_use]
    pub fn debug_attach(&self) -> Option<&DebugAttachReport> {
        self.debug_attach.as_ref()
    }

    /// Returns whether forward or mutating use must first mark a debug branch.
    #[must_use]
    pub const fn debug_branch_required(&self) -> bool {
        self.debug_branch_required
    }

    /// Returns the number of scheduler quanta driven by this engine.
    #[must_use]
    pub fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Creates an independent child session from `base` plus divergent decisions.
    ///
    /// The fork is recorded through [`TemporalGraph::fork`], which realizes
    /// `base` via `instantiate`, appends the supplied [`Decision`] values with
    /// the execution-model step operation, and records the branch as a thin
    /// checkpoint. The returned child is a normal paused [`SessionActor`] with
    /// its own mailbox and live snapshot; continuing it advances from the
    /// branch checkpoint through the same path as resume.
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
        let branch_configuration = fork.branch.clone();
        let branch_checkpoint = fork.branch_checkpoint.clone();
        let runtime = self.graph.resume_checkpoint(branch_checkpoint.id)?.runtime;
        let child_graph = self.graph.clone();
        let record = SessionForkRecord {
            from_checkpoint: fork.base.checkpoint,
            branch_checkpoint: branch_checkpoint.id,
            schedule_delta: branch_checkpoint.schedule_delta.clone(),
        };
        let child_engine = Engine::from_realized_checkpoint(
            branch_configuration.clone(),
            child_graph,
            child_quantum_loop,
            runtime,
            &branch_checkpoint,
        )
        .with_white_box_policies(self.white_box_policies.clone());
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

    /// Resumes an independent session actor from a recorded graph checkpoint.
    ///
    /// The checkpoint is resolved to its recorded [`Configuration`] and realized
    /// through [`TemporalGraph::resume_checkpoint`]. The returned actor is a
    /// normal paused session with its own mailbox and live mirror; continuing it
    /// advances from the resumed configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Engine`] when the checkpoint or its configuration
    /// is not recorded, or when temporal-graph resume cannot instantiate it.
    pub fn resume_session_from_checkpoint<C>(
        &mut self,
        checkpoint: ContentHash,
        session_quantum_loop: C,
    ) -> Result<SessionResume<C>, SessionError> {
        let checkpoint_record =
            self.graph
                .checkpoint_record(checkpoint)
                .cloned()
                .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                    checkpoint,
                }))?;
        let configuration = self
            .graph
            .checkpoint_configuration(checkpoint)
            .cloned()
            .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                checkpoint,
            }))?;
        let resumed = self.graph.resume_checkpoint(checkpoint)?;
        let runtime = resumed.runtime;
        let session_graph = self.graph.clone();
        let session_engine = Engine::from_realized_checkpoint(
            configuration.clone(),
            session_graph,
            session_quantum_loop,
            runtime.clone(),
            &checkpoint_record,
        )
        .with_white_box_policies(self.white_box_policies.clone());
        let (session_sender, receiver) = mpsc::channel(SESSION_FORK_MAILBOX_CAPACITY);
        let session_actor = SessionActor::new(session_engine, receiver);

        Ok(SessionResume {
            checkpoint: resumed.checkpoint,
            configuration,
            runtime,
            session_sender,
            session_actor,
        })
    }

    /// Forks an independent child actor from a recorded checkpoint prefix.
    ///
    /// The parent must already be at a forkable boundary. `from` is resolved to a
    /// checkpoint-backed prefix, then recorded through [`TemporalGraph::fork`]
    /// with an empty decision delta. The returned child actor is independently
    /// paused at [`PauseReason::Instantiated`] and can diverge through subsequent
    /// scheduler decisions without mutating the parent.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when called while the parent
    /// is loaded or running. A running parent must first pause at a quantum
    /// boundary. Returns [`SessionError::Engine`] when the checkpoint cannot be
    /// resolved or the graph cannot instantiate the prefix.
    pub fn fork_child_from_checkpoint<C>(
        &mut self,
        from: CheckpointRef,
        child_quantum_loop: C,
    ) -> Result<SessionFork<C>, SessionError> {
        let parent_state = self.state.clone();
        if !matches!(
            parent_state,
            EngineState::Paused { .. } | EngineState::Stopped { .. }
        ) {
            return Err(SessionError::InvalidEngineState {
                state: parent_state,
                operation: "fork_child_from_checkpoint",
            });
        }

        let checkpoint = self.resolve_fork_checkpoint(from)?;
        self.build_checkpoint_child(parent_state, checkpoint.id, child_quantum_loop)
    }

    fn build_checkpoint_child<C>(
        &mut self,
        parent_state: EngineState,
        checkpoint: ContentHash,
        child_quantum_loop: C,
    ) -> Result<SessionFork<C>, SessionError> {
        let base = self
            .graph
            .checkpoint_configuration(checkpoint)
            .cloned()
            .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                checkpoint,
            }))?;
        let fork = self.graph.fork(&base, std::iter::empty::<Decision>())?;
        let child_graph = self.graph.clone();
        let branch_configuration = fork.branch.clone();
        let branch_checkpoint = fork.branch_checkpoint.clone();
        let runtime = fork.base.runtime;
        let record = SessionForkRecord {
            from_checkpoint: fork.base.checkpoint,
            branch_checkpoint: branch_checkpoint.id,
            schedule_delta: Schedule::empty(),
        };
        let child_engine = Engine::from_realized_checkpoint(
            branch_configuration.clone(),
            child_graph,
            child_quantum_loop,
            runtime,
            &branch_checkpoint,
        )
        .with_white_box_policies(self.white_box_policies.clone());
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
            terminal_savepoint: self.terminal_savepoint.clone(),
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
            state: Box::new(self.state.clone()),
            command: Box::new(command),
        }
    }

    fn invalid_engine_state(&self, operation: &'static str) -> SessionError {
        SessionError::InvalidEngineState {
            state: self.state.clone(),
            operation,
        }
    }

    fn current_debug_attach(
        &self,
        operation: &'static str,
    ) -> Result<DebugAttachReport, SessionError> {
        self.debug_attach
            .clone()
            .ok_or(SessionError::DebugAttachRequired { operation })
    }

    fn reject_debug_forward_without_branch(
        &self,
        command: &SessionCommand,
    ) -> Result<(), SessionError> {
        if self.debug_branch_required && command.requires_non_canonical_debug_branch() {
            return Err(SessionError::DebugNonCanonicalBranchRequired {
                operation: SessionCommandKind::from(command).operation_name(),
            });
        }
        Ok(())
    }

    fn update_debug_position(
        &mut self,
        previous_attach: &DebugAttachReport,
        goto: &DebugGotoReport,
    ) -> Result<DebugAttachReport, SessionError> {
        let configuration = self
            .graph
            .checkpoint_configuration(goto.target_configuration)
            .or_else(|| self.graph.checkpoint_configuration(goto.target_checkpoint))
            .cloned()
            .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                checkpoint: goto.target_configuration,
            }))?;
        let frontier = self
            .graph
            .checkpoint_record(goto.target_configuration)
            .or_else(|| self.graph.checkpoint_record(goto.target_checkpoint))
            .map_or_else(
                || {
                    let ticks = goto
                        .runtime
                        .runtime
                        .node_icounts
                        .values()
                        .map(|icount| icount.retired)
                        .min()
                        .unwrap_or_default();
                    VirtualTime { ticks }
                },
                |checkpoint| checkpoint.virtual_time,
            );
        self.configuration = configuration.clone();
        self.runtime = Some(goto.runtime.runtime.clone());
        self.runtime_instantiated = true;
        self.frontier = frontier;
        self.event_log_len = u64_to_usize(goto.runtime.runtime.event_log.events);
        self.active_step = None;
        if matches!(self.state, EngineState::Running) {
            self.state = EngineState::Paused {
                reason: PauseReason::UserRequested,
            };
        }
        self.debug_branch_required = true;
        let request = DebugAttachRequest {
            configuration,
            node: previous_attach.gdbstub.node.clone(),
            qemu_gdbstub: previous_attach.gdbstub.qemu_endpoint.clone(),
            gdb_listen: previous_attach.gdbstub.operator_listen.clone(),
        };
        let refreshed = self.graph.debug_attach(&request)?;
        self.debug_attach = Some(refreshed.clone());
        Ok(refreshed)
    }

    fn admit_control_operation(&mut self, kind: ControlOperationKind) {
        self.next_control_sequence = self.next_control_sequence.saturating_add(1);
        self.pending_control.push(ControlOperation {
            sequence: self.next_control_sequence,
            kind,
        });
    }

    fn apply_control_operation_at_boundary(
        &mut self,
        kind: ControlOperationKind,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        self.apply_control_operations_at_boundary(vec![kind])
    }

    fn apply_control_operations_at_boundary(
        &mut self,
        kinds: Vec<ControlOperationKind>,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        if kinds.is_empty() {
            return Ok(());
        }
        let mut control = Vec::with_capacity(kinds.len());
        for kind in kinds {
            self.next_control_sequence = self.next_control_sequence.saturating_add(1);
            control.push(ControlOperation {
                sequence: self.next_control_sequence,
                kind,
            });
        }
        let entries = self.quantum_loop.apply_control_at_boundary(control)?;
        self.append_boundary_event_log_entries(entries)
    }

    fn append_boundary_event_log_entries(
        &mut self,
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<(), SessionError> {
        let current_event_log_len = usize_to_u64(self.event_log_len);
        let emitted_event_log_entries = usize_to_u64(entries.len());
        let expected_event_log_len = current_event_log_len
            .checked_add(emitted_event_log_entries)
            .ok_or(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: emitted_event_log_entries,
                next: current_event_log_len,
            })?;
        for (index, entry) in entries.iter().enumerate() {
            let expected_sequence = current_event_log_len.saturating_add(usize_to_u64(index));
            if entry.sequence() != expected_sequence {
                return Err(SessionError::EventLogOffsetMismatch {
                    current: current_event_log_len,
                    emitted: emitted_event_log_entries,
                    next: entry.sequence(),
                });
            }
        }
        self.event_log_len = u64_to_usize(expected_event_log_len);
        self.pending_event_log_entries.extend(entries);
        Ok(())
    }

    fn validate_event_log_prefix(
        &self,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<(), SessionError> {
        let current_event_log_len = usize_to_u64(self.event_log_len);
        if event_log.len() != self.event_log_len {
            return Err(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: 0,
                next: usize_to_u64(event_log.len()),
            });
        }
        for (index, entry) in event_log.iter().enumerate() {
            let expected_sequence = usize_to_u64(index);
            if entry.sequence() != expected_sequence {
                return Err(SessionError::EventLogOffsetMismatch {
                    current: current_event_log_len,
                    emitted: 0,
                    next: entry.sequence(),
                });
            }
        }
        Ok(())
    }

    fn record_boundary_control(
        &mut self,
        command: &SessionCommand,
        scheduler_control: Option<ControlOperationKind>,
    ) {
        let event_log_sequence_before = usize_to_u64(self.event_log_len());
        self.record_boundary_control_at(command, scheduler_control, event_log_sequence_before);
    }

    fn record_boundary_control_at(
        &mut self,
        command: &SessionCommand,
        scheduler_control: Option<ControlOperationKind>,
        event_log_sequence_before: u64,
    ) {
        let payload = SessionControlPayload::from(command);
        let scheduler_batch = if scheduler_control.is_some() {
            self.next_boundary_control_batch()
        } else {
            0
        };
        self.record_boundary_control_kind_payload_in_batch(
            SessionCommandKind::from(command),
            payload,
            scheduler_control,
            scheduler_batch,
            event_log_sequence_before,
        );
    }

    fn record_boundary_control_kind_in_batch(
        &mut self,
        command: SessionCommandKind,
        scheduler_control: Option<ControlOperationKind>,
        scheduler_batch: u64,
        event_log_sequence_before: u64,
    ) {
        let payload =
            SessionControlPayload::from_control_or_kind(command, scheduler_control.as_ref());
        self.record_boundary_control_kind_payload_in_batch(
            command,
            payload,
            scheduler_control,
            scheduler_batch,
            event_log_sequence_before,
        );
    }

    fn record_boundary_control_kind_payload_in_batch(
        &mut self,
        command: SessionCommandKind,
        payload: SessionControlPayload,
        scheduler_control: Option<ControlOperationKind>,
        scheduler_batch: u64,
        event_log_sequence_before: u64,
    ) {
        self.next_boundary_control_sequence = self.next_boundary_control_sequence.saturating_add(1);
        self.boundary_control_log.push(SessionControlLogEntry {
            sequence: self.next_boundary_control_sequence,
            command,
            payload,
            frontier: self.frontier,
            quanta: self.quanta,
            event_log_sequence_before,
            result: SessionControlResult::Accepted,
            scheduler_batch,
            scheduler_control,
        });
    }

    fn next_boundary_control_batch(&mut self) -> u64 {
        self.next_boundary_control_batch = self.next_boundary_control_batch.saturating_add(1);
        self.next_boundary_control_batch
    }

    fn evaluate_breakpoints(
        &mut self,
        event_log_entries: &[SchedulerEventLogEntry],
        emitted_event_log_entries: usize,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        if self.breakpoints.is_empty() {
            return Ok(());
        }

        let Some(prefix) =
            self.breakpoint_condition_prefix(event_log_entries, emitted_event_log_entries)?
        else {
            return Ok(());
        };
        let evaluations = self
            .breakpoints
            .iter()
            .map(|(id, spec, was_true)| {
                let mut pass =
                    ConditionEvaluationPass::from_log_prefix(prefix.clone(), NoBreakpointLeaves)
                        .with_once_latches(self.breakpoints.once_latches(id))
                        .with_white_box_policies(self.white_box_policies.clone());
                if let Some(quiescence) = self.scheduler_quiescence.clone() {
                    pass = pass.with_scheduler_quiescence(quiescence);
                }
                let is_true = pass.evaluate_assertion_condition(&spec.predicate);
                (
                    id,
                    spec.clone(),
                    was_true,
                    is_true,
                    pass.once_latches().to_vec(),
                )
            })
            .collect::<Vec<_>>();

        for (id, spec, was_true, is_true, once_latches) in evaluations {
            if is_true && !was_true {
                self.fire_breakpoint(id, &spec)?;
                if matches!(spec.policy, BreakpointPolicy::OneShot) {
                    self.breakpoints.remove(id);
                } else {
                    self.breakpoints.set_once_latches(id, once_latches);
                    self.breakpoints.set_last_truth(id, true);
                }
            } else {
                self.breakpoints.set_once_latches(id, once_latches);
                self.breakpoints.set_last_truth(id, is_true);
            }
        }

        Ok(())
    }

    fn breakpoint_condition_prefix(
        &self,
        event_log_entries: &[SchedulerEventLogEntry],
        emitted_event_log_entries: usize,
    ) -> Result<Option<ConditionEventLogPrefix>, SessionError> {
        if emitted_event_log_entries == 0 {
            if self.scheduler_quiescence.is_some() {
                return ConditionEventLogPrefix::from_scheduler_event_log_entries_with_evaluation_boundary(
                    event_log_entries.to_vec(),
                    usize_to_u64(self.event_log_len),
                    self.frontier,
                    SchedulerEvaluationBoundaryKind::Quantum,
                )
                .map(Some)
                .map_err(|error| SessionError::BreakpointConditionPrefix {
                    reason: error.to_string(),
                });
            }
            return Ok(None);
        }

        ConditionEventLogPrefix::from_scheduler_event_log_entries(event_log_entries.to_vec())
            .map(Some)
            .map_err(|error| SessionError::BreakpointConditionPrefix {
                reason: error.to_string(),
            })
    }

    fn fire_breakpoint(
        &mut self,
        id: BreakpointId,
        spec: &BreakpointSpec,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        let mut scheduler_controls = Vec::new();
        match &spec.disposition {
            BreakpointDisposition::Suspend => {
                self.active_step = None;
                self.state = EngineState::Paused {
                    reason: PauseReason::Breakpoint { id },
                };
            }
            BreakpointDisposition::Trace => {}
            BreakpointDisposition::Action(action) => {
                self.apply_breakpoint_action(action, &mut scheduler_controls)?;
            }
        }

        self.next_breakpoint_firing_sequence =
            self.next_breakpoint_firing_sequence.saturating_add(1);
        self.breakpoint_firings.push(BreakpointFiring {
            sequence: self.next_breakpoint_firing_sequence,
            id,
            predicate: spec.predicate.clone(),
            disposition: spec.disposition.clone(),
            frontier: self.frontier,
            quanta: self.quanta,
            scheduler_controls,
        });
        Ok(())
    }

    fn apply_breakpoint_action(
        &mut self,
        action: &Action,
        scheduler_controls: &mut Vec<ControlOperationKind>,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        let planned_controls = Self::plan_breakpoint_action(action)?;
        let event_log_sequence_before = usize_to_u64(self.event_log_len());
        self.apply_control_operations_at_boundary(planned_controls.clone())?;
        let scheduler_batch = if planned_controls.is_empty() {
            0
        } else {
            self.next_boundary_control_batch()
        };
        for control in &planned_controls {
            if let Some(command) = control_operation_command_kind(control) {
                self.record_boundary_control_kind_in_batch(
                    command,
                    Some(control.clone()),
                    scheduler_batch,
                    event_log_sequence_before,
                );
            }
        }
        scheduler_controls.extend(planned_controls);
        Ok(())
    }

    fn plan_breakpoint_action(action: &Action) -> Result<Vec<ControlOperationKind>, SessionError> {
        let mut scheduler_controls = Vec::new();
        Self::plan_breakpoint_action_into(action, &mut scheduler_controls)?;
        Ok(scheduler_controls)
    }

    fn plan_breakpoint_action_into(
        action: &Action,
        scheduler_controls: &mut Vec<ControlOperationKind>,
    ) -> Result<(), SessionError> {
        match action {
            Action::InjectFault { tag, fault } => {
                let Some(fault) = fault.table_fault() else {
                    return Err(SessionError::UnsupportedBreakpointFault {
                        action: "inject-fault",
                        reason: "fault has no scheduler-control representation",
                    });
                };
                scheduler_controls.push(ControlOperationKind::InjectFault {
                    tag: tag.clone(),
                    fault,
                });
            }
            Action::HealFault { tag } => {
                scheduler_controls.push(ControlOperationKind::HealFault { tag: tag.clone() });
            }
            Action::Group(actions) => {
                for action in actions {
                    Self::plan_breakpoint_action_into(action, scheduler_controls)?;
                }
            }
            Action::ArmTimer { .. }
            | Action::CancelTimer { .. }
            | Action::StartNode { .. }
            | Action::StopNode { .. }
            | Action::CreateSavepoint { .. }
            | Action::Fork { .. }
            | Action::Pass
            | Action::Fail { .. }
            | Action::Log { .. } => {
                return Err(SessionError::UnsupportedBreakpointAction {
                    action: breakpoint_action_kind(action),
                });
            }
        }
        Ok(())
    }

    fn pending_control_len(&self) -> usize {
        self.pending_control.len()
    }

    fn enter_stopped(&mut self, outcome: Outcome) -> Result<(), SessionError> {
        let checkpoint = self.graph.save_checkpoint(&self.configuration)?;
        self.terminal_savepoint = Some(checkpoint);
        self.state = EngineState::Stopped { outcome };
        Ok(())
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

        let runtime = self.graph.resume(&self.configuration)?.runtime;
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

        let runtime = self.graph.resume(&self.configuration)?.runtime;
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

        let runtime = self.graph.resume(&self.configuration)?.runtime;
        self.runtime = None;
        self.runtime = Some(runtime);
        Ok(self.snapshot())
    }

    /// Replays deterministic scheduler-control payloads from `artifact`.
    ///
    /// The supplied temporal graph and quantum loop must represent the same
    /// deterministic model used to produce the artifact. Replay starts from the
    /// artifact's initial configuration, applies every recorded scheduler-owned
    /// control payload at its recorded quanta/frontier boundary, and advances to
    /// the final recorded quantum boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] if the initial configuration
    /// cannot be started, [`SessionError::Scheduler`] or [`SessionError::Engine`]
    /// if the replay loop cannot advance, or a control-replay mismatch error if
    /// the artifact records a control entry for a boundary not reached by replay.
    pub fn replay_control_replay_artifact(
        artifact: &SessionControlReplayArtifact,
        graph: TemporalGraph,
        quantum_loop: L,
    ) -> Result<EngineSnapshot, SessionError> {
        let mut engine = Self::new(artifact.initial_configuration.clone(), graph, quantum_loop);
        engine.apply_command(SessionCommand::Start)?;
        engine.apply_command(SessionCommand::Continue)?;

        let mut log_index = 0;
        while engine.quanta < artifact.final_snapshot.quanta {
            engine.replay_controls_at_current_boundary(artifact, &mut log_index)?;
            let _ = engine.step_quantum()?;
        }
        engine.replay_controls_at_current_boundary(artifact, &mut log_index)?;
        if let Some(entry) = artifact.control_log.get(log_index) {
            return Err(SessionError::ControlReplayBoundaryMismatch {
                current_quanta: engine.quanta,
                recorded_quanta: entry.quanta,
            });
        }
        let replayed = engine.snapshot();
        if replayed != artifact.final_snapshot {
            return Err(SessionError::ControlReplayFinalSnapshotMismatch {
                expected: Box::new(artifact.final_snapshot.clone()),
                actual: Box::new(replayed),
            });
        }
        Ok(replayed)
    }

    fn replay_controls_at_current_boundary(
        &mut self,
        artifact: &SessionControlReplayArtifact,
        log_index: &mut usize,
    ) -> Result<(), SessionError> {
        while let Some(entry) = artifact.control_log.get(*log_index) {
            if entry.quanta < self.quanta {
                return Err(SessionError::ControlReplayBoundaryMismatch {
                    current_quanta: self.quanta,
                    recorded_quanta: entry.quanta,
                });
            }
            if entry.quanta != self.quanta {
                return Ok(());
            }
            if entry.frontier != self.frontier {
                return Err(SessionError::ControlReplayFrontierMismatch {
                    current: self.frontier,
                    recorded: entry.frontier,
                });
            }
            if entry.scheduler_control.is_none() {
                self.replay_non_scheduler_boundary_control(entry.command)?;
                *log_index += 1;
                continue;
            }

            let scheduler_batch = entry.scheduler_batch;
            if scheduler_batch == 0 {
                return Err(SessionError::ControlReplayBatchMismatch {
                    sequence: entry.sequence,
                    scheduler_batch,
                });
            }
            let mut controls = Vec::new();
            while let Some(batch_entry) = artifact.control_log.get(*log_index) {
                if batch_entry.quanta != self.quanta
                    || batch_entry.frontier != self.frontier
                    || batch_entry.scheduler_batch != scheduler_batch
                {
                    break;
                }
                let Some(control) = batch_entry.scheduler_control.clone() else {
                    return Err(SessionError::ControlReplayBatchMismatch {
                        sequence: batch_entry.sequence,
                        scheduler_batch,
                    });
                };
                controls.push(control);
                *log_index += 1;
            }
            self.apply_control_operations_at_boundary(controls)?;
        }
        Ok(())
    }

    fn replay_non_scheduler_boundary_control(
        &mut self,
        command: SessionCommandKind,
    ) -> Result<(), SessionError> {
        match command {
            SessionCommandKind::Pause | SessionCommandKind::Fork => {
                self.active_step = None;
                self.state = EngineState::Paused {
                    reason: PauseReason::UserRequested,
                };
            }
            SessionCommandKind::Stop => {
                self.quantum_loop.shutdown()?;
                self.pending_control.clear();
                self.active_step = None;
                self.enter_stopped(Outcome::Stopped)?;
            }
            SessionCommandKind::Start
            | SessionCommandKind::Continue
            | SessionCommandKind::StepQuantum
            | SessionCommandKind::StepEvent
            | SessionCommandKind::StepAssertion
            | SessionCommandKind::StepTimer
            | SessionCommandKind::StepDuration
            | SessionCommandKind::Inject
            | SessionCommandKind::InjectFault
            | SessionCommandKind::HealFault
            | SessionCommandKind::SetBreakpoint
            | SessionCommandKind::RemoveBreakpoint
            | SessionCommandKind::CreateSavepoint
            | SessionCommandKind::Query
            | SessionCommandKind::Snapshot
            | SessionCommandKind::AttachGdb
            | SessionCommandKind::DebugGoto
            | SessionCommandKind::DebugReverseStep
            | SessionCommandKind::DebugReverseContinue
            | SessionCommandKind::DebugForkNonCanonical => {}
        }
        Ok(())
    }

    /// Applies one actor-owned command at a state-machine boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] if the command is not valid
    /// in the current state. Returns [`SessionError::Engine`] or
    /// [`SessionError::Scheduler`] if the model or scheduler boundary fails.
    pub fn apply_command(&mut self, command: SessionCommand) -> Result<EngineSnapshot, SessionError>
    where
        L: QuantumLoop,
    {
        self.apply_command_with_event_log(command, &[])
    }

    /// Applies one actor-owned command with the current event-log prefix.
    ///
    /// `event_log` is used only by debugger branch-marking commands that must
    /// append visible non-canonical fork metadata to the actor-owned log.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] if the command is not valid
    /// in the current state. Returns [`SessionError::Engine`] or
    /// [`SessionError::Scheduler`] if the model or scheduler boundary fails.
    pub fn apply_command_with_event_log(
        &mut self,
        command: SessionCommand,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<EngineSnapshot, SessionError>
    where
        L: QuantumLoop,
    {
        match &command {
            SessionCommand::Acknowledge { command, reply } => {
                let result = self.apply_command_with_event_log((**command).clone(), event_log);
                match &result {
                    Ok(_) => reply.complete(Ok(())),
                    Err(error) => reply.complete(Err(error.clone())),
                }
                result
            }
            SessionCommand::Start => {
                if matches!(self.state, EngineState::Loaded) {
                    self.instantiate_runtime()
                } else {
                    Err(self.invalid_transition(command.clone()))
                }
            }
            SessionCommand::Continue => {
                if matches!(self.state, EngineState::Paused { .. }) {
                    self.reject_debug_forward_without_branch(&command)?;
                    self.active_step = None;
                    self.state = EngineState::Running;
                    Ok(self.snapshot())
                } else {
                    Err(self.invalid_transition(command.clone()))
                }
            }
            SessionCommand::Pause => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    self.active_step = None;
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
                    self.reject_debug_forward_without_branch(&command)?;
                    self.active_step = Some(ActiveStep::new(*mode, self.frontier));
                    self.state = EngineState::Running;
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
                EngineState::Running | EngineState::Paused { .. } | EngineState::Stopped { .. } => {
                    let checkpoint = self.resolve_fork_checkpoint(*from)?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    let handle = SessionHandle::new(self.configuration.id(), &checkpoint);
                    reply.complete(Ok(handle));
                    Ok(self.snapshot())
                }
                EngineState::Loaded => Err(self.invalid_transition(command.clone())),
            },
            SessionCommand::Inject => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let control = ControlOperationKind::Inject;
                    let event_log_sequence_before = usize_to_u64(self.event_log_len());
                    self.apply_control_operation_at_boundary(control.clone())?;
                    self.record_boundary_control_at(
                        &command,
                        Some(control),
                        event_log_sequence_before,
                    );
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::InjectFault { spec, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let control = ControlOperationKind::InjectFault {
                        tag: spec.tag.clone(),
                        fault: spec.fault.clone(),
                    };
                    let event_log_sequence_before = usize_to_u64(self.event_log_len());
                    self.apply_control_operation_at_boundary(control.clone())?;
                    self.record_boundary_control_at(
                        &command,
                        Some(control),
                        event_log_sequence_before,
                    );
                    reply.complete(Ok(spec.tag.clone()));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::HealFault { tag, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let control = ControlOperationKind::HealFault { tag: tag.clone() };
                    let event_log_sequence_before = usize_to_u64(self.event_log_len());
                    self.apply_control_operation_at_boundary(control.clone())?;
                    self.record_boundary_control_at(
                        &command,
                        Some(control),
                        event_log_sequence_before,
                    );
                    reply.complete(Ok(()));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::SetBreakpoint { spec, reply } => match self.state {
                EngineState::Loaded | EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    let id = self.breakpoints.insert(spec.clone());
                    reply.complete(Ok(id));
                    Ok(self.snapshot())
                }
                EngineState::Stopped { .. } => Err(self.invalid_transition(command.clone())),
            },
            SessionCommand::RemoveBreakpoint { id, reply } => match self.state {
                EngineState::Loaded | EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let removed = self.breakpoints.remove(*id);
                    if !removed {
                        let error = SessionError::BreakpointNotFound { id: *id };
                        reply.complete(Err(error.clone()));
                        return Err(error);
                    }
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    reply.complete(Ok(true));
                    Ok(self.snapshot())
                }
                EngineState::Stopped { .. } => Err(self.invalid_transition(command.clone())),
            },
            SessionCommand::CreateSavepoint { label, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let checkpoint = self.graph.save_checkpoint(&self.configuration)?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
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
                    self.quantum_loop.shutdown()?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    self.pending_control.clear();
                    self.active_step = None;
                    self.debug_branch_required = false;
                    self.enter_stopped(Outcome::Stopped)?;
                    Ok(self.snapshot())
                }
            }
            SessionCommand::Query { kind, reply } => {
                if matches!(self.state, EngineState::Running) {
                    self.admit_control_operation(ControlOperationKind::Query);
                }
                let snapshot = self.snapshot();
                let result = match kind {
                    QueryKind::Snapshot => QueryResult::Snapshot(Box::new(snapshot.clone())),
                    QueryKind::BreakpointFirings => {
                        QueryResult::BreakpointFirings(self.breakpoint_firings.clone())
                    }
                    QueryKind::State => {
                        QueryResult::State(LifecycleStateKind::from(&snapshot.state))
                    }
                    QueryKind::EventLogLength => {
                        QueryResult::EventLogLength(snapshot.event_log_len)
                    }
                    QueryKind::ExecutionFingerprint { node } => QueryResult::ExecutionFingerprint(
                        self.quantum_loop.sample_fingerprint(node.clone())?,
                    ),
                };
                reply.complete(Ok(result));
                Ok(snapshot)
            }
            SessionCommand::AttachGdb {
                node,
                listen,
                reply,
            } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let info = self
                        .quantum_loop
                        .open_gdbstub(node.clone(), listen.clone())?;
                    let qemu_endpoint = info.qemu_endpoint.clone();
                    let operator_listen = info.operator_listen.as_str().to_owned();
                    let request = DebugAttachRequest::new(
                        self.configuration.clone(),
                        info.node,
                        qemu_endpoint,
                        operator_listen,
                    )?;
                    let attach = self.graph.debug_attach(&request)?;
                    self.debug_attach = Some(attach.clone());
                    if matches!(self.state, EngineState::Running) {
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    reply.complete(Ok(attach));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugGoto { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let attach = self.current_debug_attach("debug-goto")?;
                    let report = self.graph.debug_goto(&attach, request)?;
                    let _refreshed = self.update_debug_position(&attach, &report)?;
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugReverseStep { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let attach = self.current_debug_attach("debug-reverse-step")?;
                    let report = self.graph.debug_reverse_step(&attach, request)?;
                    let _refreshed = self.update_debug_position(&attach, &report.goto)?;
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugReverseContinue { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let attach = self.current_debug_attach("debug-reverse-continue")?;
                    let report = self.graph.debug_reverse_continue(&attach, request)?;
                    if let Some(matched) = report.matched.as_ref() {
                        let _refreshed = self.update_debug_position(&attach, &matched.goto)?;
                    } else if matches!(self.state, EngineState::Running) {
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugForkNonCanonical { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.validate_event_log_prefix(event_log)?;
                    let attach = self.current_debug_attach("debug-fork-non-canonical")?;
                    let report = self
                        .graph
                        .debug_non_canonical_branch(&attach, request, event_log)?;
                    let entries = report
                        .event_log_with_fork_marker
                        .iter()
                        .skip(event_log.len())
                        .cloned()
                        .collect::<Vec<_>>();
                    self.append_boundary_event_log_entries(entries)?;
                    self.debug_branch_required = false;
                    if matches!(self.state, EngineState::Running) {
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
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
        let step_completion = if let Some(step) = self.active_step.as_ref() {
            Some((
                step.mode,
                step.is_complete(&outcome, current_event_log_len)
                    .map_err(|error| SessionError::BreakpointConditionPrefix {
                        reason: error.to_string(),
                    })?,
            ))
        } else {
            None
        };
        let runtime = self.graph.resume(&outcome.configuration)?.runtime;

        self.configuration = outcome.configuration.clone();
        self.runtime = Some(runtime);
        self.runtime_instantiated = true;
        self.frontier = outcome.frontier;
        self.event_log_len = u64_to_usize(outcome.event_log_offset.events);
        self.scheduler_quiescence = outcome.scheduler_quiescence.clone();
        self.quanta = self.quanta.saturating_add(1);
        self.pending_event_log_entries
            .extend(outcome.event_log_entries.iter().cloned());
        if let Some((mode, true)) = step_completion {
            self.state = EngineState::Paused {
                reason: PauseReason::StepComplete { mode },
            };
            self.active_step = None;
        }

        Ok(outcome)
    }

    fn stop_on_continuous_quiescence(&mut self) -> Result<(), SessionError> {
        if matches!(self.state, EngineState::Running)
            && self.active_step.is_none()
            && self.breakpoints.is_empty()
            && self
                .scheduler_quiescence
                .as_ref()
                .is_some_and(SchedulerQuiescence::is_quiescent)
        {
            self.quantum_loop.shutdown()?;
            self.pending_control.clear();
            self.enter_stopped(Outcome::Passed)?;
        }
        Ok(())
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
}

fn is_recoverable_command_rejection(command: &SessionCommand, error: &SessionError) -> bool {
    let SessionCommand::Acknowledge { .. } = command else {
        return false;
    };
    match error {
        SessionError::InvalidTransition { .. }
        | SessionError::InvalidEngineState { .. }
        | SessionError::BreakpointConditionPrefix { .. }
        | SessionError::UnsupportedBreakpointAction { .. }
        | SessionError::UnsupportedBreakpointFault { .. }
        | SessionError::BreakpointNotFound { .. }
        | SessionError::DebugAttachRequired { .. }
        | SessionError::DebugNonCanonicalBranchRequired { .. } => true,
        SessionError::Engine(error) => is_recoverable_engine_rejection(error),
        SessionError::Scheduler(error) => is_recoverable_scheduler_rejection(error),
        SessionError::ChannelClosed
        | SessionError::EventLogOffsetRegression { .. }
        | SessionError::EventLogOffsetMismatch { .. }
        | SessionError::ControlReplayBoundaryMismatch { .. }
        | SessionError::ControlReplayFrontierMismatch { .. }
        | SessionError::ControlReplayBatchMismatch { .. }
        | SessionError::ControlReplayFinalSnapshotMismatch { .. } => false,
    }
}

fn is_recoverable_engine_rejection(error: &EngineError) -> bool {
    matches!(
        error,
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
            | EngineError::DebugTimeTravelUnknownNode { .. }
            | EngineError::NotImplemented { .. }
            | EngineError::WorldNodeUnsupportedWorkload { .. }
            | EngineError::WorldNodeUnsupportedWorkloadConfigTree { .. }
            | EngineError::WorldNodeUnsupportedWorkloadPattern { .. }
            | EngineError::WorldNodeUnsupportedWorkloadSpikeMode { .. }
            | EngineError::WorldNodeUnsupportedWorkloadTimeSource { .. }
            | EngineError::PlanFaultUnsupportedParam { .. }
            | EngineError::DebugBreakpointRequiresAllowMutate { .. }
            | EngineError::EventLogReplayUnsupported { .. }
            | EngineError::SchedulePrefix(_)
    )
}

const fn is_recoverable_scheduler_rejection(error: &SchedulerError) -> bool {
    match error {
        SchedulerError::NotImplemented { .. }
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => true,
        SchedulerError::Backend(error) => is_recoverable_backend_rejection(error),
    }
}

const fn is_recoverable_backend_rejection(error: &BackendError) -> bool {
    match error {
        BackendError::NotImplemented { .. }
        | BackendError::Unsupported { .. }
        | BackendError::Rejected { .. } => true,
    }
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
    fn from(command: &SessionCommand) -> Self {
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

    fn from_control_or_kind(
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
    engine: Engine<L>,
    mailbox: mpsc::Receiver<SessionCommand>,
    live: Arc<LiveSnapshot>,
    event_log: SessionEventLog,
    reproduction_log: SessionReproductionLog,
    state_transitions: SessionStateTransitionBus,
    last_published_state: EngineState,
    fork_loop_factory: Option<SessionForkLoopFactory<L>>,
    condition_event_log: Vec<SchedulerEventLogEntry>,
    commands_applied: u64,
    yielded_after_quanta: u64,
    control_acknowledgements: u64,
    state_transition_sequence: u64,
    terminal_command_keepalive: bool,
    terminal_shutdown_requested: bool,
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
            commands_applied: 0,
            yielded_after_quanta: 0,
            control_acknowledgements: 0,
            state_transition_sequence: 0,
            terminal_command_keepalive: false,
            terminal_shutdown_requested: false,
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
        self.live.publish(&snapshot, self.control_acknowledgements);
        let after = self.live.read();
        let after_state = snapshot.state.clone();
        if before_state != after_state {
            self.state_transition_sequence = self.state_transition_sequence.saturating_add(1);
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

    fn append_event_log_entries(&mut self, entries: &[SchedulerEventLogEntry]) {
        let base_len = self.engine.event_log_len().saturating_sub(entries.len());
        self.event_log.truncate_to_len(base_len);
        self.condition_event_log.truncate(base_len);
        self.event_log.append_entries(entries);
        self.condition_event_log.extend(entries.iter().cloned());
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
}

fn split_acknowledged_command(
    command: SessionCommand,
) -> (SessionCommand, Option<CommandReply<()>>) {
    match command {
        SessionCommand::Acknowledge { command, reply } => (*command, Some(reply)),
        command => (command, None),
    }
}

fn acknowledged_stop_command(command: &SessionCommand) -> bool {
    matches!(
        command,
        SessionCommand::Acknowledge { command, .. } if matches!(command.as_ref(), SessionCommand::Stop)
    )
}

fn complete_acknowledgement(
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
    /// Returns [`SessionError::ChannelClosed`] if the mailbox closes before a
    /// terminal state. Returns other [`SessionError`] variants if a command,
    /// model operation, or scheduler quantum fails.
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
            self.run_once().await?;
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
            self.run_once_without_spawning_forks().await?;
        }
    }

    async fn run_once(&mut self) -> Result<(), SessionError> {
        match self.engine.state().clone() {
            EngineState::Running => {
                if let Some(command) = self.next_boundary_command()? {
                    self.apply_command_or_recover(command).await?;
                    return Ok(());
                }

                let pending_control = self.engine.pending_control_len() as u64;
                let _outcome = self.engine.step_quantum()?;
                let entries = self.engine.drain_event_log_entries();
                let emitted_event_log_entries = entries.len();
                self.append_event_log_entries(&entries);
                self.engine
                    .evaluate_breakpoints(&self.condition_event_log, emitted_event_log_entries)?;
                self.sync_reproduction_log();
                let breakpoint_entries = self.engine.drain_event_log_entries();
                self.append_event_log_entries(&breakpoint_entries);
                self.engine.stop_on_continuous_quiescence()?;
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
                self.apply_command_or_recover(command).await
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
                if let Some(command) = self.next_boundary_command()? {
                    self.apply_command_without_spawning_forks_or_recover(command)
                        .await?;
                    return Ok(());
                }

                let pending_control = self.engine.pending_control_len() as u64;
                let _outcome = self.engine.step_quantum()?;
                let entries = self.engine.drain_event_log_entries();
                let emitted_event_log_entries = entries.len();
                self.append_event_log_entries(&entries);
                self.engine
                    .evaluate_breakpoints(&self.condition_event_log, emitted_event_log_entries)?;
                self.sync_reproduction_log();
                let breakpoint_entries = self.engine.drain_event_log_entries();
                self.append_event_log_entries(&breakpoint_entries);
                self.engine.stop_on_continuous_quiescence()?;
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
                self.apply_command_without_spawning_forks_or_recover(command)
                    .await
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

    async fn apply_command(&mut self, command: SessionCommand) -> Result<(), SessionError> {
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

    async fn apply_command_without_spawning_forks(
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
        if let Err(error) = self
            .engine
            .apply_command_with_event_log(command.clone(), &condition_event_log)
        {
            command.complete_error(error.clone());
            complete_acknowledgement(acknowledgement, &Err(error.clone()));
            return Err(error);
        }
        let entries = self.engine.drain_event_log_entries();
        self.append_event_log_entries(&entries);
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
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use crucible::{
        Action, AssertionId, AssertionPhase, BackendInput, Checkpoint, CheckpointKind, ChoiceTag,
        DebugNonCanonicalBranchAction, DebugNonCanonicalBranchTrigger, DebugOperatorControlKind,
        DebugReverseStepGrain, Decision, DeliveryOrderDecision, Event, EventGraph, EventGraphState,
        EventId, EventKey, GdbAttachInfo, GenesisCheckpoint, LogLevel, MembershipFault, NodeId,
        NodeLifecycle, NodeTemplate, OverrideDecision, Predicate, ReadyPoint, ScenarioDef,
        ScheduledEvent, ScheduledEventKey, SchedulerNodeId, SchedulingNodeKind, SchedulingPoint,
        Seed, TimerId, TriggerActionApplication, VirtualTime, VmArchitecture, WhiteBoxPolicy,
        World, WorldNode, bake, step, try_step,
    };

    #[test]
    fn step_modes_cover_forward_vocabulary_and_reverse_grains() {
        assert_eq!(
            StepMode::ALL,
            [
                StepMode::Quantum,
                StepMode::Event,
                StepMode::Assertion,
                StepMode::Timer,
                StepMode::Duration(StepMode::DEFAULT_DURATION),
            ]
        );
        assert_eq!(
            StepMode::ALL
                .into_iter()
                .filter_map(StepMode::reverse_grain)
                .collect::<Vec<_>>(),
            vec![
                DebugReverseStepGrain::Quantum,
                DebugReverseStepGrain::Event,
                DebugReverseStepGrain::Assertion,
                DebugReverseStepGrain::Timer,
            ]
        );
        assert_eq!(
            StepMode::Duration(SimDuration { nanos: 10 }).reverse_grain(),
            None,
            "duration is a forward-only step bound until the debug model has a duration grain"
        );
    }

    #[test]
    fn step_modes_are_expressible_as_one_shot_breakpoints() {
        let start = VirtualTime { ticks: 10 };
        for mode in StepMode::ALL {
            let step = ActiveStep::new(mode, start);
            assert_eq!(step.breakpoint.disposition, BreakpointDisposition::Suspend);
            assert_eq!(step.breakpoint.policy, BreakpointPolicy::OneShot);
            match (mode, &step.breakpoint.predicate) {
                (
                    StepMode::Duration(duration),
                    Condition::At {
                        at: VirtualTime { ticks },
                    },
                ) => {
                    assert_eq!(*ticks, start.ticks.saturating_add(duration.nanos));
                }
                (StepMode::Quantum, Condition::Named { name, nodes }) => {
                    assert_eq!(name, "session.step.quantum");
                    assert!(nodes.is_empty());
                }
                (StepMode::Event, Condition::Named { name, nodes }) => {
                    assert_eq!(name, "session.step.event");
                    assert!(nodes.is_empty());
                }
                (StepMode::Assertion, Condition::Named { name, nodes }) => {
                    assert_eq!(name, "session.step.assertion");
                    assert!(nodes.is_empty());
                }
                (StepMode::Timer, Condition::Named { name, nodes }) => {
                    assert_eq!(name, "session.step.timer");
                    assert!(nodes.is_empty());
                }
                other => panic!("unexpected step stop condition: {other:?}"),
            }
        }
    }

    #[test]
    fn engine_step_modes_start_bounded_execution_for_forward_vocabulary() {
        let scenario = generated_scenario(22);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        for mode in StepMode::ALL {
            let mut engine = Engine::new(config.clone(), graph.clone(), StubLoop);
            if let Err(error) = engine.apply_command(SessionCommand::Start) {
                panic!("start should instantiate runtime: {error}");
            }
            let snapshot = match engine.apply_command(SessionCommand::Step { mode }) {
                Ok(snapshot) => snapshot,
                Err(error) => panic!("{mode:?} step should be accepted: {error}"),
            };
            assert_eq!(snapshot.state, EngineState::Running);
            assert_eq!(engine.quanta(), 0);
            assert_eq!(
                engine.active_step.as_ref().map(|step| step.mode),
                Some(mode)
            );
        }
    }

    #[test]
    fn engine_step_modes_complete_from_quantum_outcomes() {
        let cases = vec![
            (
                22,
                StepMode::Event,
                ScriptedStepLoop::with_payload(2, resolved_backend_input_payload(2)),
            ),
            (
                23,
                StepMode::Assertion,
                ScriptedStepLoop::with_payload(2, assertion_state_change_payload()),
            ),
            (
                24,
                StepMode::Timer,
                ScriptedStepLoop::with_payload(2, timer_fire_payload(2)),
            ),
            (
                25,
                StepMode::Duration(SimDuration { nanos: 2 }),
                ScriptedStepLoop::default(),
            ),
        ];

        for (seed, mode, quantum_loop) in cases {
            assert_engine_step_completes_after_second_quantum(seed, mode, quantum_loop);
        }
    }

    #[test]
    fn timer_step_ignores_timer_actions_without_timer_predicate_fire() {
        let scenario = generated_scenario(26);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(
            config,
            graph,
            ScriptedStepLoop::with_payload(2, timer_action_payload(2)),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime before timer action test: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Step {
            mode: StepMode::Timer,
        }) {
            panic!("timer step should start bounded execution: {error}");
        }

        for iteration in 0..2 {
            if let Err(error) = engine.step_quantum() {
                panic!("timer action test quantum {iteration} should run: {error}");
            }
        }

        assert_eq!(engine.quanta(), 2);
        assert_eq!(engine.state(), &EngineState::Running);
        assert_eq!(
            engine.active_step.as_ref().map(|step| step.mode),
            Some(StepMode::Timer)
        );
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
                SessionCommandKind::StepEvent,
                SessionCommandKind::StepAssertion,
                SessionCommandKind::StepTimer,
                SessionCommandKind::StepDuration,
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
                SessionCommandKind::AttachGdb,
                SessionCommandKind::DebugGoto,
                SessionCommandKind::DebugReverseStep,
                SessionCommandKind::DebugReverseContinue,
                SessionCommandKind::DebugForkNonCanonical,
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
                to: LifecycleStateKind::Running,
            }
        );
        assert_eq!(
            lifecycle_transition(LifecycleStateKind::Running, SessionCommandKind::Fork),
            LifecycleTransition::Accepted {
                to: LifecycleStateKind::Paused,
            }
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
            LifecycleTransition::Rejected
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
                let model = lifecycle_transition(state, command_kind);
                if command_kind == SessionCommandKind::RemoveBreakpoint
                    && matches!(model, LifecycleTransition::Accepted { .. })
                {
                    engine
                        .apply_command(SessionCommand::SetBreakpoint {
                            spec: BreakpointSpec::suspend_once(Condition::Quiescent),
                            reply: CommandReply::discard(),
                        })
                        .unwrap_or_else(|error| {
                            panic!("remove-breakpoint fixture should register breakpoint: {error}")
                        });
                }
                let before = engine.snapshot();
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
        assert_eq!(engine.pending_control_len(), 0);

        let (heal_reply, heal_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::HealFault {
            tag: fault_tag.clone(),
            reply: heal_reply,
        }) {
            panic!("heal fault should complete its acknowledgement: {error}");
        }
        receive_reply(heal_receiver).await;
        assert_eq!(engine.pending_control_len(), 0);

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
        assert_eq!(engine.pending_control_len(), 1);

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
        assert_eq!(fork.configuration, engine.configuration().id());
    }

    #[tokio::test]
    async fn debug_time_travel_commands_reposition_without_scheduler_control_log() {
        let (root, first, second, graph) = debug_time_travel_fixture();
        let mut engine = Engine::new(second.clone(), graph, DebugGdbLoop);

        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("debug fixture should instantiate: {error}");
        }
        let (attach_reply, attach_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::AttachGdb {
            node: node_id("guest-a"),
            listen: gdb_listen("127.0.0.1:9000"),
            reply: attach_reply,
        }) {
            panic!("attach-gdb should use the loop gdbstub capability: {error}");
        }
        let attach = receive_reply(attach_receiver).await;
        assert_eq!(attach.configuration, second.id());
        assert!(attach.has_four_channel_debug_boundary());
        assert!(engine.boundary_control_log().is_empty());

        let (reverse_continue_reply, reverse_continue_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::DebugReverseContinue {
            request: DebugReverseContinueRequest::new(
                second.clone(),
                Condition::At {
                    at: VirtualTime { ticks: 1 },
                },
                Vec::new(),
            ),
            reply: reverse_continue_reply,
        }) {
            panic!("reverse-continue with no matching prefix should complete: {error}");
        }
        assert!(
            receive_reply(reverse_continue_receiver)
                .await
                .matched
                .is_none()
        );
        assert!(!engine.debug_branch_required());

        let (goto_reply, goto_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::DebugGoto {
            request: DebugGotoRequest::at_configuration(second.clone(), first.clone()),
            reply: goto_reply,
        }) {
            panic!("debug goto should delegate to restore-plus-replay: {error}");
        }
        let goto = receive_reply(goto_receiver).await;
        assert_eq!(goto.target_configuration, first.id());
        assert_eq!(engine.configuration().id(), first.id());
        assert_eq!(
            engine.debug_attach().map(|active| active.configuration),
            Some(first.id())
        );
        assert!(engine.debug_branch_required());
        assert!(engine.boundary_control_log().is_empty());

        let blocked = engine
            .apply_command(SessionCommand::Continue)
            .expect_err("continuing after debug reposition must require branch metadata");
        assert!(matches!(
            blocked,
            SessionError::DebugNonCanonicalBranchRequired {
                operation: "continue"
            }
        ));

        let branch_request = DebugNonCanonicalBranchRequest::new(
            first.clone(),
            engine.frontier(),
            DebugNonCanonicalBranchTrigger::OperatorContinue,
        )
        .with_action(DebugNonCanonicalBranchAction::operator_control(
            DebugOperatorControlKind::Continue,
        ));
        let (branch_reply, branch_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::DebugForkNonCanonical {
            request: branch_request,
            reply: branch_reply,
        }) {
            panic!("non-canonical debug branch should clear forward guard: {error}");
        }
        let branch = receive_reply(branch_receiver).await;
        assert!(branch.proves_non_canonical_debug_branch());
        assert!(!engine.debug_branch_required());
        let branch_entries = engine.drain_event_log_entries();
        assert_eq!(branch_entries.len(), 1);
        assert_eq!(branch_entries[0].sequence(), 0);
        let branch_count = engine.graph.debug_non_canonical_branch_count();
        let stale_prefix_error = engine
            .apply_command(SessionCommand::DebugForkNonCanonical {
                request: DebugNonCanonicalBranchRequest::new(
                    first.clone(),
                    engine.frontier(),
                    DebugNonCanonicalBranchTrigger::OperatorContinue,
                )
                .with_action(DebugNonCanonicalBranchAction::operator_control(
                    DebugOperatorControlKind::Continue,
                )),
                reply: CommandReply::discard(),
            })
            .expect_err("direct branch without a nonzero event-log prefix must fail first");
        assert!(matches!(
            stale_prefix_error,
            SessionError::EventLogOffsetMismatch {
                current: 1,
                emitted: 0,
                next: 0,
            }
        ));
        assert_eq!(
            engine.graph.debug_non_canonical_branch_count(),
            branch_count,
            "prefix mismatch must not mutate graph branch metadata"
        );
        let malformed_prefix_error = engine
            .apply_command_with_event_log(
                SessionCommand::DebugForkNonCanonical {
                    request: DebugNonCanonicalBranchRequest::new(
                        first.clone(),
                        engine.frontier(),
                        DebugNonCanonicalBranchTrigger::OperatorContinue,
                    )
                    .with_action(
                        DebugNonCanonicalBranchAction::operator_control(
                            DebugOperatorControlKind::Continue,
                        ),
                    ),
                    reply: CommandReply::discard(),
                },
                &[test_event_log_entry(7)],
            )
            .expect_err("same-length malformed branch prefix must fail before graph mutation");
        assert!(matches!(
            malformed_prefix_error,
            SessionError::EventLogOffsetMismatch {
                current: 1,
                emitted: 0,
                next: 7,
            }
        ));
        assert_eq!(
            engine.graph.debug_non_canonical_branch_count(),
            branch_count,
            "malformed same-length prefix must not mutate graph branch metadata"
        );
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue after non-canonical branch marker should be accepted: {error}");
        }

        let (reverse_step_reply, reverse_step_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::DebugReverseStep {
            request: DebugReverseStepRequest::new(
                first.clone(),
                DebugReverseStepGrain::Instruction,
                Vec::new(),
            ),
            reply: reverse_step_reply,
        }) {
            panic!("reverse-step should delegate through debug goto: {error}");
        }
        let reverse_step = receive_reply(reverse_step_receiver).await;
        assert_eq!(reverse_step.target_configuration, root.id());
        assert!(reverse_step.realized_by_goto());
        assert_eq!(engine.configuration().id(), root.id());
        assert!(engine.debug_branch_required());
        assert!(engine.boundary_control_log().is_empty());
        if let Err(error) = engine.apply_command(SessionCommand::Stop) {
            panic!("stop after debug reposition should be accepted: {error}");
        }
        let terminal_continue = engine
            .apply_command(SessionCommand::Continue)
            .expect_err("terminal continue should fail as invalid transition, not debug guard");
        assert!(matches!(
            terminal_continue,
            SessionError::InvalidTransition { .. }
        ));
    }

    #[tokio::test]
    async fn actor_debug_noncanonical_branch_appends_visible_event_log_marker() {
        let (_root, first, second, graph) = debug_time_travel_fixture();
        let engine = Engine::new(second.clone(), graph, DebugGdbLoop);
        let (_sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor
            .apply_command_without_spawning_forks(SessionCommand::Start)
            .await
        {
            panic!("debug actor fixture should instantiate: {error}");
        }
        let (attach_reply, attach_receiver) = CommandReply::channel();
        if let Err(error) = actor
            .apply_command_without_spawning_forks(SessionCommand::AttachGdb {
                node: node_id("guest-a"),
                listen: gdb_listen("127.0.0.1:9000"),
                reply: attach_reply,
            })
            .await
        {
            panic!("debug actor should attach gdb: {error}");
        }
        let attach = receive_reply(attach_receiver).await;
        assert_eq!(attach.configuration, second.id());

        let mut unread_stream = actor.event_log_stream(EventLogCursor::new(0));
        let mut past_stream = actor.event_log_stream(EventLogCursor::new(0));

        actor.append_event_log_entries(&[test_event_log_entry(0), test_event_log_entry(1)]);
        actor.engine.event_log_len = 2;
        for expected in [test_event_log_entry(0), test_event_log_entry(1)] {
            let frame = past_stream
                .recv()
                .await
                .expect("past stream should not lag before rewind")
                .expect("past stream should receive the stale prefix before rewind");
            assert_eq!(frame.generation, 0);
            assert_eq!(frame.entry, expected);
        }
        assert_eq!(past_stream.cursor(), EventLogCursor::new(2));

        let (goto_reply, goto_receiver) = CommandReply::channel();
        if let Err(error) = actor
            .apply_command_without_spawning_forks(SessionCommand::DebugGoto {
                request: DebugGotoRequest::at_configuration(second.clone(), first.clone()),
                reply: goto_reply,
            })
            .await
        {
            panic!("debug goto should rewind actor to first prefix: {error}");
        }
        let goto = receive_reply(goto_receiver).await;
        assert_eq!(goto.target_configuration, first.id());
        assert_eq!(actor.engine.event_log_len(), 0);

        let branch_request = DebugNonCanonicalBranchRequest::new(
            first.clone(),
            actor.engine.frontier(),
            DebugNonCanonicalBranchTrigger::OperatorContinue,
        )
        .with_action(DebugNonCanonicalBranchAction::operator_control(
            DebugOperatorControlKind::Continue,
        ));
        let (branch_reply, branch_receiver) = CommandReply::channel();
        if let Err(error) = actor
            .apply_command_without_spawning_forks(SessionCommand::DebugForkNonCanonical {
                request: branch_request,
                reply: branch_reply,
            })
            .await
        {
            panic!("debug branch should append through actor event log: {error}");
        }
        let branch = receive_reply(branch_receiver).await;
        assert!(branch.proves_non_canonical_debug_branch());
        let marker = branch.branch.fork_marker.entry.clone();
        let mut replay = actor.event_log_stream(EventLogCursor::new(0));
        let frame = replay
            .recv()
            .await
            .expect("event-log stream should not lag")
            .expect("debug branch marker should be visible after stale future truncation");
        assert_eq!(frame.cursor, EventLogCursor::new(0));
        assert!(frame.generation > 0);
        assert_eq!(frame.entry, marker);
        assert_ne!(frame.entry, test_event_log_entry(0));
        assert_ne!(frame.entry, test_event_log_entry(1));

        let unread_frame = unread_stream
            .recv()
            .await
            .expect("unread active stream should not lag")
            .expect("unread active stream should receive the replacement marker");
        assert_eq!(unread_frame.cursor, EventLogCursor::new(0));
        assert!(unread_frame.generation > 0);
        assert_eq!(unread_frame.entry, marker);
        assert_ne!(unread_frame.entry, test_event_log_entry(0));
        assert_ne!(unread_frame.entry, test_event_log_entry(1));

        let past_frame = past_stream
            .recv()
            .await
            .expect("past active stream should not lag")
            .expect("past active stream should receive the replacement marker");
        assert_eq!(past_frame.cursor, EventLogCursor::new(0));
        assert!(past_frame.generation > 0);
        assert_eq!(past_frame.entry, marker);
        assert_ne!(past_frame.entry, test_event_log_entry(0));
        assert_ne!(past_frame.entry, test_event_log_entry(1));

        assert_eq!(actor.event_log.len(), 1);
        assert_eq!(actor.condition_event_log.len(), 1);
        assert_eq!(actor.condition_event_log[0], marker);
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
        let (set_reply, set_receiver) = CommandReply::channel();
        let (remove_reply, remove_receiver) = CommandReply::channel();
        let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
        let rejected_set = SessionCommand::SetBreakpoint {
            spec: BreakpointSpec::suspend_once(Condition::Quiescent),
            reply: set_reply,
        };
        let rejected_remove = SessionCommand::RemoveBreakpoint {
            id: 1,
            reply: remove_reply,
        };
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
            rejected_set.clone(),
            rejected_remove.clone(),
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
        assert_eq!(fork.configuration, report.final_snapshot.configuration.id());
        let error = receive_reply_error::<BreakpointId>(set_receiver).await;
        assert_rejection_names_state_and_command(
            error,
            report.final_snapshot.state.clone(),
            rejected_set,
        );
        let error = receive_reply_error::<bool>(remove_receiver).await;
        assert_rejection_names_state_and_command(
            error,
            report.final_snapshot.state.clone(),
            rejected_remove,
        );
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

    #[tokio::test]
    async fn running_boundary_commands_record_deterministic_control_log() {
        let scenario = generated_scenario(35);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let control_batches = Arc::new(Mutex::new(Vec::new()));
        let mut engine = Engine::new(
            config,
            graph,
            RecordingLoop::new(Arc::clone(&control_batches)),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (sender, receiver) = mpsc::channel(16);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("initial running iteration should establish a nonzero boundary: {error}");
        }
        assert_eq!(actor.engine().quanta(), 1);

        if let Err(error) = sender.send(SessionCommand::Inject).await {
            panic!("legacy inject command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running legacy inject should be applied at a boundary: {error}");
        }

        let fault_tag = FaultTag::from_name("boundary-log-fault");
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        let (inject_reply, inject_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::InjectFault {
                spec: FaultSpec::new(fault_tag.clone(), fault.clone()),
                reply: inject_reply,
            })
            .await
        {
            panic!("inject-fault command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running inject-fault should be applied at a boundary: {error}");
        }
        assert_eq!(receive_reply(inject_receiver).await, fault_tag.clone());

        let (heal_reply, heal_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::HealFault {
                tag: fault_tag.clone(),
                reply: heal_reply,
            })
            .await
        {
            panic!("heal-fault command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running heal-fault should be applied at a boundary: {error}");
        }
        receive_reply(heal_receiver).await;
        assert_eq!(actor.engine().pending_control_len(), 0);

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
            panic!("running set-breakpoint should be applied at a boundary: {error}");
        }
        let breakpoint_id = receive_reply(set_receiver).await;

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
            panic!("running remove-breakpoint should be applied at a boundary: {error}");
        }
        assert!(receive_reply(remove_receiver).await);

        let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::CreateSavepoint {
                label: String::from("boundary-log-savepoint"),
                reply: savepoint_reply,
            })
            .await
        {
            panic!("savepoint command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running savepoint should be applied at a boundary: {error}");
        }
        assert_eq!(
            receive_reply(savepoint_receiver).await.label,
            "boundary-log-savepoint"
        );

        let (fork_reply, fork_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::Fork {
                from: CheckpointRef::Current,
                reply: fork_reply,
            })
            .await
        {
            panic!("fork command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running fork should pause and resolve at a boundary: {error}");
        }
        let fork = receive_reply(fork_receiver).await;
        assert_eq!(fork.checkpoint, actor.engine().configuration().id());
        assert_eq!(fork.configuration, actor.engine().configuration().id());

        let log = actor.engine().boundary_control_log();
        assert_eq!(log.len(), 7);
        assert_boundary_log_entry(
            &log[0],
            1,
            SessionCommandKind::Inject,
            Some(ControlOperationKind::Inject),
        );
        assert_boundary_log_entry(
            &log[1],
            2,
            SessionCommandKind::InjectFault,
            Some(ControlOperationKind::InjectFault {
                tag: fault_tag.clone(),
                fault: fault.clone(),
            }),
        );
        assert_boundary_log_entry(
            &log[2],
            3,
            SessionCommandKind::HealFault,
            Some(ControlOperationKind::HealFault {
                tag: fault_tag.clone(),
            }),
        );
        assert_boundary_log_entry(&log[3], 4, SessionCommandKind::SetBreakpoint, None);
        assert_boundary_log_entry(&log[4], 5, SessionCommandKind::RemoveBreakpoint, None);
        assert_boundary_log_entry(&log[5], 6, SessionCommandKind::CreateSavepoint, None);
        assert_boundary_log_entry(&log[6], 7, SessionCommandKind::Fork, None);
        assert!(
            log.iter()
                .all(|entry| entry.frontier.ticks > 0 && entry.quanta > 0),
            "all commands were applied at nonzero scheduler boundaries"
        );
        assert_eq!(log[0].frontier, VirtualTime { ticks: 1 });
        assert_eq!(log[0].quanta, 1);
        assert_eq!(log[6].frontier, VirtualTime { ticks: 1 });
        assert_eq!(log[6].quanta, 1);
        assert_eq!(
            recorded_control_batches(&control_batches),
            vec![
                Vec::new(),
                vec![ControlOperationKind::Inject],
                vec![ControlOperationKind::InjectFault {
                    tag: fault_tag.clone(),
                    fault,
                }],
                vec![ControlOperationKind::HealFault { tag: fault_tag }],
            ]
        );
        assert_eq!(actor.engine().pending_control_len(), 0);
        assert_eq!(actor.engine().quanta(), 1);
        assert!(matches!(
            actor.engine().state(),
            EngineState::Paused {
                reason: PauseReason::UserRequested
            }
        ));
    }

    #[tokio::test]
    async fn paused_boundary_mutators_apply_and_record_control_log() {
        let scenario = generated_scenario(43);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let control_batches = Arc::new(Mutex::new(Vec::new()));
        let mut engine = Engine::new(
            config,
            graph,
            RecordingLoop::new(Arc::clone(&control_batches)),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }

        if let Err(error) = engine.apply_command(SessionCommand::Inject) {
            panic!("paused legacy inject should apply at the current boundary: {error}");
        }

        let fault_tag = FaultTag::from_name("paused-boundary-fault");
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        let (inject_reply, inject_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::InjectFault {
            spec: FaultSpec::new(fault_tag.clone(), fault.clone()),
            reply: inject_reply,
        }) {
            panic!("paused inject-fault should apply at the current boundary: {error}");
        }
        assert_eq!(receive_reply(inject_receiver).await, fault_tag.clone());

        let (heal_reply, heal_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::HealFault {
            tag: fault_tag.clone(),
            reply: heal_reply,
        }) {
            panic!("paused heal-fault should apply at the current boundary: {error}");
        }
        receive_reply(heal_receiver).await;

        let log = engine.boundary_control_log();
        assert_eq!(log.len(), 3);
        assert_boundary_log_entry(
            &log[0],
            1,
            SessionCommandKind::Inject,
            Some(ControlOperationKind::Inject),
        );
        assert_boundary_log_entry(
            &log[1],
            2,
            SessionCommandKind::InjectFault,
            Some(ControlOperationKind::InjectFault {
                tag: fault_tag.clone(),
                fault: fault.clone(),
            }),
        );
        assert_boundary_log_entry(
            &log[2],
            3,
            SessionCommandKind::HealFault,
            Some(ControlOperationKind::HealFault {
                tag: fault_tag.clone(),
            }),
        );
        assert!(
            log.iter()
                .all(|entry| entry.frontier == VirtualTime::default() && entry.quanta == 0),
            "paused mutators should record the existing boundary, not host timing"
        );
        assert_eq!(
            recorded_control_batches(&control_batches),
            vec![
                vec![ControlOperationKind::Inject],
                vec![ControlOperationKind::InjectFault {
                    tag: fault_tag.clone(),
                    fault,
                }],
                vec![ControlOperationKind::HealFault { tag: fault_tag }],
            ]
        );
        assert_eq!(engine.pending_control_len(), 0);
        assert!(matches!(
            engine.state(),
            EngineState::Paused {
                reason: PauseReason::Instantiated
            }
        ));
    }

    #[test]
    fn boundary_control_at_sequence_is_before_scheduler_control_events() {
        let scenario = generated_scenario(431);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ControlEventLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }

        if let Err(error) = engine.apply_command(SessionCommand::Inject) {
            panic!("paused inject should apply at the current boundary: {error}");
        }

        assert_eq!(engine.event_log_len(), 1);
        let log = engine.boundary_control_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].event_log_sequence_before, 0);
        assert_eq!(log[0].command, SessionCommandKind::Inject);
        assert_eq!(
            log[0].payload,
            SessionControlPayload::CommandKind {
                command: SessionCommandKind::Inject,
            },
        );
    }

    #[test]
    fn control_replay_artifact_reproduces_interactive_scheduler_state() {
        let scenario = generated_scenario(44);
        let initial = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut interactive = Engine::new(
            initial.clone(),
            graph.clone(),
            ControlSensitiveLoop::default(),
        );
        if let Err(error) = interactive.apply_command(SessionCommand::Start) {
            panic!("interactive replay producer should instantiate: {error}");
        }
        if let Err(error) = interactive.apply_command(SessionCommand::Continue) {
            panic!("interactive replay producer should run: {error}");
        }
        if let Err(error) = interactive.step_quantum() {
            panic!("first producer quantum should establish a control boundary: {error}");
        }

        let fault_tag = FaultTag::from_name("control-replay-fault");
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        if let Err(error) = interactive.apply_command(SessionCommand::Inject) {
            panic!("producer legacy inject should apply at the current boundary: {error}");
        }
        let (inject_reply, inject_receiver) = CommandReply::channel();
        if let Err(error) = interactive.apply_command(SessionCommand::InjectFault {
            spec: FaultSpec::new(fault_tag.clone(), fault),
            reply: inject_reply,
        }) {
            panic!("producer inject-fault should apply at the current boundary: {error}");
        }
        drop(inject_receiver);
        if let Err(error) = interactive.step_quantum() {
            panic!("second producer quantum should observe injected scheduler state: {error}");
        }

        let (heal_reply, heal_receiver) = CommandReply::channel();
        if let Err(error) = interactive.apply_command(SessionCommand::HealFault {
            tag: fault_tag,
            reply: heal_reply,
        }) {
            panic!("producer heal-fault should apply at the current boundary: {error}");
        }
        drop(heal_receiver);
        if let Err(error) = interactive.step_quantum() {
            panic!("third producer quantum should observe healed scheduler state: {error}");
        }

        let artifact = interactive.control_replay_artifact(initial);
        let replay = match Engine::<ControlSensitiveLoop>::replay_control_replay_artifact(
            &artifact,
            graph_with_baked_genesis(&scenario),
            ControlSensitiveLoop::default(),
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                panic!("control replay artifact should reproduce scheduler state: {error}")
            }
        };

        assert_eq!(
            replay.configuration.id(),
            artifact.final_snapshot.configuration.id()
        );
        assert_eq!(replay.frontier, artifact.final_snapshot.frontier);
        assert_eq!(replay.event_log_len, artifact.final_snapshot.event_log_len);
        assert_eq!(replay.quanta, artifact.final_snapshot.quanta);
        assert_eq!(artifact.control_log.len(), 3);
        assert!(
            artifact
                .control_log
                .iter()
                .all(|entry| entry.frontier.ticks > 0 && entry.quanta > 0),
            "replay controls should be keyed by virtual-time boundaries"
        );
        assert_eq!(
            artifact.control_log[0].quanta,
            artifact.control_log[1].quanta
        );
        assert_ne!(
            artifact.control_log[0].scheduler_batch, artifact.control_log[1].scheduler_batch,
            "separate operator commands at the same boundary must remain separate scheduler batches"
        );
    }

    #[test]
    fn control_replay_artifact_rejects_wrong_boundary_frontier() {
        let scenario = generated_scenario(45);
        let initial = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut interactive = Engine::new(
            initial.clone(),
            graph.clone(),
            ControlSensitiveLoop::default(),
        );
        if let Err(error) = interactive.apply_command(SessionCommand::Start) {
            panic!("interactive replay producer should instantiate: {error}");
        }
        if let Err(error) = interactive.apply_command(SessionCommand::Continue) {
            panic!("interactive replay producer should run: {error}");
        }
        if let Err(error) = interactive.step_quantum() {
            panic!("producer quantum should establish a replay boundary: {error}");
        }
        if let Err(error) = interactive.apply_command(SessionCommand::Inject) {
            panic!("producer inject should apply at the current boundary: {error}");
        }
        let mut artifact = interactive.control_replay_artifact(initial);
        artifact.control_log[0].frontier = VirtualTime { ticks: 99 };

        let error = match Engine::<ControlSensitiveLoop>::replay_control_replay_artifact(
            &artifact,
            graph_with_baked_genesis(&scenario),
            ControlSensitiveLoop::default(),
        ) {
            Ok(snapshot) => {
                panic!("frontier-mismatched artifact should reject, got {snapshot:?}")
            }
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SessionError::ControlReplayFrontierMismatch {
                current: VirtualTime { ticks: 1 },
                recorded: VirtualTime { ticks: 99 },
            }
        ));
    }

    #[test]
    fn control_replay_artifact_rejects_final_snapshot_mismatch() {
        let scenario = generated_scenario(46);
        let initial = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut interactive = Engine::new(initial.clone(), graph, ControlSensitiveLoop::default());
        if let Err(error) = interactive.apply_command(SessionCommand::Start) {
            panic!("interactive replay producer should instantiate: {error}");
        }
        if let Err(error) = interactive.apply_command(SessionCommand::Continue) {
            panic!("interactive replay producer should run: {error}");
        }
        if let Err(error) = interactive.step_quantum() {
            panic!("producer quantum should establish a replay boundary: {error}");
        }
        let mut artifact = interactive.control_replay_artifact(initial);
        artifact.final_snapshot.event_log_len += 1;

        let error = match Engine::<ControlSensitiveLoop>::replay_control_replay_artifact(
            &artifact,
            graph_with_baked_genesis(&scenario),
            ControlSensitiveLoop::default(),
        ) {
            Ok(snapshot) => {
                panic!("final-snapshot-mismatched artifact should reject, got {snapshot:?}")
            }
            Err(error) => error,
        };

        let SessionError::ControlReplayFinalSnapshotMismatch { expected, actual } = error else {
            panic!("expected final snapshot mismatch, got {error:?}");
        };
        assert_eq!(expected.event_log_len, actual.event_log_len + 1);
        assert_eq!(expected.quanta, actual.quanta);
        assert_eq!(expected.frontier, actual.frontier);
        assert_eq!(expected.configuration.id(), actual.configuration.id());
    }

    #[tokio::test]
    async fn control_replay_artifact_replays_grouped_breakpoint_actions_as_one_batch() {
        let scenario = generated_scenario(47);
        let initial = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(
            initial.clone(),
            graph.clone(),
            ControlSensitiveLoop::default(),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("group replay producer should instantiate: {error}");
        }
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        let first_tag = FaultTag::from_name("group-replay-first");
        let second_tag = FaultTag::from_name("group-replay-second");
        let action = Action::group(vec![
            Action::inject_fault(first_tag.clone(), MembershipFault::taxonomy(fault.clone())),
            Action::inject_fault(second_tag.clone(), MembershipFault::taxonomy(fault)),
        ]);
        let breakpoint = BreakpointSpec {
            predicate: Predicate::at(VirtualTime { ticks: 1 }),
            disposition: BreakpointDisposition::Action(action),
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, _receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("group breakpoint should register before continue: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("group replay producer should run: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);
        if let Err(error) = actor.run_once().await {
            panic!("first producer quantum should fire the grouped breakpoint: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("second producer quantum should observe grouped scheduler state: {error}");
        }
        let artifact = actor.engine().control_replay_artifact(initial);

        assert_eq!(artifact.control_log.len(), 2);
        assert_ne!(artifact.control_log[0].scheduler_batch, 0);
        assert_eq!(
            artifact.control_log[0].scheduler_batch, artifact.control_log[1].scheduler_batch,
            "grouped breakpoint controls must share one scheduler batch"
        );
        assert!(matches!(
            &artifact.control_log[0].scheduler_control,
            Some(ControlOperationKind::InjectFault { tag, .. }) if tag == &first_tag
        ));
        assert!(matches!(
            &artifact.control_log[1].scheduler_control,
            Some(ControlOperationKind::InjectFault { tag, .. }) if tag == &second_tag
        ));

        let replay = match Engine::<ControlSensitiveLoop>::replay_control_replay_artifact(
            &artifact,
            graph_with_baked_genesis(&scenario),
            ControlSensitiveLoop::default(),
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("grouped breakpoint controls should replay as one batch: {error}"),
        };
        assert_eq!(replay, artifact.final_snapshot);
    }

    #[tokio::test]
    async fn pause_and_stop_take_effect_at_boundary_without_extra_quantum() {
        for command in [SessionCommand::Pause, SessionCommand::Stop] {
            let scenario = generated_scenario(36);
            let config = Configuration::genesis(scenario.clone());
            let graph = graph_with_baked_genesis(&scenario);
            let shutdowns = Arc::new(AtomicU64::new(0));
            let mut engine = Engine::new(config, graph, ShutdownLoop::new(Arc::clone(&shutdowns)));
            if let Err(error) = engine.apply_command(SessionCommand::Start) {
                panic!("start should instantiate runtime: {error}");
            }
            if let Err(error) = engine.apply_command(SessionCommand::Continue) {
                panic!("continue should enter running state: {error}");
            }
            let (sender, receiver) = mpsc::channel(2);
            let mut actor = SessionActor::new(engine, receiver);
            if let Err(error) = sender.send(command.clone()).await {
                panic!("boundary command should enqueue: {error}");
            }

            if let Err(error) = actor.run_once().await {
                panic!("{command:?} should be serviced at the next boundary check: {error}");
            }

            assert_eq!(actor.engine().quanta(), 0);
            let log = actor.engine().boundary_control_log();
            assert_eq!(log.len(), 1);
            assert_boundary_log_entry(&log[0], 1, SessionCommandKind::from(&command), None);
            let expected_shutdowns = match &command {
                SessionCommand::Stop => 1,
                _ => 0,
            };
            match &command {
                SessionCommand::Pause => assert!(matches!(
                    actor.engine().state(),
                    EngineState::Paused {
                        reason: PauseReason::UserRequested
                    }
                )),
                SessionCommand::Stop => assert!(matches!(
                    actor.engine().state(),
                    EngineState::Stopped {
                        outcome: Outcome::Stopped
                    }
                )),
                _ => panic!("test only covers pause and stop"),
            }
            assert_eq!(shutdowns.load(Ordering::SeqCst), expected_shutdowns);
        }
    }

    #[tokio::test]
    async fn stop_after_scheduler_control_does_not_drop_logged_effect() {
        let scenario = generated_scenario(37);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let control_batches = Arc::new(Mutex::new(Vec::new()));
        let shutdowns = Arc::new(AtomicU64::new(0));
        let mut engine = Engine::new(
            config,
            graph,
            RecordingLoop::with_shutdown(Arc::clone(&control_batches), Arc::clone(&shutdowns)),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        let fault_tag = FaultTag::from_name("stop-after-control");
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        let (inject_reply, inject_receiver) = CommandReply::channel();
        if let Err(error) = sender
            .send(SessionCommand::InjectFault {
                spec: FaultSpec::new(fault_tag.clone(), fault.clone()),
                reply: inject_reply,
            })
            .await
        {
            panic!("inject-fault command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("running inject-fault should be applied at a boundary: {error}");
        }
        assert_eq!(receive_reply(inject_receiver).await, fault_tag.clone());
        assert_eq!(actor.engine().pending_control_len(), 0);

        if let Err(error) = sender.send(SessionCommand::Stop).await {
            panic!("stop command should enqueue after scheduler control: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("stop after scheduler control should not drive a quantum: {error}");
        }

        assert_eq!(actor.engine().quanta(), 0);
        assert_eq!(
            recorded_control_batches(&control_batches),
            vec![vec![ControlOperationKind::InjectFault {
                tag: fault_tag,
                fault,
            }]]
        );
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        let log = actor.engine().boundary_control_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].command, SessionCommandKind::InjectFault);
        assert_eq!(log[1].command, SessionCommandKind::Stop);
        assert!(matches!(
            actor.engine().state(),
            EngineState::Stopped {
                outcome: Outcome::Stopped
            }
        ));
    }

    #[tokio::test]
    async fn breakpoint_suspend_uses_shared_condition_and_preserves_canonical_log() {
        let baseline_entries = {
            let scenario = generated_scenario(38);
            let config = Configuration::genesis(scenario.clone());
            let graph = graph_with_baked_genesis(&scenario);
            let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
            if let Err(error) = engine.apply_command(SessionCommand::Start) {
                panic!("baseline start should instantiate runtime: {error}");
            }
            if let Err(error) = engine.apply_command(SessionCommand::Continue) {
                panic!("baseline continue should enter running state: {error}");
            }
            let (_sender, receiver) = mpsc::channel(1);
            let mut actor = SessionActor::new(engine, receiver);
            if let Err(error) = actor.run_once().await {
                panic!("baseline actor should drive one quantum: {error}");
            }
            actor.event_log.lock_entries().clone()
        };

        let scenario = generated_scenario(38);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("breakpoint start should instantiate runtime: {error}");
        }
        let predicate = Predicate::all_of(vec![
            Predicate::once(Predicate::at(VirtualTime { ticks: 1 })),
            Predicate::not(Predicate::at(VirtualTime { ticks: 2 })),
        ]);
        let breakpoint = BreakpointSpec::suspend_once(predicate.clone());
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint.clone(),
            reply,
        }) {
            panic!("breakpoint should register before continue: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("breakpoint actor should drive one quantum: {error}");
        }

        assert_eq!(
            actor.engine().state(),
            &EngineState::Paused {
                reason: PauseReason::Breakpoint { id: breakpoint_id },
            }
        );
        assert!(actor.engine().breakpoints().is_empty());
        assert_eq!(
            &*actor.event_log.lock_entries(),
            baseline_entries.as_slice()
        );
        assert_eq!(
            actor.engine().breakpoint_firings(),
            &[BreakpointFiring {
                sequence: 1,
                id: breakpoint_id,
                predicate,
                disposition: BreakpointDisposition::Suspend,
                frontier: VirtualTime { ticks: 1 },
                quanta: 1,
                scheduler_controls: Vec::new(),
            }]
        );
    }

    #[tokio::test]
    async fn repeatable_trace_breakpoint_fires_on_false_to_true_transitions() {
        let scenario = generated_scenario(39);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("trace breakpoint start should instantiate runtime: {error}");
        }
        let predicate = Predicate::any_of(vec![
            Predicate::at(VirtualTime { ticks: 1 }),
            Predicate::at(VirtualTime { ticks: 3 }),
        ]);
        let breakpoint = BreakpointSpec {
            predicate,
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::Repeatable,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("trace breakpoint should register before continue: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("trace breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("first trace quantum should run: {error}");
        }
        assert_eq!(actor.engine().breakpoint_firings().len(), 1);
        assert!(matches!(actor.engine().state(), EngineState::Running));

        if let Err(error) = actor.run_once().await {
            panic!("second trace quantum should run: {error}");
        }
        assert_eq!(actor.engine().breakpoint_firings().len(), 1);
        assert!(actor.engine().breakpoints().get(breakpoint_id).is_some());

        if let Err(error) = actor.run_once().await {
            panic!("third trace quantum should run: {error}");
        }
        assert_eq!(
            actor
                .engine()
                .breakpoint_firings()
                .iter()
                .map(|firing| firing.id)
                .collect::<Vec<_>>(),
            vec![breakpoint_id, breakpoint_id]
        );
        assert!(matches!(actor.engine().state(), EngineState::Running));
    }

    #[tokio::test]
    async fn breakpoint_once_combinator_latches_across_boundaries() {
        let scenario = generated_scenario(40);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("once breakpoint start should instantiate runtime: {error}");
        }
        let predicate = Predicate::all_of(vec![
            Predicate::once(Predicate::at(VirtualTime { ticks: 1 })),
            Predicate::at(VirtualTime { ticks: 3 }),
        ]);
        let breakpoint = BreakpointSpec {
            predicate,
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::Repeatable,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("once breakpoint should register before continue: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("once breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        for quantum in 1..=2 {
            if let Err(error) = actor.run_once().await {
                panic!("once breakpoint quantum {quantum} should run: {error}");
            }
            assert!(actor.engine().breakpoint_firings().is_empty());
        }

        if let Err(error) = actor.run_once().await {
            panic!("once breakpoint third quantum should run: {error}");
        }

        assert_eq!(
            actor
                .engine()
                .breakpoint_firings()
                .iter()
                .map(|firing| firing.id)
                .collect::<Vec<_>>(),
            vec![breakpoint_id]
        );
        assert!(matches!(actor.engine().state(), EngineState::Running));
    }

    #[tokio::test]
    async fn breakpoint_action_applies_scheduler_control_at_boundary() {
        let scenario = generated_scenario(41);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let control_batches = Arc::new(Mutex::new(Vec::new()));
        let mut engine = Engine::new(
            config,
            graph,
            RecordingLoop::new(Arc::clone(&control_batches)),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("action breakpoint start should instantiate runtime: {error}");
        }
        let tag = FaultTag::from_name("breakpoint-action-fault");
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        let action = Action::inject_fault(tag.clone(), MembershipFault::taxonomy(fault.clone()));
        let breakpoint = BreakpointSpec {
            predicate: Predicate::at(VirtualTime { ticks: 1 }),
            disposition: BreakpointDisposition::Action(action),
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("action breakpoint should register before continue: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("action breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("action breakpoint quantum should run: {error}");
        }

        let expected_control = ControlOperationKind::InjectFault {
            tag: tag.clone(),
            fault: fault.clone(),
        };
        assert!(matches!(actor.engine().state(), EngineState::Running));
        assert_eq!(actor.engine().pending_control_len(), 0);
        assert_eq!(
            actor.engine().breakpoint_firings()[0].scheduler_controls,
            vec![expected_control.clone()]
        );
        assert_eq!(actor.engine().breakpoint_firings()[0].id, breakpoint_id);
        let log = actor.engine().boundary_control_log();
        assert_eq!(log.len(), 1);
        assert_boundary_log_entry(
            &log[0],
            1,
            SessionCommandKind::InjectFault,
            Some(expected_control.clone()),
        );
        assert_eq!(
            recorded_control_batches(&control_batches),
            vec![Vec::new(), vec![expected_control]]
        );
    }

    #[tokio::test]
    async fn unsupported_breakpoint_action_fails_loudly() {
        let scenario = generated_scenario(42);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("unsupported-action breakpoint start should instantiate runtime: {error}");
        }
        let breakpoint = BreakpointSpec {
            predicate: Predicate::at(VirtualTime { ticks: 1 }),
            disposition: BreakpointDisposition::Action(Action::Log {
                level: LogLevel::Info,
                message: String::from("unsupported breakpoint action"),
            }),
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("unsupported-action breakpoint should register: {error}");
        }
        let _breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("unsupported-action breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        let error = actor
            .run_once()
            .await
            .expect_err("unsupported action breakpoint should fail loudly");

        assert_eq!(
            error,
            SessionError::UnsupportedBreakpointAction { action: "log" }
        );
        assert!(actor.engine().breakpoint_firings().is_empty());
    }

    #[tokio::test]
    async fn unsupported_breakpoint_fault_fails_loudly() {
        let scenario = generated_scenario(43);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("unsupported-fault breakpoint start should instantiate runtime: {error}");
        }
        let breakpoint = BreakpointSpec {
            predicate: Predicate::at(VirtualTime { ticks: 1 }),
            disposition: BreakpointDisposition::Action(Action::inject_fault(
                FaultTag::from_name("unsupported-breakpoint-fault"),
                MembershipFault::Isolate {
                    node: NodeId {
                        name: String::from("node-a"),
                    },
                },
            )),
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("unsupported-fault breakpoint should register: {error}");
        }
        let _breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("unsupported-fault breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        let error = actor
            .run_once()
            .await
            .expect_err("unsupported fault breakpoint should fail loudly");

        assert_eq!(
            error,
            SessionError::UnsupportedBreakpointFault {
                action: "inject-fault",
                reason: "fault has no scheduler-control representation",
            }
        );
        assert!(actor.engine().breakpoint_firings().is_empty());
    }

    #[tokio::test]
    async fn breakpoint_action_group_is_prevalidated_before_control_application() {
        let scenario = generated_scenario(44);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let control_batches = Arc::new(Mutex::new(Vec::new()));
        let mut engine = Engine::new(
            config,
            graph,
            RecordingLoop::new(Arc::clone(&control_batches)),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("group breakpoint start should instantiate runtime: {error}");
        }
        let tag = FaultTag::from_name("group-prefix-fault");
        let fault = Fault::Node(crucible::NodeFault::Crash {
            node: NodeId {
                name: String::from("node-a"),
            },
            restart: crucible::RestartPolicy::StayDown,
        });
        let breakpoint = BreakpointSpec {
            predicate: Predicate::at(VirtualTime { ticks: 1 }),
            disposition: BreakpointDisposition::Action(Action::Group(vec![
                Action::inject_fault(tag, MembershipFault::taxonomy(fault)),
                Action::Log {
                    level: LogLevel::Info,
                    message: String::from("unsupported group suffix"),
                },
            ])),
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("group breakpoint should register: {error}");
        }
        let _breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("group breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        let error = actor
            .run_once()
            .await
            .expect_err("unsupported group suffix should fail before control application");

        assert_eq!(
            error,
            SessionError::UnsupportedBreakpointAction { action: "log" }
        );
        assert!(actor.engine().breakpoint_firings().is_empty());
        assert!(actor.engine().boundary_control_log().is_empty());
        assert_eq!(recorded_control_batches(&control_batches), vec![Vec::new()]);
    }

    #[tokio::test]
    async fn breakpoint_conditions_cover_node_and_assertion_state_leaves() {
        let scenario = generated_scenario(45);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let node = NodeId {
            name: String::from("node-a"),
        };
        let assertion = AssertionId::from_name("session-step-assertion");
        let mut engine = Engine::new(
            config,
            graph,
            ScriptedStepLoop::with_payloads(
                1,
                vec![
                    SchedulerEventLogPayload::Observable(ObservableEventPayload::NodeState {
                        node: node.clone(),
                        state: NodeLifecycle::Exited,
                    }),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::AssertionStateChanged {
                            name: assertion.clone(),
                            state: AssertionPhase::Satisfied,
                        },
                    ),
                ],
            ),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("leaf breakpoint start should instantiate runtime: {error}");
        }

        let node_breakpoint = BreakpointSpec {
            predicate: Predicate::node_state(node, NodeLifecycle::Exited),
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::OneShot,
        };
        let (node_reply, node_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: node_breakpoint,
            reply: node_reply,
        }) {
            panic!("node-state breakpoint should register: {error}");
        }
        let node_breakpoint_id = receive_reply(node_receiver).await;

        let assertion_breakpoint = BreakpointSpec {
            predicate: Predicate::assertion_state(assertion, AssertionPhase::Satisfied),
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::OneShot,
        };
        let (assertion_reply, assertion_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: assertion_breakpoint,
            reply: assertion_reply,
        }) {
            panic!("assertion-state breakpoint should register: {error}");
        }
        let assertion_breakpoint_id = receive_reply(assertion_receiver).await;

        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("leaf breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("leaf breakpoint quantum should run: {error}");
        }

        assert_eq!(
            actor
                .engine()
                .breakpoint_firings()
                .iter()
                .map(|firing| firing.id)
                .collect::<Vec<_>>(),
            vec![node_breakpoint_id, assertion_breakpoint_id]
        );
        assert!(actor.engine().breakpoints().is_empty());
        assert!(matches!(actor.engine().state(), EngineState::Running));
    }

    #[tokio::test]
    async fn breakpoint_conditions_cover_guest_marker_white_box_leaves() {
        let world = single_node_debug_world("guest-marker-breakpoint")
            .unwrap_or_else(|error| panic!("guest marker world should build: {error}"));
        let scenario = world.scenario_def();
        let node = world
            .nodes()
            .first()
            .map(|node| node.id.clone())
            .unwrap_or_else(|| panic!("guest marker world should contain a node"));
        let marker = crucible::MarkerId::from_name("session-marker");

        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut denied_engine = Engine::new(
            config,
            graph,
            ScriptedStepLoop::with_payloads(
                1,
                vec![SchedulerEventLogPayload::Observable(
                    ObservableEventPayload::GuestMarker {
                        retired_icount: crucible::Icount { retired: 1 },
                        node: node.clone(),
                        marker: marker.clone(),
                    },
                )],
            ),
        );
        if let Err(error) = denied_engine.apply_command(SessionCommand::Start) {
            panic!("guest-marker denied start should instantiate runtime: {error}");
        }
        let (denied_reply, denied_receiver) = CommandReply::channel();
        if let Err(error) = denied_engine.apply_command(SessionCommand::SetBreakpoint {
            spec: BreakpointSpec::suspend_once(Predicate::guest_marker(marker.clone())),
            reply: denied_reply,
        }) {
            panic!("guest-marker denied breakpoint should register: {error}");
        }
        let denied_breakpoint_id = receive_reply(denied_receiver).await;
        if let Err(error) = denied_engine.apply_command(SessionCommand::Continue) {
            panic!("guest-marker denied continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut denied_actor = SessionActor::new(denied_engine, receiver);
        if let Err(error) = denied_actor.run_once().await {
            panic!("guest-marker denied quantum should run: {error}");
        }
        assert!(denied_actor.engine().breakpoint_firings().is_empty());
        assert!(
            denied_actor
                .engine()
                .breakpoints()
                .get(denied_breakpoint_id)
                .is_some()
        );

        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(
            config,
            graph,
            ScriptedStepLoop::with_payloads(
                1,
                vec![SchedulerEventLogPayload::Observable(
                    ObservableEventPayload::GuestMarker {
                        retired_icount: crucible::Icount { retired: 1 },
                        node,
                        marker: marker.clone(),
                    },
                )],
            ),
        )
        .with_world_white_box_policies(&world);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("guest-marker breakpoint start should instantiate runtime: {error}");
        }
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: BreakpointSpec::suspend_once(Predicate::guest_marker(marker)),
            reply,
        }) {
            panic!("guest-marker breakpoint should register: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("guest-marker breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("guest-marker breakpoint quantum should run: {error}");
        }

        assert_eq!(
            actor
                .engine()
                .breakpoint_firings()
                .iter()
                .map(|firing| firing.id)
                .collect::<Vec<_>>(),
            vec![breakpoint_id]
        );
        assert!(actor.engine().breakpoints().is_empty());
        assert!(matches!(actor.engine().state(), EngineState::Paused { .. }));
    }

    #[tokio::test]
    async fn breakpoint_conditions_cover_after_and_timer_runtime_facts() {
        let scenario = generated_scenario(46);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let after_event = EventId::from_name("breakpoint-after-source");
        let timer = TimerId {
            name: String::from("breakpoint-timer"),
        };
        let mut engine = Engine::new(
            config,
            graph,
            ScriptedStepLoop::with_payloads(
                1,
                vec![
                    trigger_fired_payload(
                        1,
                        after_event.clone(),
                        Predicate::at(VirtualTime { ticks: 1 }),
                    ),
                    SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
                        sequence: 0,
                        event: EventId::from_name("breakpoint-timer-arm"),
                        at: VirtualTime { ticks: 1 },
                        path: Vec::new(),
                        action: Action::arm_timer(timer.clone(), SimDuration { nanos: 1 }),
                    }),
                ],
            ),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("runtime-fact breakpoint start should instantiate runtime: {error}");
        }

        let after_breakpoint = BreakpointSpec {
            predicate: Predicate::after(SimDuration { nanos: 1 }, after_event),
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::OneShot,
        };
        let (after_reply, after_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: after_breakpoint,
            reply: after_reply,
        }) {
            panic!("after breakpoint should register: {error}");
        }
        let after_breakpoint_id = receive_reply(after_receiver).await;

        let timer_breakpoint = BreakpointSpec {
            predicate: Predicate::timer(timer),
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::OneShot,
        };
        let (timer_reply, timer_receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: timer_breakpoint,
            reply: timer_reply,
        }) {
            panic!("timer breakpoint should register: {error}");
        }
        let timer_breakpoint_id = receive_reply(timer_receiver).await;

        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("runtime-fact breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("first runtime-fact quantum should run: {error}");
        }
        assert!(actor.engine().breakpoint_firings().is_empty());

        if let Err(error) = actor.run_once().await {
            panic!("second runtime-fact quantum should run: {error}");
        }

        assert_eq!(
            actor
                .engine()
                .breakpoint_firings()
                .iter()
                .map(|firing| firing.id)
                .collect::<Vec<_>>(),
            vec![after_breakpoint_id, timer_breakpoint_id]
        );
        assert!(actor.engine().breakpoints().is_empty());
    }

    #[tokio::test]
    async fn quiescent_breakpoint_uses_scheduler_quiescence_evidence() {
        let scenario = generated_scenario(47);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(
            config,
            graph,
            ScriptedStepLoop::with_quiescence(SchedulerQuiescence::default()),
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("quiescent breakpoint start should instantiate runtime: {error}");
        }
        let breakpoint = BreakpointSpec {
            predicate: Predicate::quiescent(),
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("quiescent breakpoint should register: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("quiescent breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("quiescent breakpoint quantum should run: {error}");
        }

        assert_eq!(
            actor
                .engine()
                .breakpoint_firings()
                .iter()
                .map(|firing| firing.id)
                .collect::<Vec<_>>(),
            vec![breakpoint_id]
        );
        assert!(actor.engine().breakpoints().is_empty());
        assert!(matches!(
            actor.engine().state(),
            EngineState::Stopped {
                outcome: Outcome::Passed
            }
        ));
    }

    #[tokio::test]
    async fn quiescent_breakpoint_fires_without_emitted_entries() {
        let scenario = generated_scenario(48);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(
            config,
            graph,
            NoEventQuiescenceLoop {
                quiescence: SchedulerQuiescence::default(),
            },
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("no-event quiescent breakpoint start should instantiate runtime: {error}");
        }
        let breakpoint = BreakpointSpec {
            predicate: Predicate::quiescent(),
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("no-event quiescent breakpoint should register: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("no-event quiescent breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("no-event quiescent breakpoint quantum should run: {error}");
        }

        assert!(actor.event_log.lock_entries().is_empty());
        assert_eq!(
            actor
                .engine()
                .breakpoint_firings()
                .iter()
                .map(|firing| firing.id)
                .collect::<Vec<_>>(),
            vec![breakpoint_id]
        );
    }

    #[tokio::test]
    async fn no_entry_breakpoint_after_prior_event_uses_current_boundary() {
        let scenario = generated_scenario(49);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(
            config,
            graph,
            PriorEventThenNoEventQuiescenceLoop {
                quanta: 0,
                quiescence: SchedulerQuiescence::default(),
            },
        );
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("post-event no-entry breakpoint start should instantiate runtime: {error}");
        }
        let predicate = Predicate::all_of(vec![
            Predicate::at(VirtualTime { ticks: 2 }),
            Predicate::quiescent(),
        ]);
        let breakpoint = BreakpointSpec {
            predicate: predicate.clone(),
            disposition: BreakpointDisposition::Trace,
            policy: BreakpointPolicy::OneShot,
        };
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply,
        }) {
            panic!("post-event no-entry breakpoint should register: {error}");
        }
        let breakpoint_id = receive_reply(receiver).await;
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("post-event no-entry breakpoint continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = actor.run_once().await {
            panic!("first post-event no-entry quantum should run: {error}");
        }
        assert!(actor.engine().breakpoint_firings().is_empty());
        assert_eq!(actor.event_log.lock_entries().len(), 1);

        if let Err(error) = actor.run_once().await {
            panic!("second post-event no-entry quantum should run: {error}");
        }

        assert_eq!(actor.event_log.lock_entries().len(), 1);
        assert_eq!(
            actor.engine().breakpoint_firings(),
            &[BreakpointFiring {
                sequence: 1,
                id: breakpoint_id,
                predicate,
                disposition: BreakpointDisposition::Trace,
                frontier: VirtualTime { ticks: 2 },
                quanta: 2,
                scheduler_controls: Vec::new(),
            }]
        );
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
            "\nimpl<L> SessionActor<L>\nwhere",
        );
        let actor_quantum_impl = source_section(
            source,
            "impl<L> SessionActor<L>\nwhere\n    L: QuantumLoop + Send + 'static,\n{",
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

    async fn receive_state_transition(
        stream: &mut SessionStateTransitionStream,
    ) -> SessionStateTransitionFrame {
        match stream.recv().await {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!("state-transition stream should remain open"),
            Err(error) => panic!("state-transition stream should not lag: {error}"),
        }
    }

    fn assert_boundary_log_entry(
        entry: &SessionControlLogEntry,
        sequence: u64,
        command: SessionCommandKind,
        scheduler_control: Option<ControlOperationKind>,
    ) {
        assert_eq!(entry.sequence, sequence);
        assert_eq!(entry.command, command);
        assert_eq!(entry.scheduler_control, scheduler_control);
    }

    fn recorded_control_batches(
        control_batches: &Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
    ) -> Vec<Vec<ControlOperationKind>> {
        match control_batches.lock() {
            Ok(batches) => batches.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    async fn assert_actor_step_completes_after_second_quantum(
        seed: u64,
        mode: StepMode,
        quantum_loop: ScriptedStepLoop,
    ) {
        let scenario = generated_scenario(seed);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, quantum_loop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime before scripted step: {error}");
        }
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        if let Err(error) = sender.send(SessionCommand::Step { mode }).await {
            panic!("{mode:?} step should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("{mode:?} step should start bounded execution: {error}");
        }
        assert_eq!(actor.engine().quanta(), 0);
        assert!(matches!(actor.engine().state(), EngineState::Running));

        if let Err(error) = actor.run_once().await {
            panic!("{mode:?} step should stay running before the stop boundary: {error}");
        }
        assert_eq!(actor.engine().quanta(), 1);
        assert!(matches!(actor.engine().state(), EngineState::Running));

        if let Err(error) = actor.run_once().await {
            panic!("{mode:?} step should complete at its deterministic boundary: {error}");
        }
        assert_eq!(actor.engine().quanta(), 2);
        assert_eq!(actor.engine().configuration().schedule.len(), 2);
        assert_eq!(
            actor.engine().state(),
            &EngineState::Paused {
                reason: PauseReason::StepComplete { mode },
            }
        );
    }

    fn assert_engine_step_completes_after_second_quantum(
        seed: u64,
        mode: StepMode,
        quantum_loop: ScriptedStepLoop,
    ) {
        let scenario = generated_scenario(seed);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, quantum_loop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime before scripted engine step: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Step { mode }) {
            panic!("{mode:?} step should start bounded execution: {error}");
        }
        assert_eq!(engine.state(), &EngineState::Running);
        assert_eq!(engine.quanta(), 0);

        if let Err(error) = engine.step_quantum() {
            panic!("{mode:?} step should stay running before the stop boundary: {error}");
        }
        assert_eq!(engine.quanta(), 1);
        assert_eq!(engine.state(), &EngineState::Running);

        if let Err(error) = engine.step_quantum() {
            panic!("{mode:?} step should complete at its deterministic boundary: {error}");
        }
        assert_eq!(engine.quanta(), 2);
        assert_eq!(
            engine.state(),
            &EngineState::Paused {
                reason: PauseReason::StepComplete { mode },
            }
        );
        assert_eq!(engine.active_step, None);
    }

    fn assert_rejection_names_state_and_command(
        error: SessionError,
        expected_state: EngineState,
        expected_command: SessionCommand,
    ) {
        match error {
            SessionError::InvalidTransition { state, command } => {
                assert_eq!(*state, expected_state);
                assert_eq!(*command, expected_command);
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
        assert_rejection_names_state_and_command(
            error,
            EngineState::Loaded,
            SessionCommand::Continue,
        );
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
        let mut actor = SessionActor::new(engine, receiver);
        for command in [
            SessionCommand::Start,
            SessionCommand::Step {
                mode: StepMode::Quantum,
            },
        ] {
            if let Err(error) = sender.send(command).await {
                panic!("command should enqueue: {error}");
            }
        }

        if let Err(error) = actor.run_once().await {
            panic!("start command should instantiate runtime: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("step command should start bounded execution: {error}");
        }
        assert_eq!(actor.engine().quanta(), 0);
        assert!(matches!(actor.engine().state(), EngineState::Running));
        if let Err(error) = actor.run_once().await {
            panic!("quantum step should complete after one scheduler boundary: {error}");
        }
        assert_eq!(actor.engine().quanta(), 1);
        assert_eq!(actor.yielded_after_quanta(), 1);
        assert_eq!(
            actor.engine().state(),
            &EngineState::Paused {
                reason: PauseReason::StepComplete {
                    mode: StepMode::Quantum,
                }
            }
        );

        if let Err(error) = sender.send(SessionCommand::Stop).await {
            panic!("stop should enqueue after step completion: {error}");
        }
        let report = match actor.run().await {
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
            panic!("running quantum step should start bounded execution: {error}");
        }
        assert_eq!(actor.control_acknowledgements(), 0);
        assert_eq!(actor.engine().pending_control_len(), 1);
        assert_eq!(actor.engine().quanta(), 0);
        assert!(matches!(actor.engine().state(), EngineState::Running));

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
            panic!("paused quantum step should start bounded execution: {error}");
        }
        assert_eq!(actor.control_acknowledgements(), 1);
        assert_eq!(actor.engine().pending_control_len(), 1);
        assert_eq!(actor.engine().quanta(), 0);
        assert!(matches!(actor.engine().state(), EngineState::Running));

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

    #[tokio::test]
    async fn session_actor_step_modes_stop_on_deterministic_boundaries() {
        let cases = vec![
            (
                30,
                StepMode::Event,
                ScriptedStepLoop::with_payload(2, resolved_backend_input_payload(2)),
            ),
            (
                31,
                StepMode::Assertion,
                ScriptedStepLoop::with_payload(2, assertion_state_change_payload()),
            ),
            (
                32,
                StepMode::Timer,
                ScriptedStepLoop::with_payload(2, timer_fire_payload(2)),
            ),
            (
                33,
                StepMode::Duration(SimDuration { nanos: 2 }),
                ScriptedStepLoop::default(),
            ),
        ];

        for (seed, mode, quantum_loop) in cases {
            assert_actor_step_completes_after_second_quantum(seed, mode, quantum_loop).await;
        }
    }

    #[tokio::test]
    async fn session_actor_step_modes_are_interruptible_by_pause_and_stop() {
        for command in [SessionCommand::Pause, SessionCommand::Stop] {
            let scenario = generated_scenario(34);
            let config = Configuration::genesis(scenario.clone());
            let graph = graph_with_baked_genesis(&scenario);
            let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
            if let Err(error) = engine.apply_command(SessionCommand::Start) {
                panic!("start should instantiate runtime before interruptible step: {error}");
            }
            let (sender, receiver) = mpsc::channel(4);
            let mut actor = SessionActor::new(engine, receiver);
            if let Err(error) = sender
                .send(SessionCommand::Step {
                    mode: StepMode::Duration(SimDuration { nanos: 8 }),
                })
                .await
            {
                panic!("duration step should enqueue: {error}");
            }

            if let Err(error) = actor.run_once().await {
                panic!("duration step should start bounded execution: {error}");
            }
            if let Err(error) = actor.run_once().await {
                panic!("first duration-step quantum should run: {error}");
            }
            assert_eq!(actor.engine().quanta(), 1);
            assert!(matches!(actor.engine().state(), EngineState::Running));

            if let Err(error) = sender.send(command.clone()).await {
                panic!("interrupt command should enqueue: {error}");
            }
            if let Err(error) = actor.run_once().await {
                panic!("interrupt command should be serviced before the next quantum: {error}");
            }

            assert_eq!(actor.engine().quanta(), 1);
            assert_eq!(actor.engine().active_step, None);
            match command {
                SessionCommand::Pause => assert!(matches!(
                    actor.engine().state(),
                    EngineState::Paused {
                        reason: PauseReason::UserRequested
                    }
                )),
                SessionCommand::Stop => assert!(matches!(
                    actor.engine().state(),
                    EngineState::Stopped {
                        outcome: Outcome::Stopped
                    }
                )),
                _ => panic!("test only covers pause and stop interrupts"),
            }
        }
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
    async fn session_actor_live_query_reads_atomic_mirror_without_mailbox_query() {
        let scenario = generated_scenario(18);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, AppendingLoop::default());
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);

        let initial = actor.live_status();
        assert_eq!(initial, actor.live_snapshot().read());
        assert_eq!(
            actor.live_snapshot().query(LiveQueryKind::Status),
            LiveQueryResult::Status(initial)
        );
        assert_eq!(
            actor.live_snapshot().query(LiveQueryKind::State),
            LiveQueryResult::State(LifecycleStateKind::Loaded)
        );
        assert_eq!(initial.state_kind, LiveStateKind::Loaded);

        if let Err(error) = sender.send(SessionCommand::Start).await {
            panic!("start command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("start command should publish live status: {error}");
        }

        let after_start = actor.live_status();
        assert_eq!(after_start, actor.live_snapshot().read());
        assert_eq!(
            actor.live_snapshot().query(LiveQueryKind::State),
            LiveQueryResult::State(LifecycleStateKind::Paused)
        );
        assert_eq!(
            actor.live_snapshot().query(LiveQueryKind::EventLogLength),
            LiveQueryResult::EventLogLength(0)
        );
        assert_eq!(after_start.state_kind, LiveStateKind::Paused);
        assert_eq!(after_start.quanta_stepped, 0);
    }

    #[tokio::test]
    async fn session_actor_live_snapshot_publishes_monotone_progress() {
        let scenario = generated_scenario(19);
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

    #[tokio::test]
    async fn session_actor_state_transition_bus_broadcasts_actor_owned_transitions() {
        let scenario = generated_scenario(20);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, AppendingLoop::default());
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);
        let mut transitions = actor.state_transition_stream();

        if let Err(error) = sender.send(SessionCommand::Start).await {
            panic!("start command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("start command should run: {error}");
        }
        let started = receive_state_transition(&mut transitions).await;
        assert_eq!(started.sequence, 1);
        assert_eq!(started.from_state, EngineState::Loaded);
        assert_eq!(
            started.to_state,
            EngineState::Paused {
                reason: PauseReason::Instantiated,
            }
        );
        assert_eq!(started.from.state_kind, LiveStateKind::Loaded);
        assert_eq!(started.to.state_kind, LiveStateKind::Paused);

        if let Err(error) = sender.send(SessionCommand::Pause).await {
            panic!("paused pause command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("paused pause command should run: {error}");
        }
        let repaused = receive_state_transition(&mut transitions).await;
        assert_eq!(repaused.sequence, 2);
        assert_eq!(
            repaused.from_state,
            EngineState::Paused {
                reason: PauseReason::Instantiated,
            }
        );
        assert_eq!(
            repaused.to_state,
            EngineState::Paused {
                reason: PauseReason::UserRequested,
            }
        );
        assert_eq!(repaused.from.state_kind, LiveStateKind::Paused);
        assert_eq!(repaused.to.state_kind, LiveStateKind::Paused);

        if let Err(error) = sender.send(SessionCommand::Continue).await {
            panic!("continue command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("continue command should run: {error}");
        }
        let continued = receive_state_transition(&mut transitions).await;
        assert_eq!(continued.sequence, 3);
        assert_eq!(
            continued.from_state,
            EngineState::Paused {
                reason: PauseReason::UserRequested,
            }
        );
        assert_eq!(continued.to_state, EngineState::Running);
        assert_eq!(continued.from.state_kind, LiveStateKind::Paused);
        assert_eq!(continued.to.state_kind, LiveStateKind::Running);

        if let Err(error) = actor.run_once().await {
            panic!("running quantum should not block state stream: {error}");
        }
        if let Err(error) = sender.send(SessionCommand::Pause).await {
            panic!("pause command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("pause command should run: {error}");
        }
        let paused = receive_state_transition(&mut transitions).await;
        assert_eq!(paused.sequence, 4);
        assert_eq!(paused.from_state, EngineState::Running);
        assert_eq!(
            paused.to_state,
            EngineState::Paused {
                reason: PauseReason::UserRequested,
            }
        );
        assert_eq!(paused.from.state_kind, LiveStateKind::Running);
        assert_eq!(paused.to.state_kind, LiveStateKind::Paused);

        if let Err(error) = sender.send(SessionCommand::Stop).await {
            panic!("stop command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("stop command should run: {error}");
        }
        let stopped = receive_state_transition(&mut transitions).await;
        assert_eq!(stopped.sequence, 5);
        assert_eq!(
            stopped.from_state,
            EngineState::Paused {
                reason: PauseReason::UserRequested,
            }
        );
        assert_eq!(
            stopped.to_state,
            EngineState::Stopped {
                outcome: Outcome::Stopped,
            }
        );
        assert_eq!(stopped.from.state_kind, LiveStateKind::Paused);
        assert_eq!(stopped.to.state_kind, LiveStateKind::Stopped);
        assert_eq!(stopped.to.outcome, Some(OutcomeKind::Stopped));
    }

    #[tokio::test]
    async fn session_state_transition_stream_reports_lag_without_backpressure() {
        let bus = SessionStateTransitionBus::new();
        let mut stream = bus.subscribe();
        let view = LiveSnapshotView {
            state_kind: LiveStateKind::Loaded,
            outcome: None,
            terminal_savepoint: None,
            virtual_time: VirtualTime { ticks: 0 },
            event_log_len: 0,
            quanta_stepped: 0,
            control_acknowledgements: 0,
        };

        for sequence in 0..=usize_to_u64(SESSION_STATE_BROADCAST_CAPACITY) {
            bus.publish(SessionStateTransitionFrame {
                sequence,
                from_state: EngineState::Loaded,
                to_state: EngineState::Loaded,
                from: view,
                to: view,
            });
        }

        match stream.recv().await {
            Err(SessionStateTransitionStreamError::Lagged { skipped }) => assert!(skipped > 0),
            Ok(frame) => panic!("lagged state stream should not deliver frame {frame:?}"),
        }
    }

    #[test]
    fn engine_rejects_event_log_offset_mismatch() {
        let scenario = generated_scenario(21);
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
        let scenario = generated_scenario(22);
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
                scheduler_quiescence: None,
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
                scheduler_quiescence: None,
            })
        }
    }

    struct RecordingLoop {
        quanta: u64,
        control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
        shutdowns: Option<Arc<AtomicU64>>,
    }

    impl RecordingLoop {
        fn new(control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>) -> Self {
            Self {
                quanta: 0,
                control_batches,
                shutdowns: None,
            }
        }

        fn with_shutdown(
            control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
            shutdowns: Arc<AtomicU64>,
        ) -> Self {
            Self {
                quanta: 0,
                control_batches,
                shutdowns: Some(shutdowns),
            }
        }
    }

    impl QuantumLoop for RecordingLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            let control_batch = request
                .control
                .iter()
                .map(|control| control.kind.clone())
                .collect::<Vec<_>>();
            match self.control_batches.lock() {
                Ok(mut batches) => batches.push(control_batch),
                Err(poisoned) => poisoned.into_inner().push(control_batch),
            }
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
                scheduler_quiescence: None,
            })
        }

        fn apply_control_at_boundary(
            &mut self,
            control: Vec<ControlOperation>,
        ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
            let control_batch = control
                .iter()
                .map(|operation| operation.kind.clone())
                .collect::<Vec<_>>();
            match self.control_batches.lock() {
                Ok(mut batches) => batches.push(control_batch),
                Err(poisoned) => poisoned.into_inner().push(control_batch),
            }
            Ok(Vec::new())
        }

        fn shutdown(&mut self) -> Result<(), SchedulerError> {
            if let Some(shutdowns) = &self.shutdowns {
                shutdowns.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    struct ControlEventLoop;

    impl QuantumLoop for ControlEventLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime::default(),
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible::EventLogOffset::default(),
                scheduler_quiescence: None,
            })
        }

        fn apply_control_at_boundary(
            &mut self,
            _control: Vec<ControlOperation>,
        ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
            Ok(vec![test_event_log_entry(0)])
        }
    }

    #[derive(Default)]
    struct ControlSensitiveLoop {
        quanta: u64,
        active_faults: std::collections::BTreeSet<FaultTag>,
        legacy_injects: u64,
        control_batches: u64,
    }

    impl ControlSensitiveLoop {
        fn apply_control_batch(&mut self, controls: &[ControlOperation]) {
            if controls.is_empty() {
                return;
            }
            self.control_batches = self.control_batches.saturating_add(1);
            for control in controls {
                match &control.kind {
                    ControlOperationKind::Inject => {
                        self.legacy_injects = self.legacy_injects.saturating_add(1);
                    }
                    ControlOperationKind::InjectFault { tag, .. } => {
                        self.active_faults.insert(tag.clone());
                    }
                    ControlOperationKind::HealFault { tag } => {
                        self.active_faults.remove(tag);
                    }
                    ControlOperationKind::Pause
                    | ControlOperationKind::Resume
                    | ControlOperationKind::Step
                    | ControlOperationKind::Snapshot
                    | ControlOperationKind::Fork
                    | ControlOperationKind::Query => {}
                }
            }
        }

        fn decision_seed(&self) -> u64 {
            self.quanta
                .saturating_add((self.active_faults.len() as u64).saturating_mul(1_000))
                .saturating_add(self.legacy_injects.saturating_mul(10_000))
                .saturating_add(self.control_batches.saturating_mul(100_000))
        }
    }

    impl QuantumLoop for ControlSensitiveLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            self.apply_control_batch(&request.control);
            self.quanta = self.quanta.saturating_add(1);
            let decision = generated_decision(self.decision_seed());
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
                scheduler_quiescence: None,
            })
        }

        fn apply_control_at_boundary(
            &mut self,
            control: Vec<ControlOperation>,
        ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
            self.apply_control_batch(&control);
            Ok(Vec::new())
        }
    }

    struct ShutdownLoop {
        quanta: u64,
        shutdowns: Arc<AtomicU64>,
    }

    impl ShutdownLoop {
        fn new(shutdowns: Arc<AtomicU64>) -> Self {
            Self {
                quanta: 0,
                shutdowns,
            }
        }
    }

    impl QuantumLoop for ShutdownLoop {
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
                scheduler_quiescence: None,
            })
        }

        fn shutdown(&mut self) -> Result<(), SchedulerError> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Default)]
    struct ScriptedStepLoop {
        quanta: u64,
        event_log_entries: u64,
        payloads_by_quantum: std::collections::BTreeMap<u64, Vec<SchedulerEventLogPayload>>,
        scheduler_quiescence: Option<SchedulerQuiescence>,
    }

    impl ScriptedStepLoop {
        fn with_payload(quantum: u64, payload: SchedulerEventLogPayload) -> Self {
            Self::with_payloads(quantum, vec![payload])
        }

        fn with_payloads(quantum: u64, payloads: Vec<SchedulerEventLogPayload>) -> Self {
            let mut payloads_by_quantum = std::collections::BTreeMap::new();
            payloads_by_quantum.insert(quantum, payloads);
            Self {
                quanta: 0,
                event_log_entries: 0,
                payloads_by_quantum,
                scheduler_quiescence: None,
            }
        }

        fn with_quiescence(scheduler_quiescence: SchedulerQuiescence) -> Self {
            Self {
                scheduler_quiescence: Some(scheduler_quiescence),
                ..Self::default()
            }
        }
    }

    impl QuantumLoop for ScriptedStepLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            self.quanta = self.quanta.saturating_add(1);
            let at = VirtualTime { ticks: self.quanta };
            let entries = if let Some(payloads) = self.payloads_by_quantum.remove(&self.quanta) {
                payloads
                    .into_iter()
                    .enumerate()
                    .map(|(index, payload)| {
                        crucible::test_support::condition_payload_entry_for_test(
                            self.event_log_entries + usize_to_u64(index),
                            at,
                            payload,
                        )
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![crucible::test_support::condition_boundary_entry_for_test(
                    self.event_log_entries,
                    at,
                    crucible::SchedulerEvaluationBoundaryKind::Quantum,
                )]
            };
            self.event_log_entries = self
                .event_log_entries
                .saturating_add(usize_to_u64(entries.len()));
            let decision = generated_decision(self.quanta);
            let configuration = step(&request.configuration, decision.clone());
            Ok(QuantumOutcome {
                configuration,
                frontier: at,
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: vec![decision],
                event_log_entries: entries,
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible::EventLogOffset::new(
                    Default::default(),
                    0,
                    self.event_log_entries,
                ),
                scheduler_quiescence: self.scheduler_quiescence.clone(),
            })
        }
    }

    struct NoEventQuiescenceLoop {
        quiescence: SchedulerQuiescence,
    }

    impl QuantumLoop for NoEventQuiescenceLoop {
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
                event_log_offset: crucible::EventLogOffset::default(),
                scheduler_quiescence: Some(self.quiescence.clone()),
            })
        }
    }

    struct PriorEventThenNoEventQuiescenceLoop {
        quanta: u64,
        quiescence: SchedulerQuiescence,
    }

    impl QuantumLoop for PriorEventThenNoEventQuiescenceLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            self.quanta = self.quanta.saturating_add(1);
            let at = VirtualTime { ticks: self.quanta };
            let entries = if self.quanta == 1 {
                vec![crucible::test_support::condition_boundary_entry_for_test(
                    0,
                    at,
                    crucible::SchedulerEvaluationBoundaryKind::Quantum,
                )]
            } else {
                Vec::new()
            };
            let decision = generated_decision(self.quanta);
            let configuration = step(&request.configuration, decision.clone());
            Ok(QuantumOutcome {
                configuration,
                frontier: at,
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: vec![decision],
                event_log_entries: entries,
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 1),
                scheduler_quiescence: Some(self.quiescence.clone()),
            })
        }
    }

    struct NoLeaves;

    impl ConditionLeafOracle for NoLeaves {
        fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
            match leaf {
                ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                    panic!("session step-mode tests should not evaluate host leaf predicates")
                }
            }
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
                scheduler_quiescence: None,
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
                scheduler_quiescence: None,
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
                scheduler_quiescence: None,
            })
        }
    }

    struct DebugGdbLoop;

    impl QuantumLoop for DebugGdbLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime::default(),
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible::EventLogOffset::default(),
                scheduler_quiescence: None,
            })
        }

        fn open_gdbstub(
            &mut self,
            node: NodeId,
            listen: GdbListen,
        ) -> Result<GdbAttachInfo, SchedulerError> {
            GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen).map_err(SchedulerError::from)
        }
    }

    fn debug_time_travel_fixture() -> (Configuration, Configuration, Configuration, TemporalGraph) {
        let world = single_node_debug_world("session-command")
            .unwrap_or_else(|error| panic!("debug world should build: {error}"));
        let scenario = world.scenario_def();
        let root = Configuration::genesis(scenario.clone());
        let first = try_step(
            &root,
            override_decision("session/debug-time-travel", "first"),
        )
        .unwrap_or_else(|error| panic!("first debug step should build: {error}"));
        let second = try_step(
            &first,
            override_decision("session/debug-time-travel", "second"),
        )
        .unwrap_or_else(|error| panic!("second debug step should build: {error}"));
        let mut graph = TemporalGraph::empty()
            .with_baked_genesis(
                &scenario,
                bake(&world).unwrap_or_else(|error| panic!("debug world should bake: {error}")),
            )
            .unwrap_or_else(|error| panic!("debug graph should have baked genesis: {error}"));
        graph
            .record_thin_checkpoint(&first)
            .unwrap_or_else(|error| panic!("first checkpoint should record: {error}"));
        graph
            .record_thin_checkpoint(&second)
            .unwrap_or_else(|error| panic!("second checkpoint should record: {error}"));
        (root, first, second, graph)
    }

    fn single_node_debug_world(label: &str) -> Result<World, EngineError> {
        World::from_nodes(vec![WorldNode {
            id: node_id("guest-a"),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: format!("crucible-session-debug={label}"),
            ready_point: ReadyPoint::FixedIcount {
                icount: crucible::Icount { retired: 100 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }])
    }

    fn override_decision(point: &str, choice: &str) -> Decision {
        Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: point.to_owned(),
            },
            choice: ChoiceTag {
                name: choice.to_owned(),
            },
        })
    }

    fn gdb_listen(endpoint: &str) -> GdbListen {
        GdbListen::new(endpoint)
            .unwrap_or_else(|error| panic!("test gdb listen should be stable: {error}"))
    }

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
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
            VirtualTime {
                ticks: sequence.saturating_add(1),
            },
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        )
    }

    fn resolved_backend_input_payload(seed: u64) -> SchedulerEventLogPayload {
        let node = scheduler_node("node-a");
        SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
            key: ScheduledEventKey::from_parts(
                VirtualTime { ticks: seed },
                node.clone(),
                node.clone(),
                seed,
            ),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: node.node,
                payload: vec![1, 2, 3],
            }),
        })
    }

    fn assertion_state_change_payload() -> SchedulerEventLogPayload {
        SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged {
            name: AssertionId::from_name("session-step-assertion"),
            state: AssertionPhase::Satisfied,
        })
    }

    fn trigger_fired_payload(
        sequence: u64,
        event: EventId,
        predicate: Predicate,
    ) -> SchedulerEventLogPayload {
        let graph = EventGraph::new(vec![Event::once(
            event.clone(),
            Some(predicate),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("session breakpoint trigger fired"),
            },
        )])
        .unwrap_or_else(|error| panic!("trigger-fired event graph should build: {error}"));
        let mut graph_state = EventGraphState::new();
        let mut pass = ConditionEvaluationPass::from_log_prefix(
            crucible::test_support::condition_prefix_at_quantum_boundary_for_test(sequence),
            NoLeaves,
        );
        let firings = pass.evaluate_event_graph(&graph, &mut graph_state);
        let Some(firing) = firings
            .iter()
            .find(|firing| firing.event() == &event)
            .cloned()
        else {
            panic!("trigger-fired event graph should produce the requested firing");
        };
        SchedulerEventLogPayload::TriggerFired(firing)
    }

    fn timer_fire_payload(sequence: u64) -> SchedulerEventLogPayload {
        let timer = TimerId {
            name: String::from("session-step-timer"),
        };
        let graph = EventGraph::new(vec![
            Event::once(
                EventId::from_name("session-step-arm-timer"),
                None,
                Action::arm_timer(timer.clone(), SimDuration { nanos: sequence }),
            ),
            Event::once(
                EventId::from_name("session-step-timer"),
                Some(Predicate::timer(timer.clone())),
                Action::Log {
                    level: LogLevel::Info,
                    message: String::from("session step timer fired"),
                },
            ),
        ])
        .unwrap_or_else(|error| panic!("timer fire event graph should build: {error}"));
        let mut graph_state = EventGraphState::new();
        let mut timer_fires = std::collections::BTreeMap::new();
        timer_fires.insert(timer, VirtualTime { ticks: sequence });
        let mut pass = ConditionEvaluationPass::from_log_prefix(
            crucible::test_support::condition_prefix_at_quantum_boundary_for_test(sequence),
            NoLeaves,
        )
        .with_timer_fires(timer_fires);
        let firings = pass.evaluate_event_graph(&graph, &mut graph_state);
        let Some(firing) = firings
            .iter()
            .find(|firing| condition_summary_is_timer_fire(firing.condition_summary()))
            .cloned()
        else {
            panic!("timer fire event graph should produce a timer predicate firing");
        };
        SchedulerEventLogPayload::TriggerFired(firing)
    }

    fn timer_action_payload(sequence: u64) -> SchedulerEventLogPayload {
        SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
            sequence,
            event: EventId::from_name("session-step-timer"),
            at: VirtualTime { ticks: sequence },
            path: Vec::new(),
            action: Action::cancel_timer(TimerId {
                name: String::from("session-step-timer"),
            }),
        })
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
