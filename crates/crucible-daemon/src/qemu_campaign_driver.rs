//! Concrete modeled driving and observation projection for campaign QEMU attempts.
//!
//! The shared semantic core advances only through [`QemuModeledAttemptLifecycle`],
//! stops on the attempt's exact semantic boundary or a modeled terminal verdict,
//! and retains a bounded dense event log. Fresh and exact execution seal after
//! runner-owned shutdown contributes its final observational suffix. Hot-fork
//! execution seals the already-paused branch-private child before runner-owned
//! termination, which is forbidden from resuming guest execution. Both paths
//! reconstruct the exact child artifact, evaluate scenario properties offline,
//! derive grow-only coverage identities, and produce one self-contained
//! campaign observation candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crucible::model::MeasurementTerminalState;
use crucible::{
    Configuration, ContentHash, Decision, EventLogCoverageObservation, HostAssertionOutcomeKind,
    ObservableEventPayload, OfflineAssertionCheckError, OfflineAssertionChecker, QuantumOutcome,
    QuantumRequest, QuantumTerminalVerdict, SchedulerError, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerOperationalFailureClass, SchedulerQuiescence,
    SelectionDecision, VirtualTime, step,
};
use crucible_campaign::{
    AttemptStartMode, CampaignCodecError, CampaignHash, ChoiceDiscovery, ChoiceDomainId,
    ChoiceOpportunityId, CoverageProjection, MAX_OBSERVATION_CHOICE_DISCOVERIES,
    MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES, Observation, ObservationCandidate, PropertyEvidence,
    PropertyVerdict, PropertyVerdictSet, SelectableId, Selection, SelectionOrigin, StopCondition,
    StopOutcome,
};
use crucible_cas::content_store::ContentId;
use crucible_protocol::SelectionReply;
use crucible_qemu::QemuNodeSelectablePendingRequest;
use thiserror::Error;

use crate::guest_selectable::{
    GuestSelectableError, resolve_guest_selectable, selected_guest_reply,
};
use crate::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure, CrucibleArtifactError,
    CrucibleAttemptExecution, CrucibleMeasurementError, CrucibleResolvedAttemptStart,
    PreparedSemanticAttemptResult, PreparedSemanticResultCodecError, QemuFreshAttemptDriver,
    QemuFreshAttemptLifecycle, QemuFreshDriveOutcome, QemuFreshStartMaterialization,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
    evaluate_crucible_measurement_publication,
};
#[cfg(target_os = "linux")]
use crate::{QemuHotForkAttemptDriver, QemuHotForkLiveExecution};

/// Maximum scheduler entries retained by one in-memory fresh-attempt projection.
pub const MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES: usize = 1_000_000;

/// Maximum aggregate canonical event material retained by one fresh attempt.
pub const MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES: usize = 64 * 1024 * 1024;

/// Maximum property-by-event evaluations admitted by one fresh-attempt seal.
pub const MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS: usize = 1_000_000;

/// Maximum simultaneously open guest measurement instances in one attempt.
pub const MAX_QEMU_CAMPAIGN_OPEN_MEASUREMENT_INSTANCES: usize = 65_536;

/// Failure while driving or projecting one fresh modeled campaign attempt.
#[derive(Debug, Error)]
pub enum QemuFreshModeledDriverError {
    /// The attempt was canceled at a modeled boundary.
    #[error("fresh campaign attempt was canceled")]
    Canceled,
    /// Scheduler progress or final event validation failed.
    #[error("fresh campaign scheduler failed: {0}")]
    Scheduler(#[source] SchedulerError),
    /// Strict Crucible artifact reconstruction failed.
    #[error("fresh campaign artifact projection failed: {0}")]
    Artifact(#[source] CrucibleArtifactError),
    /// Campaign canonical construction failed.
    #[error("fresh campaign observation projection failed: {0}")]
    Campaign(#[source] CampaignCodecError),
    /// Offline property evaluation rejected the complete retained event log.
    #[error("fresh campaign property evaluation failed: {0}")]
    Assertions(#[source] OfflineAssertionCheckError),
    /// Measurement evaluation or campaign binding rejected the retained run.
    #[error("fresh campaign measurement evaluation failed: {0}")]
    Measurements(#[source] CrucibleMeasurementError),
    /// Prepared semantic result construction rejected the complete closure.
    #[error("fresh campaign prepared-result projection failed: {0}")]
    PreparedResult(#[source] PreparedSemanticResultCodecError),
    /// A guest measurement or semantic-marker message violated the scenario contract.
    #[error("fresh campaign guest measurement protocol failed at sequence {sequence}: {reason}")]
    GuestMeasurementProtocol {
        /// Exact scheduler sequence carrying the invalid message.
        sequence: u64,
        /// Stable validation diagnostic.
        reason: String,
    },
    /// The lifecycle returned a child configuration for another scenario.
    #[error("fresh campaign lifecycle returned a configuration for another scenario")]
    ScenarioMismatch,
    /// The lifecycle reported failure without any modeled failure reason.
    #[error("fresh campaign lifecycle returned an empty scenario failure")]
    EmptyScenarioFailure,
    /// A repeated opportunity ID carried conflicting canonical bodies.
    #[error("fresh campaign lifecycle returned conflicting bodies for opportunity `{0}`")]
    ConflictingChoice(ChoiceOpportunityId),
    /// A paused guest selectable request violated the scenario or reply contract.
    #[error("fresh campaign guest selectable failed: {0}")]
    GuestSelectable(#[source] GuestSelectableError),
    /// Retained event or property-evaluation work exceeded the driver bound.
    #[error("fresh campaign modeled projection exceeded `{limit}`")]
    LimitExceeded {
        /// Stable name of the exceeded limit.
        limit: &'static str,
    },
    /// A modeled stop was reported while network output remained uncommitted.
    #[error("fresh campaign stop retained {0} uncommitted network outputs")]
    PendingNetworkOutput(usize),
    /// The authoritative scheduler-quantum coordinate moved backward.
    #[error("fresh campaign scheduler quantum coordinate regressed from {before} to {after}")]
    QuantumCounterRegressed {
        /// Coordinate observed before the operation.
        before: u64,
        /// Coordinate observed after the operation.
        after: u64,
    },
    /// The retained start and live scheduler name different quantum coordinates.
    #[error(
        "fresh campaign start quantum coordinate {materialized} differs from live scheduler coordinate {authoritative}"
    )]
    StartQuantumCoordinateMismatch {
        /// Coordinate carried by the retained start materialization.
        materialized: u64,
        /// Coordinate reported by the live scheduler lifecycle.
        authoritative: u64,
    },
    /// An internal savepoint-replay proof was absent, repeated, or poisoned.
    #[error("savepoint replay proof state is inconsistent")]
    SavepointReplayProof,
}

impl From<CrucibleArtifactError> for QemuFreshModeledDriverError {
    fn from(error: CrucibleArtifactError) -> Self {
        Self::Artifact(error)
    }
}

impl From<CampaignCodecError> for QemuFreshModeledDriverError {
    fn from(error: CampaignCodecError) -> Self {
        Self::Campaign(error)
    }
}

impl From<OfflineAssertionCheckError> for QemuFreshModeledDriverError {
    fn from(error: OfflineAssertionCheckError) -> Self {
        Self::Assertions(error)
    }
}

impl From<PreparedSemanticResultCodecError> for QemuFreshModeledDriverError {
    fn from(error: PreparedSemanticResultCodecError) -> Self {
        Self::PreparedResult(error)
    }
}

/// Concrete bounded modeled driver for one fresh campaign QEMU lifecycle.
#[derive(Clone, Copy, Debug, Default)]
pub struct QemuFreshModeledDriver;

/// Concrete semantic driver for one already-materialized hot-fork child.
///
/// This driver reuses the same bounded scheduler and observation projection as
/// fresh and exact execution. The live-child owner must first assemble a
/// process-owner-neutral [`QemuModeledAttemptLifecycle`]; raw QMP, shared-memory,
/// and host-I/O capabilities alone are rejected before guest progress.
#[derive(Clone, Copy, Debug, Default)]
#[cfg(target_os = "linux")]
pub struct QemuHotForkModeledDriver;

/// Failure while driving or sealing one modeled hot-fork child.
#[derive(Debug, Error)]
#[cfg(target_os = "linux")]
pub enum QemuHotForkModeledDriverError {
    /// The live child has not installed its process-owner-neutral scheduler view.
    #[error("hot-fork child has no assembled modeled-execution lifecycle: {0}")]
    LifecycleUnavailable(#[source] crucible_qemu::QemuVmRealizationError),
    /// The modeled core requested an exact checkpoint unsupported by this phase contract.
    #[error("hot-fork modeled execution requested an exact checkpoint handoff")]
    CheckpointRequested,
    /// Shared semantic driving or observation projection failed.
    #[error(transparent)]
    Modeled(#[from] QemuFreshModeledDriverError),
}

/// Bounded modeled state retained until runner-owned final drain completes.
#[derive(Debug)]
pub struct QemuFreshPendingObservation {
    input: CrucibleAttemptExecution,
    configuration: crucible::Configuration,
    stop: ModeledStop,
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_bytes: usize,
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    terminal_at: VirtualTime,
}

/// Compact proof of the modeled boundary reached by an independent replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuSavepointReplayProof {
    configuration: ContentHash,
    completed_quanta: u64,
    frontier: VirtualTime,
    event_count: u64,
    event_digest: [u8; 32],
}

impl QemuSavepointReplayProof {
    /// Binds a reached configuration to its scheduler coordinate and complete
    /// event prefix.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::SavepointReplayProof`] when the
    /// event count cannot be represented by the portable proof.
    pub fn from_reached_boundary(
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let event_count = u64::try_from(entries.len())
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?;
        Ok(Self {
            configuration: configuration.id(),
            completed_quanta,
            frontier,
            event_count,
            event_digest: savepoint_event_prefix_digest(entries),
        })
    }

    /// Returns whether one restored checkpoint has this exact modeled boundary.
    #[must_use]
    pub fn matches_checkpoint(
        self,
        configuration: &Configuration,
        scheduler: &crucible::SingleSchedulerCheckpoint,
    ) -> bool {
        self.matches_boundary(
            configuration,
            scheduler.quanta(),
            scheduler.frontier(),
            scheduler.retained_event_log_base_events(),
            scheduler.retained_event_log_entries(),
        )
    }

    fn matches_boundary(
        self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        event_base: u64,
        entries: &[SchedulerEventLogEntry],
    ) -> bool {
        let Ok(event_count) = u64::try_from(entries.len()) else {
            return false;
        };
        self.configuration == configuration.id()
            && self.completed_quanta == completed_quanta
            && self.frontier == frontier
            && event_base == 0
            && self.event_count == event_count
            && self.event_digest == savepoint_event_prefix_digest(entries)
    }
}

/// Modeled driver that records the reached boundary while producing no durable result.
pub(crate) struct QemuSavepointReplayProbe {
    proof: Arc<Mutex<Option<QemuSavepointReplayProof>>>,
}

/// Read side of one independent savepoint replay probe.
pub(crate) struct QemuSavepointReplayReceipt {
    proof: Arc<Mutex<Option<QemuSavepointReplayProof>>>,
}

impl QemuSavepointReplayProbe {
    /// Creates one single-use replay driver and its disjoint proof receipt.
    pub(crate) fn new() -> (Self, QemuSavepointReplayReceipt) {
        let proof = Arc::new(Mutex::new(None));
        (
            Self {
                proof: Arc::clone(&proof),
            },
            QemuSavepointReplayReceipt { proof },
        )
    }
}

impl QemuSavepointReplayReceipt {
    /// Consumes the exact boundary proof recorded before lifecycle shutdown.
    pub(crate) fn take(self) -> Result<QemuSavepointReplayProof, QemuFreshModeledDriverError> {
        self.proof
            .lock()
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?
            .take()
            .ok_or(QemuFreshModeledDriverError::SavepointReplayProof)
    }
}

#[derive(Debug)]
enum ModeledStop {
    Reached(StopCondition),
    TerminalPassed,
    TerminalFailed(Vec<String>),
}

impl QemuFreshModeledDriver {
    /// Creates the stateless fresh-attempt driver.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Scheduler progress needed by the materialization-independent modeled core.
///
/// Fresh execution and exact resume have different process and checkpoint
/// owners, but they must interpret an admitted attempt and project its result
/// identically. This narrow boundary keeps that semantic loop independent of
/// how the live scheduler was materialized while exposing no shutdown,
/// checkpoint-publication, or resource-release authority.
/// Process-owner-neutral scheduler operations required by modeled campaign execution.
///
/// Implementations expose semantic progress, selectable delivery, quiescence,
/// and network settlement without exposing process termination, resource
/// release, VMState restore, or template recovery authority. Fresh, exact, and
/// hot materialization must implement this same boundary before the common
/// modeled driver can produce campaign evidence.
pub trait QemuModeledAttemptLifecycle {
    /// Advances exactly one scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the guarded scheduler cannot complete
    /// the requested quantum.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError>;

    /// Returns the absolute scheduler-quantum coordinate at the current boundary.
    #[must_use]
    fn completed_quanta(&self) -> u64;

    /// Observes the current modeled terminal verdict, if any.
    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict>;

    /// Returns whether every live node is at an exact checkpoint boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when quiescence cannot be authenticated.
    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError>;

    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the selectable transport is malformed.
    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError>;

    /// Applies one exact host-authorized selectable reply at the scheduler frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the request is stale or the reply is
    /// incompatible with its retained reservation.
    fn apply_selectable_reply(
        &mut self,
        parent: &crucible::Configuration,
        decision: SelectionDecision,
        selected: &crucible::Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError>;

    /// Returns the number of guest frames not yet globally committed.
    #[must_use]
    fn pending_network_output_count(&self) -> usize;
}

impl QemuModeledAttemptLifecycle for QemuFreshAttemptLifecycle<'_> {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        QemuFreshAttemptLifecycle::drive_quantum(self, request)
    }

    fn completed_quanta(&self) -> u64 {
        QemuFreshAttemptLifecycle::completed_quanta(self)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        QemuFreshAttemptLifecycle::terminal_verdict_for_stop(self)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        QemuFreshAttemptLifecycle::exact_checkpoint_ready(self)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        QemuFreshAttemptLifecycle::drain_pending_selectable_requests(self)
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &crucible::Configuration,
        decision: SelectionDecision,
        selected: &crucible::Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        QemuFreshAttemptLifecycle::apply_selectable_reply(
            self, parent, decision, selected, pending, reply,
        )
    }

    fn pending_network_output_count(&self) -> usize {
        QemuFreshAttemptLifecycle::pending_network_output_count(self)
    }
}

impl QemuFreshAttemptDriver for QemuFreshModeledDriver {
    type Pending = QemuFreshPendingObservation;
    type Error = QemuFreshModeledDriverError;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        drive_modeled_attempt(lifecycle, input, context, materialization)
    }

    fn seal(
        &mut self,
        mut pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        append_event_entries(
            &mut pending.event_log,
            &mut pending.event_log_bytes,
            final_events,
        )
        .map_err(AttemptWorkerFailure::Terminal)?;
        build_observation_candidate(pending).map_err(AttemptWorkerFailure::Terminal)
    }
}

impl QemuFreshAttemptDriver for QemuSavepointReplayProbe {
    type Pending = QemuFreshPendingObservation;
    type Error = QemuFreshModeledDriverError;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        let outcome = drive_modeled_attempt(lifecycle, input, context, materialization)?;
        if let QemuFreshDriveOutcome::Observation(pending) = &outcome {
            let proof = QemuSavepointReplayProof::from_reached_boundary(
                &pending.configuration,
                lifecycle.completed_quanta(),
                pending.terminal_at,
                &pending.event_log,
            )
            .map_err(AttemptWorkerFailure::Terminal)?;
            let mut slot = self.proof.lock().map_err(|_| {
                AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::SavepointReplayProof)
            })?;
            if slot.replace(proof).is_some() {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::SavepointReplayProof,
                ));
            }
        }
        Ok(outcome)
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        QemuFreshModeledDriver.seal(pending, final_events)
    }
}

fn savepoint_event_prefix_digest(entries: &[SchedulerEventLogEntry]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.savepoint-replay-event-prefix.v1\0");
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&entry.sequence().to_be_bytes());
        hasher.update(&entry.content_hash().bytes);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(target_os = "linux")]
impl QemuHotForkAttemptDriver for QemuHotForkModeledDriver {
    type Pending = QemuFreshPendingObservation;
    type Error = QemuHotForkModeledDriverError;

    fn drive<L>(
        &mut self,
        live: &mut L,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Pending, AttemptWorkerFailure<Self::Error>>
    where
        L: QemuHotForkLiveExecution,
    {
        let materialization = live
            .take_start_materialization()
            .map_err(classify_hot_lifecycle_failure)?;
        let lifecycle = live
            .modeled_lifecycle()
            .map_err(classify_hot_lifecycle_failure)?;
        match drive_modeled_attempt(lifecycle, input, context, materialization)
            .map_err(map_hot_modeled_failure)?
        {
            QemuFreshDriveOutcome::Observation(pending) => Ok(pending),
            QemuFreshDriveOutcome::CheckpointRequested => Err(AttemptWorkerFailure::Terminal(
                QemuHotForkModeledDriverError::CheckpointRequested,
            )),
        }
    }

    fn seal<L>(
        &mut self,
        pending: Self::Pending,
        live: &mut L,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>>
    where
        L: QemuHotForkLiveExecution,
    {
        live.check_operational_boundary()
            .map_err(classify_hot_lifecycle_failure)?;
        build_observation_candidate(pending)
            .map_err(QemuHotForkModeledDriverError::Modeled)
            .map_err(AttemptWorkerFailure::Terminal)
    }
}

#[cfg(target_os = "linux")]
fn classify_hot_lifecycle_failure(
    error: crucible_qemu::QemuVmRealizationError,
) -> AttemptWorkerFailure<QemuHotForkModeledDriverError> {
    let retryable = matches!(
        error,
        crucible_qemu::QemuVmRealizationError::StoreUnavailable { .. }
            | crucible_qemu::QemuVmRealizationError::ExecutorUnavailable { .. }
    );
    let canceled = matches!(
        error,
        crucible_qemu::QemuVmRealizationError::Canceled { .. }
    );
    let error = QemuHotForkModeledDriverError::LifecycleUnavailable(error);
    if retryable {
        AttemptWorkerFailure::Retryable(error)
    } else if canceled {
        AttemptWorkerFailure::Canceled(error)
    } else {
        AttemptWorkerFailure::Terminal(error)
    }
}

#[cfg(target_os = "linux")]
fn map_hot_modeled_failure(
    failure: AttemptWorkerFailure<QemuFreshModeledDriverError>,
) -> AttemptWorkerFailure<QemuHotForkModeledDriverError> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuHotForkModeledDriverError::Modeled(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuHotForkModeledDriverError::Modeled(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuHotForkModeledDriverError::Modeled(error))
        }
    }
}

fn drive_modeled_attempt(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    materialization: QemuFreshStartMaterialization,
) -> Result<
    QemuFreshDriveOutcome<QemuFreshPendingObservation>,
    AttemptWorkerFailure<QemuFreshModeledDriverError>,
> {
    let scenario = input.scenario().scenario_def();
    let mut configuration = match input.start() {
        CrucibleResolvedAttemptStart::Discover { configuration } => configuration.clone(),
        CrucibleResolvedAttemptStart::Branch { selected, .. } => selected.clone(),
    };
    if configuration.def != scenario {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::ScenarioMismatch,
        ));
    }

    let (
        mut event_log,
        mut event_log_bytes,
        mut completed_quanta,
        frontier,
        mut terminal_quiescence,
        terminal_verdict,
    ) = materialization.into_parts();
    let authoritative_quanta = lifecycle.completed_quanta();
    if completed_quanta != authoritative_quanta {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::StartQuantumCoordinateMismatch {
                materialized: completed_quanta,
                authoritative: authoritative_quanta,
            },
        ));
    }
    let mut terminal_at = frontier;
    let mut discoveries = RetainedChoiceDiscoveries::default();
    check_cancellation(context)?;
    if let Some(verdict) = terminal_verdict {
        let stop = modeled_terminal_stop(verdict).map_err(AttemptWorkerFailure::Terminal)?;
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
            },
        );
    }
    if checkpoint_is_ready(lifecycle, context)? {
        return Ok(QemuFreshDriveOutcome::CheckpointRequested);
    }
    if initial_requested_stop_reached(input.attempt().stop(), terminal_at, completed_quanta) {
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop: ModeledStop::Reached(input.attempt().stop().clone()),
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
            },
        );
    }

    let mut observed_event_count = 0usize;
    loop {
        if check_operational_signals(lifecycle, context)? {
            return Ok(QemuFreshDriveOutcome::CheckpointRequested);
        }
        let mut outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            })
            .map_err(classify_scheduler_error)?;
        let next_completed_quanta = lifecycle.completed_quanta();
        if next_completed_quanta < completed_quanta {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::QuantumCounterRegressed {
                    before: completed_quanta,
                    after: next_completed_quanta,
                },
            ));
        }
        completed_quanta = next_completed_quanta;
        if outcome.configuration.def != scenario {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::ScenarioMismatch,
            ));
        }

        check_cancellation(context)?;
        let terminal_stop = match lifecycle.terminal_verdict_for_stop() {
            Some(QuantumTerminalVerdict::Passed) => Some(ModeledStop::TerminalPassed),
            Some(verdict @ QuantumTerminalVerdict::Failed(_)) => {
                Some(modeled_terminal_stop(verdict).map_err(AttemptWorkerFailure::Terminal)?)
            }
            None => None,
        };
        if terminal_stop.is_none() && checkpoint_is_ready(lifecycle, context)? {
            return Ok(QemuFreshDriveOutcome::CheckpointRequested);
        }
        if terminal_stop.is_none() {
            resolve_pending_guest_choices(lifecycle, input, &mut outcome, &mut discoveries)?;
        }
        let stop = terminal_stop.or_else(|| {
            reached_requested_stop(
                input.attempt().stop(),
                &outcome,
                observed_event_count,
                completed_quanta,
                &discoveries.discoveries,
            )
        });
        observed_event_count = observed_event_count
            .checked_add(outcome.event_log_entries.len())
            .ok_or(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::LimitExceeded {
                    limit: "fresh-campaign-event-log-entry-count",
                },
            ))?;
        let retain_signal_fault_discoveries = matches!(
            stop.as_ref(),
            Some(ModeledStop::Reached(StopCondition::NextChoice))
        );
        configuration = append_quantum(
            &mut event_log,
            &mut event_log_bytes,
            &mut discoveries,
            &mut terminal_quiescence,
            &mut terminal_at,
            retain_signal_fault_discoveries,
            outcome,
        )?;
        let Some(stop) = stop else {
            continue;
        };

        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
            },
        );
    }
}

fn modeled_stop_outcome(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    context: &AttemptExecutionContext,
    pending: QemuFreshPendingObservation,
) -> Result<
    QemuFreshDriveOutcome<QemuFreshPendingObservation>,
    AttemptWorkerFailure<QemuFreshModeledDriverError>,
> {
    if !matches!(
        context.start_mode(),
        AttemptStartMode::SavepointCapture { .. }
    ) {
        return Ok(QemuFreshDriveOutcome::Observation(pending));
    }
    if !context.checkpoint_request().is_requested() {
        return Err(classify_scheduler_error(
            SchedulerError::BoundaryViolation {
                message: String::from(
                    "savepoint capture reached its stop without a checkpoint request",
                ),
            },
        ));
    }
    if !lifecycle
        .exact_checkpoint_ready()
        .map_err(classify_scheduler_error)?
    {
        return Err(classify_scheduler_error(
            SchedulerError::BoundaryViolation {
                message: String::from("savepoint capture stop is not checkpoint ready"),
            },
        ));
    }
    Ok(QemuFreshDriveOutcome::CheckpointRequested)
}

fn resolve_pending_guest_choices(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    outcome: &mut QuantumOutcome,
    discoveries: &mut RetainedChoiceDiscoveries,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let pending = lifecycle
        .drain_pending_selectable_requests()
        .map_err(classify_scheduler_error)?;
    let mut continuations = Vec::with_capacity(pending.len());
    for pending in pending {
        let discovery = resolve_guest_selectable(
            input.lineage().scenario(),
            input.scenario(),
            pending.node(),
            pending.pending(),
        )
        .map_err(|error| {
            AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::GuestSelectable(error))
        })?;
        discoveries
            .insert(discovery.clone())
            .map_err(AttemptWorkerFailure::Terminal)?;
        if input.attempt().stop() != &StopCondition::NextChoice {
            let selection = Selection::new(
                discovery.opportunity(),
                discovery.domain(),
                discovery.opportunity().default().clone(),
                SelectionOrigin::Default,
            )
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::GuestSelectable(
                    GuestSelectableError::Campaign(error),
                ))
            })?;
            let reply = selected_guest_reply(pending.pending(), &discovery, &selection).map_err(
                |error| {
                    AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::GuestSelectable(
                        error,
                    ))
                },
            )?;
            continuations.push((pending, reply, SelectionDecision::new(&selection)));
        }
    }
    for (pending, reply, decision) in continuations {
        let parent = outcome.configuration.clone();
        let selected = step(&parent, Decision::Selection(decision.clone()));
        let entries = lifecycle
            .apply_selectable_reply(&parent, decision, &selected, &pending, &reply)
            .map_err(classify_scheduler_error)?;
        outcome.configuration = selected;
        outcome.event_log_entries.extend(entries);
    }
    Ok(())
}

fn require_settled_network(
    lifecycle: &(impl QemuModeledAttemptLifecycle + ?Sized),
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let pending = lifecycle.pending_network_output_count();
    if pending == 0 {
        Ok(())
    } else {
        Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::PendingNetworkOutput(pending),
        ))
    }
}

fn check_operational_signals(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    context: &AttemptExecutionContext,
) -> Result<bool, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    check_cancellation(context)?;
    checkpoint_is_ready(lifecycle, context)
}

fn check_cancellation(
    context: &AttemptExecutionContext,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if context.cancellation().is_canceled() {
        return Err(AttemptWorkerFailure::Canceled(
            QemuFreshModeledDriverError::Canceled,
        ));
    }
    Ok(())
}

fn checkpoint_is_ready(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    context: &AttemptExecutionContext,
) -> Result<bool, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if matches!(
        context.start_mode(),
        AttemptStartMode::SavepointCapture { .. }
    ) {
        return Ok(false);
    }
    if context.checkpoint_request().is_requested() {
        return lifecycle
            .exact_checkpoint_ready()
            .map_err(classify_scheduler_error);
    }
    Ok(false)
}

fn classify_scheduler_error(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshModeledDriverError> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuFreshModeledDriverError::Scheduler(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn append_quantum(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    event_log_bytes: &mut usize,
    discoveries: &mut RetainedChoiceDiscoveries,
    terminal_quiescence: &mut Option<SchedulerQuiescence>,
    terminal_at: &mut VirtualTime,
    retain_signal_fault_discoveries: bool,
    outcome: QuantumOutcome,
) -> Result<crucible::Configuration, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let QuantumOutcome {
        configuration,
        discovered_choices,
        event_log_entries,
        scheduler_quiescence,
        frontier,
        ..
    } = outcome;
    append_event_entries(event_log, event_log_bytes, event_log_entries)
        .map_err(AttemptWorkerFailure::Terminal)?;
    for discovery in discovered_choices {
        if is_signal_fault_discovery(&discovery) && !retain_signal_fault_discoveries {
            continue;
        }
        discoveries
            .insert(discovery)
            .map_err(AttemptWorkerFailure::Terminal)?;
    }
    *terminal_quiescence = scheduler_quiescence;
    *terminal_at = (*terminal_at).max(frontier);
    Ok(configuration)
}

fn is_signal_fault_discovery(discovery: &ChoiceDiscovery) -> bool {
    matches!(
        discovery.opportunity().source(),
        crucible_campaign::ChoiceSource::Environment { adapter, .. }
            if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
    )
}

fn append_event_entries(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    retained_bytes: &mut usize,
    entries: Vec<SchedulerEventLogEntry>,
) -> Result<(), QemuFreshModeledDriverError> {
    let total = event_log.len().checked_add(entries.len()).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-entry-count",
        },
    )?;
    if total > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-entry-count",
        });
    }
    let added_bytes = entries.iter().try_fold(0usize, |total, entry| {
        total.checked_add(entry.canonical_material_len()).ok_or(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            },
        )
    })?;
    let total_bytes = retained_bytes.checked_add(added_bytes).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
        },
    )?;
    if total_bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
        });
    }
    event_log.extend(entries);
    *retained_bytes = total_bytes;
    Ok(())
}

#[derive(Default)]
struct RetainedChoiceDiscoveries {
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    representatives: BTreeMap<(SelectableId, ChoiceDomainId), ChoiceDiscovery>,
    charged_records: BTreeSet<ContentId>,
    charged_bytes: usize,
}

impl RetainedChoiceDiscoveries {
    fn insert(
        &mut self,
        mut discovery: ChoiceDiscovery,
    ) -> Result<(), QemuFreshModeledDriverError> {
        let declaration = discovery.opportunity().declaration();
        let domain = discovery.opportunity().domain();
        let opportunity = discovery.opportunity().id()?;
        let contract = (declaration, domain);
        if let Some(validated) = self.representatives.get(&contract) {
            discovery.share_dependencies_from(validated)?;
        } else {
            self.charge(
                declaration.content_id(),
                discovery.declaration().canonical_bytes().len(),
            )?;
            self.charge(
                domain.content_id(),
                discovery.domain().canonical_bytes().len(),
            )?;
            self.representatives.insert(contract, discovery.clone());
        }

        if let Some(existing) = self.discoveries.get(&opportunity) {
            if existing.opportunity() != discovery.opportunity() {
                return Err(QemuFreshModeledDriverError::ConflictingChoice(opportunity));
            }
            return Ok(());
        }
        if self.discoveries.len() == MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-count",
            });
        }
        self.charge(
            opportunity.content_id(),
            discovery.opportunity().canonical_bytes().len(),
        )?;
        self.discoveries.insert(opportunity, discovery);
        Ok(())
    }

    fn charge(&mut self, id: ContentId, bytes: usize) -> Result<(), QemuFreshModeledDriverError> {
        if !self.charged_records.insert(id) {
            return Ok(());
        }
        let total = self.charged_bytes.checked_add(bytes).ok_or(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            },
        )?;
        if total > MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            });
        }
        self.charged_bytes = total;
        Ok(())
    }
}

fn reached_requested_stop(
    requested: &StopCondition,
    outcome: &QuantumOutcome,
    observed_event_count: usize,
    completed_quanta: u64,
    discoveries: &BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
) -> Option<ModeledStop> {
    let reached = match requested {
        StopCondition::NextChoice => {
            !discoveries.is_empty() || !outcome.discovered_choices.is_empty()
        }
        StopCondition::NamedBoundary(name) => outcome.event_log_entries.iter().any(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                    marker,
                    ..
                }) if marker.name == *name
            )
        }),
        StopCondition::VirtualTimeNanoseconds(deadline) => outcome.frontier.ticks >= *deadline,
        StopCondition::EventCount(count) => observed_event_count
            .checked_add(outcome.event_log_entries.len())
            .and_then(|events| u64::try_from(events).ok())
            .is_some_and(|events| events >= *count),
        StopCondition::Terminal => false,
        StopCondition::ExecutionQuanta(bound) => completed_quanta >= *bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        } => {
            outcome.frontier.ticks >= *virtual_time_nanoseconds
                || completed_quanta >= *execution_quanta
        }
    };
    reached.then(|| ModeledStop::Reached(requested.clone()))
}

fn initial_requested_stop_reached(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
) -> bool {
    match requested {
        StopCondition::VirtualTimeNanoseconds(deadline) => frontier.ticks >= *deadline,
        StopCondition::ExecutionQuanta(bound) => completed_quanta >= *bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        } => frontier.ticks >= *virtual_time_nanoseconds || completed_quanta >= *execution_quanta,
        StopCondition::NextChoice
        | StopCondition::NamedBoundary(_)
        | StopCondition::EventCount(_)
        | StopCondition::Terminal => false,
    }
}

fn build_observation_candidate(
    pending: QemuFreshPendingObservation,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    let assertion_count = pending
        .input
        .scenario()
        .properties()
        .assertions()
        .len()
        .max(1);
    let assertion_visits = pending.event_log.len().checked_mul(assertion_count).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-assertion-event-visits",
        },
    )?;
    if assertion_visits > MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-assertion-event-visits",
        });
    }

    let mut checker = OfflineAssertionChecker::new()
        .with_world_white_box_policies(pending.input.scenario().world());
    if let Some(quiescence) = pending.terminal_quiescence.clone() {
        checker = checker.with_terminal_scheduler_quiescence(quiescence);
    }
    let report = checker.check_run(pending.input.scenario().properties(), &pending.event_log)?;
    let properties = property_verdicts(&report)?;

    let scenario_artifact = encode_crucible_scenario_artifact(pending.input.scenario())?;
    if scenario_artifact.id()? != pending.input.lineage().scenario_content()
        || scenario_artifact.scenario() != pending.input.lineage().scenario()
    {
        return Err(QemuFreshModeledDriverError::ScenarioMismatch);
    }
    let child = encode_crucible_configuration_artifact(
        &scenario_artifact,
        &pending.configuration.schedule,
    )?;
    let measurement_publication = campaign_measurements(&pending, child.configuration())?;
    let (measurement_evidence, _, measurements) = measurement_publication.into_parts();
    let stop = stop_outcome(pending.stop, &report);
    let coverage = coverage_projection(&pending.event_log)?;
    let discovered_choices = pending.discoveries.into_values().collect::<Vec<_>>();
    let discovered_ids = discovered_choices
        .iter()
        .map(|discovery| discovery.opportunity().id())
        .collect::<Result<BTreeSet<_>, _>>()?;
    let produced_selections = pending
        .configuration
        .schedule
        .decisions()
        .iter()
        .filter_map(|decision| match decision {
            Decision::Selection(selection) => Some(selection),
            _ => None,
        })
        .map(|decision| Selection::from_canonical_bytes(decision.canonical_bytes()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|selection| discovered_ids.contains(&selection.opportunity()))
        .collect();
    let observation = Observation::new(
        pending.input.attempt().id()?,
        child.configuration(),
        child.id()?,
        pending.input.path().id()?,
        stop,
        measurements.id()?,
        properties.id()?,
        coverage.id()?,
        discovered_ids,
    )?;
    let candidate = ObservationCandidate::new(
        child,
        measurements,
        properties,
        coverage,
        discovered_choices,
        observation,
    )
    .and_then(|candidate| candidate.with_produced_selections(produced_selections))?;
    let result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
        candidate,
        vec![measurement_evidence],
        None,
    )?;
    Ok(AttemptExecutionProduct::prepared_semantic(result))
}

fn campaign_measurements(
    pending: &QemuFreshPendingObservation,
    configuration: crucible_campaign::ConfigurationId,
) -> Result<crate::CrucibleMeasurementPublication, QemuFreshModeledDriverError> {
    let definitions = pending.input.scenario().measurements();
    let mut node_icounts = BTreeMap::new();
    for entry in &pending.event_log {
        if let Some(node) = &entry.time().icount.node {
            node_icounts
                .entry(node.clone())
                .and_modify(|value: &mut crucible::Icount| {
                    *value = (*value).max(entry.time().icount.icount);
                })
                .or_insert(entry.time().icount.icount);
        }
    }
    let terminal = MeasurementTerminalState {
        scenario_ready_at: pending
            .event_log
            .iter()
            .find(|entry| entry.event_payload().kind() == "scenario_ready")
            .map(SchedulerEventLogEntry::at),
        at: pending
            .event_log
            .last()
            .map_or(pending.terminal_at, |entry| {
                pending.terminal_at.max(entry.at())
            }),
        node_icounts,
        scheduler_quiescent: pending
            .terminal_quiescence
            .as_ref()
            .is_some_and(SchedulerQuiescence::is_quiescent),
    };
    evaluate_crucible_measurement_publication(
        pending.input.lineage().scenario(),
        configuration,
        definitions,
        pending.event_log.clone(),
        terminal,
        MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    )
    .map_err(QemuFreshModeledDriverError::Measurements)
}

fn property_verdicts(
    report: &crucible::HostAssertionReport,
) -> Result<PropertyVerdictSet, QemuFreshModeledDriverError> {
    let mut properties = BTreeMap::new();
    for outcome in report.outcomes() {
        let verdict = match outcome.kind {
            HostAssertionOutcomeKind::Passed | HostAssertionOutcomeKind::Satisfied => {
                PropertyVerdict::Passed
            }
            HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail => {
                PropertyVerdict::Failed
            }
            HostAssertionOutcomeKind::Warning
            | HostAssertionOutcomeKind::NeverEvaluated
            | HostAssertionOutcomeKind::NeverTriggered
            | HostAssertionOutcomeKind::NeverReachedWarn => PropertyVerdict::Inconclusive,
        };
        let evidence = PropertyEvidence::new(verdict, BTreeSet::new())?;
        if properties
            .insert(outcome.assertion.name.clone(), evidence)
            .is_some()
        {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-duplicate-property-outcome",
            });
        }
    }
    PropertyVerdictSet::new(properties).map_err(Into::into)
}

fn stop_outcome(stop: ModeledStop, report: &crucible::HostAssertionReport) -> StopOutcome {
    if let Some(failure) = report.verdict().failures().first() {
        return StopOutcome::AssertionFailure(failure.assertion.name.clone());
    }
    match stop {
        ModeledStop::Reached(stop) => StopOutcome::Reached(stop),
        ModeledStop::TerminalPassed => StopOutcome::TerminalSuccess,
        ModeledStop::TerminalFailed(reasons) => StopOutcome::ScenarioFailure(reasons),
    }
}

fn modeled_terminal_stop(
    verdict: QuantumTerminalVerdict,
) -> Result<ModeledStop, QemuFreshModeledDriverError> {
    match verdict {
        QuantumTerminalVerdict::Passed => Ok(ModeledStop::TerminalPassed),
        QuantumTerminalVerdict::Failed(reasons) if reasons.is_empty() => {
            Err(QemuFreshModeledDriverError::EmptyScenarioFailure)
        }
        QuantumTerminalVerdict::Failed(reasons) => Ok(ModeledStop::TerminalFailed(reasons)),
    }
}

fn coverage_projection(
    event_log: &[SchedulerEventLogEntry],
) -> Result<CoverageProjection, QemuFreshModeledDriverError> {
    let projection = crucible::event_log_coverage_projection(event_log);
    let identities = projection
        .entries()
        .iter()
        .map(|entry| coverage_identity(&entry.observation))
        .collect();
    CoverageProjection::new(identities, BTreeSet::new()).map_err(Into::into)
}

fn coverage_identity(observation: &EventLogCoverageObservation) -> CampaignHash {
    CampaignHash::from_bytes(observation.content_hash().bytes)
}

#[cfg(test)]
mod tests;
