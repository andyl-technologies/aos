//! Attempt-guarded construction of the production QEMU lifecycle.
//!
//! This module is the daemon-side join between an admitted campaign execution
//! context and the production lifecycle scheduler. It installs one exact
//! process/resource guard before lifecycle construction, validates the guard's
//! resource and cancellation incarnation, and transfers that authority into
//! [`QemuAttemptProductionVmNodeLauncher`]. [`QemuFreshExecutionRunner`] keeps
//! final drain and teardown outside the modeled driver and seals a result only
//! after those final events are available. The fresh path never silently
//! substitutes for an exact-checkpoint resume.

use std::collections::BTreeSet;

use crucible::{
    Configuration, ContentHash, Decision, QuantumLoop, QuantumOutcome, QuantumRequest,
    QuantumTerminalVerdict, ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerEventLogEntry,
    SchedulerOperationalFailureClass, SchedulerQuiescence,
};
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig,
    ProductionVmLifecycleLoop, ProductionVmNodeReplayLaunchProfile,
    build_production_vm_lifecycle_loop_from_exact_closure_with_launcher,
    build_production_vm_lifecycle_loop_with_launcher,
};
use crucible_campaign::{CampaignHash, ConfigurationId, ExactCheckpointId, SelectionOrigin};
use crucible_cas::content_store::StoreError;
use crucible_protocol::SelectionReply;
use crucible_qemu::{QemuNodeSelectablePendingRequest, QemuVmRealizationError};
use thiserror::Error;

use crate::guest_selectable::{
    GuestSelectableError, resolve_guest_selectable, selected_guest_reply,
};
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionProduct,
    AttemptWorkerFailure, CapturedAttemptCheckpoint, CheckpointHandoffFailure,
    CrucibleAttemptExecution, CrucibleExecutionOutcome, CrucibleExecutionRunner,
    CrucibleMaterializationTier, ExactCheckpointStore, ExactCheckpointStoreError,
    MAX_QEMU_ATTEMPT_GENERATION_NODES, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES, ProductionAttemptCheckpointRestoreError,
    QemuAttemptGenerationResourceOwner, QemuAttemptOperationalBoundary,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmNodeLauncher, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory, install_attempt_production_resume_checkpoint,
};

mod app_random_branch_replay;
use app_random_branch_replay::app_random_branch_replay;

/// Failure to bind an admitted attempt to a fresh production VM lifecycle.
#[derive(Debug, Error)]
pub enum QemuAttemptProductionVmLifecycleError {
    /// The fresh lifecycle path was asked to resume an exact checkpoint.
    #[error("fresh production VM lifecycle cannot resume exact checkpoint `{0}`")]
    ResumeCheckpointUnsupported(ExactCheckpointId),
    /// The serialized scenario form did not reconstruct the supplied identity.
    #[error("production VM lifecycle scenario form does not match the supplied scenario")]
    ScenarioIdentityMismatch,
    /// The scenario's QEMU-node count is outside the attempt-owner bound.
    #[error(
        "production VM lifecycle node count {0} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
    )]
    InvalidNodeCount(usize),
    /// Installing the attempt resource guard failed.
    #[error("install production VM attempt resources: {0}")]
    ResourceInstallation(#[source] QemuVmRealizationError),
    /// The installed guard did not echo the exact admitted attempt contract.
    #[error(
        "production VM resource guard did not install the exact admitted limits and cancellation signal"
    )]
    ResourceContractMismatch,
    /// Releasing a mismatched resource guard failed.
    #[error("release mismatched production VM attempt resources: {0}")]
    ResourceContractCleanup(#[source] QemuVmRealizationError),
    /// The production lifecycle rejected construction under the installed guard.
    #[error("build guarded production VM lifecycle: {0}")]
    Lifecycle(#[source] LifecycleApiError),
    /// The durable version-four root failed exact attempt resume admission.
    #[error("install production VM attempt checkpoint: {0}")]
    CheckpointRestore(#[source] ProductionAttemptCheckpointRestoreError),
    /// The resolved start configuration does not form an executable branch plan.
    #[error("derive exact app-random branch replay: {0}")]
    InvalidAppRandomBranchReplay(String),
    /// The authenticated promoted signal-fault plan names a different start.
    #[error("derive exact signal-fault branch replay: {0}")]
    InvalidSignalFaultBranchReplay(String),
}

/// Factory that binds one admitted attempt to the guarded production lifecycle.
pub struct QemuAttemptProductionVmLifecycleFactory<R> {
    config: ProductionVmLifecycleConfig,
    resources: R,
}

/// Runner-owned fresh lifecycle operations hidden from modeled drivers.
///
/// The owner includes shutdown because the campaign runner, rather than the
/// modeled driver, must perform the final event drain and resource teardown.
/// Drivers receive only [`QemuFreshAttemptLifecycle`], which deliberately does
/// not expose this terminal capability.
pub trait QemuFreshAttemptLifecycleOwner {
    /// Enables exact live signal-fault promotion from the current boundary.
    ///
    /// The fresh runner calls this only after the admitted start configuration
    /// has been materialized. Previously retained signal-fault frontiers remain
    /// replay-only evidence and cannot become discoveries retroactively.
    fn enable_signal_fault_campaign_promotion(&mut self);

    /// Advances one scheduler quantum under the attempt resource guard.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the scheduler or guarded backend cannot
    /// complete the exact quantum.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError>;

    /// Observes the terminal verdict without consuming checkpoint ownership.
    #[must_use]
    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict>;

    /// Returns whether every live node can enter an exact checkpoint now.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when live-node or host-I/O state cannot be
    /// inspected consistently.
    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError>;

    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a live node's request stream is malformed
    /// or violates its single-pending-request contract.
    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError>;

    /// Enqueues one exact semantic reply before the owning guest resumes.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the request is stale, names another node
    /// generation, or the reply violates the retained reservation.
    fn enqueue_selectable_reply(
        &mut self,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), SchedulerError>;

    /// Captures the exact current attempt continuation without CAS publication.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the current boundary is unsafe or the
    /// complete production continuation cannot be durably captured and reopened.
    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError>;

    /// Copies immutable node launch profiles for independent background replay.
    ///
    /// The default fails closed so a lifecycle implementation cannot
    /// accidentally claim baked-genesis support without preserving its exact
    /// scenario-aware QEMU launch basis.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when replay launch profiles are unavailable
    /// or inconsistent with the live lifecycle.
    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        Err(SchedulerError::NotImplemented {
            operation: "copy fresh-genesis replay launch profiles",
        })
    }

    /// Captures read-only production fault evidence at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a fault adapter or retained trace cannot
    /// be inspected consistently.
    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError>;

    /// Returns the number of guest frames not yet globally committed.
    #[must_use]
    fn pending_network_output_count(&self) -> usize;

    /// Performs final drain, process reap, lease release, and aggregate release.
    ///
    /// Returned entries are the only scheduler observations produced during
    /// teardown and must be supplied to modeled result sealing.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when final drain or resource cleanup cannot
    /// be attested. The implementation must retain unfinished authority in
    /// quarantine on failure.
    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError>;
}

impl QemuFreshAttemptLifecycleOwner for ProductionVmLifecycleLoop {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        ProductionVmLifecycleLoop::enable_signal_fault_campaign_promotion(self);
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        QuantumLoop::drive_quantum(self, request)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        QuantumLoop::terminal_verdict_for_stop(self)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        ProductionVmLifecycleLoop::exact_checkpoint_ready(self)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        ProductionVmLifecycleLoop::drain_pending_selectable_requests(self)
    }

    fn enqueue_selectable_reply(
        &mut self,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), SchedulerError> {
        ProductionVmLifecycleLoop::enqueue_selectable_reply(self, pending, reply)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        self.capture_portable_exact_checkpoint_with_boundary(&mut || {
            if context.cancellation().is_canceled() {
                return Err(SchedulerError::OperationalBoundary {
                    class: SchedulerOperationalFailureClass::Canceled,
                    message: String::from("checkpoint capture canceled"),
                });
            }
            Ok(())
        })
        .map(Into::into)
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        ProductionVmLifecycleLoop::replay_launch_profiles(self).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("derive production replay launch profiles: {error}"),
            }
        })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        ProductionVmLifecycleLoop::fault_evidence_snapshot(self)
    }

    fn pending_network_output_count(&self) -> usize {
        ProductionVmLifecycleLoop::pending_network_output_count(self)
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        QuantumLoop::shutdown(self)
    }
}

/// Narrow modeled-execution view of one guarded fresh QEMU lifecycle.
///
/// This facade exposes bounded scheduler progress and read-only evidence but no
/// shutdown or raw node-launch authority. The runner therefore remains the
/// unique owner of final drain and resource release.
pub struct QemuFreshAttemptLifecycle<'a> {
    owner: &'a mut dyn QemuFreshAttemptLifecycleOwner,
}

impl QemuFreshAttemptLifecycle<'_> {
    pub(crate) fn new(
        owner: &mut dyn QemuFreshAttemptLifecycleOwner,
    ) -> QemuFreshAttemptLifecycle<'_> {
        QemuFreshAttemptLifecycle { owner }
    }

    /// Advances exactly one scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the guarded lifecycle rejects or cannot
    /// complete the quantum.
    pub fn drive_quantum(
        &mut self,
        request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.owner.drive_quantum(request)
    }

    /// Observes the terminal verdict without consuming checkpoint ownership.
    #[must_use]
    pub fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.owner.terminal_verdict_for_stop()
    }

    /// Returns whether every live node can enter an exact checkpoint now.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live checkpoint boundary cannot be
    /// inspected consistently.
    pub fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.owner.exact_checkpoint_ready()
    }

    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// The result remains untrusted guest input until the modeled driver binds
    /// it to the scenario declaration and selects a legal value.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request stream is malformed.
    pub fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.owner.drain_pending_selectable_requests()
    }

    /// Enqueues one exact semantic reply before the owning guest resumes.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request/reply binding fails.
    pub fn enqueue_selectable_reply(
        &mut self,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), SchedulerError> {
        self.owner.enqueue_selectable_reply(pending, reply)
    }

    /// Captures read-only production fault evidence at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when retained production evidence cannot be
    /// inspected consistently.
    pub fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        self.owner.fault_evidence_snapshot()
    }

    /// Returns the number of guest frames not yet globally committed.
    #[must_use]
    pub fn pending_network_output_count(&self) -> usize {
        self.owner.pending_network_output_count()
    }
}

/// Factory for one guarded scenario-genesis lifecycle used by the campaign runner.
pub trait QemuFreshAttemptLifecycleFactory {
    /// Exact lifecycle owner created for one attempt.
    type Lifecycle: QemuFreshAttemptLifecycleOwner;
    /// Factory-specific admission or construction failure.
    type Error;

    /// Starts one scenario-genesis lifecycle under the admitted attempt context.
    ///
    /// # Errors
    ///
    /// Returns a classified failure for invalid semantic input, canceled or
    /// unavailable resource installation, or lifecycle construction failure.
    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>>;
}

/// Two-phase modeled driver for one guarded fresh production lifecycle.
///
/// [`Self::drive`] may advance and inspect the lifecycle but cannot shut it
/// down. [`Self::seal`] runs only after runner-owned shutdown has supplied every
/// final event-log entry, preventing a candidate from being accepted at a
/// pre-teardown observable boundary.
pub trait QemuFreshAttemptDriver {
    /// Driver state retained between modeled stop and final shutdown drain.
    type Pending;
    /// Driver-specific modeled or result-construction failure.
    type Error;

    /// Drives the lifecycle to a modeled stop without returning an accepted product.
    ///
    /// `materialization` contains the bounded event history, terminal state,
    /// and quiescence reconstructed while the runner reached `input`'s exact
    /// start. The driver must preserve that history when evaluating or sealing
    /// cumulative modeled evidence, while stop conditions begin at the admitted
    /// start rather than being satisfied by replayed prefix events.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable, canceled, or terminal modeled failure.
    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>>;

    /// Seals one product after final lifecycle drain and resource cleanup.
    ///
    /// `final_events` is the complete dense suffix produced during shutdown.
    /// A conforming observation builder must incorporate it into the canonical
    /// evidence or reject the result.
    ///
    /// # Errors
    ///
    /// Returns a classified failure when the drained events cannot be projected
    /// into the exact modeled result.
    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>>;
}

/// Runner-owned disposition after modeled fresh-attempt driving.
#[derive(Debug)]
pub enum QemuFreshDriveOutcome<P> {
    /// A modeled stop was reached and awaits final-drain sealing.
    Observation(P),
    /// The sticky checkpoint request reached an exact capture-ready boundary.
    CheckpointRequested,
}

/// Fresh-QEMU campaign runner with exact prefix replay and runner-owned teardown.
///
/// The runner reconstructs an admitted selection-free or standardized
/// model-sampled schedule from scenario genesis before lending the lifecycle to
/// its modeled driver. Producer-owned overrides remain rejected before resource
/// installation until their versioned live injection protocol is available.
pub struct QemuFreshExecutionRunner<F, D> {
    lifecycles: F,
    driver: D,
}

impl<F, D> QemuFreshExecutionRunner<F, D> {
    /// Creates a genesis-start runner from its guarded lifecycle factory and modeled driver.
    #[must_use]
    pub const fn new(lifecycles: F, driver: D) -> Self {
        Self { lifecycles, driver }
    }

    /// Returns the guarded lifecycle factory.
    #[must_use]
    pub const fn lifecycle_factory(&self) -> &F {
        &self.lifecycles
    }

    /// Returns mutable access to the guarded lifecycle factory.
    #[must_use]
    pub const fn lifecycle_factory_mut(&mut self) -> &mut F {
        &mut self.lifecycles
    }

    /// Returns the modeled fresh-attempt driver.
    #[must_use]
    pub const fn driver(&self) -> &D {
        &self.driver
    }

    /// Returns mutable access to the modeled fresh-attempt driver.
    #[must_use]
    pub const fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Consumes the runner into its lifecycle factory and driver.
    #[must_use]
    pub fn into_parts(self) -> (F, D) {
        (self.lifecycles, self.driver)
    }
}

/// Failure from one phase of [`QemuFreshExecutionRunner`].
#[derive(Debug, Error)]
pub enum QemuFreshExecutionRunnerError<F, D> {
    /// The fresh runner was asked to execute a durable resume incarnation.
    #[error("fresh production QEMU runner cannot resume exact checkpoint `{0}`")]
    ResumeCheckpointUnsupported(ExactCheckpointId),
    /// The target contains a producer-owned override with no live injection path.
    #[error(
        "fresh production QEMU runner cannot inject decision {decision} of configuration `{configuration:?}`"
    )]
    StartDecisionUnsupported {
        /// Exact target configuration.
        configuration: crucible::ContentHash,
        /// Zero-based unsupported schedule position.
        decision: usize,
    },
    /// Exact replay from scenario genesis failed.
    #[error("fresh production QEMU start replay failed: {0}")]
    StartReplay(#[source] QemuFreshStartReplayError),
    /// Guarded lifecycle admission or construction failed.
    #[error("fresh production QEMU lifecycle construction failed")]
    Lifecycle(F),
    /// Modeled driving or post-shutdown result sealing failed.
    #[error("fresh production QEMU attempt driver failed")]
    Driver(D),
    /// Final drain, process reap, or resource release failed.
    #[error("fresh production QEMU lifecycle cleanup failed: {0}")]
    Cleanup(SchedulerError),
    /// Complete production checkpoint capture failed at a safe boundary.
    #[error("fresh production QEMU checkpoint capture failed: {0}")]
    CheckpointCapture(#[source] SchedulerError),
    /// The prepared exact root could not be handed to the durable supervisor phase.
    #[error("fresh production QEMU checkpoint handoff failed: {0}")]
    CheckpointHandoff(#[source] CheckpointHandoffFailure),
    /// A modeled driver requested capture without the supervisor's sticky signal.
    #[error("fresh production QEMU driver returned an unsolicited checkpoint request")]
    UnsolicitedCheckpoint,
    /// Cleanup failed after the driver had already returned a failure.
    #[error("fresh production QEMU lifecycle cleanup failed after driver failure: {cleanup}")]
    CleanupAfterDriver {
        /// Original driver failure retained for diagnosis.
        driver: D,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
    /// Cleanup failed after start replay or another runner-owned phase failed.
    #[error(
        "fresh production QEMU lifecycle cleanup failed after runner failure `{failure}`: {cleanup}"
    )]
    CleanupAfterRunner {
        /// Original runner failure retained for diagnosis.
        failure: Box<QemuFreshExecutionRunnerError<F, D>>,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
}

/// Bounded history reconstructed before one fresh attempt begins.
#[derive(Debug)]
pub struct QemuFreshStartMaterialization {
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_bytes: usize,
    terminal_quiescence: Option<SchedulerQuiescence>,
    terminal_verdict: Option<QuantumTerminalVerdict>,
}

impl QemuFreshStartMaterialization {
    pub(crate) fn genesis() -> Self {
        Self {
            event_log: Vec::new(),
            event_log_bytes: 0,
            terminal_quiescence: None,
            terminal_verdict: None,
        }
    }

    /// Consumes the materialization into cumulative replay evidence and state.
    ///
    /// The byte count is the checked aggregate canonical material length of
    /// `event_log`. `terminal_quiescence` and `terminal_verdict` describe the
    /// exact admitted start after replay, not a later attempt quantum.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<SchedulerEventLogEntry>,
        usize,
        Option<SchedulerQuiescence>,
        Option<QuantumTerminalVerdict>,
    ) {
        (
            self.event_log,
            self.event_log_bytes,
            self.terminal_quiescence,
            self.terminal_verdict,
        )
    }

    pub(crate) fn from_resume_parts(
        event_log: Vec<SchedulerEventLogEntry>,
        event_log_bytes: usize,
        terminal_quiescence: SchedulerQuiescence,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        Self {
            event_log,
            event_log_bytes,
            terminal_quiescence: Some(terminal_quiescence),
            terminal_verdict,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        event_log: Vec<SchedulerEventLogEntry>,
        terminal_quiescence: Option<SchedulerQuiescence>,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        let event_log_bytes = event_log
            .iter()
            .map(SchedulerEventLogEntry::canonical_material_len)
            .sum();
        Self {
            event_log,
            event_log_bytes,
            terminal_quiescence,
            terminal_verdict,
        }
    }
}

/// Failure while reconstructing one exact fresh-QEMU start configuration.
#[derive(Debug, Error)]
pub enum QemuFreshStartReplayError {
    /// The attempt was canceled before its start configuration was reached.
    #[error("fresh start replay was canceled")]
    Canceled,
    /// The lifecycle scheduler rejected one replay quantum.
    #[error("fresh start replay scheduler failed: {0}")]
    Scheduler(#[source] SchedulerError),
    /// A paused guest selectable did not match the exact replay decision.
    #[error("fresh start replay guest selectable failed: {0}")]
    GuestSelectable(#[source] GuestSelectableError),
    /// Replay produced a schedule outside the exact requested prefix.
    #[error("fresh start replay diverged from the requested schedule")]
    Diverged,
    /// The scenario stopped before reaching the requested configuration.
    #[error("fresh start replay reached a terminal verdict before the requested configuration")]
    Terminated,
    /// Replay exhausted the attempt's admitted execution-quanta ceiling.
    #[error("fresh start replay exhausted the admitted execution-quanta ceiling")]
    QuantumLimit,
    /// Replayed event history exceeded the observation projection bound.
    #[error("fresh start replay exceeded `{limit}`")]
    LimitExceeded {
        /// Stable name of the exceeded limit.
        limit: &'static str,
    },
}

/// Failure before a fresh genesis checkpoint candidate reached teardown.
#[derive(Debug, Error)]
pub enum QemuFreshGenesisCheckpointCaptureFailure {
    /// The freshly launched lifecycle was not at an exact checkpoint boundary.
    #[error("fresh genesis lifecycle is not checkpoint ready")]
    NotCheckpointReady,
    /// Exact checkpoint capture failed at the authenticated genesis boundary.
    #[error("capture fresh genesis checkpoint: {0}")]
    Capture(#[source] SchedulerError),
    /// Immutable replay launch profiles could not be copied from the lifecycle.
    #[error("capture fresh genesis replay launch profiles: {0}")]
    LaunchProfiles(#[source] SchedulerError),
    /// The capture named a scenario or configuration other than exact genesis.
    #[error("fresh genesis checkpoint capture returned a foreign semantic basis")]
    BasisMismatch,
}

/// Exact native capture and immutable launch basis produced at fresh genesis.
#[derive(Debug)]
pub struct QemuFreshGenesisCheckpointCandidate {
    capture: CapturedAttemptCheckpoint,
    launch_profiles: Vec<ProductionVmNodeReplayLaunchProfile>,
}

impl QemuFreshGenesisCheckpointCandidate {
    /// Returns the exact captured scenario identity.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        self.capture.scenario()
    }

    /// Returns the exact captured genesis configuration identity.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        self.capture.configuration()
    }

    /// Returns immutable replay profiles in World node order.
    #[must_use]
    pub fn launch_profiles(&self) -> &[ProductionVmNodeReplayLaunchProfile] {
        &self.launch_profiles
    }

    /// Consumes the candidate into its native capture and immutable profiles.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CapturedAttemptCheckpoint,
        Vec<ProductionVmNodeReplayLaunchProfile>,
    ) {
        (self.capture, self.launch_profiles)
    }
}

/// Failure while producing one independently captured genesis checkpoint candidate.
#[derive(Debug, Error)]
pub enum QemuFreshGenesisCheckpointError<E> {
    /// Fresh lifecycle construction failed with its original retry class.
    #[error("start fresh genesis checkpoint lifecycle")]
    Start(AttemptWorkerFailure<E>),
    /// Capture failed after lifecycle construction and teardown succeeded.
    #[error(transparent)]
    Capture(#[from] QemuFreshGenesisCheckpointCaptureFailure),
    /// Teardown failed and therefore retains precedence over an earlier result.
    #[error("tear down fresh genesis checkpoint lifecycle: {cleanup}")]
    Cleanup {
        /// Earlier capture failure, when teardown followed another failure.
        prior: Option<Box<QemuFreshGenesisCheckpointCaptureFailure>>,
        /// Mandatory lifecycle teardown failure.
        #[source]
        cleanup: SchedulerError,
    },
}

/// Captures a fresh exact checkpoint at the scenario's genesis ready boundary.
///
/// This is the QEMU-backed bootstrap primitive for a future authenticated baked-
/// genesis catalog. It starts the ordinary production lifecycle at exact
/// genesis, performs no modeled quantum, captures through the same portable
/// checkpoint path used by attempts, and always tears the lifecycle down before
/// returning. The returned value remains only a candidate: a catalog owner must
/// require the version-four production variant and authenticate its complete
/// closure before lending any thin-replay authority.
///
/// # Errors
///
/// Returns [`QemuFreshGenesisCheckpointError`] when guarded lifecycle startup
/// fails, genesis is not checkpoint ready, capture returns a foreign basis, or
/// mandatory teardown cannot be attested. Teardown failure takes precedence
/// and retains any earlier capture diagnostic.
pub fn capture_fresh_genesis_checkpoint_candidate<F>(
    factory: &mut F,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<QemuFreshGenesisCheckpointCandidate, QemuFreshGenesisCheckpointError<F::Error>>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    let scenario = source.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let signal_fault_replay = crucible::SignalFaultCampaignReplayPlan::empty(genesis.clone());
    let mut lifecycle = factory
        .start_fresh_lifecycle(&scenario, source, &genesis, &signal_fault_replay, context)
        .map_err(QemuFreshGenesisCheckpointError::Start)?;

    let captured = match lifecycle.exact_checkpoint_ready() {
        Ok(true) => lifecycle
            .capture_attempt_checkpoint(context)
            .map_err(QemuFreshGenesisCheckpointCaptureFailure::Capture)
            .and_then(|capture| {
                if capture.scenario() != scenario.id() || capture.configuration() != genesis.id() {
                    return Err(QemuFreshGenesisCheckpointCaptureFailure::BasisMismatch);
                }
                let launch_profiles = lifecycle
                    .replay_launch_profiles()
                    .map_err(QemuFreshGenesisCheckpointCaptureFailure::LaunchProfiles)?;
                Ok(QemuFreshGenesisCheckpointCandidate {
                    capture,
                    launch_profiles,
                })
            }),
        Ok(false) => Err(QemuFreshGenesisCheckpointCaptureFailure::NotCheckpointReady),
        Err(error) => Err(QemuFreshGenesisCheckpointCaptureFailure::Capture(error)),
    };
    let cleanup = lifecycle.shutdown();

    match (captured, cleanup) {
        (Ok(capture), Ok(_final_events)) => Ok(capture),
        (Err(error), Ok(_final_events)) => Err(error.into()),
        (Ok(_capture), Err(cleanup)) => Err(QemuFreshGenesisCheckpointError::Cleanup {
            prior: None,
            cleanup,
        }),
        (Err(prior), Err(cleanup)) => Err(QemuFreshGenesisCheckpointError::Cleanup {
            prior: Some(Box::new(prior)),
            cleanup,
        }),
    }
}

enum QemuFreshRunnerResult<P> {
    Observation(P),
    Checkpoint(AttemptCheckpointResult),
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R> {
    /// Creates a factory from trusted lifecycle configuration and host resources.
    #[must_use]
    pub const fn new(config: ProductionVmLifecycleConfig, resources: R) -> Self {
        Self { config, resources }
    }

    /// Returns the trusted lifecycle configuration.
    #[must_use]
    pub const fn config(&self) -> &ProductionVmLifecycleConfig {
        &self.config
    }

    /// Returns the resource-guard factory.
    #[must_use]
    pub const fn resources(&self) -> &R {
        &self.resources
    }

    /// Returns the mutable resource-guard factory.
    #[must_use]
    pub const fn resources_mut(&mut self) -> &mut R {
        &mut self.resources
    }

    /// Consumes the factory into its lifecycle configuration and resource owner.
    #[must_use]
    pub fn into_parts(self) -> (ProductionVmLifecycleConfig, R) {
        (self.config, self.resources)
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Builds one fresh lifecycle under the exact admitted attempt guard.
    ///
    /// Exact-checkpoint resume is deliberately not accepted by this method. A
    /// resumed execution must use the exact-root realization path so a missing
    /// or unavailable root cannot silently become a fresh guest execution.
    /// Construction failure drops the installed generation owner, which
    /// transfers the guard to quarantine rather than releasing it without a
    /// complete lifecycle shutdown attestation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAttemptProductionVmLifecycleError`] when the context names
    /// an exact resume root, scenario identity or node bounds do not match, the
    /// resource guard cannot install the exact contract, or lifecycle
    /// construction fails.
    pub fn begin_fresh(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        context: &AttemptExecutionContext,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        self.begin_fresh_with_config(scenario, source, context, self.config.clone())
    }

    /// Builds one resumed lifecycle from an exact promoted version-four root.
    ///
    /// The campaign root is installed and completely authenticated before the
    /// attempt process guard exists. Only a closure whose every live snapshot
    /// carries source-bound matching replay evidence reaches the guarded
    /// multi-node launcher. Missing or invalid roots never fall back to fresh
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAttemptProductionVmLifecycleError`] when the context/root
    /// basis, scenario, branch prefix, replay evidence, resource contract, or
    /// guarded lifecycle construction is invalid or unavailable.
    // crucible-lint: allow rust-allow -- exact resume binds the store root, semantic start, scenario source, and operational context independently.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_resume(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        initial: &Configuration,
        post_selection: Option<&Configuration>,
        context: &AttemptExecutionContext,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        if context.resume_checkpoint() != Some(checkpoint) {
            return Err(
                QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(checkpoint),
            );
        }
        if source.scenario_def() != *scenario {
            return Err(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch);
        }
        let maximum_nodes = source.world().vm_nodes().len();
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(QemuAttemptProductionVmLifecycleError::InvalidNodeCount(
                maximum_nodes,
            ));
        }

        let installed = install_attempt_production_resume_checkpoint(
            checkpoints,
            checkpoint,
            source,
            initial,
            post_selection,
            self.config.run_state_root(),
            context.cancellation(),
        )
        .map_err(QemuAttemptProductionVmLifecycleError::CheckpointRestore)?;
        let config = production_lifecycle_config_for_start(
            &self.config,
            source,
            installed.configuration(),
            None,
        )?;
        let closure = installed.closure().identity();
        self.with_attempt_launcher(context, maximum_nodes, |launcher| {
            build_production_vm_lifecycle_loop_from_exact_closure_with_launcher(
                scenario, source, &config, closure, launcher,
            )
        })
    }

    fn begin_fresh_with_config(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        context: &AttemptExecutionContext,
        config: ProductionVmLifecycleConfig,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        if let Some(checkpoint) = context.resume_checkpoint() {
            return Err(
                QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(checkpoint),
            );
        }
        if source.scenario_def() != *scenario {
            return Err(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch);
        }
        let maximum_nodes = source.world().vm_nodes().len();
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(QemuAttemptProductionVmLifecycleError::InvalidNodeCount(
                maximum_nodes,
            ));
        }

        self.with_attempt_launcher(context, maximum_nodes, |launcher| {
            build_production_vm_lifecycle_loop_with_launcher(scenario, source, &config, launcher)
        })
    }

    fn with_attempt_launcher<T>(
        &mut self,
        context: &AttemptExecutionContext,
        maximum_nodes: usize,
        build: impl FnOnce(
            QemuAttemptProductionVmNodeLauncher<R::Guard>,
        ) -> Result<T, LifecycleApiError>,
    ) -> Result<T, QemuAttemptProductionVmLifecycleError> {
        let mut guard = self
            .resources
            .begin(context.resources(), context.cancellation().clone())
            .map_err(QemuAttemptProductionVmLifecycleError::ResourceInstallation)?;
        if guard.resource_limits() != context.resources()
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            guard
                .finish()
                .map_err(QemuAttemptProductionVmLifecycleError::ResourceContractCleanup)?;
            return Err(QemuAttemptProductionVmLifecycleError::ResourceContractMismatch);
        }

        let owner = QemuAttemptGenerationResourceOwner::new(guard, maximum_nodes)
            .map_err(QemuAttemptProductionVmLifecycleError::Lifecycle)?;
        build(QemuAttemptProductionVmNodeLauncher::new(owner))
            .map_err(QemuAttemptProductionVmLifecycleError::Lifecycle)
    }
}

impl<R> QemuFreshAttemptLifecycleFactory for QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Lifecycle = ProductionVmLifecycleLoop;
    type Error = QemuAttemptProductionVmLifecycleError;

    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let config = production_lifecycle_config_for_start(
            &self.config,
            source,
            start,
            Some(signal_fault_replay),
        )
        .map_err(AttemptWorkerFailure::Terminal)?;
        self.begin_fresh_with_config(scenario, source, context, config)
            .map_err(classify_production_lifecycle_failure)
    }
}

fn production_lifecycle_config_for_start(
    config: &ProductionVmLifecycleConfig,
    source: &ScenarioDefForm,
    start: &Configuration,
    signal_fault_replay: Option<&crucible::SignalFaultCampaignReplayPlan>,
) -> Result<ProductionVmLifecycleConfig, QemuAttemptProductionVmLifecycleError> {
    let (selections, plans) = app_random_branch_replay(start)
        .map_err(QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay)?;
    if plans.keys().any(|node| {
        !source
            .world()
            .vm_nodes()
            .iter()
            .any(|vm| vm.id == *node && vm.white_box == crucible::WhiteBoxPolicy::Enabled)
    }) {
        return Err(
            QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(String::from(
                "app-random branch plan names a missing or white-box-disabled VM",
            )),
        );
    }
    let mut config = config
        .clone()
        .with_app_random_branch_replay(selections, plans);
    if let Some(replay) = signal_fault_replay {
        if replay.target() != start {
            return Err(
                QemuAttemptProductionVmLifecycleError::InvalidSignalFaultBranchReplay(
                    String::from(
                        "signal-fault replay target differs from the admitted start configuration",
                    ),
                ),
            );
        }
        config = config.with_signal_fault_campaign_replay(replay.clone());
    }
    Ok(config)
}

impl<F, D> CrucibleExecutionRunner for QemuFreshExecutionRunner<F, D>
where
    F: QemuFreshAttemptLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    type Error = QemuFreshExecutionRunnerError<F::Error, D::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        if let Some(checkpoint) = context.resume_checkpoint() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ResumeCheckpointUnsupported(checkpoint),
            ));
        }
        let scenario = input.scenario().scenario_def();
        let start = match input.start() {
            crate::CrucibleResolvedAttemptStart::Discover { configuration } => configuration,
            crate::CrucibleResolvedAttemptStart::Branch { selected, .. } => selected,
        };
        if let Some(decision) =
            unsupported_fresh_replay_decision(start, input.signal_fault_replay())
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                    configuration: start.id(),
                    decision,
                },
            ));
        }
        let mut lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(
                &scenario,
                input.scenario(),
                start,
                input.signal_fault_replay(),
                context,
            )
            .map_err(map_fresh_lifecycle_failure)?;
        let materialization = materialize_fresh_start(&mut lifecycle, input, start, context);
        let driven = materialization.and_then(|materialization| {
            if input.attempt().stop() == &crucible_campaign::StopCondition::NextChoice {
                lifecycle.enable_signal_fault_campaign_promotion();
            }
            let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
            let outcome = self
                .driver
                .drive(&mut facade, input, context, materialization)
                .map_err(map_fresh_driver_failure)?;
            match outcome {
                QemuFreshDriveOutcome::Observation(pending) => {
                    Ok(QemuFreshRunnerResult::Observation(pending))
                }
                QemuFreshDriveOutcome::CheckpointRequested => {
                    if !context.checkpoint_request().is_requested() {
                        return Err(AttemptWorkerFailure::Terminal(
                            QemuFreshExecutionRunnerError::UnsolicitedCheckpoint,
                        ));
                    }
                    let capture = lifecycle
                        .capture_attempt_checkpoint(context)
                        .map_err(map_checkpoint_capture_failure)?;
                    context
                        .prepare_and_stage_checkpoint(capture)
                        .map(QemuFreshRunnerResult::Checkpoint)
                        .map_err(map_checkpoint_handoff_failure)
                }
            }
        });
        let cleanup = lifecycle.shutdown();

        let (pending, final_events) = match (driven, cleanup) {
            (Ok(pending), Ok(events)) => (pending, events),
            (Err(failure), Ok(_events)) => return Err(failure),
            (Ok(_pending), Err(cleanup)) => {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::Cleanup(cleanup),
                ));
            }
            (Err(failure), Err(cleanup)) => {
                return Err(AttemptWorkerFailure::Terminal(
                    cleanup_after_fresh_runner_failure(failure, cleanup),
                ));
            }
        };
        let product = match pending {
            QemuFreshRunnerResult::Observation(pending) => self
                .driver
                .seal(pending, final_events)
                .map_err(map_fresh_driver_failure)?,
            QemuFreshRunnerResult::Checkpoint(checkpoint) => {
                AttemptExecutionProduct::exact_checkpoint(checkpoint)
            }
        };
        Ok(CrucibleExecutionOutcome::new(
            product,
            CrucibleMaterializationTier::ThinReplay,
        ))
    }
}

fn unsupported_fresh_replay_decision(
    target: &Configuration,
    signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
) -> Option<usize> {
    if signal_fault_replay.target() != target {
        return Some(0);
    }
    let covered_signal_fault_overrides = signal_fault_replay
        .branches()
        .iter()
        .filter(|branch| branch.decisions().len() == 2)
        .map(|branch| branch.parent().schedule.len() + 1)
        .collect::<BTreeSet<_>>();
    target
        .schedule
        .decisions()
        .iter()
        .enumerate()
        .find_map(|(index, decision)| match decision {
            Decision::Override(_) if covered_signal_fault_overrides.contains(&index) => None,
            Decision::Override(_) | Decision::AppRandom(_) => Some(index),
            Decision::Selection(selection) => selection
                .selection()
                .map_or(true, |decoded| {
                    matches!(decoded.origin(), SelectionOrigin::ModelSample(_))
                        && !selection.is_app_random_model_sample()
                })
                .then_some(index),
            Decision::DeliveryOrder(_) | Decision::RngDraw(_) | Decision::Preemption(_) => None,
        })
}

fn materialize_fresh_start<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    target: &Configuration,
    context: &AttemptExecutionContext,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let mut replay = QemuFreshStartMaterialization::genesis();
    let mut current = Configuration::genesis(target.def.clone());
    if current == *target {
        return Ok(replay);
    }

    for _ in 0..context.resources().maximum_execution_quanta() {
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Canceled),
            ));
        }
        let prior_len = current.schedule.len();
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: current,
                control: Vec::new(),
            })
            .map_err(map_start_replay_scheduler_failure)?;
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Canceled),
            ));
        }

        let mut next = outcome.configuration;
        let next_len = next.schedule.len();
        if next.def != target.def
            || next_len < prior_len
            || next_len > target.schedule.len()
            || next.schedule.decisions()[prior_len..]
                != target.schedule.decisions()[prior_len..next_len]
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Diverged),
            ));
        }
        let terminal = lifecycle.terminal_verdict_for_stop();
        if terminal.is_none() {
            apply_replayed_guest_selectables(
                lifecycle,
                input.lineage().scenario(),
                input.scenario(),
                target,
                &mut next,
            )?;
        }

        append_start_replay_events(&mut replay, &outcome.event_log_entries)?;
        replay.terminal_quiescence = outcome.scheduler_quiescence;
        current = next;
        if current == *target {
            replay.terminal_verdict = terminal;
            return Ok(replay);
        }
        if terminal.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
            ));
        }
    }

    Err(AttemptWorkerFailure::Terminal(
        QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::QuantumLimit),
    ))
}

fn apply_replayed_guest_selectables<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    scenario: crucible_campaign::ScenarioDefId,
    source: &ScenarioDefForm,
    target: &Configuration,
    current: &mut Configuration,
) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    let pending = lifecycle
        .drain_pending_selectable_requests()
        .map_err(map_start_replay_scheduler_failure)?;
    let mut replayed = current.clone();
    let mut replies = Vec::with_capacity(pending.len());
    for pending in pending {
        let discovery =
            resolve_guest_selectable(scenario, source, pending.node(), pending.pending())
                .map_err(start_replay_guest_selectable_failure)?;
        let Some(Decision::Selection(decision)) =
            target.schedule.decisions().get(replayed.schedule.len())
        else {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Diverged),
            ));
        };
        let selection = decision
            .selection()
            .map_err(GuestSelectableError::Campaign)
            .map_err(start_replay_guest_selectable_failure)?;
        match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(discovery.opportunity(), discovery.domain())
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent =
                    ConfigurationId::from_hash(CampaignHash::from_bytes(replayed.id().bytes));
                selection.validate_branch_replay(
                    discovery.opportunity(),
                    discovery.domain(),
                    discovery.opportunity().branch_point_id(parent),
                )
            }
            SelectionOrigin::ModelSample(_) => {
                Err(crucible_campaign::CampaignCodecError::InvalidValue {
                    reason: "guest selectable replay does not admit model-sample provenance",
                })
            }
        }
        .map_err(GuestSelectableError::Campaign)
        .map_err(start_replay_guest_selectable_failure)?;
        let reply = selected_guest_reply(pending.pending(), &discovery, &selection)
            .map_err(start_replay_guest_selectable_failure)?;
        replies.push((pending, reply));
        replayed = crucible::step(&replayed, Decision::Selection(decision.clone()));
    }
    for (pending, reply) in replies {
        lifecycle
            .enqueue_selectable_reply(&pending, &reply)
            .map_err(map_start_replay_scheduler_failure)?;
    }
    *current = replayed;
    Ok(())
}

fn start_replay_guest_selectable_failure<F, D>(
    error: GuestSelectableError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(error),
    ))
}

fn append_start_replay_events<F, D>(
    replay: &mut QemuFreshStartMaterialization,
    entries: &[SchedulerEventLogEntry],
) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    let count = replay
        .event_log
        .len()
        .checked_add(entries.len())
        .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-entry-count"))?;
    if count > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::LimitExceeded {
                limit: "fresh-campaign-event-log-entry-count",
            }),
        ));
    }
    let added = entries.iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.canonical_material_len())
            .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-bytes"))
    })?;
    let bytes = replay
        .event_log_bytes
        .checked_add(added)
        .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-bytes"))?;
    if bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            }),
        ));
    }
    replay.event_log.extend_from_slice(entries);
    replay.event_log_bytes = bytes;
    Ok(())
}

fn start_replay_limit_failure<F, D>(
    limit: &'static str,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::LimitExceeded { limit },
    ))
}

fn map_start_replay_scheduler_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error =
        QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Scheduler(error));
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_checkpoint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuFreshExecutionRunnerError::CheckpointCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_checkpoint_handoff_failure<F, D>(
    failure: AttemptWorkerFailure<CheckpointHandoffFailure>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
    }
}

pub(crate) fn classify_production_lifecycle_failure(
    error: QemuAttemptProductionVmLifecycleError,
) -> AttemptWorkerFailure<QemuAttemptProductionVmLifecycleError> {
    match &error {
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::StoreUnavailable { .. }
            | QemuVmRealizationError::ExecutorUnavailable { .. },
        ) => AttemptWorkerFailure::Retryable(error),
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::Canceled { .. },
        )
        | QemuAttemptProductionVmLifecycleError::CheckpointRestore(
            ProductionAttemptCheckpointRestoreError::Canceled,
        ) => AttemptWorkerFailure::Canceled(error),
        QemuAttemptProductionVmLifecycleError::CheckpointRestore(
            ProductionAttemptCheckpointRestoreError::Checkpoint(ExactCheckpointStoreError::Store(
                StoreError::NotFound { .. }
                | StoreError::Unavailable
                | StoreError::Io { .. }
                | StoreError::StreamIo { .. },
            )),
        ) => AttemptWorkerFailure::Retryable(error),
        QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(_)
        | QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch
        | QemuAttemptProductionVmLifecycleError::InvalidNodeCount(_)
        | QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::InvalidSignalFaultBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::ResourceInstallation(_)
        | QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
        | QemuAttemptProductionVmLifecycleError::ResourceContractCleanup(_)
        | QemuAttemptProductionVmLifecycleError::Lifecycle(_)
        | QemuAttemptProductionVmLifecycleError::CheckpointRestore(_) => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_fresh_lifecycle_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
    }
}

fn map_fresh_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error))
        }
    }
}

fn cleanup_after_fresh_runner_failure<F, D>(
    failure: AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
    cleanup: SchedulerError,
) -> QemuFreshExecutionRunnerError<F, D> {
    let driver = match failure {
        AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error)) => error,
        AttemptWorkerFailure::Retryable(error)
        | AttemptWorkerFailure::Canceled(error)
        | AttemptWorkerFailure::Terminal(error) => {
            return QemuFreshExecutionRunnerError::CleanupAfterRunner {
                failure: Box::new(error),
                cleanup,
            };
        }
    };
    QemuFreshExecutionRunnerError::CleanupAfterDriver { driver, cleanup }
}

#[cfg(test)]
mod tests;
