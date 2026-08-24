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

use crucible::{
    Configuration, Decision, QuantumLoop, QuantumOutcome, QuantumRequest, QuantumTerminalVerdict,
    ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerEventLogEntry,
    SchedulerOperationalFailureClass, SchedulerQuiescence,
};
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig,
    ProductionVmLifecycleLoop, build_production_vm_lifecycle_loop_with_launcher,
};
use crucible_campaign::ExactCheckpointId;
use crucible_qemu::QemuVmRealizationError;
use thiserror::Error;

use crate::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure,
    CrucibleAttemptExecution, CrucibleExecutionOutcome, CrucibleExecutionRunner,
    CrucibleMaterializationTier, MAX_QEMU_ATTEMPT_GENERATION_NODES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES, MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
    QemuAttemptGenerationResourceOwner, QemuAttemptOperationalBoundary,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmNodeLauncher, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory,
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
    /// The resolved start configuration does not form an executable branch plan.
    #[error("derive exact app-random branch replay: {0}")]
    InvalidAppRandomBranchReplay(String),
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
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        QuantumLoop::drive_quantum(self, request)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        QuantumLoop::terminal_verdict_for_stop(self)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        ProductionVmLifecycleLoop::exact_checkpoint_ready(self)
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
    ) -> Result<Self::Pending, AttemptWorkerFailure<Self::Error>>;

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
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let (selections, plans) = app_random_branch_replay(start).map_err(|message| {
            AttemptWorkerFailure::Terminal(
                QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(message),
            )
        })?;
        if plans.keys().any(|node| {
            !source
                .world()
                .vm_nodes()
                .iter()
                .any(|vm| vm.id == *node && vm.white_box == crucible::WhiteBoxPolicy::Enabled)
        }) {
            return Err(AttemptWorkerFailure::Terminal(
                QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(String::from(
                    "app-random branch plan names a missing or white-box-disabled VM",
                )),
            ));
        }
        let config = self
            .config
            .clone()
            .with_app_random_branch_replay(selections, plans);
        self.begin_fresh_with_config(scenario, source, context, config)
            .map_err(classify_production_lifecycle_failure)
    }
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
        if let Some(decision) = unsupported_fresh_replay_decision(start) {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                    configuration: start.id(),
                    decision,
                },
            ));
        }
        let mut lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(&scenario, input.scenario(), start, context)
            .map_err(map_fresh_lifecycle_failure)?;
        let materialization = materialize_fresh_start(&mut lifecycle, start, context);
        let driven = materialization.and_then(|materialization| {
            let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
            self.driver
                .drive(&mut facade, input, context, materialization)
                .map_err(map_fresh_driver_failure)
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
        let product = self
            .driver
            .seal(pending, final_events)
            .map_err(map_fresh_driver_failure)?;
        Ok(CrucibleExecutionOutcome::new(
            product,
            CrucibleMaterializationTier::ThinReplay,
        ))
    }
}

fn unsupported_fresh_replay_decision(target: &Configuration) -> Option<usize> {
    target
        .schedule
        .decisions()
        .iter()
        .position(|decision| match decision {
            Decision::Override(_) | Decision::AppRandom(_) => true,
            Decision::Selection(selection) => {
                !selection.is_app_random_model_sample() && !selection.is_campaign_branch()
            }
            Decision::DeliveryOrder(_) | Decision::RngDraw(_) | Decision::Preemption(_) => false,
        })
}

fn materialize_fresh_start<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
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

        let next = &outcome.configuration;
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

        append_start_replay_events(&mut replay, &outcome.event_log_entries)?;
        replay.terminal_quiescence = outcome.scheduler_quiescence;
        current = outcome.configuration;
        let terminal = lifecycle.terminal_verdict_for_stop();
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

fn classify_production_lifecycle_failure(
    error: QemuAttemptProductionVmLifecycleError,
) -> AttemptWorkerFailure<QemuAttemptProductionVmLifecycleError> {
    match &error {
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::StoreUnavailable { .. }
            | QemuVmRealizationError::ExecutorUnavailable { .. },
        ) => AttemptWorkerFailure::Retryable(error),
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::Canceled { .. },
        ) => AttemptWorkerFailure::Canceled(error),
        QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(_)
        | QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch
        | QemuAttemptProductionVmLifecycleError::InvalidNodeCount(_)
        | QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::ResourceInstallation(_)
        | QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
        | QemuAttemptProductionVmLifecycleError::ResourceContractCleanup(_)
        | QemuAttemptProductionVmLifecycleError::Lifecycle(_) => {
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
