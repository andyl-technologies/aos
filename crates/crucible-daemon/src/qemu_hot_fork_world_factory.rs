//! Whole-world retained-source selection, launch, execution, and recovery.
//!
//! The production factory checks out one complete prepared source world before
//! installing target resources, launches every running node into one atomic
//! assembly, and hands only the complete assembly to the production lifecycle
//! installer. The runner starts from the captured scheduler boundary, performs
//! ordinary modeled execution, shuts down every adopted node, and retains the
//! source and aggregate target authorities until durable publication.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// crucible-lint: allow host-nondeterminism-state -- The factory authenticates and forwards an unchanged captured scheduler continuation; operational source availability cannot mutate it.
use crucible::{Configuration, ContentHash, ScenarioDef, SchedulerError};
use crucible_api::{
    ProductionVmHotForkNodeServiceState, ProductionVmHotForkSourceWorld, ProductionVmNodeGeneration,
};
use crucible_qemu::{
    LinuxQemuHotForkChildProcessAuthority, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuHotForkChildProcessOwner, QemuShutdownPolicy, QemuVmRealizationError,
};

use crate::qemu_campaign_lifecycle::{
    QemuFreshScenarioResourceError, validate_fresh_qemu_scenario_resources,
};
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionDisposition,
    AttemptExecutionProduct, AttemptExecutionReconciliationStep, AttemptWorkerFailure,
    CheckpointHandoffFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleMaterializationTier, LinuxQemuHotForkReconciliationBackend,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory, QemuFreshAttemptDriver, QemuFreshAttemptLifecycle,
    QemuFreshAttemptLifecycleOwner, QemuFreshDriveOutcome, QemuHotForkAttemptReconciliation,
    QemuHotForkWorldAssembly, QemuHotForkWorldNodeTarget, QemuHotForkWorldResourceOwner,
    QemuProductionHotForkWorldLifecycle,
};

/// Checked-out source-world storage used by the production hot-fork factory.
pub trait QemuHotForkSourceWorldProvider {
    /// Provider-specific checkout failure.
    type Error;

    /// Removes an exact source world from reusable storage when one is available.
    ///
    /// # Errors
    ///
    /// Returns an availability failure without removing a source world.
    fn checkout(
        &mut self,
        scenario: ContentHash,
        configuration: ContentHash,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error>;

    /// Returns a completely reconciled source world to reusable storage.
    fn restore(&mut self, source: ProductionVmHotForkSourceWorld);
}

/// One exact prepared source world used until managed pooling is installed.
#[must_use = "retain the prepared source world for hot-fork execution"]
pub struct QemuSingleHotForkSourceWorldProvider {
    source: Option<ProductionVmHotForkSourceWorld>,
}

impl QemuSingleHotForkSourceWorldProvider {
    /// Creates a provider owning one complete prepared source world.
    pub const fn new(source: ProductionVmHotForkSourceWorld) -> Self {
        Self {
            source: Some(source),
        }
    }

    /// Returns whether the exact source world is currently reusable.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.source.is_some()
    }
}

impl QemuHotForkSourceWorldProvider for QemuSingleHotForkSourceWorldProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        scenario: ContentHash,
        configuration: ContentHash,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        let compatible = self.source.as_ref().is_some_and(|source| {
            source.continuation().configuration().def.id() == scenario
                && source.continuation().configuration().id() == configuration
        });
        Ok(compatible.then(|| self.source.take()).flatten())
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        if self.source.is_some() {
            let _retained_for_process_lifetime = Box::leak(Box::new(source));
            return;
        }
        match source.into_reusable() {
            Ok(source) => self.source = Some(source),
            Err(failure) => {
                let _retained_for_process_lifetime = Box::leak(Box::new(failure));
            }
        }
    }
}

/// Source provider used when the packaged executor has no retained world yet.
#[derive(Clone, Copy, Debug, Default)]
pub struct QemuUnavailableHotForkSourceWorldProvider;

impl QemuHotForkSourceWorldProvider for QemuUnavailableHotForkSourceWorldProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        _scenario: ContentHash,
        _configuration: ContentHash,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        Ok(None)
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        let _retained_for_process_lifetime = Box::leak(Box::new(source));
    }
}

/// Result of attempting retained-source lifecycle construction.
pub enum QemuHotForkWorldLifecycleStart<L> {
    /// The exact source world is unavailable or requires another capability.
    Declined,
    /// A complete adopted production lifecycle is ready at the requested start.
    Started(L),
}

/// Factory boundary used by the whole-world execution runner.
pub trait QemuHotForkWorldLifecycleFactory {
    /// Whole-world lifecycle retained through semantic reconciliation.
    type Lifecycle: QemuHotForkWorldLifecycleOwner;
    /// Provider, resource, launch, or lifecycle-construction failure.
    type Error;

    /// Tries to construct an exact hot-fork lifecycle for one attempt.
    ///
    /// # Errors
    ///
    /// Returns a classified failure only after every created child authority was
    /// retained by the returned lifecycle or transferred to quarantine.
    fn try_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>;

    /// Restores the source from a completely reconciled lifecycle.
    ///
    /// # Errors
    ///
    /// Returns the lifecycle with all live process and resource ownership when
    /// complete source ownership cannot be recovered. Reaped modeled-channel
    /// loans may already have been released after final reconciliation.
    fn recover(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle>;

    /// Transfers an incomplete lifecycle to process-lifetime quarantine.
    fn quarantine(&mut self, lifecycle: Self::Lifecycle);
}

/// Runner-owned operations beyond ordinary modeled lifecycle execution.
pub trait QemuHotForkWorldLifecycleOwner: QemuFreshAttemptLifecycleOwner + Sized {
    /// Returns the exact supervisor execution incarnation.
    #[must_use]
    fn runtime_basis(&self) -> crate::AttemptExecutionRuntimeBasis;

    /// Projects the already-materialized start boundary.
    ///
    /// # Errors
    ///
    /// Returns a scheduler error when complete start evidence is unavailable.
    fn start_materialization(&self)
    -> Result<crate::QemuFreshStartMaterialization, SchedulerError>;

    /// Advances one bounded post-publication reconciliation operation.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle error while retaining retry or quarantine authority.
    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, crucible_api::LifecycleApiError>;

    /// Transfers owned operational authority to fail-closed quarantine.
    fn quarantine(&mut self);
}

impl<G> QemuHotForkWorldLifecycleOwner for QemuProductionHotForkWorldLifecycle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn runtime_basis(&self) -> crate::AttemptExecutionRuntimeBasis {
        QemuProductionHotForkWorldLifecycle::runtime_basis(self)
    }

    fn start_materialization(
        &self,
    ) -> Result<crate::QemuFreshStartMaterialization, SchedulerError> {
        QemuProductionHotForkWorldLifecycle::start_materialization(self)
    }

    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, crucible_api::LifecycleApiError> {
        QemuProductionHotForkWorldLifecycle::reconcile_execution_disposition(self, disposition)
    }

    fn quarantine(&mut self) {
        QemuProductionHotForkWorldLifecycle::quarantine(self);
    }
}

/// Concrete source-world and target-resource lifecycle factory.
pub struct QemuProductionHotForkWorldLifecycleFactory<S, R> {
    sources: S,
    resources: R,
    run_state_root: PathBuf,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
}

impl<S, R> QemuProductionHotForkWorldLifecycleFactory<S, R> {
    /// Creates a production whole-world factory from its linear authorities.
    #[must_use]
    pub fn new(
        sources: S,
        resources: R,
        run_state_root: impl Into<PathBuf>,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
    ) -> Self {
        Self {
            sources,
            resources,
            run_state_root: run_state_root.into(),
            shutdown_policy,
            async_policy,
        }
    }

    /// Returns the retained source provider.
    #[must_use]
    pub const fn sources(&self) -> &S {
        &self.sources
    }
}

/// Failure while constructing one complete production hot-fork world.
#[derive(Debug, thiserror::Error)]
pub enum QemuProductionHotForkWorldLifecycleFactoryError<P> {
    /// The source provider could not complete exact checkout.
    #[error("check out production hot-fork source world")]
    SourceProvider(P),
    /// The supervisor omitted its exact runtime incarnation.
    #[error("production hot-fork world requires an exact worker runtime basis")]
    MissingRuntimeBasis,
    /// The complete target World exceeds the admitted attempt resources.
    #[error("admit production hot-fork target World resources: {0}")]
    ScenarioResources(#[source] QemuFreshScenarioResourceError),
    /// The target resource guard could not be installed.
    #[error("install production hot-fork target resources: {0}")]
    Resource(#[source] QemuVmRealizationError),
    /// The installed guard differs from the admitted attempt contract.
    #[error("production hot-fork target guard differs from the admitted attempt contract")]
    ResourceContractMismatch,
    /// The checked-out source contradicted its exact configuration or roster.
    #[error("authenticate production hot-fork source world: {0}")]
    Source(String),
    /// One child launch or atomic assembly phase failed.
    #[error("assemble production hot-fork child world: {0}")]
    Assembly(String),
    /// The complete child world could not enter the production lifecycle.
    #[error("install production hot-fork lifecycle: {0}")]
    Lifecycle(#[source] crucible_api::LifecycleApiError),
}

type ProductionAssembly<G> = QemuHotForkWorldAssembly<
    QemuHotForkAttemptReconciliation<
        LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
    >,
>;

type ProductionLifecycleStartResult<G, P> = Result<
    QemuHotForkWorldLifecycleStart<QemuProductionHotForkWorldLifecycle<G>>,
    AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<P>>,
>;

impl<S, R> QemuHotForkWorldLifecycleFactory for QemuProductionHotForkWorldLifecycleFactory<S, R>
where
    S: QemuHotForkSourceWorldProvider,
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    type Lifecycle = QemuProductionHotForkWorldLifecycle<R::Guard>;
    type Error = QemuProductionHotForkWorldLifecycleFactoryError<S::Error>;

    fn try_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        let runtime_basis = context
            .runtime_basis()
            .ok_or_else(|| AttemptWorkerFailure::Terminal(Self::Error::MissingRuntimeBasis))?;
        validate_fresh_qemu_scenario_resources(input.scenario(), context.resources()).map_err(
            |error| AttemptWorkerFailure::Terminal(Self::Error::ScenarioResources(error)),
        )?;
        let scenario = input.scenario().scenario_def();
        let start = execution_start(input);
        let Some(mut source_world) = self
            .sources
            .checkout(scenario.id(), start.id())
            .map_err(|error| AttemptWorkerFailure::Retryable(Self::Error::SourceProvider(error)))?
        else {
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        };
        let source_matches = source_world.continuation().configuration().def.id() == scenario.id()
            && source_world.continuation().configuration().id() == start.id();
        if !source_matches {
            self.sources.restore(source_world);
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        }
        if source_world.continuation().nodes().iter().any(|boundary| {
            boundary.service_state() == ProductionVmHotForkNodeServiceState::PoweredOff
        }) {
            self.sources.restore(source_world);
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        }
        let continuation = match source_world.fork_continuation() {
            Ok(continuation) => continuation,
            Err(error) => {
                self.sources.restore(source_world);
                return Err(AttemptWorkerFailure::Retryable(Self::Error::Source(
                    error.to_string(),
                )));
            }
        };
        let mut guard = match self
            .resources
            .begin(context.resources(), context.cancellation().clone())
        {
            Ok(guard) => guard,
            Err(error) => {
                self.sources.restore(source_world);
                return Err(AttemptWorkerFailure::Retryable(Self::Error::Resource(
                    error,
                )));
            }
        };
        if guard.resource_limits() != context.resources()
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            guard.quarantine();
            self.sources.restore(source_world);
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::ResourceContractMismatch,
            ));
        }
        let maximum_nodes = input.scenario().world().vm_nodes().len();
        let resources = match QemuHotForkWorldResourceOwner::new(guard, maximum_nodes) {
            Ok(resources) => resources,
            Err(error) => {
                self.sources.restore(source_world);
                return Err(AttemptWorkerFailure::Terminal(Self::Error::Resource(error)));
            }
        };
        let source_world = Arc::new(Mutex::new(source_world));
        self.launch_complete_world(
            input,
            context,
            scenario,
            source_world,
            continuation,
            resources,
            runtime_basis,
        )
    }

    fn recover(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        match lifecycle.into_source_world() {
            Ok(source) => {
                self.sources.restore(source);
                Ok(())
            }
            Err(lifecycle) => Err(*lifecycle),
        }
    }

    fn quarantine(&mut self, mut lifecycle: Self::Lifecycle) {
        lifecycle.quarantine();
        let _retained_for_process_lifetime = Box::leak(Box::new(lifecycle));
    }
}

impl<S, R> QemuProductionHotForkWorldLifecycleFactory<S, R>
where
    S: QemuHotForkSourceWorldProvider,
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    // crucible-lint: allow rust-allow -- the transaction inputs remain explicit at the sole whole-world launch boundary.
    #[allow(clippy::too_many_arguments)]
    fn launch_complete_world(
        &mut self,
        input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        scenario: ScenarioDef,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        continuation: crucible_api::ProductionVmHotForkWorldContinuation,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        runtime_basis: crate::AttemptExecutionRuntimeBasis,
    ) -> ProductionLifecycleStartResult<R::Guard, S::Error> {
        let boundaries = continuation
            .nodes()
            .iter()
            .map(|boundary| {
                (
                    boundary.node().clone(),
                    (boundary.service_state(), boundary.generation()),
                )
            })
            .collect::<Vec<_>>();
        let mut assembly = QemuHotForkWorldAssembly::new(continuation);
        for (node, (service_state, generation)) in boundaries {
            match service_state {
                ProductionVmHotForkNodeServiceState::PermanentlyFailed => continue,
                ProductionVmHotForkNodeServiceState::PoweredOff => {
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return Err(AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Source(String::from(
                            "powered-off node passed the capability fallback boundary",
                        )),
                    ));
                }
                ProductionVmHotForkNodeServiceState::Running => {}
            }
            let child_generation = match generation.checked_add(1) {
                Some(generation) => generation,
                None => {
                    let message = format!("source generation for `{}` cannot advance", node.name);
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return Err(AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Source(message),
                    ));
                }
            };
            let identity = match ProductionVmNodeGeneration::new(node.clone(), child_generation) {
                Ok(identity) => identity,
                Err(error) => {
                    let message = error.to_string();
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return Err(AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Source(message),
                    ));
                }
            };
            let child = match QemuHotForkAttemptReconciliation::launch_from_source_world(
                runtime_basis,
                input,
                Arc::clone(&source_world),
                node.clone(),
                &mut resources,
                identity,
                assembly.child_launch_token(),
            ) {
                Ok(child) => child,
                Err(error) => {
                    let message = error.to_string();
                    drop(error);
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return Err(AttemptWorkerFailure::Retryable(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                    ));
                }
            };
            let mut child = child;
            if let Err(error) = child.admit_child() {
                let message = error.to_string();
                quarantine_failed_assembly(source_world, resources, assembly, Some(child));
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                ));
            }
            if let Err(error) = child.install_scheduler_node(
                node.clone(),
                self.shutdown_policy,
                self.async_policy,
                QemuCrashDetector::new(node.name.clone()),
            ) {
                let message = error.to_string();
                quarantine_failed_assembly(source_world, resources, assembly, Some(child));
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                ));
            }
            if let Err(error) = assembly.admit_child(node, child) {
                let message = error.to_string();
                let (_node, child, _failure) = error.into_parts();
                quarantine_failed_assembly(source_world, resources, assembly, Some(child));
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                ));
            }
        }
        let complete = match assembly.publish() {
            Ok(complete) => complete,
            Err(incomplete) => {
                let message = incomplete.to_string();
                let assembly = incomplete.into_assembly();
                quarantine_failed_assembly(source_world, resources, assembly, None);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                ));
            }
        };
        let lifecycle = complete
            .install_production_lifecycle(
                &scenario,
                input.scenario(),
                source_world,
                runtime_basis,
                self.run_state_root.clone(),
                resources,
            )
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(error),
                )
            })?;
        Ok(QemuHotForkWorldLifecycleStart::Started(lifecycle))
    }
}

struct QuarantinedHotForkWorld<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    _source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    _resources: QemuHotForkWorldResourceOwner<G>,
    _assembly: ProductionAssembly<G>,
}

fn quarantine_failed_assembly<G>(
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    mut resources: QemuHotForkWorldResourceOwner<G>,
    mut assembly: ProductionAssembly<G>,
    child: Option<
        QemuHotForkAttemptReconciliation<
            LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
        >,
    >,
) where
    G: QemuAttemptProcessResourceGuard + Send + 'static,
{
    if let Some(mut child) = child {
        child.quarantine();
        let _retained_child = Box::leak(Box::new(child));
    }
    assembly.quarantine();
    resources.quarantine();
    let quarantine = QuarantinedHotForkWorld {
        _source_world: source_world,
        _resources: resources,
        _assembly: assembly,
    };
    let _retained_for_process_lifetime = Box::leak(Box::new(quarantine));
}

fn execution_start(input: &CrucibleAttemptExecution) -> &Configuration {
    match input.start() {
        crate::CrucibleResolvedAttemptStart::Discover { configuration } => configuration,
        crate::CrucibleResolvedAttemptStart::Branch { selected, .. } => selected,
    }
}

/// Whole-world runner result before durable publication reconciliation.
pub enum QemuHotForkWorldExecutionAttempt {
    /// No exact retained source was available; a lower tier may run.
    Declined,
    /// The retained source produced a complete candidate.
    Executed(CrucibleExecutionOutcome),
}

/// Production whole-world runner with publication-ordered source recovery.
pub struct QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    factory: F,
    driver: D,
    pending: Option<F::Lifecycle>,
}

impl<F, D> QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    /// Creates a whole-world runner from its lifecycle factory and modeled driver.
    #[must_use]
    pub const fn new(factory: F, driver: D) -> Self {
        Self {
            factory,
            driver,
            pending: None,
        }
    }

    /// Returns the whole-world lifecycle factory.
    #[must_use]
    pub const fn lifecycle_factory(&self) -> &F {
        &self.factory
    }
}

/// Failure from one production whole-world execution phase.
#[derive(Debug, thiserror::Error)]
pub enum QemuHotForkWorldExecutionRunnerError<F, D> {
    /// A prior successful execution still owns publication authority.
    #[error("hot-fork world still awaits prior semantic reconciliation")]
    PriorReconciliationPending,
    /// The lifecycle factory failed after exact source selection.
    #[error("construct production hot-fork world lifecycle")]
    Factory(F),
    /// The factory returned a lifecycle for another supervisor incarnation.
    #[error("production hot-fork world runtime basis differs from its worker reservation")]
    RuntimeBasisMismatch,
    /// The adopted start boundary could not be reconstructed exactly.
    #[error("materialize production hot-fork start: {0}")]
    Start(#[source] SchedulerError),
    /// Modeled driving or result construction failed.
    #[error("drive production hot-fork world")]
    Driver(D),
    /// A checkpoint result lacked a sticky supervisor request.
    #[error("production hot-fork driver returned an unsolicited checkpoint")]
    UnsolicitedCheckpoint,
    /// Capturing a later exact checkpoint failed.
    #[error("capture production hot-fork checkpoint: {0}")]
    CheckpointCapture(#[source] SchedulerError),
    /// Durable checkpoint handoff failed.
    #[error("handoff production hot-fork checkpoint: {0}")]
    CheckpointHandoff(#[source] CheckpointHandoffFailure),
    /// Final drain or adopted-node cleanup failed.
    #[error("clean up production hot-fork world: {0}")]
    Cleanup(#[source] SchedulerError),
    /// Cleanup failed after an earlier runner phase failed.
    #[error("production hot-fork cleanup failed after `{failure}`: {cleanup}")]
    CleanupAfterRunner {
        /// Earlier runner failure.
        failure: Box<QemuHotForkWorldExecutionRunnerError<F, D>>,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
    /// Durable publication reconciliation failed.
    #[error("reconcile production hot-fork publication: {0}")]
    Reconciliation(#[source] crucible_api::LifecycleApiError),
    /// A reconciliation callback arrived without pending authority.
    #[error("production hot-fork runner has no pending reconciliation")]
    NoPendingReconciliation,
    /// Complete source-world recovery contradicted lifecycle ownership.
    #[error("recover production hot-fork source world")]
    SourceRecovery,
}

type HotForkWorldRunnerFailure<F, D> = AttemptWorkerFailure<
    QemuHotForkWorldExecutionRunnerError<
        <F as QemuHotForkWorldLifecycleFactory>::Error,
        <D as QemuFreshAttemptDriver>::Error,
    >,
>;

enum HotForkRunnerResult<P> {
    Observation(P),
    Checkpoint(AttemptCheckpointResult),
}

impl<F, D> QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    /// Tries exact hot-fork execution without hiding a capability decline.
    ///
    /// # Errors
    ///
    /// Returns a classified failure after factory, modeled, cleanup, or source
    /// ownership failure. A returned error leaves no droppable live authority.
    pub fn try_execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldExecutionAttempt, HotForkWorldRunnerFailure<F, D>> {
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotForkWorldExecutionRunnerError::PriorReconciliationPending,
            ));
        }
        let mut lifecycle = match self
            .factory
            .try_start(input, context)
            .map_err(map_hot_fork_factory_failure)?
        {
            QemuHotForkWorldLifecycleStart::Declined => {
                return Ok(QemuHotForkWorldExecutionAttempt::Declined);
            }
            QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        };
        if context.runtime_basis() != Some(lifecycle.runtime_basis()) {
            self.factory.quarantine(lifecycle);
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotForkWorldExecutionRunnerError::RuntimeBasisMismatch,
            ));
        }
        let driven = lifecycle
            .start_materialization()
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(QemuHotForkWorldExecutionRunnerError::Start(error))
            })
            .and_then(|materialization| {
                if input.attempt().stop() == &crucible_campaign::StopCondition::NextChoice {
                    lifecycle.enable_signal_fault_campaign_promotion();
                }
                let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
                match self
                    .driver
                    .drive(&mut facade, input, context, materialization)
                    .map_err(map_hot_fork_driver_failure)?
                {
                    QemuFreshDriveOutcome::Observation(pending) => {
                        Ok(HotForkRunnerResult::Observation(pending))
                    }
                    QemuFreshDriveOutcome::CheckpointRequested => {
                        if !context.checkpoint_request().is_requested() {
                            return Err(AttemptWorkerFailure::Terminal(
                                QemuHotForkWorldExecutionRunnerError::UnsolicitedCheckpoint,
                            ));
                        }
                        let capture =
                            lifecycle
                                .capture_attempt_checkpoint(context)
                                .map_err(|error| {
                                    AttemptWorkerFailure::Terminal(
                                        QemuHotForkWorldExecutionRunnerError::CheckpointCapture(
                                            error,
                                        ),
                                    )
                                })?;
                        context
                            .prepare_and_stage_checkpoint(capture)
                            .map(HotForkRunnerResult::Checkpoint)
                            .map_err(map_hot_fork_checkpoint_handoff_failure)
                    }
                }
            });
        let cleanup = lifecycle.shutdown();
        let (pending, final_events) = match (driven, cleanup) {
            (Ok(pending), Ok(events)) => (pending, events),
            (Err(failure), Ok(_)) => {
                self.factory.quarantine(lifecycle);
                return Err(failure);
            }
            (Ok(_), Err(cleanup)) => {
                self.factory.quarantine(lifecycle);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuHotForkWorldExecutionRunnerError::Cleanup(cleanup),
                ));
            }
            (Err(failure), Err(cleanup)) => {
                self.factory.quarantine(lifecycle);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuHotForkWorldExecutionRunnerError::CleanupAfterRunner {
                        failure: Box::new(failure.into_error()),
                        cleanup,
                    },
                ));
            }
        };
        let product = match pending {
            HotForkRunnerResult::Observation(pending) => {
                match self.driver.seal(pending, final_events) {
                    Ok(product) => product,
                    Err(failure) => {
                        self.factory.quarantine(lifecycle);
                        return Err(map_hot_fork_driver_failure(failure));
                    }
                }
            }
            HotForkRunnerResult::Checkpoint(checkpoint) => {
                AttemptExecutionProduct::exact_checkpoint(checkpoint)
            }
        };
        self.pending = Some(lifecycle);
        Ok(QemuHotForkWorldExecutionAttempt::Executed(
            CrucibleExecutionOutcome::new(product, CrucibleMaterializationTier::HotFork),
        ))
    }

    /// Reconciles one bounded publication phase for the pending child world.
    pub fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, HotForkWorldRunnerFailure<F, D>> {
        let Some(mut lifecycle) = self.pending.take() else {
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotForkWorldExecutionRunnerError::NoPendingReconciliation,
            ));
        };
        match lifecycle.reconcile_execution_disposition(disposition) {
            Ok(AttemptExecutionReconciliationStep::Progressed) => {
                self.pending = Some(lifecycle);
                Ok(AttemptExecutionReconciliationStep::Progressed)
            }
            Ok(AttemptExecutionReconciliationStep::Complete) => {
                match self.factory.recover(lifecycle) {
                    Ok(()) => Ok(AttemptExecutionReconciliationStep::Complete),
                    Err(lifecycle) => {
                        self.factory.quarantine(lifecycle);
                        Err(AttemptWorkerFailure::Terminal(
                            QemuHotForkWorldExecutionRunnerError::SourceRecovery,
                        ))
                    }
                }
            }
            Err(error) => {
                self.factory.quarantine(lifecycle);
                Err(AttemptWorkerFailure::Terminal(
                    QemuHotForkWorldExecutionRunnerError::Reconciliation(error),
                ))
            }
        }
    }
}

impl<F, D> Drop for QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    fn drop(&mut self) {
        if let Some(lifecycle) = self.pending.take() {
            self.factory.quarantine(lifecycle);
        }
    }
}

fn map_hot_fork_factory_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    failure.map(QemuHotForkWorldExecutionRunnerError::Factory)
}

fn map_hot_fork_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    failure.map(QemuHotForkWorldExecutionRunnerError::Driver)
}

fn map_hot_fork_checkpoint_handoff_failure<F, D>(
    failure: AttemptWorkerFailure<CheckpointHandoffFailure>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    failure.map(QemuHotForkWorldExecutionRunnerError::CheckpointHandoff)
}

pub(crate) trait AttemptWorkerFailureExt<E> {
    fn map<T>(self, map: impl FnOnce(E) -> T) -> AttemptWorkerFailure<T>;
    fn into_error(self) -> E;
}

impl<E> AttemptWorkerFailureExt<E> for AttemptWorkerFailure<E> {
    fn map<T>(self, map: impl FnOnce(E) -> T) -> AttemptWorkerFailure<T> {
        match self {
            Self::Retryable(error) => AttemptWorkerFailure::Retryable(map(error)),
            Self::Canceled(error) => AttemptWorkerFailure::Canceled(map(error)),
            Self::Terminal(error) => AttemptWorkerFailure::Terminal(map(error)),
        }
    }

    fn into_error(self) -> E {
        match self {
            Self::Retryable(error) | Self::Canceled(error) | Self::Terminal(error) => error,
        }
    }
}

#[cfg(test)]
#[path = "qemu_hot_fork_world_factory/tests.rs"]
mod tests;
