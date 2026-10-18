//! Whole-world retained-source selection, launch, execution, and recovery.
//!
//! The production factory checks out one complete prepared source world before
//! installing target resources, launches every retained node into one atomic
//! assembly, and hands only the complete assembly to the production lifecycle
//! installer. The runner starts from the captured scheduler boundary, performs
//! ordinary modeled execution, shuts down every adopted node, and retains the
//! source and aggregate target authorities until durable publication.

use std::collections::BTreeMap;
#[cfg(test)]
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// crucible-lint: allow host-nondeterminism-state -- The factory authenticates and forwards an unchanged captured scheduler continuation; operational source availability cannot mutate it.
use crate::vm_lifecycle::ProductionVmHotForkNodeBoundary;
use crate::{
    ProductionVmHotForkNodeServiceState, ProductionVmHotForkSourceWorld, ProductionVmNodeGeneration,
};
use crucible_engine::{ContentHash, ScenarioDef, SchedulerError, SchedulerOperationalFailureClass};
use crucible_campaign::{
    AttemptResourceLimits, CampaignCodecError, CampaignLineageId, ExactCheckpointId,
    ExecutorCompatibilityProfile,
};

use crucible_qemu_host::{
    LinuxQemuHotForkChildProcessAuthority, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuHotForkChildProcessOwner, QemuHotForkLaunchError, QemuNodeSetPreparedHotForkSource,
    QemuPreparedRunDirectory, QemuShutdownPolicy, QemuVmRealizationError,
};

use crate::managed_qemu_hot_fork_source_world_pool::QemuHotForkSourceWorldLease;
use crate::qemu_campaign_lifecycle::{
    QemuFreshScenarioResourceError, QemuObservedFreshAttemptLifecycle,
    QemuObservedFreshAttemptLifecycleFactory, QemuObservedFreshAttemptLifecycleFactoryError,
    validate_fresh_qemu_scenario_resources,
};
use crate::qemu_hot_fork_world::{
    HotForkInstallationRetirementError, HotForkLifecycleInstallError,
    QemuHotForkProductionLifecycleContext, RetainedHotForkInstallation,
};
use crate::supervision::ProcessDeadline;
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionDisposition,
    AttemptExecutionProduct, AttemptExecutionReconciliationStep, AttemptWorkerFailure,
    CheckpointHandoffFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleMaterializationTier, ExactCheckpointStore, LinuxQemuHotForkReconciliationBackend,
    LinuxQemuHotForkSourceWorldAttemptLaunchError, LinuxQemuHotForkWorldAttemptLaunchFailure,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory, QemuFreshAttemptDriver, QemuFreshAttemptLifecycle,
    QemuFreshAttemptLifecycleOwner, QemuFreshDriveOutcome, QemuFreshExecutionRunnerError,
    QemuHotForkAttemptReconciliation, QemuHotForkReconciliationStep, QemuHotForkWorldAssembly,
    QemuHotForkWorldAuxiliaryResourceBroker, QemuHotForkWorldNodeTarget,
    QemuHotForkWorldResourceOwner, QemuProductionHotForkWorldLifecycle,
};

mod native;
pub(crate) use native::PreparedTargetLaunch;
mod source_selection;
use source_selection::SelectedTargetSource;
mod runtime;
pub(crate) mod target_construction;
mod target_operations;
#[cfg(test)]
use target_operations::TargetBeginFailure;
use target_operations::{NativeTargetOperations, WorldTargetOperations};

/// Exact semantic and executor basis of one retained source world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QemuHotForkSourceWorldKey {
    template: crate::HotCheckpointPoolKey,
    scenario: ContentHash,
    profile: ExecutorCompatibilityProfile,
    boundary: QemuHotForkSourceWorldBoundary,
}

/// Authenticated semantic boundary represented by one retained source world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QemuHotForkSourceWorldBoundary {
    /// The source is at the lineage's canonical scenario-genesis boundary.
    CanonicalGenesis,
    /// The source is at one completely authenticated exact-checkpoint boundary.
    ExactCheckpoint(ExactCheckpointId),
}

/// Failure while deriving the exact retained-source lookup key for an attempt.
#[derive(Debug, thiserror::Error)]
pub(crate) enum QemuHotForkSourceWorldKeyError {
    /// The authenticated campaign lineage could not produce its canonical ID.
    #[error("derive hot-fork source lineage")]
    Lineage(#[source] CampaignCodecError),
    /// The operational runtime basis belongs to another campaign lineage.
    #[error("hot-fork runtime lineage differs from the authenticated attempt lineage")]
    RuntimeLineageMismatch,
}

impl QemuHotForkSourceWorldKey {
    /// Binds one retained source world to its complete reuse identity.
    #[must_use]
    pub(crate) const fn new(
        lineage: CampaignLineageId,
        scenario: ContentHash,
        configuration: ContentHash,
        profile: ExecutorCompatibilityProfile,
    ) -> Self {
        Self {
            template: crate::HotCheckpointPoolKey::new(lineage, configuration),
            scenario,
            profile,
            boundary: QemuHotForkSourceWorldBoundary::CanonicalGenesis,
        }
    }

    /// Binds one retained source world to an authenticated exact checkpoint.
    #[must_use]
    pub(crate) const fn new_exact(
        lineage: CampaignLineageId,
        scenario: ContentHash,
        configuration: ContentHash,
        profile: ExecutorCompatibilityProfile,
        checkpoint: ExactCheckpointId,
    ) -> Self {
        Self {
            template: crate::HotCheckpointPoolKey::new(lineage, configuration),
            scenario,
            profile,
            boundary: QemuHotForkSourceWorldBoundary::ExactCheckpoint(checkpoint),
        }
    }

    /// Returns the lineage and paused-source identity used by shared accounting.
    #[must_use]
    pub const fn template_key(&self) -> crate::HotCheckpointPoolKey {
        self.template
    }

    /// Returns the exact retained scenario definition.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.scenario
    }

    /// Returns the paused source configuration.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.template.configuration()
    }

    /// Returns the authenticated scheduler boundary represented by this source.
    #[must_use]
    pub const fn boundary(&self) -> QemuHotForkSourceWorldBoundary {
        self.boundary
    }

    pub(crate) fn for_execution(
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        runtime_basis: crate::AttemptExecutionRuntimeBasis,
    ) -> Result<Self, QemuHotForkSourceWorldKeyError> {
        let lineage = input
            .lineage()
            .id()
            .map_err(QemuHotForkSourceWorldKeyError::Lineage)?;
        if runtime_basis.key().lineage() != lineage {
            return Err(QemuHotForkSourceWorldKeyError::RuntimeLineageMismatch);
        }
        let configuration = match input.start() {
            crate::CrucibleResolvedAttemptStart::Discover { configuration } => configuration.id(),
            crate::CrucibleResolvedAttemptStart::Branch { parent, .. } => parent.id(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
                input.start().configuration().id()
            }
        };
        let scenario = input.scenario().scenario_def().id();
        let profile = ExecutorCompatibilityProfile::from_lineage(input.lineage());
        Ok(match context.resume_checkpoint() {
            Some(checkpoint) => {
                Self::new_exact(lineage, scenario, configuration, profile, checkpoint)
            }
            None => Self::new(lineage, scenario, configuration, profile),
        })
    }
}

/// Exact source incarnation retained across one provider checkout.
///
/// A prepared source may mint a new transaction generation while it is made
/// reusable, but its world-node generations and Linux process incarnations
/// remain fixed. Providers use this receipt to prevent a caller from returning
/// another prepared world under the checked-out source's authenticated key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QemuHotForkSourceWorldCheckoutIdentity {
    scenario: ContentHash,
    configuration: ContentHash,
    nodes: Vec<ProductionVmHotForkNodeBoundary>,
}

impl QemuHotForkSourceWorldCheckoutIdentity {
    pub(crate) fn capture(
        source: &ProductionVmHotForkSourceWorld,
    ) -> Result<Self, crate::vm_lifecycle::ProductionVmHotForkContinuationUnavailable> {
        let continuation = source.continuation()?;
        Ok(Self {
            scenario: continuation.configuration().def.id(),
            configuration: continuation.configuration().id(),
            nodes: continuation.nodes().to_vec(),
        })
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn single_node(&self) -> Option<&crucible_engine::NodeId> {
        match self.nodes.as_slice() {
            [boundary] => Some(boundary.node()),
            _ => None,
        }
    }

    pub(crate) fn matches(&self, source: &ProductionVmHotForkSourceWorld) -> bool {
        source.continuation().is_ok_and(|continuation| {
            self.scenario == continuation.configuration().def.id()
                && self.configuration == continuation.configuration().id()
                && self.nodes == continuation.nodes()
        })
    }
}

pub(crate) mod source_world_provider_sealed {
    /// Prevents source-world authority providers from being implemented outside
    /// the daemon crate.
    pub trait Sealed {}
}

/// Checked-out source-world storage used by the production hot-fork factory.
pub(crate) trait QemuHotForkSourceWorldProvider:
    source_world_provider_sealed::Sealed
{
    /// Provider-specific checkout failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Removes an exact source world from reusable storage when one is available.
    ///
    /// # Errors
    ///
    /// Returns an availability failure without removing a source world.
    fn checkout(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error>;

    /// Removes or materializes the exact source requested by one attempt.
    ///
    /// Ordinary providers delegate to [`Self::checkout`]. A packaged provider
    /// may use the authenticated input and execution origin to restore a
    /// demanded exact-checkpoint source before checkout.
    ///
    /// # Errors
    ///
    /// Returns the provider's availability or authenticated materialization
    /// failure without exposing a partial source world.
    fn checkout_for_attempt(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        let _ = (input, context);
        self.checkout(key)
    }

    /// Performs the selected actor's fixed park invocation before child aliases.
    ///
    /// Ordinary providers have no retained actor caller and perform no park
    /// operation. This default is not a drain, eligibility or native receipt.
    /// The genuine packaged provider overrides it using its closed issuer loan.
    ///
    /// # Errors
    /// Preserves typed park refusal with the actual pool-held source custody.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn parent_park_before_fork(
        &mut self,
        _lease: &QemuHotForkSourceWorldLease,
    ) -> Result<(), crate::managed_qemu_hot_fork_source_world_pool::ManagedParentParkError> {
        Ok(())
    }

    /// Classifies a checkout failure for the attempt supervisor.
    ///
    /// Providers backed only by an operational live-source pool use the
    /// retryable default. Providers that authenticate or materialize an exact
    /// source override this hook so cancellation and semantic rejection retain
    /// their original class.
    #[must_use]
    fn failure_class(_error: &Self::Error) -> SchedulerOperationalFailureClass {
        SchedulerOperationalFailureClass::Retryable
    }

    /// Returns a completely reconciled source world to reusable storage.
    fn restore(&mut self, source: QemuHotForkSourceWorldLease);

    /// Marks the checked-out source unavailable after its authority moved to quarantine.
    fn abandon(&mut self);
}

/// One exact prepared source world used by focused factory tests.
#[must_use = "retain the prepared source world for hot-fork execution"]
#[cfg(test)]
pub(crate) struct QemuSingleHotForkSourceWorldProvider {
    key: QemuHotForkSourceWorldKey,
    source: Option<ProductionVmHotForkSourceWorld>,
    checked_out: Option<QemuHotForkSourceWorldCheckoutIdentity>,
    quarantined: bool,
}

#[cfg(test)]
impl QemuSingleHotForkSourceWorldProvider {
    /// Creates a provider owning one complete prepared source world.
    pub(crate) const fn new(
        key: QemuHotForkSourceWorldKey,
        source: ProductionVmHotForkSourceWorld,
    ) -> Self {
        Self {
            key,
            source: Some(source),
            checked_out: None,
            quarantined: false,
        }
    }

    /// Returns whether the exact source world is currently reusable.
    #[must_use]
    pub fn available(&self) -> bool {
        !self.quarantined
            && self
                .source
                .as_ref()
                .is_some_and(|source| self.checked_out.is_none() && !source.fork_target_is_owned())
    }

    /// Removes the reconciled source for explicit descendant-lineage retirement.
    pub(crate) fn take_available(&mut self) -> Option<ProductionVmHotForkSourceWorld> {
        if self.quarantined
            || self
                .source
                .as_ref()
                .is_some_and(ProductionVmHotForkSourceWorld::fork_target_is_owned)
        {
            return None;
        }
        self.source.take()
    }

    fn restore_returned_source(&mut self, mut source: ProductionVmHotForkSourceWorld) {
        if source.fork_target_is_owned() {
            self.source = Some(source);
            return;
        }
        if source.restore_retained_service_supervisor().is_err() {
            self.quarantined = true;
            self.source = Some(source);
            return;
        }
        match source.into_reusable() {
            Ok(source) => {
                self.source = Some(source);
                self.checked_out = None;
            }
            Err(failure) => match failure.into_retained_source() {
                Ok(source) => self.source = Some(source),
                Err(failure) => {
                    self.quarantined = true;
                    let _retained_for_process_lifetime = Box::leak(Box::new(failure));
                }
            },
        }
    }
}

#[cfg(test)]
impl source_world_provider_sealed::Sealed for QemuSingleHotForkSourceWorldProvider {}

#[cfg(test)]
impl QemuHotForkSourceWorldProvider for QemuSingleHotForkSourceWorldProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        if self.quarantined
            || self
                .source
                .as_ref()
                .is_some_and(ProductionVmHotForkSourceWorld::fork_target_is_owned)
        {
            return Ok(None);
        }
        if self.checked_out.is_some()
            && let Some(source) = self.source.take()
        {
            self.restore_returned_source(source);
        }
        if self.checked_out.is_some() || self.quarantined {
            return Ok(None);
        }
        let identity = self.source.as_ref().and_then(|source| {
            let continuation = source.continuation().ok()?;
            if &self.key != key
                || continuation.configuration().def.id() != key.scenario()
                || continuation.configuration().id() != key.configuration()
            {
                return None;
            }
            QemuHotForkSourceWorldCheckoutIdentity::capture(source).ok()
        });
        let Some(identity) = identity else {
            return Ok(None);
        };
        let Some(source) = self.source.take() else {
            return Ok(None);
        };
        self.checked_out = Some(identity.clone());
        match QemuHotForkSourceWorldLease::exclusive(self.key.template_key(), source, identity) {
            Ok(lease) => Ok(Some(lease)),
            Err(source) => {
                self.source = Some(source);
                self.quarantined = true;
                Ok(None)
            }
        }
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        let mut source = match source.into_exclusive_source() {
            Ok(source) => source,
            Err(source) => {
                self.quarantined = true;
                drop(source);
                return;
            }
        };
        let Some(identity) = self.checked_out.as_ref() else {
            let _ = source.retire();
            return;
        };
        if !identity.matches(&source) {
            let _ = source.retire();
            return;
        }
        if self.source.is_some() {
            let _ = source.retire();
            return;
        }
        self.restore_returned_source(source);
    }

    fn abandon(&mut self) {
        self.quarantined = true;
    }
}

/// Result of attempting retained-source lifecycle construction.
pub(crate) enum QemuHotForkWorldLifecycleStart<L> {
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

    /// Retires retained construction through the same supplied operation.
    ///
    /// The default is valid only for factories without retained owners.
    /// Resource-owning factories keep unfinished state in themselves on refusal.
    ///
    /// # Errors
    /// Keeps actual retained owners when physical cleanup or publication refuses.
    fn try_retire_original(
        &mut self,
        _original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

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
pub(crate) trait QemuHotForkWorldLifecycleOwner:
    QemuFreshAttemptLifecycleOwner + Sized
{
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
    ) -> Result<AttemptExecutionReconciliationStep, crate::ProductionVmConstructionCleanupError>;
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
    ) -> Result<AttemptExecutionReconciliationStep, crate::ProductionVmConstructionCleanupError>
    {
        QemuProductionHotForkWorldLifecycle::reconcile_execution_disposition(self, disposition)
    }
}

impl<L> QemuHotForkWorldLifecycleOwner for QemuObservedFreshAttemptLifecycle<L>
where
    L: QemuHotForkWorldLifecycleOwner,
{
    fn runtime_basis(&self) -> crate::AttemptExecutionRuntimeBasis {
        self.lifecycle().runtime_basis()
    }

    fn start_materialization(
        &self,
    ) -> Result<crate::QemuFreshStartMaterialization, SchedulerError> {
        self.lifecycle().start_materialization()
    }

    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, crate::ProductionVmConstructionCleanupError>
    {
        self.lifecycle_mut()
            .reconcile_execution_disposition(disposition)
    }
}

impl<F> QemuHotForkWorldLifecycleFactory for QemuObservedFreshAttemptLifecycleFactory<F>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    type Lifecycle = QemuObservedFreshAttemptLifecycle<F::Lifecycle>;
    type Error = QemuObservedFreshAttemptLifecycleFactoryError<F::Error>;

    fn try_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        let fingerprint_nodes = self
            .prepare_observation(input.scenario())
            .map_err(|failure| {
                failure.map(QemuObservedFreshAttemptLifecycleFactoryError::Evidence)
            })?;
        let started = self
            .inner_mut()
            .try_start(input, context)
            .map_err(|failure| failure.map(QemuObservedFreshAttemptLifecycleFactoryError::Inner))?;

        Ok(match started {
            QemuHotForkWorldLifecycleStart::Declined => QemuHotForkWorldLifecycleStart::Declined,
            QemuHotForkWorldLifecycleStart::Started(lifecycle) => {
                QemuHotForkWorldLifecycleStart::Started(self.observe(lifecycle, fingerprint_nodes))
            }
        })
    }

    fn try_retire_original(
        &mut self,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        self.inner_mut()
            .try_retire_original(original)
            .map_err(QemuObservedFreshAttemptLifecycleFactoryError::Inner)
    }

    fn recover(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        let (lifecycle, fingerprint_nodes, evidence) = lifecycle.into_recovery_parts();

        self.inner_mut().recover(lifecycle).map_err(|lifecycle| {
            QemuObservedFreshAttemptLifecycle::new(lifecycle, fingerprint_nodes, evidence)
        })
    }

    fn quarantine(&mut self, lifecycle: Self::Lifecycle) {
        let (lifecycle, _, _) = lifecycle.into_recovery_parts();
        self.inner_mut().quarantine(lifecycle);
    }
}

/// Concrete source-world and target-resource lifecycle factory.
pub(crate) struct QemuProductionHotForkWorldLifecycleFactory<S, R, O = NativeTargetOperations>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard,
{
    sources: S,
    resources: R,
    target_operations: O,
    auxiliary_resources: Option<QemuHotForkWorldAuxiliaryResourceBroker<R::Guard>>,
    retained_installation: Option<RetainedHotForkInstallation<R::Guard>>,
    retained_target: Option<runtime::TargetRetirement<R>>,
    preclaimed_target: Option<crate::PreparedSourceSelector>,
    retained_target_admission: Option<target_construction::TargetMainAdmissionFailure<R>>,
    terminal_checkpoints: Option<Arc<ExactCheckpointStore>>,
    run_state_root: PathBuf,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
    #[cfg(test)]
    native_qualification_ram_mode: Option<crucible_host_resources::ram_policy::HostRamMode>,
}

impl<S, R> QemuProductionHotForkWorldLifecycleFactory<S, R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard,
{
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
            target_operations: NativeTargetOperations,
            auxiliary_resources: None,
            retained_installation: None,
            retained_target: None,
            preclaimed_target: None,
            retained_target_admission: None,
            terminal_checkpoints: None,
            run_state_root: run_state_root.into(),
            shutdown_policy,
            async_policy,
            #[cfg(test)]
            native_qualification_ram_mode: None,
        }
    }
}

impl<S, R, O> QemuProductionHotForkWorldLifecycleFactory<S, R, O>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard,
{
    /// Selects a component resource model without changing the transaction.
    #[cfg(test)]
    fn with_target_operations<P>(
        self,
        target_operations: P,
    ) -> QemuProductionHotForkWorldLifecycleFactory<S, R, P> {
        QemuProductionHotForkWorldLifecycleFactory {
            sources: self.sources,
            resources: self.resources,
            target_operations,
            auxiliary_resources: self.auxiliary_resources,
            retained_installation: self.retained_installation,
            retained_target: self.retained_target,
            preclaimed_target: self.preclaimed_target,
            retained_target_admission: self.retained_target_admission,
            terminal_checkpoints: self.terminal_checkpoints,
            run_state_root: self.run_state_root,
            shutdown_policy: self.shutdown_policy,
            async_policy: self.async_policy,
            native_qualification_ram_mode: self.native_qualification_ram_mode,
        }
    }

    /// Selects strict initial placement for a genuine native child fixture.
    ///
    /// The mode enters the original registration grant before plan sealing;
    /// public capabilities remain unchanged and native placement must attest it.
    #[cfg(test)]
    pub(crate) fn with_native_qualification_ram_mode(
        mut self,
        mode: crucible_host_resources::ram_policy::HostRamMode,
    ) -> Self {
        self.native_qualification_ram_mode = Some(mode);
        self
    }

    /// Selects the campaign store used for recoverable terminal restarts.
    #[must_use]
    pub(crate) fn with_terminal_checkpoints(
        mut self,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Self {
        self.terminal_checkpoints = Some(checkpoints);
        self
    }

    /// Loans the existing provider to native fixtures after child reconciliation.
    #[cfg(test)]
    pub(crate) fn source_provider_mut_for_test(&mut self) -> &mut S {
        &mut self.sources
    }

    /// Binds private post-shutdown lifecycles to the retained aggregate guard.
    #[must_use]
    pub(crate) fn with_auxiliary_resources(
        mut self,
        auxiliary_resources: QemuHotForkWorldAuxiliaryResourceBroker<R::Guard>,
    ) -> Self {
        self.auxiliary_resources = Some(auxiliary_resources);
        self
    }
}

/// Failure while constructing one complete production hot-fork world.
#[derive(Debug, thiserror::Error)]
pub(crate) enum QemuProductionHotForkWorldLifecycleFactoryError<P> {
    /// The original Target owner retains its exact first and cleanup obligations.
    #[error("original Main retains Target construction and cleanup")]
    RetainedTarget,
    /// The original counted report borrows Main's unchanged construction cause.
    #[error("construct original Target: {0}")]
    TargetConstruction(#[source] crate::lifecycle_cleanup::PreparedSourceFailure),
    /// Main refused before Target effects; original input remains in the factory.
    #[error("original factory retains the refused Target admission")]
    RetainedTargetAdmission,
    /// Main refused before effects and the unchanged Source was restored.
    #[error("admit original Target Main owner: {0}")]
    TargetAdmission(#[source] target_construction::TargetMainAdmissionError),
    /// The same counted report protects the original Target cleanup cause.
    #[error("retire original Target: {0}")]
    TargetCleanup(#[source] crate::ProductionVmConstructionCleanupError),
    /// The source provider could not complete exact checkout.
    #[error("check out production hot-fork source world")]
    SourceProvider(#[source] P),
    /// A selected genuine parent park retains its complete source on refusal.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    #[error("original managed parent park refused")]
    ParentPark(#[source] crate::managed_qemu_hot_fork_source_world_pool::ManagedParentParkError),
    /// The attempt could not produce one exact retained-source lookup key.
    #[error("authenticate production hot-fork source-world key")]
    SourceKey(#[source] QemuHotForkSourceWorldKeyError),
    /// The supervisor omitted its exact runtime incarnation.
    #[error("production hot-fork world requires an exact worker runtime basis")]
    MissingRuntimeBasis,
    /// The complete target World exceeds the admitted attempt resources.
    #[error("admit production hot-fork target World resources: {0}")]
    ScenarioResources(#[source] QemuFreshScenarioResourceError),
    /// The target resource guard could not be installed.
    #[error("install production hot-fork target resources: {0}")]
    Resource(#[source] QemuVmRealizationError),
    /// Target begin preserves its initiating and independent rollback refusals.
    #[error("install production hot-fork target resources: {0}")]
    ResourceBegin(#[source] crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport),
    /// The installed guard differs from the admitted attempt contract.
    #[error("production hot-fork target guard differs from the admitted attempt contract")]
    ResourceContractMismatch,
    /// The checked-out source contradicted its exact configuration or roster.
    #[error("authenticate production hot-fork source world: {0}")]
    Source(String),
    /// One child launch or atomic assembly phase failed.
    #[error("assemble production hot-fork child world: {0}")]
    Assembly(String),
    /// Assembly's unchanged initiating report and independent typed cleanup.
    #[error("assemble production hot-fork child world: {message}; cleanup: {cleanup}")]
    AssemblyCleanup {
        /// Existing initiating assembly and rollback diagnostics.
        message: String,
        /// Actual moved cleanup cause, without a replacement diagnostic Box.
        #[source]
        cleanup: crate::ProductionVmConstructionCleanupError,
    },
    /// The complete child world could not enter the production lifecycle.
    #[error("install production hot-fork lifecycle: {0}")]
    Lifecycle(#[source] crucible_control_api::LifecycleApiError),
    /// The fixed factory slot retains the original typed construction cause.
    #[error("production hot-fork installation retains its original cleanup owner")]
    RetainedInstallation,
    /// Physical retirement refused while the exact installation stays retained.
    #[error("retire retained production hot-fork installation")]
    InstallationRetirement(#[source] HotForkInstallationRetirementError),
}

type ProductionChild<G> =
    QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>;

type ProductionAssembly<G> = QemuHotForkWorldAssembly<ProductionChild<G>>;

type ProductionStagedChild<G> = (
    crucible_engine::NodeId,
    QemuHotForkWorldNodeTarget<G>,
    QemuPreparedRunDirectory,
);

struct ConcurrentNodeLaunch<G>
where
    G: QemuAttemptResourceGuard,
{
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    node: crucible_engine::NodeId,
    target: QemuHotForkWorldNodeTarget<G>,
    run_directory: QemuPreparedRunDirectory,
    assembly: crate::qemu_hot_fork_world::QemuHotForkWorldAssemblyToken,
}

fn launch_concurrent_node<G>(
    source: QemuNodeSetPreparedHotForkSource<'_>,
    launch: ConcurrentNodeLaunch<G>,
) -> Result<ProductionChild<G>, LinuxQemuHotForkSourceWorldAttemptLaunchError>
where
    G: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    QemuHotForkAttemptReconciliation::launch_from_prepared_source(
        launch.source_world,
        launch.node,
        source,
        launch.target,
        launch.run_directory,
        launch.assembly,
    )
}

struct ProvenNoChildLaunchRecovery<'a> {
    checkout_identity: &'a QemuHotForkSourceWorldCheckoutIdentity,
    source_lease: QemuHotForkSourceWorldLease,
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    errors: Vec<LinuxQemuHotForkSourceWorldAttemptLaunchError>,
}

type ProductionLifecycleStartResult<G, P> = Result<
    QemuHotForkWorldLifecycleStart<QemuProductionHotForkWorldLifecycle<G>>,
    AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<P>>,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckedOutSourceDisposition {
    /// The exact checkout was returned to its provider.
    Restored,
    /// Process authority remains in a lifecycle or fail-closed quarantine.
    OwnedByLifecycleOrQuarantine,
}

struct ProductionLifecycleStartOutcome<G, P>
where
    G: QemuAttemptProcessResourceGuard,
{
    result: ProductionLifecycleStartResult<G, P>,
    source: CheckedOutSourceDisposition,
}

impl<G, P> ProductionLifecycleStartOutcome<G, P>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn started(lifecycle: QemuProductionHotForkWorldLifecycle<G>) -> Self {
        Self {
            result: Ok(QemuHotForkWorldLifecycleStart::Started(lifecycle)),
            source: CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
        }
    }

    fn failed(
        failure: AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<P>>,
        source: CheckedOutSourceDisposition,
    ) -> Self {
        Self {
            result: Err(failure),
            source,
        }
    }
}

impl<S, R, O> QemuHotForkWorldLifecycleFactory
    for QemuProductionHotForkWorldLifecycleFactory<S, R, O>
where
    S: QemuHotForkSourceWorldProvider,
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
    O: WorldTargetOperations<R>,
{
    type Lifecycle = O::Lifecycle;
    type Error = QemuProductionHotForkWorldLifecycleFactoryError<S::Error>;

    fn try_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        let Some(selected) = self.select_source_for_attempt(input, context)? else {
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        };
        O::construct_world(self, input, context, selected)
    }

    fn try_retire_original(
        &mut self,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        if let Some(failure) = self.retained_target_admission.take() {
            match failure.try_restore_source() {
                Ok((source, _first)) => self.sources.restore(source),
                Err(failure) => {
                    self.retained_target_admission = Some(failure);
                    return Err(Self::Error::RetainedTargetAdmission);
                }
            }
        }
        if let Some(target) = self.retained_target.as_mut() {
            match target.poll().map_err(Self::Error::TargetCleanup)? {
                AttemptExecutionReconciliationStep::Progressed => {
                    return Err(Self::Error::RetainedTarget);
                }
                AttemptExecutionReconciliationStep::Complete => {
                    let Some(source) = target.take_source() else {
                        return Err(Self::Error::RetainedTarget);
                    };
                    self.retained_target = None;
                    self.preclaimed_target = None;
                    self.sources.restore(source);
                }
            }
        }
        let Some(retained) = self.retained_installation.as_mut() else {
            return Ok(());
        };
        match retained.advance_original_retirement(original) {
            Ok(Some((source, history))) => {
                // Destroy the completed receipt and enclosing aliases before
                // restoring the exact Source. History is a separate report,
                // never an unfinished cleanup or another Source checkout.
                self.retained_installation = None;
                self.sources.restore(source);
                if history.is_empty() {
                    Ok(())
                } else {
                    Err(Self::Error::InstallationRetirement(
                        HotForkInstallationRetirementError::Historical(history),
                    ))
                }
            }
            // Yield to Main so it can drain a carrier published by this step.
            Ok(None) => Err(Self::Error::InstallationRetirement(
                HotForkInstallationRetirementError::Pending,
            )),
            Err(error) => Err(Self::Error::InstallationRetirement(error)),
        }
    }

    fn recover(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        match O::into_source_lease(lifecycle) {
            Ok(source) => {
                self.sources.restore(source);
                Ok(())
            }
            Err(lifecycle) => Err(lifecycle),
        }
    }

    fn quarantine(&mut self, lifecycle: Self::Lifecycle) {
        O::abandon_runtime(lifecycle);
        self.sources.abandon();
    }
}

#[cfg(test)]
impl<S, R, O> QemuProductionHotForkWorldLifecycleFactory<S, R, O>
where
    S: QemuHotForkSourceWorldProvider,
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
    O: WorldTargetOperations<R>,
{
    // crucible-lint: allow rust-allow -- the transaction inputs remain explicit at the sole whole-world launch boundary.
    #[allow(clippy::too_many_arguments)]
    fn launch_complete_world(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        scenario: ScenarioDef,
        checkout_identity: QemuHotForkSourceWorldCheckoutIdentity,
        source_lease: QemuHotForkSourceWorldLease,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        continuation: crate::ProductionVmHotForkWorldContinuation,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        runtime_basis: crate::AttemptExecutionRuntimeBasis,
        ram_factory: Arc<dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory>,
        #[cfg(test)] component_construction: Option<Box<crate::ProductionVmConstructionCustody>>,
    ) -> ProductionLifecycleStartOutcome<R::Guard, S::Error> {
        let mut source_lease = Some(source_lease);
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
        if context
            .remaining_host_watchdog()
            .is_some_and(|remaining| remaining.is_zero())
        {
            quarantine_failed_assembly(source_world, resources, assembly, None);
            return ProductionLifecycleStartOutcome::failed(
                AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(String::from(
                        "assignment host watchdog expired before child launch",
                    )),
                ),
                CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
            );
        }
        let async_policy = self.async_policy;
        let mut child_supervisors = BTreeMap::new();
        let mut staged: Vec<ProductionStagedChild<R::Guard>> = Vec::new();
        for (node, (service_state, generation)) in boundaries {
            match service_state {
                ProductionVmHotForkNodeServiceState::PermanentlyFailed => continue,
                ProductionVmHotForkNodeServiceState::Running
                | ProductionVmHotForkNodeServiceState::PoweredOff => {}
            }
            let child_generation = match generation.checked_add(1) {
                Some(generation) => generation,
                None => {
                    let message = format!("source generation for `{}` cannot advance", node.name);
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return ProductionLifecycleStartOutcome::failed(
                        AttemptWorkerFailure::Terminal(
                            QemuProductionHotForkWorldLifecycleFactoryError::Source(message),
                        ),
                        CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                    );
                }
            };
            let identity = match ProductionVmNodeGeneration::new(node.clone(), child_generation) {
                Ok(identity) => identity,
                Err(error) => {
                    let message = error.to_string();
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return ProductionLifecycleStartOutcome::failed(
                        AttemptWorkerFailure::Terminal(
                            QemuProductionHotForkWorldLifecycleFactoryError::Source(message),
                        ),
                        CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                    );
                }
            };
            let launch_resources = match source_world
                .lock()
                .map_err(|_| String::from("source-world ownership lock is poisoned"))
                .and_then(|world| {
                    world
                        .prepared_launch_resources(&node)
                        .map_err(|error| error.to_string())
                }) {
                Ok(resources) => resources,
                Err(message) => {
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return ProductionLifecycleStartOutcome::failed(
                        AttemptWorkerFailure::Terminal(
                            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                        ),
                        CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                    );
                }
            };
            let mut target = match resources.reserve_process_node(identity) {
                Ok(target) => target,
                Err(error) => {
                    return self.recover_preflight_rejection(
                        &checkout_identity,
                        source_lease.take(),
                        source_world,
                        resources,
                        assembly,
                        staged,
                        None,
                        error.to_string(),
                    );
                }
            };
            let operational = self.target_operations.prepare_member(
                &mut target,
                context,
                ram_factory.as_ref(),
                &node,
                child_generation,
                launch_resources,
            );
            let supervisor = match operational {
                Ok(supervisor) => supervisor,
                Err(message) => {
                    return self.recover_preflight_rejection(
                        &checkout_identity,
                        source_lease.take(),
                        source_world,
                        resources,
                        assembly,
                        staged,
                        Some(target),
                        message,
                    );
                }
            };
            child_supervisors.insert(node.clone(), supervisor);
            let prepared = self.target_operations.prepare_directory(
                &source_world,
                &mut target,
                launch_resources,
            );
            let run_directory = match prepared {
                Ok(directory) => directory,
                Err(error) => {
                    return self.recover_preflight_rejection(
                        &checkout_identity,
                        source_lease.take(),
                        source_world,
                        resources,
                        assembly,
                        staged,
                        Some(target),
                        error.to_string(),
                    );
                }
            };
            staged.push((node, target, run_directory));
        }

        let launch_token = assembly.child_launch_token();
        let operations = staged
            .into_iter()
            .map(|(node, target, run_directory)| {
                (
                    node.clone(),
                    ConcurrentNodeLaunch {
                        source_world: Arc::clone(&source_world),
                        node,
                        target,
                        run_directory,
                        assembly: launch_token.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let launched = match source_world
            .lock()
            .map_err(|_| String::from("source-world ownership lock is poisoned"))
            .and_then(|mut world| {
                world
                    .map_prepared_sources_concurrent(operations, launch_concurrent_node::<R::Guard>)
                    .map_err(|error| error.to_string())
            }) {
            Ok(launched) => launched,
            Err(message) => {
                quarantine_failed_assembly(source_world, resources, assembly, None);
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
        };

        let mut launch_failures = Vec::new();
        for (node, child) in launched {
            let mut child = match child {
                Ok(child) => child,
                Err(error) => {
                    launch_failures.push(error);
                    continue;
                }
            };
            if let Err(error) = child.admit_child() {
                let message = error.to_string();
                quarantine_failed_assembly(source_world, resources, assembly, Some(child));
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
            let supervisor = child_supervisors.remove(&node);
            if supervisor.is_none() {
                quarantine_failed_assembly(source_world, resources, assembly, Some(child));
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(String::from(
                            "adopted child lost its original pre-fork operational owner",
                        )),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
            if let Err(error) = child.install_scheduler_node(
                node.clone(),
                self.shutdown_policy,
                async_policy,
                QemuCrashDetector::new(node.name.clone()),
                supervisor,
            ) {
                let message = error.to_string();
                quarantine_failed_assembly(source_world, resources, assembly, Some(child));
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
            if let Err(error) = assembly.admit_child(node, child) {
                let message = error.to_string();
                let (_node, child, _failure) = error.into_parts();
                quarantine_failed_assembly(source_world, resources, assembly, Some(child));
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
        }
        if let Some(error) = launch_failures.first() {
            let message = error.to_string();
            let Some(source_lease) = source_lease.take() else {
                drop(launch_failures);
                quarantine_failed_assembly(source_world, resources, assembly, None);
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(String::from(
                            "source lease disappeared before launch rollback",
                        )),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            };
            let recovery = ProvenNoChildLaunchRecovery {
                checkout_identity: &checkout_identity,
                source_lease,
                source_world,
                errors: launch_failures,
            };
            let mut failure_message = message;
            let mut cleanup_failure = None;
            let source = self.recover_proven_no_child_launch(
                recovery,
                resources,
                assembly,
                &mut failure_message,
                &mut cleanup_failure,
            );
            let failure = match cleanup_failure {
                Some(cleanup) => QemuProductionHotForkWorldLifecycleFactoryError::AssemblyCleanup {
                    message: failure_message,
                    cleanup,
                },
                None => QemuProductionHotForkWorldLifecycleFactoryError::Assembly(failure_message),
            };
            return ProductionLifecycleStartOutcome::failed(
                AttemptWorkerFailure::Retryable(failure),
                source,
            );
        }
        let complete = match assembly.publish() {
            Ok(complete) => complete,
            Err(incomplete) => {
                let message = incomplete.to_string();
                quarantine_failed_assembly(source_world, resources, assembly, None);
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
        };
        let Some(source_lease) = source_lease.take() else {
            complete.quarantine();
            resources.quarantine();
            let _retained_source_owner = Box::leak(Box::new(source_world));
            return ProductionLifecycleStartOutcome::failed(
                AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(String::from(
                        "source lease disappeared before lifecycle installation",
                    )),
                ),
                CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
            );
        };
        let install_context = QemuHotForkProductionLifecycleContext::new(
            &scenario,
            input.scenario(),
            runtime_basis,
            self.run_state_root.clone(),
        )
        .with_terminal_checkpoints(
            self.terminal_checkpoints.clone(),
            context.cancellation().clone(),
        );
        #[cfg(test)]
        let install_context = install_context.with_component_construction(component_construction);
        let lifecycle = match complete.install_production_lifecycle(
            install_context,
            source_lease,
            source_world,
            resources,
            self.auxiliary_resources.clone(),
        ) {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                let error = match error {
                    HotForkLifecycleInstallError::Lifecycle(error) => {
                        QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(error)
                    }
                    HotForkLifecycleInstallError::Retained(retained) => {
                        // try_start checked this slot before checkout. The
                        // exclusive &mut factory cannot start another attempt
                        // or replace this slot during this installation.
                        let retained = self.retained_installation.insert(retained);
                        #[cfg(test)]
                        if let Some(first) = retained.take_component_construction_cause() {
                            // The fixture's actual body stays in this same slot.
                            // Reporting its cause is not canonical publication.
                            return ProductionLifecycleStartOutcome::failed(
                                AttemptWorkerFailure::Terminal(
                                    QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(
                                        first,
                                    ),
                                ),
                                CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                            );
                        }
                        match retained.publish_construction() {
                            Ok(Some(first)) => {
                                QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(first)
                            }
                            Ok(None) | Err(_) => {
                                QemuProductionHotForkWorldLifecycleFactoryError::RetainedInstallation
                            }
                        }
                    }
                };
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(error),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
        };
        ProductionLifecycleStartOutcome::started(lifecycle)
    }

    // crucible-lint: allow rust-allow -- the transaction inputs remain explicit at the sole preflight rollback boundary.
    #[allow(clippy::too_many_arguments)]
    fn recover_preflight_rejection(
        &mut self,
        checkout_identity: &QemuHotForkSourceWorldCheckoutIdentity,
        source_lease: Option<QemuHotForkSourceWorldLease>,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        assembly: ProductionAssembly<R::Guard>,
        staged: Vec<ProductionStagedChild<R::Guard>>,
        rejected_target: Option<QemuHotForkWorldNodeTarget<R::Guard>>,
        mut message: String,
    ) -> ProductionLifecycleStartOutcome<R::Guard, S::Error> {
        let mut rollback_failed = false;
        let mut cleanup_failure = None;
        if let Some(target) = rejected_target
            && let Err(error) = target.abort_without_child()
        {
            rollback_failed = true;
            message.push_str(&format!(
                "; reject target reservation rollback failed: {error}"
            ));
        }
        for (_node, target, run_directory) in staged {
            drop(run_directory);
            if let Err(error) = target.abort_without_child() {
                rollback_failed = true;
                message.push_str(&format!(
                    "; staged target reservation rollback failed: {error}"
                ));
            }
        }
        if !rollback_failed && let Err(error) = resources.finish() {
            rollback_failed = true;
            message.push_str("; aggregate target release failed after preflight rejection");
            cleanup_failure = Some(error.into());
        }
        if rollback_failed {
            let Some(source_lease) = source_lease else {
                quarantine_failed_assembly(source_world, resources, assembly, None);
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Retryable(match cleanup_failure {
                        Some(cleanup) => {
                            QemuProductionHotForkWorldLifecycleFactoryError::AssemblyCleanup {
                                message,
                                cleanup,
                            }
                        }
                        None => QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                    }),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            };
            let retained = (source_lease, source_world, resources);
            let _retained_for_process_lifetime = Box::leak(Box::new(retained));
            drop(assembly);
            return ProductionLifecycleStartOutcome::failed(
                AttemptWorkerFailure::Retryable(match cleanup_failure {
                    Some(cleanup) => {
                        QemuProductionHotForkWorldLifecycleFactoryError::AssemblyCleanup {
                            message,
                            cleanup,
                        }
                    }
                    None => QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                }),
                CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
            );
        }

        drop(resources);
        drop(source_world);
        let Some(source_lease) = source_lease else {
            return ProductionLifecycleStartOutcome::failed(
                AttemptWorkerFailure::Retryable(match cleanup_failure {
                    Some(cleanup) => {
                        QemuProductionHotForkWorldLifecycleFactoryError::AssemblyCleanup {
                            message,
                            cleanup,
                        }
                    }
                    None => QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                }),
                CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
            );
        };
        if source_lease.identity() != checkout_identity {
            message.push_str(
                "; exact source-world checkout identity changed during preflight rollback",
            );
            let _retained_for_process_lifetime = Box::leak(Box::new(source_lease));
            return ProductionLifecycleStartOutcome::failed(
                AttemptWorkerFailure::Retryable(match cleanup_failure {
                    Some(cleanup) => {
                        QemuProductionHotForkWorldLifecycleFactoryError::AssemblyCleanup {
                            message,
                            cleanup,
                        }
                    }
                    None => QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                }),
                CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
            );
        }
        if !source_lease.reauthenticates_source() {
            message
                .push_str("; exact source-world reauthentication failed after preflight rollback");
            let _retained_for_process_lifetime = Box::leak(Box::new(source_lease));
            return ProductionLifecycleStartOutcome::failed(
                AttemptWorkerFailure::Retryable(match cleanup_failure {
                    Some(cleanup) => {
                        QemuProductionHotForkWorldLifecycleFactoryError::AssemblyCleanup {
                            message,
                            cleanup,
                        }
                    }
                    None => QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                }),
                CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
            );
        }
        self.sources.restore(source_lease);
        ProductionLifecycleStartOutcome::failed(
            AttemptWorkerFailure::Retryable(match cleanup_failure {
                Some(cleanup) => QemuProductionHotForkWorldLifecycleFactoryError::AssemblyCleanup {
                    message,
                    cleanup,
                },
                None => QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
            }),
            CheckedOutSourceDisposition::Restored,
        )
    }

    fn recover_proven_no_child_launch(
        &mut self,
        recovery: ProvenNoChildLaunchRecovery<'_>,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        assembly: ProductionAssembly<R::Guard>,
        failure_message: &mut String,
        cleanup_failure: &mut Option<crate::ProductionVmConstructionCleanupError>,
    ) -> CheckedOutSourceDisposition {
        let ProvenNoChildLaunchRecovery {
            checkout_identity,
            source_lease,
            source_world,
            errors,
        } = recovery;
        // Only the typed no-child outcome plus successful reservation rollback
        // permits source reuse. Every other launch state retains all authority.
        let mut recovered_sources = Vec::with_capacity(errors.len());
        for error in errors {
            let (failure, owner) = error.into_parts();
            let proven_rejection = matches!(
                failure,
                LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(
                    QemuHotForkLaunchError::Rejected { .. }
                )
            );
            if !proven_rejection {
                drop(owner);
                quarantine_failed_assembly(source_world, resources, assembly, None);
                return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
            }

            let (recovered_source, run_directory) = match owner.into_recoverable_parts() {
                Ok(parts) => parts,
                Err(owner) => {
                    drop(owner);
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
                }
            };
            drop(run_directory);

            if !Arc::ptr_eq(&source_world, &recovered_source) {
                failure_message.push_str("; clean rejection returned another source-world owner");
                let children = assembly.into_rollback_children();
                quarantine_failed_rollback(
                    source_world,
                    Some(recovered_source),
                    resources,
                    children,
                );
                return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
            }
            recovered_sources.push(recovered_source);
        }

        let children = assembly.into_rollback_children();
        if let Err((children, rollback)) =
            rollback_hot_fork_children(children, self.shutdown_policy)
        {
            failure_message.push_str(&format!("; clean-rejection rollback failed: {rollback}"));
            drop(recovered_sources);
            quarantine_failed_rollback(source_world, None, resources, children);
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }

        if let Err(error) = resources.finish() {
            failure_message.push_str("; aggregate target release failed after rollback");
            crate::ProductionVmConstructionCleanupError::retain_first(
                cleanup_failure,
                error.into(),
            );
            drop(recovered_sources);
            quarantine_failed_rollback(source_world, None, resources, BTreeMap::new());
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }
        drop(resources);
        drop(source_world);
        drop(recovered_sources);
        if source_lease.identity() != checkout_identity {
            failure_message.push_str(
                "; exact source-world checkout identity changed before rollback recovery",
            );
            let _retained_for_process_lifetime = Box::leak(Box::new(source_lease));
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }
        if !source_lease.reauthenticates_source() {
            failure_message.push_str("; exact source-world reauthentication failed after rollback");
            let _retained_for_process_lifetime = Box::leak(Box::new(source_lease));
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }
        self.sources.restore(source_lease);
        CheckedOutSourceDisposition::Restored
    }
}

trait HotForkRollbackChild {
    fn request_rollback_termination(&mut self) -> Result<(), String>;

    fn rollback_step(&mut self) -> Result<QemuHotForkReconciliationStep, String>;

    fn reconcile_rollback_cancellation(
        &mut self,
    ) -> Result<AttemptExecutionReconciliationStep, String>;

    fn quarantine_rollback(&mut self);
}

impl<G> HotForkRollbackChild for ProductionChild<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn request_rollback_termination(&mut self) -> Result<(), String> {
        self.request_termination()
            .map_err(|error| error.to_string())
    }

    fn rollback_step(&mut self) -> Result<QemuHotForkReconciliationStep, String> {
        self.reconcile_step().map_err(|error| error.to_string())
    }

    fn reconcile_rollback_cancellation(
        &mut self,
    ) -> Result<AttemptExecutionReconciliationStep, String> {
        self.reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
            .map_err(|error| error.to_string())
    }

    fn quarantine_rollback(&mut self) {
        self.quarantine();
    }
}

fn rollback_hot_fork_children<C>(
    mut children: BTreeMap<crucible_engine::NodeId, C>,
    shutdown_policy: QemuShutdownPolicy,
) -> Result<(), (BTreeMap<crucible_engine::NodeId, C>, String)>
where
    C: HotForkRollbackChild,
{
    let mut termination_failures = Vec::new();
    for (node, child) in &mut children {
        if let Err(error) = child.request_rollback_termination() {
            termination_failures.push(format!("request termination for `{}`: {error}", node.name));
        }
    }
    if !termination_failures.is_empty() {
        return Err((children, termination_failures.join("; ")));
    }

    let running_wait = shutdown_policy
        .sigkill_wait
        .saturating_add(shutdown_policy.reap_wait);
    let poll_wait = if shutdown_policy.reap_wait.is_zero() {
        shutdown_policy.sigkill_wait
    } else {
        shutdown_policy.reap_wait
    };
    let nodes = children.keys().cloned().collect::<Vec<_>>();
    for node in nodes {
        let Some(deadline) = ProcessDeadline::after(running_wait) else {
            let failure = format!(
                "reconcile `{}` within configured SIGKILL and reap waits",
                node.name
            );
            return Err((children, failure));
        };
        let Some(child) = children.get_mut(&node) else {
            return Err((
                children,
                format!("retained rollback child `{}` disappeared", node.name),
            ));
        };
        loop {
            if deadline.expired() {
                let failure = format!(
                    "reconcile `{}` within configured SIGKILL and reap waits",
                    node.name
                );
                return Err((children, failure));
            }
            match child.rollback_step() {
                Ok(QemuHotForkReconciliationStep::ChildRunning) => {
                    deadline.pause(poll_wait);
                }
                Ok(QemuHotForkReconciliationStep::AwaitingPublication) => break,
                Ok(QemuHotForkReconciliationStep::ChildDiagnosticsDrained)
                | Ok(QemuHotForkReconciliationStep::Advanced(_)) => {}
                Ok(QemuHotForkReconciliationStep::Complete) => {
                    let failure = format!(
                        "child `{}` completed before rollback cancellation was recorded",
                        node.name
                    );
                    return Err((children, failure));
                }
                Err(error) => {
                    let failure = format!(
                        "reconcile child `{}` before publication: {error}",
                        node.name
                    );
                    return Err((children, failure));
                }
            }
        }
        loop {
            if deadline.expired() {
                let failure = format!(
                    "reconcile cancellation for `{}` within configured SIGKILL and reap waits",
                    node.name
                );
                return Err((children, failure));
            }
            match child.reconcile_rollback_cancellation() {
                Ok(AttemptExecutionReconciliationStep::Progressed) => {}
                Ok(AttemptExecutionReconciliationStep::Complete) => break,
                Err(error) => {
                    let failure = format!("reconcile cancellation for `{}`: {error}", node.name);
                    return Err((children, failure));
                }
            }
        }
        children.remove(&node);
    }

    Ok(())
}

struct QuarantinedHotForkWorld<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    _source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    _resources: QemuHotForkWorldResourceOwner<G>,
    _assembly: ProductionAssembly<G>,
}

struct QuarantinedHotForkRollbackWorld<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    _source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    _recovered_source: Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>>,
    _resources: QemuHotForkWorldResourceOwner<G>,
    _children: BTreeMap<crucible_engine::NodeId, ProductionChild<G>>,
}

fn quarantine_failed_rollback<G>(
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    recovered_source: Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>>,
    mut resources: QemuHotForkWorldResourceOwner<G>,
    mut children: BTreeMap<crucible_engine::NodeId, ProductionChild<G>>,
) where
    G: QemuAttemptProcessResourceGuard + Send + 'static,
{
    for child in children.values_mut() {
        child.quarantine_rollback();
    }
    resources.quarantine();
    let quarantine = QuarantinedHotForkRollbackWorld {
        _source_world: source_world,
        _recovered_source: recovered_source,
        _resources: resources,
        _children: children,
    };
    let _retained_for_process_lifetime = Box::leak(Box::new(quarantine));
}

fn quarantine_failed_assembly<G>(
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    mut resources: QemuHotForkWorldResourceOwner<G>,
    mut assembly: ProductionAssembly<G>,
    child: Option<QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>>,
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

mod runner;

pub(crate) use runner::{
    AttemptWorkerFailureExt, QemuHotForkWorldExecutionAttempt, QemuHotForkWorldExecutionRunner,
    QemuHotForkWorldExecutionRunnerError,
};

#[cfg(test)]
pub(crate) use tests::assert_native_atomic_resources_private;
#[cfg(test)]
pub(crate) use tests::assert_native_sibling_resources_private;

#[cfg(test)]
#[path = "qemu_hot_fork_world_factory/tests.rs"]
mod tests;

#[cfg(test)]
impl<S, R, O> QemuProductionHotForkWorldLifecycleFactory<S, R, O>
where
    S: QemuHotForkSourceWorldProvider,
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
    O: target_operations::ComponentWorldTargetOperations<R>,
{
    fn try_start_component_world(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        source_lease: QemuHotForkSourceWorldLease,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        continuation: crate::ProductionVmHotForkWorldContinuation,
        runtime_basis: crate::AttemptExecutionRuntimeBasis,
    ) -> ProductionLifecycleStartResult<R::Guard, S::Error> {
        let scenario = input.scenario().scenario_def();
        let ram_preflight = (|| {
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
            #[cfg(test)]
            let factory = if let Some(mode) = self.native_qualification_ram_mode {
                crate::qemu_campaign_lifecycle::create_native_qualification_ram_registration_factory(context, mode)
            } else {
                crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(context)
            }.map_err(|error| error.to_string())?;
            #[cfg(not(test))]
            let factory =
                crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(context)
                    .map_err(|error| error.to_string())?;
            let world = source_world
                .lock()
                .map_err(|_| String::from("source-world ownership lock is poisoned"))?;
            let mut shapes = Vec::new();
            for (node, (state, _)) in &boundaries {
                if *state == ProductionVmHotForkNodeServiceState::PermanentlyFailed {
                    continue;
                }
                let launch = world
                    .prepared_launch_resources(node)
                    .map_err(|error| error.to_string())?;
                shapes.push(
                    crucible_control_api::host_operational::ProductionHostRamLaunchShape {
                        node: node.name.clone(),
                        declared_ram_bytes: launch.guest_memory_bytes(),
                        vcpus: launch.virtual_cpus(),
                    },
                );
            }
            factory
                .configure_world(&shapes)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(factory)
        })();
        let ram_factory = match ram_preflight {
            Ok(factory) => factory,
            Err(message) => {
                drop(source_world);
                self.sources.restore(source_lease);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                ));
            }
        };
        let process_resources = (|| {
            let native = ram_factory
                .native_world_limits()
                .map_err(|error| error.to_string())?;
            let remaining = context
                .process_resources()
                .map_err(|error| error.to_string())?;
            AttemptResourceLimits::new(
                native.cpu_slots,
                native.resident_bytes,
                native.writable_bytes,
                remaining.maximum_execution_quanta(),
            )
            .map_err(|error| error.to_string())
        })();
        let process_resources = match process_resources {
            Ok(resources) => resources,
            Err(message) => {
                drop(source_world);
                self.sources.restore(source_lease);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                ));
            }
        };
        #[cfg(test)]
        let component_construction = match self.target_operations.prepare_component_construction() {
            Ok(custody) => custody,
            Err(first) => {
                drop(source_world);
                self.sources.restore(source_lease);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(first),
                ));
            }
        };
        let mut guard = match self.target_operations.begin_target(
            &mut self.resources,
            &source_world,
            process_resources,
            context.cancellation().clone(),
        ) {
            Ok(guard) => guard,
            Err(failure) => {
                drop(source_world);
                self.sources.restore(source_lease);
                let error = match failure {
                    TargetBeginFailure::Source(message) => {
                        QemuProductionHotForkWorldLifecycleFactoryError::Source(message)
                    }
                    TargetBeginFailure::Resources(error) => {
                        QemuProductionHotForkWorldLifecycleFactoryError::ResourceBegin(error)
                    }
                };
                return Err(AttemptWorkerFailure::Retryable(error));
            }
        };
        if guard.resource_limits() != process_resources
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            guard.quarantine();
            drop(source_world);
            self.sources.restore(source_lease);
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::ResourceContractMismatch,
            ));
        }
        let bound = self
            .target_operations
            .bind_world(&mut guard, ram_factory.as_ref(), input);
        if let Err(message) = bound {
            guard.quarantine();
            drop(source_world);
            self.sources.restore(source_lease);
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
            ));
        }
        let maximum_nodes = input.scenario().world().vm_nodes().len();
        let resources = match QemuHotForkWorldResourceOwner::new_fork_target(
            guard,
            maximum_nodes,
            Arc::clone(&source_world),
        ) {
            Ok(resources) => resources,
            Err(error) => {
                drop(source_world);
                self.sources.restore(source_lease);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::Resource(error),
                ));
            }
        };
        let checkout_identity = source_lease.identity().clone();
        let outcome = self.launch_complete_world(
            input,
            context,
            scenario,
            checkout_identity,
            source_lease,
            source_world,
            continuation,
            resources,
            runtime_basis,
            ram_factory,
            #[cfg(test)]
            component_construction,
        );
        if outcome.source == CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine
            && outcome.result.is_err()
            && self.retained_installation.is_none()
        {
            self.sources.abandon();
        }
        outcome.result
    }
}
