//! Whole-world retained-source selection, launch, execution, and recovery.
//!
//! The production factory checks out one complete prepared source world before
//! installing target resources, launches every running node into one atomic
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
use crucible::{ContentHash, ScenarioDef, SchedulerError, SchedulerOperationalFailureClass};
use crucible_api::vm_lifecycle::ProductionVmHotForkNodeBoundary;
use crucible_api::{
    ProductionVmHotForkNodeServiceState, ProductionVmHotForkSourceWorld, ProductionVmNodeGeneration,
};
use crucible_campaign::{
    CampaignCodecError, CampaignLineageId, ExactCheckpointId, ExecutorCompatibilityProfile,
};
use crucible_qemu::{
    LinuxQemuHotForkChildProcessAuthority, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuHotForkChildProcessOwner, QemuHotForkLaunchError, QemuShutdownPolicy,
    QemuVmRealizationError,
};

use crate::managed_qemu_hot_fork_source_world_pool::QemuHotForkSourceWorldLease;
use crate::qemu_campaign_lifecycle::{
    QemuFreshScenarioResourceError, QemuObservedFreshAttemptLifecycle,
    QemuObservedFreshAttemptLifecycleFactory, QemuObservedFreshAttemptLifecycleFactoryError,
    validate_fresh_qemu_scenario_resources,
};
use crate::qemu_hot_fork_world::QemuHotForkProductionLifecycleContext;
use crate::supervision::ProcessDeadline;
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionDisposition,
    AttemptExecutionProduct, AttemptExecutionReconciliationStep, AttemptWorkerFailure,
    CheckpointHandoffFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleMaterializationTier, LinuxQemuHotForkReconciliationBackend,
    LinuxQemuHotForkSourceWorldAttemptLaunchError, LinuxQemuHotForkWorldAttemptLaunchFailure,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory, QemuFreshAttemptDriver, QemuFreshAttemptLifecycle,
    QemuFreshAttemptLifecycleOwner, QemuFreshDriveOutcome, QemuFreshExecutionRunnerError,
    QemuHotForkAttemptReconciliation, QemuHotForkReconciliationStep, QemuHotForkWorldAssembly,
    QemuHotForkWorldAuxiliaryResourceBroker, QemuHotForkWorldNodeTarget,
    QemuHotForkWorldResourceOwner, QemuProductionHotForkWorldLifecycle,
};

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

    fn for_execution(
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
    pub(crate) fn capture(source: &ProductionVmHotForkSourceWorld) -> Self {
        Self {
            scenario: source.continuation().configuration().def.id(),
            configuration: source.continuation().configuration().id(),
            nodes: source.continuation().nodes().to_vec(),
        }
    }

    pub(crate) fn matches(&self, source: &ProductionVmHotForkSourceWorld) -> bool {
        self.scenario == source.continuation().configuration().def.id()
            && self.configuration == source.continuation().configuration().id()
            && self.nodes == source.continuation().nodes()
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
        }
    }

    /// Returns whether the exact source world is currently reusable.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.source.is_some()
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
        let compatible = &self.key == key
            && self.source.as_ref().is_some_and(|source| {
                source.continuation().configuration().def.id() == key.scenario()
                    && source.continuation().configuration().id() == key.configuration()
            });
        let source = compatible.then(|| self.source.take()).flatten();
        self.checked_out = source
            .as_ref()
            .map(QemuHotForkSourceWorldCheckoutIdentity::capture);
        Ok(source
            .map(|source| QemuHotForkSourceWorldLease::exclusive(self.key.template_key(), source)))
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        let source = match source.into_exclusive_source() {
            Ok(source) => source,
            Err(source) => {
                let _retained_for_process_lifetime = Box::leak(source);
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
        self.checked_out = None;
        if self.source.is_some() {
            let _ = source.retire();
            return;
        }
        match source.into_reusable() {
            Ok(source) => self.source = Some(source),
            Err(failure) => {
                let _retained_for_process_lifetime = Box::leak(Box::new(failure));
            }
        }
    }

    fn abandon(&mut self) {
        self.checked_out = None;
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
    ) -> Result<AttemptExecutionReconciliationStep, crucible_api::LifecycleApiError>;
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
    ) -> Result<AttemptExecutionReconciliationStep, crucible_api::LifecycleApiError> {
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
pub(crate) struct QemuProductionHotForkWorldLifecycleFactory<S, R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard,
{
    sources: S,
    resources: R,
    auxiliary_resources: Option<QemuHotForkWorldAuxiliaryResourceBroker<R::Guard>>,
    run_state_root: PathBuf,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
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
            auxiliary_resources: None,
            run_state_root: run_state_root.into(),
            shutdown_policy,
            async_policy,
        }
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
    /// The source provider could not complete exact checkout.
    #[error("check out production hot-fork source world")]
    SourceProvider(#[source] P),
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

type ProductionChild<G> = QemuHotForkAttemptReconciliation<
    LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
>;

type ProductionAssembly<G> = QemuHotForkWorldAssembly<ProductionChild<G>>;

struct ProvenNoChildLaunchRecovery<'a> {
    checkout_identity: &'a QemuHotForkSourceWorldCheckoutIdentity,
    source_lease: QemuHotForkSourceWorldLease,
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    error: LinuxQemuHotForkSourceWorldAttemptLaunchError,
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
        if matches!(
            input.start(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        }
        let runtime_basis = context
            .runtime_basis()
            .ok_or_else(|| AttemptWorkerFailure::Terminal(Self::Error::MissingRuntimeBasis))?;
        validate_fresh_qemu_scenario_resources(input.scenario(), context.resources()).map_err(
            |error| AttemptWorkerFailure::Terminal(Self::Error::ScenarioResources(error)),
        )?;
        let scenario = input.scenario().scenario_def();
        let source_key = QemuHotForkSourceWorldKey::for_execution(input, context, runtime_basis)
            .map_err(|error| AttemptWorkerFailure::Terminal(Self::Error::SourceKey(error)))?;
        let Some(source_lease) = self
            .sources
            .checkout_for_attempt(input, context, &source_key)
            .map_err(|error| {
                let class = S::failure_class(&error);
                let error = Self::Error::SourceProvider(error);
                match class {
                    SchedulerOperationalFailureClass::Retryable => {
                        AttemptWorkerFailure::Retryable(error)
                    }
                    SchedulerOperationalFailureClass::Canceled => {
                        AttemptWorkerFailure::Canceled(error)
                    }
                    SchedulerOperationalFailureClass::Terminal => {
                        AttemptWorkerFailure::Terminal(error)
                    }
                }
            })?
        else {
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        };
        let source_world = source_lease.source_owner();
        let mut source = match source_world.lock() {
            Ok(source) => source,
            Err(_error) => {
                self.sources.abandon();
                let _retained_source_lease = Box::leak(Box::new(source_lease));
                return Err(AttemptWorkerFailure::Retryable(Self::Error::Source(
                    String::from("retained source-world lock is poisoned"),
                )));
            }
        };
        let source_matches = source.continuation().configuration().def.id()
            == source_key.scenario()
            && source.continuation().configuration().id() == source_key.configuration();
        if !source_matches {
            drop(source);
            drop(source_world);
            self.sources.restore(source_lease);
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        }
        if source.continuation().nodes().iter().any(|boundary| {
            boundary.service_state() == ProductionVmHotForkNodeServiceState::PoweredOff
        }) {
            drop(source);
            drop(source_world);
            self.sources.restore(source_lease);
            return Ok(QemuHotForkWorldLifecycleStart::Declined);
        }
        let continuation = match source.fork_continuation() {
            Ok(continuation) => continuation,
            Err(error) => {
                drop(source);
                drop(source_world);
                self.sources.restore(source_lease);
                return Err(AttemptWorkerFailure::Retryable(Self::Error::Source(
                    error.to_string(),
                )));
            }
        };
        drop(source);
        let mut guard =
            match self
                .resources
                .begin(context.resources(), context.cancellation().clone(), None)
            {
                Ok(guard) => guard,
                Err(failure) => {
                    let (error, _) = failure.into_parts();
                    drop(source_world);
                    self.sources.restore(source_lease);
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
            drop(source_world);
            self.sources.restore(source_lease);
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::ResourceContractMismatch,
            ));
        }
        let maximum_nodes = input.scenario().world().vm_nodes().len();
        let resources = match QemuHotForkWorldResourceOwner::new(guard, maximum_nodes) {
            Ok(resources) => resources,
            Err(error) => {
                drop(source_world);
                self.sources.restore(source_lease);
                return Err(AttemptWorkerFailure::Terminal(Self::Error::Resource(error)));
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
        );
        if outcome.source == CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine
            && outcome.result.is_err()
        {
            self.sources.abandon();
        }
        outcome.result
    }

    fn recover(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        match lifecycle.into_source_lease() {
            Ok(source) => {
                self.sources.restore(source);
                Ok(())
            }
            Err(lifecycle) => Err(*lifecycle),
        }
    }

    fn quarantine(&mut self, mut lifecycle: Self::Lifecycle) {
        lifecycle.quarantine();
        self.sources.abandon();
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
        checkout_identity: QemuHotForkSourceWorldCheckoutIdentity,
        source_lease: QemuHotForkSourceWorldLease,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        continuation: crucible_api::ProductionVmHotForkWorldContinuation,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        runtime_basis: crate::AttemptExecutionRuntimeBasis,
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
        for (node, (service_state, generation)) in boundaries {
            match service_state {
                ProductionVmHotForkNodeServiceState::PermanentlyFailed => continue,
                ProductionVmHotForkNodeServiceState::PoweredOff => {
                    quarantine_failed_assembly(source_world, resources, assembly, None);
                    return ProductionLifecycleStartOutcome::failed(
                        AttemptWorkerFailure::Terminal(
                            QemuProductionHotForkWorldLifecycleFactoryError::Source(String::from(
                                "powered-off node passed the capability fallback boundary",
                            )),
                        ),
                        CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                    );
                }
                ProductionVmHotForkNodeServiceState::Running => {}
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
            let child = match QemuHotForkAttemptReconciliation::launch_from_source_world(
                Arc::clone(&source_world),
                node.clone(),
                &mut resources,
                identity,
                assembly.child_launch_token(),
            ) {
                Ok(child) => child,
                Err(error) => {
                    let mut message = error.to_string();
                    let Some(source_lease) = source_lease.take() else {
                        quarantine_failed_assembly(source_world, resources, assembly, None);
                        return ProductionLifecycleStartOutcome::failed(
                            AttemptWorkerFailure::Terminal(
                                QemuProductionHotForkWorldLifecycleFactoryError::Assembly(
                                    String::from("source lease disappeared before launch recovery"),
                                ),
                            ),
                            CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                        );
                    };
                    let recovery = ProvenNoChildLaunchRecovery {
                        checkout_identity: &checkout_identity,
                        source_lease,
                        source_world,
                        error,
                    };
                    let source = self.recover_proven_no_child_launch(
                        recovery,
                        resources,
                        assembly,
                        &mut message,
                    );
                    return ProductionLifecycleStartOutcome::failed(
                        AttemptWorkerFailure::Retryable(
                            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
                        ),
                        source,
                    );
                }
            };
            let mut child = child;
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
            if let Err(error) = child.install_scheduler_node(
                node.clone(),
                self.shutdown_policy,
                self.async_policy,
                QemuCrashDetector::new(node.name.clone()),
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
        let complete = match assembly.publish() {
            Ok(complete) => complete,
            Err(incomplete) => {
                let message = incomplete.to_string();
                let assembly = incomplete.into_assembly();
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
        );
        let lifecycle = match complete.install_production_lifecycle(
            install_context,
            source_lease,
            source_world,
            resources,
            self.auxiliary_resources.clone(),
        ) {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                return ProductionLifecycleStartOutcome::failed(
                    AttemptWorkerFailure::Terminal(
                        QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(error),
                    ),
                    CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine,
                );
            }
        };
        ProductionLifecycleStartOutcome::started(lifecycle)
    }

    fn recover_proven_no_child_launch(
        &mut self,
        recovery: ProvenNoChildLaunchRecovery<'_>,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        assembly: ProductionAssembly<R::Guard>,
        failure_message: &mut String,
    ) -> CheckedOutSourceDisposition {
        let ProvenNoChildLaunchRecovery {
            checkout_identity,
            source_lease,
            source_world,
            error,
        } = recovery;
        // Only the typed no-child outcome plus successful reservation rollback
        // permits source reuse. Every other launch state retains all authority.
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
            quarantine_failed_rollback(source_world, Some(recovered_source), resources, children);
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }

        let children = assembly.into_rollback_children();
        if let Err((children, rollback)) =
            rollback_hot_fork_children(children, self.shutdown_policy)
        {
            failure_message.push_str(&format!("; clean-rejection rollback failed: {rollback}"));
            drop(recovered_source);
            quarantine_failed_rollback(source_world, None, resources, children);
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }

        if let Err(error) = resources.finish() {
            failure_message.push_str(&format!(
                "; aggregate target release failed after rollback: {error}"
            ));
            drop(recovered_source);
            quarantine_failed_rollback(source_world, None, resources, BTreeMap::new());
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }
        drop(resources);
        drop(source_world);
        drop(recovered_source);
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
    mut children: BTreeMap<crucible::NodeId, C>,
    shutdown_policy: QemuShutdownPolicy,
) -> Result<(), (BTreeMap<crucible::NodeId, C>, String)>
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
    _children: BTreeMap<crucible::NodeId, ProductionChild<G>>,
}

fn quarantine_failed_rollback<G>(
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    recovered_source: Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>>,
    mut resources: QemuHotForkWorldResourceOwner<G>,
    mut children: BTreeMap<crucible::NodeId, ProductionChild<G>>,
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

mod runner;

pub(crate) use runner::{
    AttemptWorkerFailureExt, QemuHotForkWorldExecutionAttempt, QemuHotForkWorldExecutionRunner,
    QemuHotForkWorldExecutionRunnerError,
};

#[cfg(test)]
#[path = "qemu_hot_fork_world_factory/tests.rs"]
mod tests;
