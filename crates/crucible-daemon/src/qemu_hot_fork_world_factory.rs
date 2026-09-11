//! Whole-world retained-source selection, launch, execution, and recovery.
//!
//! The production factory checks out one complete prepared source world before
//! installing target resources, launches every running node into one atomic
//! assembly, and hands only the complete assembly to the production lifecycle
//! installer. The runner starts from the captured scheduler boundary, performs
//! ordinary modeled execution, shuts down every adopted node, and retains the
//! source and aggregate target authorities until durable publication.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
// crucible-lint: allow host-nondeterminism-state -- Wall time bounds operational cleanup while no modeled execution capability is exposed.
use std::thread;
use std::time::Instant;

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

use crate::qemu_campaign_lifecycle::{
    QemuFreshScenarioResourceError, QemuObservedFreshAttemptLifecycle,
    QemuObservedFreshAttemptLifecycleFactory, QemuObservedFreshAttemptLifecycleFactoryError,
    validate_fresh_qemu_scenario_resources,
};
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
pub struct QemuHotForkSourceWorldKey {
    template: crate::QemuHotForkTemplateKey,
    scenario: ContentHash,
    profile: ExecutorCompatibilityProfile,
    boundary: QemuHotForkSourceWorldBoundary,
}

/// Authenticated semantic boundary represented by one retained source world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkSourceWorldBoundary {
    /// The source is at the lineage's canonical scenario-genesis boundary.
    CanonicalGenesis,
    /// The source is at one completely authenticated exact-checkpoint boundary.
    ExactCheckpoint(ExactCheckpointId),
}

/// Failure while deriving the exact retained-source lookup key for an attempt.
#[derive(Debug, thiserror::Error)]
pub enum QemuHotForkSourceWorldKeyError {
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
            template: crate::QemuHotForkTemplateKey::new(lineage, configuration),
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
            template: crate::QemuHotForkTemplateKey::new(lineage, configuration),
            scenario,
            profile,
            boundary: QemuHotForkSourceWorldBoundary::ExactCheckpoint(checkpoint),
        }
    }

    /// Returns the lineage and paused-source identity used by shared accounting.
    #[must_use]
    pub const fn template_key(&self) -> crate::QemuHotForkTemplateKey {
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

    /// Returns the complete executor compatibility profile.
    #[must_use]
    pub const fn profile(&self) -> &ExecutorCompatibilityProfile {
        &self.profile
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
pub trait QemuHotForkSourceWorldProvider: source_world_provider_sealed::Sealed {
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
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error>;

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
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
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
    fn restore(&mut self, source: ProductionVmHotForkSourceWorld);

    /// Marks the checked-out source unavailable after its authority moved to quarantine.
    fn abandon(&mut self);
}

/// One exact prepared source world used by focused factory tests.
#[must_use = "retain the prepared source world for hot-fork execution"]
#[cfg(test)]
pub struct QemuSingleHotForkSourceWorldProvider {
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
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        let compatible = &self.key == key
            && self.source.as_ref().is_some_and(|source| {
                source.continuation().configuration().def.id() == key.scenario()
                    && source.continuation().configuration().id() == key.configuration()
            });
        let source = compatible.then(|| self.source.take()).flatten();
        self.checked_out = source
            .as_ref()
            .map(QemuHotForkSourceWorldCheckoutIdentity::capture);
        Ok(source)
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
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

/// Source provider used when the packaged executor has no retained world yet.
#[derive(Clone, Copy, Debug, Default)]
pub struct QemuUnavailableHotForkSourceWorldProvider;

impl source_world_provider_sealed::Sealed for QemuUnavailableHotForkSourceWorldProvider {}

impl QemuHotForkSourceWorldProvider for QemuUnavailableHotForkSourceWorldProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        _key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        Ok(None)
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        let _retained_for_process_lifetime = Box::leak(Box::new(source));
    }

    fn abandon(&mut self) {}
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

    fn quarantine(&mut self) {
        self.lifecycle_mut().quarantine();
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
pub struct QemuProductionHotForkWorldLifecycleFactory<S, R>
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

    /// Returns the retained source provider.
    #[must_use]
    pub const fn sources(&self) -> &S {
        &self.sources
    }

    /// Binds private post-shutdown lifecycles to the retained aggregate guard.
    #[must_use]
    pub fn with_auxiliary_resources(
        mut self,
        auxiliary_resources: QemuHotForkWorldAuxiliaryResourceBroker<R::Guard>,
    ) -> Self {
        self.auxiliary_resources = Some(auxiliary_resources);
        self
    }
}

/// Failure while constructing one complete production hot-fork world.
#[derive(Debug, thiserror::Error)]
pub enum QemuProductionHotForkWorldLifecycleFactoryError<P> {
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
        let Some(mut source_world) = self
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
        let source_matches = source_world.continuation().configuration().def.id()
            == source_key.scenario()
            && source_world.continuation().configuration().id() == source_key.configuration();
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
        let checkout_identity = QemuHotForkSourceWorldCheckoutIdentity::capture(&source_world);
        let source_world = Arc::new(Mutex::new(source_world));
        let outcome = self.launch_complete_world(
            input,
            context,
            scenario,
            checkout_identity,
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
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        continuation: crucible_api::ProductionVmHotForkWorldContinuation,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        runtime_basis: crate::AttemptExecutionRuntimeBasis,
    ) -> ProductionLifecycleStartOutcome<R::Guard, S::Error> {
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
                    let mut message = error.to_string();
                    let source = self.recover_proven_no_child_launch(
                        &checkout_identity,
                        source_world,
                        resources,
                        assembly,
                        error,
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
        let lifecycle = match complete.install_production_lifecycle(
            &scenario,
            input.scenario(),
            source_world,
            runtime_basis,
            self.run_state_root.clone(),
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
        checkout_identity: &QemuHotForkSourceWorldCheckoutIdentity,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        mut resources: QemuHotForkWorldResourceOwner<R::Guard>,
        assembly: ProductionAssembly<R::Guard>,
        error: LinuxQemuHotForkSourceWorldAttemptLaunchError,
        failure_message: &mut String,
    ) -> CheckedOutSourceDisposition {
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
        let source = match Arc::try_unwrap(recovered_source) {
            Ok(source) => source,
            Err(source) => {
                let _retained_for_process_lifetime = Box::leak(Box::new(source));
                return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
            }
        };
        let source = match source.into_inner() {
            Ok(source) => source,
            Err(poisoned) => {
                let _retained_for_process_lifetime = Box::leak(Box::new(poisoned.into_inner()));
                return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
            }
        };
        let mut source = match source.into_reusable() {
            Ok(source) => source,
            Err(failure) => {
                failure_message.push_str(&format!(
                    "; exact source-world reauthentication failed after rollback: {failure}"
                ));
                let _retained_for_process_lifetime = Box::leak(Box::new(failure));
                return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
            }
        };
        let source_reauthentication = if checkout_identity.matches(&source) {
            source
                .fork_continuation()
                .map(|_continuation| ())
                .map_err(|error| error.to_string())
        } else {
            Err(String::from("checkout identity changed"))
        };
        if let Err(error) = source_reauthentication {
            failure_message.push_str(&format!(
                "; exact source-world reauthentication failed after rollback: {error}"
            ));
            let _retained_for_process_lifetime = Box::leak(Box::new(source));
            return CheckedOutSourceDisposition::OwnedByLifecycleOrQuarantine;
        }
        self.sources.restore(source);
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

// crucible-lint: allow clippy-disallowed-method -- monotonic deadlines bound operational child cleanup and never enter campaign state.
#[allow(clippy::disallowed_methods)]
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
        let deadline = Instant::now().checked_add(running_wait);
        let Some(child) = children.get_mut(&node) else {
            return Err((
                children,
                format!("retained rollback child `{}` disappeared", node.name),
            ));
        };
        loop {
            let Some(remaining) = deadline
                .and_then(|limit| limit.checked_duration_since(Instant::now()))
                .filter(|remaining| !remaining.is_zero())
            else {
                let failure = format!(
                    "reconcile `{}` within configured SIGKILL and reap waits",
                    node.name
                );
                return Err((children, failure));
            };
            match child.rollback_step() {
                Ok(QemuHotForkReconciliationStep::ChildRunning) => {
                    thread::sleep(poll_wait.min(remaining));
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
            let Some(_remaining) = deadline
                .and_then(|limit| limit.checked_duration_since(Instant::now()))
                .filter(|remaining| !remaining.is_zero())
            else {
                let failure = format!(
                    "reconcile cancellation for `{}` within configured SIGKILL and reap waits",
                    node.name
                );
                return Err((children, failure));
            };
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
    abandoned_native_checkpoint: Option<crate::NativeCheckpointCleanup>,
    in_flight_native_checkpoint: Option<crucible_api::ProductionExactCheckpointRetirement>,
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
            abandoned_native_checkpoint: None,
            in_flight_native_checkpoint: None,
        }
    }

    /// Returns the whole-world lifecycle factory.
    #[must_use]
    pub const fn lifecycle_factory(&self) -> &F {
        &self.factory
    }

    /// Transfers a pending retained world to the factory's quarantine owner.
    pub(crate) fn quarantine_pending_execution(&mut self) {
        if let Some(lifecycle) = self.pending.take() {
            self.factory.quarantine(lifecycle);
        }
    }

    pub(crate) fn take_abandoned_native_checkpoint(
        &mut self,
    ) -> Option<crate::NativeCheckpointCleanup> {
        if let Some(retirement) = self.in_flight_native_checkpoint.take() {
            self.retain_native_checkpoint_cleanup(crate::NativeCheckpointCleanup::Quarantine(
                retirement,
            ));
        }
        self.abandoned_native_checkpoint.take()
    }

    fn retain_native_checkpoint_cleanup(&mut self, cleanup: crate::NativeCheckpointCleanup) {
        crate::NativeCheckpointCleanup::retain(&mut self.abandoned_native_checkpoint, cleanup);
    }

    fn register_native_checkpoint_capture(
        &mut self,
        checkpoint: &crate::CapturedAttemptCheckpoint,
    ) {
        let Some(retirement) = checkpoint.native_retirement() else {
            return;
        };
        if let Some(prior) = self.in_flight_native_checkpoint.replace(retirement) {
            self.retain_native_checkpoint_cleanup(crate::NativeCheckpointCleanup::Quarantine(
                prior,
            ));
        }
    }

    fn resolve_native_checkpoint_capture(
        &mut self,
        shutdown_succeeded: bool,
        result_succeeded: bool,
    ) {
        let Some(retirement) = self.in_flight_native_checkpoint.take() else {
            return;
        };
        if !shutdown_succeeded {
            self.retain_native_checkpoint_cleanup(crate::NativeCheckpointCleanup::Quarantine(
                retirement,
            ));
        } else if !result_succeeded {
            self.retain_native_checkpoint_cleanup(crate::NativeCheckpointCleanup::Retire(
                retirement,
            ));
        }
    }
}

/// Failure from one production whole-world execution phase.
#[derive(Debug)]
pub enum QemuHotForkWorldExecutionRunnerError<F, D> {
    /// A prior successful execution still owns publication authority.
    PriorReconciliationPending,
    /// The lifecycle factory failed after exact source selection.
    Factory(F),
    /// The factory returned a lifecycle for another supervisor incarnation.
    RuntimeBasisMismatch,
    /// The adopted start boundary could not be reconstructed exactly.
    Start(SchedulerError),
    /// The authenticated branch edge could not be applied at the captured parent.
    StartReplay(String),
    /// Modeled driving or result construction failed.
    Driver(D),
    /// A checkpoint result lacked a sticky supervisor request.
    UnsolicitedCheckpoint,
    /// Capturing a later exact checkpoint failed.
    CheckpointCapture(SchedulerError),
    /// Exact terminal execution fingerprint capture failed before teardown.
    TerminalFingerprintCapture(SchedulerError),
    /// Durable checkpoint handoff failed.
    CheckpointHandoff(CheckpointHandoffFailure),
    /// Final drain or adopted-node cleanup failed.
    Cleanup(SchedulerError),
    /// Cleanup failed after an earlier runner phase failed.
    CleanupAfterRunner {
        /// Earlier runner failure.
        failure: Box<QemuHotForkWorldExecutionRunnerError<F, D>>,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
    /// Durable publication reconciliation failed.
    Reconciliation(crucible_api::LifecycleApiError),
    /// A reconciliation callback arrived without pending authority.
    NoPendingReconciliation,
    /// Complete source-world recovery contradicted lifecycle ownership.
    SourceRecovery,
}

impl<F, D> std::fmt::Display for QemuHotForkWorldExecutionRunnerError<F, D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PriorReconciliationPending => {
                formatter.write_str("hot-fork world still awaits prior semantic reconciliation")
            }
            Self::Factory(_) => {
                formatter.write_str("construct production hot-fork world lifecycle")
            }
            Self::RuntimeBasisMismatch => formatter.write_str(
                "production hot-fork world runtime basis differs from its worker reservation",
            ),
            Self::Start(error) => {
                write!(formatter, "materialize production hot-fork start: {error}")
            }
            Self::StartReplay(error) => {
                write!(formatter, "apply production hot-fork branch start: {error}")
            }
            Self::Driver(_) => formatter.write_str("drive production hot-fork world"),
            Self::UnsolicitedCheckpoint => {
                formatter.write_str("production hot-fork driver returned an unsolicited checkpoint")
            }
            Self::CheckpointCapture(error) => {
                write!(formatter, "capture production hot-fork checkpoint: {error}")
            }
            Self::TerminalFingerprintCapture(error) => {
                write!(
                    formatter,
                    "capture production hot-fork terminal fingerprints: {error}"
                )
            }
            Self::CheckpointHandoff(error) => {
                write!(formatter, "handoff production hot-fork checkpoint: {error}")
            }
            Self::Cleanup(error) => {
                write!(formatter, "clean up production hot-fork world: {error}")
            }
            Self::CleanupAfterRunner { cleanup, .. } => write!(
                formatter,
                "production hot-fork cleanup failed after a prior runner failure: {cleanup}"
            ),
            Self::Reconciliation(error) => {
                write!(
                    formatter,
                    "reconcile production hot-fork publication: {error}"
                )
            }
            Self::NoPendingReconciliation => {
                formatter.write_str("production hot-fork runner has no pending reconciliation")
            }
            Self::SourceRecovery => formatter.write_str("recover production hot-fork source world"),
        }
    }
}

impl<F, D> std::error::Error for QemuHotForkWorldExecutionRunnerError<F, D>
where
    F: std::error::Error + 'static,
    D: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Factory(error) => Some(error),
            Self::Start(error)
            | Self::CheckpointCapture(error)
            | Self::TerminalFingerprintCapture(error)
            | Self::Cleanup(error) => Some(error),
            Self::Driver(error) => Some(error),
            Self::CheckpointHandoff(error) => Some(error),
            Self::CleanupAfterRunner { failure, .. } => Some(failure.as_ref()),
            Self::Reconciliation(error) => Some(error),
            Self::PriorReconciliationPending
            | Self::RuntimeBasisMismatch
            | Self::StartReplay(_)
            | Self::UnsolicitedCheckpoint
            | Self::NoPendingReconciliation
            | Self::SourceRecovery => None,
        }
    }
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
        if matches!(
            input.start(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            return Ok(QemuHotForkWorldExecutionAttempt::Declined);
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
                let (source, target) = match input.start() {
                    crate::CrucibleResolvedAttemptStart::Discover { configuration } => {
                        (configuration, configuration)
                    }
                    crate::CrucibleResolvedAttemptStart::Branch {
                        parent, selected, ..
                    } => (parent, selected),
                    crate::CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
                        let boundary = input.start().configuration();
                        (boundary, boundary)
                    }
                };
                let materialization =
                    crate::qemu_campaign_lifecycle::materialize_start_from::<F::Error, D::Error>(
                        &mut lifecycle,
                        input,
                        source.clone(),
                        target,
                        context,
                        materialization,
                    )
                    .map_err(map_hot_fork_start_replay_failure)?;
                if input.attempt().stop().accepts_next_choice() {
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
                        self.register_native_checkpoint_capture(&capture);
                        context
                            .prepare_and_stage_checkpoint(&capture)
                            .map(HotForkRunnerResult::Checkpoint)
                            .map_err(map_hot_fork_checkpoint_handoff_failure)
                    }
                }
            });
        let driven = driven.and_then(|pending| {
            lifecycle
                .prepare_terminal_fingerprints()
                .map(|()| pending)
                .map_err(map_hot_fork_terminal_fingerprint_capture_failure)
        });
        let cleanup = lifecycle.shutdown();
        self.resolve_native_checkpoint_capture(cleanup.is_ok(), driven.is_ok());
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

    /// Reconciles one bounded publication phase and recovers its source world.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable or terminal failure when no lifecycle
    /// awaits reconciliation, child reconciliation fails, or source recovery
    /// cannot be completed or quarantined.
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

fn map_hot_fork_start_replay_failure<F, D>(
    failure: AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(
            QemuHotForkWorldExecutionRunnerError::StartReplay(start_replay_message(error)),
        ),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(
            QemuHotForkWorldExecutionRunnerError::StartReplay(start_replay_message(error)),
        ),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(
            QemuHotForkWorldExecutionRunnerError::StartReplay(start_replay_message(error)),
        ),
    }
}

fn start_replay_message<F, D>(error: QemuFreshExecutionRunnerError<F, D>) -> String {
    match error {
        QemuFreshExecutionRunnerError::StartReplay(source) => source.to_string(),
        _ => String::from("start replay returned an unrelated execution phase failure"),
    }
}

impl<F, D> Drop for QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    fn drop(&mut self) {
        self.quarantine_pending_execution();
        if let Some(retirement) = self.in_flight_native_checkpoint.take() {
            crate::NativeCheckpointCleanup::Quarantine(retirement).retain_for_process_lifetime();
        }
        if let Some(cleanup) = self.abandoned_native_checkpoint.take() {
            cleanup.retain_for_process_lifetime();
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

fn map_hot_fork_terminal_fingerprint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        // crucible-lint: allow host-nondeterminism-state -- this arm only classifies an already-produced scheduler failure as terminal and cannot feed an observation back into forked execution.
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuHotForkWorldExecutionRunnerError::TerminalFingerprintCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
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
