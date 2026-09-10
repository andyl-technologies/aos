//! Packaged retained-source composition, routing, and lifecycle ownership.

use super::*;

pub(crate) enum PackagedQemuInitialExecutionRunner<H, F> {
    HotFork(H),
    Fresh(F),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PackagedQemuInitialExecutionRunnerError<H, F> {
    #[error("packaged hot-first QEMU execution failed")]
    HotFork(#[source] H),
    #[error("packaged fresh QEMU execution failed")]
    Fresh(#[source] F),
}

pub(super) type PackagedQemuHotForkDemotionError = AuthenticatedHotCheckpointDemotionError<
    QemuHotCheckpointFallbackAuthenticationError,
    QemuHotForkSourceWorldDemotionError,
>;

/// Complete retained-source shutdown failure report for a packaged executor.
pub type PackagedQemuHotForkSourceShutdownError =
    SharedManagedQemuHotForkSourceWorldShutdownError<PackagedQemuHotForkDemotionError>;

pub(super) trait PackagedQemuHotForkSourceOwner: Send {
    fn orderly_shutdown(&self) -> Result<(), PackagedQemuHotForkSourceShutdownError>;

    fn retention_admin(&self) -> Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>;
}

struct ConcretePackagedQemuHotForkSourceOwner<D, R>
where
    D: crate::HotCheckpointTemplateDemotionSink<crate::ManagedQemuHotForkSourceWorld>
        + Send
        + 'static,
    D::Error: std::fmt::Debug,
    R: crate::HotCheckpointFallbackRetentionStore + Send + 'static,
{
    pool: SharedManagedQemuHotForkSourceWorldPool<D, R>,
    retention: Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>,
}

impl<D, R> PackagedQemuHotForkSourceOwner for ConcretePackagedQemuHotForkSourceOwner<D, R>
where
    D: crate::HotCheckpointTemplateDemotionSink<
            crate::ManagedQemuHotForkSourceWorld,
            Error = PackagedQemuHotForkDemotionError,
        > + Send
        + 'static,
    R: crate::HotCheckpointFallbackRetentionStore + Send + 'static,
{
    fn orderly_shutdown(&self) -> Result<(), PackagedQemuHotForkSourceShutdownError> {
        self.pool.orderly_shutdown().map(|_demotions| ())
    }

    fn retention_admin(&self) -> Arc<dyn crate::HotCheckpointFallbackRetentionAdmin> {
        Arc::clone(&self.retention)
    }
}

impl<D, R> Drop for ConcretePackagedQemuHotForkSourceOwner<D, R>
where
    D: crate::HotCheckpointTemplateDemotionSink<crate::ManagedQemuHotForkSourceWorld>
        + Send
        + 'static,
    D::Error: std::fmt::Debug,
    R: crate::HotCheckpointFallbackRetentionStore + Send + 'static,
{
    fn drop(&mut self) {
        let _ = self.pool.orderly_shutdown();
    }
}

struct PackagedDemandedQemuHotForkSourceProvider<D, R, G>
where
    D: crate::HotCheckpointTemplateDemotionSink<crate::ManagedQemuHotForkSourceWorld>,
    R: crate::HotCheckpointFallbackRetentionStore,
{
    pool: SharedManagedQemuHotForkSourceWorldPool<D, R>,
    provider: SharedQemuHotForkSourceWorldProvider<D, R>,
    checkpoints: Arc<ExactCheckpointStore>,
    factories: BTreeMap<CampaignLineageId, ProductionQemuHotForkSourceFactory<G>>,
    signals: HotCheckpointHotnessSignals,
}

impl<D, R, G> crate::qemu_hot_fork_world_factory::source_world_provider_sealed::Sealed
    for PackagedDemandedQemuHotForkSourceProvider<D, R, G>
where
    D: crate::HotCheckpointTemplateDemotionSink<crate::ManagedQemuHotForkSourceWorld>,
    R: crate::HotCheckpointFallbackRetentionStore,
{
}

#[derive(Debug, thiserror::Error)]
enum PackagedDemandedQemuHotForkSourceProviderError {
    #[error(transparent)]
    Pool(#[from] SharedQemuHotForkSourceWorldProviderError),
    #[error("restore demanded exact hot-fork source: {diagnostic}")]
    Capture {
        class: crucible::SchedulerOperationalFailureClass,
        diagnostic: String,
    },
    #[error("shared source-world pool lock is poisoned during exact admission")]
    AdmissionPoisoned,
    #[error("admit demanded exact hot-fork source")]
    Admission(
        #[source]
        Box<ManagedQemuHotForkAuthenticatedAdmissionError<PackagedQemuHotForkDemotionError>>,
    ),
    #[error("retain demanded exact hot-fork fallback")]
    Retention(
        #[source]
        Box<
            crate::managed_qemu_hot_fork_source_world_pool::SharedManagedQemuHotForkColdRetentionError<
                PackagedQemuHotForkDemotionError,
            >,
        >,
    ),
    #[error("retire declined demanded exact hot-fork source")]
    Retirement(#[source] crucible_api::LifecycleApiError),
}

impl<D, R, G> QemuHotForkSourceWorldProvider for PackagedDemandedQemuHotForkSourceProvider<D, R, G>
where
    D: crate::HotCheckpointTemplateDemotionSink<
            crate::ManagedQemuHotForkSourceWorld,
            Error = PackagedQemuHotForkDemotionError,
        > + Send,
    R: crate::HotCheckpointFallbackRetentionStore + Send,
    G: QemuAttemptResourceGuardFactory,
    G::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Error = PackagedDemandedQemuHotForkSourceProviderError;

    fn checkout(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        self.provider.checkout(key).map_err(Into::into)
    }

    fn checkout_for_attempt(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        if let Some(source) = self.provider.checkout(key)? {
            return Ok(Some(source));
        }
        let QemuHotForkSourceWorldBoundary::ExactCheckpoint(checkpoint) = key.boundary() else {
            return Ok(None);
        };
        let lineage = key.template_key().lineage();
        let Some(factory) = self.factories.get_mut(&lineage) else {
            return Ok(None);
        };
        let Some(source) = factory
            .capture_exact(&self.checkpoints, input, context)
            .map_err(|source| {
                let class = source.failure_class(context.cancellation().is_canceled());
                let diagnostic = source.to_string();
                let _retained_for_process_lifetime = Box::leak(Box::new(source));
                Self::Error::Capture { class, diagnostic }
            })?
        else {
            return Ok(None);
        };

        match self
            .pool
            .admit_authenticated_exact_source(source, self.signals)
        {
            Ok(_commit) => self.provider.checkout(key).map_err(Into::into),
            Err(
                crate::managed_qemu_hot_fork_source_world_pool::SharedManagedQemuHotForkExactAdmissionFailure::Poisoned,
            ) => Err(Self::Error::AdmissionPoisoned),
            Err(
                crate::managed_qemu_hot_fork_source_world_pool::SharedManagedQemuHotForkExactAdmissionFailure::Admission(
                    failure,
                ),
            ) => self.reconcile_exact_admission_failure(key, checkpoint, failure),
        }
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        self.provider.restore(source);
    }

    fn abandon(&mut self) {
        self.provider.abandon();
    }

    fn failure_class(error: &Self::Error) -> crucible::SchedulerOperationalFailureClass {
        match error {
            Self::Error::Capture { class, .. } => *class,
            Self::Error::Pool(_) | Self::Error::AdmissionPoisoned | Self::Error::Retention(_) => {
                crucible::SchedulerOperationalFailureClass::Retryable
            }
            Self::Error::Admission(_) | Self::Error::Retirement(_) => {
                crucible::SchedulerOperationalFailureClass::Terminal
            }
        }
    }
}

impl<D, R, G> PackagedDemandedQemuHotForkSourceProvider<D, R, G>
where
    D: crate::HotCheckpointTemplateDemotionSink<
            crate::ManagedQemuHotForkSourceWorld,
            Error = PackagedQemuHotForkDemotionError,
        > + Send,
    R: crate::HotCheckpointFallbackRetentionStore + Send,
{
    fn reconcile_exact_admission_failure(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
        checkpoint: crucible_campaign::ExactCheckpointId,
        failure: ManagedQemuHotForkAuthenticatedAdmissionFailure<PackagedQemuHotForkDemotionError>,
    ) -> Result<
        Option<ProductionVmHotForkSourceWorld>,
        PackagedDemandedQemuHotForkSourceProviderError,
    > {
        let failure = match failure {
            ManagedQemuHotForkAuthenticatedAdmissionFailure::Binding(failure) => {
                let (source, error) = failure.into_parts();
                if let Err(retirement) = source.retire() {
                    return Err(PackagedDemandedQemuHotForkSourceProviderError::Retirement(
                        retirement,
                    ));
                }
                return Err(PackagedDemandedQemuHotForkSourceProviderError::Admission(
                    Box::new(ManagedQemuHotForkAuthenticatedAdmissionError::Binding(
                        error,
                    )),
                ));
            }
            ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) => failure,
        };
        let (candidate, cleanup_slot, error) = failure.into_parts();
        if cleanup_slot.is_none()
            && matches!(
                &error,
                ManagedQemuHotForkSourceWorldAdmissionError::DuplicateSource
            )
        {
            retire_managed_demanded_source(candidate)?;
            return self.provider.checkout(key).map_err(Into::into);
        }
        if cleanup_slot.is_none()
            && matches!(
                &error,
                ManagedQemuHotForkSourceWorldAdmissionError::Rejected(_)
            )
        {
            if let Err(source) = self
                .pool
                .retain_cold_fallback(key.template_key(), HotCheckpointFallback::Exact(checkpoint))
            {
                let _retained_for_process_lifetime = Box::leak(Box::new(candidate));
                return Err(PackagedDemandedQemuHotForkSourceProviderError::Retention(
                    Box::new(source),
                ));
            }
            retire_managed_demanded_source(candidate)?;
            return Ok(None);
        }

        let _retained_for_process_lifetime = Box::leak(Box::new(candidate));
        let error = ManagedQemuHotForkAuthenticatedAdmissionError::Admission {
            cleanup_slot,
            source: error,
        };
        Err(PackagedDemandedQemuHotForkSourceProviderError::Admission(
            Box::new(error),
        ))
    }
}

fn retire_managed_demanded_source(
    candidate: crate::ManagedQemuHotForkSourceWorld,
) -> Result<(), PackagedDemandedQemuHotForkSourceProviderError> {
    let source = candidate.into_source().map_err(|candidate| {
        let _retained_for_process_lifetime = Box::leak(candidate);
        PackagedDemandedQemuHotForkSourceProviderError::AdmissionPoisoned
    })?;
    source
        .retire()
        .map_err(PackagedDemandedQemuHotForkSourceProviderError::Retirement)
}

pub(super) struct PackagedQemuInitialRunnerBuild<R> {
    pub(super) runners: Vec<(R, QemuAttemptExecutionEvidence)>,
    pub(super) hot_fork_owner: Option<Box<dyn PackagedQemuHotForkSourceOwner>>,
}

impl<R> PackagedQemuInitialRunnerBuild<R> {
    pub(super) fn fresh(runners: Vec<(R, QemuAttemptExecutionEvidence)>) -> Self {
        Self {
            runners,
            hot_fork_owner: None,
        }
    }

    fn hot_fork(
        runners: Vec<(R, QemuAttemptExecutionEvidence)>,
        owner: Box<dyn PackagedQemuHotForkSourceOwner>,
    ) -> Self {
        Self {
            runners,
            hot_fork_owner: Some(owner),
        }
    }
}

impl<H, F> crate::CrucibleExecutionRunner for PackagedQemuInitialExecutionRunner<H, F>
where
    H: crate::CrucibleExecutionRunner,
    F: crate::CrucibleExecutionRunner,
{
    type Error = PackagedQemuInitialExecutionRunnerError<H::Error, F::Error>;

    fn execute(
        &mut self,
        input: &crate::CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<crate::CrucibleExecutionOutcome, crate::AttemptWorkerFailure<Self::Error>> {
        match self {
            Self::HotFork(runner) => runner
                .execute(input, context)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::HotFork)),
            Self::Fresh(runner) => runner
                .execute(input, context)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::Fresh)),
        }
    }

    fn reconcile_execution(
        &mut self,
        disposition: crate::AttemptExecutionDisposition,
    ) -> Result<crate::AttemptExecutionReconciliationStep, crate::AttemptWorkerFailure<Self::Error>>
    {
        match self {
            Self::HotFork(runner) => runner
                .reconcile_execution(disposition)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::HotFork)),
            Self::Fresh(runner) => runner
                .reconcile_execution(disposition)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::Fresh)),
        }
    }

    fn quarantine_pending_execution(&mut self) {
        match self {
            Self::HotFork(runner) => runner.quarantine_pending_execution(),
            Self::Fresh(runner) => runner.quarantine_pending_execution(),
        }
    }
}

impl<H, F> crate::QemuSelectedOriginVerifier for PackagedQemuInitialExecutionRunner<H, F>
where
    H: crate::QemuSelectedOriginVerifier,
    F: crate::QemuSelectedOriginVerifier,
{
    fn verify_selected_origin(
        &mut self,
        input: &crate::CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<crate::QemuSavepointReplayProof, crate::AttemptWorkerFailure<Self::Error>> {
        match self {
            Self::HotFork(runner) => runner
                .verify_selected_origin(input, context, target)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::HotFork)),
            Self::Fresh(runner) => runner
                .verify_selected_origin(input, context, target)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::Fresh)),
        }
    }
}

impl<H, F> crate::QemuAttemptStartVerifier for PackagedQemuInitialExecutionRunner<H, F>
where
    H: crate::QemuAttemptStartVerifier,
    F: crate::QemuAttemptStartVerifier,
{
    fn verify_attempt_start(
        &mut self,
        input: &crate::CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<crate::QemuAttemptStartReplayProof, crate::AttemptWorkerFailure<Self::Error>> {
        match self {
            Self::HotFork(runner) => runner
                .verify_attempt_start(input, context)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::HotFork)),
            Self::Fresh(runner) => runner
                .verify_attempt_start(input, context)
                .map_err(|failure| failure.map(PackagedQemuInitialExecutionRunnerError::Fresh)),
        }
    }
}

pub(super) fn authenticate_packaged_hot_fork_launch(
    lifecycle: &ProductionVmLifecycleConfig,
    hot_fork: &PackagedQemuHotForkConfig,
    profile: &ExecutorCompatibilityProfile,
) -> Result<(), PackagedQemuExecutorError> {
    let launch = hot_fork.launch_identity();
    if lifecycle.executable() != launch.qemu() || lifecycle.plugin() != launch.plugin() {
        return Err(PackagedQemuExecutorError::HotForkLaunchPathMismatch);
    }
    if profile.qemu_build() != launch.qemu_build_id() {
        return Err(PackagedQemuExecutorError::QemuBuildMismatch {
            expected: profile.qemu_build().to_owned(),
            actual: launch.qemu_build_id().to_owned(),
        });
    }
    Ok(())
}

pub(super) fn compose_packaged_qemu_executor_with_baked_genesis<H>(
    repository: Arc<CampaignRepository>,
    checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
    hot_fork_retention: DirectoryHotCheckpointFallbackRetentionStore,
    basis: PackagedCampaignBasis,
    config: PackagedQemuExecutorConfig,
    shared: SharedQemuAttemptHostResourceFactory<H>,
    baked: BTreeMap<ScenarioArtifactId, ProductionBakedGenesisCheckpoint>,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    let catalog = ProductionBakedGenesisReplayCatalogFactory::new(
        baked.into_values(),
        ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
    )?
    .with_savepoint_replay_config(config.lifecycle.clone());
    let promotion_catalog = catalog.clone();
    let source_catalog = catalog;
    let source_bases = basis.sources.values().cloned().collect::<Vec<_>>();
    let hot_fork = config.hot_fork.clone();

    compose_packaged_qemu_executor_with_builders(
        repository,
        checkpoint_backend,
        basis,
        config,
        shared,
        move |store, checkpoints, _shared, run_state_root, worker_count| {
            (0..worker_count)
                .map(|slot| {
                    ProductionCheckpointPromotionWorker::new(
                        store.clone(),
                        Arc::clone(checkpoints),
                        run_state_root.join(format!("worker-{slot:03}")),
                        promotion_catalog.clone(),
                    )
                })
                .collect::<Vec<_>>()
        },
        move |store,
              checkpoints,
              shared,
              worker_state_root,
              worker_count,
              lifecycles,
              lifecycle_config,
              resource_ceiling| {
            let fresh_runners = || {
                PackagedQemuInitialRunnerBuild::fresh(
                    (0..worker_count)
                        .map(|slot| {
                            let lifecycle = lifecycle_config.clone().with_run_state_root(
                                worker_state_root.join(format!("worker-{slot:03}")),
                            );
                            let lifecycle_factory = PackagedStatusLifecycleFactory {
                                inner: QemuAttemptProductionVmLifecycleFactory::new(
                                    lifecycle,
                                    ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                                ),
                                lifecycles: lifecycles.clone(),
                            };
                            let (lifecycle_factory, evidence) =
                                QemuObservedFreshAttemptLifecycleFactory::with_evidence(
                                    lifecycle_factory,
                                );
                            (
                                PackagedQemuInitialExecutionRunner::Fresh(
                                    QemuFreshExecutionRunner::new(
                                        lifecycle_factory,
                                        QemuFreshModeledDriver,
                                    ),
                                ),
                                evidence,
                            )
                        })
                        .collect(),
                )
            };
            let Some(hot_fork) = hot_fork else {
                return Ok(fresh_runners());
            };

            let retention_admin: Arc<dyn crate::HotCheckpointFallbackRetentionAdmin> =
                Arc::new(hot_fork_retention.clone());
            let authenticator = QemuHotCheckpointFallbackAuthenticator::new(
                store.clone(),
                Arc::clone(checkpoints),
                source_catalog.clone(),
            );
            let demotions = AuthenticatedHotCheckpointDemotionSink::new(
                authenticator,
                QemuHotForkSourceWorldDemoter,
            );
            let mut source_factories = Vec::with_capacity(source_bases.len());
            for basis in &source_bases {
                let lineage = basis.lineage_id();
                let fallback = HotCheckpointFallback::Thin(basis.source_artifact());
                let source_lifecycle = lifecycle_config.clone().with_run_state_root(
                    lifecycle_config
                        .run_state_root()
                        .join("campaign-hot-fork-sources")
                        .join(lineage.to_string()),
                );
                let lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
                    source_lifecycle,
                    ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                );
                let factory = ProductionQemuHotForkSourceFactory::new(
                    basis.clone(),
                    lifecycles,
                    hot_fork.launch_identity().qemu_build_id(),
                )?;
                source_factories.push((lineage, fallback, factory));
            }

            let mut pool = ManagedQemuHotForkSourceWorldPool::open(
                hot_fork.limits(),
                demotions,
                hot_fork_retention,
            )?;

            let capture_context = AttemptExecutionContext::new(
                resource_ceiling,
                ExecutionRetentionIntent::Discard,
                ExecutionCancellation::default(),
                ExecutionCheckpointRequest::default(),
            );
            for (lineage, fallback, mut source_factory) in source_factories {
                let source = match source_factory.capture(&capture_context) {
                    Ok(source) => source,
                    Err(source) => {
                        let source = PackagedQemuExecutorError::HotForkSourceCapture {
                            lineage,
                            source: Box::new(source),
                        };
                        return Err(cleanup_captured_sources(source, &mut pool));
                    }
                };
                if let Err(failure) =
                    pool.admit_authenticated_source(source, hot_fork.initial_signals(), fallback)
                {
                    reconcile_source_admission_failure(lineage, fallback, failure, &mut pool)?;
                }
            }

            let pool = SharedManagedQemuHotForkSourceWorldPool::new(pool);
            let owner: Box<dyn PackagedQemuHotForkSourceOwner> =
                Box::new(ConcretePackagedQemuHotForkSourceOwner {
                    pool: pool.clone(),
                    retention: retention_admin,
                });
            let mut runners = Vec::with_capacity(worker_count);
            for slot in 0..worker_count {
                let evidence = QemuAttemptExecutionEvidence::default();
                let lifecycle = lifecycle_config
                    .clone()
                    .with_run_state_root(worker_state_root.join(format!("worker-{slot:03}")));
                let fallback_lifecycles = PackagedStatusLifecycleFactory {
                    inner: QemuAttemptProductionVmLifecycleFactory::new(
                        lifecycle,
                        ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                    ),
                    lifecycles: lifecycles.clone(),
                };
                let fallback_lifecycles =
                    QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
                        fallback_lifecycles,
                        evidence.clone(),
                    );
                let fallback =
                    QemuFreshExecutionRunner::new(fallback_lifecycles, QemuFreshModeledDriver);
                let provider = match pool.provider() {
                    Ok(provider) => provider,
                    Err(source) => {
                        return Err(cleanup_shared_sources(
                            PackagedQemuExecutorError::HotForkProvider(source),
                            owner.as_ref(),
                        ));
                    }
                };
                let mut demanded_factories = BTreeMap::new();
                for basis in &source_bases {
                    let lineage = basis.lineage_id();
                    let source_lifecycle = lifecycle_config.clone().with_run_state_root(
                        lifecycle_config
                            .run_state_root()
                            .join("campaign-hot-fork-demanded")
                            .join(format!("worker-{slot:03}"))
                            .join(lineage.to_string()),
                    );
                    let lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
                        source_lifecycle,
                        ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                    );
                    let factory = ProductionQemuHotForkSourceFactory::new(
                        basis.clone(),
                        lifecycles,
                        hot_fork.launch_identity().qemu_build_id(),
                    )?;
                    demanded_factories.insert(lineage, factory);
                }
                let provider = PackagedDemandedQemuHotForkSourceProvider {
                    pool: pool.clone(),
                    provider,
                    checkpoints: Arc::clone(checkpoints),
                    factories: demanded_factories,
                    signals: hot_fork.initial_signals(),
                };
                let hot_factory = QemuProductionHotForkWorldLifecycleFactory::new(
                    provider,
                    ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                    worker_state_root.join(format!("worker-{slot:03}")),
                    hot_fork.shutdown_policy(),
                    hot_fork.async_policy(),
                );
                let hot_factory = PackagedStatusHotForkFactory {
                    inner: hot_factory,
                    lifecycles: lifecycles.clone(),
                };
                let hot_factory = QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
                    hot_factory,
                    evidence.clone(),
                );
                let hot_runner =
                    QemuHotForkWorldExecutionRunner::new(hot_factory, QemuFreshModeledDriver);
                runners.push((
                    PackagedQemuInitialExecutionRunner::HotFork(
                        crate::QemuHotFirstExecutionRouter::new(hot_runner, fallback),
                    ),
                    evidence,
                ));
            }

            Ok(PackagedQemuInitialRunnerBuild::hot_fork(runners, owner))
        },
    )
}

fn reconcile_source_admission_failure<D, R>(
    lineage: CampaignLineageId,
    fallback: HotCheckpointFallback,
    failure: ManagedQemuHotForkAuthenticatedAdmissionFailure<PackagedQemuHotForkDemotionError>,
    pool: &mut ManagedQemuHotForkSourceWorldPool<D, R>,
) -> Result<(), PackagedQemuExecutorError>
where
    D: crate::HotCheckpointTemplateDemotionSink<
            crate::ManagedQemuHotForkSourceWorld,
            Error = PackagedQemuHotForkDemotionError,
        >,
    R: crate::HotCheckpointFallbackRetentionStore,
{
    let failure = match failure {
        ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) => failure,
        ManagedQemuHotForkAuthenticatedAdmissionFailure::Binding(failure) => {
            let (source_world, error) = failure.into_parts();
            let _retained_for_process_lifetime = Box::leak(Box::new(source_world));
            let source = PackagedQemuExecutorError::HotForkSourceAdmission {
                lineage,
                source: Box::new(ManagedQemuHotForkAuthenticatedAdmissionError::Binding(
                    error,
                )),
            };
            return Err(cleanup_captured_sources(source, pool));
        }
    };
    let (candidate, cleanup_slot, error) = failure.into_parts();
    if !matches!(
        &error,
        ManagedQemuHotForkSourceWorldAdmissionError::Rejected(_)
    ) {
        let _retained_for_process_lifetime = Box::leak(Box::new(candidate));
        let source = PackagedQemuExecutorError::HotForkSourceAdmission {
            lineage,
            source: Box::new(ManagedQemuHotForkAuthenticatedAdmissionError::Admission {
                cleanup_slot,
                source: error,
            }),
        };
        return Err(cleanup_captured_sources(source, pool));
    }

    reconcile_policy_declined_source(lineage, fallback, candidate, cleanup_slot, error, pool)
}

fn reconcile_policy_declined_source<D, R>(
    lineage: CampaignLineageId,
    fallback: HotCheckpointFallback,
    candidate: crate::ManagedQemuHotForkSourceWorld,
    cleanup_slot: Option<crate::HotCheckpointFallbackSlot>,
    rejection: ManagedQemuHotForkSourceWorldAdmissionError<PackagedQemuHotForkDemotionError>,
    pool: &mut ManagedQemuHotForkSourceWorldPool<D, R>,
) -> Result<(), PackagedQemuExecutorError>
where
    D: crate::HotCheckpointTemplateDemotionSink<
            crate::ManagedQemuHotForkSourceWorld,
            Error = PackagedQemuHotForkDemotionError,
        >,
    R: crate::HotCheckpointFallbackRetentionStore,
{
    let key = candidate.key().template_key();
    if let Err(retention) = pool.retain_cold_fallback(key, fallback) {
        let (retirement, candidate_quarantined) = cleanup_policy_declined_candidate(candidate);
        let source = PackagedQemuExecutorError::HotForkRejectedSourceCleanup {
            lineage,
            retention,
            retirement,
            candidate_quarantined,
        };
        return Err(cleanup_captured_sources(source, pool));
    }

    let source_world = match candidate.into_source() {
        Ok(source_world) => source_world,
        Err(candidate) => {
            let _retained_for_process_lifetime = Box::leak(candidate);
            let source = PackagedQemuExecutorError::HotForkSourceAdmission {
                lineage,
                source: Box::new(ManagedQemuHotForkAuthenticatedAdmissionError::Admission {
                    cleanup_slot,
                    source: rejection,
                }),
            };
            return Err(cleanup_captured_sources(source, pool));
        }
    };
    if let Err(source) = source_world.retire() {
        let source = PackagedQemuExecutorError::HotForkRejectedSourceRetirement { lineage, source };
        return Err(cleanup_captured_sources(source, pool));
    }
    Ok(())
}

fn cleanup_policy_declined_candidate(
    candidate: crate::ManagedQemuHotForkSourceWorld,
) -> (Option<Box<crucible_api::LifecycleApiError>>, bool) {
    match candidate.into_source() {
        Ok(source_world) => (source_world.retire().err().map(Box::new), false),
        Err(candidate) => {
            let _retained_for_process_lifetime = Box::leak(candidate);
            (None, true)
        }
    }
}

fn cleanup_captured_sources<D, R>(
    source: PackagedQemuExecutorError,
    pool: &mut ManagedQemuHotForkSourceWorldPool<D, R>,
) -> PackagedQemuExecutorError
where
    D: crate::HotCheckpointTemplateDemotionSink<
            crate::ManagedQemuHotForkSourceWorld,
            Error = PackagedQemuHotForkDemotionError,
        >,
    R: crate::HotCheckpointFallbackRetentionStore,
{
    match pool.orderly_shutdown() {
        Ok(_demotions) => source,
        Err(cleanup) => PackagedQemuExecutorError::HotForkStartupCleanup {
            source: Box::new(source),
            cleanup: Box::new(SharedManagedQemuHotForkSourceWorldShutdownError::Sources(
                cleanup,
            )),
        },
    }
}

fn cleanup_shared_sources(
    source: PackagedQemuExecutorError,
    owner: &dyn PackagedQemuHotForkSourceOwner,
) -> PackagedQemuExecutorError {
    match owner.orderly_shutdown() {
        Ok(()) => source,
        Err(cleanup) => PackagedQemuExecutorError::HotForkStartupCleanup {
            source: Box::new(source),
            cleanup: Box::new(cleanup),
        },
    }
}
