//! Packaged retained-source composition, routing, and lifecycle ownership.

use super::*;

enum PackagedQemuInitialExecutionRunner<H, F> {
    HotFork(H),
    Fresh(F),
}

#[derive(Debug, thiserror::Error)]
enum PackagedQemuInitialExecutionRunnerError<H, F> {
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

pub(super) struct PackagedQemuInitialRunnerBuild<R> {
    pub(super) runners: Vec<R>,
    pub(super) hot_fork_owner: Option<Box<dyn PackagedQemuHotForkSourceOwner>>,
}

impl<R> PackagedQemuInitialRunnerBuild<R> {
    pub(super) fn fresh(runners: Vec<R>) -> Self {
        Self {
            runners,
            hot_fork_owner: None,
        }
    }

    fn hot_fork(runners: Vec<R>, owner: Box<dyn PackagedQemuHotForkSourceOwner>) -> Self {
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
    )?;
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
                            PackagedQemuInitialExecutionRunner::Fresh(
                                QemuFreshExecutionRunner::new(
                                    lifecycle_factory,
                                    QemuFreshModeledDriver,
                                ),
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
            for basis in source_bases {
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
                    basis,
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
                let hot_runner =
                    QemuHotForkWorldExecutionRunner::new(hot_factory, QemuFreshModeledDriver);
                runners.push(PackagedQemuInitialExecutionRunner::HotFork(
                    crate::QemuHotFirstExecutionRouter::new(hot_runner, fallback),
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
