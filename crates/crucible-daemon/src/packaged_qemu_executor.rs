//! Packaged production-QEMU executor composition for local campaigns.
//!
//! This module joins the durable assignment ledger, repository-backed
//! admission, fixed semantic worker pool, guarded fresh-QEMU runner, and
//! managed executor endpoint behind one owner. Each worker routes a durable
//! version-four root exclusively through the guarded production-resume path;
//! fresh execution never substitutes for an invalid root. The advertised
//! public production preparation captures one authenticated native baked
//! genesis, installs one concrete replay-oracle promotion owner per fixed
//! semantic worker, and advertises exact restore only with that complete owner
//! set. Test-only composition helpers can still omit promotion deliberately.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    AttemptResourceLimits, CampaignCodecError, CampaignExecutorStore, CampaignHash, CampaignName,
    CampaignRepository, CampaignRepositoryError, DaemonEpoch, ExecutionRetentionIntent,
    ExecutorCapabilitySet, ExecutorCompatibilityProfile, ExecutorDescription,
    ExecutorMaterializationCapability, ExecutorRejection, ObservationId, ScenarioArtifactId,
    SubmitAttemptRequest,
};
use crucible_cas::content_store::{DirectoryBlobBackend, ImmutableBlobBackend};
use crucible_qemu::{LinuxQemuAttemptHostConfig, QemuVmRealizationError};

use crate::{
    AssignmentLedgerError, AttemptAdmissionValidator, AttemptExecutionContext,
    CompletionValidationFailure, ComposedQemuAttemptResourceGuardFactory, CrucibleArtifactError,
    CrucibleExecutionModel, DirectoryAssignmentLedger, ExactCheckpointStore,
    ExactCheckpointStoreError, ExecutionCancellation, ExecutionCheckpointRequest, ExecutorCapacity,
    ExecutorLocalService, ExecutorLocalServiceError, ExecutorLocalServiceReport,
    ExecutorLocalServiceShutdown, ExecutorLoopbackEndpointConfig, ExecutorLoopbackEndpointError,
    ExecutorLoopbackListenerError, ExecutorLoopbackServerConfig,
    LinuxQemuAttemptHostResourceFactory, LocalCheckpointPromotionWorker,
    LocalExecutorCapabilityService, LocalExecutorPoolConfigError, LocalExecutorSupervisor,
    LocalExecutorWorkerPool, ProductionBakedGenesisCaptureError, ProductionBakedGenesisCheckpoint,
    ProductionBakedGenesisReplayFactory, ProductionCheckpointPromotionWorker,
    QemuAttemptExecutionRouter, QemuAttemptHostResourceFactory, QemuAttemptHostResourceOwner,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmLifecycleError,
    QemuAttemptProductionVmLifecycleFactory, QemuFreshExecutionRunner, QemuFreshModeledDriver,
    QemuProductionExactResumeExecutionRunner, RepositoryAttemptWorker,
    SharedQemuAttemptHostResourceFactory, UnixPeerExecutorIdentity,
    capture_production_baked_genesis, decode_crucible_scenario_artifact,
};

#[cfg(test)]
mod tests;

/// Complete deployment contract for one packaged local QEMU executor pool.
#[derive(Clone, Debug)]
pub struct PackagedQemuExecutorConfig {
    campaigns: BTreeSet<CampaignName>,
    endpoint: ExecutorLoopbackEndpointConfig,
    server: ExecutorLoopbackServerConfig,
    ledger_root: PathBuf,
    checkpoint_root: PathBuf,
    maximum_checkpoint_bytes: u64,
    daemon_epoch: DaemonEpoch,
    capacity: ExecutorCapacity,
    worker_count: usize,
    host_architecture: String,
    qemu_profile: String,
    store_namespace: CampaignHash,
    lifecycle: ProductionVmLifecycleConfig,
    host: LinuxQemuAttemptHostConfig,
}

impl PackagedQemuExecutorConfig {
    /// Builds one explicit fresh-QEMU executor deployment contract.
    ///
    /// # Errors
    ///
    /// Returns [`PackagedQemuExecutorConfigError`] when the campaign set or
    /// worker count is empty, the campaign set exceeds the runtime attachment
    /// ceiling, the checkpoint ceiling is zero, or the worker count exceeds the
    /// configured execution-slot ceiling.
    // crucible-lint: allow rust-allow -- the deployment contract keeps every startup-fixed authority and bound explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaigns: BTreeSet<CampaignName>,
        endpoint: ExecutorLoopbackEndpointConfig,
        server: ExecutorLoopbackServerConfig,
        ledger_root: impl Into<PathBuf>,
        checkpoint_root: impl Into<PathBuf>,
        maximum_checkpoint_bytes: u64,
        daemon_epoch: DaemonEpoch,
        capacity: ExecutorCapacity,
        worker_count: usize,
        host_architecture: impl Into<String>,
        qemu_profile: impl Into<String>,
        store_namespace: CampaignHash,
        lifecycle: ProductionVmLifecycleConfig,
        host: LinuxQemuAttemptHostConfig,
    ) -> Result<Self, PackagedQemuExecutorConfigError> {
        if campaigns.is_empty() {
            return Err(PackagedQemuExecutorConfigError::NoCampaigns);
        }
        if campaigns.len() > crate::MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES {
            return Err(PackagedQemuExecutorConfigError::TooManyCampaigns);
        }
        if worker_count == 0 {
            return Err(PackagedQemuExecutorConfigError::ZeroWorkers);
        }
        if worker_count
            > usize::try_from(capacity.maximum_concurrent_executions()).unwrap_or(usize::MAX)
        {
            return Err(PackagedQemuExecutorConfigError::WorkersExceedSlots);
        }
        if maximum_checkpoint_bytes == 0 {
            return Err(PackagedQemuExecutorConfigError::ZeroCheckpointBytes);
        }
        Ok(Self {
            campaigns,
            endpoint,
            server,
            ledger_root: ledger_root.into(),
            checkpoint_root: checkpoint_root.into(),
            maximum_checkpoint_bytes,
            daemon_epoch,
            capacity,
            worker_count,
            host_architecture: host_architecture.into(),
            qemu_profile: qemu_profile.into(),
            store_namespace,
            lifecycle,
            host,
        })
    }

    /// Returns the campaigns sharing this exact packaged executor pool.
    #[must_use]
    pub const fn campaigns(&self) -> &BTreeSet<CampaignName> {
        &self.campaigns
    }

    /// Returns the managed executor endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &ExecutorLoopbackEndpointConfig {
        &self.endpoint
    }

    /// Returns the crash-safe assignment-ledger root.
    #[must_use]
    pub fn ledger_root(&self) -> &Path {
        &self.ledger_root
    }

    /// Returns the durable exact-checkpoint object root.
    #[must_use]
    pub fn checkpoint_root(&self) -> &Path {
        &self.checkpoint_root
    }

    /// Returns the fixed modeled-worker count.
    #[must_use]
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the hard aggregate executor capacity.
    #[must_use]
    pub const fn capacity(&self) -> ExecutorCapacity {
        self.capacity
    }
}

/// Invalid packaged-executor deployment configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackagedQemuExecutorConfigError {
    /// No campaign was assigned to the packaged pool.
    #[error("packaged QEMU executor campaign set is empty")]
    NoCampaigns,
    /// More campaigns were assigned than the daemon attachment ceiling.
    #[error("packaged QEMU executor campaign set exceeds the attachment ceiling")]
    TooManyCampaigns,
    /// No semantic worker was configured.
    #[error("packaged QEMU executor worker count is zero")]
    ZeroWorkers,
    /// More semantic workers were requested than execution slots.
    #[error("packaged QEMU executor worker count exceeds its slot ceiling")]
    WorkersExceedSlots,
    /// No exact checkpoint can fit the configured immutable store.
    #[error("packaged QEMU executor checkpoint byte ceiling is zero")]
    ZeroCheckpointBytes,
}

/// Prepared packaged executor pool bound to one exact campaign repository.
pub struct PackagedQemuExecutor {
    repository_identity: Arc<CampaignRepository>,
    admitted_scenario: ScenarioArtifactId,
    endpoint: PathBuf,
    service: ExecutorLocalService<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
}

/// Running packaged executor-pool thread coupled to one daemon service lifecycle.
pub struct AttachedPackagedQemuExecutor {
    repository_identity: Arc<CampaignRepository>,
    admitted_scenario: ScenarioArtifactId,
    endpoint: PathBuf,
    shutdown: ExecutorLocalServiceShutdown<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    completion: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<Result<ExecutorLocalServiceReport, ExecutorLocalServiceError>>>,
}

impl AttachedPackagedQemuExecutor {
    /// Starts the fixed listener/worker owner on one named daemon thread.
    ///
    /// # Errors
    ///
    /// Returns [`PackagedQemuExecutorStartError`] when the operating system
    /// cannot create the single service-owner thread.
    pub fn start(service: PackagedQemuExecutor) -> Result<Self, PackagedQemuExecutorStartError> {
        let PackagedQemuExecutor {
            repository_identity,
            admitted_scenario,
            endpoint,
            service,
        } = service;
        let shutdown = service.shutdown_handle();
        let completion = Arc::new((Mutex::new(false), Condvar::new()));
        let thread_completion = Arc::clone(&completion);
        let thread = thread::Builder::new()
            .name(String::from("crucible-packaged-qemu-executor"))
            .spawn(move || {
                let _completion = PackagedQemuExecutorCompletionGuard(thread_completion);
                service.serve()
            })
            .map_err(|source| PackagedQemuExecutorStartError::Spawn { source })?;
        Ok(Self {
            repository_identity,
            admitted_scenario,
            endpoint,
            shutdown,
            completion,
            thread: Some(thread),
        })
    }

    /// Returns a cloneable completion signal for daemon lifecycle coupling.
    #[must_use]
    pub fn completion_handle(&self) -> PackagedQemuExecutorCompletion {
        PackagedQemuExecutorCompletion {
            state: Arc::clone(&self.completion),
        }
    }

    pub(crate) fn uses_repository(&self, repository: &Arc<CampaignRepository>) -> bool {
        Arc::ptr_eq(&self.repository_identity, repository)
    }

    /// Returns the exact scenario artifact backed by the native baked genesis.
    pub(crate) const fn admitted_scenario(&self) -> ScenarioArtifactId {
        self.admitted_scenario
    }

    /// Returns the exact managed endpoint served by this pool.
    pub(crate) fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Requests sticky listener and semantic-worker shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.shutdown();
    }

    /// Requests shutdown and joins the complete packaged executor owner.
    ///
    /// # Errors
    ///
    /// Returns [`PackagedQemuExecutorJoinError`] when the service reports a
    /// listener/worker failure or its owner thread escapes through a panic.
    pub fn shutdown_and_join(
        mut self,
    ) -> Result<ExecutorLocalServiceReport, PackagedQemuExecutorJoinError> {
        self.request_shutdown();
        self.join_inner()
    }

    fn join_inner(&mut self) -> Result<ExecutorLocalServiceReport, PackagedQemuExecutorJoinError> {
        let Some(thread) = self.thread.take() else {
            return Err(PackagedQemuExecutorJoinError::OwnerUnavailable);
        };
        thread
            .join()
            .map_err(|_| PackagedQemuExecutorJoinError::ThreadPanicked)?
            .map_err(Into::into)
    }
}

impl Drop for AttachedPackagedQemuExecutor {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.join_inner();
    }
}

/// Cloneable completion signal for one packaged executor incarnation.
#[derive(Clone)]
pub struct PackagedQemuExecutorCompletion {
    state: Arc<(Mutex<bool>, Condvar)>,
}

struct PackagedQemuExecutorCompletionGuard(Arc<(Mutex<bool>, Condvar)>);

impl Drop for PackagedQemuExecutorCompletionGuard {
    fn drop(&mut self) {
        let (done, changed) = self.0.as_ref();
        match done.lock() {
            Ok(mut done) => {
                *done = true;
                changed.notify_all();
            }
            Err(poisoned) => {
                *poisoned.into_inner() = true;
                changed.notify_all();
            }
        }
    }
}

impl PackagedQemuExecutorCompletion {
    /// Blocks until the packaged executor owner has returned.
    pub fn wait(&self) {
        let (done, changed) = self.state.as_ref();
        let mut done = match done.lock() {
            Ok(done) => done,
            Err(poisoned) => poisoned.into_inner(),
        };
        while !*done {
            done = match changed.wait(done) {
                Ok(done) => done,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }
}

/// Failure to start the packaged executor owner thread.
#[derive(Debug, thiserror::Error)]
pub enum PackagedQemuExecutorStartError {
    /// The operating system rejected the fixed service-owner thread.
    #[error("packaged QEMU executor owner thread could not be created")]
    Spawn {
        /// Underlying operating-system failure.
        #[source]
        source: std::io::Error,
    },
}

/// Terminal failure from one attached packaged executor.
#[derive(Debug, thiserror::Error)]
pub enum PackagedQemuExecutorJoinError {
    /// The owner was already joined.
    #[error("packaged QEMU executor owner is unavailable")]
    OwnerUnavailable,
    /// The owner thread escaped through an invariant panic.
    #[error("packaged QEMU executor owner thread panicked")]
    ThreadPanicked,
    /// The listener or semantic pool returned a terminal failure.
    #[error(transparent)]
    Service(#[from] ExecutorLocalServiceError),
}

/// Opens every durable/host owner and starts one packaged local QEMU executor.
///
/// Every configured repository head is authenticated in canonical campaign
/// order before host-resource acquisition or endpoint binding. All campaigns
/// must share the exact compatibility profile and scenario artifact captured
/// by the pool's one native baked genesis. The returned service owns the
/// listener, semantic workers, shared Linux host allocator, and exact
/// repository incarnation used for admission and result publication.
///
/// # Errors
///
/// Returns [`PackagedQemuExecutorError`] when a campaign or lineage cannot be
/// authenticated, configured campaign bases differ, a durable or host owner
/// cannot be acquired, capabilities do not encode, workers cannot start, or
/// the managed endpoint cannot bind.
pub fn prepare_packaged_qemu_executor(
    repository: Arc<CampaignRepository>,
    config: PackagedQemuExecutorConfig,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError> {
    let basis = authenticate_packaged_campaigns(&repository, &config.campaigns)?;
    let scenario_artifact = repository.load_scenario_artifact(basis.scenario)?;
    let scenario = decode_crucible_scenario_artifact(&scenario_artifact)?;
    let host = SharedQemuAttemptHostResourceFactory::new(
        LinuxQemuAttemptHostResourceFactory::open(config.host.clone())?,
    );
    let resource_ceiling = packaged_resource_ceiling(&config)?;
    let capture_context = AttemptExecutionContext::new(
        resource_ceiling,
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    );
    let baked_lifecycle = config.lifecycle.clone().with_run_state_root(
        config
            .lifecycle
            .run_state_root()
            .join("campaign-baked-genesis"),
    );
    let mut baked_factory = QemuAttemptProductionVmLifecycleFactory::new(
        baked_lifecycle,
        ComposedQemuAttemptResourceGuardFactory::new(host.clone()),
    );
    let baked = capture_production_baked_genesis(&mut baked_factory, &scenario, &capture_context)
        .map_err(|source| PackagedQemuExecutorError::BakedGenesis(Box::new(source)))?;
    compose_packaged_qemu_executor_with_baked_genesis(repository, basis, config, host, baked)
}

#[derive(Clone)]
struct PackagedCampaignBasis {
    profile: ExecutorCompatibilityProfile,
    scenario: ScenarioArtifactId,
}

fn authenticate_packaged_campaigns(
    repository: &CampaignRepository,
    campaigns: &BTreeSet<CampaignName>,
) -> Result<PackagedCampaignBasis, PackagedQemuExecutorError> {
    let mut campaigns = campaigns.iter();
    let first = campaigns
        .next()
        .ok_or(PackagedQemuExecutorError::NoCampaigns)?;
    let head = repository.head(first.as_str())?;
    let lineage = repository.load_lineage(head.snapshot().lineage())?;
    let basis = PackagedCampaignBasis {
        profile: ExecutorCompatibilityProfile::from_lineage(&lineage),
        scenario: lineage.scenario_content(),
    };

    for campaign in campaigns {
        let head = repository.head(campaign.as_str())?;
        let lineage = repository.load_lineage(head.snapshot().lineage())?;
        if !basis.profile.admits(&lineage) {
            return Err(PackagedQemuExecutorError::CampaignCompatibilityMismatch {
                campaign: campaign.clone(),
            });
        }
        if lineage.scenario_content() != basis.scenario {
            return Err(PackagedQemuExecutorError::CampaignScenarioMismatch {
                campaign: campaign.clone(),
            });
        }
    }
    Ok(basis)
}

#[cfg(test)]
pub(crate) fn compose_packaged_qemu_executor<H>(
    repository: Arc<CampaignRepository>,
    profile: ExecutorCompatibilityProfile,
    scenario: ScenarioArtifactId,
    config: PackagedQemuExecutorConfig,
    host: H,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
{
    compose_packaged_qemu_executor_with_checkpoint_promotions(
        repository,
        PackagedCampaignBasis { profile, scenario },
        config,
        host,
        Vec::<DisabledPackagedCheckpointPromotionWorker>::new(),
    )
}

#[cfg(test)]
struct DisabledPackagedCheckpointPromotionWorker;

#[cfg(test)]
impl LocalCheckpointPromotionWorker for DisabledPackagedCheckpointPromotionWorker {
    type Error = ();

    fn prepare(
        &mut self,
        _work: crate::CheckpointPromotionRestartWork,
        _cancellation: crate::ExecutionCancellation,
    ) -> Result<crate::PreparedPausedCheckpointPromotionRestart, crate::AttemptWorkerFailure<()>>
    {
        Err(crate::AttemptWorkerFailure::Terminal(()))
    }
}

#[cfg(test)]
fn compose_packaged_qemu_executor_with_checkpoint_promotions<H, P>(
    repository: Arc<CampaignRepository>,
    basis: PackagedCampaignBasis,
    config: PackagedQemuExecutorConfig,
    host: H,
    promotion_workers: Vec<P>,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
    P: LocalCheckpointPromotionWorker + Send + 'static,
{
    let shared = SharedQemuAttemptHostResourceFactory::new(host);
    compose_packaged_qemu_executor_with_promotion_builder(
        repository,
        basis,
        config,
        shared,
        move |_store, _checkpoints, _shared, _run_state_root, _worker_count| promotion_workers,
    )
}

fn compose_packaged_qemu_executor_with_baked_genesis<H>(
    repository: Arc<CampaignRepository>,
    basis: PackagedCampaignBasis,
    config: PackagedQemuExecutorConfig,
    shared: SharedQemuAttemptHostResourceFactory<H>,
    baked: ProductionBakedGenesisCheckpoint,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
{
    compose_packaged_qemu_executor_with_promotion_builder(
        repository,
        basis,
        config,
        shared,
        move |store, checkpoints, shared, run_state_root, worker_count| {
            (0..worker_count)
                .map(|slot| {
                    let factory = ProductionBakedGenesisReplayFactory::new(
                        baked.clone(),
                        ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                    );
                    ProductionCheckpointPromotionWorker::new(
                        store.clone(),
                        Arc::clone(checkpoints),
                        run_state_root.join(format!("worker-{slot:03}")),
                        factory,
                    )
                })
                .collect::<Vec<_>>()
        },
    )
}

fn compose_packaged_qemu_executor_with_promotion_builder<H, P, B>(
    repository: Arc<CampaignRepository>,
    basis: PackagedCampaignBasis,
    config: PackagedQemuExecutorConfig,
    shared: SharedQemuAttemptHostResourceFactory<H>,
    build_promotions: B,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
    P: LocalCheckpointPromotionWorker + Send + 'static,
    B: FnOnce(
        &CampaignExecutorStore,
        &Arc<ExactCheckpointStore>,
        &SharedQemuAttemptHostResourceFactory<H>,
        &Path,
        usize,
    ) -> Vec<P>,
{
    let ledger = DirectoryAssignmentLedger::open(&config.ledger_root)?;
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "campaign-exact-checkpoints",
        &config.checkpoint_root,
    ));
    let checkpoints = Arc::new(ExactCheckpointStore::new(
        checkpoint_backend,
        config.maximum_checkpoint_bytes,
    )?);
    let resource_ceiling = packaged_resource_ceiling(&config)?;
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let worker_state_root = config.lifecycle.run_state_root().join("campaign-workers");
    let promotion_state_root = config
        .lifecycle
        .run_state_root()
        .join("campaign-checkpoint-promotions");
    let promotion_workers = build_promotions(
        &store,
        &checkpoints,
        &shared,
        &promotion_state_root,
        config.worker_count,
    );
    let promotion_enabled = !promotion_workers.is_empty();
    let mut materialization = BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]);
    if promotion_enabled {
        materialization.insert(ExecutorMaterializationCapability::ExactRestore);
    }
    let capabilities = ExecutorCapabilitySet::new(
        basis.profile.clone(),
        config.host_architecture,
        BTreeSet::from([config.qemu_profile]),
        materialization,
        config.capacity.maximum_concurrent_executions(),
        resource_ceiling,
        BTreeSet::from([config.store_namespace]),
    )?;
    let description = ExecutorDescription::new(config.daemon_epoch, capabilities)?;
    let supervisor = LocalExecutorSupervisor::new(
        ledger,
        PackagedAttemptAdmission::new(Arc::clone(&repository), basis.profile, basis.scenario),
        config.daemon_epoch,
        config.capacity,
    );
    let executor = LocalExecutorCapabilityService::new(supervisor, description)?;

    let workers = (0..config.worker_count)
        .map(|slot| {
            let lifecycle = config
                .lifecycle
                .clone()
                .with_run_state_root(worker_state_root.join(format!("worker-{slot:03}")));
            let fresh_lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
                lifecycle.clone(),
                ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
            );
            let resume_lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
                lifecycle,
                ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
            );
            let fresh = QemuFreshExecutionRunner::new(fresh_lifecycles, QemuFreshModeledDriver);
            let resume = QemuProductionExactResumeExecutionRunner::new(
                Arc::clone(&checkpoints),
                resume_lifecycles,
                QemuFreshModeledDriver,
            );
            let runner = QemuAttemptExecutionRouter::new(fresh, resume);
            let model = CrucibleExecutionModel::new(store.clone(), runner);
            RepositoryAttemptWorker::new(store.clone(), model)
        })
        .collect();
    let pool = if promotion_enabled {
        LocalExecutorWorkerPool::start_with_checkpoint_promotions(
            executor,
            store,
            checkpoints,
            workers,
            promotion_workers,
        )?
    } else {
        LocalExecutorWorkerPool::start(executor, store, checkpoints, workers)?
    };
    let endpoint = config.endpoint.path().to_owned();
    let listener = config.endpoint.bind()?;
    let service = ExecutorLocalService::from_managed_listener(
        listener,
        pool,
        UnixPeerExecutorIdentity::new(
            config.endpoint.owner_user_id(),
            config.endpoint.owner_group_id(),
        ),
        config.server,
    )?;
    Ok(PackagedQemuExecutor {
        repository_identity: repository,
        admitted_scenario: basis.scenario,
        endpoint,
        service,
    })
}

fn packaged_resource_ceiling(
    config: &PackagedQemuExecutorConfig,
) -> Result<AttemptResourceLimits, CampaignCodecError> {
    AttemptResourceLimits::new(
        config.capacity.maximum_vcpus(),
        config.capacity.maximum_resident_bytes(),
        config.capacity.maximum_disk_bytes(),
        config.capacity.maximum_execution_quanta(),
    )
}

#[derive(Clone)]
struct PackagedAttemptAdmission {
    repository: Arc<CampaignRepository>,
    profile: ExecutorCompatibilityProfile,
    scenario: ScenarioArtifactId,
}

impl PackagedAttemptAdmission {
    const fn new(
        repository: Arc<CampaignRepository>,
        profile: ExecutorCompatibilityProfile,
        scenario: ScenarioArtifactId,
    ) -> Self {
        Self {
            repository,
            profile,
            scenario,
        }
    }

    fn validate_scenario(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        let lineage = self
            .repository
            .load_lineage(request.lineage())
            .map_err(|error| error.executor_rejection())?;
        if lineage.scenario_content() != self.scenario {
            return Err(ExecutorRejection::Incompatible);
        }
        Ok(())
    }
}

impl AttemptAdmissionValidator for PackagedAttemptAdmission {
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        self.repository
            .validate_executor_request_with_profile(request, &self.profile)
            .map_err(|error| error.executor_rejection())?;
        self.validate_scenario(request)
    }

    fn validate_completion(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        self.repository
            .validate_executor_completion_with_profile(request, observation, &self.profile)
            .map_err(completion_validation_failure)?;
        self.validate_scenario(request)
            .map_err(|_| CompletionValidationFailure::Incompatible)
    }
}

fn completion_validation_failure(error: CampaignRepositoryError) -> CompletionValidationFailure {
    match error.executor_rejection() {
        ExecutorRejection::UnavailableInput => CompletionValidationFailure::UnavailableInput,
        ExecutorRejection::Unauthorized => CompletionValidationFailure::Unauthorized,
        ExecutorRejection::Incompatible
        | ExecutorRejection::Backpressure
        | ExecutorRejection::ConflictingAssignment => CompletionValidationFailure::Incompatible,
    }
}

/// Failure to acquire or compose one packaged local QEMU executor.
#[derive(Debug, thiserror::Error)]
pub enum PackagedQemuExecutorError {
    /// The internal deployment contract named no campaign.
    #[error("packaged QEMU executor has no campaign")]
    NoCampaigns,
    /// A configured campaign does not share the pool's exact compatibility basis.
    #[error(
        "campaign `{}` is incompatible with the packaged QEMU executor pool",
        campaign.as_str()
    )]
    CampaignCompatibilityMismatch {
        /// Incompatible configured campaign.
        campaign: CampaignName,
    },
    /// A configured campaign does not share the pool's native baked scenario.
    #[error(
        "campaign `{}` uses another packaged QEMU scenario",
        campaign.as_str()
    )]
    CampaignScenarioMismatch {
        /// Campaign whose exact scenario artifact differs.
        campaign: CampaignName,
    },
    /// Campaign or lineage authentication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// The retained Crucible scenario artifact failed semantic authentication.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// Exact baked-genesis capture or complete native admission failed.
    #[error(transparent)]
    BakedGenesis(Box<ProductionBakedGenesisCaptureError<QemuAttemptProductionVmLifecycleError>>),
    /// Durable assignment-ledger acquisition failed.
    #[error(transparent)]
    Ledger(#[from] AssignmentLedgerError),
    /// Durable exact-checkpoint store construction failed.
    #[error(transparent)]
    Checkpoints(#[from] ExactCheckpointStoreError),
    /// Linux process/storage resource ownership could not be acquired.
    #[error(transparent)]
    Host(#[from] QemuVmRealizationError),
    /// An immutable executor capability or resource bound was invalid.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// Fixed semantic-worker construction failed.
    #[error(transparent)]
    Pool(#[from] LocalExecutorPoolConfigError),
    /// Managed endpoint acquisition failed.
    #[error(transparent)]
    Endpoint(#[from] ExecutorLoopbackEndpointError),
    /// Fixed listener construction failed.
    #[error(transparent)]
    Listener(#[from] ExecutorLoopbackListenerError),
}
