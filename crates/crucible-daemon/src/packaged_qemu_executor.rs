//! Packaged production-QEMU executor composition for one local campaign.
//!
//! This module joins the durable assignment ledger, repository-backed
//! admission, fixed semantic worker pool, guarded fresh-QEMU runner, and
//! managed executor endpoint behind one owner. The advertised materialization
//! set is deliberately limited to thin replay until the concrete live
//! exact-resume driver is composed; unsupported roots therefore fail closed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    AttemptResourceLimits, CampaignCodecError, CampaignExecutorStore, CampaignHash, CampaignName,
    CampaignRepository, CampaignRepositoryError, DaemonEpoch, ExecutorCapabilitySet,
    ExecutorCompatibilityProfile, ExecutorDescription, ExecutorMaterializationCapability,
};
use crucible_cas::content_store::{DirectoryBlobBackend, ImmutableBlobBackend};
use crucible_qemu::{LinuxQemuAttemptHostConfig, QemuVmRealizationError};

use crate::{
    AssignmentLedgerError, ComposedQemuAttemptResourceGuardFactory, CrucibleExecutionModel,
    DirectoryAssignmentLedger, ExactCheckpointStore, ExactCheckpointStoreError, ExecutorCapacity,
    ExecutorLocalService, ExecutorLocalServiceError, ExecutorLocalServiceReport,
    ExecutorLocalServiceShutdown, ExecutorLoopbackEndpointConfig, ExecutorLoopbackEndpointError,
    ExecutorLoopbackListenerError, ExecutorLoopbackServerConfig,
    LinuxQemuAttemptHostResourceFactory, LocalExecutorCapabilityService,
    LocalExecutorPoolConfigError, LocalExecutorSupervisor, LocalExecutorWorkerPool,
    QemuAttemptHostResourceFactory, QemuAttemptHostResourceOwner, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmLifecycleFactory, QemuFreshExecutionRunner, QemuFreshModeledDriver,
    RepositoryAttemptAdmission, RepositoryAttemptWorker, SharedQemuAttemptHostResourceFactory,
    UnixPeerExecutorIdentity,
};

#[cfg(test)]
mod tests;

/// Complete deployment contract for one packaged local QEMU executor.
#[derive(Clone, Debug)]
pub struct PackagedQemuExecutorConfig {
    campaign: CampaignName,
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
    /// Returns [`PackagedQemuExecutorConfigError`] when the worker count or
    /// checkpoint ceiling is zero, or the worker count exceeds the configured
    /// execution-slot ceiling.
    // crucible-lint: allow rust-allow -- the deployment contract keeps every startup-fixed authority and bound explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign: CampaignName,
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
            campaign,
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

    /// Returns the campaign whose exact lineage this executor admits.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
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

/// Prepared packaged executor bound to one exact campaign repository.
pub struct PackagedQemuExecutor {
    repository_identity: Arc<CampaignRepository>,
    service: ExecutorLocalService<DirectoryAssignmentLedger, RepositoryAttemptAdmission>,
}

/// Running packaged executor thread coupled to one daemon service lifecycle.
pub struct AttachedPackagedQemuExecutor {
    repository_identity: Arc<CampaignRepository>,
    shutdown: ExecutorLocalServiceShutdown<DirectoryAssignmentLedger, RepositoryAttemptAdmission>,
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
/// The repository head is authenticated before any executor endpoint is bound.
/// The returned service owns the listener, semantic workers, shared Linux host
/// allocator, and exact repository incarnation used for admission and result
/// publication.
///
/// # Errors
///
/// Returns [`PackagedQemuExecutorError`] when the campaign or lineage cannot be
/// authenticated, a durable or host owner cannot be acquired, capabilities do
/// not encode, workers cannot start, or the managed endpoint cannot bind.
pub fn prepare_packaged_qemu_executor(
    repository: Arc<CampaignRepository>,
    config: PackagedQemuExecutorConfig,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError> {
    let head = repository.head(config.campaign.as_str())?;
    let lineage = repository.load_lineage(head.snapshot().lineage())?;
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())?;
    compose_packaged_qemu_executor(repository, profile, config, host)
}

fn compose_packaged_qemu_executor<H>(
    repository: Arc<CampaignRepository>,
    profile: ExecutorCompatibilityProfile,
    config: PackagedQemuExecutorConfig,
    host: H,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
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
    let resource_ceiling = AttemptResourceLimits::new(
        config.capacity.maximum_vcpus(),
        config.capacity.maximum_resident_bytes(),
        config.capacity.maximum_disk_bytes(),
        config.capacity.maximum_execution_quanta(),
    )?;
    let capabilities = ExecutorCapabilitySet::new(
        profile.clone(),
        config.host_architecture,
        BTreeSet::from([config.qemu_profile]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        config.capacity.maximum_concurrent_executions(),
        resource_ceiling,
        BTreeSet::from([config.store_namespace]),
    )?;
    let description = ExecutorDescription::new(config.daemon_epoch, capabilities)?;
    let supervisor = LocalExecutorSupervisor::new(
        ledger,
        RepositoryAttemptAdmission::new(Arc::clone(&repository), profile),
        config.daemon_epoch,
        config.capacity,
    );
    let executor = LocalExecutorCapabilityService::new(supervisor, description)?;

    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let shared = SharedQemuAttemptHostResourceFactory::new(host);
    let worker_state_root = config.lifecycle.run_state_root().join("campaign-workers");
    let workers = (0..config.worker_count)
        .map(|slot| {
            let resources = ComposedQemuAttemptResourceGuardFactory::new(shared.clone());
            let lifecycle = config
                .lifecycle
                .clone()
                .with_run_state_root(worker_state_root.join(format!("worker-{slot:03}")));
            let lifecycles = QemuAttemptProductionVmLifecycleFactory::new(lifecycle, resources);
            let runner = QemuFreshExecutionRunner::new(lifecycles, QemuFreshModeledDriver);
            let model = CrucibleExecutionModel::new(store.clone(), runner);
            RepositoryAttemptWorker::new(store.clone(), model)
        })
        .collect();
    let pool = LocalExecutorWorkerPool::start(executor, store, checkpoints, workers)?;
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
        service,
    })
}

/// Failure to acquire or compose one packaged local QEMU executor.
#[derive(Debug, thiserror::Error)]
pub enum PackagedQemuExecutorError {
    /// Campaign or lineage authentication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
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
