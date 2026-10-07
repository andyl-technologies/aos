//! Packaged production-QEMU executor composition for local campaigns.
//!
//! This module joins the durable assignment ledger, repository-backed
//! admission, fixed semantic worker pool, guarded fresh-QEMU runner, and
//! managed executor endpoint behind one owner. Each worker routes a durable
//! authenticated paged root exclusively through the guarded production-resume path;
//! fresh execution never substitutes for an invalid root. The advertised
//! public production preparation captures an authenticated native baked
//! genesis for every scenario in its closed catalog, installs one concrete
//! replay-oracle promotion owner per fixed semantic worker, and advertises
//! exact restore only with that complete owner set. Test-only composition
//! helpers can still omit promotion deliberately.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use crucible::ScenarioDefForm;
use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    AttemptId, AttemptResourceLimits, CampaignCodecError, CampaignExecutorStore, CampaignHash,
    CampaignLineageId, CampaignName, CampaignOperationalStatusProvider, CampaignRepository,
    CampaignRepositoryError, DaemonEpoch, ExecutorCapabilitySet, ExecutorCompatibilityProfile,
    ExecutorDescription, ExecutorMaterializationCapability, ExecutorRejection,
    FindingCandidateBundleId, ObservationId, ScenarioArtifactId, SubmitAttemptRequest,
};
use crucible_cas::content_store::ImmutableBlobBackend;
use crucible_qemu::{
    LinuxQemuAttemptHostConfig, LinuxQemuHotForkChildProcessAuthority, QemuAsyncDriverError,
    QemuAsyncDriverPolicy, QemuHotForkChildProcessOwner, QemuLaunchArtifactIdentity,
    QemuLaunchArtifactIdentityError, QemuShutdownPolicy, QemuVmRealizationError,
};

#[cfg(test)]
use crate::assignment_ledger::AttemptRuntimeState;
#[cfg(test)]
use crate::executor_pool::LocalExecutorOperationalSnapshot;
use crate::executor_pool::{
    PreparedResultJournalConfig, reconcile_stable_prepared_result_journals,
};
#[cfg(test)]
use crate::executor_supervisor::LocalExecutionActivity;
use crate::guest_selectable::GuestSelectableBoundaryDiagnosticRecorder;
use crate::qemu_campaign_lifecycle::{
    QemuAttemptExecutionEvidence, QemuObservedFreshAttemptLifecycleFactory,
    QemuTerminalEvidenceExecutionRunner,
};
use crate::qemu_hot_fork_world_factory::AttemptWorkerFailureExt;
use crate::qemu_hot_fork_world_factory::QemuHotForkSourceWorldProvider;
use crate::qemu_resource_guard::QemuAttemptSelectedHostResourceFactory;
use crate::{
    AssignmentLedgerError, AttemptAdmissionValidator, AttemptExecutionContext,
    AuthenticatedHotCheckpointDemotionError, AuthenticatedHotCheckpointDemotionSink,
    AuthenticatedQemuHotForkSourceBasis, AuthenticatedQemuHotForkSourceBasisError,
    AutomaticFindingExecutionRunner, CompletionValidationFailure,
    ComposedQemuAttemptResourceGuardFactory, CrucibleArtifactError, CrucibleAttemptExecution,
    CrucibleExecutionModel, DirectoryAssignmentLedger,
    DirectoryHotCheckpointFallbackRetentionStore, ExactCheckpointStore, ExactCheckpointStoreError,
    ExecutionCancellation, ExecutorCapacity, ExecutorLocalService, ExecutorLocalServiceError,
    ExecutorLocalServiceReport, ExecutorLocalServiceShutdown, ExecutorLoopbackEndpointConfig,
    ExecutorLoopbackListenerError, ExecutorLoopbackServerConfig,
    GuestSelectableBoundaryDiagnosticConfig, HotCheckpointFallback,
    HotCheckpointFallbackRetentionError, HotCheckpointHotnessSignals, HotCheckpointLimits,
    LinuxQemuAttemptHostResourceFactory, LocalCheckpointPromotionWorker,
    LocalComponentEndpointError, LocalExecutorPoolConfigError, LocalExecutorSupervisor,
    LocalExecutorWorkerPool, MAX_PREPARED_SEMANTIC_RESULT_BYTES,
    ManagedQemuHotForkAuthenticatedAdmissionError, ManagedQemuHotForkAuthenticatedAdmissionFailure,
    ManagedQemuHotForkSourceWorldAdmissionError, ManagedQemuHotForkSourceWorldPool,
    ManagedQemuHotForkSourceWorldPoolConstructionError, PreparedResultJournalError,
    PreparedResultJournalNamespace, ProductionBakedGenesisCaptureError,
    ProductionBakedGenesisCheckpoint, ProductionBakedGenesisReplayCatalogError,
    ProductionBakedGenesisReplayCatalogFactory, ProductionCheckpointPromotionWorker,
    ProductionQemuHotForkSourceCaptureError, ProductionQemuHotForkSourceFactory,
    QemuAttemptExecutionRouter, QemuAttemptHostResourceFactory, QemuAttemptHostResourceOwner,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmLifecycleError,
    QemuAttemptProductionVmLifecycleFactory, QemuAttemptResourceGuardFactory,
    QemuFreshExecutionRunner, QemuFreshModeledDriver, QemuHotCheckpointFallbackAuthenticationError,
    QemuHotCheckpointFallbackAuthenticator, QemuHotForkSourceWorldBoundary,
    QemuHotForkSourceWorldDemoter, QemuHotForkSourceWorldDemotionError, QemuHotForkSourceWorldKey,
    QemuHotForkSourceWorldLease, QemuHotForkWorldAuxiliaryResourceBroker,
    QemuHotForkWorldAuxiliaryResourceFactory, QemuHotForkWorldExecutionRunner,
    QemuProductionExactResumeExecutionRunner, QemuProductionHotForkWorldLifecycleFactory,
    RepositoryAttemptWorker, SharedManagedQemuHotForkSourceWorldPool,
    SharedManagedQemuHotForkSourceWorldShutdownError, SharedQemuAttemptHostResourceFactory,
    SharedQemuHotForkSourceWorldProvider, SharedQemuHotForkSourceWorldProviderConstructionError,
    SharedQemuHotForkSourceWorldProviderError, UnixPeerExecutorIdentity,
    capture_production_baked_genesis, decode_crucible_scenario_artifact,
    reconcile_pending_finding_candidates,
};

mod exact_pin_materializer;
mod hot_fork;
pub(crate) use hot_fork::retained_service::{
    RetainedTemplateService, RetainedTemplateServiceFactory,
};
mod ram_catalog;
pub use ram_catalog::{PackagedRamCatalogConfig, PackagedRamCatalogConfigError};

pub(crate) mod guarded;
mod preparation;
pub use preparation::PreparationExpiredCause;
mod status;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::run_host_parallel_native;
#[cfg(test)]
pub(crate) use tests::{
    NativeAtomicFailureCase, NativeAtomicWorldCase, NativeEquivalenceCase,
    run_atomic_failure_native, run_atomic_world_native, run_dma_borrowers_native,
    run_equivalence_native,
};

pub use exact_pin_materializer::PackagedExactPinMaterializerError;
use exact_pin_materializer::{
    PackagedExactPinMaterializerOwner, prepare_packaged_exact_pin_materializer,
};
pub use hot_fork::PackagedQemuHotForkSourceShutdownError;
#[cfg(test)]
pub(crate) use hot_fork::PackagedQemuInitialExecutionRunner;
use hot_fork::{
    PackagedQemuHotForkDemotionError, PackagedQemuHotForkSourceOwner,
    PackagedQemuInitialRunnerBuild, authenticate_packaged_hot_fork_launch,
    compose_packaged_qemu_executor_with_baked_genesis,
};
#[cfg(test)]
pub(crate) use status::{
    MAX_PACKAGED_ATTEMPT_FAILURE_DIAGNOSTIC_BYTES, packaged_attempt_failure_diagnostic,
};
#[cfg(test)]
use status::{
    OperationalPhase, PackagedWorldLifecyclePhase, operational_phase, successive_actor_snapshots,
};
use status::{
    PackagedQemuOperationalStatusProvider, PackagedStatusAttemptWorker,
    PackagedStatusHotForkFactory, PackagedStatusLifecycleFactory, PackagedWorldLifecycleTracker,
};

/// Maximum aggregate canonical bytes in one packaged scenario catalog.
///
/// Startup authenticates the closed catalog under its admitted metadata owner.
/// This semantic ceiling also limits aggregate hostile immutable-store work;
/// each decoded allocation remains charged to that original resource account.
pub const MAX_PACKAGED_SCENARIO_CATALOG_BYTES: usize = 128 * 1024 * 1024;

pub(crate) fn packaged_finding_replay_runner<F>(
    lifecycle: impl Into<Arc<ProductionVmLifecycleConfig>>,
    lifecycles: F,
) -> QemuFreshExecutionRunner<QemuObservedFreshAttemptLifecycleFactory<F>, QemuFreshModeledDriver> {
    let (lifecycles, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(lifecycles);
    let capture = crate::automatic_finding_runner::QemuFindingReplayCaptureProducer::new(
        lifecycle,
        evidence,
        crucible_campaign::MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES,
    );

    QemuFreshExecutionRunner::new(lifecycles, QemuFreshModeledDriver)
        .with_finding_replay_capture(capture)
}

/// Explicit process-wide policy for packaged retained source worlds.
///
/// Absence of this policy keeps hot-fork source capture and capability
/// advertisement disabled. Every retained-resource and fork-rate ceiling is
/// supplied by the deployment owner rather than inferred from attempt limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackagedQemuHotForkConfig {
    launch: QemuLaunchArtifactIdentity,
    limits: HotCheckpointLimits,
    initial_signals: HotCheckpointHotnessSignals,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
}

impl PackagedQemuHotForkConfig {
    /// Authenticates one launch pair and creates an explicit retained-source policy.
    ///
    /// # Errors
    ///
    /// Returns [`PackagedQemuHotForkConfigError`] when the selected QEMU and
    /// plugin markers do not authenticate, or a host timeout is zero.
    pub fn authenticate(
        lifecycle: &ProductionVmLifecycleConfig,
        limits: HotCheckpointLimits,
        initial_signals: HotCheckpointHotnessSignals,
        shutdown_step_timeout: std::time::Duration,
        host_io_timeout: std::time::Duration,
    ) -> Result<Self, PackagedQemuHotForkConfigError> {
        if shutdown_step_timeout.is_zero() {
            return Err(PackagedQemuHotForkConfigError::ZeroShutdownTimeout);
        }
        if host_io_timeout.is_zero() {
            return Err(PackagedQemuHotForkConfigError::ZeroHostIoTimeout);
        }
        let launch =
            QemuLaunchArtifactIdentity::authenticate(lifecycle.executable(), lifecycle.plugin())
                .map_err(PackagedQemuHotForkConfigError::Launch)?;
        let shutdown_policy = QemuShutdownPolicy {
            control_quit_wait: shutdown_step_timeout,
            qmp_quit_wait: shutdown_step_timeout,
            sigterm_wait: shutdown_step_timeout,
            sigkill_wait: shutdown_step_timeout,
            reap_wait: shutdown_step_timeout,
        };
        let async_policy = QemuAsyncDriverPolicy::new(
            host_io_timeout,
            host_io_timeout,
            host_io_timeout,
            host_io_timeout,
        );
        async_policy
            .validate()
            .map_err(PackagedQemuHotForkConfigError::HostIo)?;

        Ok(Self::new(
            launch,
            limits,
            initial_signals,
            shutdown_policy,
            async_policy,
        ))
    }

    /// Creates an already-authenticated retained-source policy internally.
    #[must_use]
    pub(crate) fn new(
        launch: QemuLaunchArtifactIdentity,
        limits: HotCheckpointLimits,
        initial_signals: HotCheckpointHotnessSignals,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
    ) -> Self {
        Self {
            launch,
            limits,
            initial_signals,
            shutdown_policy,
            async_policy,
        }
    }

    /// Returns the marker-authenticated QEMU and plugin launch identity.
    #[must_use]
    pub(crate) const fn launch_identity(&self) -> &QemuLaunchArtifactIdentity {
        &self.launch
    }

    /// Returns the process-wide retained-source and fork-rate ceilings.
    #[must_use]
    pub const fn limits(&self) -> HotCheckpointLimits {
        self.limits
    }

    /// Returns the initial operational ranking signals for packaged sources.
    #[must_use]
    pub const fn initial_signals(&self) -> HotCheckpointHotnessSignals {
        self.initial_signals
    }

    /// Returns the bounded child shutdown policy.
    #[must_use]
    pub(crate) const fn shutdown_policy(&self) -> QemuShutdownPolicy {
        self.shutdown_policy
    }

    /// Returns the bounded hot-child host-I/O policy.
    #[must_use]
    pub(crate) const fn async_policy(&self) -> QemuAsyncDriverPolicy {
        self.async_policy
    }
}

/// Invalid packaged retained-source deployment policy.
#[derive(Debug, thiserror::Error)]
pub enum PackagedQemuHotForkConfigError {
    /// The selected QEMU and plugin markers did not authenticate.
    #[error("authenticate packaged QEMU launch pair: {0}")]
    Launch(#[source] QemuLaunchArtifactIdentityError),
    /// A shutdown escalation rung had no wait budget.
    #[error("packaged hot-fork shutdown timeout is zero")]
    ZeroShutdownTimeout,
    /// A host-I/O wait had no timeout budget.
    #[error("packaged hot-fork host-I/O timeout is zero")]
    ZeroHostIoTimeout,
    /// The derived host-I/O policy was invalid.
    #[error("validate packaged hot-fork host-I/O policy: {0}")]
    HostIo(#[source] QemuAsyncDriverError),
}

/// Complete operational deployment contract for one packaged local QEMU executor pool.
///
/// Exact checkpoint objects are deliberately absent from this configuration:
/// the prepared campaign-service owner supplies its already-authenticated
/// composed immutable store so checkpoints, campaign closure authentication,
/// and stopped-owner GC share one physical graph.
#[derive(Clone, Debug)]
pub struct PackagedQemuExecutorConfig {
    campaigns: BTreeSet<CampaignName>,
    endpoint: ExecutorLoopbackEndpointConfig,
    server: ExecutorLoopbackServerConfig,
    ledger_root: PathBuf,
    maximum_checkpoint_bytes: u64,
    daemon_epoch: DaemonEpoch,
    capacity: ExecutorCapacity,
    host_operational_capacity: crate::HostOperationalCapacity,
    worker_count: usize,
    host_architecture: String,
    qemu_profile: String,
    store_namespace: CampaignHash,
    lifecycle: Arc<ProductionVmLifecycleConfig>,
    host: LinuxQemuAttemptHostConfig,
    hot_fork: Option<PackagedQemuHotForkConfig>,
    retained_template_resources: Option<crucible_api::host_operational::HostResourceVector>,
    assignment_resources: Option<crucible_api::host_operational::HostResourceVector>,
    assignment_limits: Option<AttemptResourceLimits>,
    ram_catalog: Option<PackagedRamCatalogConfig>,
    operational_registry_resources: Option<crucible_api::host_operational::HostResourceVector>,
    operational_registry_quota: Option<(u32, u64)>,
    host_operation_budgets: Option<crucible_api::host_operational::HostOperationBudgets>,
    guest_selectable_boundary_diagnostics: Option<GuestSelectableBoundaryDiagnosticConfig>,
    verify_determinism_findings: bool,
}

impl PackagedQemuExecutorConfig {
    /// Projects immutable operational inputs for the guarded campaign adapter.
    pub(crate) fn guarded_inputs(
        &self,
    ) -> Option<(
        Arc<ProductionVmLifecycleConfig>,
        LinuxQemuAttemptHostConfig,
        AttemptResourceLimits,
    )> {
        Some((
            self.lifecycle.clone(),
            self.host.clone(),
            self.assignment_limits?,
        ))
    }

    /// Copies a mutable launch projection under its original catalog authority.
    ///
    /// Existing decoder custody is preserved. Static preparation uses the
    /// already admitted namespace's metadata allocator, never spare capacity.
    pub(crate) fn admitted_lifecycle_config(
        &self,
    ) -> Result<ProductionVmLifecycleConfig, PackagedQemuExecutorError> {
        if crucible::owned_decode::current_budget().is_some() {
            return Ok(self.lifecycle.try_clone_admitted()?);
        }
        let provider = self.lifecycle.ram_catalog_provider().ok_or(
            crucible_cas::content_store::StoreError::Unsupported {
                capability: "admitted-lifecycle-metadata",
            },
        )?;
        let authority = provider.prepare_directory(self.lifecycle.run_state_root())?;
        let budget = crucible::owned_decode::DecodeBudget::for_store(authority)?;
        let _scope = budget.enter();
        let lifecycle = self.lifecycle.try_clone_admitted()?;
        budget.check()?;
        Ok(lifecycle)
    }

    /// Returns the original charged actor incarnation.
    pub(crate) fn guarded_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

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
        maximum_checkpoint_bytes: u64,
        daemon_epoch: DaemonEpoch,
        capacity: ExecutorCapacity,
        host_operational_capacity: crate::HostOperationalCapacity,
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
        if host_operational_capacity
            .maximum_metadata_bytes()
            .checked_add(host_operational_capacity.maximum_staging_bytes())
            .is_none_or(|bytes| bytes > capacity.maximum_resident_bytes())
            || host_operational_capacity.maximum_staging_bytes() > capacity.maximum_disk_bytes()
        {
            return Err(PackagedQemuExecutorConfigError::InvalidHostResourceCapacity);
        }
        Ok(Self {
            campaigns,
            endpoint,
            server,
            ledger_root: ledger_root.into(),
            maximum_checkpoint_bytes,
            daemon_epoch,
            capacity,
            host_operational_capacity,
            worker_count,
            host_architecture: host_architecture.into(),
            qemu_profile: qemu_profile.into(),
            store_namespace,
            lifecycle: Arc::new(lifecycle),
            host,
            hot_fork: None,
            retained_template_resources: None,
            assignment_resources: None,
            assignment_limits: None,
            ram_catalog: None,
            operational_registry_resources: None,
            operational_registry_quota: None,
            host_operation_budgets: None,
            guest_selectable_boundary_diagnostics: None,
            verify_determinism_findings: false,
        })
    }

    /// Enables source-world capture under explicit process-wide limits.
    #[must_use]
    pub fn with_hot_fork_sources(mut self, hot_fork: PackagedQemuHotForkConfig) -> Self {
        self.hot_fork = Some(hot_fork);
        self
    }

    /// Retains an authored complete native and host resource ceiling for sources.
    ///
    /// Actual capture admission also checks every concurrent retained owner;
    /// this validation cannot reserve global headroom by itself.
    ///
    /// # Errors
    /// Rejects zero dimensions, invalid memory subsets or a ceiling above any
    /// deployed aggregate capacity.
    pub fn with_retained_template_resources(
        mut self,
        resources: crucible_api::host_operational::HostResourceVector,
    ) -> Result<Self, PackagedQemuExecutorConfigError> {
        if !self.host_owner_resources_fit(resources) {
            return Err(PackagedQemuExecutorConfigError::InvalidRetainedTemplateResources);
        }
        self.retained_template_resources = Some(resources);
        Ok(self)
    }

    fn host_owner_resources_fit(
        &self,
        resources: crucible_api::host_operational::HostResourceVector,
    ) -> bool {
        let subsets = resources
            .metadata_bytes
            .checked_add(resources.staging_bytes);
        !([
            resources.resident_peak_bytes,
            resources.backing_peak_bytes,
            resources.metadata_bytes,
            resources.staging_bytes,
            resources.paging_io_slots,
            resources.cpu_slots,
            resources.task_slots,
            resources.file_descriptors,
        ]
        .contains(&0)
            || subsets.is_none_or(|bytes| bytes > resources.resident_peak_bytes)
            || resources.staging_bytes > resources.backing_peak_bytes
            || resources.cpu_slots > u64::from(self.capacity.maximum_vcpus())
            || resources.resident_peak_bytes > self.capacity.maximum_resident_bytes()
            || resources.backing_peak_bytes > self.capacity.maximum_disk_bytes()
            || resources.paging_io_slots > self.host_operational_capacity.maximum_paging_io_slots()
            || resources.task_slots > self.host_operational_capacity.maximum_task_slots()
            || resources.file_descriptors
                > self.host_operational_capacity.maximum_file_descriptors()
            || resources.metadata_bytes > self.host_operational_capacity.maximum_metadata_bytes()
            || resources.staging_bytes > self.host_operational_capacity.maximum_staging_bytes())
    }

    /// Retains a separately authored per-assignment host and modeled ceiling.
    ///
    /// # Errors
    /// Refuses invalid resource dimensions, modeled request limits above their
    /// physical assignment bounds, or a bound above its deployed aggregate capacity.
    pub fn with_assignment_resources(
        mut self,
        resources: crucible_api::host_operational::HostResourceVector,
        limits: AttemptResourceLimits,
    ) -> Result<Self, PackagedQemuExecutorConfigError> {
        if !self.host_owner_resources_fit(resources)
            || u64::from(limits.maximum_vcpus()) > resources.cpu_slots
            || limits.maximum_resident_bytes() > resources.resident_peak_bytes
            || limits.maximum_disk_bytes() > resources.backing_peak_bytes
            || limits.maximum_execution_quanta() > self.capacity.maximum_execution_quanta()
        {
            return Err(PackagedQemuExecutorConfigError::InvalidAssignmentResources);
        }
        self.assignment_resources = Some(resources);
        self.assignment_limits = Some(limits);
        Ok(self)
    }

    /// Retains the independently contained catalog service deployment contract.
    ///
    /// # Errors
    /// Refuses shared lifecycle configuration or a catalog dimension above
    /// deployed aggregate capacity. Actual admission reserves the complete
    /// service before opening its backend.
    pub fn with_ram_catalog(
        mut self,
        catalog: PackagedRamCatalogConfig,
    ) -> Result<Self, PackagedQemuExecutorConfigError> {
        if !self.host_owner_resources_fit(catalog.resources()) {
            return Err(PackagedQemuExecutorConfigError::InvalidRamCatalogResources);
        }
        let run_state_root = if self.lifecycle.run_state_root().starts_with(catalog.root()) {
            self.lifecycle.run_state_root().to_path_buf()
        } else {
            catalog.root().join("worlds")
        };
        let lifecycle = Arc::try_unwrap(self.lifecycle)
            .map_err(|_| PackagedQemuExecutorConfigError::SharedLifecycleConfiguration)?;
        self.lifecycle = Arc::new(
            lifecycle
                .with_run_state_root(run_state_root)
                .with_ram_catalog_provider(catalog.provider()),
        );
        self.ram_catalog = Some(catalog);
        Ok(self)
    }

    /// Returns the independently authored physical RAM catalog contract.
    #[must_use]
    pub fn ram_catalog(&self) -> Option<&PackagedRamCatalogConfig> {
        self.ram_catalog.as_ref()
    }

    /// Retains the independent durable operational registry service entitlement.
    ///
    /// # Errors
    /// Refuses zero dimensions, invalid subsets, or resources above deployed
    /// aggregate capacity. Actual admission precedes opening registry files.
    pub fn with_operational_registry_resources(
        mut self,
        resources: crucible_api::host_operational::HostResourceVector,
    ) -> Result<Self, PackagedQemuExecutorConfigError> {
        if !self.host_owner_resources_fit(resources) {
            return Err(PackagedQemuExecutorConfigError::InvalidOperationalRegistryResources);
        }
        self.operational_registry_resources = Some(resources);
        Ok(self)
    }

    /// Returns the separately authored complete durable registry service bound.
    #[must_use]
    pub const fn operational_registry_resources(
        &self,
    ) -> Option<crucible_api::host_operational::HostResourceVector> {
        self.operational_registry_resources
    }

    /// Binds the durable registry to a distinct operator-installed project quota.
    ///
    /// The hard byte ceiling comes from the already authored registry backing
    /// entitlement. Startup authenticates the installed quota before opening
    /// any durable ledger or operational-history file.
    ///
    /// # Errors
    /// Refuses a missing registry entitlement, unsupported project identifier,
    /// zero inode ceiling, or unsupported exact kernel quota limits.
    pub fn with_operational_registry_quota(
        mut self,
        project_id: u32,
        maximum_inodes: u64,
    ) -> Result<Self, PackagedQemuExecutorConfigError> {
        let resources = self
            .operational_registry_resources
            .ok_or(PackagedQemuExecutorConfigError::InvalidOperationalRegistryQuota)?;
        if !(1..0x8000_0000).contains(&project_id)
            || crucible_linux_resource::LinuxProjectQuotaLimits::new(
                resources.backing_peak_bytes,
                maximum_inodes,
            )
            .is_err()
        {
            return Err(PackagedQemuExecutorConfigError::InvalidOperationalRegistryQuota);
        }
        self.operational_registry_quota = Some((project_id, maximum_inodes));
        Ok(self)
    }

    /// Returns the exact persistent registry project and inode entitlement.
    #[must_use]
    pub const fn operational_registry_quota(&self) -> Option<(u32, u64)> {
        self.operational_registry_quota
    }

    /// Retains the independently authored roster for every host operation class.
    ///
    /// All infrastructure classes require finite progress or total supervision;
    /// the quantum class may use unlimited host waiting. Later owners start this
    /// same roster once and never derive it from a copied remaining deadline.
    ///
    /// # Errors
    /// Refuses empty polling slices, zero or unrepresentable allowances, and
    /// unbounded infrastructure classes.
    pub fn with_host_operation_budgets(
        mut self,
        budgets: crucible_api::host_operational::HostOperationBudgets,
    ) -> Result<Self, PackagedQemuExecutorConfigError> {
        budgets
            .validate(false)
            .map_err(PackagedQemuExecutorConfigError::HostOperationBudgets)?;
        self.host_operation_budgets = Some(budgets);
        Ok(self)
    }

    /// Returns the authored roster, or absence before complete configuration.
    #[must_use]
    pub const fn host_operation_budgets(
        &self,
    ) -> Option<crucible_api::host_operational::HostOperationBudgets> {
        self.host_operation_budgets
    }

    /// Returns the complete authored per-assignment host resource bound.
    #[must_use]
    pub const fn assignment_resources(
        &self,
    ) -> Option<crucible_api::host_operational::HostResourceVector> {
        self.assignment_resources
    }

    /// Returns the separately authored modeled request limits for each assignment.
    #[must_use]
    pub const fn assignment_limits(&self) -> Option<AttemptResourceLimits> {
        self.assignment_limits
    }

    /// Returns the authored complete resource entitlement for retained sources.
    #[must_use]
    pub const fn retained_template_resources(
        &self,
    ) -> Option<crucible_api::host_operational::HostResourceVector> {
        self.retained_template_resources
    }

    /// Enables bounded diagnostics shared by every worker in this executor pool.
    #[must_use]
    pub fn with_guest_selectable_boundary_diagnostics(
        mut self,
        diagnostics: GuestSelectableBoundaryDiagnosticConfig,
    ) -> Self {
        self.guest_selectable_boundary_diagnostics = Some(diagnostics);
        self
    }

    /// Enables paired private replay for automatic determinism findings.
    #[must_use]
    pub const fn with_determinism_finding_verification(mut self) -> Self {
        self.verify_determinism_findings = true;
        self
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

    fn exact_pin_materialization_root(&self) -> PathBuf {
        self.ledger_root
            .with_file_name(crate::EXACT_PIN_MATERIALIZATION_DIRECTORY)
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

    /// Returns the retained-source policy when hot-fork execution is enabled.
    #[must_use]
    pub const fn hot_fork(&self) -> Option<&PackagedQemuHotForkConfig> {
        self.hot_fork.as_ref()
    }

    /// Returns the boundary-diagnostic policy when operational emission is enabled.
    #[must_use]
    pub const fn guest_selectable_boundary_diagnostics(
        &self,
    ) -> Option<GuestSelectableBoundaryDiagnosticConfig> {
        self.guest_selectable_boundary_diagnostics
    }

    /// Returns whether ordinary attempts receive paired determinism verification.
    #[must_use]
    pub const fn verifies_determinism_findings(&self) -> bool {
        self.verify_determinism_findings
    }
}

/// Invalid packaged-executor deployment configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackagedQemuExecutorConfigError {
    /// The lifecycle configuration is already shared with another owner.
    #[error("shared packaged lifecycle configuration cannot be modified")]
    SharedLifecycleConfiguration,
    /// The authored host operation roster cannot supervise infrastructure.
    #[error("packaged host operation budgets are invalid: {0}")]
    HostOperationBudgets(#[source] crucible_linux_resource::host_supervision::HostSupervisionError),
    /// The catalog service exceeds independently deployed aggregate resources.
    #[error("RAM catalog resources exceed deployed aggregate capacity")]
    InvalidRamCatalogResources,
    /// The durable operational registry service has invalid complete bounds.
    #[error(
        "packaged operational registry resources exceed deployed capacity or have invalid subsets"
    )]
    InvalidOperationalRegistryResources,
    /// The persistent registry project quota has invalid or missing geometry.
    #[error("packaged operational registry quota is missing or invalid")]
    InvalidOperationalRegistryQuota,

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
    /// The complete retained-source entitlement is invalid or exceeds deployment.
    #[error("packaged QEMU retained-template resources exceed their deployed contract")]
    InvalidRetainedTemplateResources,
    /// A separately authored assignment ceiling is invalid or exceeds deployment.
    #[error("packaged QEMU assignment resources exceed their deployed contract")]
    InvalidAssignmentResources,
    /// Aggregate metadata and staging do not fit complete resident/disk peaks.
    #[error("packaged QEMU aggregate host subsets exceed complete resource peaks")]
    InvalidHostResourceCapacity,
}

/// Prepared packaged executor pool bound to one exact campaign repository.
pub struct PackagedQemuExecutor {
    guarded_state: guarded::PackagedGuardedState,
    host_operational_registry: crate::HostOperationalRegistry,
    repository_identity: Arc<CampaignRepository>,
    admitted_scenarios: BTreeSet<ScenarioArtifactId>,
    endpoint: PathBuf,
    service: ExecutorLocalService<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    exact_pin_materializer: PackagedExactPinMaterializerOwner,
    operational_status: Arc<dyn CampaignOperationalStatusProvider>,
    hot_fork_owner: Option<Box<dyn PackagedQemuHotForkSourceOwner>>,
    hot_fork_retention: Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>>,
    campaign_debug: Arc<crate::CampaignDebugQemuCapability>,
}

impl PackagedQemuExecutor {
    /// Shares the existing admitted actor, repository and native allocator.
    ///
    /// # Errors
    /// Refuses unavailable native ownership or shutdown. The supplied planner
    /// must be the authenticated component authority of this same repository.
    pub fn guarded_campaign_owner(
        &self,
        planner: crucible_campaign::PlannerAuthorityKey,
    ) -> Result<guarded::GuardedCampaignOwner, PackagedQemuExecutorError> {
        guarded::GuardedCampaignOwner::from_packaged(
            &self.guarded_state,
            Arc::clone(&self.repository_identity),
            planner,
        )
    }

    /// Returns the durable hot-fallback root catalog for campaign GC.
    #[must_use]
    pub fn hot_fork_retention_admin(
        &self,
    ) -> Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>> {
        self.hot_fork_retention.as_ref().map(Arc::clone)
    }
}

/// Running packaged executor-pool thread coupled to one daemon service lifecycle.
pub struct AttachedPackagedQemuExecutor {
    guarded_state: guarded::PackagedGuardedState,
    host_operational_registry: crate::HostOperationalRegistry,
    repository_identity: Arc<CampaignRepository>,
    admitted_scenarios: BTreeSet<ScenarioArtifactId>,
    endpoint: PathBuf,
    operational_status: Arc<dyn CampaignOperationalStatusProvider>,
    hot_fork_retention: Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>>,
    campaign_debug: Arc<crate::CampaignDebugQemuCapability>,
    shutdown: ExecutorLocalServiceShutdown<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    completion: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<Result<ExecutorLocalServiceReport, PackagedQemuExecutorJoinError>>>,
}

impl AttachedPackagedQemuExecutor {
    /// Shares the existing admitted actor, repository and native allocator.
    ///
    /// # Errors
    /// Refuses unavailable native ownership or shutdown. The supplied planner
    /// must be the authenticated component authority of this same repository.
    pub fn guarded_campaign_owner(
        &self,
        planner: crucible_campaign::PlannerAuthorityKey,
    ) -> Result<guarded::GuardedCampaignOwner, PackagedQemuExecutorError> {
        guarded::GuardedCampaignOwner::from_packaged(
            &self.guarded_state,
            Arc::clone(&self.repository_identity),
            planner,
        )
    }

    /// Starts the fixed listener/worker owner on one named daemon thread.
    ///
    /// # Errors
    ///
    /// Returns [`PackagedQemuExecutorStartError`] when the operating system
    /// cannot create the single service-owner thread.
    pub fn start(service: PackagedQemuExecutor) -> Result<Self, PackagedQemuExecutorStartError> {
        let PackagedQemuExecutor {
            guarded_state,
            host_operational_registry,
            repository_identity,
            admitted_scenarios,
            endpoint,
            service,
            exact_pin_materializer,
            operational_status,
            hot_fork_owner,
            hot_fork_retention,
            campaign_debug,
        } = service;
        let shutdown = service.shutdown_handle();
        let completion = Arc::new((Mutex::new(false), Condvar::new()));
        let thread_completion = Arc::clone(&completion);
        let thread = thread::Builder::new()
            .name(String::from("crucible-packaged-qemu-executor"))
            .spawn(move || {
                let _completion = PackagedQemuExecutorCompletionGuard(thread_completion);
                let service_result = service.serve();
                exact_pin_materializer.request_shutdown();
                let materializer_result = exact_pin_materializer.join();
                let hot_fork_result = hot_fork_owner
                    .as_ref()
                    .map(|owner| owner.orderly_shutdown())
                    .unwrap_or(Ok(()));
                combine_packaged_qemu_join_results(
                    service_result,
                    materializer_result,
                    hot_fork_result,
                )
            })
            .map_err(|source| PackagedQemuExecutorStartError::Spawn { source })?;
        Ok(Self {
            guarded_state,
            host_operational_registry,
            repository_identity,
            admitted_scenarios,
            endpoint,
            operational_status,
            hot_fork_retention,
            campaign_debug,
            shutdown,
            completion,
            thread: Some(thread),
        })
    }

    /// Returns live host operational authority independently of guest execution.
    #[must_use]
    pub fn host_operational_registry(&self) -> crate::HostOperationalRegistry {
        self.host_operational_registry.clone()
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

    /// Returns every exact scenario artifact backed by the native catalog.
    pub(crate) const fn admitted_scenarios(&self) -> &BTreeSet<ScenarioArtifactId> {
        &self.admitted_scenarios
    }

    /// Returns the exact managed endpoint served by this pool.
    pub(crate) fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Returns generation-bound operational status for the packaged pool.
    pub(crate) fn operational_status_provider(&self) -> Arc<dyn CampaignOperationalStatusProvider> {
        Arc::clone(&self.operational_status)
    }

    /// Returns owner-only exact-restore authority for campaign debug sessions.
    #[must_use]
    pub fn campaign_debug_capability(&self) -> Arc<crate::CampaignDebugQemuCapability> {
        Arc::clone(&self.campaign_debug)
    }

    /// Returns the durable hot-fallback root catalog for campaign GC.
    #[must_use]
    pub fn hot_fork_retention_admin(
        &self,
    ) -> Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>> {
        self.hot_fork_retention.as_ref().map(Arc::clone)
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
    /// Exact-pin materialization failed and stopped the executor.
    #[error(transparent)]
    ExactPinMaterializer(Box<PackagedExactPinMaterializerError>),
    /// Retained source-world shutdown failed after workers stopped.
    #[error(transparent)]
    HotForkSources(Box<PackagedQemuHotForkSourceShutdownError>),
    /// More than one independently owned executor component failed to stop.
    #[error(transparent)]
    Multiple(Box<PackagedQemuExecutorJoinFailures>),
}

/// Complete report when multiple packaged executor owners fail during shutdown.
#[derive(Debug, thiserror::Error)]
#[error("multiple packaged QEMU executor owners failed during shutdown")]
pub struct PackagedQemuExecutorJoinFailures {
    service: Option<Box<ExecutorLocalServiceError>>,
    exact_pin_materializer: Option<Box<PackagedExactPinMaterializerError>>,
    hot_fork_sources: Option<Box<PackagedQemuHotForkSourceShutdownError>>,
}

impl PackagedQemuExecutorJoinFailures {
    /// Returns the listener or semantic-pool failure, when present.
    #[must_use]
    pub fn service(&self) -> Option<&ExecutorLocalServiceError> {
        self.service.as_deref()
    }

    /// Returns the exact-pin materializer failure, when present.
    #[must_use]
    pub fn exact_pin_materializer(&self) -> Option<&PackagedExactPinMaterializerError> {
        self.exact_pin_materializer.as_deref()
    }

    /// Returns the retained source-world shutdown report, when present.
    #[must_use]
    pub fn hot_fork_sources(&self) -> Option<&PackagedQemuHotForkSourceShutdownError> {
        self.hot_fork_sources.as_deref()
    }
}

fn combine_packaged_qemu_join_results(
    service: Result<ExecutorLocalServiceReport, ExecutorLocalServiceError>,
    materializer: Result<(), PackagedExactPinMaterializerError>,
    hot_fork: Result<(), PackagedQemuHotForkSourceShutdownError>,
) -> Result<ExecutorLocalServiceReport, PackagedQemuExecutorJoinError> {
    match (service, materializer, hot_fork) {
        (Ok(report), Ok(()), Ok(())) => Ok(report),
        (Err(source), Ok(()), Ok(())) => Err(PackagedQemuExecutorJoinError::Service(source)),
        (Ok(_report), Err(source), Ok(())) => Err(
            PackagedQemuExecutorJoinError::ExactPinMaterializer(Box::new(source)),
        ),
        (Ok(_report), Ok(()), Err(source)) => Err(PackagedQemuExecutorJoinError::HotForkSources(
            Box::new(source),
        )),
        (service, materializer, hot_fork) => Err(PackagedQemuExecutorJoinError::Multiple(
            Box::new(PackagedQemuExecutorJoinFailures {
                service: service.err().map(Box::new),
                exact_pin_materializer: materializer.err().map(Box::new),
                hot_fork_sources: hot_fork.err().map(Box::new),
            }),
        )),
    }
}

/// Opens every durable/host owner and starts one packaged local QEMU executor.
///
/// Every configured repository head is authenticated in canonical campaign
/// order before host-resource acquisition or endpoint binding. All campaigns
/// must share the exact compatibility profile. One native baked genesis is
/// captured for every distinct exact scenario artifact, and the fixed workers
/// route promotion through that closed catalog while sharing one aggregate
/// Linux host allocator and capacity owner.
///
/// # Errors
///
/// Returns [`PackagedQemuExecutorError`] when a campaign or lineage cannot be
/// authenticated, configured campaign bases differ, the supplied checkpoint
/// store or another durable or host owner cannot be acquired, capabilities do
/// not encode, workers cannot start, or the managed endpoint cannot bind.
pub(crate) fn prepare_packaged_qemu_executor(
    repository: Arc<CampaignRepository>,
    checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
    hot_fork_retention: DirectoryHotCheckpointFallbackRetentionStore,
    config: PackagedQemuExecutorConfig,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError> {
    let basis =
        authenticate_packaged_campaigns(&repository, &config.campaigns, config.hot_fork.is_some())?;
    if let Some(hot_fork) = config.hot_fork() {
        authenticate_packaged_hot_fork_launch(&config.lifecycle, hot_fork, &basis.profile)?;
    }
    if basis.profile.exact_closure_schema() != crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION {
        return Err(PackagedQemuExecutorError::UnsupportedExactClosureSchema {
            actual: basis.profile.exact_closure_schema(),
            supported: crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        });
    }
    let scenarios = preflight_packaged_scenario_catalog(&repository, &basis.scenarios)?;
    let preparation = preparation::prepare_runtime(
        &repository,
        Arc::clone(&checkpoint_backend),
        &basis,
        &config,
    )?;
    let host = SharedQemuAttemptHostResourceFactory::new(
        LinuxQemuAttemptHostResourceFactory::open(config.host.clone())?,
    );
    let mut baked = BTreeMap::new();
    for (scenario_id, scenario) in scenarios {
        let baked_lifecycle = config.admitted_lifecycle_config()?.with_run_state_root(
            config
                .lifecycle
                .run_state_root()
                .join("campaign-baked-genesis")
                .join(CampaignHash::from_bytes(scenario_id.content_id().digest()).to_hex()),
        );
        let mut baked_factory = QemuAttemptProductionVmLifecycleFactory::new(
            baked_lifecycle,
            ComposedQemuAttemptResourceGuardFactory::new(host.clone()),
        );
        let checkpoint = preparation::run_capture(&preparation, &config, &scenario, |context| {
            capture_production_baked_genesis(&mut baked_factory, &scenario, context).map_err(
                |source| PackagedQemuExecutorError::BakedGenesis {
                    scenario: scenario_id,
                    source: Box::new(source),
                },
            )
        })?;
        baked.insert(scenario_id, checkpoint);
    }
    let storage = PackagedQemuExecutorStorage::new(repository, checkpoint_backend);
    let guarded_host = host.clone();
    let mut executor = compose_packaged_qemu_executor_with_baked_genesis(
        storage,
        hot_fork_retention,
        basis,
        config,
        host,
        baked,
        preparation,
    )?;
    executor.guarded_state.host = Some(guarded_host);
    Ok(executor)
}

fn preflight_packaged_scenario_catalog(
    repository: &CampaignRepository,
    scenarios: &BTreeSet<ScenarioArtifactId>,
) -> Result<Vec<(ScenarioArtifactId, ScenarioDefForm)>, PackagedQemuExecutorError> {
    let mut charged = 0;
    let mut semantic_bases = BTreeSet::new();
    let mut decoded = Vec::with_capacity(scenarios.len());
    for scenario_id in scenarios {
        let artifact = repository.load_scenario_artifact(*scenario_id)?;
        charge_packaged_scenario_catalog_bytes(
            &mut charged,
            artifact.canonical_bytes().len(),
            MAX_PACKAGED_SCENARIO_CATALOG_BYTES,
        )?;
        let scenario = decode_crucible_scenario_artifact(&artifact)?;
        if !semantic_bases.insert((scenario.world().id, scenario.scenario_def().id())) {
            return Err(PackagedQemuExecutorError::BakedGenesisCatalog(
                ProductionBakedGenesisReplayCatalogError::DuplicateBasis,
            ));
        }
        decoded.push((*scenario_id, scenario));
    }
    Ok(decoded)
}

fn charge_packaged_scenario_catalog_bytes(
    charged: &mut usize,
    record_bytes: usize,
    maximum: usize,
) -> Result<(), PackagedQemuExecutorError> {
    *charged = charged
        .checked_add(record_bytes)
        .ok_or(PackagedQemuExecutorError::ScenarioCatalogBytesExceeded { maximum })?;
    if *charged > maximum {
        return Err(PackagedQemuExecutorError::ScenarioCatalogBytesExceeded { maximum });
    }
    Ok(())
}

#[derive(Clone)]
struct PackagedCampaignBasis {
    profile: ExecutorCompatibilityProfile,
    scenarios: BTreeSet<ScenarioArtifactId>,
    sources: BTreeMap<CampaignLineageId, AuthenticatedQemuHotForkSourceBasis>,
}

#[derive(Clone)]
/// Groups durable stores used by one packaged executor.
pub(crate) struct PackagedQemuExecutorStorage {
    repository: Arc<CampaignRepository>,
    checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
}

impl PackagedQemuExecutorStorage {
    /// Groups the authenticated repository and checkpoint store.
    pub(crate) fn new(
        repository: Arc<CampaignRepository>,
        checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
    ) -> Self {
        Self {
            repository,
            checkpoint_backend,
        }
    }
}

fn authenticate_packaged_campaigns(
    repository: &Arc<CampaignRepository>,
    campaigns: &BTreeSet<CampaignName>,
    authenticate_hot_fork_sources: bool,
) -> Result<PackagedCampaignBasis, PackagedQemuExecutorError> {
    let mut campaigns = campaigns.iter();
    let first = campaigns
        .next()
        .ok_or(PackagedQemuExecutorError::NoCampaigns)?;
    let head = repository.head(first.as_str())?;
    let lineage = repository.load_lineage(head.snapshot().lineage())?;
    let mut lineages = BTreeSet::from([head.snapshot().lineage()]);
    let mut scenarios = BTreeSet::from([lineage.scenario_content()]);
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);

    for campaign in campaigns {
        let head = repository.head(campaign.as_str())?;
        let lineage = repository.load_lineage(head.snapshot().lineage())?;
        if !profile.admits(&lineage) {
            return Err(PackagedQemuExecutorError::CampaignCompatibilityMismatch {
                campaign: campaign.clone(),
            });
        }
        lineages.insert(head.snapshot().lineage());
        scenarios.insert(lineage.scenario_content());
    }
    let sources = if authenticate_hot_fork_sources {
        let store = CampaignExecutorStore::new(Arc::clone(repository));
        let mut sources = BTreeMap::new();
        for lineage in lineages {
            let source =
                AuthenticatedQemuHotForkSourceBasis::authenticate(&store, lineage, &profile);
            if let Some(source) = admit_packaged_hot_fork_source_basis(source)? {
                sources.insert(lineage, source);
            }
        }
        sources
    } else {
        BTreeMap::new()
    };
    Ok(PackagedCampaignBasis {
        profile,
        scenarios,
        sources,
    })
}

fn admit_packaged_hot_fork_source_basis(
    source: Result<AuthenticatedQemuHotForkSourceBasis, AuthenticatedQemuHotForkSourceBasisError>,
) -> Result<Option<AuthenticatedQemuHotForkSourceBasis>, AuthenticatedQemuHotForkSourceBasisError> {
    match source {
        Ok(source) => Ok(Some(source)),
        Err(AuthenticatedQemuHotForkSourceBasisError::NonCanonicalGenesis) => Ok(None),
        Err(source) => Err(source),
    }
}

#[cfg(test)]
pub(crate) fn compose_packaged_qemu_executor<H>(
    storage: PackagedQemuExecutorStorage,
    profile: ExecutorCompatibilityProfile,
    scenario: ScenarioArtifactId,
    config: PackagedQemuExecutorConfig,
    host: H,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
{
    compose_packaged_qemu_executor_for_scenarios(
        storage,
        profile,
        BTreeSet::from([scenario]),
        config,
        host,
    )
}

#[cfg(test)]
pub(crate) fn compose_packaged_qemu_executor_for_scenarios<H>(
    storage: PackagedQemuExecutorStorage,
    profile: ExecutorCompatibilityProfile,
    scenarios: BTreeSet<ScenarioArtifactId>,
    config: PackagedQemuExecutorConfig,
    host: H,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
{
    compose_packaged_qemu_executor_with_checkpoint_promotions(
        storage,
        PackagedCampaignBasis {
            profile,
            scenarios,
            sources: BTreeMap::new(),
        },
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
        _work: &mut crate::CheckpointPromotionRestartWork,
        _cancellation: crate::ExecutionCancellation,
    ) -> Result<crate::PreparedPausedCheckpointPromotionRestart, crate::AttemptWorkerFailure<()>>
    {
        Err(crate::AttemptWorkerFailure::Terminal(()))
    }
}

#[cfg(test)]
fn compose_packaged_qemu_executor_with_checkpoint_promotions<H, P>(
    storage: PackagedQemuExecutorStorage,
    basis: PackagedCampaignBasis,
    config: PackagedQemuExecutorConfig,
    host: H,
    promotion_workers: Vec<P>,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
    H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
    crate::ComposedQemuAttemptResourceGuard<H::Owner>:
        QemuAttemptProcessResourceGuard + Send + 'static,
    P: LocalCheckpointPromotionWorker + Send + 'static,
{
    let shared = SharedQemuAttemptHostResourceFactory::new(host);
    compose_packaged_qemu_executor_with_promotion_builder(
        storage,
        basis,
        config,
        shared,
        None,
        move |_store, _checkpoints, _shared, _run_state_root, _worker_count| promotion_workers,
    )
}

#[cfg(test)]
fn compose_packaged_qemu_executor_with_promotion_builder<H, P, B>(
    storage: PackagedQemuExecutorStorage,
    basis: PackagedCampaignBasis,
    config: PackagedQemuExecutorConfig,
    shared: SharedQemuAttemptHostResourceFactory<H>,
    preparation: Option<preparation::PackagedPreparation>,
    build_promotions: B,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
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
    // Mock host factories exercise actor composition without asserting that a
    // temporary directory carries an operator-installed project quota.
    // A supplied preparation preserves the original writer and complete
    // account after an exclusive startup inspection, through pool handoff.
    let preparation = match preparation {
        Some(preparation) => preparation,
        None => preparation::prepare_component_runtime(
            &storage.repository,
            Arc::clone(&storage.checkpoint_backend),
            &basis,
            &config,
        )?,
    };
    compose_packaged_qemu_executor_with_builders(
        storage,
        basis,
        config,
        shared,
        Some(preparation),
        build_promotions,
        |_store,
         checkpoints,
         finding_exact_retention,
         shared,
         worker_state_root,
         worker_count,
         lifecycles,
         _finding_replay_brokers,
         lifecycle_config,
         _resource_ceiling,
         _preparation| {
            Ok(PackagedQemuInitialRunnerBuild::fresh(
                (0..worker_count)
                    .map(|slot| {
                        let lifecycle = lifecycle_config.try_clone_admitted()?.with_run_state_root(
                            worker_state_root.join(format!("worker-{slot:03}")),
                        );
                        let fresh_lifecycles = PackagedStatusLifecycleFactory {
                            inner: QemuAttemptProductionVmLifecycleFactory::new(
                                lifecycle,
                                ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                            )
                            .with_terminal_checkpoints(Arc::clone(checkpoints)),
                            lifecycles: lifecycles.clone(),
                        };
                        let (fresh_lifecycles, evidence) =
                            QemuObservedFreshAttemptLifecycleFactory::with_evidence(
                                fresh_lifecycles,
                            );
                        Ok::<_, PackagedQemuExecutorError>((
                            QemuFreshExecutionRunner::new(fresh_lifecycles, QemuFreshModeledDriver)
                                .with_terminal_exact_retention_source(Arc::clone(
                                    finding_exact_retention,
                                )),
                            evidence,
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        },
    )
}

fn compose_packaged_qemu_executor_with_builders<H, P, B, I, R>(
    storage: PackagedQemuExecutorStorage,
    basis: PackagedCampaignBasis,
    config: PackagedQemuExecutorConfig,
    shared: SharedQemuAttemptHostResourceFactory<H>,
    preparation: Option<preparation::PackagedPreparation>,
    build_promotions: B,
    build_initial_runners: I,
) -> Result<PackagedQemuExecutor, PackagedQemuExecutorError>
where
    H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
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
    I: FnOnce(
        &CampaignExecutorStore,
        &Arc<ExactCheckpointStore>,
        &Arc<dyn crate::automatic_finding_runner::FindingExactRetentionSource>,
        &SharedQemuAttemptHostResourceFactory<H>,
        &Path,
        usize,
        &PackagedWorldLifecycleTracker,
        &[QemuHotForkWorldAuxiliaryResourceBroker<
            crate::ComposedQemuAttemptResourceGuard<H::Owner>,
        >],
        &ProductionVmLifecycleConfig,
        AttemptResourceLimits,
        &preparation::PackagedPreparation,
    ) -> Result<PackagedQemuInitialRunnerBuild<R>, PackagedQemuExecutorError>,
    R: crate::QemuAttemptStartVerifier + crate::QemuSelectedOriginVerifier + Send + 'static,
    R::Error: std::error::Error + 'static,
{
    let PackagedQemuExecutorStorage {
        repository,
        checkpoint_backend,
    } = storage;
    let guarded_config = config.clone();
    let campaigns = config.campaigns.clone();
    let ledger_root = config.ledger_root.clone();
    let preparation = match preparation {
        Some(prepared) => prepared,
        None => preparation::prepare_runtime(&repository, checkpoint_backend, &basis, &config)?,
    };
    let checkpoints = Arc::clone(&preparation.checkpoints);
    let lifecycle_metadata = crucible::owned_decode::DecodeBudget::for_store(
        checkpoints.metadata_resource_authority()?,
    )?;
    let _lifecycle_scope = lifecycle_metadata.enter();
    let finding_exact_retention = preparation.prepared_exact_pins.finding_retention_source();
    let resource_ceiling = packaged_resource_ceiling(&config)?;
    let campaign_debug = Arc::new(crate::CampaignDebugQemuCapability::new(
        Arc::clone(&checkpoints),
        config
            .admitted_lifecycle_config()?
            .with_run_state_root(config.lifecycle.run_state_root().join("campaign-debug")),
        shared.clone(),
        RetainedTemplateServiceFactory::new(&preparation, &config),
    ));
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let worker_state_root = config.lifecycle.run_state_root().join("campaign-workers");
    let finding_replay_state_root = config
        .lifecycle
        .run_state_root()
        .join("campaign-finding-replays");
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
    let lifecycles = PackagedWorldLifecycleTracker::new();
    let finding_replay_brokers = (0..config.worker_count)
        .map(|_| QemuHotForkWorldAuxiliaryResourceBroker::new())
        .collect::<Vec<_>>();
    let initial_runner_build = build_initial_runners(
        &store,
        &checkpoints,
        &finding_exact_retention,
        &shared,
        &worker_state_root,
        config.worker_count,
        &lifecycles,
        &finding_replay_brokers,
        &config.lifecycle,
        resource_ceiling,
        &preparation,
    )?;
    let preparation::PackagedPreparation {
        actor,
        host_operational_registry,
        checkpoints,
        prepared_exact_pins,
        checkpoint_observer,
        prepared_results,
        ..
    } = preparation;
    if initial_runner_build.runners.len() != config.worker_count {
        return Err(PackagedQemuExecutorError::InitialRunnerCount {
            expected: config.worker_count,
            actual: initial_runner_build.runners.len(),
        });
    }
    let hot_fork_enabled = initial_runner_build.hot_fork_owner.is_some();
    if hot_fork_enabled != config.hot_fork.is_some() {
        return Err(PackagedQemuExecutorError::HotForkCompositionMismatch);
    }
    let hot_fork_retention = initial_runner_build
        .hot_fork_owner
        .as_ref()
        .map(|owner| owner.retention_admin());
    let hot_fork_owner = initial_runner_build.hot_fork_owner;
    let promotion_enabled = !promotion_workers.is_empty();
    let mut materialization = BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]);
    if promotion_enabled {
        materialization.insert(ExecutorMaterializationCapability::ExactRestore);
    }
    if hot_fork_enabled {
        materialization.insert(ExecutorMaterializationCapability::HotFork);
    }
    let aggregate = crucible_api::host_operational::HostResourceVector {
        resident_peak_bytes: config.capacity.maximum_resident_bytes(),
        backing_peak_bytes: config.capacity.maximum_disk_bytes(),
        metadata_bytes: config.host_operational_capacity.maximum_metadata_bytes(),
        staging_bytes: config.host_operational_capacity.maximum_staging_bytes(),
        paging_io_slots: config.host_operational_capacity.maximum_paging_io_slots(),
        cpu_slots: u64::from(config.capacity.maximum_vcpus()),
        task_slots: config.host_operational_capacity.maximum_task_slots(),
        file_descriptors: config.host_operational_capacity.maximum_file_descriptors(),
    };
    let assignment = config
        .assignment_resources()
        .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?;
    let bounds = crucible_campaign::ExecutorResourceBounds::new(
        crate::executor_capability::portable_resources(aggregate),
        crate::executor_capability::portable_resources(assignment),
        resource_ceiling,
    )?;
    let capabilities = ExecutorCapabilitySet::new(
        basis.profile.clone(),
        config.host_architecture,
        BTreeSet::from([config.qemu_profile]),
        materialization,
        config.capacity.maximum_concurrent_executions(),
        bounds,
        BTreeSet::from([config.store_namespace]),
    )?;
    let description = ExecutorDescription::new(config.daemon_epoch, capabilities)?;
    let guest_selectable_diagnostics = config
        .guest_selectable_boundary_diagnostics
        .map(GuestSelectableBoundaryDiagnosticRecorder::stderr)
        .unwrap_or_default();
    let workers = initial_runner_build
        .runners
        .into_iter()
        .zip(finding_replay_brokers)
        .enumerate()
        .map(|(slot, ((fresh, evidence), finding_replay_broker))| {
            let finding_replay_config = config
                .lifecycle
                .try_clone_admitted()?
                .with_run_state_root(finding_replay_state_root.join(format!("worker-{slot:03}")));
            let finding_replay_lifecycle = Arc::new(finding_replay_config);
            let finding_replay_resources = QemuHotForkWorldAuxiliaryResourceFactory::new(
                finding_replay_broker,
                ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
            );
            let finding_replay_lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
                finding_replay_lifecycle.clone(),
                finding_replay_resources,
            )
            .with_terminal_checkpoints(Arc::clone(&checkpoints));
            let finding_replay =
                packaged_finding_replay_runner(finding_replay_lifecycle, finding_replay_lifecycles);

            let lifecycle = config
                .lifecycle
                .try_clone_admitted()?
                .with_run_state_root(worker_state_root.join(format!("worker-{slot:03}")));
            let resume_lifecycles = PackagedStatusLifecycleFactory {
                inner: QemuAttemptProductionVmLifecycleFactory::new(
                    lifecycle,
                    ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
                )
                .with_terminal_checkpoints(Arc::clone(&checkpoints)),
                lifecycles: lifecycles.clone(),
            };
            let resume_lifecycles = QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
                resume_lifecycles,
                evidence.clone(),
            );
            let resume = QemuProductionExactResumeExecutionRunner::new(
                Arc::clone(&checkpoints),
                resume_lifecycles,
                QemuFreshModeledDriver,
            );
            let runner = QemuAttemptExecutionRouter::new(fresh, resume);
            let runner = QemuTerminalEvidenceExecutionRunner::new(runner, evidence.clone());
            let mut runner = AutomaticFindingExecutionRunner::new(
                store.clone(),
                Arc::clone(&finding_exact_retention),
                runner,
                finding_replay,
            )
            .with_exact_failure_evidence(evidence);
            if config.verify_determinism_findings {
                runner = runner.with_determinism_finding_verification();
            }
            let model = CrucibleExecutionModel::new(store.clone(), runner);
            Ok::<_, PackagedQemuExecutorError>(PackagedStatusAttemptWorker {
                inner: RepositoryAttemptWorker::new(store.clone(), model)
                    .with_guest_selectable_boundary_diagnostics(
                        guest_selectable_diagnostics.clone(),
                    ),
                lifecycles: lifecycles.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    lifecycle_metadata.check()?;
    let guarded_state = guarded::PackagedGuardedState {
        actor: actor.campaign_port(),
        config: guarded_config,
        checkpoints: Arc::clone(&checkpoints),
        host: None,
    };
    let pool = LocalExecutorWorkerPool::start_prepared_with_observer(
        (actor, description),
        store,
        checkpoints,
        workers,
        promotion_workers,
        checkpoint_observer,
        Some(prepared_results),
    )?;
    let pool_status = pool.service();
    let pool_shutdown = pool.shutdown_handle();
    let exact_pin_materializer = prepared_exact_pins.start(move || pool_shutdown.shutdown())?;
    let operational_status: Arc<dyn CampaignOperationalStatusProvider> =
        Arc::new(PackagedQemuOperationalStatusProvider {
            repository: Arc::clone(&repository),
            campaigns,
            ledger_root,
            pool: pool_status,
            lifecycles,
            materializer: exact_pin_materializer.status_handle(),
        });
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
        guarded_state,
        host_operational_registry,
        repository_identity: repository,
        admitted_scenarios: basis.scenarios,
        endpoint,
        service,
        exact_pin_materializer,
        operational_status,
        hot_fork_owner,
        hot_fork_retention,
        campaign_debug,
    })
}

// These are every ephemeral native lifecycle tree created by the packaged
// composition. Durable exact/thin fallback records live under the campaign
// service state directory and are deliberately outside this restart cleanup.
const PACKAGED_NATIVE_NAMESPACES: [&str; 7] = [
    "campaign-workers",
    "campaign-finding-replays",
    "campaign-checkpoint-promotions",
    "campaign-baked-genesis",
    "campaign-debug",
    "campaign-hot-fork-sources",
    "campaign-hot-fork-demanded",
];
const PACKAGED_PREPARED_RESULT_NAMESPACE: &str = "campaign-prepared-results";

fn prepare_packaged_prepared_result_namespace(
    run_state_root: &Path,
) -> Result<PathBuf, PackagedNativeCatalogRecoveryError> {
    let namespace = run_state_root.join(PACKAGED_PREPARED_RESULT_NAMESPACE);
    fs::create_dir_all(&namespace).map_err(|source| PackagedNativeCatalogRecoveryError::Io {
        operation: "create",
        path: namespace.clone(),
        source,
    })?;
    if !packaged_directory_presence(&namespace)? {
        return Err(PackagedNativeCatalogRecoveryError::InvalidPath { path: namespace });
    }
    sync_packaged_native_parent(&namespace)?;
    sync_packaged_native_parent(run_state_root)?;
    Ok(namespace)
}

fn reconcile_packaged_native_catalogs(
    run_state_root: &Path,
) -> Result<(), PackagedNativeCatalogRecoveryError> {
    for namespace in PACKAGED_NATIVE_NAMESPACES {
        retire_packaged_native_namespace(run_state_root, namespace)?;
    }
    Ok(())
}

fn retire_packaged_native_namespace(
    parent: &Path,
    namespace: &'static str,
) -> Result<(), PackagedNativeCatalogRecoveryError> {
    let active = parent.join(namespace);
    let retired = parent.join(format!(".retired-{namespace}"));
    let active_present = packaged_directory_presence(&active)?;
    let retired_present = packaged_directory_presence(&retired)?;
    if active_present && retired_present {
        return Err(PackagedNativeCatalogRecoveryError::ConflictingGeneration { namespace });
    }
    if retired_present {
        remove_packaged_native_namespace(parent, &retired)?;
    }
    if !active_present {
        sync_packaged_native_parent(parent)?;
        return Ok(());
    }

    fs::rename(&active, &retired).map_err(|source| PackagedNativeCatalogRecoveryError::Io {
        operation: "rename",
        path: active,
        source,
    })?;
    sync_packaged_native_parent(parent)?;
    remove_packaged_native_namespace(parent, &retired)
}

fn packaged_directory_presence(path: &Path) -> Result<bool, PackagedNativeCatalogRecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(PackagedNativeCatalogRecoveryError::InvalidPath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(PackagedNativeCatalogRecoveryError::Io {
            operation: "inspect",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_packaged_native_namespace(
    parent: &Path,
    retired: &Path,
) -> Result<(), PackagedNativeCatalogRecoveryError> {
    fs::remove_dir_all(retired).map_err(|source| PackagedNativeCatalogRecoveryError::Io {
        operation: "remove",
        path: retired.to_path_buf(),
        source,
    })?;
    sync_packaged_native_parent(parent)
}

fn sync_packaged_native_parent(parent: &Path) -> Result<(), PackagedNativeCatalogRecoveryError> {
    let directory = match File::open(parent) {
        Ok(directory) => directory,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(PackagedNativeCatalogRecoveryError::Io {
                operation: "open parent for synchronization",
                path: parent.to_path_buf(),
                source,
            });
        }
    };
    directory
        .sync_all()
        .map_err(|source| PackagedNativeCatalogRecoveryError::Io {
            operation: "synchronize parent",
            path: parent.to_path_buf(),
            source,
        })
}

fn packaged_resource_ceiling(
    config: &PackagedQemuExecutorConfig,
) -> Result<AttemptResourceLimits, PackagedQemuExecutorError> {
    config
        .assignment_limits()
        .ok_or_else(|| crucible_api::host_operational::HostOperationalError::Unavailable.into())
}

#[derive(Clone, Default)]
pub(crate) struct PackagedAttemptAdmission {
    authority: Arc<OnceLock<ClosedPackagedAdmission>>,
}

impl PackagedAttemptAdmission {
    fn new(
        repository: Arc<CampaignRepository>,
        profile: ExecutorCompatibilityProfile,
        scenarios: BTreeSet<ScenarioArtifactId>,
    ) -> Self {
        let authority = OnceLock::from(ClosedPackagedAdmission {
            repository,
            profile,
            scenarios,
        });
        Self {
            authority: Arc::new(authority),
        }
    }

    fn bind(
        &self,
        repository: Arc<CampaignRepository>,
        profile: ExecutorCompatibilityProfile,
        scenarios: BTreeSet<ScenarioArtifactId>,
    ) -> Result<(), crucible_api::host_operational::HostOperationalError> {
        if let Some(current) = self.authority.get() {
            return if Arc::ptr_eq(&current.repository, &repository)
                && current.profile == profile
                && current.scenarios == scenarios
            {
                Ok(())
            } else {
                Err(crucible_api::host_operational::HostOperationalError::Unavailable)
            };
        }
        self.authority
            .set(ClosedPackagedAdmission {
                repository,
                profile,
                scenarios,
            })
            .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)
    }

    fn get(&self) -> Result<&ClosedPackagedAdmission, ExecutorRejection> {
        self.authority.get().ok_or(ExecutorRejection::Unauthorized)
    }
}

impl AttemptAdmissionValidator for PackagedAttemptAdmission {
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        self.get()?.validate(request)
    }

    fn validate_execution_scope(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<(), ExecutorRejection> {
        self.get()?.validate_execution_scope(request)
    }

    fn selected_savepoint_source_attempt(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<Option<AttemptId>, ExecutorRejection> {
        self.get()?.selected_savepoint_source_attempt(request)
    }

    fn validate_completion(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        self.get()
            .map_err(|_| CompletionValidationFailure::Unauthorized)?
            .validate_completion(request, observation)
    }

    fn validate_completion_artifacts(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
        finding: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        self.get()
            .map_err(|_| CompletionValidationFailure::Unauthorized)?
            .validate_completion_artifacts(request, observation, finding)
    }

    fn validate_retained_completion(
        &self,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        observation: ObservationId,
        finding: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        self.get()
            .map_err(|_| CompletionValidationFailure::Unauthorized)?
            .validate_retained_completion(lineage, attempt, observation, finding)
    }
}

#[derive(Clone)]
struct ClosedPackagedAdmission {
    repository: Arc<CampaignRepository>,
    profile: ExecutorCompatibilityProfile,
    scenarios: BTreeSet<ScenarioArtifactId>,
}

impl ClosedPackagedAdmission {
    fn validate_scenario(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        self.validate_lineage_scenario(request.lineage())
    }

    fn validate_lineage_scenario(
        &self,
        lineage: CampaignLineageId,
    ) -> Result<(), ExecutorRejection> {
        let lineage = self
            .repository
            .load_lineage(lineage)
            .map_err(|error| error.executor_rejection())?;
        if !self.scenarios.contains(&lineage.scenario_content()) {
            return Err(ExecutorRejection::Incompatible);
        }
        Ok(())
    }
}

impl AttemptAdmissionValidator for ClosedPackagedAdmission {
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        self.repository
            .validate_executor_request_with_profile(request, &self.profile)
            .map_err(|error| error.executor_rejection())?;
        self.validate_scenario(request)
    }

    fn validate_execution_scope(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<(), ExecutorRejection> {
        self.repository
            .validate_executor_execution_scope_with_profile(request, &self.profile)
            .map_err(|error| error.executor_rejection())?;
        self.validate_scenario(request)
    }

    fn selected_savepoint_source_attempt(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<Option<crucible_campaign::AttemptId>, ExecutorRejection> {
        self.repository
            .executor_selected_savepoint_source_attempt(request)
            .map_err(|error| error.executor_rejection())
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

    fn validate_completion_artifacts(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        self.repository
            .validate_executor_completion_artifacts_with_profile(
                request,
                observation,
                finding_candidate,
                &self.profile,
            )
            .map_err(completion_validation_failure)?;
        self.validate_scenario(request)
            .map_err(|_| CompletionValidationFailure::Incompatible)
    }

    fn validate_retained_completion(
        &self,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        self.repository
            .validate_retained_executor_completion_with_profile(
                lineage,
                attempt,
                observation,
                finding_candidate,
                &self.profile,
            )
            .map_err(completion_validation_failure)?;
        self.validate_lineage_scenario(lineage)
            .map_err(|_| CompletionValidationFailure::Incompatible)
    }
}

fn completion_validation_failure(error: CampaignRepositoryError) -> CompletionValidationFailure {
    match error.executor_rejection() {
        ExecutorRejection::UnavailableInput => CompletionValidationFailure::UnavailableInput,
        ExecutorRejection::Unauthorized => CompletionValidationFailure::Unauthorized,
        ExecutorRejection::Incompatible
        | ExecutorRejection::Backpressure
        | ExecutorRejection::ConflictingAssignment
        | ExecutorRejection::TerminalFailure => CompletionValidationFailure::Incompatible,
    }
}

/// Failure to acquire or compose one packaged local QEMU executor.
#[derive(Debug, thiserror::Error)]
pub enum PackagedQemuExecutorError {
    /// Original provider-service bootstrap refused before error erasure.
    #[error(transparent)]
    ProviderServiceAdmission(#[from] crate::ProviderServiceAdmissionError),
    /// A required mutable lifecycle copy lacks its original allocation custody.
    #[error(transparent)]
    LifecycleConfiguration(#[from] crucible_api::vm_lifecycle::ProductionVmLifecycleConfigCloneError),
    /// The original catalog refused lifecycle metadata allocation.
    #[error(transparent)]
    DecodedMetadata(#[from] crucible::owned_decode::DecodeAdmissionError),
    /// The original registry namespace lacks its exact physical quota authority.
    #[error("operational registry physical quota admission failed: {0}")]
    RegistryQuota(#[from] crucible_linux_resource::LinuxProjectQuotaError),
    /// Persistent native RAM catalog containment or admission failed.
    #[error(transparent)]
    RamCatalog(#[from] crucible_cas::content_store::StoreError),
    /// Durable host operational authority could not be acquired safely.
    #[error(transparent)]
    HostOperational(#[from] crucible_api::host_operational::HostOperationalError),
    /// The complete retained world cannot satisfy its actual RAM launch contract.
    #[error("host RAM launch admission failed: {0}")]
    HostRamAdmission(#[from] crucible_api::vm_lifecycle::HostRamAdmissionError),
    /// Preparation could not start its separately charged watchdog or namespace.
    #[error("packaged preparation supervision failed: {0}")]
    PreparationSupervisor(#[source] std::io::Error),
    /// Preparation could not prove that its complete physical service was cleaned.
    #[error("packaged preparation cleanup remains uncertain: {source}")]
    PreparationCleanup {
        /// Physical authority that refused a capacity discharge.
        #[source]
        source: crucible_api::host_operational::HostOperationalError,
        /// Original preparation failure retained for containment diagnostics.
        preparation: Option<Box<PackagedQemuExecutorError>>,
    },
    /// Preparation expired before its cleaned native candidate could be accepted.
    #[error("packaged preparation host allowance expired")]
    PreparationExpired {
        /// Failure returned by the canceled capture, when one was available.
        #[source]
        source: Option<PreparationExpiredCause>,
    },
    /// The internal deployment contract named no campaign.
    #[error("packaged QEMU executor has no campaign")]
    NoCampaigns,
    /// The lineage requests a closure format this concrete executor cannot emit.
    #[error("packaged QEMU executor supports exact closure schema {supported}, not {actual}")]
    UnsupportedExactClosureSchema {
        /// Requested lineage compatibility version.
        actual: u32,
        /// Concrete checkpoint writer's version.
        supported: u32,
    },
    /// A configured campaign does not share the pool's exact compatibility basis.
    #[error(
        "campaign `{}` is incompatible with the packaged QEMU executor pool",
        campaign.as_str()
    )]
    CampaignCompatibilityMismatch {
        /// Incompatible configured campaign.
        campaign: CampaignName,
    },
    /// The selected immutable QEMU artifacts do not match the lineage build.
    #[error("selected QEMU build `{actual}` differs from campaign lineage build `{expected}`")]
    QemuBuildMismatch {
        /// Build identity authenticated by the campaign lineage.
        expected: String,
        /// Build identity authenticated from the selected QEMU and plugin artifacts.
        actual: String,
    },
    /// The authenticated launch receipt names different lifecycle artifacts.
    #[error("packaged hot-fork launch receipt differs from lifecycle QEMU or plugin path")]
    HotForkLaunchPathMismatch,
    /// Initial-runner construction disagreed with the configured hot-fork policy.
    #[error("packaged hot-fork policy and constructed source owner disagree")]
    HotForkCompositionMismatch,
    /// Campaign or lineage authentication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// A retained-source basis failed closed authentication.
    #[error(transparent)]
    HotForkSourceBasis(#[from] AuthenticatedQemuHotForkSourceBasisError),
    /// The retained Crucible scenario artifact failed semantic authentication.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The complete native scenario catalog exceeds its startup work bound.
    #[error("packaged QEMU scenario catalog exceeds {maximum} canonical bytes")]
    ScenarioCatalogBytesExceeded {
        /// Maximum admitted aggregate canonical record-body bytes.
        maximum: usize,
    },
    /// Exact baked-genesis capture or complete native admission failed.
    #[error("packaged QEMU baked-genesis capture failed for scenario {scenario:?}")]
    BakedGenesis {
        /// Exact scenario whose native capture failed.
        scenario: ScenarioArtifactId,
        /// Guarded capture or native admission failure.
        #[source]
        source: Box<ProductionBakedGenesisCaptureError<QemuAttemptProductionVmLifecycleError>>,
    },
    /// The durable retained-source fallback catalog could not be opened.
    #[error(transparent)]
    HotForkRetention(#[from] HotCheckpointFallbackRetentionError),
    /// Existing retained-source fallback records could not be authenticated.
    #[error(transparent)]
    HotForkPool(#[from] ManagedQemuHotForkSourceWorldPoolConstructionError),
    /// A canonical source world could not be launched and prepared.
    #[error("capture packaged hot-fork source for lineage {lineage}")]
    HotForkSourceCapture {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Guarded launch or source-world preparation failure.
        #[source]
        source: Box<ProductionQemuHotForkSourceCaptureError>,
    },
    /// A prepared source world failed managed admission and entered quarantine.
    #[error("admit packaged hot-fork source for lineage {lineage}")]
    HotForkSourceAdmission {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Source-free admission diagnostic after quarantine.
        #[source]
        source:
            Box<ManagedQemuHotForkAuthenticatedAdmissionError<PackagedQemuHotForkDemotionError>>,
    },
    /// A binding-rejected source could not attest complete process/resource cleanup.
    #[error("clean up binding-rejected packaged hot-fork source for lineage {lineage}: {binding}")]
    HotForkSourceBindingCleanup {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Original source binding rejection.
        binding: Box<
            crate::managed_qemu_hot_fork_source_world_pool::ManagedQemuHotForkSourceWorldBindingError,
        >,
        /// Complete source-world retirement failure. Its retained lifecycle has
        /// already entered the production quarantine path.
        #[source]
        retirement: Box<crucible_api::LifecycleApiError>,
    },
    /// Cold-fallback retention failed while the declined source was also cleaned up.
    #[error("retain fallback and clean up policy-declined hot-fork source for lineage {lineage}")]
    HotForkRejectedSourceCleanup {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Durable fallback retention failure.
        #[source]
        retention:
            Box<ManagedQemuHotForkSourceWorldAdmissionError<PackagedQemuHotForkDemotionError>>,
        /// Source retirement failure, when retirement was attempted but did not complete.
        retirement: Option<Box<crucible_api::LifecycleApiError>>,
        /// Whether an unavailable managed candidate was retained for the process lifetime.
        candidate_quarantined: bool,
    },
    /// A policy-declined source could not be safely retired after fallback retention.
    #[error("retire policy-declined packaged hot-fork source for lineage {lineage}")]
    HotForkRejectedSourceRetirement {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Complete source-world retirement failure.
        #[source]
        source: crucible_api::LifecycleApiError,
    },
    /// A fixed worker could not acquire an independent shared-pool session.
    #[error(transparent)]
    HotForkProvider(#[from] SharedQemuHotForkSourceWorldProviderConstructionError),
    /// Source capture failed and one or more earlier sources also failed cleanup.
    #[error("packaged hot-fork startup and retained-source cleanup both failed")]
    HotForkStartupCleanup {
        /// Primary startup failure.
        #[source]
        source: Box<PackagedQemuExecutorError>,
        /// Complete keyed cleanup failure report.
        cleanup: Box<PackagedQemuHotForkSourceShutdownError>,
    },
    /// The complete native scenario catalog was empty or ambiguous.
    #[error(transparent)]
    BakedGenesisCatalog(#[from] ProductionBakedGenesisReplayCatalogError),
    /// Durable assignment-ledger acquisition failed.
    #[error(transparent)]
    Ledger(#[from] AssignmentLedgerError),
    /// Durable prepared-result journal namespace acquisition failed.
    #[error(transparent)]
    PreparedResults(#[from] PreparedResultJournalError),
    /// Pending finding incorporation could not be resumed safely.
    #[error("reconcile pending finding candidates after packaged executor restart")]
    FindingRestart(#[source] crate::FindingCandidateRestartError<AssignmentLedgerError>),
    /// A bounded restart pass left work without releasing any matching root.
    #[error(
        "campaign `{}` finding restart made no progress with {remaining} roots remaining",
        campaign.as_str()
    )]
    FindingRestartNoProgress {
        /// Campaign whose pending finding roots could not advance.
        campaign: CampaignName,
        /// Roots deferred after the stalled pass.
        remaining: usize,
    },
    /// Abandoned attempt-local native checkpoint state could not be reconciled.
    #[error(transparent)]
    NativeCatalogRecovery(#[from] PackagedNativeCatalogRecoveryError),
    /// Durable exact-checkpoint store construction failed.
    #[error(transparent)]
    Checkpoints(#[from] ExactCheckpointStoreError),
    /// Exact-pin journal acquisition or startup reconciliation failed.
    #[error(transparent)]
    ExactPinMaterializer(Box<PackagedExactPinMaterializerError>),
    /// Linux process/storage resource ownership could not be acquired.
    #[error(transparent)]
    Host(#[from] QemuVmRealizationError),
    /// An immutable executor capability or resource bound was invalid.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// Fixed semantic-worker construction failed.
    #[error(transparent)]
    Pool(#[from] LocalExecutorPoolConfigError),
    /// Internal initial-runner construction did not cover every fixed worker.
    #[error("packaged QEMU initial runner count is {actual}, expected {expected}")]
    InitialRunnerCount {
        /// Fixed semantic-worker count.
        expected: usize,
        /// Constructed initial-runner count.
        actual: usize,
    },
    /// Managed endpoint acquisition failed.
    #[error(transparent)]
    Endpoint(#[from] LocalComponentEndpointError),
    /// Fixed listener construction failed.
    #[error(transparent)]
    Listener(#[from] ExecutorLoopbackListenerError),
}

impl From<PackagedExactPinMaterializerError> for PackagedQemuExecutorError {
    fn from(source: PackagedExactPinMaterializerError) -> Self {
        Self::ExactPinMaterializer(Box::new(source))
    }
}

/// Failure to reconcile abandoned packaged-worker native checkpoint state.
#[derive(Debug, thiserror::Error)]
pub enum PackagedNativeCatalogRecoveryError {
    /// Active and retired generations appeared together under exclusive ownership.
    #[error("packaged native namespace `{namespace}` has conflicting generations")]
    ConflictingGeneration {
        /// Dedicated worker namespace with conflicting generations.
        namespace: &'static str,
    },
    /// A dedicated namespace path was replaced by another filesystem type.
    #[error("packaged native namespace path is not a directory: {path}")]
    InvalidPath {
        /// Path that violated the worker-state namespace contract.
        path: PathBuf,
    },
    /// Durable namespace reconciliation failed.
    #[error("{operation} packaged native namespace {path}: {source}")]
    Io {
        /// Stable filesystem operation label.
        operation: &'static str,
        /// Exact path involved in the failed operation.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
}
