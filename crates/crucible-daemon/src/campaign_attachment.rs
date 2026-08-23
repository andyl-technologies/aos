//! Concrete single-host attachment for one canonical campaign runtime.
//!
//! This module composes the repository-owned coordinator with the packaged
//! canonical planner process and one already-connected local executor stream.
//! Attachment performs capability negotiation and exact lineage validation
//! before publishing the deterministic planner basis or starting a thread.
//! The caller remains responsible for authenticating the executor peer before
//! handing over the connected stream.

use std::cmp;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crucible_campaign::{
    AttemptResourceLimits, AuthorizedPlannerService, AuthorizedPlannerServiceError,
    CampaignCodecError, CampaignExecutorDriver, CampaignExecutorDriverConfigError, CampaignName,
    CampaignPlannerDriver, CampaignPlannerDriverConfigError, CampaignRepository,
    CampaignRepositoryError, CampaignSupervisor, CampaignSupervisorConfigError,
    CampaignSupervisorError, CanonicalFrontierPlanner, ExecutionRetentionIntent, ExecutorClient,
    ExecutorClientError, MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS, MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS,
    MAX_PLANNER_SCAN_PAGE_ITEMS, PlannerAuthorityKey, PlannerClient, PlanningBudget,
};

use crate::{
    CampaignRuntime, CampaignRuntimeCompletion, CampaignRuntimeConfig, CampaignRuntimeJoinError,
    CampaignRuntimeReport, CampaignRuntimeStartError, CanonicalPlannerProcessCancellation,
    CanonicalPlannerProcessConfig, CanonicalPlannerProcessError, CanonicalPlannerProcessSupervisor,
    LoopbackExecutorProtocolError, LoopbackExecutorService,
};

/// Default positions served to one packaged planner invocation.
pub const DEFAULT_CANONICAL_PLANNER_SCAN_LIMIT: u32 = 1_024;

/// Default accounting positions scanned by one executor-driver step.
pub const DEFAULT_CANONICAL_EXECUTOR_SCAN_LIMIT: usize = 1_024;

/// Default canonical planner input-byte allowance per invocation.
pub const DEFAULT_CANONICAL_PLANNER_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Exact startup contract for one canonical single-host campaign runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalCampaignRuntimeConfig {
    campaign: CampaignName,
    planner_process: CanonicalPlannerProcessConfig,
    planner_scan_limit: u32,
    planning_budget: PlanningBudget,
    executor_resources: Option<AttemptResourceLimits>,
    retention: ExecutionRetentionIntent,
    executor_scan_limit: usize,
    worker_slots: Option<u32>,
    runtime: CampaignRuntimeConfig,
}

impl CanonicalCampaignRuntimeConfig {
    /// Builds one explicit canonical runtime attachment contract.
    ///
    /// `None` executor resources select the executor's advertised per-attempt
    /// ceiling. `None` worker slots select its advertised slot ceiling capped
    /// by the coordinator's fixed 256-slot bound.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalCampaignRuntimeConfigError`] when either scan limit
    /// or an explicit worker-slot count is outside its fixed protocol bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign: CampaignName,
        planner_process: CanonicalPlannerProcessConfig,
        planner_scan_limit: u32,
        planning_budget: PlanningBudget,
        executor_resources: Option<AttemptResourceLimits>,
        retention: ExecutionRetentionIntent,
        executor_scan_limit: usize,
        worker_slots: Option<u32>,
        runtime: CampaignRuntimeConfig,
    ) -> Result<Self, CanonicalCampaignRuntimeConfigError> {
        if planner_scan_limit == 0 || planner_scan_limit > MAX_PLANNER_SCAN_PAGE_ITEMS {
            return Err(CanonicalCampaignRuntimeConfigError::InvalidPlannerScanLimit);
        }
        if executor_scan_limit == 0 || executor_scan_limit > MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS {
            return Err(CanonicalCampaignRuntimeConfigError::InvalidExecutorScanLimit);
        }
        if worker_slots
            .is_some_and(|slots| slots == 0 || slots > MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS)
        {
            return Err(CanonicalCampaignRuntimeConfigError::InvalidWorkerSlots);
        }
        Ok(Self {
            campaign,
            planner_process,
            planner_scan_limit,
            planning_budget,
            executor_resources,
            retention,
            executor_scan_limit,
            worker_slots,
            runtime,
        })
    }

    /// Builds the reviewed default attachment profile.
    ///
    /// The profile serves at most 1,024 positions and 16 MiB per planner call,
    /// retains exact state on modeled failure, uses the executor's advertised
    /// resource ceiling, and caps worker slots at 256.
    ///
    /// # Errors
    ///
    /// Returns a codec or configuration error if a fixed default unexpectedly
    /// violates the canonical budget or attachment bounds.
    pub fn canonical_defaults(
        campaign: CampaignName,
        planner_process: CanonicalPlannerProcessConfig,
    ) -> Result<Self, CanonicalCampaignRuntimeConfigError> {
        let planning_budget = PlanningBudget::new(
            1,
            1,
            DEFAULT_CANONICAL_PLANNER_SCAN_LIMIT,
            DEFAULT_CANONICAL_PLANNER_INPUT_BYTES,
            u64::from(DEFAULT_CANONICAL_PLANNER_SCAN_LIMIT) + 1,
        )
        .map_err(CanonicalCampaignRuntimeConfigError::Codec)?;
        Self::new(
            campaign,
            planner_process,
            DEFAULT_CANONICAL_PLANNER_SCAN_LIMIT,
            planning_budget,
            None,
            ExecutionRetentionIntent::RetainOnFailure,
            DEFAULT_CANONICAL_EXECUTOR_SCAN_LIMIT,
            None,
            CampaignRuntimeConfig::default(),
        )
    }

    /// Returns the exact campaign selected at process startup.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the packaged planner process contract.
    #[must_use]
    pub const fn planner_process(&self) -> &CanonicalPlannerProcessConfig {
        &self.planner_process
    }

    /// Returns the planner page bound.
    #[must_use]
    pub const fn planner_scan_limit(&self) -> u32 {
        self.planner_scan_limit
    }

    /// Returns the complete planner invocation budget.
    #[must_use]
    pub const fn planning_budget(&self) -> PlanningBudget {
        self.planning_budget
    }

    /// Returns the requested resources or `None` for advertised ceilings.
    #[must_use]
    pub const fn executor_resources(&self) -> Option<AttemptResourceLimits> {
        self.executor_resources
    }

    /// Returns the exact execution-retention intent.
    #[must_use]
    pub const fn retention(&self) -> ExecutionRetentionIntent {
        self.retention
    }

    /// Returns the executor accounting page bound.
    #[must_use]
    pub const fn executor_scan_limit(&self) -> usize {
        self.executor_scan_limit
    }

    /// Returns explicit worker slots or `None` for advertised capacity.
    #[must_use]
    pub const fn worker_slots(&self) -> Option<u32> {
        self.worker_slots
    }

    /// Returns the long-lived runtime cadence.
    #[must_use]
    pub const fn runtime(&self) -> CampaignRuntimeConfig {
        self.runtime
    }
}

/// Invalid static canonical-runtime attachment configuration.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalCampaignRuntimeConfigError {
    /// The planner scan limit is outside `1..=10,000`.
    #[error("canonical campaign planner scan limit is outside 1..=10,000")]
    InvalidPlannerScanLimit,
    /// The executor scan limit is outside `1..=10,000`.
    #[error("canonical campaign executor scan limit is outside 1..=10,000")]
    InvalidExecutorScanLimit,
    /// The worker-slot count is zero or exceeds 256.
    #[error("canonical campaign worker slots are outside 1..=256")]
    InvalidWorkerSlots,
    /// A fixed canonical budget could not be constructed.
    #[error(transparent)]
    Codec(CampaignCodecError),
}

type CanonicalPlannerService =
    AuthorizedPlannerService<CanonicalFrontierPlanner, CanonicalPlannerProcessSupervisor>;
type CanonicalSupervisor = CampaignSupervisor<CanonicalPlannerService, LoopbackExecutorService>;
type CanonicalSupervisorFailure = CampaignSupervisorError<
    AuthorizedPlannerServiceError<CampaignCodecError, CanonicalPlannerProcessError>,
    LoopbackExecutorProtocolError,
>;

/// Prepared coordinator that has not started its long-lived thread.
#[must_use = "prepared campaign runtime must be started or explicitly dropped"]
pub struct PreparedCanonicalCampaignRuntime {
    repository_identity: Arc<CampaignRepository>,
    supervisor: CanonicalSupervisor,
    planner_cancellation: CanonicalPlannerProcessCancellation,
    runtime: CampaignRuntimeConfig,
}

impl PreparedCanonicalCampaignRuntime {
    pub(crate) fn uses_repository(&self, repository: &Arc<CampaignRepository>) -> bool {
        Arc::ptr_eq(&self.repository_identity, repository)
    }

    /// Starts the fixed campaign runtime thread.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalCampaignRuntimeError::RuntimeStart`] when the host
    /// refuses to create the one fixed thread.
    pub fn start(self) -> Result<AttachedCanonicalCampaignRuntime, CanonicalCampaignRuntimeError> {
        let runtime = CampaignRuntime::start(self.supervisor, self.runtime)
            .map_err(CanonicalCampaignRuntimeError::RuntimeStart)?;
        Ok(AttachedCanonicalCampaignRuntime {
            runtime,
            planner_cancellation: self.planner_cancellation,
        })
    }
}

/// Long-lived canonical campaign runtime attached to one local executor.
///
/// Dropping this owner synchronously cancels and joins the runtime so a
/// containing service cannot release repository ownership first.
#[must_use = "attached campaign runtime must be shut down and joined"]
pub struct AttachedCanonicalCampaignRuntime {
    runtime: CampaignRuntime<CanonicalSupervisor>,
    planner_cancellation: CanonicalPlannerProcessCancellation,
}

impl AttachedCanonicalCampaignRuntime {
    /// Returns a capability-free terminal completion signal.
    #[must_use]
    pub fn completion_handle(&self) -> CampaignRuntimeCompletion {
        self.runtime.completion_handle()
    }

    /// Requests sticky runtime and in-flight planner-process cancellation.
    pub fn request_shutdown(&self) {
        self.planner_cancellation.cancel();
        self.runtime.request_shutdown();
    }

    /// Stops and joins the runtime, returning its bounded counters.
    ///
    /// # Errors
    ///
    /// Returns a terminal driver failure or thread panic from the attached
    /// runtime. Planner cancellation is made sticky before joining.
    pub fn shutdown_and_join(
        mut self,
    ) -> Result<CampaignRuntimeReport, CanonicalCampaignRuntimeError> {
        self.planner_cancellation.cancel();
        self.runtime
            .shutdown_and_join_in_place()
            .map_err(CanonicalCampaignRuntimeError::Runtime)
    }
}

impl Drop for AttachedCanonicalCampaignRuntime {
    fn drop(&mut self) {
        self.planner_cancellation.cancel();
        let _ = self.runtime.shutdown_and_join_in_place();
    }
}

/// Prepares one exact built-in planner and checked local-executor composition.
///
/// The executor stream must already be connected and authenticated by the
/// deployment owner. This function first obtains immutable executor facts,
/// authenticates the selected campaign and exact lineage compatibility, and
/// validates requested ceilings. Only then does it publish the fixed planner
/// basis and construct the restart-rebuildable drivers.
///
/// # Errors
///
/// Returns [`CanonicalCampaignRuntimeError`] for transport, repository,
/// compatibility, resource, driver, or supervisor composition failure.
pub fn prepare_canonical_campaign_runtime(
    repository: Arc<CampaignRepository>,
    planner_authority: PlannerAuthorityKey,
    executor_stream: UnixStream,
    config: &CanonicalCampaignRuntimeConfig,
) -> Result<PreparedCanonicalCampaignRuntime, CanonicalCampaignRuntimeError> {
    let service = LoopbackExecutorService::new(executor_stream)
        .map_err(CanonicalCampaignRuntimeError::ExecutorProtocol)?;
    let mut executor = ExecutorClient::new(service);
    let description = executor
        .describe_executor()
        .map_err(CanonicalCampaignRuntimeError::ExecutorDescription)?;

    let head = repository
        .head(config.campaign().as_str())
        .map_err(CanonicalCampaignRuntimeError::Repository)?;
    let lineage = repository
        .load_lineage(head.snapshot().lineage())
        .map_err(CanonicalCampaignRuntimeError::Repository)?;
    let capabilities = description.capabilities();
    if !capabilities.compatibility().admits(&lineage) {
        return Err(CanonicalCampaignRuntimeError::ExecutorIncompatible);
    }

    let resources = config
        .executor_resources()
        .unwrap_or_else(|| capabilities.resource_ceiling());
    if !resources_fit(resources, capabilities.resource_ceiling()) {
        return Err(CanonicalCampaignRuntimeError::ExecutorResourcesExceedCeiling);
    }
    let worker_slots = config.worker_slots().unwrap_or_else(|| {
        cmp::min(
            capabilities.maximum_slots(),
            MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS,
        )
    });
    if worker_slots == 0 || worker_slots > capabilities.maximum_slots() {
        return Err(CanonicalCampaignRuntimeError::ExecutorSlotsExceedCeiling);
    }

    let basis = repository
        .publish_canonical_frontier_planner_basis()
        .map_err(CanonicalCampaignRuntimeError::Repository)?;
    let (planner_supervisor, planner_cancellation) =
        CanonicalPlannerProcessSupervisor::new(config.planner_process().clone());
    let planner_service = AuthorizedPlannerService::new(
        CanonicalFrontierPlanner,
        planner_supervisor,
        planner_authority.clone(),
    );
    let planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        PlannerClient::new(planner_service, planner_authority),
        basis.engine().clone(),
        basis.artifact().clone(),
        basis.initial_state().clone(),
        config.planner_scan_limit(),
        config.planning_budget(),
    )
    .map_err(CanonicalCampaignRuntimeError::PlannerDriver)?;
    let executor = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        executor,
        description.daemon_epoch(),
        usize::try_from(worker_slots)
            .map_err(|_| CanonicalCampaignRuntimeError::ExecutorSlotsExceedCeiling)?,
        resources,
        config.retention(),
        config.executor_scan_limit(),
    )
    .map_err(CanonicalCampaignRuntimeError::ExecutorDriver)?;
    let supervisor = CampaignSupervisor::new(
        Arc::clone(&repository),
        config.campaign().clone(),
        planner,
        executor,
        worker_slots,
    )
    .map_err(CanonicalCampaignRuntimeError::Supervisor)?;
    Ok(PreparedCanonicalCampaignRuntime {
        repository_identity: Arc::clone(&repository),
        supervisor,
        planner_cancellation,
        runtime: config.runtime(),
    })
}

fn resources_fit(requested: AttemptResourceLimits, ceiling: AttemptResourceLimits) -> bool {
    requested.maximum_vcpus() <= ceiling.maximum_vcpus()
        && requested.maximum_resident_bytes() <= ceiling.maximum_resident_bytes()
        && requested.maximum_disk_bytes() <= ceiling.maximum_disk_bytes()
        && requested.maximum_execution_quanta() <= ceiling.maximum_execution_quanta()
}

/// Failure while preparing, starting, or joining one canonical runtime.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalCampaignRuntimeError {
    /// The checked executor transport could not be constructed.
    #[error("canonical campaign executor transport is invalid")]
    ExecutorProtocol(#[source] LoopbackExecutorProtocolError),
    /// Immutable executor capability negotiation failed.
    #[error("canonical campaign executor description failed")]
    ExecutorDescription(#[source] ExecutorClientError<LoopbackExecutorProtocolError>),
    /// The selected campaign or its immutable basis could not be authenticated.
    #[error("canonical campaign repository validation failed")]
    Repository(#[source] CampaignRepositoryError),
    /// The executor compatibility profile does not admit the campaign lineage.
    #[error("canonical campaign executor is incompatible with the campaign lineage")]
    ExecutorIncompatible,
    /// Requested per-attempt resources exceed the executor's immutable ceiling.
    #[error("canonical campaign execution resources exceed the executor ceiling")]
    ExecutorResourcesExceedCeiling,
    /// Requested worker slots exceed the executor's immutable slot ceiling.
    #[error("canonical campaign worker slots exceed the executor ceiling")]
    ExecutorSlotsExceedCeiling,
    /// The canonical planner driver could not be configured.
    #[error("canonical campaign planner driver configuration failed")]
    PlannerDriver(#[source] CampaignPlannerDriverConfigError),
    /// The checked executor driver could not be configured.
    #[error("canonical campaign executor driver configuration failed")]
    ExecutorDriver(#[source] CampaignExecutorDriverConfigError),
    /// The two drivers could not be composed under one supervisor.
    #[error("canonical campaign supervisor configuration failed")]
    Supervisor(#[source] CampaignSupervisorConfigError),
    /// The fixed runtime thread could not be started.
    #[error("canonical campaign runtime could not start")]
    RuntimeStart(#[source] CampaignRuntimeStartError),
    /// The runtime stopped because its driver failed or its thread panicked.
    #[error("canonical campaign runtime stopped unexpectedly")]
    Runtime(#[source] CampaignRuntimeJoinError<CanonicalSupervisorFailure>),
}

#[cfg(test)]
mod tests;
