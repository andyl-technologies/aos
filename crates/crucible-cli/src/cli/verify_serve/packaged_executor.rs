//! Strict deployment-file adapter for the packaged campaign QEMU executor.
//!
//! The TOML envelope is versioned independently of modeled campaign identities:
//!
//! ```toml
//! schema = "crucible.campaign-packaged-executor"
//! version = 3
//! ```
//!
//! The complete required resource tables, finite operation budgets and kernel
//! quota setup are documented in `docs/users/crucible/campaigns.md`.

use std::fs::{self, File};
use std::io::{Read, Take};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{Mode, OFlags};
use serde::Deserialize;

use super::*;

const PACKAGED_EXECUTOR_SCHEMA: &str = "crucible.campaign-packaged-executor";
const PACKAGED_EXECUTOR_VERSION: u32 = 3;
const MAX_PACKAGED_EXECUTOR_CONFIG_BYTES: usize = 64 * 1024;
const OS_ENTROPY_DEVICE: &str = "/dev/urandom";
const DEFAULT_PACKAGED_RUN_INTERVAL_ICOUNT: u64 = 1_000_000;
const GUARDED_RUN_QEMU_PROFILE: &str = "deterministic-tcg-v1";
const CAMPAIGN_DEPLOYMENT_ENV: &str = "CRUCIBLE_CAMPAIGN_DEPLOYMENT";
const DEFAULT_CAMPAIGN_DEPLOYMENT_PATH: &str = "/etc/crucible/packaged-executor.toml";

/// Keeps packaged campaign RUNs bounded without reducing the terminal ceiling.
pub(super) fn production_rendezvous_interval(
    requested: Option<u64>,
    packaged: bool,
) -> Option<u64> {
    // Conditions, checkpoint requests, and resource checks run at modeled
    // boundaries. Without rendezvous, an isolated VM can consume the complete
    // forty-billion-instruction CLI run allowance before returning to them.
    requested.or_else(|| packaged.then_some(DEFAULT_PACKAGED_RUN_INTERVAL_ICOUNT))
}

/// Authored deployment contract; unknown fields fail closed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagedExecutorDeployment {
    schema: String,
    version: u32,
    cgroup_root: PathBuf,
    run_root: PathBuf,
    attempt_namespace: String,
    first_project_id: u32,
    project_id_count: u32,
    child_user_id: u32,
    child_group_id: u32,
    maximum_tasks: u32,
    maximum_file_descriptors: u64,
    maximum_locked_bytes: u64,
    maximum_node_host_service_tasks: u64,
    maximum_node_host_service_file_descriptors: u64,
    maximum_node_host_service_resident_bytes: u64,
    watcher_service_resident_bytes: u64,
    maximum_inodes: u64,
    finish_timeout_ms: u64,
    maximum_slots: u32,
    maximum_paging_io_slots: u64,
    maximum_host_task_slots: u64,
    maximum_host_file_descriptors: u64,
    maximum_host_metadata_bytes: u64,
    maximum_host_staging_bytes: u64,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_disk_bytes: u64,
    maximum_execution_quanta: u64,
    assignment_limits: AssignmentLimitsDeployment,
    ram_catalog_root: PathBuf,
    ram_catalog_project_id: u32,
    maximum_ram_catalog_inodes: u64,
    maximum_ram_catalog_sqlite_heap_bytes: u64,
    ram_catalog_resources: HostOwnerResourcesDeployment,
    operational_registry_resources: HostOwnerResourcesDeployment,
    operational_registry_root: PathBuf,
    operational_registry_project_id: u32,
    operational_registry_maximum_inodes: u64,
    assignment_resources: HostOwnerResourcesDeployment,
    maximum_checkpoint_bytes: u64,
    worker_count: usize,
    host_architecture: String,
    qemu_profile: String,
    operations: PackagedExecutorOperationsDeployment,
    host_operation_budgets:
        std::collections::BTreeMap<String, host_operation_budgets::OperationBudgetDeployment>,
    hot_fork: Option<PackagedHotForkDeployment>,
    retained_template_resources: HostOwnerResourcesDeployment,
    guest_selectable_boundary_diagnostics: Option<GuestSelectableBoundaryDiagnosticsDeployment>,
    #[serde(default)]
    verify_determinism_findings: bool,
}

#[path = "host_operation_budgets.rs"]
pub(super) mod host_operation_budgets;

/// Independently authored modeled request limits, separate from physical backing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentLimitsDeployment {
    vcpus: u32,
    resident_bytes: u64,
    disk_bytes: u64,
    execution_quanta: u64,
}

impl AssignmentLimitsDeployment {
    fn limits(&self) -> Result<crucible_campaign::AttemptResourceLimits, CliError> {
        crucible_campaign::AttemptResourceLimits::new(
            self.vcpus,
            self.resident_bytes,
            self.disk_bytes,
            self.execution_quanta,
        )
        .map_err(|error| serve_error(format!("campaign assignment limits error: {error}")))
    }
}

/// Required fixed bounds for coordinator and executor service work.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagedExecutorOperationsDeployment {
    listener_workers: usize,
    pending_connections: usize,
    requests_per_connection: usize,
    accept_poll_interval_ms: u64,
    exchange_read_timeout_ms: u64,
    exchange_write_timeout_ms: u64,
    runtime_poll_interval_ms: u64,
    planner_scan_limit: u32,
    planner_input_bytes: u64,
    planner_fuel: u64,
    executor_scan_limit: usize,
    worker_slots_per_campaign: u32,
}

/// Optional retained-source policy; absence keeps hot-fork execution disabled.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagedHotForkDeployment {
    maximum_templates: usize,
    maximum_template_bytes: u64,
    maximum_expected_private_dirty_bytes: u64,
    maximum_processes: u32,
    maximum_virtual_cpus: u32,
    maximum_descriptors: u32,
    maximum_overlays: u32,
    maximum_forks_per_window: u32,
    fork_rate_window_ms: u64,
    shutdown_step_timeout_ms: u64,
    host_io_timeout_ms: u64,
}

/// Complete independently authored native and host resource entitlement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostOwnerResourcesDeployment {
    resident_peak_bytes: u64,
    backing_peak_bytes: u64,
    metadata_bytes: u64,
    staging_bytes: u64,
    paging_io_slots: u64,
    cpu_slots: u64,
    task_slots: u64,
    file_descriptors: u64,
}

impl HostOwnerResourcesDeployment {
    fn portable_resources(&self) -> crucible_campaign::ExecutorHostResources {
        crucible_campaign::ExecutorHostResources {
            resident_peak_bytes: self.resident_peak_bytes,
            backing_peak_bytes: self.backing_peak_bytes,
            metadata_bytes: self.metadata_bytes,
            staging_bytes: self.staging_bytes,
            paging_io_slots: self.paging_io_slots,
            cpu_slots: self.cpu_slots,
            task_slots: self.task_slots,
            file_descriptors: self.file_descriptors,
        }
    }

    /// Projects the complete authored entitlement without inferred suballocations.
    pub(crate) fn resources(&self) -> crucible_api::host_operational::HostResourceVector {
        crucible_api::host_operational::HostResourceVector {
            resident_peak_bytes: self.resident_peak_bytes,
            backing_peak_bytes: self.backing_peak_bytes,
            metadata_bytes: self.metadata_bytes,
            staging_bytes: self.staging_bytes,
            paging_io_slots: self.paging_io_slots,
            cpu_slots: self.cpu_slots,
            task_slots: self.task_slots,
            file_descriptors: self.file_descriptors,
        }
    }
}

/// Optional bounded emission for guest-selectable source and replay coordinates.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestSelectableBoundaryDiagnosticsDeployment {
    maximum_events: usize,
}

/// Guarded host capability loaded for one campaign run.
pub(crate) struct GuardedCampaignRunDeployment {
    policy: PackagedExecutorDeployment,
    pub(crate) host: crucible_daemon::LinuxQemuAttemptHostConfig,
    pub(crate) resources: crucible_campaign::AttemptResourceLimits,
    pub(crate) verify_determinism_findings: bool,
}

/// Prepared packaged executor and its authenticated coordinator tuning.
pub(super) struct PreparedCliPackagedExecutor {
    pub(super) executor: crucible_daemon::AttachedPackagedQemuExecutor,
    pub(super) verify_determinism_findings: bool,
    operations: PackagedExecutorOperations,
}

#[derive(Clone, Copy)]
struct PackagedExecutorOperations {
    server: crucible_daemon::ExecutorLoopbackServerConfig,
    exchange_timeouts: crucible_daemon::LoopbackExecutorTimeouts,
    runtime: crucible_daemon::CampaignRuntimeConfig,
    planner_scan_limit: u32,
    planner_input_bytes: u64,
    planner_fuel: u64,
    executor_scan_limit: usize,
    worker_slots_per_campaign: Option<u32>,
}

impl PreparedCliPackagedExecutor {
    pub(super) fn runtime_config(
        &self,
        campaign: crucible_campaign::CampaignName,
        planner: crucible_daemon::CanonicalPlannerProcessConfig,
    ) -> Result<crucible_daemon::CanonicalCampaignRuntimeConfig, CliError> {
        let operations = self.operations;
        let budget = crucible_campaign::PlanningBudget::new(
            1,
            1,
            operations.planner_scan_limit,
            operations.planner_input_bytes,
            operations.planner_fuel,
        )
        .map_err(|error| serve_error(format!("campaign planner budget error: {error}")))?;
        crucible_daemon::CanonicalCampaignRuntimeConfig::new(
            campaign,
            planner,
            operations.planner_scan_limit,
            budget,
            None,
            crucible_campaign::ExecutionRetentionIntent::RetainOnFailure,
            operations.executor_scan_limit,
            operations.worker_slots_per_campaign,
            operations.runtime,
        )
        .map(|config| config.with_executor_timeouts(operations.exchange_timeouts))
        .map_err(|error| serve_error(format!("campaign runtime configuration error: {error}")))
    }
}

/// Resolves the operator-provisioned capability for local campaign execution.
///
/// Explicit CLI configuration takes precedence over the environment. When
/// neither is present, an installed system deployment is discovered at the
/// documented default path. The strict loader authenticates the selected file
/// before any host resource is acquired.
///
/// # Errors
///
/// Returns [`CliError`] when no deployment capability is configured or the
/// environment value is empty.
// crucible-lint: allow host-nondeterminism-state -- deployment discovery selects operational host authority and never enters modeled campaign identity.
pub(crate) fn resolve_guarded_campaign_deployment_path(
    explicit: Option<&Path>,
) -> Result<PathBuf, CliError> {
    let environment = std::env::var_os(CAMPAIGN_DEPLOYMENT_ENV);
    resolve_campaign_deployment_path(explicit, environment.as_deref(), |path| path.is_file())
}

fn resolve_campaign_deployment_path(
    explicit: Option<&Path>,
    environment: Option<&std::ffi::OsStr>,
    default_exists: impl FnOnce(&Path) -> bool,
) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(value) = environment {
        if value.is_empty() {
            return Err(serve_error(format!(
                "{CAMPAIGN_DEPLOYMENT_ENV} is empty; set it to an owner-only packaged-executor deployment file",
            )));
        }
        return Ok(PathBuf::from(value));
    }

    let default = Path::new(DEFAULT_CAMPAIGN_DEPLOYMENT_PATH);
    if default_exists(default) {
        return Ok(default.to_path_buf());
    }
    Err(serve_error(format!(
        "local QEMU execution requires guarded campaign host authority; pass --campaign-deployment PATH, set {CAMPAIGN_DEPLOYMENT_ENV}, or provision {DEFAULT_CAMPAIGN_DEPLOYMENT_PATH}",
    )))
}

/// Loads the complete deployed resource policy for a guarded campaign owner.
///
/// The deployment uses the same strict schema, ownership, cgroup, and project
/// quota policy as the packaged executor. Projection preserves physical host
/// entitlements independently of the original semantic execution limits.
///
/// # Errors
///
/// Returns [`CliError`] when the deployment file or its resource policy is
/// malformed, mutable by another user, or outside the supported bounds.
pub(crate) fn load_campaign_run_deployment(
    path: &Path,
) -> Result<GuardedCampaignRunDeployment, CliError> {
    let deployment = load_validated_deployment(path)?;
    if deployment.host_architecture != std::env::consts::ARCH {
        return Err(serve_error(format!(
            "campaign deployment host architecture `{}` does not match this `{}` host",
            deployment.host_architecture,
            std::env::consts::ARCH,
        )));
    }
    if deployment.qemu_profile != GUARDED_RUN_QEMU_PROFILE {
        return Err(serve_error(format!(
            "campaign deployment QEMU profile `{}` is unsupported; guarded run requires `{GUARDED_RUN_QEMU_PROFILE}`",
            deployment.qemu_profile,
        )));
    }
    let host = deployment_host(&deployment)?;
    let capacity = deployment_capacity(&deployment)?;
    let resources = deployment.assignment_limits.limits()?;
    if resources.maximum_vcpus() > capacity.maximum_vcpus()
        || resources.maximum_resident_bytes() > capacity.maximum_resident_bytes()
        || resources.maximum_disk_bytes() > capacity.maximum_disk_bytes()
        || resources.maximum_execution_quanta() > capacity.maximum_execution_quanta()
    {
        return Err(serve_error(
            "campaign assignment resources exceed aggregate deployment capacity",
        ));
    }

    let verify_determinism_findings = deployment.verify_determinism_findings;
    Ok(GuardedCampaignRunDeployment {
        policy: deployment,
        host,
        resources,
        verify_determinism_findings,
    })
}

pub(super) fn prepare_cli_packaged_executor(
    prepared: &crucible_daemon::PreparedCampaignLocalService,
    args: &ServeArgs,
    campaigns: std::collections::BTreeSet<crucible_campaign::CampaignName>,
    executor_socket: &Path,
    deployment_path: &Path,
    lifecycle: crucible_api::ProductionVmLifecycleConfig,
) -> Result<PreparedCliPackagedExecutor, CliError> {
    let deployment = load_validated_deployment(deployment_path)?;
    let operations = deployment_operations(&deployment)?;
    let host = deployment_host(&deployment)?;
    let capacity = deployment_capacity(&deployment)?;
    let host_operational_capacity = crucible_daemon::HostOperationalCapacity::new(
        args.host_paging_io_slots
            .unwrap_or(deployment.maximum_paging_io_slots),
        args.host_task_slots
            .unwrap_or(deployment.maximum_host_task_slots),
        args.host_file_descriptors
            .unwrap_or(deployment.maximum_host_file_descriptors),
        args.host_metadata_bytes
            .unwrap_or(deployment.maximum_host_metadata_bytes),
        args.host_staging_bytes
            .unwrap_or(deployment.maximum_host_staging_bytes),
    )
    .map_err(|error| serve_error(format!("campaign host operational capacity error: {error}")))?;
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    let endpoint = crucible_daemon::ExecutorLoopbackEndpointConfig::new(
        executor_socket,
        user_id,
        group_id,
        0o600,
    )
    .map_err(|error| serve_error(format!("campaign executor endpoint error: {error}")))?;
    let state = args
        .campaign_state
        .as_ref()
        .ok_or_else(|| serve_error("campaign packaged executor has no state directory"))?;
    let config = build_packaged_executor_config(
        &deployment,
        PackagedExecutorBinding {
            campaigns,
            endpoint,
            state,
            lifecycle,
            host,
            capacity,
            host_operational_capacity,
            assignment_limits: deployment.assignment_limits.limits()?,
        },
    )?;
    let executor = prepared
        .prepare_packaged_executor(config)
        .map_err(|error| {
            serve_error(format!(
                "campaign executor preparation error: {}",
                preparation_error_chain(&error)
            ))
        })?;
    let executor = crucible_daemon::AttachedPackagedQemuExecutor::start(executor)
        .map_err(|error| serve_error(format!("campaign executor startup error: {error}")))?;
    Ok(PreparedCliPackagedExecutor {
        executor,
        verify_determinism_findings: deployment.verify_determinism_findings,
        operations,
    })
}

/// Local execution binds the complete deployed policy before admission.
impl GuardedCampaignRunDeployment {
    /// Admits the deployed namespace for input and remote-control metadata.
    ///
    /// No guest process is created. The existing project quota and independent
    /// service vector retain every decoder loan under the original supervisor.
    ///
    /// # Errors
    /// Refuses invalid supervision, unavailable service credit, a busy namespace,
    /// or an operator quota that differs from the authored physical bounds.
    pub(crate) fn input_metadata_resources(
        &self,
    ) -> Result<
        std::sync::Arc<dyn crucible_daemon::campaign_store_composition::StorePhysicalQuotaGuard>,
        CliError,
    > {
        use crucible_daemon::campaign_store_composition::StorePhysicalQuotaBinder;

        let resources = self.policy.ram_catalog_resources.resources();
        let service = crucible_daemon::CampaignQuotaServiceConfig::from_authored_budgets(
            host_operation_budgets::deployed_budgets(&self.policy.host_operation_budgets)?,
            None,
            resources,
        )
        .map_err(CliError::ProviderAdmission)?;
        let binder = crucible_daemon::LinuxProjectQuotaBinder::new(service)
            .map_err(CliError::ProviderAdmission)?;
        binder
            .bind(
                &self.policy.ram_catalog_root,
                self.policy.ram_catalog_project_id,
                resources.backing_peak_bytes,
                self.policy.maximum_ram_catalog_inodes,
            )
            .map_err(|source| CliError::InputAuthority(Box::new(source)))
    }

    /// Projects the deployed physical policy and an admitted semantic subset.
    ///
    /// # Errors
    /// Refuses semantic limits above the authored deployment, invalid endpoint
    /// ownership, or a complete physical/configuration contract that cannot fit.
    pub(crate) fn execution_config(
        &self,
        lifecycle: crucible_api::ProductionVmLifecycleConfig,
        campaign: crucible_campaign::CampaignName,
        state: &Path,
        limits: crucible_campaign::AttemptResourceLimits,
    ) -> Result<crucible_daemon::PackagedQemuExecutorConfig, CliError> {
        if limits.maximum_vcpus() > self.resources.maximum_vcpus()
            || limits.maximum_resident_bytes() > self.resources.maximum_resident_bytes()
            || limits.maximum_disk_bytes() > self.resources.maximum_disk_bytes()
            || limits.maximum_execution_quanta() > self.resources.maximum_execution_quanta()
        {
            return Err(serve_error(
                "guarded execution exceeds authored semantic limits",
            ));
        }
        let endpoint = crucible_daemon::ExecutorLoopbackEndpointConfig::new(
            state.join("guarded-executor.sock"),
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            0o600,
        )
        .map_err(|error| serve_error(format!("guarded executor endpoint error: {error}")))?;
        let host_operational_capacity = crucible_daemon::HostOperationalCapacity::new(
            self.policy.maximum_paging_io_slots,
            self.policy.maximum_host_task_slots,
            self.policy.maximum_host_file_descriptors,
            self.policy.maximum_host_metadata_bytes,
            self.policy.maximum_host_staging_bytes,
        )
        .map_err(|error| {
            serve_error(format!("guarded host operational capacity error: {error}"))
        })?;
        build_packaged_executor_config(
            &self.policy,
            PackagedExecutorBinding {
                campaigns: std::collections::BTreeSet::from([campaign]),
                endpoint,
                state,
                lifecycle,
                host: self.host.clone(),
                capacity: deployment_capacity(&self.policy)?,
                host_operational_capacity,
                assignment_limits: limits,
            },
        )
    }
}

struct PackagedExecutorBinding<'a> {
    campaigns: std::collections::BTreeSet<crucible_campaign::CampaignName>,
    endpoint: crucible_daemon::ExecutorLoopbackEndpointConfig,
    state: &'a Path,
    lifecycle: crucible_api::ProductionVmLifecycleConfig,
    host: crucible_daemon::LinuxQemuAttemptHostConfig,
    capacity: crucible_daemon::ExecutorCapacity,
    host_operational_capacity: crucible_daemon::HostOperationalCapacity,
    assignment_limits: crucible_campaign::AttemptResourceLimits,
}

fn build_packaged_executor_config(
    deployment: &PackagedExecutorDeployment,
    binding: PackagedExecutorBinding<'_>,
) -> Result<crucible_daemon::PackagedQemuExecutorConfig, CliError> {
    let PackagedExecutorBinding {
        campaigns,
        endpoint,
        state,
        lifecycle,
        host,
        capacity,
        host_operational_capacity,
        assignment_limits,
    } = binding;
    let operations = deployment_operations(deployment)?;
    let store_namespace = packaged_store_namespace(state);
    let daemon_epoch = fresh_daemon_epoch()?;
    // This durable namespace is prepared only by the admitted catalog provider.
    // A caller's temporary workspace never owns or automatically deletes it.
    let lifecycle = lifecycle.with_run_state_root(
        deployment
            .ram_catalog_root
            .join("workers")
            .join(store_namespace.to_hex()),
    );
    let hot_fork = deployment_hot_fork_policy(deployment, &lifecycle)?;
    let retained_template_resources = deployment.retained_template_resources.resources();
    let ram_catalog = deployment_ram_catalog(deployment)?;
    let assignment_resources = deployment.assignment_resources.resources();
    let operational_registry_resources = deployment.operational_registry_resources.resources();
    let guest_selectable_diagnostics =
        deployment_guest_selectable_boundary_diagnostics(deployment)?;
    let mut config = crucible_daemon::PackagedQemuExecutorConfig::new(
        campaigns,
        endpoint,
        operations.server,
        deployment.operational_registry_root.clone(),
        deployment.maximum_checkpoint_bytes,
        daemon_epoch,
        capacity,
        host_operational_capacity,
        deployment.worker_count,
        deployment.host_architecture.clone(),
        deployment.qemu_profile.clone(),
        store_namespace,
        lifecycle,
        host,
    )
    .map_err(|error| serve_error(format!("campaign executor configuration error: {error}")))?;
    config = config
        .with_ram_catalog(ram_catalog)
        .map_err(|error| serve_error(format!("campaign RAM catalog error: {error}")))?;
    config = config
        .with_operational_registry_resources(operational_registry_resources)
        .map_err(|error| {
            serve_error(format!(
                "campaign operational registry resource error: {error}"
            ))
        })?;
    config = config
        .with_operational_registry_quota(
            deployment.operational_registry_project_id,
            deployment.operational_registry_maximum_inodes,
        )
        .map_err(|error| {
            serve_error(format!(
                "campaign operational registry quota error: {error}"
            ))
        })?;
    config = config
        .with_assignment_resources(assignment_resources, assignment_limits)
        .map_err(|error| serve_error(format!("campaign assignment resource error: {error}")))?;
    config = config
        .with_host_operation_budgets(host_operation_budgets::deployed_budgets(
            &deployment.host_operation_budgets,
        )?)
        .map_err(|error| serve_error(format!("campaign host operation budget error: {error}")))?;
    config = config
        .with_retained_template_resources(retained_template_resources)
        .map_err(|error| {
            serve_error(format!(
                "campaign retained-template resource error: {error}"
            ))
        })?;
    if let Some(hot_fork) = hot_fork {
        config = config.with_hot_fork_sources(hot_fork);
    }
    if let Some(diagnostics) = guest_selectable_diagnostics {
        config = config.with_guest_selectable_boundary_diagnostics(diagnostics);
    }
    if deployment.verify_determinism_findings {
        config = config.with_determinism_finding_verification();
    }
    Ok(config)
}

fn deployment_operations(
    deployment: &PackagedExecutorDeployment,
) -> Result<PackagedExecutorOperations, CliError> {
    let operations = &deployment.operations;
    let exchange_timeouts = crucible_daemon::LoopbackExecutorTimeouts::new(
        deployment_timeout(
            "executor exchange read",
            operations.exchange_read_timeout_ms,
        )?,
        deployment_timeout(
            "executor exchange write",
            operations.exchange_write_timeout_ms,
        )?,
    )
    .map_err(|error| serve_error(format!("campaign executor exchange policy error: {error}")))?;
    let server = crucible_daemon::ExecutorLoopbackServerConfig::new(
        operations.listener_workers,
        operations.pending_connections,
        operations.requests_per_connection,
        deployment_timeout("executor accept poll", operations.accept_poll_interval_ms)?,
        exchange_timeouts,
    )
    .map_err(|error| serve_error(format!("campaign executor listener policy error: {error}")))?;
    let runtime = crucible_daemon::CampaignRuntimeConfig::new(deployment_timeout(
        "runtime fallback poll",
        operations.runtime_poll_interval_ms,
    )?)
    .map_err(|error| serve_error(format!("campaign runtime cadence error: {error}")))?;
    crucible_campaign::PlanningBudget::new(
        1,
        1,
        operations.planner_scan_limit,
        operations.planner_input_bytes,
        operations.planner_fuel,
    )
    .map_err(|error| serve_error(format!("campaign planner budget error: {error}")))?;
    if operations.planner_scan_limit > crucible_campaign::MAX_PLANNER_SCAN_PAGE_ITEMS
        || operations.planner_input_bytes
            > crucible_campaign::MAX_RETAINED_PLANNER_REQUEST_BYTES as u64
        || operations.executor_scan_limit == 0
        || operations.executor_scan_limit > crucible_campaign::MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS
        || operations.worker_slots_per_campaign == 0
        || operations.worker_slots_per_campaign
            > crucible_campaign::MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS
        || operations.worker_slots_per_campaign > deployment.maximum_slots
    {
        return Err(serve_error(
            "campaign packaged-executor coordinator policy exceeds fixed protocol bounds",
        ));
    }

    Ok(PackagedExecutorOperations {
        server,
        exchange_timeouts,
        runtime,
        planner_scan_limit: operations.planner_scan_limit,
        planner_input_bytes: operations.planner_input_bytes,
        planner_fuel: operations.planner_fuel,
        executor_scan_limit: operations.executor_scan_limit,
        worker_slots_per_campaign: Some(operations.worker_slots_per_campaign),
    })
}

fn deployment_guest_selectable_boundary_diagnostics(
    deployment: &PackagedExecutorDeployment,
) -> Result<Option<crucible_daemon::GuestSelectableBoundaryDiagnosticConfig>, CliError> {
    deployment
        .guest_selectable_boundary_diagnostics
        .as_ref()
        .map(|diagnostics| {
            crucible_daemon::GuestSelectableBoundaryDiagnosticConfig::new(
                diagnostics.maximum_events,
            )
            .map_err(|error| {
                serve_error(format!(
                    "campaign guest-selectable boundary diagnostic policy error: {error}"
                ))
            })
        })
        .transpose()
}

fn deployment_hot_fork_policy(
    deployment: &PackagedExecutorDeployment,
    lifecycle: &crucible_api::ProductionVmLifecycleConfig,
) -> Result<Option<crucible_daemon::PackagedQemuHotForkConfig>, CliError> {
    let Some(policy) = deployment.hot_fork.as_ref() else {
        return Ok(None);
    };
    let maximum_resources = crucible_daemon::HotCheckpointResourceProfile::new(
        policy.maximum_template_bytes,
        policy.maximum_expected_private_dirty_bytes,
        policy.maximum_processes,
        policy.maximum_virtual_cpus,
        policy.maximum_descriptors,
        policy.maximum_overlays,
    )
    .map_err(|error| serve_error(format!("campaign hot-fork resource policy error: {error}")))?;
    let fork_rate_window_nanos = policy
        .fork_rate_window_ms
        .checked_mul(1_000_000)
        .ok_or_else(|| serve_error("campaign hot-fork rate window overflows nanoseconds"))?;
    let limits = crucible_daemon::HotCheckpointLimits::new(
        policy.maximum_templates,
        maximum_resources,
        policy.maximum_forks_per_window,
        fork_rate_window_nanos,
    )
    .map_err(|error| serve_error(format!("campaign hot-fork limit policy error: {error}")))?;
    let shutdown_wait =
        deployment_timeout("hot-fork shutdown step", policy.shutdown_step_timeout_ms)?;
    let host_io_timeout = deployment_timeout("hot-fork host I/O", policy.host_io_timeout_ms)?;
    let hot_fork = crucible_daemon::PackagedQemuHotForkConfig::authenticate(
        lifecycle,
        limits,
        crucible_daemon::HotCheckpointHotnessSignals::new(),
        shutdown_wait,
        host_io_timeout,
    )
    .map_err(|error| serve_error(format!("campaign hot-fork policy error: {error}")))?;

    Ok(Some(hot_fork))
}

fn deployment_timeout(role: &str, milliseconds: u64) -> Result<Duration, CliError> {
    let timeout = Duration::from_millis(milliseconds);
    if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
        return Err(serve_error(format!(
            "campaign {role} timeout is outside 1ms..=1h"
        )));
    }
    Ok(timeout)
}

fn load_validated_deployment(path: &Path) -> Result<PackagedExecutorDeployment, CliError> {
    let deployment = load_deployment(path)?;
    if deployment.schema != PACKAGED_EXECUTOR_SCHEMA
        || deployment.version != PACKAGED_EXECUTOR_VERSION
    {
        return Err(serve_error(
            "campaign packaged-executor deployment has an unsupported schema or version",
        ));
    }
    host_operation_budgets::deployed_budgets(&deployment.host_operation_budgets)?;
    let registry_project = deployment.operational_registry_project_id;
    let native_project_end = deployment
        .first_project_id
        .checked_add(deployment.project_id_count)
        .ok_or_else(|| serve_error("campaign native project-ID range overflows"))?;
    if !deployment.operational_registry_root.is_absolute()
        || deployment.operational_registry_root == deployment.ram_catalog_root
        || deployment
            .operational_registry_root
            .starts_with(&deployment.ram_catalog_root)
        || deployment
            .ram_catalog_root
            .starts_with(&deployment.operational_registry_root)
        || !(1..0x8000_0000).contains(&registry_project)
        || registry_project == deployment.ram_catalog_project_id
        || (deployment.first_project_id..native_project_end).contains(&registry_project)
        || deployment.operational_registry_resources.backing_peak_bytes == 0
        || deployment.operational_registry_maximum_inodes == 0
    {
        return Err(serve_error(
            "campaign operational registry quota is invalid or overlaps another owner",
        ));
    }
    if deployment.project_id_count < deployment.maximum_slots {
        return Err(serve_error(
            "campaign packaged-executor project-ID count is below its slot ceiling",
        ));
    }
    crucible_daemon::HostOperationalCapacity::new(
        deployment.maximum_paging_io_slots,
        deployment.maximum_host_task_slots,
        deployment.maximum_host_file_descriptors,
        deployment.maximum_host_metadata_bytes,
        deployment.maximum_host_staging_bytes,
    )
    .map_err(|error| serve_error(format!("campaign host operational capacity error: {error}")))?;
    if deployment.maximum_file_descriptors == 0 {
        return Err(serve_error("campaign node descriptor capacity is zero"));
    }
    if deployment
        .maximum_host_metadata_bytes
        .checked_add(deployment.maximum_host_staging_bytes)
        .is_none_or(|bytes| bytes > deployment.maximum_resident_bytes)
        || deployment.maximum_host_staging_bytes > deployment.maximum_disk_bytes
    {
        return Err(serve_error(
            "campaign aggregate host subsets exceed complete resident or backing capacity",
        ));
    }
    if deployment.maximum_checkpoint_bytes > deployment.maximum_disk_bytes {
        return Err(serve_error(
            "campaign packaged-executor checkpoint ceiling exceeds writable-disk capacity",
        ));
    }
    if deployment.maximum_checkpoint_bytes == 0 {
        return Err(serve_error(
            "campaign packaged-executor checkpoint byte ceiling is zero",
        ));
    }
    if deployment.worker_count == 0
        || deployment.worker_count > usize::try_from(deployment.maximum_slots).unwrap_or(usize::MAX)
    {
        return Err(serve_error(
            "campaign packaged-executor worker count is outside its slot ceiling",
        ));
    }
    let aggregate = crucible_campaign::ExecutorHostResources {
        resident_peak_bytes: deployment.maximum_resident_bytes,
        backing_peak_bytes: deployment.maximum_disk_bytes,
        metadata_bytes: deployment.maximum_host_metadata_bytes,
        staging_bytes: deployment.maximum_host_staging_bytes,
        paging_io_slots: deployment.maximum_paging_io_slots,
        cpu_slots: u64::from(deployment.maximum_vcpus),
        task_slots: deployment.maximum_host_task_slots,
        file_descriptors: deployment.maximum_host_file_descriptors,
    };
    let physical_assignment = deployment.assignment_resources.portable_resources();
    for (name, resources) in [
        ("assignment", physical_assignment),
        (
            "retained-template replay",
            deployment.retained_template_resources.portable_resources(),
        ),
        (
            "RAM catalog",
            deployment.ram_catalog_resources.portable_resources(),
        ),
        (
            "operational registry",
            deployment
                .operational_registry_resources
                .portable_resources(),
        ),
    ] {
        if [
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
            || resources
                .metadata_bytes
                .checked_add(resources.staging_bytes)
                .is_none_or(|bytes| bytes > resources.resident_peak_bytes)
            || resources.staging_bytes > resources.backing_peak_bytes
            || !resources.fits(aggregate)
        {
            return Err(serve_error(format!(
                "campaign {name} has invalid resources or exceeds aggregate capacity"
            )));
        }
    }
    let limits = deployment.assignment_limits.limits()?;
    crucible_campaign::ExecutorResourceBounds::new(aggregate, physical_assignment, limits)
        .map_err(|error| serve_error(format!("campaign resource bounds error: {error}")))?;
    if limits.maximum_execution_quanta() > deployment.maximum_execution_quanta {
        return Err(serve_error(
            "campaign assignment modeled work exceeds aggregate capacity",
        ));
    }
    deployment_ram_catalog(&deployment)?;
    deployment_guest_selectable_boundary_diagnostics(&deployment)?;
    deployment_operations(&deployment)?;
    let finish_timeout = Duration::from_millis(deployment.finish_timeout_ms);
    if finish_timeout.is_zero() || finish_timeout > Duration::from_secs(60 * 60) {
        return Err(serve_error(
            "campaign packaged-executor finish timeout is outside 1ms..=1h",
        ));
    }

    Ok(deployment)
}

fn deployment_ram_catalog(
    deployment: &PackagedExecutorDeployment,
) -> Result<crucible_daemon::PackagedRamCatalogConfig, CliError> {
    crucible_daemon::PackagedRamCatalogConfig::new(
        &deployment.ram_catalog_root,
        deployment.ram_catalog_project_id,
        deployment.maximum_ram_catalog_inodes,
        deployment.ram_catalog_resources.resources(),
        deployment.maximum_ram_catalog_sqlite_heap_bytes,
    )
    .map_err(|error| serve_error(format!("campaign RAM catalog configuration error: {error}")))
}

fn deployment_host(
    deployment: &PackagedExecutorDeployment,
) -> Result<crucible_daemon::LinuxQemuAttemptHostConfig, CliError> {
    let finish_timeout = Duration::from_millis(deployment.finish_timeout_ms);
    crucible_daemon::LinuxQemuAttemptHostConfig::new(
        deployment.cgroup_root.clone(),
        deployment.run_root.clone(),
        deployment.attempt_namespace.clone(),
        deployment.first_project_id,
        deployment.project_id_count,
        deployment.child_user_id,
        deployment.child_group_id,
        deployment.maximum_tasks,
        deployment.maximum_file_descriptors,
        deployment.maximum_node_host_service_tasks,
        deployment.maximum_node_host_service_file_descriptors,
        deployment.maximum_node_host_service_resident_bytes,
        deployment.watcher_service_resident_bytes,
        deployment.maximum_inodes,
        finish_timeout,
    )
    .and_then(|host| host.with_maximum_locked_bytes(deployment.maximum_locked_bytes))
    .map_err(|error| serve_error(format!("campaign executor host policy error: {error}")))
}

fn deployment_capacity(
    deployment: &PackagedExecutorDeployment,
) -> Result<crucible_daemon::ExecutorCapacity, CliError> {
    crucible_daemon::ExecutorCapacity::new(
        deployment.maximum_slots,
        deployment.maximum_vcpus,
        deployment.maximum_resident_bytes,
        deployment.maximum_disk_bytes,
        deployment.maximum_execution_quanta,
    )
    .map_err(|error| serve_error(format!("campaign executor capacity error: {error}")))
}

/// Keeps nested startup causes visible without unbounded diagnostic traversal.
fn preparation_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = String::new();
    let mut current = Some(error);
    for _ in 0..12 {
        let Some(error) = current else { break };
        if !message.is_empty() {
            message.push_str("; caused by: ");
        }
        message.extend(error.to_string().chars().take(1024));
        current = error.source();
    }
    if current.is_some() {
        message.push_str("; further causes omitted");
    }
    message
}

fn packaged_store_namespace(state: &Path) -> crucible_campaign::CampaignHash {
    crucible_campaign::CampaignHash::derive(
        "crucible.campaign.packaged-executor-store.v2",
        state.as_os_str().as_encoded_bytes(),
    )
}

fn load_deployment(path: &Path) -> Result<PackagedExecutorDeployment, CliError> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor metadata error for {}: {error}",
            path.display()
        ))
    })?;
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    if !before.is_file()
        || before.uid() != user_id
        || before.gid() != group_id
        || before.mode() & 0o777 != 0o600
        || before.len() > MAX_PACKAGED_EXECUTOR_CONFIG_BYTES as u64
    {
        return Err(serve_error(
            "campaign packaged-executor deployment is not an exact-owner mode-0600 bounded file",
        ));
    }
    let mut file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor open error for {}: {error}",
            path.display()
        ))
    })?
    .into();
    let after = file.metadata().map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor opened metadata error for {}: {error}",
            path.display()
        ))
    })?;
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || !after.is_file()
        || after.uid() != user_id
        || after.gid() != group_id
        || after.mode() & 0o777 != 0o600
        || after.len() > MAX_PACKAGED_EXECUTOR_CONFIG_BYTES as u64
    {
        return Err(serve_error(
            "campaign packaged-executor deployment changed while opening",
        ));
    }

    let mut bytes = Vec::with_capacity(after.len() as usize);
    let mut bounded: Take<&mut File> =
        std::io::Read::by_ref(&mut file).take((MAX_PACKAGED_EXECUTOR_CONFIG_BYTES + 1) as u64);
    bounded.read_to_end(&mut bytes).map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor read error for {}: {error}",
            path.display()
        ))
    })?;
    if bytes.len() > MAX_PACKAGED_EXECUTOR_CONFIG_BYTES {
        return Err(serve_error(
            "campaign packaged-executor deployment exceeds 64 KiB",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| serve_error("campaign packaged-executor deployment is not UTF-8"))?;
    toml::from_str(text).map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor TOML is invalid: {error}"
        ))
    })
}

fn fresh_daemon_epoch() -> Result<crucible_campaign::DaemonEpoch, CliError> {
    let mut bytes = [0_u8; 16];
    File::open(OS_ENTROPY_DEVICE)
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| serve_error(format!("campaign executor entropy error: {error}")))?;
    crucible_campaign::DaemonEpoch::from_bytes(bytes)
        .map_err(|error| serve_error(format!("campaign executor epoch error: {error}")))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[derive(Debug)]
    struct CyclicCause;

    impl std::fmt::Display for CyclicCause {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded cause")
        }
    }

    impl std::error::Error for CyclicCause {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    #[test]
    fn preparation_diagnostics_bound_cyclic_and_long_causes() {
        let cycle = preparation_error_chain(&CyclicCause);
        assert_eq!(cycle.matches("bounded cause").count(), 12);
        assert!(cycle.ends_with("further causes omitted"));
        let long = std::io::Error::other("x".repeat(4096));
        assert_eq!(preparation_error_chain(&long).len(), 1024);
    }

    fn authored_without_operations() -> String {
        let policy = String::from(
            r#"schema = "crucible.campaign-packaged-executor"
version = 3
cgroup_root = "/sys/fs/cgroup/crucible"
run_root = "/var/lib/crucible/attempts"
attempt_namespace = "campaign-local"
first_project_id = 10000
project_id_count = 4
child_user_id = 2000
child_group_id = 2000
maximum_tasks = 64
maximum_file_descriptors = 1024
maximum_locked_bytes = 0
maximum_node_host_service_tasks = 4
maximum_node_host_service_file_descriptors = 32
maximum_node_host_service_resident_bytes = 8388608
watcher_service_resident_bytes = 1048576
maximum_inodes = 4096
finish_timeout_ms = 30000
maximum_slots = 2
maximum_paging_io_slots = 8
maximum_host_task_slots = 1024
maximum_host_file_descriptors = 8192
maximum_host_metadata_bytes = 1073741824
maximum_host_staging_bytes = 134217728
maximum_vcpus = 8
maximum_resident_bytes = 3221225472
maximum_disk_bytes = 6442450944
maximum_execution_quanta = 100000
ram_catalog_root = "/var/lib/crucible/ram-catalogs"
ram_catalog_project_id = 30000
operational_registry_root = "/var/lib/crucible/executor-ledger"
operational_registry_project_id = 31000
operational_registry_maximum_inodes = 262144
maximum_ram_catalog_inodes = 262144
maximum_ram_catalog_sqlite_heap_bytes = 8388608
verify_determinism_findings = false
maximum_checkpoint_bytes = 1073741824
worker_count = 2
host_architecture = "x86_64"
qemu_profile = "deterministic-tcg-v1"

[operational_registry_resources]
resident_peak_bytes = 134217728
backing_peak_bytes = 16777216
metadata_bytes = 67108864
staging_bytes = 8388608
paging_io_slots = 1
cpu_slots = 1
task_slots = 1
file_descriptors = 128

[ram_catalog_resources]
resident_peak_bytes = 134217728
backing_peak_bytes = 536870912
metadata_bytes = 67108864
staging_bytes = 8388608
paging_io_slots = 1
cpu_slots = 1
task_slots = 1
file_descriptors = 128

[assignment_limits]
vcpus = 1
resident_bytes = 536870912
disk_bytes = 1073741824
execution_quanta = 50000

[assignment_resources]
resident_peak_bytes = 536870912
backing_peak_bytes = 1073741824
metadata_bytes = 134217728
staging_bytes = 16777216
paging_io_slots = 1
cpu_slots = 1
task_slots = 69
file_descriptors = 1056

[retained_template_resources]
resident_peak_bytes = 536870912
backing_peak_bytes = 1073741824
metadata_bytes = 134217728
staging_bytes = 16777216
paging_io_slots = 1
cpu_slots = 1
task_slots = 69
file_descriptors = 1056
"#,
        )
        .replace(
            "host_architecture = \"x86_64\"",
            &format!("host_architecture = \"{}\"", std::env::consts::ARCH),
        );
        let budgets = host_operation_budgets::CLASS_NAMES
            .iter()
            .map(|name| format!("\n[host_operation_budgets.{name}]\npoll_interval_ms = 10\ntotal_timeout_ms = 60000\n"))
            .collect::<String>();
        format!("{policy}{budgets}")
    }

    fn authored() -> String {
        format!(
            "{}\n[operations]\n\
             listener_workers = 6\n\
             pending_connections = 48\n\
             requests_per_connection = 512\n\
             accept_poll_interval_ms = 25\n\
             exchange_read_timeout_ms = 45000\n\
             exchange_write_timeout_ms = 20000\n\
             runtime_poll_interval_ms = 250\n\
             planner_scan_limit = 256\n\
             planner_input_bytes = 8388608\n\
             planner_fuel = 257\n\
             executor_scan_limit = 384\n\
             worker_slots_per_campaign = 2\n",
            authored_without_operations()
        )
    }

    fn authored_hot_fork() -> String {
        format!(
            "{}\n[hot_fork]\n\
             maximum_templates = 2\n\
             maximum_template_bytes = 1073741824\n\
             maximum_expected_private_dirty_bytes = 536870912\n\
             maximum_processes = 8\n\
             maximum_virtual_cpus = 8\n\
             maximum_descriptors = 4096\n\
             maximum_overlays = 16\n\
             maximum_forks_per_window = 8\n\
             fork_rate_window_ms = 1000\n\
             shutdown_step_timeout_ms = 1000\n\
             host_io_timeout_ms = 30000\n\
             ",
            authored()
        )
    }

    fn authored_guest_selectable_diagnostics(maximum_events: usize) -> String {
        format!(
            "{}\n[guest_selectable_boundary_diagnostics]\nmaximum_events = {maximum_events}\n",
            authored()
        )
    }

    fn hot_fork_artifacts(directory: &Path) -> crucible_api::ProductionVmLifecycleConfig {
        let qemu = directory.join("bin/qemu-system-x86_64");
        let plugin = directory.join("lib/libcrucible-qemu-plugin.so");
        let qemu_marker = directory.join("share/aos/crucible/qemu-build-identity.env");
        let plugin_marker = directory.join("nix-support/crucible-qemu-plugin-build-info");
        for path in [&qemu, &plugin, &qemu_marker, &plugin_marker] {
            fs::create_dir_all(path.parent().expect("artifact parent"))
                .expect("create artifact parent");
        }
        fs::write(&qemu, b"qemu").expect("write QEMU artifact");
        fs::write(&plugin, b"plugin").expect("write plugin artifact");
        let abi_version = crucible::SHMEM_ABI_VERSION;
        let abi = format!("crucible-shmem-abi-v{abi_version}");
        fs::write(
            qemu_marker,
            format!(
                "qemu_sim_capability=qemu-crucible\n\
                 qemu_crucible_atomic_patch_applied=true\n\
                 qemu_plugins_enabled=true\n\
                 qemu_build_id=qemu-build-v1\n\
                 qemu_atomic_patch_hash=sha256:patch\n\
                 qemu_shmem_abi_version={abi_version}\n\
                 qemu_shmem_abi={abi}\n\
                 qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\n\
                 qemu_shmem_header_hash=sha256:header\n"
            ),
        )
        .expect("write QEMU marker");
        fs::write(
            plugin_marker,
            format!(
                "plugin_abi={abi}\n\
                 qemu_build_id=qemu-build-v1\n\
                 shmem_abi_version={abi_version}\n\
                 shmem_abi={abi}\n\
                 shmem_generated_header_hash=sha256:header\n"
            ),
        )
        .expect("write plugin marker");
        crucible_api::ProductionVmLifecycleConfig::new(
            &qemu,
            &plugin,
            directory.join("kernel"),
            directory.join("root"),
            directory.join("run-state"),
        )
    }

    #[test]
    fn registry_quota_requires_a_distinct_persistent_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("executor.toml");
        fs::write(&path, authored())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let valid = load_validated_deployment(&path)?;
        assert_eq!(valid.operational_registry_project_id, 31000);
        assert_eq!(valid.operational_registry_maximum_inodes, 262144);

        for (needle, replacement) in [
            (
                "operational_registry_project_id = 31000",
                "operational_registry_project_id = 30000",
            ),
            (
                "operational_registry_project_id = 31000",
                "operational_registry_project_id = 10000",
            ),
            (
                "operational_registry_maximum_inodes = 262144",
                "operational_registry_maximum_inodes = 0",
            ),
            (
                "operational_registry_root = \"/var/lib/crucible/executor-ledger\"",
                "operational_registry_root = \"/var/lib/crucible/ram-catalogs/nested\"",
            ),
            (
                "operational_registry_root = \"/var/lib/crucible/executor-ledger\"",
                "operational_registry_root = \"relative-ledger\"",
            ),
        ] {
            fs::write(&path, authored().replace(needle, replacement))?;
            assert!(
                load_validated_deployment(&path).is_err(),
                "accepted {replacement}"
            );
        }
        Ok(())
    }

    #[test]
    fn packaged_executor_deployment_is_strict_and_owner_only() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, authored()).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let deployment = load_deployment(&path).expect("load deployment");
        assert_eq!(deployment.schema, PACKAGED_EXECUTOR_SCHEMA);
        assert_eq!(deployment.worker_count, 2);
        assert!(!deployment.verify_determinism_findings);
        let operations = deployment_operations(&deployment).expect("deployment operations");
        assert_eq!(operations.server.connection_workers(), 6);
        assert_eq!(
            operations.runtime.poll_interval(),
            Duration::from_millis(250)
        );
        assert_eq!(operations.worker_slots_per_campaign, Some(2));
        let guarded = load_campaign_run_deployment(&path).expect("load guarded run deployment");
        assert_eq!(guarded.resources.maximum_vcpus(), 1);
        assert_eq!(guarded.resources.maximum_disk_bytes(), 1_073_741_824);
        assert!(!guarded.verify_determinism_findings);

        assert!(
            toml::from_str::<PackagedExecutorDeployment>(&authored_without_operations()).is_err()
        );
        fs::write(&path, authored().replace("version = 3", "version = 2"))
            .expect("write superseded deployment");
        assert!(load_validated_deployment(&path).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("weaken deployment mode");
        assert!(load_deployment(&path).is_err());
    }

    #[test]
    fn guarded_projection_narrows_semantics_without_changing_physical_entitlement() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, authored()).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");
        let deployment = load_campaign_run_deployment(&path).expect("guarded deployment");
        let lifecycle = hot_fork_artifacts(directory.path());
        let campaign =
            crucible_campaign::CampaignName::new("guarded-projection").expect("campaign identity");
        let limits = crucible_campaign::AttemptResourceLimits::new(1, 268_435_456, 0, 100)
            .expect("narrow original request");

        let projected = deployment
            .execution_config(lifecycle, campaign.clone(), directory.path(), limits)
            .expect("project complete policy");

        assert_eq!(projected.assignment_limits(), Some(limits));
        assert_eq!(
            projected.assignment_resources(),
            Some(deployment.policy.assignment_resources.resources()),
        );
        assert_eq!(
            projected.operational_registry_resources(),
            Some(deployment.policy.operational_registry_resources.resources()),
        );
        assert_eq!(
            projected
                .ram_catalog()
                .expect("catalog entitlement")
                .resources(),
            deployment.policy.ram_catalog_resources.resources(),
        );
        let excessive = crucible_campaign::AttemptResourceLimits::new(
            deployment.resources.maximum_vcpus() + 1,
            deployment.resources.maximum_resident_bytes(),
            deployment.resources.maximum_disk_bytes(),
            deployment.resources.maximum_execution_quanta(),
        )
        .expect("well-formed excessive request");
        assert!(
            deployment
                .execution_config(
                    hot_fork_artifacts(directory.path()),
                    campaign,
                    directory.path(),
                    excessive
                )
                .is_err()
        );
    }

    #[test]
    fn semantic_disk_and_physical_backing_have_independent_limits() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        let authored = authored().replace("disk_bytes = 1073741824", "disk_bytes = 0");
        fs::write(&path, &authored).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let deployment = load_validated_deployment(&path).expect("independent limits");
        assert_eq!(
            deployment
                .assignment_limits
                .limits()
                .expect("valid independent limits")
                .maximum_disk_bytes(),
            0
        );
        assert_eq!(
            deployment.assignment_resources.backing_peak_bytes,
            1073741824
        );

        fs::write(&path, authored.replace("cpu_slots = 1", "cpu_slots = 9"))
            .expect("write invalid physical ceiling");
        assert!(load_validated_deployment(&path).is_err());
    }

    #[test]
    fn packaged_determinism_finding_verification_is_explicit() {
        let deployment: PackagedExecutorDeployment = toml::from_str(&authored().replace(
            "verify_determinism_findings = false",
            "verify_determinism_findings = true",
        ))
        .expect("determinism verification deployment");

        assert!(deployment.verify_determinism_findings);
    }

    #[test]
    fn packaged_operational_policy_configures_every_bounded_runtime_layer() {
        let deployment: PackagedExecutorDeployment =
            toml::from_str(&authored()).expect("operational deployment");
        let operations = deployment_operations(&deployment).expect("valid operational policy");

        assert_eq!(operations.server.connection_workers(), 6);
        assert_eq!(operations.server.pending_connections(), 48);
        assert_eq!(operations.server.maximum_requests_per_connection(), 512);
        assert_eq!(
            operations.server.accept_poll_interval(),
            Duration::from_millis(25)
        );
        assert_eq!(operations.exchange_timeouts.read(), Duration::from_secs(45));
        assert_eq!(
            operations.exchange_timeouts.write(),
            Duration::from_secs(20)
        );
        assert_eq!(
            operations.runtime.poll_interval(),
            Duration::from_millis(250)
        );
        assert_eq!(operations.planner_scan_limit, 256);
        assert_eq!(operations.planner_input_bytes, 8 * 1024 * 1024);
        assert_eq!(operations.planner_fuel, 257);
        assert_eq!(operations.executor_scan_limit, 384);
        assert_eq!(operations.worker_slots_per_campaign, Some(2));
    }

    #[test]
    fn packaged_operational_policy_rejects_unbounded_or_zero_values() {
        for (needle, replacement) in [
            ("listener_workers = 6", "listener_workers = 0"),
            (
                "runtime_poll_interval_ms = 250",
                "runtime_poll_interval_ms = 60001",
            ),
            ("planner_scan_limit = 256", "planner_scan_limit = 0"),
            (
                "planner_input_bytes = 8388608",
                "planner_input_bytes = 33554433",
            ),
            ("planner_fuel = 257", "planner_fuel = 0"),
            ("executor_scan_limit = 384", "executor_scan_limit = 10001"),
            (
                "worker_slots_per_campaign = 2",
                "worker_slots_per_campaign = 3",
            ),
        ] {
            let authored = authored().replace(needle, replacement);
            let deployment: PackagedExecutorDeployment =
                toml::from_str(&authored).expect("syntactically valid operational deployment");
            assert!(
                deployment_operations(&deployment).is_err(),
                "accepted {replacement}"
            );
        }
    }

    #[test]
    fn guarded_campaign_determinism_finding_verification_is_explicit() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        let deployment = authored().replace(
            "verify_determinism_findings = false",
            "verify_determinism_findings = true",
        );
        fs::write(&path, deployment).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let guarded = load_campaign_run_deployment(&path).expect("load guarded run deployment");

        assert!(guarded.verify_determinism_findings);
    }

    #[test]
    fn packaged_hot_fork_policy_authenticates_artifacts_and_explicit_limits() {
        let directory = tempfile::tempdir().expect("hot-fork deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, authored_hot_fork()).expect("write hot-fork deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure hot-fork deployment");
        let deployment = load_validated_deployment(&path).expect("load hot-fork deployment");
        let lifecycle = hot_fork_artifacts(directory.path());

        let policy = deployment_hot_fork_policy(&deployment, &lifecycle)
            .expect("authenticate hot-fork policy")
            .expect("hot-fork policy present");

        assert_eq!(policy.limits().maximum_templates(), 2);
        assert_eq!(policy.limits().maximum_forks_per_window(), 8);
        assert_eq!(policy.limits().fork_rate_window_nanos(), 1_000_000_000);
        let resources = deployment.retained_template_resources.resources();
        assert_eq!(resources.resident_peak_bytes, 512 * 1024 * 1024);
        assert_eq!(resources.task_slots, 69);
        assert_eq!(resources.file_descriptors, 1056);
    }

    #[test]
    fn retained_template_entitlement_is_required_for_checkpoint_replay() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        let authored = authored();
        let start = authored
            .find("[retained_template_resources]")
            .expect("authored replay entitlement");
        let suffix = authored[start..]
            .find("[operations]")
            .expect("following table")
            + start;
        let missing = format!("{}{}", &authored[..start], &authored[suffix..]);
        fs::write(&path, missing).expect("write deployment without replay entitlement");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");
        assert!(load_validated_deployment(&path).is_err());

        fs::write(&path, authored).expect("write cold-replay deployment");
        assert!(load_validated_deployment(&path).is_ok());
    }

    #[test]
    fn guest_selectable_boundary_diagnostic_policy_is_optional_and_bounded() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, authored_guest_selectable_diagnostics(256))
            .expect("write diagnostic deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let deployment = load_validated_deployment(&path).expect("validated deployment");
        let diagnostics = deployment_guest_selectable_boundary_diagnostics(&deployment)
            .expect("valid diagnostic policy")
            .expect("enabled diagnostic policy");

        assert_eq!(diagnostics.maximum_events(), 256);

        fs::write(&path, authored_guest_selectable_diagnostics(0))
            .expect("write invalid diagnostic deployment");
        assert!(load_validated_deployment(&path).is_err());

        fs::write(
            &path,
            authored_guest_selectable_diagnostics(
                crucible_daemon::MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS + 1,
            ),
        )
        .expect("write excessive diagnostic deployment");
        assert!(load_validated_deployment(&path).is_err());
    }

    #[test]
    fn guarded_campaign_run_rejects_an_unsupported_qemu_profile() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        let deployment = authored().replace(
            "qemu_profile = \"deterministic-tcg-v1\"",
            "qemu_profile = \"nondeterministic-host-v1\"",
        );
        fs::write(&path, deployment).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let error = load_campaign_run_deployment(&path)
            .err()
            .expect("unsupported guarded QEMU profile");
        assert!(
            error
                .to_string()
                .contains("QEMU profile `nondeterministic-host-v1` is unsupported")
        );
    }

    #[test]
    fn guarded_campaign_run_rejects_a_mismatched_host_architecture() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        let deployment = authored().replace(
            &format!("host_architecture = \"{}\"", std::env::consts::ARCH),
            "host_architecture = \"incompatible-test-host\"",
        );
        fs::write(&path, deployment).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let error = load_campaign_run_deployment(&path)
            .err()
            .expect("mismatched guarded host architecture");
        assert!(
            error
                .to_string()
                .contains("host architecture `incompatible-test-host` does not match")
        );
    }

    #[test]
    fn campaign_deployment_resolution_has_explicit_environment_and_system_precedence() {
        let explicit = Path::new("/explicit/campaign.toml");
        let environment = std::ffi::OsStr::new("/environment/campaign.toml");
        assert_eq!(
            resolve_campaign_deployment_path(Some(explicit), Some(environment), |_| true)
                .expect("explicit deployment"),
            explicit
        );
        assert_eq!(
            resolve_campaign_deployment_path(None, Some(environment), |_| true)
                .expect("environment deployment"),
            Path::new("/environment/campaign.toml")
        );
        assert_eq!(
            resolve_campaign_deployment_path(None, None, |_| true).expect("system deployment"),
            Path::new(DEFAULT_CAMPAIGN_DEPLOYMENT_PATH)
        );

        let missing = resolve_campaign_deployment_path(None, None, |_| false)
            .expect_err("missing host authority");
        assert!(missing.to_string().contains("--campaign-deployment PATH"));
        assert!(missing.to_string().contains(CAMPAIGN_DEPLOYMENT_ENV));
        assert!(
            missing
                .to_string()
                .contains(DEFAULT_CAMPAIGN_DEPLOYMENT_PATH)
        );
        assert!(
            resolve_campaign_deployment_path(None, Some(std::ffi::OsStr::new("")), |_| true,)
                .is_err()
        );
    }

    #[test]
    fn packaged_runs_default_to_bounded_rendezvous_without_overriding_explicit_policy() {
        assert_eq!(production_rendezvous_interval(None, false), None);
        assert_eq!(production_rendezvous_interval(None, true), Some(1_000_000));
        for packaged in [false, true] {
            assert_eq!(
                production_rendezvous_interval(Some(100), packaged),
                Some(100)
            );
            assert_eq!(
                production_rendezvous_interval(Some(2_000_000), packaged),
                Some(2_000_000)
            );
        }
    }

    #[test]
    fn packaged_executor_deployment_rejects_unknown_fields() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, format!("{}unknown = true\n", authored())).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");
        assert!(load_deployment(&path).is_err());
    }

    #[test]
    fn packaged_executor_store_namespace_is_stable_for_one_state_root() {
        let state = Path::new("/var/lib/crucible/campaign-state");
        assert_eq!(
            packaged_store_namespace(state),
            packaged_store_namespace(state)
        );
        assert_ne!(
            packaged_store_namespace(state),
            packaged_store_namespace(Path::new("/var/lib/crucible/other-state"))
        );
    }
}
