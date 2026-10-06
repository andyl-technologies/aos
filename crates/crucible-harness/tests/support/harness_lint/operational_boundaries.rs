//! Reviewed host-operation clocks and their deliberately narrow public contracts.
//!
//! These modules supervise transport, resources, and operator requests. Their
//! clock results may stop or quarantine work, but may not enter guest decisions,
//! virtual time, state reduction, or ordinary session routes. Export inventories
//! remain explicit so a new raw clock accessor requires a boundary review.

use std::path::Path;

const SUPERVISION_EXPORTS: &[&str] = &[
    "HOST_OPERATION_CLASS_COUNT",
    "MAX_HOST_OPERATIONS",
    "HostOperationClass",
    "ALL",
    "HostOperationBudget",
    "finite",
    "unlimited_quantum",
    "HostOperationBudgets",
    "get",
    "validate",
    "HostOperationState",
    "HostDeadlineSource",
    "HostProgressKind",
    "HostEffectiveDeadline",
    "HostOperationStatus",
    "HostOuterCapStatus",
    "HostOuterCapBinding",
    "HostSupervisionError",
    "HostOperationSupervisor",
    "new",
    "new_budget_owner",
    "shares_outer_cap",
    "begin",
    "begin_work",
    "begin_control",
    "cap_id",
    "update_budgets",
    "amend_outer_cap",
    "outer_cap_status",
    "outer_cap_binding",
    "operation_statuses",
    "status_snapshot",
    "budgets",
    "cancel",
    "complete",
    "HostOperationGuard",
    "status",
    "wait_slice",
    "wait_for_change",
    "wait_for_active_work_change",
    "progress",
];

const REGISTRY_EXPORTS: &[&str] = &[
    "HostResourceAdmission",
    "HostOperationalRegistry",
    "RegistryRetirementAuthority",
    "operational_identity",
    "open",
    "attach_admission",
    "bootstrap_limits",
    "configure_bootstrap_limits",
    "configure_owner",
    "admit_node",
    "repartition_node_before_cpu",
    "registered_targets",
    "grant_principal",
    "register_cap",
    "register_node",
    "register_with_qualification",
    "with_paging_qualification_match",
    "retire_node",
    "retire_node_after_cleanup",
    "retire_execution",
    "owner_ceiling",
    "capacity_custody",
    "retain_catalog_service",
    "reserve_service",
    "reserve_service_with_assignment_headroom",
    "reserve_service_with_admitted_assignment",
    "service_nodes_cleaned",
    "release_service_after_cleanup",
    "retire_service",
];

pub(super) fn operational_boundary_source(package: &str, package_dir: &Path, path: &Path) -> bool {
    let Some(relative) = relative_source(package_dir, path) else {
        return false;
    };
    matches!(
        (package, relative.as_str()),
        ("crucible-linux-resource", "src/host_supervision.rs")
            | ("crucible-daemon", "src/host_operational_registry.rs")
            | ("crucible-qemu", "src/node/shutdown_budget.rs")
            | ("crucible-qemu", "src/ram_control/supervision.rs")
            | ("crucible-qemu-plugin", "src/paged_ram/supervision.rs")
    )
}

pub(super) fn operational_public_exports(
    package: &str,
    package_dir: &Path,
    path: &Path,
) -> &'static [&'static str] {
    let Some(relative) = relative_source(package_dir, path) else {
        return &[];
    };
    match (package, relative.as_str()) {
        ("crucible-linux-resource", "src/host_supervision.rs") => SUPERVISION_EXPORTS,
        ("crucible-daemon", "src/host_operational_registry.rs") => REGISTRY_EXPORTS,
        ("crucible-daemon", "src/supervision.rs") => &["HOST_WATCHDOG_STACK_BYTES"],
        ("crucible-qemu", "src/linux_cgroup.rs") => &["LinuxQemuCgroupMemoryControl"],
        _ => &[],
    }
}

pub(super) fn operational_api_route(
    package: &str,
    package_dir: &Path,
    path: &Path,
) -> Option<&'static str> {
    let relative = relative_source(package_dir, path)?;
    match (package, relative.as_str()) {
        ("crucible-daemon", "src/host_operational_registry.rs") => Some("host_operational"),
        _ => None,
    }
}

fn relative_source(package_dir: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(package_dir)
        .ok()
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
}
