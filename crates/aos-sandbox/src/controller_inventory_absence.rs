//! Shares exact empty and completed-Stop population comparisons without proof.
//!
//! Both native Recover and maintenance consumers must independently join their
//! actual completed query/disposal owners, same held Sessions and all outer
//! Source/C/clock posts. These immutable sole-decoder models are comparison
//! DATA; their empty collections alone never establish physical absence.
//! The retained no-slot branch additionally requires actual completed C/Source
//! history and exact current protected resource anchors; it synthesizes no
//! empty service census or historical effect permission.

use crate::JournalError;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::{
    ControllerInventoryDecodedOriginalV2, ControllerInventoryModelDataV2 as Model,
};

pub(crate) fn require_first_local_inventory_absence_data_v2(
    original: RawPairedClockSample,
    cutoff: u64,
    host_outcome: &AuthenticatedBrokerMethodOutcomeV1,
    host_decoded: &ControllerInventoryDecodedOriginalV2,
    mount_outcome: &AuthenticatedBrokerMethodOutcomeV1,
    mount_decoded: &ControllerInventoryDecodedOriginalV2,
    network_outcome: &AuthenticatedBrokerMethodOutcomeV1,
    network_decoded: &ControllerInventoryDecodedOriginalV2,
) -> Result<(), JournalError> {
    let Model::Host(model) = host_decoded.model_v2() else {
        return Err(JournalError::ProtectedBoundary);
    };
    let cold = aos_sandbox_protocol::host_inventory_absence::HostInventoryAbsenceDataV5::from_inventory_v5(model)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let recovery = aos_sandbox_protocol::host_recovered_namespace::HostRecoveredNamespaceDataV7::from_inventory_v7(model)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    // Both are fresh global native census observations. A recovery row keeps
    // its old scope on the decoded original; it restores no historical owner
    // and does not complete the old request or authorize an effect.
    let absent = match (cold, recovery) {
        (Some(absent), None) => absent,
        (None, Some(recovery)) => *recovery.observation_v7(),
        _ => return Err(JournalError::ProtectedBoundary),
    };
    let (before, after) = absent.boottime_interval_v5();
    if !model.runtimes.is_empty()
        || !model.stopped_namespaces_v4.is_empty()
        || absent.request_id_v5() != &host_outcome.request().request_id()
        || absent.boot_v5() != &original.host_boot_id()
        || before < original.boottime_nanoseconds()
        || before > after
        || after >= cutoff
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let Model::Mount(slots) = mount_decoded.model_v2() else {
        return Err(JournalError::ProtectedBoundary);
    };
    let Model::Network(networks) = network_decoded.model_v2() else {
        return Err(JournalError::ProtectedBoundary);
    };
    let mount_absent = slots
        .native_absence_v2()
        .ok_or(JournalError::ProtectedBoundary)?;
    let network_absent = networks
        .native_absence_v2()
        .ok_or(JournalError::ProtectedBoundary)?;
    let (mount_before, mount_after) = mount_absent.boottime_interval_v2();
    let (network_before, network_after) = network_absent.boottime_interval_v2();
    if mount_absent.request_id_v2() != &mount_outcome.request().request_id()
        || mount_absent.boot_v2() != &original.host_boot_id()
        || mount_before < original.boottime_nanoseconds()
        || mount_before > mount_after
        || mount_after >= cutoff
    {
        return Err(JournalError::ProtectedBoundary);
    }
    if network_absent.request_id_v2() != &network_outcome.request().request_id()
        || network_absent.boot_v2() != &original.host_boot_id()
        || network_before < original.boottime_nanoseconds()
        || network_before > network_after
        || network_after >= cutoff
        || after > mount_before
        || mount_after > network_before
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let boot = original.host_boot_id();
    if slots.kernel_boot_id() != &boot
        || networks.kernel_boot_id() != &boot
        || !slots.slots().is_empty()
        || !slots.attachment_anchors().is_empty()
        || !slots.namespace_anchors_v1().is_empty()
        || !networks.networks().is_empty()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Compares the finite retained no-slot population after a proved Stop.
///
/// The caller has paid both C/history and actual inventory model frontiers,
/// bound each sole decoder to its disposed native query, and retains the same
/// protected C/Source owners. This comparison issues no physical or effect
/// authority; the existing empty-population entry remains independent above.
///
/// # Errors
/// Refuses unproved history, another native inventory family, a foreign boot,
/// disordered or expired query points, or a changed retained resource set.
#[cfg(target_os = "linux")]
pub(crate) fn require_cold_maintenance_inventory_population_v1(
    controller: &mut crate::Journal,
    history: &crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1,
    starts: &crate::controller_resource_reservation::CatalogMaintenanceCompletedStartOriginalV1,
    original: RawPairedClockSample,
    cutoff: u64,
    observed: [u64; 4],
    host: (
        &AuthenticatedBrokerMethodOutcomeV1,
        &ControllerInventoryDecodedOriginalV2,
    ),
    mount: (
        &AuthenticatedBrokerMethodOutcomeV1,
        &ControllerInventoryDecodedOriginalV2,
    ),
    storage: (
        &AuthenticatedBrokerMethodOutcomeV1,
        &ControllerInventoryDecodedOriginalV2,
    ),
    network: (
        &AuthenticatedBrokerMethodOutcomeV1,
        &ControllerInventoryDecodedOriginalV2,
    ),
) -> Result<crate::host_catalog_reconciliation::StoppedRetentionComparisonV1, JournalError> {
    use aos_sandbox_protocol::host_stopped_namespace::HostStoppedInventoryDataV1;
    let invalid = || JournalError::ProtectedBoundary;
    // The owning maintenance loan permits ordinal N only after every earlier
    // query's actual native disposal. These saved kernel points supplement
    // that genuine ordering; body timestamps cannot replace them.
    if observed
        .iter()
        .any(|sample| *sample < original.boottime_nanoseconds() || *sample >= cutoff)
        || observed.windows(2).any(|pair| pair[0] > pair[1])
    {
        return Err(invalid());
    }
    let Model::Host(model) = host.1.model_v2() else {
        return Err(invalid());
    };
    if !model.runtimes.is_empty() {
        return Err(invalid());
    }
    let stopped = HostStoppedInventoryDataV1::from_inventory_v1(model)
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let scope = stopped
        .require_completed_v1(
            host.0.request().request_id(),
            original.host_boot_id(),
            original.boottime_nanoseconds(),
            observed[0],
            cutoff,
        )
        .map_err(|_| invalid())?;
    let completed = history.require_scope_v1(scope)?;
    if let HostStoppedInventoryDataV1::Cleanup(lineage) = &stopped {
        completed.require_cleanup_v1(lineage)?;
    }
    let start = starts.require_stopped_scope_v1(scope)?;
    let (Model::Mount(destinations), Model::Storage(workspaces, _), Model::Network(networks)) = (
        mount.1.model_v2(),
        storage.1.model_v2(),
        network.1.model_v2(),
    ) else {
        return Err(invalid());
    };
    // Nonempty canonical Mount/Network inventories intentionally carry no
    // empty-only absence companion. Their same native query originals and
    // signed bodies were joined before this retained-resource comparison.
    if destinations.kernel_boot_id() != &original.host_boot_id()
        || networks.kernel_boot_id() != &original.host_boot_id()
        || workspaces.kernel_boot_id() != &original.host_boot_id()
    {
        return Err(invalid());
    }
    crate::host_catalog_reconciliation::require_retained_stopped_resources_data_v1(
        controller,
        &completed,
        start,
        workspaces,
        networks,
        destinations,
    )
    .map_err(|_| invalid())
}
