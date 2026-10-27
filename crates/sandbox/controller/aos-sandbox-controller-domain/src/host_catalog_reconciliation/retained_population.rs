//! Compares retained no-slot resources with exact completed-Stop history.
//!
//! The caller owns the fresh maintenance interval, same protected C/Source
//! cuts and positively disposed sole inventory decoders. Current catalog rows
//! and completed Stop history supply comparison identity, never a launch,
//! cleanup or publication grant. Every population member must be accounted for.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::{
    ControllerInventoryDecodedOriginalV2, ControllerInventoryModelDataV2 as Model,
};
use aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4;

/// Retains exact stopped-only comparison identity inside the live maintenance.
///
/// Private construction follows actual completed Stop/Start and fresh resource
/// joins. This record cannot issue a grant, mutate a catalog or prove native
/// currentness apart from its same held maintenance/source owner.
pub(crate) struct StoppedRetentionComparisonV1 {
    scope: HostStoppedNamespaceDataV4,
    project: aos_sandbox_model::ProjectId,
    catalog_row: [u8; 32],
}

impl StoppedRetentionComparisonV1 {
    /// Borrows the literal completed Stop scope for the same history rejoin.
    pub(crate) fn scope_v1(&self) -> &HostStoppedNamespaceDataV4 {
        &self.scope
    }

    fn require_same_catalog(
        &self,
        controller: &Journal,
    ) -> Result<(), HostCatalogReconciliationError> {
        let current = controller
            .get(RecordNamespace::HostCatalogReconciliation, CURRENT_KEY)
            .ok_or(HostCatalogReconciliationError::IncompleteResources)?;
        if self.catalog_row != <[u8; 32]>::from(Sha256::digest(current))
            || controller
                .get(RecordNamespace::HostCatalogReconciliation, PENDING_KEY)
                .is_some()
        {
            return Err(HostCatalogReconciliationError::InventoryConflict);
        }
        Ok(())
    }
}

/// Keeps the exact current catalog under the genuine stopped-only borrower.
///
/// This creates no pending catalog and does not make Fenced launchable.
///
/// # Errors
/// Refuses changed native snapshot/current history or retained physical rows.
pub(super) fn prepare_stopped_retention_model_data_v1(
    controller: &mut Journal,
    storage: DurableStorageResourceInventorySnapshotV1,
    network: DurableNetworkResourceInventorySnapshotV1,
    destinations: DurableDestinationSlotInventorySnapshotV1,
    history: CatalogHistory,
    retained: &StoppedRetentionComparisonV1,
    start: &crate::controller_resource_reservation::CatalogMaintenanceCompletedStartDataV1,
    completed: &crate::lifecycle::completed_stop::CompletedStopHistoryDataV1,
) -> Result<PreparedHostCatalogModelDataV2, HostCatalogReconciliationError> {
    storage.recheck(controller)?;
    network.recheck(controller)?;
    destinations.recheck(controller)?;
    if storage.controller_state_digest() != network.controller_state_digest()
        || retained.scope != *completed.historical_scope_v1()
        || retained.project != completed.project_v1()
        || history.pending.is_some()
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    retained.require_same_catalog(controller)?;
    let current = require_retained_stopped_resources_data_v1(
        controller,
        completed,
        start,
        storage.inventory(),
        network.inventory(),
        destinations.inventory(),
    )?;
    if current.catalog_row != retained.catalog_row {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    let record = history
        .current
        .ok_or(HostCatalogReconciliationError::IncompleteResources)?;
    Ok(PreparedHostCatalogModelDataV2::Current(
        DurableCurrentHostCatalogV1 { record },
    ))
}

/// Prices complete protected namespace selection before structural decoding.
///
/// The native maintenance owner admits this comparison geometry; the supplier
/// supplies neither an account nor current resource authority.
///
/// # Errors
/// Refuses overflowing model, map, selected-binding or catalog-history bounds.
pub(crate) fn retained_population_receiving_demand_v1(
    controller: &Journal,
) -> Result<ResourceVector, JournalError> {
    // A completed Stop necessarily retains its actual Effect. This raw
    // negative check avoids charging unreachable decoders on the empty path;
    // presence alone selects no history or resource permission.
    if controller.records(RecordNamespace::Effect).next().is_none() {
        return Ok(ResourceVector::ZERO);
    }
    let invalid = || JournalError::JournalTooLarge;
    let authority = crate::runtime_authority::current_publication_receiving_demand_v2(controller)
        .ok_or_else(invalid)?;
    let specification = crate::sandbox_spec_state::execution_source_receiving_bytes_v1(controller)
        .ok_or_else(invalid)?;
    let bindings = controller
        .records(RecordNamespace::RuntimeAuthority)
        .count()
        .checked_mul(std::mem::size_of::<RuntimeAuthorityBindingV1>())
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<RuntimeAuthorityBindingV1>>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(invalid)?;
    let comparison = std::mem::size_of::<
        aos_sandbox_protocol::host_stopped_namespace::HostStoppedInventoryDataV1,
    >()
    .checked_add(std::mem::size_of::<
        crate::lifecycle::completed_stop::CompletedStopHistoryDataV1,
    >())
    .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StoppedRetentionComparisonV1>()))
    .and_then(|bytes| {
        bytes.checked_add(std::mem::size_of::<
            Result<StoppedRetentionComparisonV1, JournalError>,
        >())
    })
    .and_then(|bytes| {
        bytes.checked_add(std::mem::size_of::<
            Result<StoppedRetentionComparisonV1, HostCatalogReconciliationError>,
        >())
    })
    .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Sha256>()))
    .and_then(|bytes| bytes.checked_add(std::mem::size_of::<[u64; 4]>()))
    .and_then(|bytes| bytes.checked_mul(3))
    .and_then(|bytes| u64::try_from(bytes).ok())
    .ok_or_else(invalid)?;
    let history = super::source_receiving::canonical_source_history_receiving_demand_v2(
        controller,
        std::mem::size_of::<CatalogHistory>(),
    )
    .map_err(|_| invalid())?;
    let memory = specification
        .checked_add(bindings)
        .and_then(|bytes| bytes.checked_add(comparison))
        .ok_or_else(invalid)?;
    authority
        .checked_add(history)
        .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory)))
        .map_err(JournalError::ReceivingAccounting)
}

/// Prices the same catalog model against the actual sole decoded inventories.
///
/// # Errors
/// Refuses another inventory family or overflowing canonical model geometry.
pub(crate) fn retained_population_model_receiving_demand_v1(
    controller: &Journal,
    storage: &ControllerInventoryDecodedOriginalV2,
    mount: &ControllerInventoryDecodedOriginalV2,
    network: &ControllerInventoryDecodedOriginalV2,
) -> Result<ResourceVector, JournalError> {
    let (Model::Storage(storage, _), Model::Mount(mount), Model::Network(network)) =
        (storage.model_v2(), mount.model_v2(), network.model_v2())
    else {
        return Err(JournalError::ProtectedBoundary);
    };
    super::source_receiving::maintenance_no_slots_projection_receiving_demand_v2(
        controller, storage, network, mount,
    )
}

/// Joins completed Stop and Start history to exact retained current resources.
///
/// # Errors
/// Refuses another assignment, unsupported attachments, incomplete or extra
/// resources, pending publication, or changed current catalog physical rows.
pub(crate) fn require_retained_stopped_resources_data_v1(
    controller: &mut Journal,
    completed: &crate::lifecycle::completed_stop::CompletedStopHistoryDataV1,
    start: &crate::controller_resource_reservation::CatalogMaintenanceCompletedStartDataV1,
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    destinations: &ValidatedDestinationSlotInventory,
) -> Result<StoppedRetentionComparisonV1, HostCatalogReconciliationError> {
    let bindings = RuntimeAuthorityStore::load(controller, RuntimeAuthorityLimits::default())?
        .current_bindings()?;
    let mut current = bindings
        .iter()
        .filter(|binding| binding.state() == RuntimeAuthorityStateV1::Bound);
    let binding = current
        .next()
        .ok_or(HostCatalogReconciliationError::IncompleteResources)?;
    if current.next().is_some()
        || binding.manifest() != start.manifest_v1()
        || binding.manifest().manifest().project() != completed.project_v1()
        || binding.manifest().manifest().sandbox() != completed.sandbox_v1()
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    crate::sandbox_spec_state::validate_namespace(controller)?;
    let specification = crate::sandbox_spec_state::get_in_validated_namespace(
        controller,
        binding.manifest().manifest().sandbox_spec(),
    )?
    .ok_or(HostCatalogReconciliationError::CorruptState)?;
    if !specification.spec().attachment_slots().is_empty() {
        return Err(HostCatalogReconciliationError::IncompleteResources);
    }
    crate::attachment_verification::require_empty_namespace_for_manifest_data_v2(
        controller,
        binding.manifest(),
    )?;
    let history = CatalogHistory::load(controller)?;
    if history.pending.is_some() {
        return Err(HostCatalogReconciliationError::PendingPublication);
    }
    if history
        .current
        .as_ref()
        .is_none_or(|record| record.mount_source != CatalogMountSourceVersionV2::NoSlots16V2)
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    let prior = &history
        .current
        .as_ref()
        .ok_or(HostCatalogReconciliationError::IncompleteResources)?
        .catalog;
    let template = start.runtime_template_v1();
    let plan = template
        .launch_plan()
        .ok_or(HostCatalogReconciliationError::InventoryConflict)?;
    if template.action() != aos_sandbox_api::aos::sandbox::local::v1::RuntimeAction::RUNTIME_ACTION_LAUNCH
        || template.fence() != completed.historical_scope_v1().fence_v4()
        || plan.attachment_anchor_handle() != completed.historical_scope_v1().anchor_v4()
        || !plan.attachment_handles().is_empty()
        || storage
            .workspaces()
            .first()
            .map(|row| row.workspace_handle())
            != Some(plan.workspace_handle())
        || network.networks().first().map(|row| row.network_handle()) != Some(plan.network_handle())
        || plan.root_image() != binding.manifest().manifest().root_view()
        || storage
            .workspaces()
            .first()
            .map(|row| row.uid_range_start())
            != Some(plan.uid_range_start())
        || storage.workspaces().first().map(|row| row.uid_range_size())
            != Some(plan.uid_range_size())
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    require_retained_inventory_rows_data_v1(
        binding.manifest(),
        completed.historical_scope_v1(),
        storage,
        network,
        destinations,
        prior,
    )?;
    let current = controller
        .get(RecordNamespace::HostCatalogReconciliation, CURRENT_KEY)
        .ok_or(HostCatalogReconciliationError::IncompleteResources)?;
    Ok(StoppedRetentionComparisonV1 {
        scope: *completed.historical_scope_v1(),
        project: completed.project_v1(),
        catalog_row: Sha256::digest(current).into(),
    })
}

/// Compares one complete no-slot resource set without issuing native proof.
///
/// # Errors
/// Refuses missing, foreign, additional, unfinished or physically changed rows.
/// Only the enclosing history/current-assignment path selects production input.
pub(super) fn require_retained_inventory_rows_data_v1(
    manifest: &CanonicalAssignmentManifestV1,
    scope: &HostStoppedNamespaceDataV4,
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    destinations: &ValidatedDestinationSlotInventory,
    prior: &HostCatalogSnapshot,
) -> Result<(), HostCatalogReconciliationError> {
    if !fence_matches_manifest_data_v2(scope.fence_v4(), manifest)
        || storage.workspaces().len() != 1
        || network.networks().len() != 1
        || !destinations.slots().is_empty()
        || destinations.attachment_anchors().len() != 1
        || destinations.namespace_anchors_v1().len() != 1
        || storage.kernel_boot_id() != network.kernel_boot_id()
        || storage.kernel_boot_id() != destinations.kernel_boot_id()
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    let selected = select_assignment_resources_with_profile_data_v1(
        manifest,
        storage,
        network,
        Some(prior),
        ResourceSelectionProfileV1::StoppedRetention,
    )?
    .ok_or(HostCatalogReconciliationError::IncompleteResources)?;
    let anchor = ready_anchor_manifest_data_v2(manifest, &[], destinations)?
        .ok_or(HostCatalogReconciliationError::IncompleteResources)?;
    if anchor.handle() != scope.anchor_v4() {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    let mut rows = ProjectedRows::default();
    append_assignment_rows_data_v2(&mut rows, manifest, selected, Some(anchor), Vec::new())?;
    let rows = finish_projected_rows_data_v2(rows, Some(prior), std::iter::once(manifest))?;
    let current = materialize_catalog(prior.generation(), &rows, Some(prior))?;
    if &current != prior {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    Ok(())
}
