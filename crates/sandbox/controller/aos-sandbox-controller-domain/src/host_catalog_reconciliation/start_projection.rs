//! Reuses the complete catalog fold for the supported no-slot Start successor.
//!
//! This is shared comparison DATA for Controller and independent Root readers.
//! It issues no binding, installed catalog, UID grant or physical completion.

use super::*;

// The two owner families select only their actual fixed callees. The fold
// and its guard, allocation and error positions remain one lexical body;
// ordinary callers gain neither a new loan nor a forwarding call frame.
macro_rules! start_successor_catalog_recipe_v2 {
    (
        $journal:ident, $predecessor:ident, $successor:ident, $specification:ident,
        $storage:ident, $network:ident, $destinations:ident, $namespace:ident;
        history = $history:ident;
        bindings = $bindings:expr;
        validate_spec = $validate_spec:expr;
        lookup = $lookup:path, input = $spec_input:expr;
        attachments = $attachments:path;
        manifest = $manifest:ident
    ) => {{
    let history = CatalogHistory::$history($journal)?;
    if history.pending.is_some() { return Err(HostCatalogReconciliationError::PendingPublication); }
    let old = $predecessor.manifest();
    let new = $successor.manifest();
    if old.sandbox() != new.sandbox() || old.incarnation() != new.incarnation()
        || old.project() != new.project() || old.sandbox_spec() != new.sandbox_spec()
        || !$specification.spec().attachment_slots().is_empty()
        || $specification.descriptor() != new.sandbox_spec()
        || !fence_matches_manifest_data_v2($namespace.fence(), $successor)
        || $namespace.namespace_generation() != new.namespace_generation().get()
        || $namespace.sandbox_spec() != new.sandbox_spec()
        || $namespace.resource_kernel_boot_id() != $destinations.kernel_boot_id()
        || !$destinations.namespace_anchors_v1().iter().any(|actual| actual == $namespace)
        || $storage.kernel_boot_id() != $network.kernel_boot_id()
        || $storage.kernel_boot_id() != $destinations.kernel_boot_id()
    { return Err(HostCatalogReconciliationError::InventoryConflict); }

    let bindings = $bindings;
    let mut replacement = 0_usize;
    let manifests = bindings.iter().filter(|binding| binding.state() == RuntimeAuthorityStateV1::Bound)
        .map(|binding| {
            if binding.manifest().manifest().sandbox() == new.sandbox() {
                replacement += 1;
                if binding.manifest() != $predecessor { return Err(HostCatalogReconciliationError::InventoryConflict); }
                Ok($successor)
            } else { Ok(binding.manifest()) }
        }).collect::<Result<Vec<_>, HostCatalogReconciliationError>>()?;
    if replacement != 1 { return Err(HostCatalogReconciliationError::InventoryConflict); }
    $validate_spec;
    let previous = history.current.as_ref().map(|record| &record.catalog);
    let mut rows = ProjectedRows::default();
    for $manifest in &manifests {
        let Some(selected) = select_assignment_resources_data_v2($manifest, $storage, $network, previous)?
            else { return Err(HostCatalogReconciliationError::IncompleteResources); };
        let spec = $lookup($spec_input,
            $manifest.manifest().sandbox_spec())?.ok_or(HostCatalogReconciliationError::CorruptState)?;
        if !spec.spec().attachment_slots().is_empty() {
            // This three-resource chain has no full Mount15 lender. Never
            // silently drop existing attachments or adopt old-assignment proof.
            return Err(HostCatalogReconciliationError::IncompleteResources);
        }
        $attachments($journal, $manifest)?;
        if $destinations.slots().iter().any(|slot| {
            slot.fence().sandbox_id() == $manifest.manifest().sandbox().as_bytes()
                && slot.fence().incarnation_id() == $manifest.manifest().incarnation().as_bytes()
                && slot.namespace_generation() == $manifest.manifest().namespace_generation().get()
        }) { return Err(HostCatalogReconciliationError::InventoryConflict); }
        let anchor = ready_anchor_manifest_data_v2($manifest, spec.spec().attachment_slots(), $destinations)?
            .ok_or(HostCatalogReconciliationError::IncompleteResources)?;
        append_assignment_rows_data_v2(&mut rows, $manifest, selected, Some(anchor), Vec::new())?;
    }
    let rows = finish_projected_rows_data_v2(rows, previous, manifests.iter().copied())?;
    if let Some(current) = &history.current {
        let unchanged = materialize_catalog(current.catalog.generation(), &rows, Some(&current.catalog))?;
        if unchanged == current.catalog { return Ok(unchanged); }
    }
    let generation = history.current.as_ref().map(|record| record.catalog.generation())
        .map_or(Some(1), |generation| generation.checked_add(1))
        .ok_or(HostCatalogReconciliationError::GenerationExhausted)?;
    materialize_catalog(generation, &rows, previous)
    }};
}

macro_rules! start_projection_receiving_recipe_v2 {
    ($journal:ident, $storage:ident, $network:ident, $destinations:ident, $semantic:ident) => {{
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    let invalid = || JournalError::JournalTooLarge;
    let historical = $journal.records(RecordNamespace::HostCatalogReconciliation)
        .try_fold(0_usize, |bytes, (key, value)| bytes.checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len())).ok_or_else(invalid))?;
    let strings = $storage.workspaces().iter().try_fold(0_usize, |bytes, workspace|
        bytes.checked_add(workspace.root_directory().len())
            .and_then(|bytes| bytes.checked_add(workspace.root_image().media_type().as_str().len()))
            .ok_or_else(invalid))?;
    let strings = $network.networks().iter().try_fold(strings, |bytes, row|
        bytes.checked_add(row.namespace_path().len()).ok_or_else(invalid))?;
    let projected = aos_sandbox_protocol::host_catalog_snapshot::host_catalog_projection_model_receiving_bytes_v2(
        $storage.workspaces().len(), $network.networks().len(), $destinations.attachment_anchors().len(),
        historical, strings).ok_or_else(invalid)?;
    let rows = $storage.workspaces().len().checked_mul(std::mem::size_of::<ProjectedWorkspace>())
        .and_then(|bytes| bytes.checked_add($network.networks().len().checked_mul(std::mem::size_of::<ProjectedNetwork>())?))
        .and_then(|bytes| bytes.checked_add($destinations.attachment_anchors().len().checked_mul(std::mem::size_of::<ProjectedAnchor>())?))
        .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
    let memory = projected.checked_add(rows).and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
    $journal.$semantic()?.checked_add(
        ResourceVector::ZERO.with(D::MemoryBytes, memory)).map_err(|_| invalid())
    }};
}


/// Projects comparison DATA for the existing empty-attachment Start profile.
///
/// Both callers must independently obtain the exact predecessor and compiled
/// successor from their genuine current owners. No binding, catalog effect or
/// currentness proof is issued. Ordinary nonempty projection remains above.
pub(crate) fn project_start_successor_catalog_data_v2(
    journal: &mut Journal,
    predecessor: &CanonicalAssignmentManifestV1,
    successor: &CanonicalAssignmentManifestV1,
    specification: &crate::sandbox_spec_state::DurableSandboxSpecV1,
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    destinations: &ValidatedDestinationSlotInventory,
    namespace: &aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1,
) -> Result<HostCatalogSnapshot, HostCatalogReconciliationError> {
    start_successor_catalog_recipe_v2!(
        journal, predecessor, successor, specification,
        storage, network, destinations, namespace;
        history = load;
        bindings = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
            .current_bindings()?;
        validate_spec = crate::sandbox_spec_state::validate_namespace(journal)?;
        lookup = crate::sandbox_spec_state::get_in_validated_namespace, input = journal;
        attachments = crate::attachment_verification::require_empty_namespace_for_manifest_data_v2;
        manifest = manifest
    )
}

pub(crate) fn project_start_successor_catalog_from_observation_v2(
    journal: crate::journal::historical_observation::HistoricalObservationV1<'_>,
    predecessor: &CanonicalAssignmentManifestV1,
    successor: &CanonicalAssignmentManifestV1,
    specification: &crate::sandbox_spec_state::DurableSandboxSpecV1,
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    destinations: &ValidatedDestinationSlotInventory,
    namespace: &aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1,
) -> Result<HostCatalogSnapshot, HostCatalogReconciliationError> {
    start_successor_catalog_recipe_v2!(
        journal, predecessor, successor, specification,
        storage, network, destinations, namespace;
        history = load_observed_v2;
        bindings = crate::runtime_authority::current_bindings_observed_v2(
            journal, RuntimeAuthorityLimits::default())?;
        validate_spec = crate::sandbox_spec_state::validate_namespace_rows_v2(journal.rows_data_v2())?;
        lookup = crate::sandbox_spec_state::get_in_validated_rows_v2, input = journal.rows_data_v2();
        attachments = crate::attachment_verification::require_empty_namespace_for_manifest_observed_v2;
        manifest = manifest
    )
}

pub(crate) fn start_projection_receiving_demand_data_v2(
    journal: &Journal, storage: &ValidatedStorageInventory, network: &ValidatedNetworkInventory,
    destinations: &ValidatedDestinationSlotInventory,
) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
    start_projection_receiving_recipe_v2!(
        journal, storage, network, destinations, create_storage_semantic_append_demand_v1
    )
}

pub(crate) fn start_projection_receiving_from_observation_v2(
    journal: crate::journal::historical_observation::HistoricalObservationV1<'_>, storage: &ValidatedStorageInventory, network: &ValidatedNetworkInventory,
    destinations: &ValidatedDestinationSlotInventory,
) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
    start_projection_receiving_recipe_v2!(
        journal, storage, network, destinations, semantic_append_model_demand_v2
    )
}

/// Prices the actual Host reader chain before its first dynamic geometry call.
pub(crate) fn host_start_observation_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    use aos_sandbox_model::ResourceVector;
    size_of::<(crate::journal::historical_observation::HistoricalObservationV1<'_>, &CanonicalAssignmentManifestV1, &CanonicalAssignmentManifestV1,
        &crate::sandbox_spec_state::DurableSandboxSpecV1, &ValidatedStorageInventory,
        &ValidatedNetworkInventory, &ValidatedDestinationSlotInventory,
        &aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1)>().checked_mul(3)?
        .checked_add(size_of::<Result<HostCatalogSnapshot, HostCatalogReconciliationError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<CatalogHistory, HostCatalogReconciliationError>>().checked_mul(3)?)?
        .checked_add(size_of::<(crate::journal::historical_observation::HistoricalObservationV1<'_>, &ValidatedStorageInventory, &ValidatedNetworkInventory, &ValidatedDestinationSlotInventory)>().checked_mul(3)?)?
        .checked_add(size_of::<(crate::journal::historical_observation::HistoricalObservationV1<'_>, &CatalogHistory)>().checked_mul(3)?)?
        .checked_add(size_of::<(&CanonicalAssignmentManifestV1, &CatalogHistory, &[RuntimeAuthorityBindingV1])>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), HostCatalogReconciliationError>>().checked_mul(3)?)?
        .checked_add(size_of::<(usize, usize)>().checked_mul(3)?)?
        .checked_add(crate::runtime_authority::all_bindings_observation_control_bytes_v2()?)?
        .checked_add(crate::sandbox_spec_state::observed_validated_control_bytes_v2()?)?
        .checked_add(crate::attachment_state::historical_observation_control_bytes_v2()?)?
        .checked_add(crate::filesystem_view_state::historical_observation_control_bytes_v2()?)?
        .checked_add(crate::attachment_slot_state::historical_observation_control_bytes_v2()?)?
        .checked_add(crate::attachment_verification::historical_observation_control_bytes_v2()?)?
        .checked_add(crate::runtime_scope::namespace_target_observation_control_bytes_v2()?)?
        .checked_add(crate::runtime_scope::generation_observation_control_bytes_v2()?)?
        .checked_add(crate::reconciler::completed_host_observation_control_bytes_v2()?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
