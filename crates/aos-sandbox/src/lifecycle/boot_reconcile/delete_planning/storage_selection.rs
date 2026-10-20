//! Shares first-local Storage cleanup selection from complete passive models.
//!
//! Root and Controller separately retain genuine current assignment, full
//! selected graph/batch and signed inventory/native originals. This one pure
//! predicate selects no authority: callers must still join their own actual D,
//! pay before construction and verify the canonical plan/lease independently.

use aos_sandbox_core::{BrokerAssignment, CanonicalAssignmentManifestV1, OperationId, SandboxId};
use aos_sandbox_protocol::{ValidatedStorageInventory,
    authorization_artifact::delete_resource_plan::DeleteResourceRequestDataV2,
    domain_ledger::lifecycle_model::LifecycleResourceV1, semantics::CatalogBindingV1};
use sha2::{Digest as _, Sha256};
use super::super::{LifecycleAuthenticatedStorageInventoryV1, LifecycleStorageInventoryKindV1};

/// Retains fixed selected request DATA without a key, native owner or permit.
#[derive(Clone, Copy)]
pub(crate) struct SelectedDeleteResourceDataV4 {
    pub(crate) request: DeleteResourceRequestDataV2,
    pub(crate) assignment: BrokerAssignment,
    pub(crate) operation: OperationId,
    pub(crate) request_id: [u8; 16],
}

pub(crate) type SelectedDeleteStoragePreparationDataV2 = SelectedDeleteResourceDataV4;

#[derive(Debug, thiserror::Error)]
#[error("first-local Delete Storage selection differs from current complete models")]
pub(crate) struct DeleteStorageSelectionErrorV2;

/// Selects the same concrete workspace/request from independently owned DATA.
pub(crate) fn select_first_local_delete_storage_preparation_data_v2(
    root: SandboxId, resources: &[LifecycleResourceV1], manifest: &CanonicalAssignmentManifestV1,
    inventory: &ValidatedStorageInventory, lifecycle: &LifecycleAuthenticatedStorageInventoryV1,
    operation: OperationId, nonce: [u8; 16], cutoff: u64,
) -> Result<SelectedDeleteStoragePreparationDataV2, DeleteStorageSelectionErrorV2> {
    let invalid = || DeleteStorageSelectionErrorV2;
    let current = manifest.manifest();
    if nonce == [0; 16] || operation.as_bytes() == &[0; 16] || cutoff == 0
        || current.sandbox() != root || resources.iter().any(|resource|
            matches!(resource, LifecycleResourceV1::Sandbox(sandbox) if *sandbox != root)
                || matches!(resource, LifecycleResourceV1::Snapshot(_) | LifecycleResourceV1::Attachment(_))) {
        return Err(invalid());
    }
    let mut roots = inventory.workspaces().iter().filter(|row|
        row.fence().sandbox_id() == current.sandbox().as_bytes());
    let workspace = roots.next().ok_or_else(invalid)?;
    if roots.next().is_some() || workspace.fence().incarnation_id() != current.incarnation().as_bytes()
        || lifecycle.source_version() != 3 { return Err(invalid()); }
    let handle = workspace.workspace_handle();
    let mut datasets = lifecycle.entries().iter().filter(|row|
        row.resource() == LifecycleResourceV1::Sandbox(root)
            && row.kind() == LifecycleStorageInventoryKindV1::Dataset);
    let dataset = datasets.next().ok_or_else(invalid)?;
    if datasets.next().is_some() || dataset.effect_subject().as_bytes() != handle
        || dataset.lifecycle_operation().map(|value| value.into_bytes()) != Some(*workspace.creation_operation_id())
        || lifecycle.entries().iter().any(|row| row.effect_subject().as_bytes() == handle
            && row.kind() == LifecycleStorageInventoryKindV1::Clone) { return Err(invalid()); }
    // The resolver's inventory and expected-head are the same physical.binding.
    // Only a NEW authenticated26 result can later supply the Apply7 catalog.
    let predecessor = CatalogBindingV1::from_publisher(lifecycle.generation(), lifecycle.head())
        .map_err(|_| invalid())?;
    let digest = Sha256::new().chain_update(b"aos.sandbox.delete.cleanup-prepare-request.v2\0")
        .chain_update(nonce).chain_update(operation.as_bytes()).chain_update(handle).finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16] { return Err(invalid()); }
    Ok(SelectedDeleteStoragePreparationDataV2 {
        request: DeleteResourceRequestDataV2::StoragePrepareDestroy { storage_handle: *handle,
            version_handle: None, inventory: predecessor, expected_head: predecessor,
            preparation_expires_boottime_nanoseconds: cutoff },
        assignment: manifest.broker_assignment().map_err(|_| invalid())?, operation, request_id,
    })
}

impl SelectedDeleteStoragePreparationDataV2 {
    /// Selects Apply7 only from the exact prior Prepare26 selection and its new catalog.
    pub(crate) fn apply_data_v3(self, catalog: CatalogBindingV1,
        current: aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3,
    ) -> Result<Self, DeleteStorageSelectionErrorV2> {
        let DeleteResourceRequestDataV2::StoragePrepareDestroy { storage_handle, version_handle, .. } = self.request
            else { return Err(DeleteStorageSelectionErrorV2); };
        let completed = current.commitment_v3().map_err(|_| DeleteStorageSelectionErrorV2)?;
        let digest = Sha256::new().chain_update(b"aos.sandbox.delete.cleanup-apply-request.v3\0")
            .chain_update(self.operation.as_bytes()).chain_update(self.request_id)
            .chain_update(completed).chain_update(catalog.generation().to_be_bytes())
            .chain_update(catalog.digest().as_bytes()).finalize();
        let mut request_id = [0;16]; request_id.copy_from_slice(&digest[..16]);
        if request_id == [0;16] || request_id == self.request_id { return Err(DeleteStorageSelectionErrorV2); }
        Ok(Self { request: DeleteResourceRequestDataV2::StorageDestroy { storage_handle, version_handle, catalog },
            request_id, ..self })
    }
}

/// Selects the exact existing Network namespace from full retained Inventory.
pub(crate) fn select_first_local_delete_network_data_v4(
    root: SandboxId, resources: &[LifecycleResourceV1], manifest: &CanonicalAssignmentManifestV1,
    inventory: &aos_sandbox_protocol::ValidatedNetworkInventory,
    lifecycle: &super::super::LifecycleAuthenticatedBrokerDomainInventoryV1,
    operation: OperationId, nonce: [u8; 16], predecessor: [u8; 32],
) -> Result<SelectedDeleteResourceDataV4, DeleteStorageSelectionErrorV2> {
    let invalid = || DeleteStorageSelectionErrorV2;
    let current = manifest.manifest();
    if current.sandbox() != root || nonce == [0; 16] || predecessor == [0; 32]
        || operation.as_bytes() == &[0; 16]
        || resources.iter().any(|resource|
            matches!(resource, LifecycleResourceV1::Sandbox(sandbox) if *sandbox != root)
                || matches!(resource, LifecycleResourceV1::Snapshot(_) | LifecycleResourceV1::Attachment(_))) {
        return Err(invalid());
    }
    let mut selected = inventory.networks().iter().filter(|namespace|
        namespace.fence().sandbox_id() == root.as_bytes());
    let namespace = selected.next().ok_or_else(invalid)?;
    let fence = namespace.fence();
    if selected.next().is_some()
        || fence.incarnation_id() != current.incarnation().as_bytes()
        || fence.assignment_epoch() != current.epoch().get()
        || fence.assignment_digest() != manifest.digest().as_bytes()
        || fence.desired_generation() != current.desired_generation().get() {
        return Err(invalid());
    }
    let mut rows = lifecycle.entries().iter().filter(|row| row.resource() == LifecycleResourceV1::Sandbox(root));
    let row = rows.next().ok_or_else(invalid)?;
    if rows.next().is_some() || row.identity().as_bytes() != namespace.resource_digest() {
        return Err(invalid());
    }
    let digest = Sha256::new().chain_update(b"aos.sandbox.delete.network-cleanup-request.v4\0")
        .chain_update(nonce).chain_update(operation.as_bytes())
        .chain_update(namespace.network_handle()).chain_update(namespace.resource_digest())
        .chain_update(predecessor).finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16] { return Err(invalid()); }
    Ok(SelectedDeleteResourceDataV4 {
        request: DeleteResourceRequestDataV2::NetworkDestroy { network_handle: *namespace.network_handle() },
        assignment: manifest.broker_assignment().map_err(|_| invalid())?, operation, request_id,
    })
}
