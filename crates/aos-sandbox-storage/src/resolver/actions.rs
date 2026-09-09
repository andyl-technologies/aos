//! Closed action-by-action resolution from protected policy and inventory.

use aos_sandbox_protocol::semantics::storage_prepare::StoragePreparationOperationV1;

use crate::root_policy::WorkspaceRootPolicyV1;
use crate::{ActiveHoldEvidence, CatalogPlanV1, HoldId, PlannedDataset, PlannedSnapshot};

use super::StorageCatalogResolverErrorV1;
use super::inventory::ProtectedStorageInventoryV2;
use super::policy::ProtectedStorageResolverPolicyV1;

pub(super) fn resolve_action(
    policy: &ProtectedStorageResolverPolicyV1,
    inventory: &ProtectedStorageInventoryV2,
    operation: StoragePreparationOperationV1,
    sandbox_id: [u8; 16],
    operation_id: [u8; 16],
) -> Result<(CatalogPlanV1, Option<WorkspaceRootPolicyV1>), StorageCatalogResolverErrorV1> {
    match operation {
        StoragePreparationOperationV1::CreateWorkspace {
            quota_bytes,
            reservation_bytes,
        } => {
            let name = policy.workspace_name(&sandbox_id)?;
            ensure_absent(inventory, &name)?;
            let destination =
                PlannedDataset::from_catalog(policy.root().clone(), &name, policy.domains())
                    .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)?;
            Ok((
                CatalogPlanV1::CreateWorkspace {
                    destination,
                    space: policy.space(quota_bytes, reservation_bytes)?,
                    ancestor: policy.project_ancestor().clone(),
                },
                Some(WorkspaceRootPolicyV1::create_initialize()),
            ))
        }
        StoragePreparationOperationV1::Snapshot { storage_handle } => {
            let source = workspace_dataset(policy, inventory, &storage_handle)?.clone();
            let component = ProtectedStorageResolverPolicyV1::snapshot_component(&operation_id);
            let destination = PlannedSnapshot::from_catalog(source.clone(), &component)
                .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)?;
            ensure_absent(inventory, destination.name())?;
            Ok((
                CatalogPlanV1::Snapshot {
                    source,
                    destination,
                },
                None,
            ))
        }
        StoragePreparationOperationV1::HoldSnapshot {
            storage_handle,
            version_handle,
            hold_id,
        } => {
            let snapshot = project_snapshot(policy, inventory, &storage_handle, &version_handle)?
                .snapshot()
                .clone();
            let hold_id = HoldId::from_bytes(hold_id)
                .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)?;
            if inventory.has_hold(snapshot.guid(), hold_id) {
                return Err(StorageCatalogResolverErrorV1::StateConflict);
            }
            Ok((CatalogPlanV1::HoldSnapshot { snapshot, hold_id }, None))
        }
        StoragePreparationOperationV1::ReleaseHold {
            storage_handle,
            version_handle,
            hold_id,
        } => {
            let snapshot = project_snapshot(policy, inventory, &storage_handle, &version_handle)?
                .snapshot()
                .clone();
            let hold_id = HoldId::from_bytes(hold_id)
                .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)?;
            if !inventory.has_hold(snapshot.guid(), hold_id) {
                return Err(StorageCatalogResolverErrorV1::StateConflict);
            }
            Ok((CatalogPlanV1::ReleaseHold { snapshot, hold_id }, None))
        }
        StoragePreparationOperationV1::Clone {
            storage_handle,
            version_handle,
            hold_id,
            quota_bytes,
            reservation_bytes,
        } => {
            let source = inventory
                .snapshot(&storage_handle, &version_handle)
                .ok_or(StorageCatalogResolverErrorV1::UnknownHandle)?;
            let hold_id = HoldId::from_bytes(hold_id)
                .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)?;
            if !inventory.has_hold(source.snapshot().guid(), hold_id) {
                return Err(StorageCatalogResolverErrorV1::StateConflict);
            }
            let root_policy = source.clone_root_policy()?;
            let name = policy.workspace_name(&sandbox_id)?;
            ensure_absent(inventory, &name)?;
            let destination =
                PlannedDataset::from_catalog(policy.root().clone(), &name, policy.domains())
                    .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)?;
            Ok((
                CatalogPlanV1::Clone {
                    source: Box::new(source.snapshot().clone()),
                    origin_hold: ActiveHoldEvidence::from_catalog(
                        source.snapshot().guid(),
                        hold_id,
                    )
                    .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)?,
                    destination,
                    space: policy.space(quota_bytes, reservation_bytes)?,
                    ancestor: policy.project_ancestor().clone(),
                },
                Some(root_policy),
            ))
        }
        StoragePreparationOperationV1::SetQuota {
            storage_handle,
            quota_bytes,
            reservation_bytes,
        } => {
            let dataset = workspace_dataset(policy, inventory, &storage_handle)?.clone();
            Ok((
                CatalogPlanV1::SetQuota {
                    dataset,
                    space: policy.space(quota_bytes, reservation_bytes)?,
                    ancestor: policy.project_ancestor().clone(),
                },
                None,
            ))
        }
        StoragePreparationOperationV1::Destroy {
            storage_handle,
            version_handle: Some(version_handle),
        } => {
            let snapshot = project_snapshot(policy, inventory, &storage_handle, &version_handle)?
                .snapshot()
                .clone();
            if inventory.snapshot_has_holds(snapshot.guid()) {
                return Err(StorageCatalogResolverErrorV1::StateConflict);
            }
            Ok((CatalogPlanV1::DestroySnapshot { snapshot }, None))
        }
        StoragePreparationOperationV1::Destroy {
            storage_handle,
            version_handle: None,
        } => {
            let dataset = workspace_dataset(policy, inventory, &storage_handle)?.clone();
            if inventory.dataset_has_snapshots(&storage_handle) {
                return Err(StorageCatalogResolverErrorV1::StateConflict);
            }
            Ok((CatalogPlanV1::DestroyDataset { dataset }, None))
        }
    }
}

fn workspace_dataset<'a>(
    policy: &ProtectedStorageResolverPolicyV1,
    inventory: &'a ProtectedStorageInventoryV2,
    storage_handle: &[u8; 32],
) -> Result<&'a crate::ResolvedDataset, StorageCatalogResolverErrorV1> {
    let dataset = inventory
        .dataset(storage_handle)
        .ok_or(StorageCatalogResolverErrorV1::UnknownHandle)?;
    let mut ancestor_prefix =
        String::with_capacity(policy.project_ancestor().dataset().name().len() + 1);
    ancestor_prefix.push_str(policy.project_ancestor().dataset().name());
    ancestor_prefix.push('/');
    if !dataset.name().starts_with(&ancestor_prefix) {
        return Err(StorageCatalogResolverErrorV1::PolicyRejected);
    }
    Ok(dataset)
}

fn project_snapshot<'a>(
    policy: &ProtectedStorageResolverPolicyV1,
    inventory: &'a ProtectedStorageInventoryV2,
    storage_handle: &[u8; 32],
    version_handle: &[u8; 32],
) -> Result<&'a super::inventory::ProtectedSnapshotInventoryV2, StorageCatalogResolverErrorV1> {
    let snapshot = inventory
        .snapshot(storage_handle, version_handle)
        .ok_or(StorageCatalogResolverErrorV1::UnknownHandle)?;
    workspace_dataset(policy, inventory, storage_handle)?;
    Ok(snapshot)
}

fn ensure_absent(
    inventory: &ProtectedStorageInventoryV2,
    name: &str,
) -> Result<(), StorageCatalogResolverErrorV1> {
    if inventory.name_is_occupied(name) {
        Err(StorageCatalogResolverErrorV1::StateConflict)
    } else {
        Ok(())
    }
}
