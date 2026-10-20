//! Closed action-by-action resolution from protected policy and inventory.

use aos_sandbox_protocol::semantics::storage_prepare::StoragePreparationOperationV1;

use crate::clone_identity::CloneIdentityRequirementV1;
use crate::root_policy::WorkspaceRootPolicyV1;
use crate::{ActiveHoldEvidence, CatalogPlanV1, HoldId, PlannedDataset, PlannedSnapshot};

use super::StorageCatalogResolverErrorV1;
use super::inventory::ProtectedStorageInventoryV1;
use super::policy::ProtectedStorageResolverPolicyV1;

pub(super) fn resolve_action(
    policy: &ProtectedStorageResolverPolicyV1,
    inventory: &ProtectedStorageInventoryV1,
    operation: StoragePreparationOperationV1,
    sandbox_id: [u8; 16],
    operation_id: [u8; 16],
) -> Result<
    (
        CatalogPlanV1,
        Option<WorkspaceRootPolicyV1>,
        Option<CloneIdentityRequirementV1>,
    ),
    StorageCatalogResolverErrorV1,
> {
    resolve_action_with_generation(policy, inventory, operation, sandbox_id, operation_id, None)
}

fn resolve_action_with_generation(
    policy: &ProtectedStorageResolverPolicyV1,
    inventory: &ProtectedStorageInventoryV1,
    operation: StoragePreparationOperationV1,
    sandbox_id: [u8; 16],
    operation_id: [u8; 16],
    generation: Option<u64>,
) -> Result<
    (CatalogPlanV1, Option<WorkspaceRootPolicyV1>, Option<CloneIdentityRequirementV1>),
    StorageCatalogResolverErrorV1,
> {
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
                None,
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
            Ok((
                CatalogPlanV1::HoldSnapshot { snapshot, hold_id },
                None,
                None,
            ))
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
            Ok((CatalogPlanV1::ReleaseHold { snapshot, hold_id }, None, None))
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
            let (root_policy, clone_identity) = source.clone_identity_policy()?;
            let name = match generation {
                None => policy.workspace_name(&sandbox_id)?,
                Some(generation) => policy.nix_generation_name(&sandbox_id, generation)?,
            };
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
                Some(clone_identity),
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
            Ok((CatalogPlanV1::DestroySnapshot { snapshot }, None, None))
        }
        StoragePreparationOperationV1::Destroy {
            storage_handle,
            version_handle: None,
        } => {
            let dataset = workspace_dataset(policy, inventory, &storage_handle)?.clone();
            if inventory.dataset_has_snapshots(&storage_handle) {
                return Err(StorageCatalogResolverErrorV1::StateConflict);
            }
            Ok((CatalogPlanV1::DestroyDataset { dataset }, None, None))
        }
    }
}

impl super::StorageCatalogResolverV1 {
    /// Resolves selected Clone intent against the same authenticated inventory.
    pub(crate) fn resolve_nix_generation(
        &self,
        authorization: &crate::AuthorizedStorageResolutionV1,
        selected: &aos_sandbox_protocol::nix_generation::CanonicalNixGenerationPreparationV1,
        current_head: crate::CatalogBindingV1,
    ) -> Result<crate::ResolvedCatalogCommitmentV1, crate::StorageCatalogPreparationError> {
        let rejected = crate::StorageCatalogPreparationError::ResolutionRejected;
        if authorization.assignment() != self.policy.assignment()
            || authorization.sandbox_id() != *self.policy.assignment().sandbox().as_bytes()
            || authorization.operation() != selected.prepare().operation()
            || authorization.operation_id() != selected.prepare().operation_id()
            || authorization.preparation_commitment() != selected.argument_commitment().digest()
            || authorization.transport_request_digest().as_bytes() == &[0; 32]
            || authorization.plan_digest().as_bytes() == &[0; 32]
            || authorization.lease_digest().as_bytes() == &[0; 32]
            || authorization.expected_catalog_head() != current_head
            || authorization.inventory_binding() != self.inventory.binding()
            || current_head != self.inventory.catalog_head()
        {
            return Err(rejected);
        }
        let (plan, root, identity) = resolve_action_with_generation(
            &self.policy, &self.inventory, authorization.operation(),
            authorization.sandbox_id(), authorization.operation_id(),
            Some(selected.prefix().next_generation),
        ).map_err(|_| crate::StorageCatalogPreparationError::ResolutionRejected)?;
        let root = root.ok_or(crate::StorageCatalogPreparationError::ResolutionRejected)?;
        let identity = identity.ok_or(crate::StorageCatalogPreparationError::ResolutionRejected)?;
        let original = selected.origin();
        if root.commitment().as_bytes() != &original.root_policy_digest
            || identity.commitment().as_bytes() != &original.clone_identity_digest
            || identity.source_metadata_record_digest().as_bytes() != &original.metadata_digest
        {
            return Err(crate::StorageCatalogPreparationError::ResolutionMismatch);
        }
        let generation = current_head.generation().checked_add(1)
            .ok_or(crate::StorageCatalogPreparationError::ResolutionRejected)?;
        crate::ResolvedCatalogCommitmentV1::new_execution_v1(
            generation, self.policy.domains(), plan, Some(root), Some(identity),
        ).map_err(|_| crate::StorageCatalogPreparationError::ResolutionRejected)
    }
}

fn workspace_dataset<'a>(
    policy: &ProtectedStorageResolverPolicyV1,
    inventory: &'a ProtectedStorageInventoryV1,
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
    inventory: &'a ProtectedStorageInventoryV1,
    storage_handle: &[u8; 32],
    version_handle: &[u8; 32],
) -> Result<&'a super::inventory::ProtectedSnapshotInventoryV1, StorageCatalogResolverErrorV1> {
    let snapshot = inventory
        .snapshot(storage_handle, version_handle)
        .ok_or(StorageCatalogResolverErrorV1::UnknownHandle)?;
    workspace_dataset(policy, inventory, storage_handle)?;
    Ok(snapshot)
}

fn ensure_absent(
    inventory: &ProtectedStorageInventoryV1,
    name: &str,
) -> Result<(), StorageCatalogResolverErrorV1> {
    if inventory.name_is_occupied(name) {
        Err(StorageCatalogResolverErrorV1::StateConflict)
    } else {
        Ok(())
    }
}
