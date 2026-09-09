//! Pure protected-policy resolver for every Storage catalog action.
//!
//! The resolver accepts only typed preparation semantics and a canonical
//! snapshot supplied by authenticated local state. It derives all backend
//! names, GUID associations, capacity choices, holds, and root policy without
//! accepting node-local identifiers from the request.

mod actions;
pub(crate) mod inventory;
pub(crate) mod policy;

use aos_sandbox_protocol::semantics::CatalogBindingV1;
use aos_sandbox_protocol::semantics::storage_prepare::StoragePreparationOperationV1;

use crate::{
    AuthorizedStorageResolutionV1, ProtectedStorageCatalogResolverV1, ResolvedCatalogCommitmentV1,
    StorageCatalogPreparationError,
};

use self::actions::resolve_action;
use self::inventory::{ProtectedStorageInventoryError, ProtectedStorageInventoryV2};
use self::policy::ProtectedStorageResolverPolicyV1;

/// Reports why protected state could not produce one closed catalog plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StorageCatalogResolverErrorV1 {
    /// Signed inventory or current-head association does not match protected state.
    #[error("Storage resolver binding is stale or mismatched")]
    BindingMismatch,
    /// A requested opaque handle is absent from protected inventory.
    #[error("Storage resolver handle is unknown")]
    UnknownHandle,
    /// Current physical state conflicts with the requested transition.
    #[error("Storage resolver state conflicts with the requested action")]
    StateConflict,
    /// Protected naming or capacity policy rejects the requested transition.
    #[error("Storage resolver policy rejected the requested action")]
    PolicyRejected,
    /// Admitted Prepare assignment or provenance does not match protected policy.
    #[error("Storage Prepare authorization does not match protected resolver policy")]
    AuthorizationMismatch,
    /// Protected inventory cannot authorize the requested root-policy decision.
    #[error("Storage resolver inventory lacks required authenticated metadata")]
    InventoryRejected,
    /// The next catalog generation cannot be represented.
    #[error("Storage resolver catalog generation is exhausted")]
    GenerationExhausted,
}

impl From<ProtectedStorageInventoryError> for StorageCatalogResolverErrorV1 {
    fn from(_: ProtectedStorageInventoryError) -> Self {
        Self::InventoryRejected
    }
}

/// Resolves all Storage actions from fixed protected policy and inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageCatalogResolverV1 {
    policy: ProtectedStorageResolverPolicyV1,
    inventory: ProtectedStorageInventoryV2,
}

impl StorageCatalogResolverV1 {
    pub(crate) fn new(
        policy: ProtectedStorageResolverPolicyV1,
        inventory: ProtectedStorageInventoryV2,
    ) -> Result<Self, StorageCatalogResolverErrorV1> {
        if policy.root() != inventory.root()
            || policy.domains() != inventory.domains()
            || inventory.dataset(&policy.project_ancestor().dataset().storage_handle())
                != Some(policy.project_ancestor().dataset())
        {
            return Err(StorageCatalogResolverErrorV1::PolicyRejected);
        }
        Ok(Self { policy, inventory })
    }

    fn resolve_operation(
        &self,
        operation: StoragePreparationOperationV1,
        sandbox_id: [u8; 16],
        operation_id: [u8; 16],
        inventory_binding: CatalogBindingV1,
        current_head: CatalogBindingV1,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageCatalogResolverErrorV1> {
        if inventory_binding != self.inventory.binding()
            || current_head != self.inventory.catalog_head()
        {
            return Err(StorageCatalogResolverErrorV1::BindingMismatch);
        }
        let generation = current_head
            .generation()
            .checked_add(1)
            .ok_or(StorageCatalogResolverErrorV1::GenerationExhausted)?;
        let (plan, root_policy) = resolve_action(
            &self.policy,
            &self.inventory,
            operation,
            sandbox_id,
            operation_id,
        )?;
        ResolvedCatalogCommitmentV1::new_execution_v3(
            generation,
            self.policy.domains(),
            plan,
            root_policy,
        )
        .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)
    }

    pub(crate) const fn inventory(&self) -> &ProtectedStorageInventoryV2 {
        &self.inventory
    }

    fn resolve_authorized(
        &self,
        authorization: &AuthorizedStorageResolutionV1,
        current_head: CatalogBindingV1,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageCatalogResolverErrorV1> {
        if authorization.assignment() != self.policy.assignment()
            || authorization.sandbox_id() != *self.policy.assignment().sandbox().as_bytes()
            || authorization.preparation_commitment().as_bytes() == &[0; 32]
            || authorization.transport_request_digest().as_bytes() == &[0; 32]
            || authorization.plan_digest().as_bytes() == &[0; 32]
            || authorization.lease_digest().as_bytes() == &[0; 32]
            || authorization.expected_catalog_head() != current_head
        {
            return Err(StorageCatalogResolverErrorV1::AuthorizationMismatch);
        }

        self.resolve_operation(
            authorization.operation(),
            authorization.sandbox_id(),
            authorization.operation_id(),
            authorization.inventory_binding(),
            current_head,
        )
    }
}

impl ProtectedStorageCatalogResolverV1 for StorageCatalogResolverV1 {
    fn resolve(
        &self,
        authorization: &AuthorizedStorageResolutionV1,
        current_head: CatalogBindingV1,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageCatalogPreparationError> {
        self.resolve_authorized(authorization, current_head)
            .map_err(|_| StorageCatalogPreparationError::ResolutionRejected)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, ObjectDigest,
        SandboxId,
    };

    use super::inventory::{
        AuthenticatedSnapshotRootMetadataV1, CheckedSnapshotRootMetadataRecordV1,
        ProtectedSnapshotInventoryV2,
    };
    use super::*;
    use crate::root_policy::PortableRootAttributesV1;
    use crate::{
        ActiveHoldEvidence, CatalogPlanV1, HoldId, ManagedDatasetRoot, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, ResolvedSnapshot, StorageDomainsV1,
    };

    struct Fixture {
        resolver: StorageCatalogResolverV1,
        workspace: ResolvedDataset,
        empty_workspace: ResolvedDataset,
        held_snapshot: ResolvedSnapshot,
        unheld_snapshot: ResolvedSnapshot,
        clone_source: ResolvedSnapshot,
        hold_id: HoldId,
    }

    fn assignment(incarnation: u8, epoch: u64) -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([incarnation; 16]),
            AssignmentEpoch::new(epoch),
            DesiredGeneration::new(6),
            ObjectDigest::from_bytes([7; 32]),
        )
        .unwrap()
    }

    fn domains() -> StorageDomainsV1 {
        StorageDomainsV1::new(
            ObjectDigest::from_bytes([11; 32]),
            ObjectDigest::from_bytes([12; 32]),
            ObjectDigest::from_bytes([13; 32]),
            ObjectDigest::from_bytes([14; 32]),
        )
        .unwrap()
    }

    fn fixture(
        authenticated_clone: bool,
        catalog_generation: u64,
        tombstones: Vec<String>,
    ) -> Fixture {
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 20).unwrap();
        let ancestor = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project",
            21,
            [22; 32],
            domains(),
        )
        .unwrap();
        let workspace = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/workspace-existing",
            23,
            [24; 32],
            domains(),
        )
        .unwrap();
        let empty_workspace = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/workspace-empty",
            25,
            [26; 32],
            domains(),
        )
        .unwrap();
        let archive = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/archive/source",
            27,
            [28; 32],
            domains(),
        )
        .unwrap();
        let held_snapshot =
            ResolvedSnapshot::from_catalog(workspace.clone(), "held", 29, [30; 32]).unwrap();
        let unheld_snapshot =
            ResolvedSnapshot::from_catalog(workspace.clone(), "unheld", 31, [32; 32]).unwrap();
        let clone_source =
            ResolvedSnapshot::from_catalog(archive.clone(), "source", 33, [34; 32]).unwrap();
        let checked_metadata = CheckedSnapshotRootMetadataRecordV1::new(
            clone_source.guid(),
            archive.guid(),
            PortableRootAttributesV1::new(501, 20, 0o6750).unwrap(),
            archive.storage_handle(),
            clone_source.version_handle(),
            ObjectDigest::from_bytes([35; 32]),
        )
        .unwrap();
        let authenticated_metadata = AuthenticatedSnapshotRootMetadataV1::authenticate_for_test(
            &checked_metadata.canonical_bytes(),
            checked_metadata.record_digest(),
        )
        .unwrap();
        let clone_row = if authenticated_clone {
            ProtectedSnapshotInventoryV2::authenticated_for_test(
                clone_source.clone(),
                checked_metadata.content_commitment(),
                authenticated_metadata,
            )
            .unwrap()
        } else {
            ProtectedSnapshotInventoryV2::legacy(clone_source.clone())
        };
        let hold_id = HoldId::from_bytes([36; 16]).unwrap();
        let head = CatalogBindingV1::from_publisher(
            catalog_generation,
            ObjectDigest::from_bytes([37; 32]),
        )
        .unwrap();
        let policy = ProtectedStorageResolverPolicyV1::new(
            assignment(2, 4),
            root.clone(),
            domains(),
            ProjectAncestorPolicyV1::new(ancestor.clone(), 1 << 30, 64, 128).unwrap(),
            1 << 28,
            1 << 26,
        )
        .unwrap();
        let inventory = ProtectedStorageInventoryV2::from_authenticated_rows_for_test(
            40,
            head,
            root,
            domains(),
            vec![
                ancestor,
                workspace.clone(),
                empty_workspace.clone(),
                archive,
            ],
            vec![
                ProtectedSnapshotInventoryV2::legacy(held_snapshot.clone()),
                ProtectedSnapshotInventoryV2::legacy(unheld_snapshot.clone()),
                clone_row,
            ],
            vec![
                ActiveHoldEvidence::from_catalog(held_snapshot.guid(), hold_id).unwrap(),
                ActiveHoldEvidence::from_catalog(clone_source.guid(), hold_id).unwrap(),
            ],
            tombstones,
        )
        .unwrap();
        let resolver = StorageCatalogResolverV1::new(policy, inventory).unwrap();
        Fixture {
            resolver,
            workspace,
            empty_workspace,
            held_snapshot,
            unheld_snapshot,
            clone_source,
            hold_id,
        }
    }

    fn resolve(
        fixture: &Fixture,
        operation: StoragePreparationOperationV1,
        sandbox_id: [u8; 16],
        operation_id: [u8; 16],
    ) -> Result<ResolvedCatalogCommitmentV1, StorageCatalogResolverErrorV1> {
        fixture.resolver.resolve_operation(
            operation,
            sandbox_id,
            operation_id,
            fixture.resolver.inventory().binding(),
            fixture.resolver.inventory().catalog_head(),
        )
    }

    #[test]
    fn every_storage_action_resolves_to_one_closed_execution_catalog() {
        let fixture = fixture(true, 50, Vec::new());
        let create = resolve(
            &fixture,
            StoragePreparationOperationV1::CreateWorkspace {
                quota_bytes: 1 << 29,
                reservation_bytes: 1 << 27,
            },
            [90; 16],
            [91; 16],
        )
        .unwrap();
        let CatalogPlanV1::CreateWorkspace {
            destination, space, ..
        } = create.plan()
        else {
            panic!("Create resolved to another action")
        };
        assert_eq!(
            destination.name(),
            "tank/aos/project/workspace-5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        );
        assert_eq!(space.refquota_bytes(), 1 << 28);
        assert_eq!(space.reservation(), ReservationPolicy::Exact(1 << 26));
        assert!(create.root_policy().unwrap().is_create_initialize());

        let snapshot = resolve(
            &fixture,
            StoragePreparationOperationV1::Snapshot {
                storage_handle: fixture.workspace.storage_handle(),
            },
            [1; 16],
            [92; 16],
        )
        .unwrap();
        assert!(matches!(snapshot.plan(), CatalogPlanV1::Snapshot { .. }));
        assert!(snapshot.root_policy().is_none());

        let hold = resolve(
            &fixture,
            StoragePreparationOperationV1::HoldSnapshot {
                storage_handle: fixture.workspace.storage_handle(),
                version_handle: fixture.unheld_snapshot.version_handle(),
                hold_id: [93; 16],
            },
            [1; 16],
            [94; 16],
        )
        .unwrap();
        assert!(matches!(hold.plan(), CatalogPlanV1::HoldSnapshot { .. }));

        let release = resolve(
            &fixture,
            StoragePreparationOperationV1::ReleaseHold {
                storage_handle: fixture.workspace.storage_handle(),
                version_handle: fixture.held_snapshot.version_handle(),
                hold_id: fixture.hold_id.as_bytes(),
            },
            [1; 16],
            [95; 16],
        )
        .unwrap();
        assert!(matches!(release.plan(), CatalogPlanV1::ReleaseHold { .. }));

        let clone = resolve(
            &fixture,
            StoragePreparationOperationV1::Clone {
                storage_handle: fixture.clone_source.dataset().storage_handle(),
                version_handle: fixture.clone_source.version_handle(),
                hold_id: fixture.hold_id.as_bytes(),
                quota_bytes: 4096,
                reservation_bytes: 1024,
            },
            [96; 16],
            [97; 16],
        )
        .unwrap();
        assert!(matches!(clone.plan(), CatalogPlanV1::Clone { .. }));
        let clone_policy = clone.root_policy().unwrap();
        assert_eq!(
            clone_policy.source_snapshot_guid(),
            Some(fixture.clone_source.guid())
        );
        assert_eq!(clone_policy.root_attributes().mode(), 0o6750);

        let quota = resolve(
            &fixture,
            StoragePreparationOperationV1::SetQuota {
                storage_handle: fixture.workspace.storage_handle(),
                quota_bytes: 8192,
                reservation_bytes: 2048,
            },
            [1; 16],
            [98; 16],
        )
        .unwrap();
        assert!(matches!(quota.plan(), CatalogPlanV1::SetQuota { .. }));

        let destroy_snapshot = resolve(
            &fixture,
            StoragePreparationOperationV1::Destroy {
                storage_handle: fixture.workspace.storage_handle(),
                version_handle: Some(fixture.unheld_snapshot.version_handle()),
            },
            [1; 16],
            [99; 16],
        )
        .unwrap();
        assert!(matches!(
            destroy_snapshot.plan(),
            CatalogPlanV1::DestroySnapshot { .. }
        ));

        let destroy_dataset = resolve(
            &fixture,
            StoragePreparationOperationV1::Destroy {
                storage_handle: fixture.empty_workspace.storage_handle(),
                version_handle: None,
            },
            [1; 16],
            [100; 16],
        )
        .unwrap();
        assert!(matches!(
            destroy_dataset.plan(),
            CatalogPlanV1::DestroyDataset { .. }
        ));

        for catalog in [
            create,
            snapshot,
            hold,
            release,
            clone,
            quota,
            destroy_snapshot,
            destroy_dataset,
        ] {
            assert_eq!(catalog.format_version(), 3);
            assert_eq!(catalog.generation(), 51);
            assert_eq!(
                catalog.execution_binding().unwrap().catalog(),
                catalog.binding()
            );
        }
    }

    #[test]
    fn clone_requires_authenticated_exact_source_metadata() {
        let legacy = fixture(false, 50, Vec::new());
        let operation = StoragePreparationOperationV1::Clone {
            storage_handle: legacy.clone_source.dataset().storage_handle(),
            version_handle: legacy.clone_source.version_handle(),
            hold_id: legacy.hold_id.as_bytes(),
            quota_bytes: 4096,
            reservation_bytes: 0,
        };
        assert_eq!(
            resolve(&legacy, operation, [96; 16], [97; 16]),
            Err(StorageCatalogResolverErrorV1::InventoryRejected)
        );

        let attributes = PortableRootAttributesV1::new(501, 20, 0o6750).unwrap();
        let metadata = CheckedSnapshotRootMetadataRecordV1::new(
            33,
            27,
            attributes,
            [28; 32],
            [34; 32],
            ObjectDigest::from_bytes([35; 32]),
        )
        .unwrap();
        let mut bytes = metadata.canonical_bytes();
        bytes[20] ^= 1;
        assert_eq!(
            AuthenticatedSnapshotRootMetadataV1::authenticate_for_test(
                &bytes,
                metadata.record_digest(),
            ),
            Err(ProtectedStorageInventoryError::RootMetadataAuthentication)
        );
    }

    #[test]
    fn resolver_rejects_occupied_names_held_objects_and_exhausted_heads() {
        let occupied_name =
            "tank/aos/project/workspace-5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a".to_owned();
        let occupied = fixture(true, 50, vec![occupied_name]);
        assert_eq!(
            resolve(
                &occupied,
                StoragePreparationOperationV1::CreateWorkspace {
                    quota_bytes: 4096,
                    reservation_bytes: 0,
                },
                [90; 16],
                [91; 16],
            ),
            Err(StorageCatalogResolverErrorV1::StateConflict)
        );
        assert_eq!(
            resolve(
                &occupied,
                StoragePreparationOperationV1::Destroy {
                    storage_handle: occupied.workspace.storage_handle(),
                    version_handle: Some(occupied.held_snapshot.version_handle()),
                },
                [1; 16],
                [92; 16],
            ),
            Err(StorageCatalogResolverErrorV1::StateConflict)
        );

        let exhausted = fixture(true, u64::MAX, Vec::new());
        assert_eq!(
            resolve(
                &exhausted,
                StoragePreparationOperationV1::SetQuota {
                    storage_handle: exhausted.workspace.storage_handle(),
                    quota_bytes: 4096,
                    reservation_bytes: 0,
                },
                [1; 16],
                [93; 16],
            ),
            Err(StorageCatalogResolverErrorV1::GenerationExhausted)
        );
    }

    #[test]
    fn policy_assignment_distinguishes_incarnation_and_epoch_for_one_sandbox() {
        let fixture = fixture(true, 50, Vec::new());

        assert_eq!(fixture.resolver.policy.assignment(), assignment(2, 4));
        assert_ne!(fixture.resolver.policy.assignment(), assignment(3, 4));
        assert_ne!(fixture.resolver.policy.assignment(), assignment(2, 5));
    }
}
