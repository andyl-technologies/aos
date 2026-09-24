//! Exact dedicated ZFS dataset facts for retained execution capture.
//!
//! The ordinary workspace catalog can observe a child whose `reservation`
//! and `refquota` both equal a protected capture allocation. This module
//! requires a deterministic, execution-specific child, its original create
//! operation and GUID, the exact domains, and an authenticated destroy
//! tombstone before logical output bytes may be released. It does not prove
//! that Host wrote only to this dataset, that pool checkpoints cannot consume
//! reservations, or that the configured allocation covers filesystem metadata.

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::VerifiedPhysicalCatalogSnapshotV1;
use crate::{
    CatalogBindingV1, ManagedDatasetRoot, PlannedDataset, ReservationPolicy, StorageDomainsV1,
    WorkspaceSpacePolicyV1,
};

pub(crate) mod readback;

const NAME_PREFIX: &str = "aos-output-";
const BINDING_DOMAIN: &[u8] = b"aos.sandbox.storage.execution-capture-dataset.v1\0";
const ATTEMPT_POLICY_DOMAIN: &[u8] = b"aos.sandbox.storage.execution-capture-attempt-policy.v1\0";
pub(crate) const MAX_CAPTURE_DATASET_NAME_BYTES: usize = 1024;

/// Rejects an absent, substituted, shared, or inadequately reserved dataset.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ExecutionCaptureDatasetErrorV1 {
    /// The claim, operation, capacity, or dataset path is invalid.
    #[error("execution capture dataset requirement is invalid")]
    InvalidRequirement,
    /// The verified physical catalog does not match the dedicated dataset.
    #[error("execution capture dataset is not physically verified")]
    NotVerified,
    /// The exact GUID and authorized delete operation have no later tombstone.
    #[error("execution capture dataset deletion is not verified")]
    DeletionNotVerified,
}

/// Fixes one execution's dedicated ZFS child and required space properties.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureDatasetRequirementV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    claim_digest: ObjectDigest,
    storage_create_operation: OperationId,
    root: ManagedDatasetRoot,
    domains: StorageDomainsV1,
    name: String,
    planned: PlannedDataset,
    space: WorkspaceSpacePolicyV1,
    admitted_bytes: u64,
    allocation_bytes: u64,
}

impl CaptureDatasetRequirementV1 {
    /// Constructs an execution-specific direct child with an explicit ZFS
    /// reservation and refquota at least as large as the admitted output.
    ///
    /// A trusted Storage policy must choose `allocation_bytes`, including
    /// measured metadata headroom. This constructor does not itself authorize
    /// that policy or the execution claim.
    ///
    /// # Errors
    ///
    /// Returns an error for zero capture, insufficient allocation, sentinel
    /// commitments, or a dataset name outside the managed root grammar.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        execution: ExecutionId,
        create_operation: OperationId,
        claim_digest: ObjectDigest,
        storage_create_operation: OperationId,
        root: ManagedDatasetRoot,
        domains: StorageDomainsV1,
        admitted_bytes: u64,
        allocation_bytes: u64,
    ) -> Result<Self, ExecutionCaptureDatasetErrorV1> {
        if execution.as_bytes() == &[0; 16]
            || create_operation.as_bytes() == &[0; 16]
            || storage_create_operation.as_bytes() == &[0; 16]
            || claim_digest.as_bytes() == &[0; 32]
            || admitted_bytes == 0
            || allocation_bytes < admitted_bytes
        {
            return Err(ExecutionCaptureDatasetErrorV1::InvalidRequirement);
        }
        let name = dataset_name(&root, execution);
        if name.len() > MAX_CAPTURE_DATASET_NAME_BYTES {
            return Err(ExecutionCaptureDatasetErrorV1::InvalidRequirement);
        }
        let planned = PlannedDataset::from_catalog(root.clone(), &name, domains)
            .map_err(|_| ExecutionCaptureDatasetErrorV1::InvalidRequirement)?;
        let space = WorkspaceSpacePolicyV1::new(
            allocation_bytes,
            ReservationPolicy::Exact(allocation_bytes),
        )
        .map_err(|_| ExecutionCaptureDatasetErrorV1::InvalidRequirement)?;
        Ok(Self {
            execution,
            create_operation,
            claim_digest,
            storage_create_operation,
            root,
            domains,
            name,
            planned,
            space,
            admitted_bytes,
            allocation_bytes,
        })
    }

    /// Returns the exact direct child the Storage create plan must select.
    pub(crate) const fn planned_dataset(&self) -> &PlannedDataset {
        &self.planned
    }

    pub(crate) const fn storage_create_operation(&self) -> OperationId {
        self.storage_create_operation
    }

    /// Returns the exact ZFS `refquota` and `reservation` policy.
    pub(crate) const fn space_policy(&self) -> WorkspaceSpacePolicyV1 {
        self.space
    }

    /// Commits every Storage-selected dataset and measured headroom input.
    pub(crate) fn attempt_policy_digest(
        &self,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(ATTEMPT_POLICY_DOMAIN);
        digest.update(self.execution.as_bytes());
        digest.update(self.create_operation.as_bytes());
        digest.update(self.claim_digest.as_bytes());
        digest.update(self.storage_create_operation.as_bytes());
        digest.update(self.root.guid().to_be_bytes());
        for name in [self.root.pool(), self.root.dataset_prefix(), &self.name] {
            digest.update((name.len() as u64).to_be_bytes());
            digest.update(name.as_bytes());
        }
        for domain in [
            self.domains.disclosure(),
            self.domains.encryption(),
            self.domains.accounting(),
            self.domains.retention(),
        ] {
            digest.update(domain.as_bytes());
        }
        digest.update(self.admitted_bytes.to_be_bytes());
        digest.update(self.allocation_bytes.to_be_bytes());
        digest.update(metadata_headroom_bytes.to_be_bytes());
        digest.update(minimum_remaining_bytes.to_be_bytes());
        ObjectDigest::from_bytes(digest.finalize().into())
    }

    /// Verifies one authenticated physical-catalog readback after create.
    pub(crate) fn verify_present(
        &self,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
    ) -> Result<VerifiedCaptureDatasetV1, ExecutionCaptureDatasetErrorV1> {
        let mut matches = catalog
            .datasets()
            .iter()
            .filter(|row| row.name() == self.name);
        let Some(dataset) = matches.next() else {
            return Err(ExecutionCaptureDatasetErrorV1::NotVerified);
        };
        let descendant_prefix = format!("{}/", self.name);
        let snapshot_prefix = format!("{}@", self.name);
        if dataset.root() != &self.root
            || matches.next().is_some()
            || dataset.domains() != self.domains
            || dataset.created_by() != Some(*self.storage_create_operation.as_bytes())
            || dataset.space() != Some((self.allocation_bytes, Some(self.allocation_bytes)))
            || dataset.aggregate().is_some()
            || dataset.origin().is_some()
            || catalog.occupied_names().iter().any(|name| {
                name.starts_with(descendant_prefix.as_str())
                    || name.starts_with(snapshot_prefix.as_str())
            })
        {
            return Err(ExecutionCaptureDatasetErrorV1::NotVerified);
        }
        let mut digest = Sha256::new();
        digest.update(BINDING_DOMAIN);
        digest.update(self.execution.as_bytes());
        digest.update(self.create_operation.as_bytes());
        digest.update(self.claim_digest.as_bytes());
        digest.update(self.storage_create_operation.as_bytes());
        digest.update(catalog.binding().generation().to_be_bytes());
        digest.update(catalog.binding().digest().as_bytes());
        digest.update(dataset.guid().to_be_bytes());
        digest.update(self.allocation_bytes.to_be_bytes());
        digest.update((self.name.len() as u64).to_be_bytes());
        digest.update(self.name.as_bytes());
        Ok(VerifiedCaptureDatasetV1 {
            requirement: self.clone(),
            catalog: catalog.binding(),
            guid: dataset.guid(),
            binding: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }
}

/// Carries an exact observed GUID and physical-catalog generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedCaptureDatasetV1 {
    requirement: CaptureDatasetRequirementV1,
    catalog: CatalogBindingV1,
    guid: u64,
    binding: ObjectDigest,
}

impl VerifiedCaptureDatasetV1 {
    pub(crate) const fn binding(&self) -> ObjectDigest {
        self.binding
    }

    pub(crate) fn dataset_name(&self) -> &str {
        &self.requirement.name
    }

    pub(crate) const fn guid(&self) -> u64 {
        self.guid
    }

    pub(crate) const fn catalog_generation(&self) -> u64 {
        self.catalog.generation()
    }

    pub(crate) fn matches_logical(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        claim_digest: [u8; 32],
        bytes: u64,
    ) -> bool {
        self.requirement.execution.as_bytes() == &execution
            && self.requirement.create_operation.as_bytes() == &create
            && self.requirement.claim_digest.as_bytes() == &claim_digest
            && self.requirement.admitted_bytes == bytes
    }

    /// Requires a later exact-GUID dataset tombstone attributed to Delete.
    pub(crate) fn verify_deleted(
        &self,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
        storage_delete_operation: OperationId,
    ) -> Result<VerifiedCaptureDeletionV1, ExecutionCaptureDatasetErrorV1> {
        verify_deleted_persisted(
            self.binding,
            &self.requirement.name,
            self.guid,
            self.catalog.generation(),
            catalog,
            storage_delete_operation,
        )
    }
}

/// Revalidates deletion from the MAC-protected binding after a cold restart.
pub(crate) fn verify_deleted_persisted(
    binding: ObjectDigest,
    name: &str,
    guid: u64,
    creation_generation: u64,
    catalog: &VerifiedPhysicalCatalogSnapshotV1,
    storage_delete_operation: OperationId,
) -> Result<VerifiedCaptureDeletionV1, ExecutionCaptureDatasetErrorV1> {
    if storage_delete_operation.as_bytes() == &[0; 16]
        || catalog.binding().generation() <= creation_generation
        || catalog.datasets().iter().any(|row| row.name() == name)
        || !catalog
            .dataset_tombstones()
            .iter()
            .any(|(retired_name, retired_guid, operation)| {
                retired_name == name
                    && *retired_guid == guid
                    && operation == storage_delete_operation.as_bytes()
            })
    {
        return Err(ExecutionCaptureDatasetErrorV1::DeletionNotVerified);
    }
    Ok(VerifiedCaptureDeletionV1 {
        dataset_binding: binding,
        storage_delete_operation,
        deletion_catalog: catalog.binding(),
    })
}

/// Carries authenticated Storage catalog evidence for exact physical deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedCaptureDeletionV1 {
    dataset_binding: ObjectDigest,
    storage_delete_operation: OperationId,
    deletion_catalog: CatalogBindingV1,
}

impl VerifiedCaptureDeletionV1 {
    pub(crate) const fn dataset_binding(&self) -> ObjectDigest {
        self.dataset_binding
    }

    pub(crate) const fn storage_delete_operation(&self) -> OperationId {
        self.storage_delete_operation
    }

    pub(crate) const fn catalog(&self) -> CatalogBindingV1 {
        self.deletion_catalog
    }
}

fn dataset_name(root: &ManagedDatasetRoot, execution: ExecutionId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = format!("{}/{}", root.dataset_prefix(), NAME_PREFIX);
    for byte in execution.as_bytes() {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::VerifiedPhysicalDatasetV1;
    use super::*;

    fn digest(value: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([value; 32])
    }

    pub(crate) fn fixture() -> (
        CaptureDatasetRequirementV1,
        VerifiedPhysicalCatalogSnapshotV1,
    ) {
        let root = ManagedDatasetRoot::from_catalog("pool", "pool/aos", 11).unwrap();
        let domains = StorageDomainsV1::new(digest(1), digest(2), digest(3), digest(4)).unwrap();
        let requirement = CaptureDatasetRequirementV1::new(
            ExecutionId::from_bytes([1; 16]),
            OperationId::from_bytes([2; 16]),
            digest(3),
            OperationId::from_bytes([4; 16]),
            root.clone(),
            domains,
            100,
            200,
        )
        .unwrap();
        let catalog = VerifiedPhysicalCatalogSnapshotV1 {
            binding: CatalogBindingV1::from_publisher(1, digest(8)).unwrap(),
            roots: vec![root.clone()],
            datasets: vec![VerifiedPhysicalDatasetV1 {
                name: requirement.name.clone(),
                guid: 17,
                root,
                domains,
                space: Some((200, Some(200))),
                aggregate: None,
                origin: None,
                created_by: Some([4; 16]),
            }],
            snapshots: Vec::new(),
            holds: Vec::new(),
            tombstones: Vec::new(),
            occupied_names: vec![requirement.name.clone()],
        };
        (requirement, catalog)
    }

    pub(crate) fn deleted_fixture(
        requirement: &CaptureDatasetRequirementV1,
        mut catalog: VerifiedPhysicalCatalogSnapshotV1,
        operation: u8,
    ) -> VerifiedPhysicalCatalogSnapshotV1 {
        catalog.datasets.clear();
        catalog.binding = CatalogBindingV1::from_publisher(2, digest(9)).unwrap();
        catalog
            .tombstones
            .push((requirement.name.clone(), 17, [operation; 16]));
        catalog
    }

    #[test]
    fn exact_dedicated_reservation_and_guid_deletion() {
        let (requirement, mut catalog) = fixture();
        assert_eq!(requirement.space_policy().refquota_bytes(), 200);
        assert_eq!(requirement.planned_dataset().name(), requirement.name);
        let present = requirement.verify_present(&catalog).unwrap();

        catalog.datasets[0].space = Some((200, None));
        assert_eq!(
            requirement.verify_present(&catalog).unwrap_err(),
            ExecutionCaptureDatasetErrorV1::NotVerified
        );
        catalog.datasets.clear();
        catalog.binding = CatalogBindingV1::from_publisher(2, digest(9)).unwrap();
        catalog
            .tombstones
            .push((requirement.name.clone(), 17, [7; 16]));
        assert_eq!(
            present
                .verify_deleted(&catalog, OperationId::from_bytes([8; 16]))
                .unwrap_err(),
            ExecutionCaptureDatasetErrorV1::DeletionNotVerified
        );
        let deletion = present
            .verify_deleted(&catalog, OperationId::from_bytes([7; 16]))
            .unwrap();
        assert_eq!(deletion.dataset_binding(), present.binding());
    }

    #[test]
    fn capture_requirement_rejects_insufficient_allocation() {
        let (mut requirement, _) = fixture();
        requirement.allocation_bytes = 99;
        assert!(matches!(
            CaptureDatasetRequirementV1::new(
                requirement.execution,
                requirement.create_operation,
                requirement.claim_digest,
                requirement.storage_create_operation,
                requirement.root,
                requirement.domains,
                100,
                99,
            ),
            Err(ExecutionCaptureDatasetErrorV1::InvalidRequirement)
        ));
    }
}
