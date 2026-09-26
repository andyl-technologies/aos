//! Fresh-evidence activation of a validated workspace catalog.
//!
//! Structural validation remains insufficient for inventory or publication.
//! A private freshness capability from the terminated fixed observer and an
//! exact second composition consume the candidate. Only then may this module
//! materialize terminal authenticated rows. Each row is journaled atomically,
//! making a crash leave a resumable prefix rather than an advertised partial
//! inventory.

use aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse;
use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, decode_storage_resource_inventory_response};
use buffa::Message as _;

use super::{
    StorageWorkspaceCatalogError, StorageWorkspaceCatalogPlanV1,
    StorageWorkspaceCatalogRowPolicyV1, ValidatedPendingStorageWorkspaceCatalogV1,
};
use crate::broker::AuthenticatedWorkspaceCatalogPhysicalPlanV1;
use crate::observation_protocol::{
    WorkspaceCatalogObservationExpectationV1, WorkspaceCatalogObservationRequestV1,
};
use crate::pin_worker_runtime::FreshWorkspaceCatalogObservationV1;
use crate::workspace_pin::workspace_pin_path;

/// Owns structural custody and its first exact physical-observation request.
pub(crate) struct StorageWorkspaceCatalogActivationCandidateV1 {
    validated: ValidatedPendingStorageWorkspaceCatalogV1,
    physical_plan: AuthenticatedWorkspaceCatalogPhysicalPlanV1,
    request: WorkspaceCatalogObservationRequestV1,
}

/// Returns validated custody when pre-observation preparation fails.
pub(crate) struct StorageWorkspaceCatalogActivationPreparationFailureV1 {
    validated: ValidatedPendingStorageWorkspaceCatalogV1,
    error: StorageWorkspaceCatalogError,
}

impl StorageWorkspaceCatalogActivationPreparationFailureV1 {
    pub(crate) const fn error(&self) -> &StorageWorkspaceCatalogError {
        &self.error
    }

    pub(crate) fn into_validated(self) -> ValidatedPendingStorageWorkspaceCatalogV1 {
        self.validated
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ValidatedPendingStorageWorkspaceCatalogV1,
        StorageWorkspaceCatalogError,
    ) {
        (self.validated, self.error)
    }
}

/// Returns catalog custody when promotion failed before an ambiguous commit.
///
/// `validated` is `None` after a journal commit error because the durable
/// prefix may have advanced beyond the consumed in-memory projection. The
/// caller must reopen the journal instead of retrying that custody.
pub(crate) struct StorageWorkspaceCatalogActivationPromotionFailureV1 {
    validated: Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    error: StorageWorkspaceCatalogError,
}

impl StorageWorkspaceCatalogActivationPromotionFailureV1 {
    pub(crate) const fn error(&self) -> &StorageWorkspaceCatalogError {
        &self.error
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<ValidatedPendingStorageWorkspaceCatalogV1>,
        StorageWorkspaceCatalogError,
    ) {
        (self.validated, self.error)
    }
}

impl StorageWorkspaceCatalogActivationCandidateV1 {
    /// Consumes a structurally validated catalog only for a terminal plan.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError::InvalidCandidate`] for a
    /// non-terminal row policy or any physical-plan, target, proof, custody, or
    /// request/catalog binding mismatch. A headless catalog and an allowed
    /// durable prefix remain valid because activation materializes them only
    /// after fresh evidence is returned.
    pub(crate) fn new(
        validated: ValidatedPendingStorageWorkspaceCatalogV1,
        physical_plan: AuthenticatedWorkspaceCatalogPhysicalPlanV1,
        request: WorkspaceCatalogObservationRequestV1,
    ) -> Result<Self, StorageWorkspaceCatalogActivationPreparationFailureV1> {
        let validation = (|| {
            validate_physical_plan(&physical_plan, &request)?;
            validate_request_bindings(&validated, &request)?;
            validate_terminal_plan(&validated, &request)
        })();
        match validation {
            Ok(()) => Ok(Self {
                validated,
                physical_plan,
                request,
            }),
            Err(error) => {
                Err(StorageWorkspaceCatalogActivationPreparationFailureV1 { validated, error })
            }
        }
    }

    /// Borrows the exact request to send to the fixed observer.
    pub(crate) const fn request(&self) -> &WorkspaceCatalogObservationRequestV1 {
        &self.request
    }

    /// Recovers structural custody when observation cannot complete.
    pub(crate) fn into_validated(self) -> ValidatedPendingStorageWorkspaceCatalogV1 {
        self.validated
    }

    /// Consumes matching fresh evidence after an exact second composition.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError::InvalidCandidate`] when the
    /// transaction plan, physical request, retained workspace snapshot, host
    /// custody, or deadline changed before promotion. A materialization I/O
    /// failure consumes catalog custody because the durable prefix is ambiguous
    /// until the journal is reopened.
    pub(crate) fn activate(
        self,
        recomposed_plan: StorageWorkspaceCatalogPlanV1,
        recomposed_physical_plan: AuthenticatedWorkspaceCatalogPhysicalPlanV1,
        recomposed_request: WorkspaceCatalogObservationRequestV1,
        fresh: FreshWorkspaceCatalogObservationV1,
        now_boottime_nanoseconds: u64,
    ) -> Result<
        ActivatedStorageWorkspaceCatalogV1,
        StorageWorkspaceCatalogActivationPromotionFailureV1,
    > {
        let validation = (|| {
            if self.validated.plan() != &recomposed_plan
                || self.physical_plan != recomposed_physical_plan
                || self.request != recomposed_request
                || now_boottime_nanoseconds >= self.request.deadline_boottime_nanoseconds()
                || !fresh
                    .result()
                    .matches_request(&self.request)
                    .map_err(|_| StorageWorkspaceCatalogError::InvalidCandidate)?
            {
                return Err(StorageWorkspaceCatalogError::InvalidCandidate);
            }
            validate_physical_plan(&self.physical_plan, &self.request)?;
            validate_request_bindings(&self.validated, &self.request)?;
            validate_terminal_plan(&self.validated, &self.request)
        })();
        if let Err(error) = validation {
            return Err(StorageWorkspaceCatalogActivationPromotionFailureV1 {
                validated: Some(self.validated),
                error,
            });
        }

        let validated = match self.validated.materialize_terminal() {
            Ok(validated) => validated,
            Err(error) => {
                return Err(StorageWorkspaceCatalogActivationPromotionFailureV1 {
                    validated: None,
                    error,
                });
            }
        };
        if let Err(error) = validate_terminal_rows(&validated, &self.request) {
            return Err(StorageWorkspaceCatalogActivationPromotionFailureV1 {
                validated: Some(validated),
                error,
            });
        }
        let prepared_inventory = match prepare_inventory(&validated, &self.request) {
            Ok(inventory) => inventory,
            Err(error) => {
                return Err(StorageWorkspaceCatalogActivationPromotionFailureV1 {
                    validated: Some(validated),
                    error,
                });
            }
        };

        Ok(ActivatedStorageWorkspaceCatalogV1 {
            validated,
            prepared_inventory,
        })
    }
}

/// Temporarily grants inventory encoding from one freshly observed snapshot.
pub(crate) struct ActivatedStorageWorkspaceCatalogV1 {
    validated: ValidatedPendingStorageWorkspaceCatalogV1,
    prepared_inventory: Vec<u8>,
}

impl ActivatedStorageWorkspaceCatalogV1 {
    /// Returns prepared inventory and restores the validated typestate.
    ///
    /// This step is infallible: post-observation materialization, encoding, and
    /// ceiling validation completed during promotion after all freshness checks.
    pub(crate) fn into_inventory(self) -> (ValidatedPendingStorageWorkspaceCatalogV1, Vec<u8>) {
        (self.validated, self.prepared_inventory)
    }
}

fn validate_physical_plan(
    physical_plan: &AuthenticatedWorkspaceCatalogPhysicalPlanV1,
    request: &WorkspaceCatalogObservationRequestV1,
) -> Result<(), StorageWorkspaceCatalogError> {
    if physical_plan.roots() != request.roots()
        || physical_plan.allowed_objects() != request.allowed_objects()
        || physical_plan.targets() != request.targets()
    {
        return Err(StorageWorkspaceCatalogError::InvalidCandidate);
    }
    Ok(())
}

fn prepare_inventory(
    validated: &ValidatedPendingStorageWorkspaceCatalogV1,
    request: &WorkspaceCatalogObservationRequestV1,
) -> Result<Vec<u8>, StorageWorkspaceCatalogError> {
    let snapshot = validated.validate_current_snapshot()?;
    let custody = request.custody();
    let mut workspaces = Vec::new();
    for record in validated
        .records()
        .values()
        .filter(|record| record.is_active())
    {
        if record.kernel_boot_id != custody.kernel_boot_id() {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        workspaces.push(record.inventory_record()?);
    }
    let response = InventoryStorageResourcesResponse {
        kernel_boot_id: custody.kernel_boot_id().to_vec(),
        journal_sequence: snapshot.journal_sequence(),
        catalog_generation: snapshot
            .catalog_generation()
            .ok_or(StorageWorkspaceCatalogError::InvalidCandidate)?,
        workspaces,
        broker_instance_id: request.bindings().broker_instance_id().to_vec(),
        ..Default::default()
    };
    let bytes = response.encode_to_vec();
    decode_storage_resource_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| StorageWorkspaceCatalogError::InvalidInventory)?;
    Ok(bytes)
}

fn validate_request_bindings(
    validated: &ValidatedPendingStorageWorkspaceCatalogV1,
    request: &WorkspaceCatalogObservationRequestV1,
) -> Result<(), StorageWorkspaceCatalogError> {
    let plan = validated.plan();
    let snapshot = validated.validate_current_snapshot()?;
    let bindings = request.bindings();
    if bindings.transaction_sequence() != plan.transaction_sequence()
        || bindings.transaction_snapshot_digest() != plan.transaction_snapshot_digest()
        || bindings.logical_plan_digest() != plan.plan_digest()
        || bindings.physical_head() != plan.physical_head()
        || bindings.workspace_journal_sequence() != snapshot.journal_sequence()
        || bindings.workspace_snapshot_digest() != snapshot.digest()
        || bindings.workspace_catalog_generation() != snapshot.catalog_generation().unwrap_or(1)
        || bindings.identity_pool()
            != (
                snapshot.identity_pool().range_start(),
                snapshot.identity_pool().range_size(),
            )
    {
        return Err(StorageWorkspaceCatalogError::InvalidCandidate);
    }
    Ok(())
}

fn validate_terminal_plan(
    validated: &ValidatedPendingStorageWorkspaceCatalogV1,
    request: &WorkspaceCatalogObservationRequestV1,
) -> Result<(), StorageWorkspaceCatalogError> {
    if validated.plan().rows().len() != request.targets().len() {
        return Err(StorageWorkspaceCatalogError::InvalidCandidate);
    }

    for (row, target) in validated.plan().rows().iter().zip(request.targets()) {
        if row.workspace_handle() != target.workspace_handle()
            || row.dataset_guid() != target.dataset_guid()
            || row.creation_operation_id() != target.creation_operation_id()
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        match row.policy() {
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(publication) => {
                let WorkspaceCatalogObservationExpectationV1::Present {
                    mount_id,
                    root_device,
                    root_inode,
                } = target.expectation()
                else {
                    return Err(StorageWorkspaceCatalogError::InvalidCandidate);
                };
                let proof = &publication.pin_proof;
                if proof.kernel_boot_id() != request.custody().kernel_boot_id()
                    || proof.mount_namespace_device() != request.custody().mount_namespace_device()
                    || proof.mount_namespace_inode() != request.custody().mount_namespace_inode()
                    || proof.mount_id() != mount_id
                    || proof.mount_root() != "/"
                    || proof.mount_point() != workspace_pin_path(&row.workspace_handle())
                    || proof.filesystem_type() != "zfs"
                    || proof.superblock_source() != target.dataset_name()
                    || proof.dataset_guid() != target.dataset_guid()
                    || proof.root_device() != root_device
                    || proof.root_inode() != root_inode
                {
                    return Err(StorageWorkspaceCatalogError::InvalidCandidate);
                }
            }
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired { creation, .. } => {
                if target.expectation() != WorkspaceCatalogObservationExpectationV1::Absent
                    || creation.pin_proof.superblock_source() != target.dataset_name()
                {
                    return Err(StorageWorkspaceCatalogError::InvalidCandidate);
                }
            }
            StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent
            | StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(_) => {
                return Err(StorageWorkspaceCatalogError::InvalidCandidate);
            }
        }
    }

    Ok(())
}

fn validate_terminal_rows(
    validated: &ValidatedPendingStorageWorkspaceCatalogV1,
    request: &WorkspaceCatalogObservationRequestV1,
) -> Result<(), StorageWorkspaceCatalogError> {
    if !validated.is_initialized()
        || validated.plan().rows().len() != request.targets().len()
        || validated.records().len() != validated.plan().rows().len()
    {
        return Err(StorageWorkspaceCatalogError::InvalidCandidate);
    }

    for (row, target) in validated.plan().rows().iter().zip(request.targets()) {
        if row.workspace_handle() != target.workspace_handle()
            || row.dataset_guid() != target.dataset_guid()
            || row.creation_operation_id() != target.creation_operation_id()
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        let record = validated
            .records()
            .get(&row.workspace_handle())
            .ok_or(StorageWorkspaceCatalogError::InvalidCandidate)?;
        match row.policy() {
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(publication) => {
                let WorkspaceCatalogObservationExpectationV1::Present {
                    mount_id,
                    root_device,
                    root_inode,
                } = target.expectation()
                else {
                    return Err(StorageWorkspaceCatalogError::InvalidCandidate);
                };
                let proof = &publication.pin_proof;
                if !record.is_active()
                    || !record.matches_creation(publication)
                    || record.pin_proof != *proof
                    || proof.kernel_boot_id() != request.custody().kernel_boot_id()
                    || proof.mount_namespace_device() != request.custody().mount_namespace_device()
                    || proof.mount_namespace_inode() != request.custody().mount_namespace_inode()
                    || proof.mount_id() != mount_id
                    || proof.mount_root() != "/"
                    || proof.mount_point() != workspace_pin_path(&row.workspace_handle())
                    || proof.filesystem_type() != "zfs"
                    || proof.superblock_source() != target.dataset_name()
                    || proof.dataset_guid() != target.dataset_guid()
                    || proof.root_device() != root_device
                    || proof.root_inode() != root_inode
                    || record.root_device != root_device
                    || record.root_inode != root_inode
                    || record.kernel_boot_id != request.custody().kernel_boot_id()
                {
                    return Err(StorageWorkspaceCatalogError::InvalidCandidate);
                }
            }
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
                creation,
                retirement,
            } => {
                if target.expectation() != WorkspaceCatalogObservationExpectationV1::Absent
                    || !record.matches_creation(creation)
                    || record.pin_proof != creation.pin_proof
                    || !record.matches_retirement(retirement)
                    || creation.pin_proof.superblock_source() != target.dataset_name()
                {
                    return Err(StorageWorkspaceCatalogError::InvalidCandidate);
                }
            }
            StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent
            | StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(_) => {
                return Err(StorageWorkspaceCatalogError::InvalidCandidate);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;

    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, MediaType,
        ObjectDescriptor, ObjectDigest, PortableMediaType, SandboxId,
    };
    use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, MINIMUM_HOST_IDENTITY_RANGE};
    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::CatalogBindingV1;
    use crate::observation_protocol::{
        WorkspaceCatalogCustodyBindingV1, WorkspaceCatalogObservationBindingsV1,
        WorkspaceCatalogObservationObjectKindV1, WorkspaceCatalogObservationObjectV1,
        WorkspaceCatalogObservationRootV1, WorkspaceCatalogObservationTargetV1,
    };
    use crate::workspace_catalog::{
        PendingStorageWorkspaceCatalogV1, StorageIdentityPoolV1,
        StorageWorkspaceCatalogActivePrefixV1, StorageWorkspaceCatalogRowPlanV1,
        StorageWorkspacePublicationV1, StorageWorkspaceRetirementV1, WORKSPACE_JOURNAL_FILE,
    };
    use crate::workspace_pin::WorkspaceRootPinProofV1;

    const RANGE_SIZE: u32 = MINIMUM_HOST_IDENTITY_RANGE;

    fn plan(sequence: u64) -> StorageWorkspaceCatalogPlanV1 {
        plan_with_rows(sequence, Vec::new())
    }

    fn plan_with_rows(
        sequence: u64,
        rows: Vec<StorageWorkspaceCatalogRowPlanV1>,
    ) -> StorageWorkspaceCatalogPlanV1 {
        StorageWorkspaceCatalogPlanV1::new(
            sequence,
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            4,
            ObjectDigest::from_bytes([5; 32]),
            rows,
        )
        .unwrap()
    }

    fn binding(generation: u64, marker: u8) -> CatalogBindingV1 {
        CatalogBindingV1::from_publisher(generation, ObjectDigest::from_bytes([marker; 32]))
            .unwrap()
    }

    fn publication(marker: u8) -> StorageWorkspacePublicationV1 {
        let workspace_handle = [marker; 32];
        let dataset_guid = u64::from(marker) + 100;
        let dataset_name = format!("tank/aos/project/work-{marker}");
        let pin_proof = WorkspaceRootPinProofV1::new(
            [9; 16],
            10,
            11,
            u64::from(marker) + 20,
            "/".to_owned(),
            workspace_pin_path(&workspace_handle),
            "zfs".to_owned(),
            dataset_name,
            dataset_guid,
            u64::from(marker) + 30,
            u64::from(marker) + 40,
            crate::root_policy::WorkspaceRootPolicyV1::create_initialize().root_attributes(),
        )
        .unwrap();

        StorageWorkspacePublicationV1 {
            operation_id: [marker.wrapping_add(10); 16],
            request_catalog: binding(u64::from(marker) + 10, marker.wrapping_add(20)),
            result_catalog: binding(u64::from(marker) + 11, marker.wrapping_add(21)),
            result_digest: ObjectDigest::from_bytes([marker.wrapping_add(22); 32]),
            workspace_handle,
            dataset_guid,
            assignment: BrokerAssignment::new(
                SandboxId::from_bytes([marker; 16]),
                IncarnationId::from_bytes([marker.wrapping_add(1); 16]),
                AssignmentEpoch::new(u64::from(marker) + 1),
                DesiredGeneration::new(u64::from(marker) + 2),
                ObjectDigest::from_bytes([marker.wrapping_add(2); 32]),
            )
            .unwrap(),
            root_image: ObjectDescriptor::new(
                MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
                ObjectDigest::from_bytes([marker.wrapping_add(30); 32]),
                u64::from(marker) + 1,
            ),
            identity_range_start: u32::from(marker) * RANGE_SIZE,
            identity_range_size: RANGE_SIZE,
            pin_proof,
        }
    }

    fn retirement(marker: u8) -> StorageWorkspaceRetirementV1 {
        StorageWorkspaceRetirementV1 {
            operation_id: [marker.wrapping_add(100); 16],
            request_catalog: binding(u64::from(marker) + 30, marker.wrapping_add(40)),
            result_catalog: binding(u64::from(marker) + 31, marker.wrapping_add(41)),
            result_digest: ObjectDigest::from_bytes([marker.wrapping_add(42); 32]),
            workspace_handle: [marker; 32],
            dataset_guid: u64::from(marker) + 100,
        }
    }

    fn row(
        publication: &StorageWorkspacePublicationV1,
        policy: StorageWorkspaceCatalogRowPolicyV1,
    ) -> StorageWorkspaceCatalogRowPlanV1 {
        let prefix = StorageWorkspaceCatalogActivePrefixV1::new(
            [publication.workspace_handle[0].wrapping_add(1); 16],
            1,
            ObjectDigest::from_bytes([publication.workspace_handle[0].wrapping_add(100); 32]),
            publication.clone(),
        )
        .unwrap();
        StorageWorkspaceCatalogRowPlanV1::new(
            publication.workspace_handle,
            publication.dataset_guid,
            publication.operation_id,
            publication.identity_range_start,
            publication.identity_range_size,
            policy,
            vec![prefix],
        )
        .unwrap()
    }

    fn physical_rows(
        active: &StorageWorkspacePublicationV1,
        retired: &StorageWorkspacePublicationV1,
    ) -> (
        Vec<WorkspaceCatalogObservationRootV1>,
        Vec<WorkspaceCatalogObservationObjectV1>,
        Vec<WorkspaceCatalogObservationTargetV1>,
    ) {
        let roots =
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 500).unwrap()];
        let allowed_objects = vec![
            WorkspaceCatalogObservationObjectV1::new(
                0,
                active.pin_proof.superblock_source().to_owned(),
                WorkspaceCatalogObservationObjectKindV1::Filesystem,
                active.dataset_guid,
            )
            .unwrap(),
        ];
        let targets = vec![
            WorkspaceCatalogObservationTargetV1::new(
                active.workspace_handle,
                active.operation_id,
                0,
                active.pin_proof.superblock_source().to_owned(),
                active.dataset_guid,
                WorkspaceCatalogObservationExpectationV1::Present {
                    mount_id: active.pin_proof.mount_id(),
                    root_device: active.pin_proof.root_device(),
                    root_inode: active.pin_proof.root_inode(),
                },
            )
            .unwrap(),
            WorkspaceCatalogObservationTargetV1::new(
                retired.workspace_handle,
                retired.operation_id,
                0,
                retired.pin_proof.superblock_source().to_owned(),
                retired.dataset_guid,
                WorkspaceCatalogObservationExpectationV1::Absent,
            )
            .unwrap(),
        ];

        (roots, allowed_objects, targets)
    }

    fn validated_empty(directory: &TempDir) -> ValidatedPendingStorageWorkspaceCatalogV1 {
        let identity_pool = StorageIdentityPoolV1::new(65_536, 65_536).unwrap();
        PendingStorageWorkspaceCatalogV1::initialize_empty_for_test(
            directory.path(),
            identity_pool,
        )
        .unwrap();
        PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
            .unwrap()
            .validate_plan(plan(1))
            .unwrap()
    }

    fn observation_request(
        validated: &ValidatedPendingStorageWorkspaceCatalogV1,
        roots: Vec<WorkspaceCatalogObservationRootV1>,
        targets: Vec<WorkspaceCatalogObservationTargetV1>,
    ) -> WorkspaceCatalogObservationRequestV1 {
        observation_request_with_nonce(validated, [6; 32], roots, Vec::new(), targets)
    }

    fn observation_request_with_nonce(
        validated: &ValidatedPendingStorageWorkspaceCatalogV1,
        nonce: [u8; 32],
        roots: Vec<WorkspaceCatalogObservationRootV1>,
        allowed_objects: Vec<WorkspaceCatalogObservationObjectV1>,
        targets: Vec<WorkspaceCatalogObservationTargetV1>,
    ) -> WorkspaceCatalogObservationRequestV1 {
        let plan = validated.plan();
        let snapshot = validated.snapshot();
        let identity_pool = snapshot.identity_pool();
        WorkspaceCatalogObservationRequestV1::new(
            nonce,
            100,
            WorkspaceCatalogObservationBindingsV1::new(
                ObjectDigest::from_bytes([7; 32]),
                [8; 16],
                plan.transaction_sequence(),
                plan.transaction_snapshot_digest(),
                plan.plan_digest(),
                plan.physical_head().0,
                plan.physical_head().1,
                snapshot.journal_sequence(),
                snapshot.digest(),
                snapshot.catalog_generation().unwrap_or(1),
                identity_pool.range_start(),
                identity_pool.range_size(),
            )
            .unwrap(),
            WorkspaceCatalogCustodyBindingV1::new([9; 16], 10, 11, 12, 13, 14).unwrap(),
            roots,
            allowed_objects,
            targets,
        )
        .unwrap()
    }

    fn physical_empty() -> AuthenticatedWorkspaceCatalogPhysicalPlanV1 {
        AuthenticatedWorkspaceCatalogPhysicalPlanV1::new_for_test(
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn initialized_empty_activation_prepares_inventory_and_restores_custody() {
        let directory = TempDir::new().unwrap();
        let validated = validated_empty(&directory);
        let request = observation_request(&validated, Vec::new(), Vec::new());
        let digest = ObjectDigest::from_bytes([15; 32]);
        let result = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            &request, digest, digest, digest, digest,
        )
        .unwrap();
        let candidate =
            StorageWorkspaceCatalogActivationCandidateV1::new(validated, physical_empty(), request)
                .ok()
                .unwrap();
        let recomposed_request = observation_request(&candidate.validated, Vec::new(), Vec::new());
        let activated = candidate
            .activate(
                plan(1),
                physical_empty(),
                recomposed_request,
                FreshWorkspaceCatalogObservationV1::new_for_test(result),
                99,
            )
            .ok()
            .unwrap();
        let (validated, bytes) = activated.into_inventory();
        let inventory =
            decode_storage_resource_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES).unwrap();

        assert!(validated.is_terminally_materialized());
        assert!(inventory.workspaces().is_empty());
        assert_eq!(inventory.catalog_generation(), 1);
    }

    #[test]
    fn headless_empty_activation_materializes_generation_one_after_fresh_evidence() {
        let directory = TempDir::new().unwrap();
        let identity_pool = StorageIdentityPoolV1::new(65_536, 65_536).unwrap();
        let validated =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(plan(1))
                .unwrap();
        let request = observation_request(&validated, Vec::new(), Vec::new());
        let digest = ObjectDigest::from_bytes([15; 32]);
        let result = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            &request, digest, digest, digest, digest,
        )
        .unwrap();
        let candidate =
            StorageWorkspaceCatalogActivationCandidateV1::new(validated, physical_empty(), request)
                .ok()
                .unwrap();
        let recomposed_request = observation_request(&candidate.validated, Vec::new(), Vec::new());
        let activated = candidate
            .activate(
                plan(1),
                physical_empty(),
                recomposed_request,
                FreshWorkspaceCatalogObservationV1::new_for_test(result),
                99,
            )
            .ok()
            .unwrap();
        let (validated, bytes) = activated.into_inventory();
        let inventory =
            decode_storage_resource_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES).unwrap();

        assert!(validated.is_initialized());
        assert!(validated.is_terminally_materialized());
        assert_eq!(inventory.catalog_generation(), 1);
        assert!(inventory.workspaces().is_empty());
    }

    #[test]
    fn fresh_nonempty_activation_reproves_and_materializes_the_exact_terminal_plan() {
        let directory = TempDir::new().unwrap();
        let identity_pool = StorageIdentityPoolV1::new(RANGE_SIZE, RANGE_SIZE * 4).unwrap();
        let active = publication(1);
        let retired_creation = publication(2);
        let retired = retirement(2);
        let active_row = row(
            &active,
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(active.clone()),
        );

        // Retain an older durable active prefix. Final activation must still
        // include it in the fresh physical request while skipping its replay.
        let prefix =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(plan_with_rows(1, vec![active_row.clone()]))
                .unwrap()
                .materialize_terminal()
                .unwrap();
        let prefix_sequence = prefix.journal_sequence();
        assert_eq!(prefix.snapshot().catalog_generation(), Some(2));
        assert_eq!(
            prefix.records()[&active.workspace_handle].catalog_generation,
            2
        );
        drop(prefix);

        let retired_row = row(
            &retired_creation,
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
                creation: retired_creation.clone(),
                retirement: retired,
            },
        );
        let final_rows = vec![active_row, retired_row];
        let validated =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(plan_with_rows(2, final_rows.clone()))
                .unwrap();
        assert!(!validated.is_terminally_materialized());

        let (roots, allowed_objects, targets) = physical_rows(&active, &retired_creation);
        let request = observation_request_with_nonce(
            &validated,
            [6; 32],
            roots.clone(),
            allowed_objects.clone(),
            targets.clone(),
        );
        assert_eq!(request.targets().len(), 2);
        assert!(matches!(
            request.targets()[0].expectation(),
            WorkspaceCatalogObservationExpectationV1::Present { .. }
        ));
        assert_eq!(
            request.targets()[1].expectation(),
            WorkspaceCatalogObservationExpectationV1::Absent
        );
        let result = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            &request,
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
            ObjectDigest::from_bytes([16; 32]),
            ObjectDigest::from_bytes([15; 32]),
        )
        .unwrap();
        assert!(result.matches_request(&request).unwrap());

        let candidate = StorageWorkspaceCatalogActivationCandidateV1::new(
            validated,
            AuthenticatedWorkspaceCatalogPhysicalPlanV1::new_for_test(
                roots.clone(),
                allowed_objects.clone(),
                targets.clone(),
            ),
            request,
        )
        .ok()
        .unwrap();
        let recomposed_request = observation_request_with_nonce(
            &candidate.validated,
            [6; 32],
            roots.clone(),
            allowed_objects.clone(),
            targets.clone(),
        );
        let activated = candidate
            .activate(
                plan_with_rows(2, final_rows),
                AuthenticatedWorkspaceCatalogPhysicalPlanV1::new_for_test(
                    roots,
                    allowed_objects,
                    targets,
                ),
                recomposed_request,
                FreshWorkspaceCatalogObservationV1::new_for_test(result),
                99,
            )
            .ok()
            .unwrap();
        let (validated, bytes) = activated.into_inventory();
        let inventory =
            decode_storage_resource_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES).unwrap();

        assert!(validated.is_terminally_materialized());
        assert!(validated.journal_sequence() > prefix_sequence);
        assert_eq!(validated.snapshot().catalog_generation(), Some(3));
        assert_eq!(validated.records().len(), 2);
        assert_eq!(
            validated.records()[&active.workspace_handle].catalog_generation,
            2
        );
        assert_eq!(
            validated.records()[&retired_creation.workspace_handle].retirement_operation_id(),
            Some(retired.operation_id)
        );
        assert_eq!(inventory.catalog_generation(), 3);
        assert_eq!(inventory.workspaces().len(), 1);
        assert_eq!(
            inventory.workspaces()[0].workspace_handle(),
            &active.workspace_handle
        );
        assert_eq!(
            inventory.workspaces()[0].dataset_guid(),
            active.dataset_guid
        );
        assert_eq!(
            inventory.workspaces()[0].root_device(),
            active.pin_proof.root_device()
        );
        assert_eq!(
            inventory.workspaces()[0].root_inode(),
            active.pin_proof.root_inode()
        );
    }

    #[test]
    fn mismatched_fresh_observation_leaves_the_journal_exactly_unchanged() {
        let directory = TempDir::new().unwrap();
        let identity_pool = StorageIdentityPoolV1::new(RANGE_SIZE, RANGE_SIZE).unwrap();
        let validated =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(plan(1))
                .unwrap();
        let request =
            observation_request_with_nonce(&validated, [6; 32], Vec::new(), Vec::new(), Vec::new());
        let mismatched_request =
            observation_request_with_nonce(&validated, [7; 32], Vec::new(), Vec::new(), Vec::new());
        let mismatch = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            &mismatched_request,
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
            ObjectDigest::from_bytes([16; 32]),
            ObjectDigest::from_bytes([15; 32]),
        )
        .unwrap();
        let candidate =
            StorageWorkspaceCatalogActivationCandidateV1::new(validated, physical_empty(), request)
                .ok()
                .unwrap();
        let recomposed_request = observation_request_with_nonce(
            &candidate.validated,
            [6; 32],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let journal_path = directory.path().join(WORKSPACE_JOURNAL_FILE);
        let bytes_before = fs::read(&journal_path).unwrap();
        let hash_before: [u8; 32] = Sha256::digest(&bytes_before).into();

        let failure = candidate
            .activate(
                plan(1),
                physical_empty(),
                recomposed_request,
                FreshWorkspaceCatalogObservationV1::new_for_test(mismatch),
                99,
            )
            .err()
            .unwrap();
        let (validated, error) = failure.into_parts();
        let bytes_after = fs::read(&journal_path).unwrap();
        let hash_after: [u8; 32] = Sha256::digest(&bytes_after).into();

        assert!(validated.is_some());
        assert!(matches!(
            error,
            StorageWorkspaceCatalogError::InvalidCandidate
        ));
        assert_eq!(bytes_after, bytes_before);
        assert_eq!(hash_after, hash_before);
    }

    #[test]
    fn post_commit_failure_consumes_custody_and_reopen_recovers_the_prefix() {
        let directory = TempDir::new().unwrap();
        let identity_pool = StorageIdentityPoolV1::new(65_536, 65_536).unwrap();
        let mut validated =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(plan(1))
                .unwrap();
        validated.fail_after_next_materialization_commit_for_test();
        let request = observation_request(&validated, Vec::new(), Vec::new());
        let digest = ObjectDigest::from_bytes([15; 32]);
        let result = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            &request, digest, digest, digest, digest,
        )
        .unwrap();
        let candidate =
            StorageWorkspaceCatalogActivationCandidateV1::new(validated, physical_empty(), request)
                .ok()
                .unwrap();
        let recomposed_request = observation_request(&candidate.validated, Vec::new(), Vec::new());
        let failure = candidate
            .activate(
                plan(1),
                physical_empty(),
                recomposed_request,
                FreshWorkspaceCatalogObservationV1::new_for_test(result),
                99,
            )
            .err()
            .unwrap();
        let (validated, error) = failure.into_parts();

        assert!(validated.is_none());
        assert!(matches!(error, StorageWorkspaceCatalogError::Journal(_)));

        let reopened =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(plan(1))
                .unwrap();
        assert!(reopened.is_terminally_materialized());
        assert_eq!(reopened.snapshot().catalog_generation(), Some(1));
    }

    #[test]
    fn preparation_failure_returns_custody_on_physical_plan_substitution() {
        let directory = TempDir::new().unwrap();
        let validated = validated_empty(&directory);
        let roots =
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 16).unwrap()];
        let targets = vec![
            WorkspaceCatalogObservationTargetV1::new(
                [17; 32],
                [18; 16],
                0,
                "tank/aos/work".to_owned(),
                19,
                WorkspaceCatalogObservationExpectationV1::Absent,
            )
            .unwrap(),
        ];
        let substituted = observation_request(&validated, roots, targets);
        let snapshot = validated.snapshot();
        let failure = StorageWorkspaceCatalogActivationCandidateV1::new(
            validated,
            physical_empty(),
            substituted,
        )
        .err()
        .unwrap();
        let (validated, error) = failure.into_parts();

        assert!(matches!(
            error,
            StorageWorkspaceCatalogError::InvalidCandidate
        ));
        assert_eq!(validated.snapshot(), snapshot);
    }

    #[test]
    fn promotion_failure_returns_custody_on_fresh_recomposition_change() {
        let directory = TempDir::new().unwrap();
        let validated = validated_empty(&directory);
        let request = observation_request(&validated, Vec::new(), Vec::new());
        let digest = ObjectDigest::from_bytes([15; 32]);
        let result = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            &request, digest, digest, digest, digest,
        )
        .unwrap();
        let candidate =
            StorageWorkspaceCatalogActivationCandidateV1::new(validated, physical_empty(), request)
                .ok()
                .unwrap();
        let recomposed_request = observation_request(&candidate.validated, Vec::new(), Vec::new());
        let snapshot = candidate.validated.snapshot();
        let failure = candidate
            .activate(
                plan(2),
                physical_empty(),
                recomposed_request,
                FreshWorkspaceCatalogObservationV1::new_for_test(result),
                99,
            )
            .err()
            .unwrap();
        let (validated, error) = failure.into_parts();

        assert!(matches!(
            error,
            StorageWorkspaceCatalogError::InvalidCandidate
        ));
        assert_eq!(validated.unwrap().snapshot(), snapshot);
    }
}
