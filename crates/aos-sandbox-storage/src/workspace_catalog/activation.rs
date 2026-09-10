//! Consuming terminal-only activation of a validated workspace catalog.
//!
//! Structural validation remains insufficient for inventory. This module
//! accepts only an initialized catalog whose durable rows already equal their
//! final authenticated active or retired state. A private freshness capability
//! from the terminated fixed observer and an exact second composition consume
//! the candidate. The resulting catalog exposes inventory encoding only; it
//! has no allocation, publication, retirement, or convergence methods.

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
    prepared_inventory: Vec<u8>,
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

/// Returns the complete candidate when final promotion fails.
pub(crate) struct StorageWorkspaceCatalogActivationPromotionFailureV1 {
    candidate: StorageWorkspaceCatalogActivationCandidateV1,
    error: StorageWorkspaceCatalogError,
}

impl StorageWorkspaceCatalogActivationPromotionFailureV1 {
    pub(crate) const fn error(&self) -> &StorageWorkspaceCatalogError {
        &self.error
    }

    pub(crate) fn into_candidate(self) -> StorageWorkspaceCatalogActivationCandidateV1 {
        self.candidate
    }

    pub(crate) fn into_validated(self) -> ValidatedPendingStorageWorkspaceCatalogV1 {
        self.candidate.validated
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ValidatedPendingStorageWorkspaceCatalogV1,
        StorageWorkspaceCatalogError,
    ) {
        (self.candidate.validated, self.error)
    }
}

impl StorageWorkspaceCatalogActivationCandidateV1 {
    /// Consumes a structurally validated catalog only when every row is terminal.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError::InvalidCandidate`] for a
    /// headless catalog, a non-terminal row policy, an older allowed active
    /// prefix, or any request/catalog binding mismatch.
    pub(crate) fn new(
        validated: ValidatedPendingStorageWorkspaceCatalogV1,
        physical_plan: AuthenticatedWorkspaceCatalogPhysicalPlanV1,
        request: WorkspaceCatalogObservationRequestV1,
    ) -> Result<Self, StorageWorkspaceCatalogActivationPreparationFailureV1> {
        let prepared = (|| {
            validate_physical_plan(&physical_plan, &request)?;
            validate_request_bindings(&validated, &request)?;
            validate_terminal_rows(&validated, &request)?;
            prepare_inventory(&validated, &request)
        })();
        match prepared {
            Ok(prepared_inventory) => Ok(Self {
                validated,
                physical_plan,
                request,
                prepared_inventory,
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
    /// custody, or deadline changed before promotion.
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
            validate_request_bindings(&self.validated, &self.request)
        })();
        match validation {
            Ok(()) => Ok(ActivatedStorageWorkspaceCatalogV1 {
                validated: self.validated,
                prepared_inventory: self.prepared_inventory,
            }),
            Err(error) => Err(StorageWorkspaceCatalogActivationPromotionFailureV1 {
                candidate: self,
                error,
            }),
        }
    }
}

/// Temporarily grants inventory encoding from one freshly observed snapshot.
pub(crate) struct ActivatedStorageWorkspaceCatalogV1 {
    validated: ValidatedPendingStorageWorkspaceCatalogV1,
    prepared_inventory: Vec<u8>,
}

impl ActivatedStorageWorkspaceCatalogV1 {
    /// Encodes inventory and restores the non-authorizing validated typestate.
    ///
    /// This step is infallible: allocation, traversal, encoding, and ceiling
    /// validation completed before the observer was launched, while the final
    /// freshness checks completed during promotion.
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
        || Some(bindings.workspace_catalog_generation()) != snapshot.catalog_generation()
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

    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES;
    use tempfile::TempDir;

    use super::*;
    use crate::observation_protocol::{
        WorkspaceCatalogCustodyBindingV1, WorkspaceCatalogObservationBindingsV1,
        WorkspaceCatalogObservationRootV1, WorkspaceCatalogObservationTargetV1,
    };
    use crate::workspace_catalog::{PendingStorageWorkspaceCatalogV1, StorageIdentityPoolV1};

    fn plan(sequence: u64) -> StorageWorkspaceCatalogPlanV1 {
        StorageWorkspaceCatalogPlanV1::new(
            sequence,
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            4,
            ObjectDigest::from_bytes([5; 32]),
            Vec::new(),
        )
        .unwrap()
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
        let plan = validated.plan();
        let snapshot = validated.snapshot();
        let identity_pool = snapshot.identity_pool();
        WorkspaceCatalogObservationRequestV1::new(
            [6; 32],
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
                snapshot.catalog_generation().unwrap(),
                identity_pool.range_start(),
                identity_pool.range_size(),
            )
            .unwrap(),
            WorkspaceCatalogCustodyBindingV1::new([9; 16], 10, 11, 12, 13, 14).unwrap(),
            roots,
            Vec::new(),
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
        assert_eq!(validated.snapshot(), snapshot);
    }
}
