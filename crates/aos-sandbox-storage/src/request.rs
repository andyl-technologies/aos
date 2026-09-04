//! Node-local resolved-catalog adapter for portable storage semantics.
//!
//! The portable compiler lives in [`aos_sandbox_protocol::semantics::storage`].
//! This module adds only the protected-node check that request handles and
//! quota select exact locally resolved catalog objects and policy.

use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};

use crate::catalog::{CatalogPlanV1, ResolvedCatalogCommitmentV1};

pub use aos_sandbox_protocol::semantics::storage::{
    CanonicalStorageSemanticsV1, CatalogBindingV1, StorageOperation, StorageSemanticsError,
};

/// Reports failure to compile portable semantics or match local resolution.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageRequestError {
    /// Portable hostile-input validation or canonicalization failed.
    #[error(transparent)]
    Semantics(#[from] StorageSemanticsError),
    /// The locally resolved plan names another action, quota, or handle.
    #[error("resolved storage catalog plan does not match the portable operation")]
    CatalogPlanMismatch,
}

/// Compiles portable semantics and verifies their exact node-local resolution.
///
/// The returned value is exactly the shared protocol semantic type. No backend
/// name or GUID is copied into its portable canonical bytes.
///
/// # Errors
///
/// Returns [`StorageRequestError::Semantics`] for portable validation failure,
/// or [`StorageRequestError::CatalogPlanMismatch`] when the resolved action,
/// quota, storage handle, or version handle differs.
pub fn decode_resolved(
    bytes: &[u8],
    catalog: &ResolvedCatalogCommitmentV1,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<CanonicalStorageSemanticsV1, StorageRequestError> {
    let semantics = CanonicalStorageSemanticsV1::decode(
        bytes,
        catalog.binding(),
        peer,
        policy,
        now_boottime_nanoseconds,
    )?;
    validate_catalog_plan(semantics.operation(), catalog.plan())?;
    Ok(semantics)
}

fn validate_catalog_plan(
    operation: StorageOperation,
    plan: &CatalogPlanV1,
) -> Result<(), StorageRequestError> {
    let matches = match (operation, plan) {
        (
            StorageOperation::CreateWorkspace { quota_bytes },
            CatalogPlanV1::CreateWorkspace { space, .. },
        ) => quota_bytes == space.refquota_bytes(),
        (StorageOperation::Snapshot { storage_handle }, CatalogPlanV1::Snapshot { source, .. }) => {
            storage_handle == source.storage_handle()
        }
        (
            StorageOperation::HoldSnapshot {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::HoldSnapshot { snapshot, .. },
        )
        | (
            StorageOperation::ReleaseHold {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::ReleaseHold { snapshot, .. },
        ) => {
            storage_handle == snapshot.dataset().storage_handle()
                && version_handle == snapshot.version_handle()
        }
        (
            StorageOperation::Clone {
                storage_handle,
                version_handle,
                quota_bytes,
            },
            CatalogPlanV1::Clone { source, space, .. },
        ) => {
            storage_handle == source.dataset().storage_handle()
                && version_handle == source.version_handle()
                && quota_bytes == space.refquota_bytes()
        }
        (
            StorageOperation::SetQuota {
                storage_handle,
                quota_bytes,
            },
            CatalogPlanV1::SetQuota { dataset, space, .. },
        ) => storage_handle == dataset.storage_handle() && quota_bytes == space.refquota_bytes(),
        (
            StorageOperation::Destroy {
                storage_handle,
                version_handle: None,
            },
            CatalogPlanV1::DestroyDataset { dataset },
        ) => storage_handle == dataset.storage_handle(),
        (
            StorageOperation::Destroy {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::DestroySnapshot { snapshot },
        ) => {
            storage_handle == snapshot.dataset().storage_handle()
                && version_handle == Some(snapshot.version_handle())
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(StorageRequestError::CatalogPlanMismatch)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{ApplyStorageRequest, Audience, StorageAction};
    use aos_sandbox_core::ObjectDigest;
    use buffa::Message as _;

    use super::*;
    use crate::{
        ManagedDatasetRoot, ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset,
        StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }
    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn request() -> ApplyStorageRequest {
        let mut request = ApplyStorageRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 101;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
        request.action = StorageAction::STORAGE_ACTION_SET_QUOTA.into();
        request.operation_id = vec![7; 16];
        request.storage_handle = vec![8; 32];
        request.quota_bytes = 4096;
        request
    }

    fn catalog() -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [9; 32], domains)
                .unwrap();
        let dataset =
            ResolvedDataset::from_catalog(root, "tank/aos/project/work", 11, [8; 32], domains)
                .unwrap();
        ResolvedCatalogCommitmentV1::new(
            9,
            domains,
            CatalogPlanV1::SetQuota {
                dataset,
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1)).unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap(),
            },
        )
        .unwrap()
    }

    #[test]
    fn shared_and_resolved_paths_are_byte_exactly_equivalent() {
        let request = request();
        let catalog = catalog();
        let portable =
            aos_sandbox_protocol::semantics::storage::CanonicalStorageSemanticsV1::decode(
                &request.encode_to_vec(),
                catalog.binding(),
                peer(),
                policy(),
                100,
            )
            .unwrap();
        let resolved =
            decode_resolved(&request.encode_to_vec(), &catalog, peer(), policy(), 100).unwrap();
        assert_eq!(resolved, portable);
        assert_eq!(resolved.canonical_bytes(), portable.canonical_bytes());
        assert_eq!(
            resolved.argument_commitment(),
            portable.argument_commitment()
        );
    }

    #[test]
    fn resolved_path_rejects_handle_substitution() {
        let mut request = request();
        let catalog = catalog();
        request.storage_handle = vec![10; 32];
        assert_eq!(
            decode_resolved(&request.encode_to_vec(), &catalog, peer(), policy(), 100),
            Err(StorageRequestError::CatalogPlanMismatch)
        );
    }
}
