//! Shares unchanged lifecycle progress transaction identities with Runtime.

use aos_sandbox_model::{ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

/// Derives the canonical transaction identity from the actual predecessor.
#[doc(hidden)]
#[must_use]
pub fn lifecycle_plan_binding_transaction_id_v1(
    operation: OperationId,
    current_record: ObjectDigest,
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-binding-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
}

/// Derives the canonical transaction identity from the actual predecessor.
#[doc(hidden)]
#[must_use]
pub fn lifecycle_initial_reservation_transaction_id_v1(
    operation: OperationId,
    current_record: ObjectDigest,
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.initial-reservation-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
}

/// Derives the canonical progress transaction identity from the actual predecessor.
#[doc(hidden)]
#[must_use]
pub fn lifecycle_progress_transaction_id_v1(
    operation: OperationId,
    current_record: ObjectDigest,
    purpose: &[u8],
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.progress-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
}

fn nonzero_lifecycle_id_from_digest(digest: [u8; 32]) -> [u8; 16] {
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    identity
}

/// Derives the existing domain-separated lifecycle auxiliary resource identity.
#[doc(hidden)]
#[must_use]
pub fn lifecycle_plan_resource_id_v5(operation: OperationId, purpose: &[u8])
    -> aos_sandbox_model::ResourceId {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-resource.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose).finalize().into();
    aos_sandbox_model::ResourceId::from_bytes(nonzero_lifecycle_id_from_digest(digest))
}

#[cfg(test)]
mod plan_resource_identity_tests {
    use super::*;

    #[test]
    fn moved_auxiliary_recipe_preserves_original_resource_bytes() {
        assert_eq!(lifecycle_plan_resource_id_v5(OperationId::from_bytes([1; 16]), b"boot-inventory-lineage").into_bytes(),
            [159, 116, 152, 49, 36, 29, 108, 150, 141, 221, 146, 93, 26, 8, 109, 127]);
        assert_eq!(lifecycle_plan_resource_id_v5(OperationId::from_bytes([2; 16]), b"coordination-lineage").into_bytes(),
            [74, 18, 129, 129, 130, 248, 93, 213, 53, 106, 202, 70, 25, 101, 43, 157]);
        assert_eq!(lifecycle_plan_resource_id_v5(OperationId::from_bytes([255; 16]), b"").into_bytes(),
            [76, 217, 21, 178, 181, 115, 43, 174, 223, 121, 229, 207, 63, 148, 220, 109]);
    }
}
