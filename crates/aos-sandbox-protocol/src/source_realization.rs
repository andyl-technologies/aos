//! Canonical Mount source-realization identity derivation.
//!
//! The wire protocol exposes only fixed-width digests here. This module keeps
//! the Mount-minted realization-handle derivation identical in the privileged
//! producer and hostile inventory validator without sharing native state.
//!
//! The physical-proof preimage has this owned, fixed field order:
//!
//! ```text
//! domain || binding digest || proof class || authority ID/generation/digest
//!        || resource ID/generation/digest || catalog generation/digest
//!        || boot ID || device || inode || unique mount ID
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const HANDLE_DOMAIN: &[u8] = b"aos.sandbox.mount.source-realization-handle.v1\0";
const PROOF_DOMAIN: &[u8] = b"aos.sandbox.mount.source-physical-proof.v1\0";

/// Classifies the authenticated proof behind a physical source realization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountSourceProofClassV1 {
    /// The provider realized an exact immutable portable tree.
    ImmutableTree,
    /// The provider pinned one same-node live-export generation.
    LocalLive,
    /// The provider pinned one externally versioned replica generation.
    BestEffortReplica,
}

impl MountSourceProofClassV1 {
    /// Returns the stable proof-class tag committed by `AOSMSP01`.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ImmutableTree => 1,
            Self::LocalLive => 2,
            Self::BestEffortReplica => 4,
        }
    }
}

/// Contains the fixed-width authority and kernel facts committed by a proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountSourcePhysicalProofV1 {
    /// Canonical logical source-binding digest.
    pub binding_digest: [u8; 32],
    /// Closed class of provider proof.
    pub proof_class: MountSourceProofClassV1,
    /// Stable provider authority identity.
    pub provider_authority_id: [u8; 16],
    /// Monotonic provider authority generation.
    pub provider_authority_generation: u64,
    /// Authenticated provider authority digest.
    pub provider_authority_digest: [u8; 32],
    /// Stable provider resource identity.
    pub provider_resource_id: [u8; 32],
    /// Monotonic provider resource generation.
    pub provider_resource_generation: u64,
    /// Authenticated provider resource digest.
    pub provider_resource_digest: [u8; 32],
    /// Monotonic provider catalog generation.
    pub provider_catalog_generation: u64,
    /// Authenticated provider catalog digest.
    pub provider_catalog_digest: [u8; 32],
    /// Kernel boot containing the source object.
    pub kernel_boot_id: [u8; 16],
    /// Source descriptor device identity.
    pub device: u64,
    /// Source descriptor inode identity.
    pub inode: u64,
    /// Source mount's kernel-lifetime identity.
    pub unique_mount_id: u64,
}

/// Carries the provider-history fields shared by admission and inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountSourceProviderHistoryV1 {
    /// Stable provider authority identity.
    pub authority_id: [u8; 16],
    /// Monotonic provider authority generation.
    pub authority_generation: u64,
    /// Authenticated provider authority digest.
    pub authority_digest: [u8; 32],
    /// Stable provider resource identity.
    pub resource_id: [u8; 32],
    /// Monotonic provider resource generation.
    pub resource_generation: u64,
    /// Authenticated provider resource digest.
    pub resource_digest: [u8; 32],
    /// Monotonic provider catalog generation.
    pub catalog_generation: u64,
    /// Authenticated provider catalog digest.
    pub catalog_digest: [u8; 32],
    /// Physical proof committed at this provider resource generation.
    pub physical_proof_digest: [u8; 32],
}

/// Reports whether provider history is monotonic and free of equivocation.
///
/// Rows under different authority IDs are independent. Within one authority,
/// authority and catalog generations must have a consistent partial order.
/// Reuse of one resource ID may not roll its generation backward relative to
/// that order, and an equal resource generation must reproduce both its
/// resource digest and complete physical proof.
#[must_use]
pub fn mount_source_provider_history_is_valid_v1(history: &[MountSourceProviderHistoryV1]) -> bool {
    for (index, left) in history.iter().enumerate() {
        for right in history.iter().skip(index + 1) {
            if left.authority_id != right.authority_id {
                continue;
            }
            if (left.authority_generation == right.authority_generation
                && left.authority_digest != right.authority_digest)
                || (left.catalog_generation == right.catalog_generation
                    && left.catalog_digest != right.catalog_digest)
            {
                return false;
            }

            let authority_order = left.authority_generation.cmp(&right.authority_generation);
            let catalog_order = left.catalog_generation.cmp(&right.catalog_generation);
            if (!authority_order.is_eq()
                && !catalog_order.is_eq()
                && authority_order != catalog_order)
                || (left.resource_id == right.resource_id
                    && !resource_history_is_valid(*left, *right, authority_order, catalog_order))
            {
                return false;
            }
        }
    }
    true
}

fn resource_history_is_valid(
    left: MountSourceProviderHistoryV1,
    right: MountSourceProviderHistoryV1,
    authority_order: std::cmp::Ordering,
    catalog_order: std::cmp::Ordering,
) -> bool {
    let resource_order = left.resource_generation.cmp(&right.resource_generation);
    let provider_order = if !authority_order.is_eq() {
        authority_order
    } else {
        catalog_order
    };
    if !provider_order.is_eq() && !resource_order.is_eq() && provider_order != resource_order {
        return false;
    }
    resource_order != std::cmp::Ordering::Equal
        || (left.resource_digest == right.resource_digest
            && left.physical_proof_digest == right.physical_proof_digest)
}

/// Derives the canonical digest of complete provider and kernel source proof.
#[must_use]
pub fn mount_source_physical_proof_digest_v1(proof: MountSourcePhysicalProofV1) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PROOF_DOMAIN);
    digest.update(proof.binding_digest);
    digest.update([proof.proof_class.code()]);
    digest.update(proof.provider_authority_id);
    digest.update(proof.provider_authority_generation.to_be_bytes());
    digest.update(proof.provider_authority_digest);
    digest.update(proof.provider_resource_id);
    digest.update(proof.provider_resource_generation.to_be_bytes());
    digest.update(proof.provider_resource_digest);
    digest.update(proof.provider_catalog_generation.to_be_bytes());
    digest.update(proof.provider_catalog_digest);
    digest.update(proof.kernel_boot_id);
    digest.update(proof.device.to_be_bytes());
    digest.update(proof.inode.to_be_bytes());
    digest.update(proof.unique_mount_id.to_be_bytes());
    digest.finalize().into()
}

/// Derives the sole Mount-minted handle for one logical binding and proof.
#[must_use]
pub fn mount_source_realization_handle_v1(
    binding_digest: [u8; 32],
    physical_proof_digest: [u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(HANDLE_DOMAIN);
    digest.update(binding_digest);
    digest.update(physical_proof_digest);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_proof_and_handle_match_independent_golden_vectors() {
        let proof = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
            binding_digest: [1; 32],
            proof_class: MountSourceProofClassV1::BestEffortReplica,
            provider_authority_id: [2; 16],
            provider_authority_generation: 3,
            provider_authority_digest: [4; 32],
            provider_resource_id: [5; 32],
            provider_resource_generation: 6,
            provider_resource_digest: [7; 32],
            provider_catalog_generation: 8,
            provider_catalog_digest: [9; 32],
            kernel_boot_id: [10; 16],
            device: 11,
            inode: 12,
            unique_mount_id: 13,
        });
        assert_eq!(
            proof,
            [
                137, 2, 211, 110, 76, 93, 10, 249, 92, 18, 236, 130, 204, 8, 41, 160, 78, 126, 70,
                178, 218, 233, 199, 129, 148, 95, 248, 121, 156, 2, 203, 88,
            ]
        );
        assert_eq!(
            mount_source_realization_handle_v1([1; 32], proof),
            [
                127, 39, 173, 145, 23, 4, 84, 62, 210, 167, 181, 137, 160, 175, 96, 14, 81, 245,
                194, 199, 100, 233, 117, 62, 147, 60, 171, 56, 106, 86, 249, 1,
            ]
        );
    }
}
