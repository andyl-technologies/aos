//! Canonical historical descriptor-handoff model DATA and commitments.
//!
//! These fields are observations of a retained handoff. They do not resolve
//! current read authority, issue a Native plan/receipt or prove physical state.

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest};
use sha2::{Digest as _, Sha256};
use super::{BackingObjectIdentityV1, hash_descriptor_fields_u16_v1};
use super::pin_data::CachePinId;

/// Records the exact historical descriptor-handoff commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorHandoffPlanDataV1 {
    /// Exact current read-decision digest.
    pub authority_digest: ObjectDigest,
    /// Committed catalog generation.
    pub catalog_digest: ObjectDigest,
    /// Retained kernel-reference or backing-registration pin.
    pub pin: CachePinId,
    /// Complete immutable object descriptor.
    pub descriptor: ObjectDescriptor,
    /// Opaque backing identity.
    pub backing: BackingObjectIdentityV1,
    /// Fresh physical evidence.
    pub physical_evidence: ObjectDigest,
    /// Latest time at which the custodian may begin handoff.
    pub valid_until: u64,
    /// Digest of all handoff semantics.
    pub digest: ObjectDigest,
}

/// Records the historical post-handoff observation commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorHandoffReceiptDataV1 {
    /// Exact handoff plan.
    pub plan_digest: ObjectDigest,
    /// Post-handoff physical observation.
    pub post_handoff_evidence: ObjectDigest,
    /// Digest of the complete confirmation.
    pub digest: ObjectDigest,
}

/// Commits all exact historical handoff plan fields.
#[doc(hidden)]
pub fn handoff_digest(plan: &DescriptorHandoffPlanDataV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.descriptor-handoff.v1\0");
    hasher.update(plan.authority_digest.as_bytes());
    hasher.update(plan.catalog_digest.as_bytes());
    hasher.update(plan.pin.as_bytes());
    hash_descriptor_fields_u16_v1(&mut hasher, &plan.descriptor);
    hasher.update(plan.backing.as_bytes());
    hasher.update(plan.physical_evidence.as_bytes());
    hasher.update(plan.valid_until.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits the exact historical handoff receipt fields.
#[doc(hidden)]
pub fn handoff_receipt_digest(receipt: &DescriptorHandoffReceiptDataV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.descriptor-handoff-receipt.v1\0");
    hasher.update(receipt.plan_digest.as_bytes());
    hasher.update(receipt.post_handoff_evidence.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
