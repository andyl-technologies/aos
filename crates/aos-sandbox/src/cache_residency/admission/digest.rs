//! Domain-separated admission and initial-pin commitments.

use aos_sandbox_protocol::cache_state::hash_descriptor_fields_u16_v1;

use sha2::{Digest as _, Sha256};

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn prepared_artifact_subject(
    plan: &ImmutableAdmissionPlanV1,
    progress_digest: ObjectDigest,
    backing: BackingObjectIdentityV1,
    seal: ImmutableSealV1,
    allocated_bytes: u64,
    root_custody: ObjectDigest,
    canonical_name: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.prepared-artifact-subject.v1\0");
    hasher.update(plan.digest.as_bytes());
    hasher.update(progress_digest.as_bytes());
    hasher.update(backing.as_bytes());
    hasher.update([seal.profile as u8]);
    hasher.update(seal.measurement.as_bytes());
    hasher.update(allocated_bytes.to_be_bytes());
    hasher.update(root_custody.as_bytes());
    hasher.update(plan.root_generation.to_be_bytes());
    hasher.update(canonical_name.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits an exact canonical initial pin set for immutable admission.
///
/// Pins must be strictly ordered by identity. The empty set has a valid
/// domain-separated digest and permits unpinned reusable residency.
///
/// # Errors
///
/// Returns [`AdmissionError::PinMismatch`] for invalid, duplicated, or
/// noncanonical pin order.
pub fn initial_pin_set_digest(pins: &[CachePinV1]) -> Result<ObjectDigest, AdmissionError> {
    aos_sandbox_protocol::cache_state::pin_data::initial_pin_set_digest(pins)
        .map_err(|error| match error {
            aos_sandbox_protocol::cache_state::pin_data::InitialPinSetDataErrorV1::Pin(error) => AdmissionError::Pin(error.into()),
            aos_sandbox_protocol::cache_state::pin_data::InitialPinSetDataErrorV1::Mismatch => AdmissionError::PinMismatch,
        })
}
