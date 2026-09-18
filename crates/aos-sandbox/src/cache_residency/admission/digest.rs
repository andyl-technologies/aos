//! Domain-separated admission and initial-pin commitments.

use sha2::{Digest as _, Sha256};

use super::*;

pub(super) fn admission_digest(plan: &ImmutableAdmissionPlanV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.admission-plan.v1\0");
    hasher.update(plan.operation.as_bytes());
    hasher.update(plan.reservation.as_bytes());
    hasher.update(plan.project.as_bytes());
    hasher.update(plan.partition.digest().as_bytes());
    let media = plan.descriptor.media_type().as_str().as_bytes();
    hasher.update((media.len() as u16).to_be_bytes());
    hasher.update(media);
    hasher.update(plan.descriptor.digest().as_bytes());
    hasher.update(plan.descriptor.encoded_size().to_be_bytes());
    hasher.update(plan.source.release_digest.as_bytes());
    hasher.update(plan.source.source_revision.as_bytes());
    let source_media = plan.source.descriptor.media_type().as_str().as_bytes();
    hasher.update((source_media.len() as u16).to_be_bytes());
    hasher.update(source_media);
    hasher.update(plan.source.descriptor.digest().as_bytes());
    hasher.update(plan.source.descriptor.encoded_size().to_be_bytes());
    hasher.update(plan.source.source_seal.as_bytes());
    hasher.update(plan.source.authority_generation.to_be_bytes());
    hasher.update(plan.source.valid_until.to_be_bytes());
    hasher.update([plan.expected_seal.profile as u8]);
    hasher.update(plan.expected_seal.measurement.as_bytes());
    hasher.update(plan.reserved_bytes.to_be_bytes());
    hasher.update(plan.policy_revision.as_bytes());
    hasher.update(plan.root_generation.to_be_bytes());
    hasher.update(plan.root_custody.as_bytes());
    hasher.update(plan.initial_pins_digest.as_bytes());
    hasher.update(plan.request_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn source_authority_subject(
    descriptor: &ObjectDescriptor,
    source_revision: ObjectDigest,
    source_seal: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.source-authority-subject.v1\0");
    hasher.update(object_descriptor_commitment(descriptor).as_bytes());
    hasher.update(source_revision.as_bytes());
    hasher.update(source_seal.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn admission_progress_digest(progress: &AdmissionProgressV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.admission-progress.v1\0");
    hasher.update(progress.plan_digest.as_bytes());
    hasher.update([progress.stage as u8, progress.last_certain_stage as u8]);
    hasher.update(progress.generation.to_be_bytes());
    hasher.update(
        progress
            .predecessor
            .map_or([0; 32], |digest| *digest.as_bytes()),
    );
    hasher.update(progress.evidence.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

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

pub(super) const fn stage_rank(stage: AdmissionStageV1) -> u8 {
    match stage {
        AdmissionStageV1::Reserved => 1,
        AdmissionStageV1::PrivateDestinationCreated => 2,
        AdmissionStageV1::ContentTransferred => 3,
        AdmissionStageV1::ContentVerified => 4,
        AdmissionStageV1::WritersClosed => 5,
        AdmissionStageV1::SealEnabledAndVerified => 6,
        AdmissionStageV1::InodeSynced => 7,
        AdmissionStageV1::CanonicalNamePublished => 8,
        AdmissionStageV1::ParentSynced => 9,
        AdmissionStageV1::CatalogCommitted => 10,
        AdmissionStageV1::Uncertain => 11,
        AdmissionStageV1::Quarantined | AdmissionStageV1::Aborted => 12,
    }
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
    if pins.len() > 65_536 {
        return Err(AdmissionError::PinMismatch);
    }
    let mut previous = None;
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.initial-pin-set.v1\0");
    hasher.update((pins.len() as u32).to_be_bytes());
    for pin in pins {
        pin.clone().validate()?;
        if previous.is_some_and(|id| id >= pin.id) {
            return Err(AdmissionError::PinMismatch);
        }
        previous = Some(pin.id);
        hasher.update(pin.id.as_bytes());
        hasher.update(pin.partition.digest().as_bytes());
        let media = pin.object.media_type().as_str().as_bytes();
        hasher.update((media.len() as u16).to_be_bytes());
        hasher.update(media);
        hasher.update(pin.object.digest().as_bytes());
        hasher.update(pin.object.encoded_size().to_be_bytes());
        hasher.update(pin.project.as_bytes());
        hasher.update(pin.view.as_bytes());
        hasher.update(pin.attachment.map_or([0; 16], |id| id.into_bytes()));
        hasher.update(pin.sandbox.map_or([0; 16], |id| id.into_bytes()));
        hasher.update(pin.incarnation.map_or([0; 16], |id| id.into_bytes()));
        hasher.update([pin.kind as u8]);
        hasher.update(pin.assignment_epoch.to_be_bytes());
        hasher.update(pin.lease_valid_until.to_be_bytes());
        hasher.update(pin.evidence.as_bytes());
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}
