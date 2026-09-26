//! Request-to-record correlation for Mount source-acquisition responses.
//!
//! Acquire uses exact assignment equality and source-consistency proof mapping.
//! Release accepts only a same-lineage current-or-dominating teardown fence.

use super::*;

pub(super) fn record_acquisition_id_is_exact(
    acquisition_id: &[u8],
    operation_id: [u8; 16],
    request_digest: [u8; 32],
) -> bool {
    mount_source_acquisition_id_v1(operation_id, ObjectDigest::from_bytes(request_digest))
        .as_bytes()
        == acquisition_id
}

pub(super) fn record_proof_matches_binding(
    record: &ValidatedMountSourceAcquisitionRecord,
    binding: &SourceRealizationBindingV1,
) -> bool {
    proof_class_matches_consistency(
        binding.consistency(),
        record.wire_record().proof_class.as_known(),
    )
}

pub(super) fn proof_class_matches_consistency(
    consistency: aos_proto::aos::sandbox::local::v1::MountSourceConsistency,
    proof_class: Option<MountSourceProofClass>,
) -> bool {
    use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;

    matches!(
        (consistency, proof_class),
        (
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE)
        ) | (
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE)
        ) | (
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA,
            Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA)
        )
    )
}

pub(super) fn release_fence_dominates_record(
    record: &ValidatedMountSourceAcquisitionRecord,
    fence: &ValidatedAssignmentFence,
) -> bool {
    record.sandbox_id() == fence.sandbox_id()
        && record.incarnation_id() == fence.incarnation_id()
        && (fence.assignment_epoch() > record.assignment_epoch()
            || fence.assignment_epoch() == record.assignment_epoch()
                && (fence.desired_generation() > record.desired_generation()
                    || fence.desired_generation() == record.desired_generation()
                        && fence.assignment_digest() == record.assignment_digest()))
}

pub(super) fn record_matches_fence(
    record: &ValidatedMountSourceAcquisitionRecord,
    fence: &ValidatedAssignmentFence,
) -> bool {
    record.sandbox_id() == fence.sandbox_id()
        && record.incarnation_id() == fence.incarnation_id()
        && record.assignment_epoch() == fence.assignment_epoch()
        && record.desired_generation() == fence.desired_generation()
        && record.assignment_digest() == fence.assignment_digest()
}
