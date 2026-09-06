//! Verifies that downstream clients can construct destination-slot mutations.

#![allow(clippy::unwrap_used)]

use aos_sandbox::{AttachmentSlotMutationV1, AttachmentSlotPresenceV1};
use aos_sandbox_core::{AttachmentSlotId, ObjectDigest, OperationId, Revision};

#[test]
fn downstream_code_can_name_attachment_slot_mutations() {
    let mutation = AttachmentSlotMutationV1::new(
        AttachmentSlotPresenceV1::Available,
        AttachmentSlotId::from_bytes([1; 16]),
        Revision::new(1),
        OperationId::from_bytes([2; 16]),
        ObjectDigest::from_bytes([3; 32]),
        None,
    )
    .unwrap();

    assert_eq!(mutation.slot_id(), AttachmentSlotId::from_bytes([1; 16]));
    assert_eq!(mutation.revision(), Revision::new(1));
    assert_eq!(mutation.expected_previous(), None);
}
