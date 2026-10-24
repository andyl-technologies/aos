//! Exercises graph custody at the actual auxiliary constructor refusal.

use super::*;
use crate::lifecycle::{
    LifecycleRetentionLedgerV1, LifecycleRetentionPurposeV1,
};
use aos_sandbox_model::{ObjectDigest, ResourceId, Revision, SandboxId};

#[test]
fn refused_retention_constructor_keeps_the_actual_parsed_entry() {
    let entry = LifecycleRetentionLedgerEntryV1::new(
        LifecycleResourceV1::Sandbox(SandboxId::from_bytes([1; 16])),
        ResourceId::from_bytes([2; 16]), LifecycleRetentionPurposeV1::Snapshot,
        ObjectDigest::from_bytes([3; 32]),
    ).unwrap();
    let ledger = LifecycleRetentionLedgerV1::new(Revision::new(1), None, vec![entry]).unwrap();
    let mut encoded = crate::lifecycle::encode_lifecycle_auxiliary_payload_v1(
        &LifecycleAuxiliaryPayloadV1::RetentionLedger(ledger),
    ).unwrap();
    encoded[..8].copy_from_slice(&0_u64.to_be_bytes());
    let mut original = LifecycleAuxiliaryDecodeOriginalV1::new();

    assert!(crate::lifecycle::auxiliary_payload::decode_lifecycle_auxiliary_payload_into(
        LifecycleAuxiliaryKindV1::RetentionLedger, &encoded,
        crate::lifecycle::auxiliary_payload::LifecycleAuxiliaryPayloadLayoutV1::Current,
        &mut original,
    ).is_err());
    assert_eq!(original.entries, vec![entry]);
    assert_eq!(original.failure(), Some(&LifecycleModelError::InvalidModel));
    assert!(original.payload.is_none());
    assert!(original.take_completed_once().is_none());
    assert!(crate::lifecycle::decode_lifecycle_auxiliary_payload_v1(
        LifecycleAuxiliaryKindV1::RetentionLedger, &encoded,
    ).is_err());
}
