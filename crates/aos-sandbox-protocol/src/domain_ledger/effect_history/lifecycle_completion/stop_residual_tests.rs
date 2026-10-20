//! Keeps Stop residual DATA distinct from ordinary and Create completion.

use super::*;
use crate::storage_capture_session::stop_cleanup::{
    CaptureQuiescentIncompleteFieldsDataV4, CaptureQuiescentIncompleteReceiptDataV4,
};

fn residual() -> CaptureQuiescentIncompleteReceiptDataV4 {
    let digest = |value| ObjectDigest::from_bytes([value; 32]);
    CaptureQuiescentIncompleteReceiptDataV4::from_fields_v4(CaptureQuiescentIncompleteFieldsDataV4 {
        nonce: [1; 32], begin: [2; 32], source: digest(3), attempt: [4; 16],
        durable_attempt: digest(5), stop_request: [6; 16], runtime: digest(7),
        stop_frame: digest(8), stop_plan: digest(9), stop_lease: digest(10),
        physical_binding: digest(11), native_cleanup: digest(12),
        observed_wall_seconds: 13, observed_boottime_nanoseconds: 14,
        stop_cutoff_boottime_nanoseconds: 15,
    }).unwrap()
}

#[test]
fn residual_receipt_round_trips_the_complete_sole_record_without_adopting_create() {
    let operation = OperationId::from_bytes([16; 16]);
    let source = ObjectDigest::from_bytes([17; 32]);
    let record = residual();
    let bytes = encode_stop_residual_lifecycle_receipt_v4(operation, source, &record).unwrap();

    let LifecycleEffectReceiptDataV1::StopResidual(parsed) =
        decode_lifecycle_effect_receipt_v1(&bytes, [0; 16]).unwrap()
    else { panic!("wrong receipt family"); };
    assert_eq!(parsed.operation_v4(), operation);
    assert_eq!(parsed.source_v4(), source);
    assert_eq!(parsed.residual_v4().canonical_bytes_v4(), record.canonical_bytes_v4());
    assert_eq!(&bytes[..8], b"AOSLIF04");
    assert_eq!(bytes.len(), 480);
}

#[test]
fn residual_framing_rejects_unknown_versions_truncation_and_missing_identity() {
    let operation = OperationId::from_bytes([16; 16]);
    let source = ObjectDigest::from_bytes([17; 32]);
    let bytes = encode_stop_residual_lifecycle_receipt_v4(operation, source, &residual()).unwrap();
    for end in 0..bytes.len() {
        assert!(decode_lifecycle_effect_receipt_v1(&bytes[..end], [0; 16]).is_err());
    }
    for (offset, value) in [(7, b'5'), (56 + 9, 5)] {
        let mut changed = bytes;
        changed[offset] = value;
        assert!(decode_lifecycle_effect_receipt_v1(&changed, [0; 16]).is_err());
    }
    let mut changed = bytes;
    changed[8..24].fill(0);
    assert!(decode_lifecycle_effect_receipt_v1(&changed, [0; 16]).is_err());
    assert!(encode_stop_residual_lifecycle_receipt_v4(OperationId::from_bytes([0; 16]), source, &residual()).is_err());
}
