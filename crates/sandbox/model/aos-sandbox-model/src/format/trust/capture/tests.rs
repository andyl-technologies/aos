//! Exercises reached destinations using the shared real canonical decoder.

use super::*;

fn key(name: &str) -> KeyReference {
    KeyReference::new(
        StableKeyId::new(name.to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes([7; 32]),
        KeyUsage::OwnershipLease,
    )
}

fn prefix(keys: usize) -> Encoder {
    let mut encoder = Encoder::new();
    encoder.array(5);
    encoder.unsigned(1);
    encoder.bytes(&[3; 16]);
    encoder.unsigned(purpose_code(SignaturePurpose::OwnershipLease));
    encoder.array(keys);
    encoder
}

fn assert_same_refusal(bytes: &[u8], capture: &mut TrustPolicyDecodeCaptureV1) {
    let ordinary = decode_trust_policy(bytes, DecodeLimits::default()).unwrap_err();
    assert!(decode_trust_policy_retaining_v1(bytes, DecodeLimits::default(), capture).is_err());
    assert_eq!(capture.failure(), Some(&ordinary));
    assert!(capture.policy().is_none());
    assert!(capture.take_policy_once().is_none());
}

#[test]
fn completed_policy_matches_ordinary_and_moves_once() {
    let policy = TrustPolicy::new(
        TrustScopeId::from_bytes([3; 16]),
        SignaturePurpose::OwnershipLease,
        vec![key("authority")],
        Vec::new(),
    ).unwrap();
    let bytes = encode_trust_policy(&policy);
    let ordinary = decode_trust_policy(&bytes, DecodeLimits::default()).unwrap();
    let mut capture = TrustPolicyDecodeCaptureV1::new();

    decode_trust_policy_retaining_v1(&bytes, DecodeLimits::default(), &mut capture).unwrap();

    assert_eq!(capture.policy(), Some(&ordinary));
    assert_eq!(capture.take_policy_once(), Some(ordinary));
    assert!(capture.take_policy_once().is_none());
    assert!(capture.failure().is_none());
}

#[test]
fn malformed_generation_preserves_canonical_error_identity_across_reentry() {
    let mut encoder = prefix(2);
    encode_key_reference(&mut encoder, &key("first"));
    encoder.array(4);
    encoder.text("second");
    encoder.text("not-a-generation");
    encoder.bytes(&[7; 32]);
    encoder.unsigned(usage_code(KeyUsage::OwnershipLease));
    encoder.array(0);
    let bytes = encoder.finish();
    let mut capture = TrustPolicyDecodeCaptureV1::new();

    assert_same_refusal(&bytes, &mut capture);

    let original = capture.failure().unwrap() as *const _;
    assert!(decode_trust_policy_retaining_v1(&[], DecodeLimits::default(), &mut capture).is_err());
    assert_eq!(capture.failure().unwrap() as *const _, original);
    assert!(capture.policy().is_none());
}

#[test]
fn invalid_stable_id_retains_the_original_typed_syntax_cause() {
    let mut encoder = prefix(1);
    encoder.array(4);
    encoder.text("");
    encoder.unsigned(1);
    encoder.bytes(&[7; 32]);
    encoder.unsigned(usage_code(KeyUsage::OwnershipLease));
    encoder.array(0);
    let bytes = encoder.finish();
    let mut capture = TrustPolicyDecodeCaptureV1::new();

    assert_same_refusal(&bytes, &mut capture);

    assert!(
        capture
            .cause()
            .unwrap()
            .downcast_ref::<crate::model::InvalidTrustModel>()
            .is_some()
    );
    assert!(capture.policy().is_none());
}

#[test]
fn malformed_feature_major_preserves_the_original_canonical_refusal() {
    let mut encoder = prefix(1);
    encode_key_reference(&mut encoder, &key("authority"));
    encoder.array(1);
    encoder.array(3);
    encoder.text("aos.test");
    encoder.text("not-a-major");
    encoder.unsigned(0);
    let bytes = encoder.finish();
    let mut capture = TrustPolicyDecodeCaptureV1::new();

    assert_same_refusal(&bytes, &mut capture);

    assert!(
        capture
            .cause()
            .unwrap()
            .downcast_ref::<CanonicalCborError>()
            .is_some()
    );
    assert!(capture.policy().is_none());
}

#[test]
fn policy_semantic_failure_retains_original_typed_constructor_cause() {
    let mut encoder = prefix(2);
    encode_key_reference(&mut encoder, &key("z"));
    encode_key_reference(&mut encoder, &key("a"));
    encoder.array(0);
    let bytes = encoder.finish();
    let mut capture = TrustPolicyDecodeCaptureV1::new();

    assert_same_refusal(&bytes, &mut capture);

    let cause = capture
        .cause()
        .unwrap()
        .downcast_ref::<crate::model::InvalidTrustModel>()
        .unwrap();
    assert_eq!(*cause, crate::model::InvalidTrustModel::KeysNotCanonical);
    let original = cause as *const _;
    assert!(decode_trust_policy_retaining_v1(&[], DecodeLimits::default(), &mut capture).is_err());
    assert_eq!(
        capture
            .cause()
            .unwrap()
            .downcast_ref::<crate::model::InvalidTrustModel>()
            .unwrap() as *const _,
        original
    );
}

#[test]
fn geometry_refuses_overflow_without_input_or_parser_entry() {
    assert!(TrustPolicyDecodeCaptureV1::receiving_carrier_bytes_v1(usize::MAX).is_none());
    assert!(TrustPolicyDecodeCaptureV1::receiving_metadata_cells_v1(usize::MAX).is_none());
    let capture = TrustPolicyDecodeCaptureV1::new();
    assert!(capture.policy().is_none());
    assert!(capture.failure().is_none());
}
