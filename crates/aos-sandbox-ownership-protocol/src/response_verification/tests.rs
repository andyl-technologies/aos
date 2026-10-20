//! Negative custody and ordinary-equivalence tests for the actual verifier.

use super::*;
use aos_sandbox_core::{AssignmentEpoch, RawClockProvenance, TrustScopeId};
use aos_sandbox_core::format::{encode_ownership_lease, encode_trust_policy};
use aos_sandbox_core::model::{SignaturePurpose, SignatureStatement, TrustPolicy};
use ed25519_dalek::SigningKey;

struct Fixture {
    verifier: OwnershipAuthorityVerifier,
    claim: OwnershipClaimV1,
    response: UnverifiedOwnershipLeaseResponse,
    clock: RawPairedClockSample,
}

fn fixture() -> Fixture {
    let key = SigningKey::from_bytes(&[31; 32]);
    let authority = KeyReference::new(StableKeyId::new("ownership-verifier-test".to_owned()).unwrap(),
        4, ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()), KeyUsage::OwnershipLease);
    let assignment = LeaseAssignment::new(SandboxId::from_bytes([1; 16]),
        IncarnationId::from_bytes([2; 16]), AssignmentEpoch::new(3), ObjectDigest::from_bytes([5; 32])).unwrap();
    let node = NodeId::from_bytes([6; 16]);
    let claim = OwnershipClaimV1::acquire([7; 16], assignment, DesiredGeneration::new(4), node, 120).unwrap();
    let lease = OwnershipLease::new(assignment, node, 1, 100, 200, 10, [8; 16]).unwrap();
    let lease_bytes = encode_ownership_lease(&lease);
    let scope = TrustScopeId::from_bytes([10; 16]);
    let policy = TrustPolicy::new(scope, SignaturePurpose::OwnershipLease,
        vec![authority.clone()], Vec::new()).unwrap();
    let policy_bytes = encode_trust_policy(&policy);
    let descriptor = |kind: PortableMediaType, bytes: &[u8]| descriptor_for_bytes(
        MediaType::new(kind.as_str().to_owned()).unwrap(), bytes);
    let policy_descriptor = descriptor(PortableMediaType::TrustPolicy, &policy_bytes);
    let sign = |kind: PortableMediaType, bytes: &[u8]| {
        let statement = SignatureStatement::new(descriptor(kind, bytes), scope, authority.clone(),
            SignaturePurpose::OwnershipLease, 100, Some(200), policy_descriptor.clone()).unwrap();
        encode_signature(&aos_sandbox_core::sign_statement(statement, &key).unwrap())
    };
    let lease_signature = sign(PortableMediaType::OwnershipLease, &lease_bytes);
    let receipt = OwnershipTransactionReceiptV1::new(authority.clone(), &claim, &lease_bytes).unwrap();
    let receipt_bytes = receipt.canonical_bytes().to_vec();
    let receipt_signature = sign(PortableMediaType::OwnershipTransactionReceipt, &receipt_bytes);
    let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(policy_bytes,
        policy_descriptor, scope, authority.clone(), key.verifying_key().to_bytes(), DecodeLimits::default()).unwrap();
    Fixture {
        verifier: OwnershipAuthorityVerifier::new(anchor, authority), claim,
        response: UnverifiedOwnershipLeaseResponse::from_transport(lease_bytes,
            lease_signature, receipt_bytes, receipt_signature).unwrap(),
        clock: RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([9; 16]).unwrap(),
            [10; 16], 150, 1_000).unwrap(),
    }
}

#[test]
fn complete_retained_verification_matches_existing_result_and_moves_once() {
    let original = fixture();
    let ordinary = original.verifier.verify_response(&original.claim, original.response.clone(), &original.clock).unwrap();
    let mut capture = OwnershipResponseVerifyCaptureV1::new();

    original.verifier.verify_response_retaining_v1(&original.claim, original.response.clone(),
        &original.clock, &mut capture).unwrap();

    assert_eq!(capture.value(), Some(&ordinary));
    let receipt = capture.verified_receipt_v1().unwrap();
    assert_eq!(receipt.request_id(), original.claim.request_id());
    assert_eq!(receipt.claim_digest(), original.claim.digest());
    assert!(std::ptr::eq(receipt, capture.work.receipt_result.as_ref().unwrap().as_ref().unwrap()));
    assert!(capture.work.lease_verification.verified().is_some());
    assert!(capture.work.receipt_verification.is_complete());
    assert_eq!(capture.take_value_once(), Some(ordinary));
    assert!(capture.verified_receipt_v1().is_none());
    assert!(capture.take_value_once().is_none());
}

#[test]
fn late_receipt_sentinel_keeps_actual_key_and_prior_verified_lease() {
    let mut original = fixture();
    let key_len = usize::from(u16::from_be_bytes(original.response.receipt[24..26].try_into().unwrap()));
    let request = 26 + key_len + 8 + 32;
    original.response.receipt[request..request + 16].fill(0);
    let expected = original.verifier.verify_response(&original.claim, original.response.clone(), &original.clock).unwrap_err();
    let mut capture = OwnershipResponseVerifyCaptureV1::new();

    let returned = original.verifier.verify_response_retaining_v1(&original.claim,
        original.response.clone(), &original.clock, &mut capture).unwrap_err();

    assert_eq!(returned, expected);
    assert_eq!(capture.work.receipt_decode.retained_authority(), Some(original.verifier.authority()));
    assert!(capture.work.lease_verification.verified().is_some());
    assert!(capture.work.signature.is_some());
    assert_eq!(capture.work.response.as_ref(), Some(&original.response));
    assert!(capture.cause().unwrap().downcast_ref::<OwnershipReceiptError>().is_some());
}

#[test]
fn final_bad_signature_keeps_actual_crypto_error_and_all_earlier_models() {
    let mut original = fixture();
    *original.response.receipt_signature.last_mut().unwrap() ^= 1;
    let expected = original.verifier.verify_response(&original.claim, original.response.clone(), &original.clock).unwrap_err();
    let mut capture = OwnershipResponseVerifyCaptureV1::new();

    let returned = original.verifier.verify_response_retaining_v1(&original.claim,
        original.response.clone(), &original.clock, &mut capture).unwrap_err();

    assert_eq!(returned, expected);
    assert!(capture.work.lease_verification.verified().is_some());
    assert!(matches!(capture.work.receipt_result, Some(Ok(_))));
    assert!(matches!(capture.work.receipt_context, Some(Ok(()))));
    assert!(capture.work.receipt_signature.is_some());
    assert!(capture.verified_receipt_v1().is_none());
    let cause = capture.cause().unwrap().downcast_ref::<ed25519_dalek::SignatureError>().unwrap();
    let first = cause as *const ed25519_dalek::SignatureError;
    assert!(original.verifier.verify_response_retaining_v1(&original.claim,
        original.response, &original.clock, &mut capture).is_err());
    assert!(std::ptr::eq(first, capture.cause().unwrap().downcast_ref::<ed25519_dalek::SignatureError>().unwrap()));
}

#[test]
fn context_short_circuit_keeps_media_before_skipping_descriptor() {
    let original = fixture();
    let receipt = OwnershipTransactionReceiptV1::from_canonical_bytes(&original.response.receipt).unwrap();
    let other = OwnershipClaimV1::acquire([44; 16], original.claim.assignment(),
        original.claim.desired_generation(), original.claim.node(), 120).unwrap();
    let mut work = receipt::ReceiptContextWorkV1::default();

    let retained = receipt::verify_context_engine(&receipt, original.verifier.authority(),
        &other, &original.response.lease, Some(&mut work)).unwrap_err();
    let ordinary = receipt.verify_context(original.verifier.authority(), &other, &original.response.lease).unwrap_err();

    assert_eq!(retained, ordinary);
    assert!(work.media.is_some());
    assert!(work.descriptor.is_none());
}

#[test]
fn hostile_quartet_lengths_refuse_before_any_copy_or_model_growth() {
    let original = fixture();
    let oversized = vec![0; MAXIMUM_SIGNATURE_BYTES + 1];
    let mut capture = OwnershipResponseVerifyCaptureV1::new();

    assert!(original.verifier.verify_response_bytes_retaining_v1(&original.claim,
        &original.response.lease, &oversized, &original.response.receipt,
        &original.response.receipt_signature, &original.clock, &mut capture).is_err());

    assert!(matches!(capture.transport, Some(Err(_))));
    assert!(capture.work.response.is_none());
    assert!(capture.work.signature.is_none());
    assert!(capture.work.signature_decode.failure().is_none());
}

#[test]
fn fixed_claim_failure_is_original_and_reentry_does_not_replace_it() {
    let original = fixture();
    let mut bytes = *original.claim.canonical_bytes();
    bytes[15] = 1;
    let ordinary = OwnershipClaimV1::from_canonical_bytes(&bytes).unwrap_err();
    let mut capture = OwnershipClaimDecodeCaptureV1::new();

    assert_eq!(capture.decode_once_v1(&bytes), Err(ordinary));
    let first = capture.failure().unwrap() as *const OwnershipClaimError;
    assert!(capture.decode_once_v1(original.claim.canonical_bytes()).is_err());
    assert!(std::ptr::eq(first, capture.failure().unwrap()));
    assert!(capture.value().is_none());
}

#[test]
fn geometry_overflow_refuses_without_entering_verification() {
    let original = fixture();

    assert!(original.verifier.response_receiving_dynamic_bytes_v2(usize::MAX).is_none());
    let bytes = original.verifier.response_receiving_dynamic_bytes_v2(4_096).unwrap();

    assert!(bytes > 4_096);
    assert!(original.verifier.response_receiving_dynamic_bytes_v2(8_192).unwrap() > bytes);
}
