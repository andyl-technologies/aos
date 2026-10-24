//! Tests portable trust construction without any native credential authority.

use super::*;
use aos_sandbox_model::{ObjectDigest, TrustScopeId};
use aos_sandbox_model::model::{KeyReference, StableKeyId, TrustPolicy};
use aos_sandbox_model::format::encode_trust_policy;
use sha2::{Digest, Sha256};

fn policy(public: [u8; 32], purpose: SignaturePurpose, usage: KeyUsage) -> Vec<u8> {
    let key = KeyReference::new(
        StableKeyId::new("ownership-authority".to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes(Sha256::digest(public).into()),
        usage,
    );
    encode_trust_policy(&TrustPolicy::new(
        TrustScopeId::from_bytes([9; 16]), purpose, vec![key], Vec::new(),
    ).unwrap())
}

#[test]
fn retained_configuration_agrees_with_ordinary_verifier() {
    let public = [11; 32];
    let bytes = policy(public, SignaturePurpose::OwnershipLease, KeyUsage::OwnershipLease);
    let ordinary = verifier_from_protected_policy_v1(bytes.clone(), public, DecodeLimits::default()).unwrap();
    let mut retained = OwnershipTrustConfigurationCaptureV1::new();

    verifier_from_protected_policy_retaining_v1(
        bytes, public, DecodeLimits::default(), &mut retained,
    ).unwrap();

    assert_eq!(retained.verifier().unwrap().authority(), ordinary.authority());
    assert!(retained.failure().is_none());
}

#[test]
fn wrong_purpose_keeps_complete_policy_and_raw_input() {
    let public = [11; 32];
    let bytes = policy(public, SignaturePurpose::Tree, KeyUsage::Tree);
    let mut retained = OwnershipTrustConfigurationCaptureV1::new();

    assert!(verifier_from_protected_policy_retaining_v1(
        bytes.clone(), public, DecodeLimits::default(), &mut retained,
    ).is_err());

    assert_eq!(retained.policy_bytes.as_deref(), Some(bytes.as_slice()));
    assert!(retained.policy.is_some());
    assert!(matches!(retained.completion, Some(Err(OwnershipTrustConfigurationErrorV1::Binding))));
    assert!(retained.verifier().is_none());
}

#[test]
fn wrong_fingerprint_keeps_actual_anchor_cause_through_reentry() {
    let bytes = policy([11; 32], SignaturePurpose::OwnershipLease, KeyUsage::OwnershipLease);
    let ordinary = verifier_from_protected_policy_v1(bytes.clone(), [12; 32], DecodeLimits::default()).err().unwrap();
    let mut retained = OwnershipTrustConfigurationCaptureV1::new();

    assert!(verifier_from_protected_policy_retaining_v1(
        bytes, [12; 32], DecodeLimits::default(), &mut retained,
    ).is_err());

    assert!(retained.policy.is_some());
    let cause = retained.failure().unwrap();
    assert_eq!(cause.to_string(), ordinary.to_string());
    let address = cause as *const dyn std::error::Error as *const ();
    assert!(verifier_from_protected_policy_retaining_v1(
        Vec::new(), [0; 32], DecodeLimits::default(), &mut retained,
    ).is_err());
    assert_eq!(retained.failure().unwrap() as *const dyn std::error::Error as *const (), address);
    assert!(retained.verifier().is_none());
}

#[test]
fn malformed_cbor_retains_input_and_original_canonical_cause() {
    let bytes = vec![0x85, 0x01];
    let mut retained = OwnershipTrustConfigurationCaptureV1::new();

    assert!(verifier_from_protected_policy_retaining_v1(
        bytes.clone(), [0; 32], DecodeLimits::default(), &mut retained,
    ).is_err());

    assert_eq!(retained.policy_bytes.as_deref(), Some(bytes.as_slice()));
    assert!(retained.failure().unwrap().downcast_ref::<CanonicalCborError>().is_some());
    assert!(retained.policy.is_none());
}

#[test]
fn actual_extent_helpers_refuse_overflow() {
    assert!(OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(usize::MAX).is_none());
    assert!(OwnershipTrustConfigurationCaptureV1::receiving_metadata_cells_v1(usize::MAX).is_none());
}
