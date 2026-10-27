//! Keeps the actual nested parse and descriptor on a real anchor refusal.

use super::*;
use crate::format::encode_trust_policy;
use sha2::{Digest, Sha256};

#[test]
fn fingerprint_refusal_keeps_raw_policy_second_parse_and_computed_descriptor() {
    let scope = TrustScopeId::from_bytes([3; 16]);
    let authority = KeyReference::new(
        crate::model::StableKeyId::new("ownership-authority".to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes(Sha256::digest([5; 32]).into()),
        KeyUsage::OwnershipLease,
    );
    let policy = TrustPolicy::new(
        scope, SignaturePurpose::OwnershipLease, vec![authority.clone()], Vec::new(),
    ).unwrap();
    let bytes = encode_trust_policy(&policy);
    let descriptor = descriptor_for_bytes(
        crate::MediaType::new(crate::PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
        &bytes,
    );
    let mut capture = OwnershipLeaseTrustAnchorConstructionV1::new();

    assert!(OwnershipLeaseTrustAnchor::from_trusted_configuration_retaining_v1(
        bytes.clone(), descriptor.clone(), scope, authority, [6; 32],
        DecodeLimits::default(), &mut capture,
    ).is_err());

    assert_eq!(capture.canonical.as_deref(), Some(bytes.as_slice()));
    assert_eq!(capture.policy.as_ref(), Some(&policy));
    assert_eq!(capture.computed.as_ref(), Some(&descriptor));
    assert!(matches!(capture.completion, Some(Err(OwnershipLeaseVerificationError::InvalidTrustAnchor))));
    assert!(capture.take_anchor_once().is_none());
}
