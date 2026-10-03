//! Signature, schema, and holder-binding regressions for entitlement custody.

use aos_sandbox_core::{
    ChannelBinding, GrantId, Operation, OperationSet, ResourceId, ResourceKind, ResourceVector,
    Selector,
};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn entry() -> EntitlementEntryV1 {
    EntitlementEntryV1 {
        principal: PrincipalId::from_bytes([1; 16]),
        project: ProjectId::from_bytes([2; 16]),
        channel_binding: [3; 32],
        policy_digest: ObjectDigest::from_bytes([4; 32]),
        policy_generation: 1,
        controller_generation: 1,
        revocation_scope: RevocationScopeId::from_bytes([5; 16]),
        revocation_generation: 1,
        not_before: 100,
        expires_at: 1_000,
        validity_seconds: 100,
        grants: vec![
            Grant::new(
                GrantId::from_bytes([6; 16]),
                ResourceKind::Sandbox,
                OperationSet::one(Operation::Create),
                Selector::Resource {
                    resource: ResourceId::from_bytes([7; 16]),
                },
                false,
            )
            .unwrap(),
        ],
        delegation: DelegationLimits::new(0, 0, ResourceVector::ZERO),
    }
}

fn signed_document(entry: EntitlementEntryV1) -> (Vec<u8>, [u8; 32]) {
    let signer = SigningKey::from_bytes(&[9; 32]);
    let entries = vec![entry];
    let unsigned = serde_json::to_vec(&UnsignedDocumentV1 {
        version: 1,
        generation: 1,
        entries: &entries,
    })
    .unwrap();
    let signature = signer.sign(&signed_bytes(&unsigned).unwrap()).to_bytes();
    let document = SignedDocumentV1 {
        version: 1,
        generation: 1,
        entries,
        signature: signature.to_vec(),
    };
    (
        serde_json::to_vec(&document).unwrap(),
        signer.verifying_key().to_bytes(),
    )
}

#[test]
fn signed_entitlement_is_exactly_bound_to_holder_and_fixed_verifier() {
    let (bytes, key) = signed_document(entry());
    let document = VerifiedEntitlementsV1::decode(&bytes, &key).unwrap();
    let binding = ChannelBinding::new([3; 32]);

    assert_eq!(document.generation(), 1);
    assert!(
        document
            .for_holder(
                PrincipalId::from_bytes([1; 16]),
                ProjectId::from_bytes([2; 16]),
                binding.as_bytes()
            )
            .is_ok()
    );
    assert!(
        document
            .for_holder(
                PrincipalId::from_bytes([8; 16]),
                ProjectId::from_bytes([2; 16]),
                binding.as_bytes()
            )
            .is_err()
    );
    assert!(
        document
            .for_holder(
                PrincipalId::from_bytes([1; 16]),
                ProjectId::from_bytes([2; 16]),
                &[8; 32]
            )
            .is_err()
    );
    assert!(VerifiedEntitlementsV1::decode(&bytes, &[8; 32]).is_err());
}

#[test]
fn offline_signer_round_trips_through_the_production_verifier() {
    let entries = vec![entry()];
    let unsigned = serde_json::to_vec_pretty(&UnsignedDocumentV1 {
        version: 1,
        generation: 7,
        entries: &entries,
    })
    .unwrap();
    let (signed, verifier) = sign_entitlement_document_v1(&unsigned, &[9; 32]).unwrap();
    let checked = VerifiedEntitlementsV1::decode(&signed, &verifier).unwrap();

    assert_eq!(checked.generation(), 7);
    assert_eq!(
        verifier,
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()
    );
    assert!(!signed.contains(&b'\n'));
    assert!(VerifiedEntitlementsV1::decode(&signed, &[10; 32]).is_err());

    let mut invalid: serde_json::Value = serde_json::from_slice(&unsigned).unwrap();
    invalid["entries"][0]["principal"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
    assert!(
        sign_entitlement_document_v1(&serde_json::to_vec(&invalid).unwrap(), &[9; 32]).is_err()
    );
}

#[test]
fn altered_or_noncanonical_document_fails_closed() {
    let (bytes, key) = signed_document(entry());
    let mut altered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    altered["entries"][0]["validity_seconds"] = serde_json::json!(300);
    assert!(VerifiedEntitlementsV1::decode(&serde_json::to_vec(&altered).unwrap(), &key).is_err());

    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
            .unwrap();
    assert!(VerifiedEntitlementsV1::decode(&pretty, &key).is_err());

    let (zero_holder, key) = signed_document(EntitlementEntryV1 {
        principal: PrincipalId::from_bytes([0; 16]),
        ..entry()
    });
    assert!(VerifiedEntitlementsV1::decode(&zero_holder, &key).is_err());
}
