//! Tests exact cold request decoding and preflight gate order.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    InventorySourceRequestV1, SourceProviderKeyUsageV1, SourceProviderMethod,
    SourceProviderSigningKeyV1, digest_signed_request, encode_inventory_request, sign_request,
};
use ed25519_dalek::SigningKey;

use super::*;

fn signed_inventory_request() -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&[22; 32]);
    let signer = SourceProviderSigningKeyV1::for_signing_key(
        [1; 16],
        2,
        ObjectDigest::from_bytes([3; 32]),
        [21; 16],
        1,
        SourceProviderKeyUsageV1::RootMountRecord,
        &signing_key,
    )
    .unwrap();
    let query = InventorySourceRequestV1::new(
        ObjectDigest::from_bytes([28; 32]),
        1,
        [23; 16],
        [1; 16],
        2,
        ObjectDigest::from_bytes([3; 32]),
        None,
        1,
    )
    .unwrap();
    sign_request(
        SourceProviderMethod::Inventory,
        encode_inventory_request(&query),
        signer,
        &signing_key,
    )
    .unwrap()
    .to_canonical_bytes()
}

#[test]
fn cold_request_checker_rejects_changed_method_bytes_and_digest() {
    let bytes = signed_inventory_request();
    let signed =
        aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(
            &bytes,
        )
        .unwrap();
    let digest = *digest_signed_request(&signed).as_bytes();

    assert_eq!(
        checked_cold_provider_request(ProviderMethodV2::Inventory, &bytes, digest)
            .unwrap()
            .to_canonical_bytes(),
        bytes
    );
    assert!(matches!(
        checked_cold_provider_request(ProviderMethodV2::Acquire, &bytes, digest),
        Err(crate::MountError::State(message))
            if message == "cold provider request differs from its durable identity"
    ));
    assert!(matches!(
        checked_cold_provider_request(
            ProviderMethodV2::Inventory,
            &bytes[..bytes.len() - 1],
            digest,
        ),
        Err(crate::MountError::State(message))
            if message == "cold provider request envelope is invalid"
    ));
    assert!(matches!(
        checked_cold_provider_request(ProviderMethodV2::Inventory, &bytes, [0; 32]),
        Err(crate::MountError::State(message))
            if message == "cold provider request differs from its durable identity"
    ));
}

#[test]
fn cold_inventory_barrier_checks_state_and_method_before_request() {
    let invalid_request = b"not a signed request";
    let indeterminate = ProviderAttemptStateV2::SupersededIndeterminate {
        successor_session_id: [1; 32],
        recovery_root_attempt_id: [2; 32],
        outcome_may_exist: true,
    };

    assert!(matches!(
        qualify_cold_inventory_barrier(
            ProviderMethodV2::Inventory,
            &indeterminate,
            invalid_request,
            [0; 32],
        ),
        Err(crate::MountError::State(message))
            if message == "cold provider disposition requires method-specific recovery"
    ));
    assert!(matches!(
        qualify_cold_inventory_barrier(
            ProviderMethodV2::Acquire,
            &ProviderAttemptStateV2::Reserved,
            invalid_request,
            [0; 32],
        ),
        Err(crate::MountError::State(message))
            if message == "cold provider attempt requires method-specific recovery"
    ));
}
