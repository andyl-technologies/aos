//! Active AOSMSA02 cold-barrier, namespace, and Create-projection tests.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    InventorySourceRequestV1, SourceProviderKeyUsageV1, SourceProviderMethod,
    SourceProviderSigningKeyV1, digest_signed_request, encode_inventory_request, sign_request,
};
use ed25519_dalek::SigningKey;

use super::format::{
    MutationTagV2, RecordKindV2, acquisition_key, holder_sequence_key, key_kind,
    mount_source_consumption_companion_digest_v2, provider_attempt_key, provider_head_key,
    provider_session_key, transaction_id,
};
use super::{ProviderAttemptStateV2, ProviderMethodV2, lifecycle, qualify_cold_inventory_barrier};

fn signed_inventory_request() -> (Vec<u8>, [u8; 32]) {
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
    .expect("valid test signer");
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
    .expect("valid Inventory query");
    let signed = sign_request(
        SourceProviderMethod::Inventory,
        encode_inventory_request(&query),
        signer,
        &signing_key,
    )
    .expect("signed Inventory query");

    let digest = *digest_signed_request(&signed).as_bytes();
    (signed.to_canonical_bytes(), digest)
}

#[test]
fn cold_inventory_qualification_rejects_wrong_method_state_and_identity() {
    let (signed_request, digest) = signed_inventory_request();

    assert!(
        qualify_cold_inventory_barrier(
            ProviderMethodV2::Inventory,
            &ProviderAttemptStateV2::Reserved,
            &signed_request,
            digest,
        )
        .is_ok()
    );
    assert!(
        qualify_cold_inventory_barrier(
            ProviderMethodV2::Acquire,
            &ProviderAttemptStateV2::Reserved,
            &signed_request,
            digest,
        )
        .is_err()
    );
    assert!(
        qualify_cold_inventory_barrier(
            ProviderMethodV2::Inventory,
            &ProviderAttemptStateV2::SupersededIndeterminate {
                successor_session_id: [1; 32],
                recovery_root_attempt_id: [2; 32],
                outcome_may_exist: true,
            },
            &signed_request,
            digest,
        )
        .is_err()
    );
    assert!(
        qualify_cold_inventory_barrier(
            ProviderMethodV2::Inventory,
            &ProviderAttemptStateV2::Reserved,
            &signed_request,
            [0; 32],
        )
        .is_err()
    );
    assert!(
        qualify_cold_inventory_barrier(
            ProviderMethodV2::Inventory,
            &ProviderAttemptStateV2::Reserved,
            b"not a canonical signed request",
            digest,
        )
        .is_err()
    );
}

#[test]
fn namespace_40_accepts_only_five_exact_v2_key_kinds() {
    let keys = [
        (acquisition_key([1; 32]), 0_u8),
        (provider_head_key([2; 16], [3; 16]), 1),
        (holder_sequence_key([4; 16]), 2),
        (provider_session_key([5; 32]), 3),
        (provider_attempt_key([6; 32]), 4),
    ];

    for (key, kind) in keys {
        assert!(matches!(
            (key_kind(&key), kind),
            (Ok(RecordKindV2::Acquisition), 0)
                | (Ok(RecordKindV2::ProviderHead), 1)
                | (Ok(RecordKindV2::HolderSequence), 2)
                | (Ok(RecordKindV2::ProviderSession), 3)
                | (Ok(RecordKindV2::ProviderQueryAttempt), 4)
        ));
        assert!(key_kind(&key[..key.len() - 1]).is_err());
    }

    let mut old_key = b"aos.mount.source-acquisition.v1\0".to_vec();
    old_key.extend_from_slice(&[1; 32]);
    assert!(key_kind(&old_key).is_err());
}

#[test]
fn v2_transaction_and_companion_digests_separate_operations() {
    let admission = transaction_id(
        MutationTagV2::InitialAdmission,
        [1; 16],
        [2; 16],
        1,
        1,
        Some([3; 32]),
        Some(1),
        None,
        None,
        None,
    );
    let inventory = transaction_id(
        MutationTagV2::CompleteInventory,
        [1; 16],
        [2; 16],
        1,
        1,
        Some([3; 32]),
        Some(1),
        None,
        None,
        None,
    );
    assert_ne!(admission, inventory);

    let put = mount_source_consumption_companion_digest_v2(40, b"key", Some(b"value"));
    assert_ne!(
        put,
        mount_source_consumption_companion_digest_v2(41, b"key", Some(b"value"))
    );
    assert_ne!(
        put,
        mount_source_consumption_companion_digest_v2(40, b"key", None)
    );
    assert_ne!(
        put,
        mount_source_consumption_companion_digest_v2(40, b"other", Some(b"value"))
    );
}

#[test]
fn final_create_projection_changes_only_catalog_field() {
    let mut final_semantics = canonical_create_semantics(&[13; 32]);
    let expected = canonical_create_semantics(&[]);

    assert_eq!(
        lifecycle::project_final_create_semantics(&final_semantics)
            .expect("valid exact field sequence"),
        expected
    );
    final_semantics.push(0);
    assert!(lifecycle::project_final_create_semantics(&final_semantics).is_err());
}

#[test]
fn final_create_projection_requires_one_nonzero_catalog_commitment() {
    let empty_catalog = canonical_create_semantics(&[]);
    let zero_catalog = canonical_create_semantics(&[0; 32]);

    assert!(lifecycle::project_final_create_semantics(&empty_catalog).is_err());
    assert!(lifecycle::project_final_create_semantics(&zero_catalog).is_err());
}

fn canonical_create_semantics(catalog: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for tag in 1_u8..=27 {
        let value: &[u8] = match tag {
            2 => &[0, 1],
            13 => catalog,
            _ => std::slice::from_ref(&tag),
        };
        bytes.push(tag);
        bytes.extend_from_slice(
            &u32::try_from(value.len())
                .expect("bounded field")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(value);
    }
    bytes
}
