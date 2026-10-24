//! Historical role scalars never qualify thread liveness or simulation readiness.

// crucible-lint: allow panic-shortcut -- These administrative role tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;

fn original() -> NativeAdministrativeFacts {
    let preparation = super::super::administrative_preparation::test_preparation();
    NativeAdministrativeFacts {
        registration_id: U64::new(1),
        thread_id: U64::new(41),
        socket_device: U64::new(preparation.socket_device),
        socket_inode: U64::new(preparation.socket_inode),
        process_id: U64::new(39),
        descriptor_slot: preparation.descriptor_slot,
        prepared_scope_hash: preparation
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap(),
        role_commitment: preparation.identity_digest().unwrap(),
        realize_request_digest: preparation.phase.initialization.realize_request_digest,
        policy_digest: preparation.policy_digest,
    }
}

#[test]
fn fixed_original_record_preserves_source_registration_and_unknown_roots() {
    let value = original();
    let preparation = super::super::administrative_preparation::test_preparation();
    value.validate_against(&preparation).unwrap();
    let bytes = value.encode().unwrap();
    assert_eq!(
        &bytes[..16],
        &[0, 0, 0, 1, 0, 0, 0, 192, 0, 0, 0, 1, 0, 0, 0, 7]
    );
    assert_eq!(&bytes[16..24], &1u64.to_be_bytes());
    assert_eq!(&bytes[24..32], &41u64.to_be_bytes());
    assert_eq!(&bytes[48..56], &39u64.to_be_bytes());
    assert_eq!(&bytes[56..64], &[0, 0, 0, 23, 0, 0, 0, 0]);
    assert_eq!(NativeAdministrativeFacts::decode(&bytes).unwrap(), value);
}

#[test]
fn unknown_flags_reserved_fields_negative_slots_and_zero_identities_refuse() {
    let bytes = original().encode().unwrap();
    for offset in [3, 7, 11, 15, 63] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(NativeAdministrativeFacts::decode(&changed).is_err());
    }
    for offset in [16, 24, 32, 40, 48] {
        let mut changed = bytes;
        changed[offset..offset + 8].fill(0);
        assert!(NativeAdministrativeFacts::decode(&changed).is_err());
    }
    let mut changed = bytes;
    changed[56..60].copy_from_slice(&(-1i32).to_be_bytes());
    assert!(NativeAdministrativeFacts::decode(&changed).is_err());
    for end in 0..192 {
        assert!(NativeAdministrativeFacts::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(NativeAdministrativeFacts::decode(&trailing).is_err());
}

#[test]
fn differing_scope_realize_policy_role_or_endpoint_cannot_match_original_preparation() {
    let preparation = super::super::administrative_preparation::test_preparation();
    for field in 0..7 {
        let mut changed = original();
        match field {
            0 => changed.prepared_scope_hash[0] ^= 1,
            1 => changed.role_commitment[0] ^= 1,
            2 => changed.realize_request_digest[0] ^= 1,
            3 => changed.policy_digest[0] ^= 1,
            4 => changed.descriptor_slot += 1,
            5 => changed.socket_device = U64::new(11),
            _ => changed.socket_inode = U64::new(37),
        }
        assert!(changed.validate_against(&preparation).is_err());
    }
}
