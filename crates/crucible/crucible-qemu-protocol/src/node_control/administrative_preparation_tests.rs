//! Raw observed-role pin tests, without native registration or readiness claims.

// crucible-lint: allow panic-shortcut -- These administrative preparation tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;

fn original() -> NativeAdministrativePreparation {
    super::test_preparation()
}

#[test]
fn original_companion_and_actual_endpoint_identity_have_fixed_closed_bytes() {
    let value = original();
    let phase = value.phase.encode().unwrap();
    let bytes = value.encode().unwrap();
    assert_eq!(&bytes[..8], MAGIC);
    assert_eq!(&bytes[8..12], &(phase.len() as u32).to_be_bytes());
    assert_eq!(&bytes[12..12 + phase.len()], phase);
    assert_eq!(bytes.len(), 64 + phase.len());
    assert_eq!(
        NativeAdministrativePreparation::decode(&bytes).unwrap(),
        value
    );

    let pin = value.early_pin().unwrap();
    assert_eq!(
        &pin[..32],
        &value
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap()
    );
    assert_eq!(&pin[32..64], &value.identity_digest().unwrap());
    assert_eq!(
        &pin[64..96],
        &value.phase.initialization.realize_request_digest
    );
    assert_eq!(&pin[96..128], &[7; 32]);
    assert_eq!(
        &pin[128..144],
        &[1, 0, 0, 0, 1, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&pin[144..152], &9u64.to_le_bytes());
    assert_eq!(&pin[152..160], &31u64.to_le_bytes());
    let argument = value.early_launch_argument().unwrap();
    assert_eq!(argument.len(), 323);
    assert!(argument.starts_with("v1:"));
    assert!(
        argument[3..]
            .bytes()
            .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
    );
}

#[test]
fn every_truncation_extra_byte_and_oversized_claim_is_refused_before_adoption() {
    let bytes = original().encode().unwrap();
    for end in 0..bytes.len() {
        assert!(NativeAdministrativePreparation::decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(NativeAdministrativePreparation::decode(&extra).is_err());
    let mut claim = bytes;
    claim[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NativeAdministrativePreparation::decode(&claim).is_err());
    assert!(NativeAdministrativePreparation::decode(&vec![0; 4097]).is_err());
}

#[test]
fn changed_original_scope_policy_realize_or_socket_changes_role_commitment() {
    let original = original();
    let expected = original.identity_digest().unwrap();
    for field in 0..6 {
        let mut changed = original.clone();
        match field {
            0 => changed.descriptor_slot += 1,
            1 => changed.socket_device += 1,
            2 => changed.socket_inode += 1,
            3 => changed.policy_digest[0] ^= 1,
            4 => changed.phase.initialization.realize_request_digest[0] ^= 1,
            _ => changed.phase.policy_digest[0] ^= 1,
        }
        assert_ne!(changed.identity_digest().unwrap(), expected);
    }
    for field in 0..5 {
        let mut invalid = original.clone();
        match field {
            0 => invalid.descriptor_slot = -1,
            1 => invalid.descriptor_slot = 2,
            2 => invalid.socket_device = 0,
            3 => invalid.socket_inode = 0,
            _ => invalid.policy_digest = [0; 32],
        }
        assert!(invalid.encode().is_err());
    }
}
