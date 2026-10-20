//! UNRUN literal preimage and closed service-role separation vectors.

use super::*;

#[test]
fn service_binding_matches_independently_assembled_fixed_preimage() {
    for (role, code, unit_length, unit) in [
        (CreateFailureServiceRoleV1::Controller, 1, 20_u16, b"aos-sandboxd.service".as_slice()),
        (CreateFailureServiceRoleV1::Host, 2, 25_u16, b"aos-sandbox-hostd.service".as_slice()),
        (CreateFailureServiceRoleV1::Root, 3, 37_u16, b"aos-sandbox-policy-authorityd.service".as_slice()),
    ] {
        let mut preimage = b"aos.sandbox.create-failure.service-owner-binding.v1\0".to_vec();
        preimage.extend_from_slice(&[0, 1, code]);
        preimage.extend_from_slice(&[0x21; 16]);
        preimage.extend_from_slice(&[0x43; 16]);
        preimage.extend_from_slice(&34_u16.to_be_bytes());
        preimage.extend_from_slice(b"root-policy-failed-create-floor-v1");
        preimage.extend_from_slice(&unit_length.to_be_bytes());
        preimage.extend_from_slice(unit);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(canonical_create_failure_service_binding_v1(role, [0x21; 16],
            [0x43; 16]).unwrap(), expected);
    }
}

#[test]
fn role_node_and_epoch_are_independent_bindings() {
    let controller = canonical_create_failure_service_binding_v1(
        CreateFailureServiceRoleV1::Controller, [1; 16], [2; 16]).unwrap();

    for (role, node, epoch) in [
        (CreateFailureServiceRoleV1::Host, [1; 16], [2; 16]),
        (CreateFailureServiceRoleV1::Root, [1; 16], [2; 16]),
        (CreateFailureServiceRoleV1::Controller, [3; 16], [2; 16]),
        (CreateFailureServiceRoleV1::Controller, [1; 16], [3; 16]),
    ] {
        assert_ne!(canonical_create_failure_service_binding_v1(role, node, epoch).unwrap(),
            controller);
    }
}

#[test]
fn zero_node_or_epoch_never_chooses_a_legacy_role() {
    for role in [CreateFailureServiceRoleV1::Controller, CreateFailureServiceRoleV1::Host,
        CreateFailureServiceRoleV1::Root]
    {
        assert!(canonical_create_failure_service_binding_v1(role, [0; 16], [1; 16]).is_err());
        assert!(canonical_create_failure_service_binding_v1(role, [1; 16], [0; 16]).is_err());
    }
}

#[test]
fn service_binding_is_not_a_target_assignment_or_an_unframed_hash() {
    let actual = canonical_create_failure_service_binding_v1(
        CreateFailureServiceRoleV1::Host, [1; 16], [2; 16]).unwrap();
    let target_assignment = [0x77; 32];
    let unframed: [u8; 32] = Sha256::new().chain_update([1; 16])
        .chain_update([2; 16]).chain_update(b"aos-sandbox-hostd.service").finalize().into();

    assert_ne!(actual, target_assignment);
    assert_ne!(actual, unframed);
}
