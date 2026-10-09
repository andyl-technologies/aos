//! Golden and hostile packet DATA checks, without owner or signer fixtures.
//!
//! The claim tuple matches the existing Source-genesis fixture. Signature
//! bytes deliberately remain zero: structural decoding is not authentication.

use super::*;

fn legacy_packet() -> [u8; PROJECT_AUTHORIZATION_SOURCE_BYTES_V2] {
    let mut bytes = [0; PROJECT_AUTHORIZATION_SOURCE_BYTES_V2];
    bytes[..8].copy_from_slice(b"AOSPSC02");
    bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
    bytes[12..20].copy_from_slice(&8_u64.to_be_bytes());
    bytes[20..36].fill(1);
    bytes[36..44].copy_from_slice(&5_u64.to_be_bytes());
    bytes[44..76].fill(2);
    bytes[76..108].fill(6);
    bytes[108..124].fill(4);
    bytes[124..132].copy_from_slice(&9_u64.to_be_bytes());
    for (index, limit) in [1_u32, 8, 7, 6, 5, 4, 3].into_iter().enumerate() {
        bytes[132 + index * 4..136 + index * 4].copy_from_slice(&limit.to_be_bytes());
    }
    bytes
}

fn resource_packet() -> [u8; PROJECT_AUTHORIZATION_SOURCE_BYTES_V3] {
    let mut bytes = [0; PROJECT_AUTHORIZATION_SOURCE_BYTES_V3];
    bytes[..160].copy_from_slice(&legacy_packet()[..160]);
    bytes[..8].copy_from_slice(b"AOSPSC03");
    bytes[8..10].copy_from_slice(&3_u16.to_be_bytes());
    for index in 0..ResourceDimension::COUNT {
        bytes[160 + index * 8..168 + index * 8]
            .copy_from_slice(&(index as u64).to_be_bytes());
    }
    bytes
}

fn assert_common_claims(claims: &UnverifiedProjectAuthorizationClaimsV2) {
    assert_eq!(claims.project(), ProjectId::from_bytes([1; 16]));
    assert_eq!(claims.limits(), TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap());
    assert_eq!(claims.issuer_generation(), 8);
    assert_eq!(claims.publisher_generation(), 5);
    assert_eq!(
        claims.publisher_head_digest(),
        ObjectDigest::from_bytes([2; 32]),
    );
    assert_eq!(
        claims.publisher_revision_digest(),
        ObjectDigest::from_bytes([6; 32]),
    );
    assert_eq!(claims.request_id(), [4; 16]);
    assert_eq!(claims.epoch(), 9);
}

#[test]
fn psc02_golden_claims_width_and_packet_domain_remain_exact() {
    let bytes = legacy_packet();
    let claims = parse_unverified_project_authorization_claims_v2(&bytes).unwrap();

    assert_eq!(bytes.len(), 224);
    assert_eq!(packet_body_bytes(&bytes).unwrap(), 160);
    assert_common_claims(&claims);
    assert_eq!(claims.resource_envelope(), None);
    assert_eq!(
        project_authorization_packet_digest(&bytes).unwrap(),
        ObjectDigest::from_bytes([
            58, 48, 3, 187, 212, 24, 245, 41, 41, 208, 96, 189, 155, 114, 182, 244,
            190, 185, 230, 232, 207, 48, 229, 24, 72, 124, 141, 250, 243, 97, 116, 183,
        ]),
    );
}

#[test]
fn psc03_golden_preserves_every_resource_dimension_and_its_distinct_domain() {
    let bytes = resource_packet();
    let claims = parse_unverified_project_authorization_claims_v2(&bytes).unwrap();
    let resources = claims.resource_envelope().unwrap();

    assert_eq!(bytes.len(), 400);
    assert_eq!(packet_body_bytes(&bytes).unwrap(), 336);
    assert_common_claims(&claims);
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        assert_eq!(resources.get(dimension), index as u64);
    }
    assert_eq!(
        project_authorization_packet_digest(&bytes).unwrap(),
        ObjectDigest::from_bytes([
            157, 64, 105, 239, 220, 136, 151, 19, 118, 186, 223, 41, 124, 244, 118, 3,
            171, 47, 247, 143, 103, 223, 89, 108, 80, 139, 232, 202, 140, 90, 66, 205,
        ]),
    );
}

#[test]
fn packet_recipes_reject_truncation_padding_foreign_magic_and_mixed_versions() {
    let legacy = legacy_packet();
    for length in 0..=401 {
        if length == legacy.len() {
            continue;
        }
        let mut bytes = legacy.to_vec();
        bytes.resize(length, 0);
        assert_eq!(
            parse_unverified_project_authorization_claims_v2(&bytes),
            Err(ProjectAuthorizationSourceDataErrorV2::NonCanonical),
        );
    }

    for offset in [0, 8, 9, 10, 11] {
        for original in [legacy.to_vec(), resource_packet().to_vec()] {
            let mut bytes = original;
            bytes[offset] ^= 1;
            assert!(parse_unverified_project_authorization_claims_v2(&bytes).is_err());
        }
    }
    let mut rejected_legacy = legacy;
    rejected_legacy[..8].copy_from_slice(b"AOSPSC01");
    assert!(parse_unverified_project_authorization_claims_v2(&rejected_legacy).is_err());
}

#[test]
fn sentinel_claims_and_each_excessive_tree_ceiling_are_rejected() {
    for original in [legacy_packet().to_vec(), resource_packet().to_vec()] {
        for (start, end) in [
            (12, 20), (20, 36), (36, 44), (44, 76), (76, 108), (108, 124), (124, 132),
        ] {
            let mut bytes = original.clone();
            bytes[start..end].fill(0);
            assert!(parse_unverified_project_authorization_claims_v2(&bytes).is_err());
        }
        for index in 0..7 {
            let mut bytes = original.clone();
            bytes[132 + index * 4..136 + index * 4]
                .copy_from_slice(&65_537_u32.to_be_bytes());
            assert!(parse_unverified_project_authorization_claims_v2(&bytes).is_err());
        }
    }
}

#[test]
fn inconsistent_tree_shapes_are_rejected_but_disabled_classes_remain_valid_data() {
    for (offset, value) in [
        (132, 9_u32), (140, 9), (144, 8), (148, 8), (152, 8), (156, 5),
    ] {
        let mut bytes = legacy_packet();
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(parse_unverified_project_authorization_claims_v2(&bytes).is_err());
    }

    let mut bytes = resource_packet();
    bytes[132..336].fill(0);
    let claims = parse_unverified_project_authorization_claims_v2(&bytes).unwrap();
    assert_eq!(claims.limits(), TreeLimitsV1::new(0, 0, 0, 0, 0, 0, 0).unwrap());
    assert_eq!(
        claims.resource_envelope(),
        Some(ResourceVector::new([0; ResourceDimension::COUNT])),
    );
}

#[test]
fn signature_bytes_are_unverified_data_but_remain_part_of_the_packet_commitment() {
    for mut bytes in [legacy_packet().to_vec(), resource_packet().to_vec()] {
        let claims = parse_unverified_project_authorization_claims_v2(&bytes).unwrap();
        let digest = project_authorization_packet_digest(&bytes).unwrap();
        let body_bytes = packet_body_bytes(&bytes).unwrap();
        bytes[body_bytes..].fill(0xff);

        assert_eq!(
            parse_unverified_project_authorization_claims_v2(&bytes).unwrap(),
            claims,
        );
        assert_ne!(project_authorization_packet_digest(&bytes).unwrap(), digest);
    }
}

#[test]
fn packet_commitment_selects_framing_only_without_adding_claim_or_signature_authority() {
    let mut bytes = legacy_packet();
    bytes[12..20].fill(0);

    assert!(parse_unverified_project_authorization_claims_v2(&bytes).is_err());
    assert!(packet_body_bytes(&bytes).is_ok());
    assert!(project_authorization_packet_digest(&bytes).is_ok());
}
