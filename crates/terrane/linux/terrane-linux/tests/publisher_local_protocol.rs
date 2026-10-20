//! Checks the closed publisher protocol before any native effect.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use prost::Message;
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_linux::publisher_local::{
    validation::{MAX_PACKET, ValidationPolicy, decode_packet, validate_packet},
    wire::{BodyKey, BodyKind, Claim, Operation, Packet},
};

fn policy() -> ValidationPolicy<'static> {
    ValidationPolicy {
        domain: "public",
        identity: &TERRANE_V1,
        chunk_profile: "cdc-1m",
    }
}

fn probe() -> Packet {
    Packet {
        version: 1,
        request_id: 1,
        operation: Operation::Probe as i32,
        domain: "public".into(),
        cache_incarnation: vec![7; 16],
        wait_budget_ms: 100,
        ..Packet::default()
    }
}

fn publish(manifest: bool) -> Packet {
    let bytes = b"fixture";
    let identity = TERRANE_V1
        .calculate(
            if manifest {
                IdentityKind::Manifest
            } else {
                IdentityKind::Chunk
            },
            bytes,
        )
        .unwrap();
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, bytes)
        .unwrap()
        .encode();
    Packet {
        operation: Operation::Publish as i32,
        claim: Some(Claim {
            descriptor: descriptor.clone(),
            chunk_profile: "cdc-1m".into(),
            plaintext_size: bytes.len() as u64,
            manifest_offset: 0,
            manifest_length: if manifest { bytes.len() as u64 } else { 0 },
            retention_id: if manifest { vec![9; 16] } else { Vec::new() },
        }),
        body: Some(BodyKey {
            kind: BodyKind::Sealed as i32,
            descriptor,
            ..BodyKey::default()
        }),
        ..probe()
    }
}

#[test]
fn registered_probe_roundtrips_without_descriptors() {
    let response = Packet {
        response: true,
        wait_budget_ms: 0,
        verity_algorithm: 1,
        verity_digest: vec![1; 32],
        ..probe()
    };
    assert!(validate_packet(&response, 1, true, &policy()).is_ok());
    assert!(validate_packet(&response, 0, true, &policy()).is_err());
    assert!(
        validate_packet(
            &Packet {
                verity_digest: vec![1; 31],
                ..response
            },
            1,
            true,
            &policy()
        )
        .is_err()
    );

    let packet = probe();
    assert_eq!(
        decode_packet(&packet.encode_to_vec(), 0, false, &policy()).unwrap(),
        packet
    );
}

#[test]
fn unknown_fields_fail_at_every_message_depth() {
    for suffix in [
        vec![0x80, 0x01, 0],
        vec![0x3a, 2, 0x38, 0],
        vec![0x42, 2, 0x28, 0],
    ] {
        let mut packet = probe().encode_to_vec();
        packet.extend(suffix);
        assert!(decode_packet(&packet, 0, false, &policy()).is_err());
    }
}

#[test]
fn duplicate_singular_wrong_wire_and_boolean_fields_fail() {
    for suffix in [
        vec![8, 1],
        vec![0x0a, 0],
        vec![0x50, 2],
        vec![0x60, 0x80, 0x80, 0x80, 0x80, 0x10],
    ] {
        let mut packet = probe().encode_to_vec();
        packet.extend(suffix);
        assert!(decode_packet(&packet, 0, false, &policy()).is_err());
    }
}

#[test]
fn explicit_unexpected_default_fields_fail() {
    let mut packet = probe().encode_to_vec();
    packet.extend([0x58, 0]);
    assert!(decode_packet(&packet, 0, false, &policy()).is_err());
}

#[test]
fn payload_and_varint_bounds_fail_before_decode() {
    for packet in [
        vec![],
        vec![0; MAX_PACKET + 1],
        vec![0x80; 10],
        vec![0x22, 0xff, 0xff, 0xff, 0xff, 0x7f],
    ] {
        assert!(decode_packet(&packet, 0, false, &policy()).is_err());
    }
}

#[test]
fn publication_requires_exact_source_and_metadata_counts() {
    for manifest in [false, true] {
        let packet = publish(manifest);
        let expected = if manifest { 2 } else { 1 };
        for count in 0..=3 {
            assert_eq!(
                validate_packet(&packet, count, false, &policy()).is_ok(),
                count == expected,
                "manifest={manifest} count={count}"
            );
        }
    }
}

#[test]
fn claim_key_profile_and_retention_mismatches_fail() {
    let packet = publish(false);
    let mut changed = packet.clone();
    changed.claim.as_mut().unwrap().chunk_profile = "other-profile".into();
    assert!(validate_packet(&changed, 1, false, &policy()).is_err());

    changed = packet.clone();
    changed.claim.as_mut().unwrap().descriptor.push(0);
    assert!(validate_packet(&changed, 1, false, &policy()).is_err());

    changed = packet;
    changed.claim.as_mut().unwrap().retention_id = vec![4; 16];
    assert!(validate_packet(&changed, 1, false, &policy()).is_err());
}

#[test]
fn recovery_and_retirement_field_matrix_is_closed() {
    let pending = Packet {
        body: Some(BodyKey {
            kind: BodyKind::Pack as i32,
            pack_id: vec![2; 16],
            ..BodyKey::default()
        }),
        operation: Operation::InspectPending as i32,
        ..probe()
    };
    assert!(validate_packet(&pending, 0, false, &policy()).is_ok());
    assert!(validate_packet(&pending, 1, false, &policy()).is_err());
    let response = Packet {
        operation: Operation::InspectPending as i32,
        response: true,
        wait_budget_ms: 0,
        body_incarnation: vec![3; 32],
        ..probe()
    };
    assert!(validate_packet(&response, 0, true, &policy()).is_ok());
    assert!(validate_packet(&response, 1, true, &policy()).is_err());
    assert!(
        validate_packet(
            &Packet {
                verity_algorithm: 1,
                verity_digest: vec![1; 32],
                ..response
            },
            0,
            true,
            &policy()
        )
        .is_err()
    );
    for operation in [Operation::Drain, Operation::Resume, Operation::Inventory] {
        let packet = Packet {
            operation: operation as i32,
            ..probe()
        };
        assert!(validate_packet(&packet, 0, false, &policy()).is_ok());
        assert!(validate_packet(&packet, 1, false, &policy()).is_err());
    }
    for operation in [
        Operation::Retire,
        Operation::Restore,
        Operation::FinishRetirement,
    ] {
        let packet = Packet {
            operation: operation as i32,
            body: Some(BodyKey {
                kind: BodyKind::Pack as i32,
                pack_id: vec![2; 16],
                ..BodyKey::default()
            }),
            body_incarnation: vec![3; 32],
            ..probe()
        };
        assert!(validate_packet(&packet, 0, false, &policy()).is_ok());
        assert!(
            validate_packet(
                &Packet {
                    body_incarnation: vec![3; 31],
                    ..packet
                },
                0,
                false,
                &policy()
            )
            .is_err()
        );
    }
}

#[test]
fn error_responses_have_no_binding_token_or_descriptors() {
    let packet = Packet {
        response: true,
        wait_budget_ms: 0,
        result: 7,
        ..probe()
    };
    assert!(validate_packet(&packet, 0, true, &policy()).is_ok());
    assert!(validate_packet(&packet, 1, true, &policy()).is_err());
    assert!(
        validate_packet(
            &Packet {
                verity_algorithm: 1,
                verity_digest: vec![0; 32],
                ..packet
            },
            0,
            true,
            &policy()
        )
        .is_err()
    );
}

#[test]
fn header_direction_domain_version_and_budget_are_checked() {
    for changed in [
        Packet {
            version: 2,
            ..probe()
        },
        Packet {
            request_id: 0,
            ..probe()
        },
        Packet {
            operation: 99,
            ..probe()
        },
        Packet {
            domain: "private:other".into(),
            ..probe()
        },
        Packet {
            cache_incarnation: vec![0; 15],
            ..probe()
        },
        Packet {
            wait_budget_ms: 0,
            ..probe()
        },
        Packet {
            wait_budget_ms: 300_001,
            ..probe()
        },
        Packet {
            response: true,
            ..probe()
        },
    ] {
        assert!(validate_packet(&changed, 0, false, &policy()).is_err());
    }
}
