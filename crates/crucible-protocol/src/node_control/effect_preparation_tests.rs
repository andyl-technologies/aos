//! Closed complete companion and exact native200 byte tests, without source authority.

// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::node_control::{
    NativeAdministrativePreparation, NativeFixedMicrovmMapping, NativeInitializationPreparation,
    NativePhaseMapping, NativePhasePreparation, NativePreparation, OwnerScope,
};
use crucible_node_contract::{HashRef, Id, Phase, Position};

fn initialization() -> NativeInitializationPreparation {
    NativeInitializationPreparation {
        preparation: NativePreparation {
            scope: OwnerScope {
                session: Id::new("session/model").unwrap(),
                incarnation: Id::new("incarnation/model").unwrap(),
                activation: Id::new("activation/model").unwrap(),
                node: Id::new("node/model").unwrap(),
                owner: Id::new("owner/model").unwrap(),
                world_generation: U64::new(1),
                owner_generation: U64::new(1),
                world_binding: HashRef {
                    algorithm: "blake3-256".into(),
                    domain: "cnp.world-binding.v1".into(),
                    digest: "01".repeat(32),
                },
                owner_binding: HashRef {
                    algorithm: "blake3-256".into(),
                    domain: "cnp.owner-binding.v1".into(),
                    digest: "02".repeat(32),
                },
            },
            boundary: Position {
                time_ps: U64::new(0),
                microstep: U64::new(0),
                phase: Phase::BoundaryControl,
            },
            maximum_commands: U64::new(4),
        },
        realize_operation: Id::new("operation/realize-model").unwrap(),
        realize_request_digest: [3; 32],
        policy_digest: [4; 32],
        class_mask: 7,
        maximum_callbacks: 64,
    }
}

fn preparation() -> NativeEffectPreparation {
    let root = NativeFixedMicrovmPreparation {
        administration: NativeAdministrativePreparation {
            phase: NativePhasePreparation {
                initialization: initialization(),
                policy_digest: [8; 32],
                mapping: NativePhaseMapping::InstructionReaction,
                maximum_microstep: U64::new(1024),
            },
            policy_digest: [9; 32],
            descriptor_slot: 23,
            socket_device: 9,
            socket_inode: 31,
        },
        policy_digest: [19; 32],
        firmware_sha256: [37; 32],
        firmware_length: U64::new(64 * 1024),
        ram_length: U64::new(32 * 1024 * 1024),
        seed: U64::new(8254),
        maximum_microstep: U64::new(1024),
        maximum_service_span: U64::new(1_000_000),
        mapping: NativeFixedMicrovmMapping::InstructionThenTimers,
        maximum_callbacks: 64,
    };
    NativeEffectPreparation {
        original_root: root,
        policy_digest: [41; 32],
        maximum_callbacks: 32,
        maximum_service_span: U64::new(500_000),
    }
}

#[test]
fn original_root_bytes_and_native200_offsets_remain_exact() {
    let original = preparation();
    let ancestor_bytes = original.original_root.encode().unwrap();
    let encoded = original.encode().unwrap();
    assert_eq!(&encoded[12..12 + ancestor_bytes.len()], ancestor_bytes);
    assert_eq!(NativeEffectPreparation::decode(&encoded).unwrap(), original);
    let native = original.native_policy().unwrap();
    assert_eq!(&native[..8], &[1, 0, 0, 0, 200, 0, 0, 0]);
    assert_eq!(
        &native[8..40],
        &original
            .original_root
            .administration
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap()
    );
    assert_eq!(&native[40..72], &original.identity_digest().unwrap());
    assert_eq!(
        &native[72..104],
        &original
            .original_root
            .administration
            .phase
            .initialization
            .realize_request_digest
    );
    assert_eq!(&native[104..136], &original.policy_digest);
    assert_eq!(
        &native[136..168],
        &original.original_root.identity_digest().unwrap()
    );
    assert_eq!(
        &native[168..184],
        &[3, 0, 0, 0, 8, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&native[184..192], &1024u64.to_le_bytes());
    assert_eq!(&native[192..200], &500_000u64.to_le_bytes());
    let argument = original.early_launch_argument().unwrap();
    assert_eq!(argument.len(), 387);
    assert!(argument.starts_with("v1:"));
    assert!(
        argument[3..]
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    );
    assert_eq!(
        original.original_root.native_policy().unwrap()[304..308],
        2u32.to_le_bytes()
    );
}

#[test]
fn every_truncated_trailing_and_hostile_length_record_is_refused() {
    let bytes = preparation().encode().unwrap();
    for length in 0..bytes.len() {
        assert!(NativeEffectPreparation::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(NativeEffectPreparation::decode(&trailing).is_err());
    let mut extent = bytes;
    extent[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NativeEffectPreparation::decode(&extent).is_err());
}

#[test]
fn ancestor_budgets_cannot_be_widened_or_rebound() {
    let original = preparation();
    for callbacks in [0, 65, u32::MAX] {
        let mut changed = original.clone();
        changed.maximum_callbacks = callbacks;
        assert!(changed.native_policy().is_err());
    }
    for span in [0, 1_000_001, u64::MAX] {
        let mut changed = original.clone();
        changed.maximum_service_span = U64::new(span);
        assert!(changed.native_policy().is_err());
    }
    let mut changed = original;
    changed.original_root.maximum_microstep = U64::new(512);
    assert!(changed.native_policy().is_err());
}

#[test]
fn full_realize_root_and_every_effect_field_contribute_to_identity() {
    let original = preparation();
    let original_digest = original.identity_digest().unwrap();
    for field in 0..7 {
        let mut changed = original.clone();
        match field {
            0 => changed.policy_digest[0] ^= 1,
            1 => changed.maximum_callbacks = 31,
            2 => changed.maximum_service_span = U64::new(400_000),
            3 => {
                changed
                    .original_root
                    .administration
                    .phase
                    .initialization
                    .realize_request_digest[0] ^= 1
            }
            4 => {
                changed
                    .original_root
                    .administration
                    .phase
                    .initialization
                    .realize_operation = Id::new("operation/other-original").unwrap()
            }
            5 => changed.original_root.firmware_sha256[0] ^= 1,
            _ => changed.original_root.administration.socket_inode += 1,
        }
        assert_ne!(changed.identity_digest().unwrap(), original_digest);
    }
}
