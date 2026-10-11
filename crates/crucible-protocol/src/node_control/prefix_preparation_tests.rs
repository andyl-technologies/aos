//! Complete prefix ancestry, exact native extents and closed decoder controls.

// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::node_control::{
    NativeAdministrativePreparation, NativeFixedMicrovmMapping, NativeFixedMicrovmPreparation,
    NativeInitializationPreparation, NativePhaseMapping, NativePhasePreparation, NativePreparation,
    OwnerScope,
};
use crucible_node_contract::{HashRef, Id, Phase, Position, U64};

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

fn prefix() -> NativePrefixPreparation {
    NativePrefixPreparation {
        original_effect: preparation(),
        policy_digest: [61; 32],
        maximum_prefixes: 8,
    }
}

#[test]
fn complete_prefix_retains_unchanged_ancestor_and_closed_native_fields() {
    let original = prefix();
    let ancestor = original.original_effect.encode().unwrap();
    let encoded = original.encode().unwrap();
    assert_eq!(&encoded[12..12 + ancestor.len()], ancestor);
    assert_eq!(NativePrefixPreparation::decode(&encoded).unwrap(), original);

    let early = original.early_pin().unwrap();
    assert_eq!(&early[..192], original.original_effect.early_pin().unwrap());
    assert_eq!(&early[192..224], original.identity_digest().unwrap());
    assert_eq!(&early[224..256], original.policy_digest);
    assert_eq!(&early[256..264], &[9, 0, 0, 0, 8, 0, 0, 0]);

    let native = original.native_policy().unwrap();
    assert_eq!(&native[..8], &[1, 0, 0, 0, 24, 1, 0, 0]);
    assert_eq!(
        &native[8..208],
        original.original_effect.native_policy().unwrap()
    );
    assert_eq!(&native[208..], &early[192..]);
    assert_eq!(original.early_launch_argument().unwrap().len(), 531);
}

#[test]
fn prefix_commitment_covers_actual_ancestor_and_every_new_policy_field() {
    let original = prefix();
    let digest = original.identity_digest().unwrap();
    let original_ancestor = original.original_effect.identity_digest().unwrap();
    assert_ne!(digest, original_ancestor);

    let mut changed = original.clone();
    changed.maximum_prefixes += 1;
    assert_ne!(changed.identity_digest().unwrap(), digest);
    assert_eq!(
        changed.original_effect.identity_digest().unwrap(),
        original_ancestor
    );

    changed = original.clone();
    changed.policy_digest[0] ^= 1;
    assert_ne!(changed.identity_digest().unwrap(), digest);
    changed = original.clone();
    changed.original_effect.original_root.seed = U64::new(8255);
    assert_ne!(changed.identity_digest().unwrap(), digest);
}

#[test]
fn prefix_decoder_refuses_unknown_tag_truncation_trailing_and_unbounded_journal() {
    let original = prefix();
    let encoded = original.encode().unwrap();
    for length in 0..encoded.len() {
        assert!(NativePrefixPreparation::decode(&encoded[..length]).is_err());
    }
    let mut changed = encoded.clone();
    changed.push(0);
    assert!(NativePrefixPreparation::decode(&changed).is_err());
    changed = encoded.clone();
    changed[0] ^= 1;
    assert!(NativePrefixPreparation::decode(&changed).is_err());
    changed = encoded.clone();
    changed[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NativePrefixPreparation::decode(&changed).is_err());

    for maximum_prefixes in [0, 1, 65, u32::MAX] {
        let mut changed = original.clone();
        changed.maximum_prefixes = maximum_prefixes;
        assert!(changed.validate().is_err());
        let mut bytes = encoded.clone();
        let end = bytes.len();
        bytes[end - 4..].copy_from_slice(&maximum_prefixes.to_be_bytes());
        assert!(NativePrefixPreparation::decode(&bytes).is_err());
    }
    let mut changed = original;
    changed.policy_digest = [0; 32];
    assert!(changed.validate().is_err());
}

#[test]
fn prefix_preparation_is_not_an_ancestor_preparation_or_partial_pin() {
    let original = prefix();
    assert!(NativePrefixPreparation::decode(&original.original_effect.encode().unwrap()).is_err());
    assert!(NativeEffectPreparation::decode(&original.encode().unwrap()).is_err());
    assert!(NativePrefixPreparation::decode(&original.early_pin().unwrap()).is_err());
    assert!(NativePrefixPreparation::decode(&original.native_policy().unwrap()).is_err());
}

#[test]
fn continuation_preparation_accepts_both_closed_prefix_cap_endpoints() {
    for maximum_prefixes in [2, 64] {
        let mut original = prefix();
        original.maximum_prefixes = maximum_prefixes;
        let encoded = original.encode().unwrap();
        assert_eq!(NativePrefixPreparation::decode(&encoded).unwrap(), original);
    }
}

#[test]
fn complete_prefix_frame_refuses_ancestor_preparation_as_a_selector() {
    use crate::node_control::{
        NativeControlEdition, NativeFrame, decode_frame_for_edition, encode_frame_for_edition,
    };

    let preparation = prefix();
    let original_ancestor =
        NativeFrame::PrepareEffect(Box::new(preparation.original_effect.clone()));
    let frame = NativeFrame::PreparePrefix(Box::new(preparation));
    let bytes = encode_frame_for_edition(NativeControlEdition::PrefixEffect, &frame).unwrap();

    assert_eq!(
        decode_frame_for_edition(NativeControlEdition::PrefixEffect, &bytes).unwrap(),
        frame
    );
    assert!(encode_frame_for_edition(NativeControlEdition::FiniteEffect, &frame).is_err());
    assert!(
        encode_frame_for_edition(NativeControlEdition::PrefixEffect, &original_ancestor).is_err()
    );
    let mut ancestor_bytes =
        encode_frame_for_edition(NativeControlEdition::FiniteEffect, &original_ancestor).unwrap();
    ancestor_bytes[8..10].copy_from_slice(&9u16.to_be_bytes());
    assert!(decode_frame_for_edition(NativeControlEdition::PrefixEffect, &ancestor_bytes).is_err());
}
