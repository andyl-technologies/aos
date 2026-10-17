//! Complete prefix ancestry, exact native extents and closed decoder controls.

// SPDX-License-Identifier: Apache-2.0

// crucible-lint: allow rust-allow -- This cfg(test) module deliberately panics on malformed codec assertions.
// crucible-lint: allow panic-shortcut -- Original-field model fixtures and assertions must fail the test on errors.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_control::{
    NativeAdministrativePreparation, NativeFixedMicrovmMapping, NativeFixedMicrovmPreparation,
    NativeInitializationPreparation, NativePhaseMapping, NativePhasePreparation, NativePreparation,
    OwnerScope,
};
use crate::node_control::{NativeEffectPreparation, NativeInitializationStatus};
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

fn observation() -> NativePrefixPreparationObservation {
    let preparation = prefix();
    let original = &preparation
        .original_effect
        .original_root
        .administration
        .phase
        .initialization;
    let receipt = NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 1,
        sequence: U64::new(1),
        hold_generation: U64::new(4),
        prepared_scope_hash: original.preparation.scope.identity_digest().unwrap(),
        initialization_commitment: original.identity_digest().unwrap(),
        original_cut_digest: [71; 32],
        realize_request_digest: original.realize_request_digest,
    };
    NativePrefixPreparationObservation {
        preparation,
        initialization: receipt,
        initial: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        epoch_incarnation: U64::new(1),
        cpu_incarnation: U64::new(26),
        next_cpu_deadline_ps: U64::new(50),
        first_timer: Some(NativePrefixPreparationTimer {
            timer_id: U64::new(5),
            list_id: U64::new(1),
            arm_generation: U64::new(1),
            evaluation: Position::new(U64::new(27_462_700_578), U64::new(0), Phase::Reaction),
        }),
    }
}

#[test]
fn original_precommand_facts_preserve_complete_companions_and_native_frontier() {
    let value = observation();
    let bytes = value.encode().unwrap();
    assert_eq!(
        NativePrefixPreparationObservation::decode(
            &bytes,
            &value.preparation,
            &value.initialization
        )
        .unwrap(),
        value
    );
    assert_eq!(&bytes[272..280], &65_536u64.to_be_bytes());
    assert_eq!(&bytes[280..288], &(32 * 1024 * 1024u64).to_be_bytes());
    assert_eq!(&bytes[312..316], &2u32.to_be_bytes());
    assert_eq!(&bytes[316..320], &7u32.to_be_bytes());
    assert_eq!(&bytes[624..628], &3u32.to_be_bytes());
    assert_ne!(
        value.identity_digest().unwrap(),
        value.preparation.identity_digest().unwrap()
    );
}

#[test]
fn changed_original_pins_or_receipt_never_decode_as_the_original_preparation() {
    let value = observation();
    let bytes = value.encode().unwrap();
    for index in 8..552 {
        let mut changed = bytes;
        changed[index] ^= 1;
        assert!(
            NativePrefixPreparationObservation::decode(
                &changed,
                &value.preparation,
                &value.initialization
            )
            .is_err(),
            "index={index}"
        );
    }
    for length in 0..640 {
        assert!(
            NativePrefixPreparationObservation::decode(
                &bytes[..length],
                &value.preparation,
                &value.initialization
            )
            .is_err()
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(
        NativePrefixPreparationObservation::decode(
            &trailing,
            &value.preparation,
            &value.initialization
        )
        .is_err()
    );
}

#[test]
fn later_stop_and_open_frontier_cannot_replace_initial_evidence() {
    let value = observation();
    let bytes = value.encode().unwrap();
    for index in [0, 4, 496, 504, 512, 560, 616, 624, 628, 632, 636] {
        let mut changed = bytes;
        changed[index..index + 4].fill(0xff);
        assert!(
            NativePrefixPreparationObservation::decode(
                &changed,
                &value.preparation,
                &value.initialization
            )
            .is_err(),
            "index={index}"
        );
    }
    for index in [552, 568, 576, 584, 592, 600] {
        let mut changed = bytes;
        changed[index..index + 8].fill(0);
        assert!(
            NativePrefixPreparationObservation::decode(
                &changed,
                &value.preparation,
                &value.initialization
            )
            .is_err(),
            "index={index}"
        );
    }
    let mut absent = value;
    absent.first_timer = None;
    assert_eq!(
        NativePrefixPreparationObservation::decode(
            &absent.encode().unwrap(),
            &absent.preparation,
            &absent.initialization
        )
        .unwrap(),
        absent
    );
}

#[test]
fn offered_initial_ack_correlates_every_original_byte_without_consumption_claim() {
    use crate::node_control::NativePrefixPreparationAcknowledgement;
    let observation = observation();
    let ack = NativePrefixPreparationAcknowledgement::from_original(&observation).unwrap();
    let bytes = ack.encode().unwrap();
    assert_eq!(
        NativePrefixPreparationAcknowledgement::decode(&bytes, &observation).unwrap(),
        ack
    );
    assert_eq!(&bytes[152..160], &1u64.to_be_bytes());
    for index in 0..160 {
        let mut changed = bytes;
        changed[index] ^= 1;
        assert!(NativePrefixPreparationAcknowledgement::decode(&changed, &observation).is_err());
    }
    for length in 0..160 {
        assert!(
            NativePrefixPreparationAcknowledgement::decode(&bytes[..length], &observation).is_err()
        );
    }
    let mut foreign = observation.clone();
    foreign.epoch_incarnation = U64::new(2);
    assert!(NativePrefixPreparationAcknowledgement::decode(&bytes, &foreign).is_err());
}

#[test]
fn initial_contract_frames_preserve_canonical_bodies_and_refuse_older_editions() {
    use super::super::{
        NativeControlEdition, NativeFrame, NativePrefixPreparationAcknowledgement,
        NativePrefixPreparationFacts, decode_frame_for_edition, encode_frame_for_edition,
    };
    let original = observation();
    let facts = NativePrefixPreparationFacts::decode(&original.encode().unwrap()).unwrap();
    let ack = NativePrefixPreparationAcknowledgement::from_original(&original).unwrap();
    let frames = [
        NativeFrame::QueryPrefixPreparation {
            scope: ack.scope,
            prefix_preparation: ack.prefix_preparation,
        },
        NativeFrame::PrefixPreparationFacts(Box::new(facts.clone())),
        NativeFrame::AcknowledgePrefixPreparation(ack.clone()),
        NativeFrame::PrefixPreparationAcknowledged(ack.clone()),
    ];

    for (index, frame) in frames.iter().enumerate() {
        let bytes = encode_frame_for_edition(NativeControlEdition::PrefixEffect, frame).unwrap();
        assert_eq!(&bytes[10..12], &(38u16 + index as u16).to_be_bytes());
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::PrefixEffect, &bytes).unwrap(),
            *frame
        );
        assert!(encode_frame_for_edition(NativeControlEdition::FiniteEffect, frame).is_err());
        for length in 0..bytes.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::PrefixEffect, &bytes[..length])
                    .is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_frame_for_edition(NativeControlEdition::PrefixEffect, &trailing).is_err());
    }
    assert_eq!(
        facts
            .observe_original(&original.preparation, &original.initialization)
            .unwrap(),
        original
    );
    assert_eq!(
        NativePrefixPreparationAcknowledgement::decode_record(&ack.encode().unwrap()).unwrap(),
        ack
    );
}

#[test]
fn framing_validity_does_not_adopt_changed_original_initialization_or_prefix() {
    use super::super::NativePrefixPreparationFacts;
    let original = observation();
    let bytes = original.encode().unwrap();

    let mut changed = bytes;
    changed[520] ^= 1;
    let uncorrelated = NativePrefixPreparationFacts::decode(&changed).unwrap();
    assert!(
        uncorrelated
            .observe_original(&original.preparation, &original.initialization)
            .is_err()
    );

    for offset in [
        0, 8, 312, 332, 344, 496, 552, 560, 568, 576, 616, 624, 628, 632, 636,
    ] {
        let mut changed = bytes;
        if [552, 568, 576].contains(&offset) {
            changed[offset..offset + 8].fill(0);
        } else {
            changed[offset] ^= 1;
        }
        assert!(
            NativePrefixPreparationFacts::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
}
