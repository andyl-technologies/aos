//! Adversarial source-birth data codecs; fixtures establish no native qualification.

// crucible-lint: allow panic-shortcut -- These phase timer tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::{Phase, Position, U64};

use super::{
    NativePhaseTimerArm, NativePhaseTimerObservation, NativeTimerBirth, NativeTimerParent,
};
use crate::node_control::{NativeTimerArm, NativeTimerList, NativeTimerObservation};

fn original() -> NativePhaseTimerObservation {
    let preparation = super::super::phase::test_preparation();
    let scope = preparation
        .initialization
        .preparation
        .scope
        .identity_digest()
        .unwrap();
    let births = [
        NativeTimerBirth::Unknown { parent: None },
        NativeTimerBirth::Unknown {
            parent: Some(NativeTimerParent {
                timer: U64::new(1),
                arm_generation: U64::new(1),
            }),
        },
        NativeTimerBirth::Construction {
            prepared_scope_hash: scope,
            initialization_commitment: preparation.initialization.identity_digest().unwrap(),
        },
        NativeTimerBirth::Reaction {
            position: Position::new(U64::new(9), U64::new(0), Phase::Reaction),
            prepared_scope_hash: scope,
            sequence: U64::new(3),
            command_digest: [6; 32],
        },
    ];
    NativePhaseTimerObservation {
        prepared_scope_hash: scope,
        sequence: U64::new(3),
        command_digest: [6; 32],
        current_ps: U64::new(10),
        mutation_generation: U64::new(7),
        gate_generation: U64::new(4),
        lists: vec![NativeTimerList {
            identity: U64::new(1),
            timer_count: 4,
            flags: 3,
        }],
        timers: births
            .into_iter()
            .enumerate()
            .map(|(index, birth)| NativePhaseTimerArm {
                arm: NativeTimerArm {
                    identity: U64::new(index as u64 + 1),
                    list: U64::new(1),
                    arm_generation: U64::new(index as u64 + 1),
                    expiry_ps: U64::new(20 + index as u64),
                    fifo_ordinal: U64::new(index as u64),
                    attributes: 0,
                    scale: 1,
                },
                birth,
            })
            .collect(),
    }
}

#[test]
fn fixed_rows_preserve_legacy_timer_prefix_and_closed_big_endian_birth_fields() {
    let observation = original();
    let encoded = observation.encode().unwrap();
    let legacy = NativeTimerObservation {
        prepared_scope_hash: observation.prepared_scope_hash,
        sequence: observation.sequence,
        command_digest: observation.command_digest,
        current_ps: observation.current_ps,
        mutation_generation: observation.mutation_generation,
        lists: observation.lists.clone(),
        timers: observation
            .timers
            .iter()
            .map(|timer| timer.arm.clone())
            .collect(),
    }
    .encode()
    .unwrap();

    assert_eq!(encoded.len(), 112 + 16 + 4 * 200);
    assert_eq!(
        &encoded[..16],
        &[0, 0, 0, 1, 0, 0, 0, 112, 0, 0, 0, 1, 0, 0, 0, 4]
    );
    assert_eq!(&encoded[32..40], &4u64.to_be_bytes());
    for row in 0..4 {
        assert_eq!(
            &encoded[128 + row * 200..176 + row * 200],
            &legacy[120 + row * 48..168 + row * 48]
        );
    }
    let reaction = 128 + 3 * 200;
    assert_eq!(
        &encoded[reaction + 48..reaction + 64],
        &[0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0]
    );
    assert_eq!(&encoded[reaction + 64..reaction + 72], &9u64.to_be_bytes());
    assert_eq!(&encoded[reaction + 80..reaction + 88], &3u64.to_be_bytes());
    assert_eq!(
        NativePhaseTimerObservation::decode(&encoded).unwrap(),
        observation
    );
}

#[test]
fn unknown_construction_and_callback_successor_births_expose_no_position() {
    let observation = NativePhaseTimerObservation::decode(&original().encode().unwrap()).unwrap();

    assert_eq!(observation.timers[0].birth.position(), None);
    assert_eq!(observation.timers[1].birth.position(), None);
    assert_eq!(observation.timers[2].birth.position(), None);
    assert_eq!(
        observation.timers[1].birth,
        NativeTimerBirth::Unknown {
            parent: Some(NativeTimerParent {
                timer: U64::new(1),
                arm_generation: U64::new(1)
            }),
        }
    );
    assert_eq!(
        observation.timers[3].birth.position(),
        Some(Position::new(U64::new(9), U64::new(0), Phase::Reaction))
    );
}

#[test]
fn fabricated_unknown_position_scope_grant_and_open_birth_flags_are_refused() {
    let encoded = original().encode().unwrap();
    let row = 128;
    for (offset, value) in [(48, 3u32), (52, 3), (56, 1), (56, 4), (60, 1)] {
        let mut bytes = encoded.clone();
        bytes[row + offset..row + offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
    for offset in [64, 72, 80, 88, 96, 104, 136, 168] {
        let mut bytes = encoded.clone();
        bytes[row + offset] = 1;
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }

    let parent_row = row + 200;
    for offset in [88, 96] {
        let mut bytes = encoded.clone();
        bytes[parent_row + offset..parent_row + offset + 8].fill(0);
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
}

#[test]
fn construction_never_adopts_a_logical_position_or_execution_command() {
    let encoded = original().encode().unwrap();
    let row = 128 + 2 * 200;
    for (offset, width) in [
        (52, 4),
        (56, 4),
        (64, 8),
        (72, 8),
        (80, 8),
        (88, 8),
        (96, 8),
        (136, 32),
    ] {
        let mut bytes = encoded.clone();
        bytes[row + offset + width - 1] = 1;
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
    for offset in [104, 168] {
        let mut bytes = encoded.clone();
        bytes[row + offset..row + offset + 32].fill(0);
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
}

#[test]
fn reaction_mapping_refuses_unknown_scope_missing_command_and_callback_ancestry() {
    let encoded = original().encode().unwrap();
    let row = 128 + 3 * 200;
    for (offset, value) in [(52, 0u32), (52, 2), (52, 4), (56, 0), (56, 2), (60, 1)] {
        let mut bytes = encoded.clone();
        bytes[row + offset..row + offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
    for offset in [72, 88, 96, 168] {
        let mut bytes = encoded.clone();
        bytes[row + offset + 7] = 1;
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
    for (offset, width) in [(80, 8), (104, 32), (136, 32)] {
        let mut bytes = encoded.clone();
        bytes[row + offset..row + offset + width].fill(0);
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
}

#[test]
fn exact_extent_truncation_open_summary_and_finite_counts_are_refused() {
    let encoded = original().encode().unwrap();
    for length in 0..encoded.len() {
        assert!(NativePhaseTimerObservation::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NativePhaseTimerObservation::decode(&trailing).is_err());
    for (offset, value) in [(0, 2u32), (4, 113), (8, 65), (12, 4097)] {
        let mut bytes = encoded.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(NativePhaseTimerObservation::decode(&bytes).is_err());
    }
    assert!(
        NativePhaseTimerObservation::decode(&vec![
            0;
            super::NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES + 1
        ])
        .is_err()
    );
}

#[test]
fn original_scope_construction_policy_and_command_cut_must_remain_correlated() {
    let observation = original();
    let preparation = super::super::phase::test_preparation();
    assert!(observation.validate_against(&preparation).is_ok());

    let mut changed = preparation;
    changed.initialization.maximum_callbacks -= 1;
    assert!(observation.validate_against(&changed).is_err());
    let mut changed = observation.clone();
    changed.prepared_scope_hash[0] ^= 1;
    assert!(changed.validate().is_err());
    let mut changed = observation.clone();
    changed.sequence = U64::new(2);
    assert!(changed.validate().is_err());
    let mut changed = observation.clone();
    changed.command_digest[0] ^= 1;
    assert!(changed.validate().is_err());
    let mut changed = observation;
    changed.current_ps = U64::new(8);
    assert!(changed.validate().is_err());
}

#[test]
fn authentic_empty_initial_cut_remains_distinct_from_missing_observation() {
    let preparation = super::super::phase::test_preparation();
    let observation = NativePhaseTimerObservation {
        prepared_scope_hash: preparation
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap(),
        sequence: U64::new(0),
        command_digest: [0; 32],
        current_ps: U64::new(0),
        mutation_generation: U64::new(0),
        gate_generation: U64::new(1),
        lists: vec![NativeTimerList {
            identity: U64::new(1),
            timer_count: 0,
            flags: 3,
        }],
        timers: Vec::new(),
    };
    let encoded = observation.encode().unwrap();
    assert_eq!(encoded.len(), 128);
    assert_eq!(
        NativePhaseTimerObservation::decode(&encoded).unwrap(),
        observation
    );

    let mut missing_gate = observation;
    missing_gate.gate_generation = U64::new(0);
    assert!(missing_gate.encode().is_err());
}

#[test]
fn phase_projection_refuses_scales_unrepresentable_by_the_native_signed_int() {
    for scale in [0, i32::MAX as u32 + 1, u32::MAX] {
        let mut observation = original();
        observation.timers[0].arm.scale = scale;
        assert!(observation.encode().is_err());
    }
    let mut observation = original();
    observation.timers[0].arm.scale = i32::MAX as u32;
    assert!(observation.encode().is_ok());
}
