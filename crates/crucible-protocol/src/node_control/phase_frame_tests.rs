//! Explicit phase edition pinning and unchanged earlier native record bodies.

// crucible-lint: allow panic-shortcut -- These phase frame tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::U64;

use super::{NativeControlEdition, decode_frame_for_edition, encode_frame_for_edition};
use crate::node_control::{
    NativeFrame, NativeInitializationQuery, NativePhaseTimerChunk, NativePhaseTimerQuery,
    NativeTimerChunk, NativeTimerQuery, NativeWriterChunk,
};

fn frames() -> Vec<NativeFrame> {
    let preparation = crate::node_control::phase::test_preparation();
    let scope = preparation
        .initialization
        .preparation
        .scope
        .identity_digest()
        .unwrap();
    vec![
        NativeFrame::PreparePhase(Box::new(preparation)),
        NativeFrame::QueryPhaseTimers(NativePhaseTimerQuery {
            prepared_scope_hash: scope,
            sequence: U64::new(0),
            offset: U64::new(0),
        }),
        NativeFrame::PhaseTimerChunk(Box::new(NativePhaseTimerChunk {
            prepared_scope_hash: scope,
            sequence: U64::new(0),
            object_digest: [8; 32],
            total_bytes: U64::new(112),
            offset: U64::new(0),
            bytes: vec![0; 112],
        })),
    ]
}

#[test]
fn phase_kinds_have_fixed_numbers_and_cannot_upgrade_prior_editions() {
    for (kind, frame) in (21u16..=23).zip(frames()) {
        let encoded =
            encode_frame_for_edition(NativeControlEdition::PhaseProjection, &frame).unwrap();

        assert_eq!(&encoded[8..10], &[0, 3]);
        assert_eq!(&encoded[10..12], &kind.to_be_bytes());
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::PhaseProjection, &encoded).unwrap(),
            frame
        );
        assert!(crate::node_control::encode_frame(&frame).is_err());
        for prior in [
            NativeControlEdition::Original,
            NativeControlEdition::OwnedCustody,
        ] {
            assert!(encode_frame_for_edition(prior, &frame).is_err());
            assert!(decode_frame_for_edition(prior, &encoded).is_err());

            // Replacing a header is not negotiation or native capability adoption.
            let mut substituted = encoded.clone();
            substituted[8..10].copy_from_slice(&prior.version().to_be_bytes());
            assert!(decode_frame_for_edition(prior, &substituted).is_err());
        }
    }
}

#[test]
fn every_phase_truncation_extent_foreign_version_and_unknown_kind_is_refused() {
    for frame in frames() {
        let encoded =
            encode_frame_for_edition(NativeControlEdition::PhaseProjection, &frame).unwrap();
        for length in 0..encoded.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::PhaseProjection, &encoded[..length])
                    .is_err()
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(
            decode_frame_for_edition(NativeControlEdition::PhaseProjection, &trailing).is_err()
        );
        for version in [0u16, 1, 2, 4, u16::MAX] {
            let mut changed = encoded.clone();
            changed[8..10].copy_from_slice(&version.to_be_bytes());
            assert!(
                decode_frame_for_edition(NativeControlEdition::PhaseProjection, &changed).is_err()
            );
        }
        for kind in [0u16, 24, u16::MAX] {
            let mut changed = encoded.clone();
            changed[10..12].copy_from_slice(&kind.to_be_bytes());
            assert!(
                decode_frame_for_edition(NativeControlEdition::PhaseProjection, &changed).is_err()
            );
        }
        let mut changed = encoded;
        changed[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_frame_for_edition(NativeControlEdition::PhaseProjection, &changed).is_err());
    }
}

#[test]
fn previous_record_bodies_are_identical_under_the_explicit_phase_header() {
    let initialization = crate::node_control::initialization::test_preparation();
    let scope = initialization.preparation.scope.identity_digest().unwrap();
    let original = vec![
        NativeFrame::Prepare(Box::new(initialization.preparation.clone())),
        NativeFrame::QueryCpuPark(scope),
        NativeFrame::QueryTimers(NativeTimerQuery {
            prepared_scope_hash: scope,
            sequence: U64::new(0),
            offset: U64::new(0),
        }),
        NativeFrame::TimerChunk(NativeTimerChunk {
            prepared_scope_hash: scope,
            sequence: U64::new(0),
            object_digest: [7; 32],
            total_bytes: U64::new(104),
            offset: U64::new(0),
            bytes: vec![0; 104],
        }),
    ];
    let custody = vec![
        NativeFrame::PrepareInitialization(Box::new(initialization.clone())),
        NativeFrame::QueryInitialization(NativeInitializationQuery {
            prepared_scope_hash: scope,
            initialization_commitment: initialization.identity_digest().unwrap(),
        }),
        NativeFrame::WriterChunk(NativeWriterChunk {
            prepared_scope_hash: scope,
            sequence: U64::new(0),
            object_digest: [7; 32],
            total_bytes: U64::new(4),
            offset: U64::new(0),
            bytes: vec![1, 2, 3, 4],
        }),
    ];

    for (prior, frames) in [
        (NativeControlEdition::Original, original),
        (NativeControlEdition::OwnedCustody, custody),
    ] {
        for frame in frames {
            let old = encode_frame_for_edition(prior, &frame).unwrap();
            let phase =
                encode_frame_for_edition(NativeControlEdition::PhaseProjection, &frame).unwrap();

            assert_eq!(&old[..8], &phase[..8]);
            assert_eq!(&old[10..], &phase[10..]);
            assert_eq!(&phase[8..10], &[0, 3]);
            assert_eq!(
                decode_frame_for_edition(NativeControlEdition::PhaseProjection, &phase).unwrap(),
                frame
            );
            assert!(decode_frame_for_edition(prior, &phase).is_err());
            assert!(decode_frame_for_edition(NativeControlEdition::PhaseProjection, &old).is_err());
        }
    }
}
