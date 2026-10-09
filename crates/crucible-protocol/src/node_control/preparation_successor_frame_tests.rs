//! Edition pinning and byte-preserving original successor slice recovery.
// crucible-lint: allow panic-shortcut -- These preparation successor frame tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_control::{
    NativeControlEdition, NativeFrame, decode_frame_for_edition, encode_frame_for_edition,
};

fn query() -> NativePreparationSuccessorQuery {
    NativePreparationSuccessorQuery {
        prepared_scope_hash: [1; 32],
        initialization_sequence: U64::new(1),
        original_cut_digest: [3; 32],
        offset: U64::new(0),
    }
}

#[test]
fn edition_four_is_pinned_before_emission_and_old_editions_refuse_new_kinds() {
    let (facts, bytes) = crate::node_control::preparation_successor_object::tests::fixture();
    for frame in [
        NativeFrame::QueryPreparationSuccessor(query()),
        NativeFrame::PreparationSuccessorChunk(Box::new(NativePreparationSuccessorChunk {
            facts,
            offset: U64::new(0),
            bytes,
        })),
    ] {
        let encoded =
            encode_frame_for_edition(NativeControlEdition::PreparationSuccessor, &frame).unwrap();
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::PreparationSuccessor, &encoded).unwrap(),
            frame
        );
        for prior in [
            NativeControlEdition::Original,
            NativeControlEdition::OwnedCustody,
            NativeControlEdition::PhaseProjection,
        ] {
            assert!(encode_frame_for_edition(prior, &frame).is_err());
            assert!(decode_frame_for_edition(prior, &encoded).is_err());
            let mut substituted = encoded.clone();
            substituted[8..10].copy_from_slice(&prior.version().to_be_bytes());
            assert!(decode_frame_for_edition(prior, &substituted).is_err());
        }
    }
}

#[test]
fn prior_query_bodies_remain_identical_except_the_pinned_version() {
    let frame = NativeFrame::QueryCpuPark([1; 32]);
    let newest =
        encode_frame_for_edition(NativeControlEdition::PreparationSuccessor, &frame).unwrap();
    for prior in [
        NativeControlEdition::Original,
        NativeControlEdition::OwnedCustody,
        NativeControlEdition::PhaseProjection,
    ] {
        let original = encode_frame_for_edition(prior, &frame).unwrap();
        assert_eq!(&newest[..8], &original[..8]);
        assert_eq!(&newest[10..], &original[10..]);
    }
}

#[test]
fn exact_offsets_empty_slices_overflow_and_all_truncations_are_checked() {
    let (facts, bytes) = crate::node_control::preparation_successor_object::tests::fixture();
    let frame = NativeFrame::PreparationSuccessorChunk(Box::new(NativePreparationSuccessorChunk {
        facts: facts.clone(),
        offset: U64::new(0),
        bytes: bytes.clone(),
    }));
    let encoded =
        encode_frame_for_edition(NativeControlEdition::PreparationSuccessor, &frame).unwrap();
    for extent in 0..encoded.len() {
        assert!(
            decode_frame_for_edition(
                NativeControlEdition::PreparationSuccessor,
                &encoded[..extent]
            )
            .is_err()
        );
    }
    for (offset, slice) in [
        (u64::MAX, vec![1]),
        (facts.content_length.get(), vec![1]),
        (0, Vec::new()),
        (0, vec![1; 3001]),
    ] {
        assert!(
            NativePreparationSuccessorChunk {
                facts: facts.clone(),
                offset: U64::new(offset),
                bytes: slice
            }
            .validate()
            .is_err()
        );
    }
    let valid = query().encode().unwrap();
    for extent in 0..valid.len() {
        assert!(NativePreparationSuccessorQuery::decode(&valid[..extent]).is_err());
    }
    assert!(
        NativePreparationSuccessorQuery {
            offset: U64::new(2097152),
            ..query()
        }
        .validate()
        .is_err()
    );
}
