//! Closed fixed-endian vectors and edition isolation; all source fields are inert test data.

use super::*;
use crate::node_control::{
    NativeControlEdition, NativeFrame, decode_frame_for_edition, encode_frame_for_edition,
};

fn source_record() -> [u8; 408] {
    let mut bytes = [0; 408];
    let mut fields = include_str!("testdata/stopped-initial-v1.hex").split_ascii_whitespace();
    for byte in &mut bytes {
        *byte = u8::from_str_radix(fields.next().unwrap(), 16).unwrap();
    }
    assert!(fields.next().is_none());
    bytes
}

fn query() -> NativeStoppedCutQuery {
    NativeStoppedCutQuery {
        scope: [1; 32],
        prefix_preparation: [2; 32],
        sequence: U64::new(1),
    }
}

#[test]
fn initial_stopped_cut_has_exact_closed_offsets_and_separate_native_identities() {
    let source = source_record();
    let observed = NativeStoppedCut::from_source_record(query(), &source).unwrap();
    assert_eq!(observed.process_id().unwrap(), 1234);
    assert_eq!(observed.thread_id().unwrap(), 5678);
    assert_eq!(observed.raw_count().unwrap(), 0);
    assert_eq!(
        observed.next_cpu().unwrap(),
        Position::new(U64::new(50), U64::new(0), Phase::Reaction)
    );
    assert_eq!(
        observed
            .consumed_preparation()
            .unwrap()
            .epoch_incarnation
            .get(),
        7
    );
    let wire = observed.encode().unwrap();
    assert_eq!(&wire[72..], &source);
    assert_eq!(NativeStoppedCut::decode(&wire).unwrap(), observed);
}

#[test]
fn initial_observation_edition_is_pinned_and_ancestor_bytes_remain_unchanged() {
    let observed = NativeStoppedCut::from_source_record(query(), &source_record()).unwrap();
    let frame = NativeFrame::StoppedCut(Box::new(observed));
    let bytes = encode_frame_for_edition(NativeControlEdition::PrefixObservation, &frame).unwrap();
    assert_eq!(&bytes[..16], b"CNQEMU01\0\x0a\0\x2b\0\0\x01\xe0");
    assert_eq!(
        decode_frame_for_edition(NativeControlEdition::PrefixObservation, &bytes).unwrap(),
        frame
    );
    for old in [
        NativeControlEdition::Original,
        NativeControlEdition::PrefixEffect,
    ] {
        assert!(encode_frame_for_edition(old, &frame).is_err());
        assert!(decode_frame_for_edition(old, &bytes).is_err());
    }
    let ancestor = NativeFrame::QueryCpuPark([5; 32]);
    let older = encode_frame_for_edition(NativeControlEdition::PrefixEffect, &ancestor).unwrap();
    let mut newer =
        encode_frame_for_edition(NativeControlEdition::PrefixObservation, &ancestor).unwrap();
    newer[8..10].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(older, newer);
}

#[test]
fn initial_stopped_cut_refuses_partial_trailing_noninitial_and_inconsistent_source_records() {
    let source = source_record();
    for length in 0..408 {
        assert!(NativeStoppedCut::from_source_record(query(), &source[..length]).is_err());
    }
    let mut trailing = source.to_vec();
    trailing.push(0);
    assert!(NativeStoppedCut::from_source_record(query(), &trailing).is_err());
    for offset in [
        0, 4, 24, 48, 56, 96, 104, 184, 192, 224, 328, 344, 384, 388, 392, 396, 400, 404,
    ] {
        let mut changed = source;
        changed[offset] ^= 0x80;
        assert!(
            NativeStoppedCut::from_source_record(query(), &changed).is_err(),
            "offset {offset}"
        );
    }
    for offset in [8, 16, 56, 64, 72] {
        let mut changed = source;
        changed[offset..offset + 8].fill(0);
        assert!(NativeStoppedCut::from_source_record(query(), &changed).is_err());
    }
    let mut changed_query = query();
    changed_query.sequence = U64::new(2);
    assert!(changed_query.encode().is_err());
    let observed = NativeStoppedCut::from_source_record(query(), &source).unwrap();
    let bytes = encode_frame_for_edition(
        NativeControlEdition::PrefixObservation,
        &NativeFrame::StoppedCut(Box::new(observed)),
    )
    .unwrap();
    for length in 0..bytes.len() {
        assert!(
            decode_frame_for_edition(NativeControlEdition::PrefixObservation, &bytes[..length])
                .is_err()
        );
    }
}
