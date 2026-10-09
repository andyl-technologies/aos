//! Separate phase-aware transport limits without legacy timer upgrades.

#![allow(clippy::unwrap_used)]

use crucible_node_contract::U64;

use super::{NativePhaseTimerChunk, NativePhaseTimerQuery};

fn chunk() -> NativePhaseTimerChunk {
    NativePhaseTimerChunk {
        prepared_scope_hash: [1; 32],
        sequence: U64::new(0),
        object_digest: [2; 32],
        total_bytes: U64::new(820_336),
        offset: U64::new(800_000),
        bytes: vec![3, 4, 5],
    }
}

#[test]
fn phase_query_has_fixed_endian_body_and_separate_finite_offset_ceiling() {
    let query = NativePhaseTimerQuery {
        prepared_scope_hash: [1; 32],
        sequence: U64::new(7),
        offset: U64::new(820_335),
    };
    let encoded = query.encode().unwrap();
    assert_eq!(encoded.len(), 48);
    assert_eq!(&encoded[32..40], &7u64.to_be_bytes());
    assert_eq!(&encoded[40..48], &820_335u64.to_be_bytes());
    assert_eq!(NativePhaseTimerQuery::decode(&encoded).unwrap(), query);

    for length in 0..encoded.len() {
        assert!(NativePhaseTimerQuery::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(NativePhaseTimerQuery::decode(&trailing).is_err());
    let mut changed = query.clone();
    changed.offset = U64::new(820_336);
    assert!(changed.encode().is_err());
    let mut changed = query;
    changed.prepared_scope_hash = [0; 32];
    assert!(changed.encode().is_err());
}

#[test]
fn larger_phase_object_is_valid_only_under_its_separate_typed_chunk_allowance() {
    let chunk = chunk();
    let encoded = chunk.encode().unwrap();
    assert_eq!(encoded.len(), 91);
    assert_eq!(&encoded[72..80], &820_336u64.to_be_bytes());
    assert_eq!(&encoded[80..88], &800_000u64.to_be_bytes());
    assert_eq!(NativePhaseTimerChunk::decode(&encoded).unwrap(), chunk);

    let legacy = crate::node_control::NativeTimerChunk {
        prepared_scope_hash: chunk.prepared_scope_hash,
        sequence: chunk.sequence,
        object_digest: chunk.object_digest,
        total_bytes: chunk.total_bytes,
        offset: chunk.offset,
        bytes: chunk.bytes,
    };
    assert!(legacy.validate().is_err());
}

#[test]
fn impossible_chunk_extents_overflow_empty_bytes_and_open_credits_are_refused() {
    for field in 0..9 {
        let mut value = chunk();
        match field {
            0 => value.prepared_scope_hash = [0; 32],
            1 => value.object_digest = [0; 32],
            2 => value.total_bytes = U64::new(111),
            3 => value.total_bytes = U64::new(820_337),
            4 => value.bytes.clear(),
            5 => value.bytes = vec![0; 3001],
            6 => value.offset = U64::new(u64::MAX),
            7 => value.offset = value.total_bytes,
            _ => value.offset = U64::new(820_334),
        }
        assert!(value.encode().is_err());
    }
    for length in 0..=88 {
        assert!(NativePhaseTimerChunk::decode(&vec![0; length]).is_err());
    }
    assert!(NativePhaseTimerChunk::decode(&vec![0; 88 + 3001]).is_err());
    let mut encoded = chunk().encode().unwrap();
    encoded[80..88].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(NativePhaseTimerChunk::decode(&encoded).is_err());
}
