//! Checks exact collector checkpoint encodings and crash-frontier invariants.

#![allow(
    clippy::unwrap_used,
    reason = "invalid fixtures must fail collector tests"
)]

use crate::gc::*;
use crate::refs::RefName;
use alloc::vec;

fn state() -> GcState {
    GcState {
        cycle: 7,
        epoch: 11,
        phase: Phase::Mark,
        snapshot_at: 100,
        checkpoints: vec![
            CheckpointPointer {
                shard: 1,
                revision: 2,
                hash: [1; 32],
            },
            CheckpointPointer {
                shard: 2,
                revision: 3,
                hash: [2; 32],
            },
        ],
        pending: vec![
            Pending {
                kind: 3,
                hash: [3; 32],
                parent_cutoff: ParentCutoff::Since(70),
                flags: 1,
                proof_context: None,
            },
            Pending {
                kind: 2,
                hash: [4; 32],
                parent_cutoff: ParentCutoff::Unbounded,
                flags: 6,
                proof_context: None,
            },
            Pending {
                kind: 3,
                hash: [9; 32],
                parent_cutoff: ParentCutoff::RootsOnly,
                flags: 1,
                proof_context: None,
            },
        ],
        expanded: vec![
            ExpandedContext {
                commit: [5; 32],
                parent_cutoff: ParentCutoff::RootsOnly,
                proof_context: None,
            },
            ExpandedContext {
                commit: [6; 32],
                parent_cutoff: ParentCutoff::Unbounded,
                proof_context: None,
            },
        ],
        progress: vec![[7; 16], [8; 16]],
        objects: vec![ExpandedObject {
            kind: 2,
            hash: [4; 32],
            flags: 14,
            proof_context: None,
        }],
    }
}

#[test]
fn gc_checkpoint_roots_roundtrip_every_closed_reason_and_optional_cutoff() {
    let reasons = [
        RootReason::Current,
        RootReason::ReflogGc,
        RootReason::ReflogCount,
        RootReason::ReflogTtl,
        RootReason::Lease,
        RootReason::Forever,
        RootReason::Tag,
        RootReason::Job,
        RootReason::RetentionWitness,
    ];
    let roots = GcRoots {
        cycle: 1,
        epoch: 2,
        timestamp: 100,
        roots: reasons
            .into_iter()
            .enumerate()
            .map(|(position, reason)| GcRoot {
                reference: RefName::parse("refs/heads/_/main").unwrap(),
                commit: [position as u8; 32],
                parent_cutoff: match position % 3 {
                    0 => ParentCutoff::Since(70),
                    1 => ParentCutoff::Unbounded,
                    _ => ParentCutoff::RootsOnly,
                },
                reason,
            })
            .collect(),
    };
    let bytes = roots.encode();
    assert_eq!(GcRoots::decode(&bytes).unwrap(), roots);
    let mut invalid = bytes.clone();
    let position = invalid.iter().position(|byte| *byte == 0xf4).unwrap();
    invalid[position] = 0xf5;
    assert!(GcRoots::decode(&invalid).is_err());
    assert_eq!(
        GcRoots {
            cycle: 1,
            epoch: 2,
            timestamp: 3,
            roots: vec![]
        }
        .encode(),
        vec![0xa5, 0, 1, 1, 1, 2, 2, 3, 3, 4, 0x80]
    );

    let mut wrong_version = bytes.clone();
    wrong_version[2] = 2;
    assert!(GcRoots::decode(&wrong_version).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(GcRoots::decode(&trailing).is_err());
}

#[test]
fn gc_checkpoint_mark_reconstructs_registered_hint_and_requires_exact_lookup() {
    let mut hash = [0; 32];
    hash[0] = 7;
    hash[1] = 0x12;
    hash[2] = 0x34;
    hash[11] = 0x80;
    hash[12] = 1;
    hash[21] = 0xff;
    hash[22] = 0xff;
    let mark = GcMark::new(1, 2, 7, vec![hash]).unwrap();
    for bit in [0x1234usize, 1, 16383] {
        assert_ne!(mark.filter()[bit / 8] & (1 << (bit % 8)), 0);
    }
    assert_eq!(
        mark.filter()
            .iter()
            .map(|byte| byte.count_ones())
            .sum::<u32>(),
        3
    );
    assert!(mark.contains(&hash));
    let mut collision = hash;
    collision[31] = 1;
    assert!(MarkSet::filter_may_contain(mark.filter(), &collision));
    assert!(!mark.contains(&collision));

    let bytes = mark.encode();
    assert_eq!(GcMark::decode(&bytes).unwrap(), mark);
    let mut corrupt_filter = bytes.clone();
    *corrupt_filter.last_mut().unwrap() ^= 1;
    assert!(GcMark::decode(&corrupt_filter).is_err());
    assert!(GcMark::new(1, 2, 7, vec![[7; 32], [7; 32]]).is_err());
    assert!(GcMark::new(1, 2, 7, vec![[8; 32]]).is_err());
    assert!(GcMark::decode(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn gc_checkpoint_state_preserves_frontier_flags_and_broader_commit_contexts() {
    let state = state();
    let bytes = state.encode().unwrap();
    assert_eq!(GcState::decode(&bytes).unwrap(), state);
    assert!(state.pending[0].is_parent());
    assert!(state.pending[1].is_root());
    assert!(state.pending[1].is_index());
    assert_eq!(state.expanded[1].parent_cutoff, ParentCutoff::Unbounded);

    let mut invalid = state.clone();
    invalid.checkpoints.swap(0, 1);
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.checkpoints[1].shard = invalid.checkpoints[0].shard;
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.expanded.swap(0, 1);
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.progress.swap(0, 1);
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.pending[0].flags = 16;
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.pending[0].kind = 0;
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.pending[0].kind = 0;
    invalid.pending[0].flags = 8;
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.objects.push(invalid.objects[0].clone());
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.objects[0].flags = 1;
    assert!(invalid.encode().is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(GcState::decode(&trailing).is_err());
}

#[test]
fn gc_checkpoint_decoders_reject_every_truncated_prefix() {
    let records = [
        GcRoots {
            cycle: 1,
            epoch: 2,
            timestamp: 3,
            roots: vec![],
        }
        .encode(),
        GcMark::new(1, 2, 7, vec![[7; 32]]).unwrap().encode(),
        state().encode().unwrap(),
    ];
    for (kind, bytes) in records.into_iter().enumerate() {
        for length in 0..bytes.len() {
            let valid = match kind {
                0 => GcRoots::decode(&bytes[..length]).is_ok(),
                1 => GcMark::decode(&bytes[..length]).is_ok(),
                _ => GcState::decode(&bytes[..length]).is_ok(),
            };
            assert!(!valid, "accepted truncated record {kind} at {length}");
        }
    }
}

#[test]
fn gc_checkpoint_wire_rejects_incomplete_arrays_and_invalid_frontier_flags() {
    // Empty registered root snapshot except for one missing root tuple.
    assert!(GcRoots::decode(&[0xa5, 0, 1, 1, 1, 2, 2, 3, 3, 4, 0x81, 0]).is_err());
    // A mark claiming a single hash with only an empty byte string.
    assert!(GcMark::decode(&[0xa6, 0, 1, 1, 1, 2, 2, 3, 7, 4, 0x81, 0x40, 5, 0x40]).is_err());

    let mut bytes = vec![
        0xaa, 0, 1, 1, 1, 2, 2, 3, 0x64, b'm', b'a', b'r', b'k', 4, 0, 5, 0x80, 6, 0x81, 0x84, 0,
        0x58, 32,
    ];
    bytes.extend([5; 32]);
    bytes.extend([0xf6, 8, 7, 0x80, 8, 0x80, 9, 0x80]);
    // Data chunks cannot carry witness-only metadata traversal.
    assert!(GcState::decode(&bytes).is_err());

    bytes[20] = 2;
    assert!(GcState::decode(&bytes).is_ok());
    let flag = bytes.len() - 7;
    bytes[flag] = 16;
    assert!(GcState::decode(&bytes).is_err());
}
