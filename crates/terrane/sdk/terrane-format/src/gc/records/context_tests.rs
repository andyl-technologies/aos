//! Exercises legacy compatibility and exact proof-sensitive checkpoint state.

#![allow(clippy::unwrap_used, reason = "malformed fixtures must fail clearly")]

use crate::gc::*;
use alloc::{vec, vec::Vec};

fn empty() -> GcState {
    GcState {
        cycle: 1,
        epoch: 2,
        phase: Phase::Mark,
        snapshot_at: 0,
        checkpoints: vec![],
        pending: vec![],
        expanded: vec![],
        progress: vec![],
        objects: vec![],
    }
}

fn context(path: &[u8]) -> ProofContext {
    ProofContext::new([3; 32], [4; 32], path.to_vec()).unwrap()
}

#[test]
fn gc_context_legacy_empty_state_keeps_exact_bytes() {
    let bytes = vec![
        0xaa, 0, 1, 1, 1, 2, 2, 3, 0x64, b'm', b'a', b'r', b'k', 4, 0, 5, 0x80, 6, 0x80, 7, 0x80,
        8, 0x80, 9, 0x80,
    ];
    assert_eq!(empty().encode().unwrap(), bytes);
    assert_eq!(GcState::decode(&bytes).unwrap(), empty());
}

#[test]
fn gc_context_checkpoint_same_identity_stays_distinct_and_cutoff_is_not_unique_key() {
    let contexts = [None, Some(context(b"/aa")), Some(context(b"/z"))];
    let mut state = empty();
    for proof_context in contexts {
        state.pending.push(Pending {
            kind: 2,
            hash: [5; 32],
            parent_cutoff: ParentCutoff::RootsOnly,
            flags: 2,
            proof_context: proof_context.clone(),
        });
        state.expanded.push(ExpandedContext {
            commit: [6; 32],
            parent_cutoff: ParentCutoff::Unbounded,
            proof_context: proof_context.clone(),
        });
        state.objects.push(ExpandedObject {
            kind: 2,
            hash: [5; 32],
            flags: 2,
            proof_context,
        });
    }
    let bytes = state.encode().unwrap();
    assert_eq!(GcState::decode(&bytes).unwrap(), state);
    // Fieldwise byte ordering puts /aa before /z despite its longer CBOR length.
    let mut invalid = state.clone();
    invalid.expanded.swap(1, 2);
    assert!(invalid.encode().is_err());
    let mut invalid = state.clone();
    invalid.objects.swap(1, 2);
    assert!(invalid.encode().is_err());
    let mut duplicate = state.expanded[2].clone();
    duplicate.parent_cutoff = ParentCutoff::RootsOnly;
    state.expanded.push(duplicate);
    assert!(state.encode().is_err());
}

#[test]
fn gc_context_cutoff_dominance_never_crosses_occurrences_or_legacy_context() {
    let a = context(b"/a");
    let b = context(b"/b");
    let mut visits = CommitVisits::new();
    assert!(visits.expand_in_context([8; 32], ParentCutoff::Unbounded, Some(&a)));
    assert!(visits.needs_expansion_in_context(&[8; 32], ParentCutoff::RootsOnly, Some(&b)));
    assert!(visits.needs_expansion(&[8; 32], ParentCutoff::RootsOnly));
    assert!(visits.expand_in_context([8; 32], ParentCutoff::RootsOnly, Some(&b)));
    assert!(visits.expand_in_context([8; 32], ParentCutoff::Since(7), Some(&b)));
    assert!(!visits.needs_expansion_in_context(&[8; 32], ParentCutoff::Since(8), Some(&b)));
    assert_eq!(visits.contexts().count(), 2);
}

#[test]
fn gc_context_absolute_paths_and_graft_occurrences_are_canonical() {
    for path in [
        b"".as_slice(),
        b"relative",
        b"//a",
        b"/a/",
        b"/./a",
        b"/a/../b",
        b"/a\0b",
    ] {
        assert!(ProofContext::new([0; 32], [0; 32], path.to_vec()).is_err());
    }
    assert_eq!(
        context(b"/")
            .descend([9; 32], b"a/b")
            .unwrap()
            .absolute_path(),
        b"/a/b"
    );
    assert_eq!(
        context(b"/mount")
            .descend([9; 32], b"a/b")
            .unwrap()
            .absolute_path(),
        b"/mount/a/b"
    );
    let components = (0..17)
        .map(|index| {
            vec![
                b'x';
                match index {
                    15 => 254,
                    16 => 1,
                    _ => 255,
                }
            ]
        })
        .collect::<Vec<_>>();
    let mut path = vec![b'/'];
    path.extend(components.join(&b'/'));
    assert_eq!(path.len(), 4097);
    assert!(ProofContext::new([0; 32], [0; 32], path.clone()).is_ok());
    path.push(b'x');
    assert!(ProofContext::new([0; 32], [0; 32], path).is_err());
}

#[test]
fn gc_context_wire_rejects_explicit_null_wrong_tuple_and_noncanonical_path() {
    let mut state = empty();
    state.pending.push(Pending {
        kind: 2,
        hash: [5; 32],
        parent_cutoff: ParentCutoff::Unbounded,
        flags: 2,
        proof_context: Some(context(b"/a")),
    });
    let bytes = state.encode().unwrap();
    let offset = bytes
        .windows(3)
        .position(|window| window == [0x83, 0x58, 0x20])
        .unwrap();
    let mut null = bytes[..offset].to_vec();
    null.extend([0xf6, 7, 0x80, 8, 0x80, 9, 0x80]);
    assert!(GcState::decode(&null).is_err());
    let mut wrong_width = bytes.clone();
    wrong_width[offset] = 0x82;
    assert!(GcState::decode(&wrong_width).is_err());
    let mut wrong_digest = bytes.clone();
    wrong_digest[offset + 2] = 31;
    assert!(GcState::decode(&wrong_digest).is_err());
    let mut relative = bytes.clone();
    let path_offset = bytes
        .windows(3)
        .position(|window| window == [0x42, b'/', b'a'])
        .unwrap();
    relative[path_offset + 1] = b'.';
    assert!(GcState::decode(&relative).is_err());
    assert!(GcState::decode(&bytes[..bytes.len() - 1]).is_err());
}
