//! Model-only partial-prefix recovery without native qualification.

// crucible-lint: allow panic-shortcut -- These preparation successor tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_protocol::node_control::NativeInitializationStatus;

fn receipt() -> NativeInitializationReceipt {
    NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 0,
        sequence: U64::new(1),
        hold_generation: U64::new(7),
        prepared_scope_hash: [1; 32],
        initialization_commitment: [2; 32],
        realize_request_digest: [3; 32],
        original_cut_digest: [4; 32],
    }
}

fn chunk() -> NativePreparationSuccessorChunk {
    NativePreparationSuccessorChunk {
        facts: NativePreparationSuccessorFacts {
            initialization_sequence: U64::new(1),
            hold_generation: U64::new(7),
            current_ps: U64::new(0),
            retired_count: U64::new(0),
            prepared_scope_hash: [1; 32],
            initialization_commitment: [2; 32],
            realize_request_digest: [3; 32],
            original_cut_digest: [4; 32],
            applied_receipt_sha256: [5; 32],
            content_length: U64::new(1000),
            content_sha256: [6; 32],
        },
        offset: U64::new(0),
        bytes: vec![10, 20, 30],
    }
}

fn assembly() -> SuccessorAssembly {
    SuccessorAssembly {
        receipt: Some(receipt()),
        ..Default::default()
    }
}

#[test]
fn lost_slice_reply_recovers_identical_prefix_and_extends_only_original_identity() {
    let mut original = assembly();
    let first = chunk();
    original.accept(&receipt(), &first).unwrap();
    original.accept(&receipt(), &first).unwrap();
    assert_eq!(original.bytes, vec![10, 20, 30]);

    let mut next = first.clone();
    next.offset = U64::new(3);
    next.bytes = vec![40, 50];
    original.accept(&receipt(), &next).unwrap();
    original.accept(&receipt(), &first).unwrap();
    assert_eq!(original.bytes, vec![10, 20, 30, 40, 50]);
    assert!(original.complete.is_none());
}

#[test]
fn changed_hash_scope_original_cut_or_replayed_bytes_cannot_replace_retained_prefix() {
    for field in 0..5 {
        let mut original = assembly();
        original.accept(&receipt(), &chunk()).unwrap();
        let mut changed = chunk();
        match field {
            0 => changed.facts.content_sha256[0] ^= 1,
            1 => changed.facts.prepared_scope_hash[0] ^= 1,
            2 => changed.facts.original_cut_digest[0] ^= 1,
            3 => changed.bytes[0] ^= 1,
            _ => changed.offset = U64::new(9),
        }
        assert!(original.accept(&receipt(), &changed).is_err());
        assert_eq!(original.bytes, vec![10, 20, 30]);
        assert!(original.complete.is_none());
        assert!(original.failed);
        assert!(original.accept(&receipt(), &chunk()).is_err());
    }
}

#[test]
fn unsolicited_or_changed_receipt_and_malformed_complete_object_remain_unqualified() {
    let mut unsolicited = SuccessorAssembly::default();
    assert!(unsolicited.accept(&receipt(), &chunk()).is_err());
    assert!(unsolicited.bytes.is_empty());

    let mut original = assembly();
    let mut changed_receipt = receipt();
    changed_receipt.sequence = U64::new(2);
    assert!(original.accept(&changed_receipt, &chunk()).is_err());
    assert!(original.bytes.is_empty());

    let mut original = assembly();
    let mut final_chunk = chunk();
    final_chunk.facts.content_length = U64::new(3);
    assert!(original.accept(&receipt(), &final_chunk).is_err());
    assert_eq!(original.bytes, final_chunk.bytes);
    assert!(original.complete.is_none());
}

#[test]
fn malformed_extent_is_sticky_without_releasing_original_prefix() {
    let mut original = assembly();
    original.accept(&receipt(), &chunk()).unwrap();

    let mut invalid = chunk();
    invalid.offset = U64::new(u64::MAX);
    assert!(original.accept(&receipt(), &invalid).is_err());
    assert_eq!(original.bytes, vec![10, 20, 30]);
    assert!(original.failed);
    assert!(original.accept(&receipt(), &chunk()).is_err());
}
