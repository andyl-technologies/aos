//! Checks ordering and terminal local-v1 discovery using inert canonical records.

#![allow(
    clippy::unwrap_used,
    reason = "Pure codec assertions must fail visibly."
)]

use super::*;

const KEY: &str = "gc/7/delete/000102030405060708090a0b0c0d0e0f/404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

fn fixture() -> DeleteOperation {
    let hex =
        include_str!("../../../../../terrane-format/src/gc/journal/vectors/delete_operation.hex");
    let compact: String = hex.chars().filter(|byte| !byte.is_whitespace()).collect();
    assert_eq!(compact.len() % 2, 0);
    let bytes: Vec<_> = (0..compact.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&compact[offset..offset + 2], 16).unwrap())
        .collect();
    DeleteOperation::decode(&bytes, KEY).unwrap()
}

fn record(nonce: u8, phase: DeletePhase) -> (String, Vec<u8>) {
    let mut value = fixture();
    value.authorization.nonce = [nonce; 32];
    value.phase = phase;
    (value.authorization.operation_key(), value.encode().unwrap())
}

#[test]
fn terminal_records_remain_distinct_from_pending_incarnations() {
    for (nonce, phase) in [
        (1, DeletePhase::Invalidated),
        (2, DeletePhase::Done),
        (3, DeletePhase::Cancelled),
    ] {
        let (key, bytes) = record(nonce, phase);
        let hint = decode_hint(key.clone(), &bytes).unwrap();
        assert_eq!(hint.operation_key, key);
        assert_eq!(hint.phase, phase);
        assert_eq!(
            hint.exclusion,
            PackExclusion {
                pack_id: fixture().authorization.pack_id,
                cycle: 7,
                epoch: fixture().authorization.epoch,
            }
        );
    }
}

fn batch(keys: &[&str], after: Option<&str>, maximum: usize) -> Vec<String> {
    let mut candidates = Candidates::new(after, maximum);
    for key in keys {
        candidates.insert((*key).into());
        assert!(candidates.keys.len() <= maximum);
    }
    candidates.into_keys().collect()
}

#[test]
fn bounded_batches_wrap_after_removed_keys_and_discover_new_lower_keys() {
    assert_eq!(batch(&["b", "d", "f"], None, 2), ["b", "d"]);
    assert_eq!(batch(&["b", "f", "a"], Some("d"), 2), ["f", "a"]);
    assert_eq!(batch(&["b", "f", "a"], Some("a"), 1), ["b"]);
    assert_eq!(
        batch(&["b", "f", "a"], Some("f"), MAX_HINTS),
        ["a", "b", "f"]
    );
}

#[test]
fn unsorted_directory_visits_and_duplicates_do_not_change_cyclic_selection() {
    assert_eq!(
        batch(&["e", "a", "c", "b", "d", "e", "c"], Some("b"), 3),
        ["c", "d", "e"]
    );
    assert!(batch(&[], Some("missing"), MAX_HINTS).is_empty());
}

#[test]
fn every_stable_candidate_is_revisited_with_one_retained_key() {
    let keys: Vec<_> = (0..600)
        .map(|value| format!("candidate-{value:03}"))
        .collect();
    let borrowed: Vec<_> = keys.iter().map(String::as_str).collect();
    let mut after = None;
    let mut visited = Vec::new();
    for _ in 0..1200 {
        let selected = batch(&borrowed, after.as_deref(), 1);
        assert_eq!(selected.len(), 1);
        after = Some(selected[0].clone());
        visited.extend(selected);
    }
    assert_eq!(&visited[..600], keys);
    assert_eq!(&visited[600..], keys);
}

#[test]
fn malformed_or_mismatched_protected_local_records_fail_closed() {
    let (key, bytes) = record(2, DeletePhase::Done);
    assert!(decode_hint(record(3, DeletePhase::Done).0, &bytes).is_err());
    assert!(decode_hint(key.clone(), &[0x86, 2]).is_err());
    assert!(decode_hint(key, &[]).is_err());
}
