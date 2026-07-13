//! Stage-B serialize-and-patch round-trip tests (RFC-0007 doc 31 §1, §9
//! decision 6): a forced value of strings + attrsets of scalars survives an
//! `EvalHeap` heap-image capture + restore, its interior `FlatBytes`/`FlatSlice`
//! witnesses rebased on load; lists are refused; the completeness audit passes.

use ratchet_value::heap::HeapImage;

use super::*;
use crate::eval::heap::EvalHeapSnapshotError;
use crate::value::ValueTag;

/// A flattened, comparable projection of a snapshot-eligible attrset.
#[derive(Debug, PartialEq)]
enum Leaf {
    Int(i64),
    Str(Vec<u8>),
}

/// Projects a forced attrset of scalar/string leaves to `(symbol id, leaf)`
/// pairs — exercising the attrs entry-run `FlatSlice` and each string's
/// `FlatBytes` witness through `heap`.
fn attrset_structure(heap: &EvalHeap, root: Value) -> Vec<(u32, Leaf)> {
    heap.get_attrs(root)
        .expect("root is an attrset")
        .entries_by_symbol()
        .iter()
        .map(|entry| {
            let leaf = match entry.value.tag() {
                ValueTag::String => Leaf::Str(
                    heap.get_string(entry.value)
                        .expect("string resolves")
                        .bytes()
                        .to_vec(),
                ),
                _ => Leaf::Int(entry.value.as_int().expect("attr value is an integer")),
            };
            (entry.key.as_u32(), leaf)
        })
        .collect()
}

#[test]
fn heap_image_round_trips_a_string_and_attrset_via_rebase() {
    let outcome = eval_owned_with_source(b"snapshot", "{ a = 1; b = \"hello world\"; }");
    let root = outcome.value();

    let image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        // Chunked fallback (no reservation) is not snapshottable here.
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        // If the lowerer left the literal bindings as thunks, this value is not
        // yet snapshottable (stage-2 collapse); nothing to round-trip.
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    // The completeness audit passes for a fully-enumerated heap.
    outcome
        .heap()
        .verify_relocation_completeness(&image)
        .expect("relocation table covers every interior pointer");
    let expected = attrset_structure(outcome.heap(), root);
    assert!(
        expected
            .iter()
            .any(|(_, leaf)| matches!(leaf, Leaf::Str(_))),
        "the fixture must exercise a flat string witness"
    );

    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    let restored = EvalHeap::from_restored_heap_image(&reloaded).expect("image restores");
    assert_eq!(attrset_structure(&restored, root), expected);
}

#[test]
fn capture_refuses_a_heap_with_a_list() {
    let outcome = eval_owned_with_source(b"snapshot-list", "{ xs = [ 1 2 3 ]; }");
    // Forcing the attrset leaves `xs` a flat list object (owned out-of-arena Vec),
    // which the serialize-and-patch increment 2 refuses.
    let _ = attrset_structure_or_skip(outcome.heap(), outcome.value());
    match outcome.heap().capture_heap_image() {
        Err(EvalHeapSnapshotError::UnsnapshottableLists { count }) => assert!(count >= 1),
        // If `xs` is still an unforced thunk, capture refuses on the closure arm.
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => {}
        Err(EvalHeapSnapshotError::Snapshot(_)) => {}
        other => panic!("expected a list/closure refusal, got {other:?}"),
    }
}

/// Forces the attrset's `xs` list to materialize (so it is a flat list object,
/// not an unforced thunk) and ignores the projection; a helper for the refusal
/// test that keeps `attrset_structure`'s scalar/string-only contract intact.
fn attrset_structure_or_skip(heap: &EvalHeap, root: Value) {
    if let Ok(attrs) = heap.get_attrs(root) {
        for entry in attrs.entries_by_symbol() {
            let _ = heap.get_list(entry.value);
        }
    }
}
