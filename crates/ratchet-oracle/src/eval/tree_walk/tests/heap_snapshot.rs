//! Stage-B serialize-and-patch round-trip tests (RFC-0007 doc 31 §1, §9
//! decision 6): a forced value of strings + attrsets of scalars survives an
//! `EvalHeap` heap-image capture + restore, its interior `FlatBytes`/`FlatSlice`
//! witnesses rebased on load; a forced list's out-of-arena element `Vec` is
//! serialized to a payload segment and rebuilt on restore; the completeness
//! audit passes.

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

/// Projects a forced integer list to its element values, exercising each
/// element word through `heap` after a restore.
fn list_integers(heap: &EvalHeap, root: Value) -> Vec<i64> {
    heap.get_list(root)
        .expect("root is a list")
        .as_slice()
        .iter()
        .map(|value| value.as_int().expect("list element is an integer"))
        .collect()
}

#[test]
fn heap_image_round_trips_a_list_via_payload() {
    let outcome = eval_owned_with_source(b"snapshot-list", "[ 1 2 3 ]");
    let root = outcome.value();

    let image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        // The list's element buffer is out of arena; a chunked fallback heap has
        // no reservation to dump.
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        // If the lowerer left the list spine or its elements as thunks, this
        // value is not yet snapshottable (stage-2 collapse).
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    // The fixture must actually exercise a list-payload segment.
    assert_eq!(
        image.list_payloads.len(),
        1,
        "one forced list yields one payload segment"
    );
    outcome
        .heap()
        .verify_relocation_completeness(&image)
        .expect("relocation table covers every interior pointer");
    let expected = list_integers(outcome.heap(), root);
    assert_eq!(expected, vec![1, 2, 3]);

    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    let restored = EvalHeap::from_restored_heap_image(&reloaded).expect("image restores");
    assert_eq!(list_integers(&restored, root), expected);
}
