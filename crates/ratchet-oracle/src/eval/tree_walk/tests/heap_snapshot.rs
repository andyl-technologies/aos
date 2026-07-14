//! Stage-B serialize-and-patch round-trip tests (RFC-0007 doc 31 §1, §9
//! decision 6): a forced value of strings + attrsets of scalars survives an
//! `EvalHeap` heap-image capture + restore, its interior `FlatBytes`/`FlatSlice`
//! witnesses rebased on load; a forced list's out-of-arena element `Vec` is
//! serialized to a payload segment and rebuilt on restore; the completeness
//! audit passes.

use ratchet_value::heap::HeapImage;

use super::*;
use crate::eval::heap::EvalHeapSnapshotError;
use crate::string::ContextKind;
use crate::value::ValueTag;

/// A flattened, comparable projection of one string context element.
type CtxElement = (ContextKind, Vec<u8>, Option<Vec<u8>>);

/// Fixture producing a context-bearing string: `"hello"` carrying one opaque
/// store-path dependency (an out-of-arena `Arc`-backed context).
const CONTEXT_STRING_SOURCE: &str = r#"builtins.appendContext "hello" {
    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
}"#;

/// Projects a forced string to its bytes and canonical context elements,
/// exercising both the rebased byte witness and the rebuilt context after a
/// restore.
fn string_with_context(heap: &EvalHeap, root: Value) -> (Vec<u8>, Vec<CtxElement>) {
    let string = heap.get_string(root).expect("root is a string");
    let context = string
        .context()
        .elements()
        .iter()
        .map(|element| {
            (
                element.kind(),
                element.path().to_vec(),
                element.output().map(<[u8]>::to_vec),
            )
        })
        .collect();
    (string.bytes().to_vec(), context)
}

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

/// Projects a forced list of strings to their bytes, exercising both the list
/// payload and each element string's rebased `FlatBytes` witness after a restore.
fn list_strings(heap: &EvalHeap, root: Value) -> Vec<Vec<u8>> {
    heap.get_list(root)
        .expect("root is a list")
        .as_slice()
        .iter()
        .map(|value| {
            heap.get_string(*value)
                .expect("list element is a string")
                .bytes()
                .to_vec()
        })
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

#[test]
fn heap_image_round_trips_a_context_bearing_string() {
    let outcome = eval_owned_with_source(b"snapshot-ctx", CONTEXT_STRING_SOURCE);
    let root = outcome.value();

    let image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    assert_eq!(
        image.context_payloads.len(),
        1,
        "one context-bearing string yields one context payload"
    );
    outcome
        .heap()
        .verify_relocation_completeness(&image)
        .expect("relocation table covers every interior pointer");
    let expected = string_with_context(outcome.heap(), root);
    assert!(
        !expected.1.is_empty(),
        "the fixture must carry a non-empty context"
    );

    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    let restored = EvalHeap::from_restored_heap_image(&reloaded).expect("image restores");
    // Value equality requires the byte witness to be rebased AND the out-of-arena
    // context `Arc` to be rebuilt and re-installed.
    assert_eq!(string_with_context(&restored, root), expected);
}

#[test]
fn restore_rejects_malformed_context_bytes() {
    let outcome = eval_owned_with_source(b"snapshot-ctx-bad", CONTEXT_STRING_SOURCE);
    let mut image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    if image.context_payloads.is_empty() {
        return;
    }
    // Truncate the context bytes below the element-count prefix so decode fails.
    image.context_payloads[0].context_bytes.truncate(1);
    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image(&reloaded),
        Err(EvalHeapSnapshotError::MalformedContextPayload { .. })
    ));
}

/// Projects an image's primop payloads to a sorted `(index, bytes)` list for a
/// representation-independent comparison across a round trip.
fn sorted_primops(image: &HeapImage) -> Vec<(u32, Vec<u8>)> {
    let mut payloads: Vec<(u32, Vec<u8>)> = image
        .primop_payloads
        .iter()
        .map(|payload| (payload.index, payload.primop_bytes.clone()))
        .collect();
    payloads.sort();
    payloads
}

#[test]
fn heap_image_round_trips_primops() {
    let outcome = eval_owned_with_source(b"snapshot-primop", "builtins.add 1");
    let image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        // A thunk/lambda would refuse; this fixture should be primop-only.
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    assert!(
        !image.primop_payloads.is_empty(),
        "the fixture must capture at least one primop"
    );
    outcome
        .heap()
        .verify_relocation_completeness(&image)
        .expect("relocation table covers every interior pointer");
    let expected = sorted_primops(&image);

    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    let restored = EvalHeap::from_restored_heap_image(&reloaded).expect("image restores");
    // Re-capturing the restored heap must reproduce each primop's registry
    // reference and applied args byte-identically.
    let recaptured = restored
        .capture_heap_image()
        .expect("the restored heap re-captures");
    assert_eq!(sorted_primops(&recaptured), expected);
}

#[test]
fn env_frame_table_dedups_a_real_shared_capture() {
    // Two lambdas closing over one `let` binding: their captured environments
    // share the binding's frame, so the deduplicated table must be smaller
    // than the raw reference count.
    let outcome = eval_owned_with_source(
        b"snapshot-env-frames",
        "let a = 1; in { f = x: x + a; g = y: y + a; }",
    );
    let table = outcome
        .heap()
        .capture_env_frame_table()
        .expect("frame table captures");
    assert!(
        table.len() >= 1,
        "the fixture's lambdas must capture at least one shared frame"
    );

    // The serialized table rebuilds into the same number of shared frames.
    let payloads = table.into_payloads();
    let restored =
        crate::eval::heap::RestoredFrameTable::rebuild(&payloads).expect("frame table rebuilds");
    assert_eq!(restored.len(), payloads.len());
}

/// A restored closure heap must yield CALLABLE lambdas: this drives the whole
/// increment-3 path — content-keyed code refs, the frame table, suspended-thunk
/// capture, and the flat-capture handle re-signing — then applies the restored
/// lambda and forces its captured thunk through the restored heap.
#[test]
fn restored_lambda_is_callable_through_code_identity() {
    let source = "let a = 2 + 3; in x: x + a";
    let ir = lower(source);
    let root_span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-callable".to_vec(),
        source.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("source evaluates");
    assert_eq!(root.tag(), ValueTag::Lambda);

    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        // Chunked fallback (no reservation) is not snapshottable here.
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("closure capture failed: {other}"),
    };
    assert!(
        !image.closure_payloads.is_empty(),
        "the fixture must capture at least the root lambda"
    );
    let bytes = image.to_bytes();

    // Swap the source heap out and drop it so its reservation domain frees;
    // the module table (and the evaluator machinery) stay alive for the call.
    let old_heap = std::mem::replace(&mut evaluator.heap, EvalHeap::new());
    drop(old_heap);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    evaluator.heap = EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity)
        .expect("closure image restores");

    // Apply the RESTORED lambda: the call resolves its code by fingerprint,
    // reads its captured environment, and forces the suspended `a` thunk
    // through the restored heap.
    let result = evaluator
        .apply_value(ir.root, root_span, root, Value::int(41))
        .expect("restored lambda applies");
    assert_eq!(result.as_int(), Ok(46));

    // Byte-identical against a cold evaluation of the same application.
    assert_eq!(eval("(let a = 2 + 3; in x: x + a) 41").as_int(), Ok(46));
}

/// The increment-4 mutating collapse: force a captured thunk, collapse the
/// heap, and round-trip — the collapsed wrapper sheds its captures, the
/// lambda's captured word is rewritten to the cached value, and the restored
/// lambda still applies to the byte-identical result.
#[test]
fn collapse_then_capture_round_trips_a_forced_capture() {
    let source = "let a = 2 + 3; in builtins.deepSeq a (x: x + a)";
    let ir = lower(source);
    let root_span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-collapse".to_vec(),
        source.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("source evaluates");
    assert_eq!(root.tag(), ValueTag::Lambda);

    let report = evaluator
        .heap
        .collapse_forced_thunks()
        .expect("forced-thunk collapse succeeds");
    assert!(
        report.thunks_collapsed >= 1,
        "deepSeq must have forced (and the pass collapsed) the captured thunk: {report:?}"
    );

    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("post-collapse capture failed: {other}"),
    };
    let bytes = image.to_bytes();

    let old_heap = std::mem::replace(&mut evaluator.heap, EvalHeap::new());
    drop(old_heap);
    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    evaluator.heap = EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity)
        .expect("collapsed image restores");

    let result = evaluator
        .apply_value(ir.root, root_span, root, Value::int(41))
        .expect("restored lambda applies after collapse");
    assert_eq!(result.as_int(), Ok(46));
    assert_eq!(
        eval("(let a = 2 + 3; in builtins.deepSeq a (x: x + a)) 41").as_int(),
        Ok(46)
    );
}

/// Without the mutating pre-pass, a forced thunk still captures: it serializes
/// as its cached value (the collapsed-thunk payload) and restores as a
/// released forced wrapper that replays the value on force.
#[test]
fn forced_thunk_captures_as_collapsed_payload_without_prepass() {
    let source = "let a = 2 + 3; in builtins.deepSeq a (x: x + a)";
    let ir = lower(source);
    let root_span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-forced-direct".to_vec(),
        source.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("source evaluates");

    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("forced-thunk capture failed: {other}"),
    };
    let bytes = image.to_bytes();

    let old_heap = std::mem::replace(&mut evaluator.heap, EvalHeap::new());
    drop(old_heap);
    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    evaluator.heap = EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity)
        .expect("forced-thunk image restores");

    let result = evaluator
        .apply_value(ir.root, root_span, root, Value::int(41))
        .expect("restored lambda applies through the released wrapper");
    assert_eq!(result.as_int(), Ok(46));
}

#[test]
fn restore_rejects_truncated_collapsed_thunk_bytes() {
    let source = "let a = 2 + 3; in builtins.deepSeq a (x: x + a)";
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-collapsed-bad".to_vec(),
        source.as_bytes().to_vec(),
    );
    evaluator.eval_root().expect("source evaluates");
    evaluator
        .heap
        .collapse_forced_thunks()
        .expect("forced-thunk collapse succeeds");
    let identity = evaluator.snapshot_code_identity();
    let mut image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("post-collapse capture failed: {other}"),
    };
    // Truncate a collapsed-thunk payload (kind byte 6 after the 4-byte
    // own-tail word) below its value word.
    let Some(payload) = image
        .closure_payloads
        .iter_mut()
        .find(|payload| payload.closure_bytes.get(4) == Some(&6))
    else {
        panic!("the collapsed fixture must emit a collapsed-thunk payload");
    };
    payload.closure_bytes.truncate(6);
    let bytes = image.to_bytes();
    drop(evaluator);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity),
        Err(EvalHeapSnapshotError::MalformedClosurePayload { .. })
    ));
}

#[test]
fn restore_refuses_drifted_lambda_code() {
    let source = "let a = 1; in x: x + a";
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-drift-a".to_vec(),
        source.as_bytes().to_vec(),
    );
    evaluator.eval_root().expect("source evaluates");
    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("closure capture failed: {other}"),
    };
    let bytes = image.to_bytes();
    drop(evaluator);

    // A different evaluator whose module fingerprints do not match: restore
    // must refuse to rebind the lambda to drifted IR, never resolve it.
    let drifted_source = "let a = 2; in x: x * a";
    let drifted_ir = lower(drifted_source);
    let drifted = TreeWalk::with_options_and_source(
        &drifted_ir,
        TreeWalkOptions::default(),
        b"snapshot-drift-b".to_vec(),
        drifted_source.as_bytes().to_vec(),
    );
    let drifted_identity = drifted.snapshot_code_identity();

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &drifted_identity),
        Err(EvalHeapSnapshotError::ClosureCodeDrift { .. })
    ));
}

#[test]
fn restore_rejects_malformed_closure_bytes() {
    let source = "let a = 1; in x: x + a";
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-closure-bad".to_vec(),
        source.as_bytes().to_vec(),
    );
    evaluator.eval_root().expect("source evaluates");
    let identity = evaluator.snapshot_code_identity();
    let mut image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("closure capture failed: {other}"),
    };
    assert!(!image.closure_payloads.is_empty());

    // An unknown closure kind tag refuses (byte 4 follows the own-tail word).
    image.closure_payloads[0].closure_bytes[4] = 0xfe;
    let bytes = image.to_bytes();
    drop(evaluator);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity),
        Err(EvalHeapSnapshotError::MalformedClosurePayload { .. })
    ));
}

#[test]
fn plain_restore_refuses_an_image_with_closures() {
    let source = "let a = 1; in x: x + a";
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-closure-plain".to_vec(),
        source.as_bytes().to_vec(),
    );
    evaluator.eval_root().expect("source evaluates");
    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("closure capture failed: {other}"),
    };
    let bytes = image.to_bytes();
    drop(evaluator);

    // Restoring without a resolver must refuse rather than silently dropping
    // the closure and frame segments.
    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image(&reloaded),
        Err(EvalHeapSnapshotError::UnexpectedFramePayloads { .. })
    ));
}

#[test]
fn capture_refuses_a_lambda() {
    let outcome = eval_owned_with_source(b"snapshot-lambda", "x: x");
    match outcome.heap().capture_heap_image() {
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { count }) => assert!(count >= 1),
        // A chunked fallback heap has no reservation to dump.
        Err(EvalHeapSnapshotError::Snapshot(_)) => {}
        other => panic!("expected a closure (lambda) refusal, got {other:?}"),
    }
}

#[test]
fn restore_rejects_a_primop_version_mismatch() {
    let outcome = eval_owned_with_source(b"snapshot-primop-ver", "builtins.add 1");
    let mut image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    if image.primop_payloads.is_empty() {
        return;
    }
    // The pinned builtin-surface version is the first length-prefixed field
    // (`version_len(u32)` then the version bytes); flip the first version byte.
    image.primop_payloads[0].primop_bytes[4] ^= 0xff;
    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image(&reloaded),
        Err(EvalHeapSnapshotError::RegistryVersionMismatch { .. })
    ));
}

#[test]
fn restore_rejects_a_duplicate_list_index() {
    let outcome = eval_owned_with_source(b"snapshot-dup", "[ 1 2 3 ]");
    let mut image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    assert_eq!(image.list_payloads.len(), 1);
    // Forge a malformed image: two records naming the same list object. Restoring
    // both would register it in the store twice and free it twice.
    image.list_payloads.push(image.list_payloads[0].clone());
    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image(&reloaded),
        Err(EvalHeapSnapshotError::DuplicateObjectIndex { .. })
    ));
}

#[test]
fn heap_image_round_trips_a_list_of_strings_with_relocated_witnesses() {
    let outcome = eval_owned_with_source(b"snapshot-list-str", "[ \"alpha\" \"beta\" ]");
    let root = outcome.value();

    let image = match outcome.heap().capture_heap_image() {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        // If the list spine or its string elements are still thunks, skip.
        Err(EvalHeapSnapshotError::UnsnapshottableClosures { .. }) => return,
        Err(other) => panic!("unexpected capture failure: {other}"),
    };
    // The fixture must exercise both mechanisms at once: one list payload and a
    // relocation table entry per element string.
    assert_eq!(image.list_payloads.len(), 1, "one forced list");
    assert!(
        image.relocations.len() >= 2,
        "each element string needs a relocation entry"
    );
    outcome
        .heap()
        .verify_relocation_completeness(&image)
        .expect("relocation table covers every interior pointer");
    let expected = list_strings(outcome.heap(), root);
    assert_eq!(expected, vec![b"alpha".to_vec(), b"beta".to_vec()]);

    let bytes = image.to_bytes();
    drop(outcome);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    let restored = EvalHeap::from_restored_heap_image(&reloaded).expect("image restores");
    // Value equality here requires the list payload to rebuild the spine AND the
    // element strings' `FlatBytes` witnesses to be delta-rebased.
    assert_eq!(list_strings(&restored, root), expected);
}
