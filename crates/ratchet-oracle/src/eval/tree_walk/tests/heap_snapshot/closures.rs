//! Closure-serializer round-trip and acceptance tests (RFC-0007 doc 31 §1
//! step 3): the env-frame table, content-keyed lambda/thunk capture with
//! refuse-on-drift restore, the mutating forced-thunk collapse, owned-storage
//! attrs/string payloads, the hermetic mini-prelude acceptance, and the
//! ignored real-prelude probe. Split from `heap_snapshot.rs` under the
//! RFC-0007 §2 file-size cap.

use super::*;

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

/// Over-threshold attrsets keep moved owned `Vec` arrays behind the arena
/// payload; the dumped headers would restore dangling, so they ride the v8
/// owned-attrs payload segment. 200 entries is safely over the flat-inline
/// element threshold (4096 bytes / ~32 bytes per entry).
#[test]
fn owned_storage_attrs_round_trip_via_payload() {
    const SOURCE: &str = "let s = builtins.listToAttrs (builtins.genList \
         (i: { name = \"k${builtins.toString i}\"; value = i; }) 200); \
         in builtins.seq s (x: builtins.concatStringsSep \",\" \
         [ (builtins.toString (builtins.length (builtins.attrNames s))) \
           (builtins.toString (s.k7 + s.k42 + x)) ])";
    let ir = lower(SOURCE);
    let root_span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-owned-attrs".to_vec(),
        SOURCE.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("source evaluates");

    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("owned-attrs capture failed: {other}"),
    };
    assert!(
        !image.attrs_payloads.is_empty(),
        "a 200-entry attrset must ride the owned-attrs segment"
    );
    let bytes = image.to_bytes();

    let old_heap = std::mem::replace(&mut evaluator.heap, EvalHeap::new());
    drop(old_heap);
    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    evaluator.heap = EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity)
        .expect("owned-attrs image restores");

    let result = evaluator
        .apply_value(ir.root, root_span, root, Value::int(1))
        .expect("restored lambda applies");
    let restored = evaluator
        .heap()
        .get_string(result)
        .expect("result is a string")
        .bytes()
        .to_vec();
    assert_eq!(restored, b"200,50".to_vec());
    assert_eq!(
        restored,
        eval_string_bytes_with_source(b"snapshot-owned-attrs-cold", &format!("({SOURCE}) 1")),
    );
}

/// Over-threshold strings keep a moved owned `Vec<u8>` behind the arena
/// payload; they ride the v8 owned-string payload segment. 4800 bytes is over
/// the 4096-byte flat-inline threshold.
#[test]
fn owned_storage_string_round_trips_via_payload() {
    const SOURCE: &str = "let s = builtins.concatStringsSep \"\" \
         (builtins.genList (i: \"0123456789abcdef\") 300); \
         in builtins.seq s (x: \"${builtins.toString (builtins.stringLength s)}-${s}\")";
    let ir = lower(SOURCE);
    let root_span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-owned-string".to_vec(),
        SOURCE.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("source evaluates");

    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("owned-string capture failed: {other}"),
    };
    assert!(
        !image.string_payloads.is_empty(),
        "a 4800-byte string must ride the owned-string segment"
    );
    let bytes = image.to_bytes();

    let old_heap = std::mem::replace(&mut evaluator.heap, EvalHeap::new());
    drop(old_heap);
    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    evaluator.heap = EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity)
        .expect("owned-string image restores");

    let result = evaluator
        .apply_value(ir.root, root_span, root, Value::int(0))
        .expect("restored lambda applies");
    let restored = evaluator
        .heap()
        .get_string(result)
        .expect("result is a string")
        .bytes()
        .to_vec();
    assert_eq!(restored.len(), 5 + 4800);
    assert!(restored.starts_with(b"4800-0123456789abcdef"));
    assert_eq!(
        restored,
        eval_string_bytes_with_source(b"snapshot-owned-string-cold", &format!("({SOURCE}) 0")),
    );
}

#[test]
fn restore_rejects_malformed_owned_attrs_and_string_bytes() {
    const SOURCE: &str = "let s = builtins.listToAttrs (builtins.genList \
         (i: { name = \"k${builtins.toString i}\"; value = i; }) 200); \
         big = builtins.concatStringsSep \"\" (builtins.genList (i: \"0123456789abcdef\") 300); \
         in builtins.seq s (builtins.seq big (x: x))";
    let ir = lower(SOURCE);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-owned-bad".to_vec(),
        SOURCE.as_bytes().to_vec(),
    );
    evaluator.eval_root().expect("source evaluates");
    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("owned-data capture failed: {other}"),
    };
    assert!(!image.attrs_payloads.is_empty());
    assert!(!image.string_payloads.is_empty());
    drop(evaluator);

    // A permutation slot at or above the entry count refuses (bounds lie).
    let mut bad_attrs = image.clone();
    let len = bad_attrs.attrs_payloads[0].attrs_bytes.len();
    bad_attrs.attrs_payloads[0].attrs_bytes[len - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
    let reloaded = HeapImage::from_bytes(&bad_attrs.to_bytes()).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity),
        Err(EvalHeapSnapshotError::MalformedAttrsPayload { .. })
    ));

    // Truncated owned-string bytes refuse.
    let mut bad_string = image;
    bad_string.string_payloads[0].string_bytes.truncate(3);
    let reloaded = HeapImage::from_bytes(&bad_string.to_bytes()).expect("image parses");
    assert!(matches!(
        EvalHeap::from_restored_heap_image_with_code_identity(&reloaded, &identity),
        Err(EvalHeapSnapshotError::MalformedStringPayload { .. })
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
