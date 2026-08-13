//! Step-4 production-wiring tests (W1/W2): cross-evaluator symbol
//! re-interning, the fresh-evaluator snapshot-adoption acceptance with the
//! lead's position-observability probe, and the manual real-prelude adopt
//! probe. Split from `closures.rs` under the RFC-0007 §2 file-size cap.

use super::*;

/// Step-4 W1 acceptance: cross-evaluator symbol re-interning. Evaluator A
/// captures a forced, collapsed (closure-free) attrset; a FRESH evaluator B —
/// whose root expression interns a *different* symbol population first, so
/// the two id spaces provably diverge — restores it. Selection by name and
/// `attrNames` through B's own symbol table must match A's byte-for-byte:
/// only the W1 re-intern of entry keys (and the induced entry re-sort and
/// permutation recompose) can make that true.
#[test]
fn reinterned_attrs_resolve_in_a_fresh_evaluator() {
    const CAPTURE_SOURCE: &str =
        "let s = { mango = 1; alpha = 2; zebra = 3; }; in builtins.deepSeq s s";
    let ir = lower(CAPTURE_SOURCE);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-reintern-a".to_vec(),
        CAPTURE_SOURCE.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("capture source evaluates");
    assert_eq!(root.tag(), ValueTag::Attrs);
    // Collapse the forced binding thunk so the image is closure-free: W1's
    // acceptance isolates symbol identity from module identity (W2).
    evaluator
        .heap
        .collapse_forced_thunks()
        .expect("forced-thunk collapse succeeds");
    let identity = evaluator.snapshot_code_identity();
    let image = match evaluator
        .heap()
        .capture_heap_image_with_code_identity(&identity, &evaluator.symbols)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("reintern capture failed: {other}"),
    };
    assert!(
        !image.symbol_names.is_empty(),
        "the v9 image must carry the capture-time symbol table"
    );
    let bytes = image.to_bytes();
    let expected_names: Vec<Vec<u8>> = {
        let attrs = evaluator.heap().get_attrs(root).expect("root is attrs");
        attrs
            .iter_lexicographic()
            .map(|entry| {
                evaluator
                    .symbols
                    .resolve(entry.key)
                    .expect("capture symbol resolves")
                    .to_vec()
            })
            .collect()
    };
    drop(evaluator);

    // A fresh evaluator whose root interns a disjoint symbol population
    // first, forcing the id spaces apart before the restore.
    const FRESH_SOURCE: &str = "let qq = 1; rr = 2; ss = 3; tt = 4; uu = 5; in qq";
    let fresh_ir = lower(FRESH_SOURCE);
    let mut fresh = TreeWalk::with_options_and_source(
        &fresh_ir,
        TreeWalkOptions::default(),
        b"snapshot-reintern-b".to_vec(),
        FRESH_SOURCE.as_bytes().to_vec(),
    );
    fresh.eval_root().expect("fresh source evaluates");
    let fresh_identity = fresh.snapshot_code_identity();
    let old_heap = std::mem::replace(&mut fresh.heap, EvalHeap::new());
    drop(old_heap);

    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    fresh.heap = EvalHeap::from_restored_heap_image_with_code_identity(
        &reloaded,
        &fresh_identity,
        &mut fresh.symbols,
    )
    .expect("cross-evaluator restore succeeds");

    // Selection by NAME through the fresh evaluator's own symbol table: the
    // key ids in the restored entries must be the fresh table's ids.
    let attrs = fresh
        .heap()
        .get_attrs(root)
        .expect("restored root is attrs");
    for (name, want) in [
        (&b"mango"[..], 1i64),
        (&b"alpha"[..], 2),
        (&b"zebra"[..], 3),
    ] {
        let symbol = fresh
            .symbols
            .lookup(name)
            .expect("restored name is interned in the fresh table");
        let entry = attrs
            .entries_by_symbol()
            .binary_search_by(|entry| entry.key.cmp(&symbol))
            .map(|slot| &attrs.entries_by_symbol()[slot])
            .unwrap_or_else(|_| panic!("selection by fresh id finds {:?}", name));
        assert_eq!(entry.value.as_int(), Ok(want));
    }
    // attrNames order (lexicographic by NAME) is byte-identical to A's.
    let restored_names: Vec<Vec<u8>> = attrs
        .iter_lexicographic()
        .map(|entry| {
            fresh
                .symbols
                .resolve(entry.key)
                .expect("restored symbol resolves in the fresh table")
                .to_vec()
        })
        .collect();
    assert_eq!(restored_names, expected_names);
    assert_eq!(
        restored_names,
        vec![b"alpha".to_vec(), b"mango".to_vec(), b"zebra".to_vec()]
    );
}

/// Step-4 W2 acceptance — THE ruled fresh-evaluator gate. A warmer evaluator
/// A imports a mini prelude from disk, deep-forces it, collapses, and
/// captures image + manifest. A FRESH evaluator B over a DIFFERENT root
/// expression adopts the snapshot before evaluating: the manifest reloads the
/// prelude module (so code fingerprints re-resolve), the restore re-interns
/// ids into B's tables, and the import seed makes B's `import` return the
/// restored prelude WITHOUT re-forcing. B's result must be byte-identical to
/// a cold evaluator C of the same expression, and the lead's
/// position-observability condition is probed via `unsafeGetAttrPos` over a
/// restored, reachable attr.
#[test]
fn fresh_evaluator_adopts_a_prelude_snapshot_byte_identically() {
    const MINI_PRELUDE: &str = r#"rec {
  version = "1.2.3";
  greet = who: "hello-${who}-${version}";
  join = sep: xs: builtins.concatStringsSep sep xs;
  names = [ "a" "b" "c" ];
}"#;
    let dir = unique_temp_dir("snapshot-adopt");
    let lib_path = dir.join("mini-lib.nix");
    fs::write(&lib_path, MINI_PRELUDE).expect("mini prelude writes");
    let lib_str = lib_path.to_str().expect("temp path is utf-8");

    // Warmer A: import + deep-force the prelude, collapse, capture.
    let warmer_source =
        format!("let lib = import {lib_str}; forced = builtins.deepSeq lib lib; in forced");
    let ir = lower(&warmer_source);
    let mut warmer = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"snapshot-warmer".to_vec(),
        warmer_source.as_bytes().to_vec(),
    );
    let warmed_root = warmer.eval_root().expect("warmer evaluates");
    assert_eq!(warmed_root.tag(), ValueTag::Attrs);
    warmer
        .heap
        .collapse_forced_thunks()
        .expect("forced-thunk collapse succeeds");
    let identity = warmer.snapshot_code_identity();
    let image = match warmer
        .heap()
        .capture_heap_image_with_code_identity(&identity, &warmer.symbols)
    {
        Ok(image) => image,
        Err(EvalHeapSnapshotError::Snapshot(_)) => return,
        Err(other) => panic!("warmer capture failed: {other}"),
    };
    let manifest = warmer.snapshot_manifest();
    assert!(
        manifest
            .import_seeds
            .iter()
            .any(|(path, _)| path.ends_with("mini-lib.nix")),
        "the manifest must seed the prelude import"
    );
    let bytes = image.to_bytes();
    drop(warmer);

    // Consumer B: a DIFFERENT root expression over the same prelude. Adopt
    // the snapshot BEFORE evaluating.
    let consumer_source = format!(
        "let zz = 1; lib = import {lib_str}; in lib.join \"-\" [ (lib.greet \"world\") \
         (builtins.toString (builtins.length lib.names)) \
         (builtins.toString (builtins.length (builtins.attrNames lib))) ]"
    );
    let consumer_ir = lower(&consumer_source);
    let root_span = consumer_ir
        .arena
        .node(consumer_ir.root)
        .expect("root node exists")
        .span;
    let _ = root_span;
    let mut consumer = TreeWalk::with_options_and_source(
        &consumer_ir,
        TreeWalkOptions::default(),
        b"snapshot-consumer".to_vec(),
        consumer_source.as_bytes().to_vec(),
    );
    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    consumer
        .adopt_heap_snapshot(&manifest, &reloaded)
        .expect("fresh evaluator adopts the snapshot");
    let value = consumer.eval_root().expect("consumer evaluates");
    let restored_bytes = consumer
        .heap()
        .get_string(value)
        .expect("consumer result is a string")
        .bytes()
        .to_vec();
    // The import must be served by the seed, never re-evaluated.
    assert_eq!(
        consumer.stats_snapshot().imports_evaluated,
        0,
        "the seeded import must not re-force the prelude"
    );

    // Cold evaluator C: same expression, no snapshot.
    let cold_bytes = eval_string_bytes_with_source(b"snapshot-cold", &consumer_source);
    assert_eq!(restored_bytes, cold_bytes);
    assert_eq!(restored_bytes, b"hello-world-1.2.3-3-4".to_vec());

    // Release the restored reservation domain before the second adopt: an
    // image's domain supports one live restore at a time.
    drop(consumer);

    // Position-observability probe (the lead's W1 degradation condition): a
    // reachable restored attr's position must be REAL — byte-identical to the
    // cold evaluator's — never degraded. The prelude module is manifest-
    // reloaded, so its positions re-resolve.
    let probe_source =
        format!("builtins.toJSON (builtins.unsafeGetAttrPos \"greet\" (import {lib_str}))");
    let probe_ir = lower(&probe_source);
    let mut probe = TreeWalk::with_options_and_source(
        &probe_ir,
        TreeWalkOptions::default(),
        b"snapshot-pos-probe".to_vec(),
        probe_source.as_bytes().to_vec(),
    );
    probe
        .adopt_heap_snapshot(
            &manifest,
            &HeapImage::from_bytes(&bytes).expect("image reparses"),
        )
        .expect("probe evaluator adopts the snapshot");
    let probe_value = probe.eval_root().expect("position probe evaluates");
    let probe_bytes = probe
        .heap()
        .get_string(probe_value)
        .expect("probe result is a string")
        .bytes()
        .to_vec();
    let cold_probe = eval_string_bytes_with_source(b"snapshot-pos-cold", &probe_source);
    assert_eq!(
        probe_bytes, cold_probe,
        "reachable restored attr positions must not degrade"
    );
    assert_ne!(
        probe_bytes,
        b"null".to_vec(),
        "the probe must observe a real position"
    );
}

/// Manual real-prelude ADOPT probe (step-4 W2). Ignored by default — the
/// production-shaped flow: a warmer evaluator forces the real prelude and
/// captures image + manifest; a FRESH consumer evaluator over a different
/// root adopts the snapshot before evaluating and must be byte-identical to
/// its own cold evaluation, with the prelude import served by the seed.
///
/// ```text
/// AOS_NIX_SNAPSHOT_WARMER='let lib = import /abs/lib { system = "x86_64-linux"; };
///                          in builtins.deepSeq lib lib' \
/// AOS_NIX_SNAPSHOT_CONSUMER='let lib = import /abs/lib { system = "x86_64-linux"; };
///                            in lib.concatStringsSep "-" [ "adopted" (builtins.toString
///                            (builtins.length (builtins.attrNames lib))) ]' \
///   cargo test -p ratchet-oracle --features candidate_c_value \
///     snapshot_adopt_probe -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual probe; set AOS_NIX_SNAPSHOT_WARMER and AOS_NIX_SNAPSHOT_CONSUMER"]
fn snapshot_adopt_probe() {
    let (Some(warmer_expr), Some(consumer_expr)) = (
        std::env::var_os("AOS_NIX_SNAPSHOT_WARMER"),
        std::env::var_os("AOS_NIX_SNAPSHOT_CONSUMER"),
    ) else {
        eprintln!("AOS_NIX_SNAPSHOT_WARMER / AOS_NIX_SNAPSHOT_CONSUMER unset; nothing to probe");
        return;
    };
    let warmer_expr = warmer_expr.to_string_lossy().into_owned();
    let consumer_expr = consumer_expr.to_string_lossy().into_owned();
    // AOS_NIX_SNAPSHOT_PROBE_CACHE points every evaluator in the probe at a
    // shared parse-cache root, reproducing the production cache posture (the
    // W5 protocol): run the probe once to warm the cache, then measure.
    let probe_options = || {
        let mut options = TreeWalkOptions::default();
        if let Some(cache) = std::env::var_os("AOS_NIX_SNAPSHOT_PROBE_CACHE") {
            options.set_parse_cache_root(std::path::PathBuf::from(cache).join("parse"));
        }
        options
    };

    let warmer_ir = lower(&warmer_expr);
    let mut warmer = TreeWalk::with_options_and_source(
        &warmer_ir,
        probe_options(),
        b"snapshot-adopt-warmer".to_vec(),
        warmer_expr.as_bytes().to_vec(),
    );
    let warm_start = std::time::Instant::now();
    warmer.eval_root().expect("warmer evaluates");
    eprintln!(
        "probe: warmer forced the prelude in {:?}",
        warm_start.elapsed()
    );
    let report = warmer
        .heap
        .collapse_forced_thunks()
        .expect("collapse succeeds");
    eprintln!("probe: collapse report {report:?}");
    let identity = warmer.snapshot_code_identity();
    let image = warmer
        .heap()
        .capture_heap_image_with_code_identity(&identity, &warmer.symbols)
        .expect("warmer capture succeeds (zero refused)");
    let manifest = warmer.snapshot_manifest();
    let bytes = image.to_bytes();
    eprintln!(
        "probe: image {} bytes; manifest {} modules, {} import seeds, {} symbols",
        bytes.len(),
        manifest.modules.len(),
        manifest.import_seeds.len(),
        image.symbol_names.len(),
    );
    drop(warmer);

    let consumer_ir = lower(&consumer_expr);
    let mut consumer = TreeWalk::with_options_and_source(
        &consumer_ir,
        probe_options(),
        b"snapshot-adopt-consumer".to_vec(),
        consumer_expr.as_bytes().to_vec(),
    );
    let adopt_start = std::time::Instant::now();
    let reloaded = HeapImage::from_bytes(&bytes).expect("image parses");
    consumer
        .adopt_heap_snapshot(&manifest, &reloaded)
        .expect("fresh consumer adopts the snapshot");
    eprintln!(
        "probe: adopt (reload+restore+seed) took {:?}",
        adopt_start.elapsed()
    );
    let eval_start = std::time::Instant::now();
    let value = consumer.eval_root().expect("consumer evaluates");
    eprintln!(
        "probe: consumer eval took {:?}; imports re-evaluated: {}",
        eval_start.elapsed(),
        consumer.stats_snapshot().imports_evaluated,
    );
    let restored_bytes = consumer
        .heap()
        .get_string(value)
        .expect("consumer result is a string")
        .bytes()
        .to_vec();
    drop(consumer);

    let cold_start = std::time::Instant::now();
    let cold = {
        let cold_ir = lower(&consumer_expr);
        let mut cold_eval = TreeWalk::with_options_and_source(
            &cold_ir,
            probe_options(),
            b"snapshot-adopt-cold".to_vec(),
            consumer_expr.as_bytes().to_vec(),
        );
        let value = cold_eval.eval_root().expect("cold consumer evaluates");
        cold_eval
            .heap()
            .get_string(value)
            .expect("cold result is a string")
            .bytes()
            .to_vec()
    };
    eprintln!("probe: cold consumer eval took {:?}", cold_start.elapsed());
    assert_eq!(
        restored_bytes, cold,
        "adopted evaluation must be byte-identical to cold"
    );
    eprintln!(
        "probe: BYTE-IDENTICAL result {:?}",
        String::from_utf8_lossy(&restored_bytes)
    );
}

/// Step-4 W3/W4: the on-disk snapshot tier round-trips through a file — a
/// warmer writes atomically, a fresh consumer adopts from disk and evaluates
/// byte-identically — and every storage-level failure (corruption, missing
/// file) is a REFUSAL that falls back to the cold path, never an error.
#[test]
fn snapshot_file_round_trips_and_refusals_fall_back() {
    use crate::eval::tree_walk::eval_core::SnapshotAdoptAttempt;

    const MINI_PRELUDE: &str = r#"rec {
  tag = "disk";
  greet = who: "hi-${who}-${tag}";
}"#;
    let dir = unique_temp_dir("snapshot-store");
    let lib_path = dir.join("mini-lib.nix");
    fs::write(&lib_path, MINI_PRELUDE).expect("mini prelude writes");
    let lib_str = lib_path.to_str().expect("temp path is utf-8");
    let snapshot_path = dir.join("snapshots").join("prelude-test.aosnap");

    // Warmer: force, then write the snapshot file (collapse + capture + wrap).
    let warmer_source =
        format!("let lib = import {lib_str}; forced = builtins.deepSeq lib lib; in forced");
    let warmer_ir = lower(&warmer_source);
    let mut warmer = TreeWalk::with_options_and_source(
        &warmer_ir,
        TreeWalkOptions::default(),
        b"snapshot-store-warmer".to_vec(),
        warmer_source.as_bytes().to_vec(),
    );
    warmer.eval_root().expect("warmer evaluates");
    match warmer.write_prelude_snapshot_to(&snapshot_path) {
        Ok(()) => {}
        // Chunked fallback (no reservation) is not snapshottable here.
        Err(_) if !snapshot_path.exists() => return,
        Err(error) => panic!("warmer snapshot write failed: {error}"),
    }
    assert!(snapshot_path.exists());
    drop(warmer);

    // Fresh consumer adopts FROM DISK and evaluates byte-identically.
    let consumer_source = format!("(import {lib_str}).greet \"disk-user\"");
    let consumer_ir = lower(&consumer_source);
    let mut consumer = TreeWalk::with_options_and_source(
        &consumer_ir,
        TreeWalkOptions::default(),
        b"snapshot-store-consumer".to_vec(),
        consumer_source.as_bytes().to_vec(),
    );
    match consumer.try_adopt_snapshot_file(&snapshot_path) {
        SnapshotAdoptAttempt::Adopted => {}
        other => panic!("disk adoption should succeed: {other:?}"),
    }
    let value = consumer.eval_root().expect("consumer evaluates");
    let adopted = consumer
        .heap()
        .get_string(value)
        .expect("consumer result is a string")
        .bytes()
        .to_vec();
    assert_eq!(consumer.stats_snapshot().imports_evaluated, 0);
    drop(consumer);
    let cold = eval_string_bytes_with_source(b"snapshot-store-cold", &consumer_source);
    assert_eq!(adopted, cold);
    assert_eq!(adopted, b"hi-disk-user-disk".to_vec());

    // A corrupted wrapper REFUSES (digest) and leaves the evaluator on the
    // cold path; a missing file likewise.
    let mut corrupted = fs::read(&snapshot_path).expect("snapshot reads");
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xff;
    let corrupted_path = dir.join("snapshots").join("corrupted.aosnap");
    fs::write(&corrupted_path, corrupted).expect("corrupted snapshot writes");
    let fallback_ir = lower(&consumer_source);
    let mut fallback = TreeWalk::with_options_and_source(
        &fallback_ir,
        TreeWalkOptions::default(),
        b"snapshot-store-fallback".to_vec(),
        consumer_source.as_bytes().to_vec(),
    );
    assert!(matches!(
        fallback.try_adopt_snapshot_file(&corrupted_path),
        SnapshotAdoptAttempt::Refused(_)
    ));
    assert!(matches!(
        fallback.try_adopt_snapshot_file(&dir.join("missing.aosnap")),
        SnapshotAdoptAttempt::Refused(_)
    ));
    // The refused evaluator still evaluates cold, byte-identically.
    let value = fallback.eval_root().expect("cold fallback evaluates");
    let fallback_bytes = fallback
        .heap()
        .get_string(value)
        .expect("fallback result is a string")
        .bytes()
        .to_vec();
    assert_eq!(fallback_bytes, cold);
}
