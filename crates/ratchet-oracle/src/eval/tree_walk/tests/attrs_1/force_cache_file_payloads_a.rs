//! Force-cache payload tests for readFile-backed attr thunks.

use super::*;

#[test]
fn read_file_backed_inline_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-backed");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let target_path = path_bytes(&root.join("target"));
    fs::write(root.join("target"), &marker_path).expect("target path writes");
    let source = "{ a = builtins.pathExists (builtins.readFile ./target); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("readFile-backed force succeeds")
            .as_bool(),
        Ok(true)
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("readFile-backed force revalidates and hits");

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFile-backed payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, &marker_path).expect("fingerprint builds"),
        ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFile and dependent pathExists edges"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_read_file_backed_inline_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-backed-changed");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let missing_path = path_bytes(&root.join("missing"));
    fs::write(root.join("target"), &marker_path).expect("target path writes");
    let source = "{ a = builtins.pathExists (builtins.readFile ./target); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("readFile-backed force succeeds")
            .as_bool(),
        Ok(true)
    );

    fs::write(root.join("target"), &missing_path).expect("target path changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile-backed force recomputes");

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn force_cache_recompute_same_value_counts_early_cutoff_after_trace_miss() {
    let root = unique_temp_dir("force-cache-read-file-same-value-cutoff");
    fs::write(root.join("target"), b"first").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = r#"{ a = let x = builtins.readFile ./target; in if x == "never" then 4 else 3; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile-backed force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(eval.stats().cache_hits(), 0);
    assert_eq!(eval.stats().cache_misses(), 0);
    assert!(eval.stats().force_cache_memoization_bypasses() > 0);
    assert_eq!(eval.stats().early_cutoffs(), 0);

    let mut admitted_options = TreeWalkOptions::new();
    admitted_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut admitted = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        admitted_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let admitted_root = admitted.eval_root().expect("attrset evaluates again");
    let admitted_thunk = {
        let attrs = admitted
            .heap()
            .get_attrs(admitted_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_admitted = admitted
        .force_value(ir.root, Span::new(0, 0), admitted_thunk)
        .expect("admitted readFile-backed force populates");
    assert_eq!(forced_admitted.as_int(), Ok(3));
    assert_eq!(admitted.stats().cache_hits(), 0);
    assert!(admitted.stats().cache_misses() > 0);
    assert_eq!(admitted.stats().early_cutoffs(), 0);

    fs::write(root.join("target"), b"second").expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(3));
    assert!(changed.stats().thunks_forced() > 0);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
    assert_eq!(changed.stats().early_cutoffs(), 1);

    fs::remove_dir_all(root).expect("temp tree removed");
}
#[test]
fn read_file_string_payload_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-string-payload");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile string payload force succeeds");
    assert_eq!(
        eval.heap()
            .get_string(forced)
            .expect("readFile result is a string")
            .bytes(),
        b"payload"
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let second_forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("readFile string payload revalidates and hits");
    let second_string = second
        .heap()
        .get_string(second_forced)
        .expect("cached string payload rehydrates into second heap");

    assert_eq!(second_string.bytes(), b"payload");
    assert!(!second_string.has_context());
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFile string payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, b"payload").expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFile edges for string payloads"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn hash_file_string_payload_thunks_hit_and_miss_after_binary_revalidation() {
    let root = unique_temp_dir("force-cache-hash-file-string-payload");
    let first_payload = b"payload\0\xffbytes";
    let changed_payload = b"changed\0\xffbytes";
    fs::write(root.join("target"), first_payload).expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = r#"{ a = builtins.hashFile "sha256" ./target; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let first_root = eval.eval_root().expect("attrset evaluates");
    let first_thunk = {
        let attrs = eval
            .heap()
            .get_attrs(first_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let first_forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), first_thunk)
        .expect("hashFile string payload force succeeds");
    let first_hash = eval
        .heap()
        .get_string(first_forced)
        .expect("hashFile result is a string")
        .bytes()
        .to_vec();

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let second_forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("hashFile string payload revalidates and hits");
    let second_hash = second
        .heap()
        .get_string(second_forced)
        .expect("cached hashFile result rehydrates into second heap");

    assert_eq!(second_hash.bytes(), first_hash.as_slice());
    assert!(!second_hash.has_context());
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable hashFile string payloads should hit after binary input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    let expected_trace = vec![
        ImpureInputFingerprint::hash_file(&target_path, first_payload).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay hashFile edges for binary payloads"
    );

    fs::write(root.join("target"), changed_payload).expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates after change");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let changed_forced = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed hashFile payload recomputes");
    let changed_hash = changed
        .heap()
        .get_string(changed_forced)
        .expect("changed hashFile result is a string");

    assert_ne!(changed_hash.bytes(), first_hash.as_slice());
    assert_eq!(
        changed.stats().thunks_forced(),
        1,
        "changed binary hashFile input should miss and recompute"
    );
    assert_eq!(changed.stats().cache_misses(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert_eq!(changed.stats().force_cache_misses(), 1);
    assert_eq!(changed.stats().force_cache_hits(), 0);
    let changed_trace = vec![
        ImpureInputFingerprint::hash_file(&target_path, changed_payload)
            .expect("changed fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn large_read_file_payload_uses_payload_scaled_materialization_work_floor() {
    let persist_root = unique_temp_dir("force-cache-persistent-large-read-file");
    let root = unique_temp_dir("force-cache-large-read-file-source");
    let contents = vec![b'z'; 4096];
    fs::write(root.join("target"), &contents).expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source(&ir, first_options, "default.nix", source);
    force_attr_a_string(&mut first, &ir, a, &contents);
    first.advance_persist_eval_cache_run_boundary();
    drop(first);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    let initial_payloads = persist
        .node_metadata_index()
        .latest_entries()
        .expect("persistent metadata entries load")
        .into_iter()
        .filter_map(|entry| {
            persist
                .load_cached_expression_node_value_indexed(entry.key())
                .expect("persistent payload lookup succeeds")
        })
        .collect::<Vec<_>>();
    assert!(
        initial_payloads.is_empty(),
        "first-run demand should advance into history without materializing yet"
    );
    drop(persist);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source(&ir, second_options, "default.nix", source);
    force_attr_a_string(&mut second, &ir, a, &contents);
    drop(second);

    let expected_payload = CachedExpressionValue::context_free_string(contents.clone());
    let expected_value_hash = expected_payload
        .value_hash()
        .expect("expected readFile payload hashes");
    let expected_trace = ImpureInputFingerprint::read_file(&target_path, &contents)
        .expect("readFile fingerprint builds");
    let expected_trace_payload = PersistNodeTracePayload::from_impure_trace([&expected_trace])
        .expect("trace payload builds");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    let metadata_entries = persist
        .node_metadata_index()
        .latest_entries()
        .expect("persistent metadata entries load");
    let materialized_payloads = metadata_entries
        .iter()
        .filter_map(|entry| {
            persist
                .load_cached_expression_node_value_indexed(entry.key())
                .expect("persistent payload lookup succeeds")
                .map(|payload| (entry, payload))
        })
        .collect::<Vec<_>>();

    let [(entry, payload)] = materialized_payloads.as_slice() else {
        panic!("expected one materialized readFile payload, got {materialized_payloads:?}");
    };
    assert_eq!(
        entry.value().materialized_value_hash(),
        Some(expected_value_hash),
        "large readFile payload should be linked from node metadata"
    );
    assert_eq!(
        payload, &expected_payload,
        "large readFile payload should materialize in the durable value store"
    );
    assert_eq!(
        persist
            .lookup_node_trace(entry.key())
            .expect("persistent trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            entry.key(),
            expected_value_hash,
            expected_trace_payload
        )),
        "large readFile payload should write its verifying trace"
    );

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persist temp tree removed");
}
