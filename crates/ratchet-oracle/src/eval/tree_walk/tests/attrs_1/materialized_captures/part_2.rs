//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn replayable_payload_extraction_caches_heap_value_hashes() {
    let ir = lower("[ 1 true null ]");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let string = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"seed".to_vec()))
        .expect("string allocates");
    let path = evaluator
        .heap
        .alloc_path(NixString::from_bytes(b"/tmp/seed".to_vec()))
        .expect("path allocates");
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![string, Value::int(7)]))
        .expect("list allocates");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(a, Value::int(1)),
            AttrEntry::new(b, Value::bool(true)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let positioned_attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            a,
            Value::int(1),
            AttrPosition::new(EvalModuleId::ROOT.as_u32(), Span::new(0, 1)),
        )],
        &evaluator.symbols,
    )
    .expect("positioned attrs build");
    let positioned_attrs = evaluator
        .heap
        .alloc_attrs(0, positioned_attrs)
        .expect("positioned attrs allocate");

    for value in [string, path, list, attrs, positioned_attrs] {
        assert_eq!(
            evaluator
                .heap()
                .cached_value_hash(value)
                .expect("heap record exists"),
            None
        );
        let payload = evaluator
            .force_cache_payload_for_value(value)
            .expect("payload extraction succeeds");
        let value_hash = payload.value_hash().expect("payload hashes");

        assert_eq!(
            evaluator
                .heap()
                .cached_value_hash(value)
                .expect("heap record exists"),
            Some(value_hash)
        );
    }

    let stale_path = evaluator
        .heap
        .alloc_path(NixString::from_bytes(b"/tmp/stale".to_vec()))
        .expect("stale path allocates");
    let stale_hash = crate::cache::ValueHash::from_context_free_string_bytes(b"stale");
    evaluator
        .heap()
        .cache_value_hash(stale_path, stale_hash)
        .expect("stale test hash stores");
    let _payload = evaluator
        .force_cache_payload_for_value(stale_path)
        .expect("payload extraction succeeds");
    assert_eq!(
        evaluator
            .heap()
            .cached_value_hash(stale_path)
            .expect("heap record exists"),
        Some(stale_hash),
        "a recomputed mismatch must not silently overwrite an existing heap value hash"
    );
}

#[test]
fn captured_preforced_computed_context_bearing_string_thunks_use_materialized_capture_keys() {
    let source = r#"
      let s = builtins.appendContext "s" {
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source" = { path = true; };
      };
      in builtins.seq s { a = s == s; }
    "#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "context-string-captures.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let hits_before = evaluator.stats().cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured context-bearing string force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(
            evaluator.stats().cache_hits() > hits_before,
            expected_hit,
            "captured preforced context-bearing strings should hash through the fulfilled thunk cell"
        );
    }
}

#[test]
fn lowered_captured_inline_forced_thunks_use_free_variable_hashes() {
    let source = "let f = x: { a = x + 2; }; in [ (f 1).a (f 5).a ]";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "lambda.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured attr force succeeds");
    assert_eq!(first.as_int(), Ok(3));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured attr force succeeds");

    assert_eq!(second.as_int(), Ok(7));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "same lowered attr body with different lambda arguments must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different inline lambda arguments should create distinct demand nodes"
    );
}

#[test]
fn source_less_lowered_captured_inline_forced_thunks_use_free_variable_hashes() {
    let source = "let f = x: { a = x + 2; }; in [ (f 1).a (f 5).a ]";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured attr force succeeds");
    assert_eq!(first.as_int(), Ok(3));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured attr force succeeds");

    assert_eq!(second.as_int(), Ok(7));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "source-less lowered attr bodies with different lambda arguments must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different source-less inline lambda arguments should create distinct demand nodes"
    );
}

#[test]
fn captured_inline_forced_thunks_hit_when_free_variable_hashes_match() {
    let source = "let x = <inline>; in x + 2";
    let ir = manual_inline_capture_force_ir(1);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "manual.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("manual let yields a thunk");
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 23), root)
            .expect("manual captured thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching inline free-variable hashes should share one demand node"
    );
}

#[test]
fn captured_inline_forced_thunks_include_free_variable_hashes_in_cache_key() {
    let source = "let x = <inline>; in x + 2";
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for (captured, expected) in [(1, 3), (5, 7)] {
        let ir = manual_inline_capture_force_ir(captured);
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "manual.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("manual let yields a thunk");
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 23), root)
            .expect("manual captured thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "changed inline free-variable values must not hit an old demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different inline free-variable hashes should create distinct demand nodes"
    );
}

#[test]
fn cold_hash_consed_values_materialize_to_indexed_value_pack_and_replay() {
    let ir = lower("null");
    let persist_root = unique_temp_dir("cold-hash-consed-value-pack");
    let options = TreeWalkOptions::with_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let name = evaluator.symbols.intern(b"name").expect("symbol interns");
    let list_name = evaluator
        .symbols
        .intern(b"list")
        .expect("list symbol interns");

    let string = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"cold-string".to_vec()))
        .expect("string allocates");
    let path = evaluator
        .heap
        .alloc_path(NixString::from_bytes(b"/tmp/cold-path".to_vec()))
        .expect("path allocates");
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![string, Value::int(7)]))
        .expect("list allocates");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(name, path), AttrEntry::new(list_name, list)],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    evaluator
        .heap
        .alloc_thunk(EvalThunk::new(ir.root))
        .expect("worker thunk allocates");

    let cold_values = evaluator
        .heap()
        .cold_hash_consed_values(1)
        .expect("cold values snapshot succeeds");
    let candidate_bytes = cold_values.iter().fold(0usize, |bytes, cold| {
        bytes.saturating_add(cold.size_bytes())
    });

    assert_eq!(cold_values.len(), 4);
    assert!(cold_values.iter().any(|cold| cold.value().raw_eq(string)));
    assert!(cold_values.iter().any(|cold| cold.value().raw_eq(path)));
    assert!(cold_values.iter().any(|cold| cold.value().raw_eq(list)));
    assert!(cold_values.iter().any(|cold| cold.value().raw_eq(attrs)));

    let report = evaluator.materialize_cold_hash_consed_values_indexed(1);
    assert_eq!(report.candidates(), 4);
    assert_eq!(report.candidate_bytes(), candidate_bytes);
    assert_eq!(report.captured(), 4);
    assert_eq!(report.uncapturable(), 0);
    assert_eq!(report.materialized(), 4);
    assert_eq!(report.skipped(), 0);
    assert_eq!(report.errors(), 0);
    assert_eq!(report.cache_unavailable(), 0);
    assert!(report.persistent_payload_bytes() > 0);
    assert_eq!(report.materialized_hashes().len(), 4);

    drop(evaluator);

    let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
    for value_hash in report.materialized_hashes() {
        let payload = persist_cache
            .load_cached_expression_value_indexed(*value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists");
        assert_eq!(payload.value_hash().expect("payload hashes"), *value_hash);

        let mut replay = TreeWalk::with_options(&ir, TreeWalkOptions::new());
        let value = replay
            .value_for_cached_expression_payload_for_test(payload)
            .expect("payload replays");
        let replayed_payload = replay
            .force_cache_payload_for_value(value)
            .expect("replayed value captures");
        assert_eq!(
            replayed_payload
                .value_hash()
                .expect("replayed payload hashes"),
            *value_hash
        );
    }

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
