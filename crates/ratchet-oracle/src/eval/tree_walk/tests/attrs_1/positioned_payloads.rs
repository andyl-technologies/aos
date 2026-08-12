//! Persistent payload tests for source-order and positioned attrsets.

use super::*;

#[test]
fn persistent_source_order_attrset_payloads_rehydrate_source_order() {
    let persist_root = unique_temp_dir("force-cache-persistent-source-order-attrs");
    let (ir, a) = position_free_source_order_attrset_ir();
    let source = "{ a = { c = 2; b = 1; }; }";
    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "persistent-source-order-attrs.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("source-order attrset materializing force succeeds");
    assert_source_order_attrset_ints(&first, forced, &[(b"c", 2), (b"b", 1)]);
    assert_eq!(first.stats().cache_hits(), 0);
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "persistent-source-order-attrs.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_source_order_attrset_ints(&second, forced, &[(b"c", 2), (b"b", 1)]);
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(
        second.persist_force_cache_hit_keys.len(),
        1,
        "fresh runtime should load the durable source-order attrset payload"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn persistent_positioned_attrset_payloads_rehydrate_binding_positions() {
    let persist_root = unique_temp_dir("force-cache-persistent-positioned-attrs");
    let source = "{ a = { b = 1; }; }";
    let source_name = "persistent-positioned-attrs.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let (expected_line, expected_column) = source_line_column(source, "b = 1");
    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        source_name,
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value =
        seed_prior_persistent_demand_for_attr(&mut evaluator, &ir, a, &persist_root, "a");
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("positioned attrset force succeeds");
    let attrs = evaluator
        .heap()
        .get_attrs(forced)
        .expect("forced value is an attrset");
    assert!(
        attrset_has_binding_position(attrs),
        "fixture must force a position-bearing attrset"
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 1);
    drop(evaluator);

    let mut verifier = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        source_name,
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let file = verifier.symbols.intern(b"file").expect("file interns");
    let line = verifier.symbols.intern(b"line").expect("line interns");
    let column = verifier.symbols.intern(b"column").expect("column interns");
    let forced = force_attr_a(&mut verifier, &ir, a);
    let attrs = verifier
        .heap()
        .get_attrs(forced)
        .expect("persistent hit is an attrset");
    assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(1));
    assert!(
        attrset_has_binding_position(attrs),
        "persistent positioned attrset hits must retain binding positions"
    );
    assert_eq!(
        verifier.stats().cache_hits(),
        1,
        "fresh runtime should load the durable positioned attrset payload"
    );
    assert_eq!(verifier.stats().cache_misses(), 0);
    assert!(
        !verifier.persist_force_cache_hit_keys.is_empty(),
        "persistent positioned attrset hit should record the durable node key"
    );

    let position = verifier
        .eval_unsafe_get_attr_pos_attrs_value(
            ir.root,
            Span::new(0, 0),
            b,
            ir.root,
            Span::new(0, source.len() as u32),
            forced,
        )
        .expect("unsafeGetAttrPos succeeds after persistent hit");
    let position_attrs = verifier
        .heap()
        .get_attrs(position)
        .expect("unsafeGetAttrPos returns an attrset");
    let file_value = position_attrs.get(file).expect("file exists");
    let file_string = verifier
        .heap()
        .get_string(file_value)
        .expect("file is a string");
    assert_eq!(file_string.bytes(), source_name.as_bytes());
    assert_eq!(
        position_attrs.get(line).expect("line exists").as_int(),
        Ok(expected_line as i64)
    );
    assert_eq!(
        position_attrs.get(column).expect("column exists").as_int(),
        Ok(expected_column as i64)
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn imported_module_positioned_attrsets_replay_with_module_position_remap() {
    let persist_root = unique_temp_dir("force-cache-persistent-imported-positioned-attrs");
    let root = fs::canonicalize(unique_temp_dir(
        "force-cache-persistent-imported-positioned-attrs-source",
    ))
    .expect("source root canonicalizes");
    let dep_source = "{ a = { b = 1; }; }";
    fs::write(root.join("dep.nix"), dep_source.as_bytes()).expect("import source writes");
    fs::write(root.join("other.nix"), b"{ z = 0; }").expect("other import source writes");
    let source = "{ dep = import ./dep.nix; other = import ./other.nix; }";
    let ir = lower(source);
    let dep = symbol_for(&ir, b"dep");
    let other = symbol_for(&ir, b"other");
    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let (expected_line, expected_column) = source_line_column(dep_source, "b = 1");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = first.eval_root().expect("attrset evaluates");
    let a = first.symbols.intern(b"a").expect("a interns");
    let dep_value = {
        let attrs = first
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(dep).expect("dep import exists")
    };
    let dep_attrs_value = first
        .force_admitted_value(ir.root, Span::new(0, 0), dep_value)
        .expect("dep import force succeeds");
    let misses_before_a = first.stats().cache_misses();
    let thunk_value = {
        let attrs = first
            .heap()
            .get_attrs(dep_attrs_value)
            .expect("dep import evaluates to an attrset");
        attrs.get(a).expect("imported a exists")
    };
    let subject = {
        let thunk = first
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended imported thunk");
        first
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("imported a force-cache subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("imported a force-cache subject has persistent metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("imported a force succeeds");
    let b = first.symbols.intern(b"b").expect("b interns");
    let attrs = first
        .heap()
        .get_attrs(forced)
        .expect("import result is an attrset");
    let position = attrs
        .get_entry(b)
        .expect("b entry exists")
        .position
        .expect("imported binding has source position");
    assert_ne!(
        position.module,
        EvalModuleId::ROOT.as_u32(),
        "fixture must produce a non-root module binding position"
    );
    assert_eq!(first.stats().cache_hits(), 0);
    assert_eq!(first.stats().cache_misses(), misses_before_a + 1);
    drop(first);
    assert!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("cache is enabled")
            .len()
            >= 1,
        "imported-module positioned payloads should populate the shared in-memory force cache"
    );

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent value lookup succeeds")
            .is_some(),
        "imported-module positioned payloads should materialize with own-module remapping"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .map(|trace| !trace.payload().is_tombstone())
            .unwrap_or(false),
        "imported-module positioned payloads should record a live persistent trace"
    );
    drop(persist);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root_value = second.eval_root().expect("second attrset evaluates");
    let (other_value, dep_value) = {
        let attrs = second
            .heap()
            .get_attrs(root_value)
            .expect("second root is an attrset");
        (
            attrs.get(other).expect("other import exists"),
            attrs.get(dep).expect("dep import exists"),
        )
    };
    let other_attrs_value = second
        .force_admitted_value(ir.root, Span::new(0, 0), other_value)
        .expect("other import force succeeds");
    let z = second.symbols.intern(b"z").expect("z interns");
    let other_attrs = second
        .heap()
        .get_attrs(other_attrs_value)
        .expect("other import evaluates to an attrset");
    assert_eq!(other_attrs.get(z).expect("z exists").as_int(), Ok(0));
    let dep_attrs_value = second
        .force_admitted_value(ir.root, Span::new(0, 0), dep_value)
        .expect("dep import force succeeds");
    let second_a = second.symbols.intern(b"a").expect("a interns");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(dep_attrs_value)
            .expect("dep import evaluates to an attrset");
        attrs.get(second_a).expect("imported a exists")
    };
    let hits_before_a = second.stats().cache_hits();
    let misses_before_a = second.stats().cache_misses();
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("imported a force succeeds");
    let b = second.symbols.intern(b"b").expect("b interns");
    let file = second.symbols.intern(b"file").expect("file interns");
    let line = second.symbols.intern(b"line").expect("line interns");
    let column = second.symbols.intern(b"column").expect("column interns");
    let attrs = second
        .heap()
        .get_attrs(forced)
        .expect("import result is an attrset");
    assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(1));
    assert_eq!(
        second.stats().cache_hits(),
        hits_before_a + 1,
        "fresh runtime should replay imported-module positions through the persistent cache"
    );
    assert_eq!(second.stats().cache_misses(), misses_before_a);
    assert!(
        !second.persist_force_cache_hit_keys.is_empty(),
        "imported-module positioned attrsets should record durable hits"
    );
    let position = second
        .eval_unsafe_get_attr_pos_attrs_value(
            ir.root,
            Span::new(0, 0),
            b,
            ir.root,
            Span::new(0, source.len() as u32),
            forced,
        )
        .expect("unsafeGetAttrPos succeeds after persistent hit");
    let position_attrs = second
        .heap()
        .get_attrs(position)
        .expect("unsafeGetAttrPos returns an attrset");
    let file_value = position_attrs.get(file).expect("file exists");
    let file_string = second
        .heap()
        .get_string(file_value)
        .expect("file is a string");
    assert_eq!(
        file_string.bytes(),
        path_bytes(&root.join("dep.nix")),
        "remapped cached binding position should point at the current imported source"
    );
    assert_eq!(
        position_attrs.get(line).expect("line exists").as_int(),
        Ok(expected_line as i64)
    );
    assert_eq!(
        position_attrs.get(column).expect("column exists").as_int(),
        Ok(expected_column as i64)
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("source temp tree removed");
}

#[test]
fn multi_module_positioned_payloads_miss_and_clear_for_persistent_hits() {
    let source_hash_root = unique_temp_dir("force-cache-positioned-source-hash");
    let source = "{ a = { b = 1; }; }";
    let source_name = "multi-module-positioned-attrs.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let mut source_hash_options = TreeWalkOptions::new();
    source_hash_options.set_eval_cache_enabled(true);
    source_hash_options.set_persist_cache_root(&source_hash_root);

    let mut source_hash_evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        source_hash_options,
        source_name,
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root_value = source_hash_evaluator
        .eval_root()
        .expect("source-hash attrset evaluates");
    let thunk_value = {
        let attrs = source_hash_evaluator
            .heap()
            .get_attrs(root_value)
            .expect("source-hash root is an attrset");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = source_hash_evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended thunk");
        source_hash_evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("a force-cache subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("a has persistent metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    PersistCache::open(&source_hash_root)
        .expect("source-hash persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("source-hash prior-run demand records");
    let forced = source_hash_evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("source-hash positioned attrset force succeeds");
    assert!(
        attrset_has_binding_position(
            source_hash_evaluator
                .heap()
                .get_attrs(forced)
                .expect("forced source-hash value is an attrset")
        ),
        "fixture must produce a position-bearing payload"
    );
    drop(source_hash_evaluator);
    let source_hash_payload = PersistCache::open(&source_hash_root)
        .expect("source-hash persistent cache reopens")
        .load_cached_expression_node_value_indexed(key)
        .expect("source-hash payload lookup succeeds")
        .expect("source-hash payload materialized");
    let source_hash = source_hash_payload
        .attr_position_source_hash()
        .expect("positioned payload carries source provenance");
    fs::remove_dir_all(source_hash_root).expect("source-hash temp tree removed");

    let persist_root = unique_temp_dir("force-cache-multi-module-positioned-attrs");
    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator =
        TreeWalk::with_options_and_source_and_eval_cache(&ir, options, source_name, source, cache);
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("a force-cache subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("a has persistent metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let stale_payload = CachedExpressionValue::positioned_attrs(vec![
        (
            b"b".to_vec(),
            Some(AttrPosition::new(
                EvalModuleId::ROOT.as_u32(),
                Span::new(0, 1),
            )),
            CachedExpressionValue::immediate(Value::int(99)).expect("stale int payload builds"),
        ),
        (
            b"c".to_vec(),
            Some(AttrPosition::new(
                EvalModuleId::ROOT.as_u32() + 1,
                Span::new(2, 3),
            )),
            CachedExpressionValue::immediate(Value::int(100)).expect("stale int payload builds"),
        ),
    ])
    .expect("multi-module positioned attrset payload builds")
    .with_attr_position_source_hash(source_hash);
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &persistent_empty_trace_payload())
        .expect("stale persistent trace records");
    drop(persist);

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("a force recomputes after multi-module stale miss");
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let c = evaluator.symbols.intern(b"c").expect("c interns");
    let attrs = evaluator
        .heap()
        .get_attrs(forced)
        .expect("forced a is an attrset");
    assert_eq!(
        attrs.get(b).expect("b exists").as_int(),
        Ok(1),
        "multi-module positioned payload must not replay as the current value"
    );
    assert!(
        attrs.get(c).is_none(),
        "stale multi-module positioned payload must not leak extra bindings"
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 1);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "multi-module positioned payloads clear the durable value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .map(|trace| trace.payload().is_tombstone())
            .unwrap_or(false),
        "multi-module positioned payloads tombstone the durable trace"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn stale_unprovenanced_positioned_payloads_miss_and_clear_for_imported_subjects() {
    let persist_root = unique_temp_dir("force-cache-stale-unprovenanced-positioned-attrs");
    let root = fs::canonicalize(unique_temp_dir(
        "force-cache-stale-unprovenanced-positioned-attrs-source",
    ))
    .expect("source root canonicalizes");
    fs::write(root.join("dep.nix"), b"{ a = { b = 1; }; }").expect("import source writes");
    let source = "import ./dep.nix";
    let ir = lower(source);
    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = evaluator.eval_root().expect("import evaluates");
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
            .expect("import evaluates to an attrset");
        attrs.get(a).expect("imported a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended imported thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("imported a subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("imported a has persistent metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let stale_payload = CachedExpressionValue::positioned_attrs(vec![(
        b"b".to_vec(),
        Some(AttrPosition::new(
            EvalModuleId::ROOT.as_u32(),
            Span::new(0, 1),
        )),
        CachedExpressionValue::immediate(Value::int(99)).expect("stale int payload builds"),
    )])
    .expect("stale positioned attrset payload builds");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                identity,
                subject.free_var_value_hashes.iter().copied(),
                stale_payload.clone(),
            )
            .expect("stale runtime payload seeds");
    }
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &persistent_empty_trace_payload())
        .expect("stale persistent trace records");
    drop(persist);

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("imported a force recomputes after stale miss");
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let attrs = evaluator
        .heap()
        .get_attrs(forced)
        .expect("forced a is an attrset");
    assert_eq!(
        attrs.get(b).expect("b exists").as_int(),
        Ok(1),
        "stale unprovenanced positioned payload must not replay as the imported value"
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 1);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "stale unprovenanced payloads clear the durable value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .map(|trace| trace.payload().is_tombstone())
            .unwrap_or(false),
        "stale unprovenanced payloads tombstone the durable trace"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("source temp tree removed");
}
