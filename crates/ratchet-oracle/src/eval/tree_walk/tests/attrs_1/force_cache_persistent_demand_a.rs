//! Persistent force-cache demand tests for public eval boundaries.

use super::*;

#[test]
fn synthetic_builtin_attr_cold_force_records_demand_without_materializing() {
    let persist_root = unique_temp_dir("force-cache-persistent-demand");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = first
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = first
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let forced = first
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentSystem force succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(0, 1)),
        "cold force records one current-run demand"
    );
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        None,
        "cold force records demand without linking a persistent value payload"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload load succeeds"),
        None,
        "cold force keeps the value in memory until prior-run demand exists"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        None,
        "cold force skips the persistent trace when the value is not materialized"
    );
    drop(persist);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        cache,
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    drop(second);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(0, 2)),
        "admitted recomputation also records current-run demand"
    );
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        None,
        "same-run demand does not predict cross-run reuse until run advancement"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn public_eval_advances_persistent_force_demand_run_boundary() {
    let persist_root = unique_temp_dir("force-cache-persistent-run-boundary");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut key_eval = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
            .expect("currentSystem is valid"),
        "synthetic-builtins.nix",
        source,
    );
    let root = key_eval.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = key_eval
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = key_eval
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = key_eval
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());

    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let attr_path = vec![b"a".to_vec()];
    let first = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        &ir,
        &attr_path,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        None,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    )
    .expect("first attr-path eval succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(first.value())
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::from_previous_run(1)),
        "successful public eval advances cold current demand into prior-run history"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "the cold run still skips the durable value payload before prior demand exists"
    );
    drop(persist);

    let second = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        &ir,
        &attr_path,
        options,
        "synthetic-builtins.nix",
        source,
        None,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    )
    .expect("second attr-path eval succeeds");
    assert_eq!(
        second
            .heap()
            .get_string(second.value())
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );

    let expected_payload = CachedExpressionValue::context_free_string(b"x86_64-linux".to_vec());
    let expected_value_hash = expected_payload
        .value_hash()
        .expect("expected payload hashes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::from_previous_run(2)),
        "second successful public eval advances the new demand observation too"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        Some(expected_payload),
        "prior-run demand lets the next run materialize the durable value payload"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            expected_value_hash,
            persistent_empty_trace_payload()
        )),
        "materialized public evals write the zero-input verifying trace"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn non_owning_public_eval_rejection_does_not_advance_persistent_force_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-rejected-boundary");
    let source = "let b = builtins; in { a = b.currentSystem; }.a";
    let ir = lower(source);

    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let error =
        eval_whnf_with_options(&ir, options).expect_err("non-owning eval rejects heap string");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::String,
        }
    );

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    let entries = persist
        .node_metadata_index()
        .latest_entries()
        .expect("latest metadata entries load");
    let [entry] = entries.as_slice() else {
        panic!("expected one force-cache demand metadata entry, got {entries:?}");
    };
    assert_eq!(
        entry.value().materialization_reuse(),
        MaterializationReuse::new(0, 1),
        "the rejected public wrapper must not promote demand into prior-run history"
    );
    assert_eq!(
        entry.value().materialized_value_hash(),
        None,
        "the rejected public wrapper must not link a durable payload"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(entry.key())
            .expect("persistent payload lookup succeeds"),
        None,
        "the rejected public wrapper must not materialize a durable payload"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn public_eval_without_persistent_force_demand_does_not_open_persist_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-unused-boundary");
    let ir = lower("1 + 2");
    let mut options = TreeWalkOptions::default();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let bytes = eval_number_raw_bytes_with_options(&ir, options).expect("number eval succeeds");
    assert_eq!(bytes, b"3");

    let entries = fs::read_dir(&persist_root)
        .expect("temp root is readable")
        .collect::<Result<Vec<_>, _>>()
        .expect("temp root entries read");
    assert!(
        entries.is_empty(),
        "successful public evals must not create persistent-cache state unless force-cache code opened it"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_hits_persistent_current_system_with_empty_trace() {
    let persist_root = unique_temp_dir("force-cache-persistent-current-system-hit");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = first
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = first
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentSystem force succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            CachedExpressionValue::context_free_string(b"x86_64-linux".to_vec())
                .value_hash()
                .expect("expected payload hashes"),
            persistent_empty_trace_payload()
        )),
        "pure currentSystem payloads use a zero-input verifying trace"
    );
    drop(persist);

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        shared_runtime.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("persistent currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    drop(second);

    {
        let runtime = shared_runtime.lock().expect("cache lock is valid");
        assert_eq!(
            runtime.cache().expect("cache is enabled").len(),
            1,
            "pure persistent hits should seed an in-memory expression node"
        );
    }

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(1, 2)),
        "persistent pure hits also record current-run demand"
    );
    drop(persist);

    fs::remove_dir_all(&persist_root).expect("temp tree removed");

    let mut third_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    third_options.set_eval_cache_enabled(true);
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "synthetic-builtins.nix",
        source,
        shared_runtime,
    );
    let forced = force_attr_a(&mut third, &ir, a);
    assert_eq!(
        third
            .heap()
            .get_string(forced)
            .expect("seeded currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        third.stats().thunks_forced(),
        2,
        "the seeded pure hit should avoid forcing the reified builtin attr thunk"
    );
    assert_eq!(third.stats().cache_hits(), 1);
    assert_eq!(third.stats().cache_misses(), 0);
}

#[test]
fn disabled_eval_cache_skips_persistent_current_system_hit() {
    let persist_root = unique_temp_dir("force-cache-persistent-hit-disabled");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut key_eval = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
            .expect("currentSystem is valid"),
        "synthetic-builtins.nix",
        source,
    );
    let root = key_eval.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = key_eval
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = key_eval
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = key_eval
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let payload = CachedExpressionValue::context_free_string(b"stale-disabled-hit".to_vec());
    let value_hash = payload.value_hash().expect("seed payload hashes");
    let trace_payload = persistent_empty_trace_payload();
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("seed persistent payload materializes");
    persist
        .record_node_trace(key, value_hash, &trace_payload)
        .expect("seed persistent trace records");
    drop(persist);

    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux",
        "disabled eval-cache observation must not rehydrate the seeded persistent payload"
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "disabled eval-cache observation must not count a persistent force hit"
    );
    assert_eq!(
        evaluator.stats().thunks_forced(),
        3,
        "disabled eval-cache observation must force the let binding, attr thunk, and builtin attr normally"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(0, 0)),
        "disabled eval-cache observation must not record fresh persistent demand"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        Some(payload),
        "disabled eval-cache observation must leave the seeded payload unchanged"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            value_hash,
            trace_payload
        )),
        "disabled eval-cache observation must leave the seeded trace unchanged"
    );
    assert_eq!(
        fs::metadata(persist.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64
            + persistent_empty_trace_payload()
                .encode()
                .expect("empty trace payload encodes")
                .len() as u64,
        "disabled eval-cache observation must not append extra persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}
