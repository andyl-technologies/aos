//! Persistent force-cache value-link materialization tests.

use super::*;

#[test]
fn rejected_force_observation_clears_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-clear-rejected");
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-node",
        )),
        IrId::new(7),
    );
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload = persistent_path_exists_trace_payload(b"/tmp/stale-input", true);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<ValueHash>(),
                stale_payload.clone(),
            )
            .expect("stale runtime payload is seeded");
    }

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("reuse metadata records");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &stale_trace_payload)
        .expect("stale persistent trace records");
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        Value::int(456),
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: false,
        },
    );

    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime
                .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>(),)
                .expect("runtime lookup succeeds")
                .is_none(),
            "rejected observation invalidates the stale runtime payload"
        );
    }
    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    let metadata = persist
        .lookup_node_metadata(key)
        .expect("metadata lookup succeeds")
        .expect("metadata remains present");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3),
        "clearing the value link preserves reuse counters"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "rejected observation clears the stale persistent value link"
    );
    let trace = persist
        .lookup_node_trace(key)
        .expect("persistent trace lookup succeeds")
        .expect("persistent trace tombstone records");
    assert_eq!(trace.key(), key);
    assert!(
        trace.payload().is_tombstone(),
        "rejected observations tombstone stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn cacheable_impure_force_observation_writes_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-impure-writeback");
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-impure",
        )),
        IrId::new(9),
    );
    let child_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-impure-child",
        )),
        IrId::new(10),
    );
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let child_key =
        PersistNodeMetadataKey::for_expression(child_identity, std::iter::empty::<ValueHash>());
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("child payload builds");
    let child_value_hash = child_payload.value_hash().expect("child payload hashes");
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        let child_node = runtime
            .get_or_insert_expression_node(
                child_identity,
                std::iter::empty::<ValueHash>(),
                Some(child_value_hash),
            )
            .expect("child node inserts")
            .expect("cache is enabled");
        let parent_node = runtime
            .get_or_insert_expression_node(identity, std::iter::empty::<ValueHash>(), None)
            .expect("parent node inserts")
            .expect("cache is enabled");
        runtime
            .replace_memo_read_dependencies(parent_node, [child_node])
            .expect("memo-read edge records")
            .expect("cache is enabled");
    }
    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            child_key,
            &child_payload,
            MaterializationDecision::Materialize,
        )
        .expect("child payload materializes");
    persist
        .record_node_trace(
            child_key,
            child_value_hash,
            &persistent_empty_trace_payload(),
        )
        .expect("child trace records");
    let trace_input = ImpureInputFingerprint::path_exists(b"/tmp/aos-cacheable-input", true)
        .expect("pathExists fingerprint builds");
    let expected_trace_payload = PersistNodeTracePayload::from_impure_trace([&trace_input])
        .expect("trace payload builds")
        .with_memo_read_dependency_records([(child_key, child_value_hash)])
        .expect("trace dependency encodes");
    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        Value::bool(true),
        ImpureInputTraceSegment {
            trace: vec![trace_input],
            complete: true,
        },
    );
    assert_eq!(
        evaluator.stats().force_cache_materialization_materializes(),
        1
    );
    assert_eq!(
        evaluator
            .stats()
            .force_cache_materialization_keeps_in_memory(),
        0
    );
    assert_eq!(evaluator.stats().force_cache_materialization_decisions(), 1);

    let expected_payload =
        CachedExpressionValue::immediate(Value::bool(true)).expect("bool payload is cacheable");
    let expected_value_hash = expected_payload
        .value_hash()
        .expect("expected payload hashes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        Some(expected_payload),
        "cacheable impure observations write the persistent value payload"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            expected_value_hash,
            expected_trace_payload
        )),
        "cacheable impure observations write the value-associated persistent verifying trace"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn force_observation_with_unproven_memo_supplier_clears_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-unproven-memo-supplier");
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-unproven-parent",
        )),
        IrId::new(11),
    );
    let child_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-unproven-child",
        )),
        IrId::new(12),
    );
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("child payload builds");
    let child_value_hash = child_payload.value_hash().expect("child payload hashes");
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        let child_node = runtime
            .get_or_insert_expression_node(
                child_identity,
                std::iter::empty::<ValueHash>(),
                Some(child_value_hash),
            )
            .expect("child node inserts")
            .expect("cache is enabled");
        let parent_node = runtime
            .get_or_insert_expression_node(identity, std::iter::empty::<ValueHash>(), None)
            .expect("parent node inserts")
            .expect("cache is enabled");
        runtime
            .replace_memo_read_dependencies(parent_node, [child_node])
            .expect("memo-read edge records")
            .expect("cache is enabled");
    }
    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let trace_input = ImpureInputFingerprint::path_exists(b"/tmp/aos-cacheable-input", true)
        .expect("pathExists fingerprint builds");

    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        Value::bool(true),
        ImpureInputTraceSegment {
            trace: vec![trace_input],
            complete: true,
        },
    );

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "persistent writeback must not omit an unproven memo-read supplier"
    );
    let trace = persist
        .lookup_node_trace(key)
        .expect("persistent trace lookup succeeds")
        .expect("persistent trace tombstone records");
    assert!(
        trace.payload().is_tombstone(),
        "cleared parent writeback should tombstone any prior durable trace"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn large_force_payload_measurement_skips_unprofitable_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-large-skip");
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-large-skip",
        )),
        IrId::new(10),
    );
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let bytes = vec![b'x'; 4096];
    let value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(bytes))
        .expect("large string allocates");

    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );
    assert_eq!(
        evaluator.stats().force_cache_materialization_materializes(),
        0
    );
    assert_eq!(
        evaluator
            .stats()
            .force_cache_materialization_keeps_in_memory(),
        1
    );
    assert_eq!(evaluator.stats().force_cache_materialization_decisions(), 1);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "large one-work-unit payloads stay in memory when measured write cost dominates"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        None,
        "unmaterialized large payloads skip persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}
#[test]
fn force_work_measurement_materializes_large_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-large-work");
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-large-work",
        )),
        IrId::new(10),
    );
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let bytes = vec![b'y'; 4096];
    let value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(bytes.clone()))
        .expect("large string allocates");

    evaluator.observe_forced_inline_expression_result_with_eval_work_units(
        Some(subject),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
        Some(16),
        false,
    );
    assert_eq!(
        evaluator.stats().force_cache_materialization_materializes(),
        1
    );
    assert_eq!(
        evaluator
            .stats()
            .force_cache_materialization_keeps_in_memory(),
        0
    );
    assert_eq!(evaluator.stats().force_cache_materialization_decisions(), 1);

    let expected_payload = CachedExpressionValue::context_free_string(bytes);
    let expected_value_hash = expected_payload
        .value_hash()
        .expect("expected payload hashes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        Some(expected_payload),
        "enough measured work lets large payloads cross the durable threshold"
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
        "materialized large pure payloads write a verifying trace"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}
#[test]
fn unprofitable_force_observation_skips_persistent_value_link_with_prior_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-unprofitable-writeback");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    options.set_force_cache_materialization_costs(MaterializationCosts::new(3, 1, 1, 1));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = evaluator
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
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentSystem force succeeds");
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        evaluator.stats().force_cache_materialization_materializes(),
        0
    );
    assert_eq!(
        evaluator
            .stats()
            .force_cache_materialization_keeps_in_memory(),
        1
    );
    assert_eq!(evaluator.stats().force_cache_materialization_decisions(), 1);
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(1, 1)),
        "production forcing records current demand before the negative threshold skips writeback"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "unprofitable observations do not write persistent value payloads"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        None,
        "unprofitable observations do not write persistent verifying traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}
#[test]
fn unsupported_force_payload_clears_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-clear-unsupported");
    let ir = lower("{ a = 1 / 0; }");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-force-unsupported",
        )),
        IrId::new(11),
    );
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload = persistent_path_exists_trace_payload(b"/tmp/stale-input", true);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &stale_trace_payload)
        .expect("stale persistent trace records");
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let unsupported = evaluator.eval_root().expect("attrset evaluates");
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        unsupported,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );

    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime
                .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>(),)
                .expect("runtime lookup succeeds")
                .is_none(),
            "the runtime starts without a node for the durable-only stale link"
        );
    }
    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "unsupported recomputation clears the stale persistent value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .expect("persistent trace tombstone records")
            .payload()
            .is_tombstone(),
        "unsupported recomputation tombstones stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn observe_payload_memo_serves_repeated_heap_aggregate_encodes() {
    // A heap list forced twice on the observe path: the first encode populates
    // the identity-keyed payload memo, the second is served from it. The
    // in-crate debug re-encode-compare guard also fires on the served hit,
    // asserting it equals a fresh encode.
    let ir = lower("1");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_eval_cache_enabled(true);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    // The memo is opt-in (default off); activate it without touching the
    // process-global environment, which would race concurrent tests.
    evaluator.force_payload_memo.borrow_mut().set_active_for_test();
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![
            Value::int(1),
            Value::int(2),
            Value::int(3),
        ]))
        .expect("list allocates");

    let first = evaluator
        .force_cache_payload_for_value(list)
        .and_then(|payload| payload.value_hash().ok());
    let second = evaluator
        .force_cache_payload_for_value(list)
        .and_then(|payload| payload.value_hash().ok());
    assert!(first.is_some());
    assert_eq!(first, second, "repeated encodes of one address agree");
    assert_eq!(
        evaluator.force_payload_memo.borrow().hits(),
        1,
        "the second encode of the same heap list is served from the memo"
    );
}
