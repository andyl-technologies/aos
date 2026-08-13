//! Memo-read edge coverage for force-cache identity hits.

use super::*;

#[test]
fn source_backed_active_force_cache_hits_record_memo_read_edges() {
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(b"memo-read-child")),
        IrId::new(1),
    );
    let parent_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(b"memo-read-parent")),
        IrId::new(2),
    );
    let child_subject = synthetic_selected_force_cache_subject(child_identity);
    let parent_subject = synthetic_selected_force_cache_subject(parent_identity);
    let child_node = {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                child_identity,
                std::iter::empty::<ValueHash>(),
                CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds"),
            )
            .expect("child payload observes")
            .expect("cache is enabled")
            .node()
    };
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let parent_node = evaluator
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");
    evaluator
        .active_memo_read_nodes
        .push(ActiveMemoReadNode::new(parent_node));
    let forced = evaluator
        .lookup_forced_inline_expression_result(Some(child_subject))
        .expect("child force-cache payload hits");
    assert_eq!(forced.as_int(), Ok(3));
    let active = evaluator
        .active_memo_read_nodes
        .pop()
        .expect("test-controlled active node pops");
    assert_eq!(
        active.node(),
        parent_node,
        "test-controlled active node stack should be balanced"
    );
    evaluator.replace_active_memo_reads(active);
    assert_eq!(
        evaluator.stats().cache_hits(),
        1,
        "cached child lookup should record a force-cache hit"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    assert!(parent.dependencies().contains(&child_node));
    assert!(
        parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .expect("parent has memo-read edges")
            .contains(&child_node)
    );
    assert!(
        cache
            .graph()
            .node(child_node)
            .expect("child node is present")
            .dependents()
            .contains(&parent_node)
    );
}

#[test]
fn source_backed_active_force_cache_hits_replace_prior_memo_read_edges() {
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let stale_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"stale-memo-read-child",
        )),
        IrId::new(1),
    );
    let fresh_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"fresh-memo-read-child",
        )),
        IrId::new(2),
    );
    let parent_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"replacement-memo-read-parent",
        )),
        IrId::new(3),
    );
    let fresh_subject = synthetic_selected_force_cache_subject(fresh_identity);
    let parent_subject = synthetic_selected_force_cache_subject(parent_identity);
    let (stale_node, fresh_node) = {
        let mut runtime = cache.lock().expect("cache lock is valid");
        let stale_node = runtime
            .observe_inline_expression_payload(
                stale_identity,
                std::iter::empty::<ValueHash>(),
                CachedExpressionValue::immediate(Value::int(1)).expect("stale int payload builds"),
            )
            .expect("stale child payload observes")
            .expect("cache is enabled")
            .node();
        let fresh_node = runtime
            .observe_inline_expression_payload(
                fresh_identity,
                std::iter::empty::<ValueHash>(),
                CachedExpressionValue::immediate(Value::int(2)).expect("fresh int payload builds"),
            )
            .expect("fresh child payload observes")
            .expect("cache is enabled")
            .node();
        (stale_node, fresh_node)
    };
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let parent_node = evaluator
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .cache_mut()
            .expect("cache is enabled")
            .record_memo_read_dependency(parent_node, stale_node)
            .expect("stale memo-read edge records");
    }

    evaluator
        .active_memo_read_nodes
        .push(ActiveMemoReadNode::new(parent_node));
    let forced = evaluator
        .lookup_forced_inline_expression_result(Some(fresh_subject))
        .expect("fresh child force-cache payload hits");
    assert_eq!(forced.as_int(), Ok(2));
    let active = evaluator
        .active_memo_read_nodes
        .pop()
        .expect("test-controlled active node pops");
    assert_eq!(
        active.node(),
        parent_node,
        "test-controlled active node stack should be balanced"
    );
    evaluator.replace_active_memo_reads(active);

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    let memo_reads = parent
        .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
        .expect("parent has replacement memo-read edges");
    assert_eq!(memo_reads.len(), 1);
    assert!(memo_reads.contains(&fresh_node));
    assert!(!memo_reads.contains(&stale_node));
    assert!(
        cache
            .graph()
            .node(fresh_node)
            .expect("fresh child node is present")
            .dependents()
            .contains(&parent_node)
    );
    assert!(
        !cache
            .graph()
            .node(stale_node)
            .expect("stale child node is present")
            .dependents()
            .contains(&parent_node),
        "stale reverse dependent edge should be removed"
    );
}

#[test]
fn source_backed_parent_force_without_hits_clears_prior_memo_read_edges() {
    let source = "{ parent = 2 + 3; }";
    let ir = lower(source);
    let parent = symbol_for(&ir, b"parent");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let stale_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"empty-replacement-stale-child",
        )),
        IrId::new(1),
    );
    let stale_node = {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                stale_identity,
                std::iter::empty::<ValueHash>(),
                CachedExpressionValue::immediate(Value::int(1)).expect("stale int payload builds"),
            )
            .expect("stale child payload observes")
            .expect("cache is enabled")
            .node()
    };
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let parent_thunk = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(parent).expect("parent exists")
    };
    let parent_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(parent_thunk)
            .expect("parent remains a suspended thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("parent force-cache subject builds")
    };
    let parent_node = evaluator
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .cache_mut()
            .expect("cache is enabled")
            .record_memo_read_dependency(parent_node, stale_node)
            .expect("stale memo-read edge records");
    }

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), parent_thunk)
        .expect("parent force succeeds");

    assert_eq!(forced.as_int(), Ok(5));
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    assert!(
        parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .is_none(),
        "successful replacement with no hits should clear prior memo-read edges"
    );
    assert!(
        !cache
            .graph()
            .node(stale_node)
            .expect("stale child node is present")
            .dependents()
            .contains(&parent_node),
        "stale reverse dependent edge should be removed"
    );
}

#[test]
fn source_backed_active_force_cache_child_misses_record_memo_read_edges() {
    let source = "{ child = 1 + 2; }";
    let ir = lower(source);
    let child = symbol_for(&ir, b"child");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let parent_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"cold-memo-read-parent",
        )),
        IrId::new(1),
    );
    let parent_subject = synthetic_selected_force_cache_subject(parent_identity);
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let child_thunk = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(child).expect("child exists")
    };
    let child_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(child_thunk)
            .expect("child remains a suspended thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("child force-cache subject builds")
    };
    let child_key = crate::cache::DemandCacheKey::for_free_vars(
        child_subject
            .lookup_identity
            .expect("child has lookup identity"),
        child_subject.free_var_value_hashes.iter().copied(),
    )
    .expect("child runtime key builds");
    let parent_node = evaluator
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");

    evaluator
        .active_memo_read_nodes
        .push(ActiveMemoReadNode::new(parent_node));
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), child_thunk)
        .expect("child force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    let active = evaluator
        .active_memo_read_nodes
        .pop()
        .expect("test-controlled active node pops");
    assert_eq!(
        active.node(),
        parent_node,
        "test-controlled active node stack should be balanced"
    );
    evaluator.replace_active_memo_reads(active);
    assert_eq!(
        evaluator.stats().cache_misses(),
        1,
        "child should be evaluated from a cold force-cache miss"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let child_node = cache
        .graph()
        .node_id_for_key(child_key)
        .expect("child miss should allocate and observe a runtime node");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    assert!(parent.dependencies().contains(&child_node));
    assert!(
        parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .expect("parent has memo-read edges")
            .contains(&child_node)
    );
    assert!(
        cache
            .graph()
            .node(child_node)
            .expect("child node is present")
            .dependents()
            .contains(&parent_node)
    );
}

#[test]
fn source_backed_active_persistent_force_cache_hits_record_memo_read_edges() {
    let persist_root = unique_temp_dir("force-cache-persistent-memo-read");
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-memo-read-child",
        )),
        IrId::new(1),
    );
    let parent_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-memo-read-parent",
        )),
        IrId::new(2),
    );
    let child_subject = synthetic_selected_force_cache_subject(child_identity);
    let parent_subject = synthetic_selected_force_cache_subject(parent_identity);
    let child_payload =
        CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds");
    let child_value_hash = child_payload.value_hash().expect("child payload hashes");
    let child_persist_key =
        PersistNodeMetadataKey::for_expression(child_identity, std::iter::empty::<ValueHash>());
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            child_persist_key,
            &child_payload,
            crate::cache::MaterializationDecision::Materialize,
        )
        .expect("child payload materializes");
    persist
        .record_node_trace(
            child_persist_key,
            child_value_hash,
            &persistent_empty_trace_payload(),
        )
        .expect("child empty trace records");
    drop(persist);

    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let parent_node = evaluator
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");
    evaluator
        .active_memo_read_nodes
        .push(ActiveMemoReadNode::new(parent_node));
    let forced = evaluator
        .lookup_forced_inline_expression_result(Some(child_subject))
        .expect("child persistent force-cache payload hits");
    assert_eq!(forced.as_int(), Ok(3));
    let active = evaluator
        .active_memo_read_nodes
        .pop()
        .expect("test-controlled active node pops");
    assert_eq!(
        active.node(),
        parent_node,
        "test-controlled active node stack should be balanced"
    );
    evaluator.replace_active_memo_reads(active);
    assert_eq!(evaluator.stats().cache_hits(), 1);
    assert_eq!(evaluator.stats().cache_misses(), 0);

    let child_key = crate::cache::DemandCacheKey::for_free_vars(
        child_identity,
        std::iter::empty::<ValueHash>(),
    )
    .expect("child runtime key builds");
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let child_node = cache
        .graph()
        .node_id_for_key(child_key)
        .expect("child persistent hit seeded runtime node");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    assert!(parent.dependencies().contains(&child_node));
    assert!(
        parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .expect("parent has memo-read edges")
            .contains(&child_node)
    );
    assert!(
        cache
            .graph()
            .node(child_node)
            .expect("child node is present")
            .dependents()
            .contains(&parent_node)
    );
    drop(runtime);

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn persistent_force_cache_hit_rejects_dirty_runtime_supplier() {
    let persist_root = unique_temp_dir("force-cache-persistent-dirty-supplier");
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-dirty-supplier-child",
        )),
        IrId::new(1),
    );
    let child_subject = synthetic_selected_force_cache_subject(child_identity);
    let child_payload =
        CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds");
    let child_value_hash = child_payload.value_hash().expect("child payload hashes");
    let child_persist_key =
        PersistNodeMetadataKey::for_expression(child_identity, std::iter::empty::<ValueHash>());
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            child_persist_key,
            &child_payload,
            crate::cache::MaterializationDecision::Materialize,
        )
        .expect("child payload materializes");
    persist
        .record_node_trace(
            child_persist_key,
            child_value_hash,
            &persistent_empty_trace_payload(),
        )
        .expect("child empty trace records");
    drop(persist);
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache_mut().expect("cache is enabled");
        let supplier_identity = CacheExprIdentity::new(
            CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
                b"persistent-dirty-supplier",
            )),
            IrId::new(2),
        );
        let supplier = cache
            .get_or_insert_expression_node(
                supplier_identity,
                std::iter::empty::<ValueHash>(),
                Some(crate::cache::ValueHash::from_canonical_value_hash(
                    DurableBlake3Hash::for_bytes(b"persistent-dirty-supplier-value"),
                )),
            )
            .expect("dirty supplier node inserts");
        cache
            .test_mark_dirty_node(supplier)
            .expect("dirty supplier node dirties");
        let child = cache
            .get_or_insert_expression_node(
                child_identity,
                std::iter::empty::<ValueHash>(),
                Some(child_value_hash),
            )
            .expect("child runtime node inserts");
        cache
            .record_memo_read_dependency(child, supplier)
            .expect("dirty supplier edge records");
    }

    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = evaluator.lookup_forced_inline_expression_result(Some(child_subject));

    assert!(
        forced.is_none(),
        "dirty supplier should reject the persistent force-cache hit"
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 1);
    assert_eq!(
        evaluator.stats().early_cutoffs(),
        0,
        "rejected persistent hits should not count an early cutoff"
    );
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(child_persist_key)
            .expect("persistent metadata lookup succeeds"),
        None,
        "rejected persistent force-cache hit should clear the durable value link"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn persistent_force_cache_hit_rejects_dirty_supplier_from_trace_dependency_key() {
    let persist_root = unique_temp_dir("force-cache-persistent-dirty-dependency-key");
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-dirty-key-child",
        )),
        IrId::new(1),
    );
    let supplier_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-dirty-key-supplier",
        )),
        IrId::new(2),
    );
    let child_subject = synthetic_selected_force_cache_subject(child_identity);
    let child_payload =
        CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds");
    let supplier_payload =
        CachedExpressionValue::immediate(Value::int(5)).expect("supplier payload builds");
    let child_value_hash = child_payload.value_hash().expect("child payload hashes");
    let supplier_value_hash = supplier_payload
        .value_hash()
        .expect("supplier payload hashes");
    let child_persist_key =
        PersistNodeMetadataKey::for_expression(child_identity, std::iter::empty::<ValueHash>());
    let supplier_persist_key =
        PersistNodeMetadataKey::for_expression(supplier_identity, std::iter::empty::<ValueHash>());
    let child_trace = persistent_empty_trace_payload()
        .with_memo_read_dependency_records([(supplier_persist_key, supplier_value_hash)])
        .expect("child trace dependency encodes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            supplier_persist_key,
            &supplier_payload,
            crate::cache::MaterializationDecision::Materialize,
        )
        .expect("supplier payload materializes");
    persist
        .record_node_trace(
            supplier_persist_key,
            supplier_value_hash,
            &persistent_empty_trace_payload(),
        )
        .expect("supplier empty trace records");
    persist
        .materialize_cached_expression_node_value_indexed(
            child_persist_key,
            &child_payload,
            crate::cache::MaterializationDecision::Materialize,
        )
        .expect("child payload materializes");
    persist
        .record_node_trace(child_persist_key, child_value_hash, &child_trace)
        .expect("child trace records");
    drop(persist);
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache_mut().expect("cache is enabled");
        let supplier = cache
            .get_or_insert_expression_node(
                supplier_identity,
                std::iter::empty::<ValueHash>(),
                Some(supplier_value_hash),
            )
            .expect("supplier runtime node inserts");
        cache
            .test_mark_dirty_node(supplier)
            .expect("supplier node dirties");
    }

    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator =
        TreeWalk::with_options_and_source_and_eval_cache(&ir, options, "expr.nix", source, cache);
    let forced = evaluator.lookup_forced_inline_expression_result(Some(child_subject));

    assert!(
        forced.is_none(),
        "dirty supplier named only by the persistent trace should reject the hit"
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 1);
    assert_eq!(
        evaluator.stats().early_cutoffs(),
        0,
        "dirty supplier rejection should not count an early cutoff"
    );
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(child_persist_key)
            .expect("persistent metadata lookup succeeds"),
        None,
        "rejected persistent force-cache hit should clear the durable child value link"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn persistent_force_cache_hit_replays_verified_unresolved_supplier_without_runtime_memoization() {
    let persist_root = unique_temp_dir("force-cache-persistent-unresolved-dependency-key");
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-unresolved-key-child",
        )),
        IrId::new(1),
    );
    let supplier_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-unresolved-key-supplier",
        )),
        IrId::new(2),
    );
    let child_subject = synthetic_selected_force_cache_subject(child_identity);
    let child_payload =
        CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds");
    let supplier_payload =
        CachedExpressionValue::immediate(Value::int(5)).expect("supplier payload builds");
    let child_value_hash = child_payload.value_hash().expect("child payload hashes");
    let supplier_value_hash = supplier_payload
        .value_hash()
        .expect("supplier payload hashes");
    let child_persist_key =
        PersistNodeMetadataKey::for_expression(child_identity, std::iter::empty::<ValueHash>());
    let supplier_persist_key =
        PersistNodeMetadataKey::for_expression(supplier_identity, std::iter::empty::<ValueHash>());
    let child_trace = persistent_empty_trace_payload()
        .with_memo_read_dependency_records([(supplier_persist_key, supplier_value_hash)])
        .expect("child trace dependency encodes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            supplier_persist_key,
            &supplier_payload,
            crate::cache::MaterializationDecision::Materialize,
        )
        .expect("supplier payload materializes");
    persist
        .record_node_trace(
            supplier_persist_key,
            supplier_value_hash,
            &persistent_empty_trace_payload(),
        )
        .expect("supplier empty trace records");
    persist
        .materialize_cached_expression_node_value_indexed(
            child_persist_key,
            &child_payload,
            crate::cache::MaterializationDecision::Materialize,
        )
        .expect("child payload materializes");
    persist
        .record_node_trace(child_persist_key, child_value_hash, &child_trace)
        .expect("child trace records");
    drop(persist);

    let mut options = TreeWalkOptions::new();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "expr.nix",
        source,
        cache.clone(),
    );

    let first = evaluator.lookup_forced_inline_expression_result(Some(child_subject.clone()));
    let second = evaluator.lookup_forced_inline_expression_result(Some(child_subject));

    assert_eq!(first.map(|value| value.as_int()), Some(Ok(3)));
    assert_eq!(second.map(|value| value.as_int()), Some(Ok(3)));
    assert_eq!(evaluator.stats().cache_hits(), 2);
    assert_eq!(evaluator.stats().cache_misses(), 0);
    assert_eq!(
        evaluator.stats().early_cutoffs(),
        2,
        "each trace-verified durable replay should report skipped evaluation work"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let child_key = DemandCacheKey::for_free_vars(child_identity, std::iter::empty::<ValueHash>())
        .expect("child runtime key builds");
    assert!(
        cache.graph().node_id_for_key(child_key).is_none(),
        "a durable-only hit must not install an unwired runtime memo node"
    );
    drop(runtime);

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}
