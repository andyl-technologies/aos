//! Force-cache identity tests for source-backed and source-less attr thunks.

use super::*;

#[test]
fn source_backed_forced_inline_thunks_update_shared_eval_cache() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for _ in 0..2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "expr.nix",
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
        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert_eq!(
        cache.len(),
        1,
        "the same source hash and IR node should reuse one demand node"
    );
    let node = cache
        .graph()
        .node(crate::cache::DemandNodeId::new(0))
        .expect("forced expression node exists");
    assert_eq!(node.freshness(), crate::cache::NodeFreshness::Clean);
    assert!(node.value_hash().is_some());
}

#[test]
fn source_backed_forced_inline_thunks_record_memoization_policy_demand() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_demands in 1..=2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "expr.nix",
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
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a remains a suspended thunk");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("force-cache subject builds")
        };
        let identity = subject
            .lookup_identity
            .expect("node thunk has a lookup identity");
        {
            let runtime = cache.lock().expect("cache lock is valid");
            if expected_demands == 1 {
                assert!(
                    runtime.cache().expect("cache is enabled").is_empty(),
                    "building a force-cache subject must not allocate graph nodes"
                );
                assert_eq!(
                    runtime
                        .memoization_demand(
                            identity,
                            subject.free_var_value_hashes.iter().copied(),
                        )
                        .expect("demand reads"),
                    None,
                    "building a force-cache subject must not record demand"
                );
            }
        }

        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(evaluator.stats().force_cache_memoization_demands(), 1);
        assert_eq!(
            evaluator.stats().force_cache_memoization_bypasses(),
            u64::from(expected_demands == 1),
            "first observed thunk demand should bypass the conditional policy"
        );
        assert_eq!(
            evaluator.stats().force_cache_memoization_admits(),
            u64::from(expected_demands == 2),
            "second observed thunk demand should admit through the conditional policy"
        );
        assert_eq!(
            evaluator.stats().force_cache_misses(),
            u64::from(expected_demands == 2),
            "only an admitted conditional thunk should probe and miss"
        );
        assert_eq!(
            evaluator.stats().force_cache_probes(),
            u64::from(expected_demands == 2),
            "bypassed conditional thunks should not probe the force cache"
        );

        let runtime = cache.lock().expect("cache lock is valid");
        let demand = runtime
            .memoization_demand(identity, subject.free_var_value_hashes.iter().copied())
            .expect("demand reads")
            .expect("force records memoization demand");
        assert_eq!(demand.current_run_demands(), expected_demands);
        assert_eq!(
            runtime.cache().expect("cache is enabled").len(),
            usize::from(expected_demands == 2),
            "only admitted policy demand should allocate an expression node"
        );
    }
}

#[test]
fn source_backed_force_cache_creates_expression_node_only_on_force() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
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
    assert_eq!(
        evaluator.stats().thunks_allocated(),
        1,
        "evaluating the attrset allocates the lazy attr thunk"
    );
    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime.cache().expect("cache is enabled").is_empty(),
            "allocating the thunk must not allocate an expression cache node"
        );
    }

    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(evaluator.stats().force_cache_memoization_bypasses(), 1);
    assert_eq!(evaluator.stats().cache_misses(), 0);
    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert_eq!(
            runtime.cache().expect("cache is enabled").len(),
            0,
            "the first conditional thunk demand bypasses expression node allocation"
        );
    }

    let mut admitted = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = admitted.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = admitted
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = admitted
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("admitted thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(admitted.stats().force_cache_memoization_admits(), 1);
    assert_eq!(admitted.stats().cache_misses(), 1);
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "an admitted force creates the expression cache node on demand"
    );
}

#[test]
fn source_backed_forced_inline_thunks_hit_shared_eval_cache_without_body_eval() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = first
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("first force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().thunks_forced(), 1);
    assert_eq!(first.stats().force_cache_memoization_bypasses(), 1);
    assert_eq!(first.stats().force_cache_hits(), 0);
    assert_eq!(first.stats().force_cache_misses(), 0);
    assert_eq!(first.stats().force_cache_probes(), 0);
    assert_eq!(first.stats().cache_misses(), 0);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = second.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("second force succeeds and populates cache");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(second.stats().thunks_forced(), 1);
    assert_eq!(second.stats().force_cache_memoization_admits(), 1);
    assert_eq!(second.stats().cache_hits(), 0);
    assert_eq!(second.stats().force_cache_hits(), 0);
    assert_eq!(second.stats().force_cache_misses(), 1);
    assert_eq!(second.stats().force_cache_probes(), 1);

    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = third.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = third.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = third
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("third force succeeds from cache");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        third.stats().thunks_forced(),
        0,
        "cache hits publish the scalar without evaluating the thunk body"
    );
    assert_eq!(third.stats().cache_hits(), 1);
    assert_eq!(third.stats().force_cache_hits(), 1);
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.stats().force_cache_probes(), 1);

    let thunk = third
        .heap()
        .get_thunk(thunk_value)
        .expect("thunk remains heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
    let forced_again = third
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("published cache hit reuses thunk cell");
    assert_eq!(forced_again.as_int(), Ok(3));
    assert_eq!(third.stats().thunk_cache_hits(), 1);
}

fn synthetic_selected_force_cache_subject(identity: CacheExprIdentity) -> ForceCacheSubject {
    ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    }
}

#[test]
fn source_backed_active_force_cache_hits_record_memo_read_edges() {
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"memo-read-child"),
        IrId::new(1),
    );
    let parent_identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"memo-read-parent"),
        IrId::new(2),
    );
    let child_subject = synthetic_selected_force_cache_subject(child_identity);
    let parent_subject = synthetic_selected_force_cache_subject(parent_identity);
    let child_node = {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                child_identity,
                std::iter::empty::<DurableBlake3Hash>(),
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
    evaluator.active_force_cache_nodes.push(parent_node);
    let forced = evaluator
        .lookup_forced_inline_expression_result(Some(child_subject))
        .expect("child force-cache payload hits");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        evaluator.active_force_cache_nodes.pop(),
        Some(parent_node),
        "test-controlled active node stack should be balanced"
    );
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
fn source_backed_active_persistent_force_cache_hits_record_memo_read_edges() {
    let persist_root = unique_temp_dir("force-cache-persistent-memo-read");
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let child_identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"persistent-memo-read-child"),
        IrId::new(1),
    );
    let parent_identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"persistent-memo-read-parent"),
        IrId::new(2),
    );
    let child_subject = synthetic_selected_force_cache_subject(child_identity);
    let parent_subject = synthetic_selected_force_cache_subject(parent_identity);
    let child_payload =
        CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds");
    let child_value_hash = child_payload.value_hash().expect("child payload hashes");
    let child_persist_key = PersistNodeMetadataKey::for_expression(
        child_identity,
        std::iter::empty::<DurableBlake3Hash>(),
    );
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
    evaluator.active_force_cache_nodes.push(parent_node);
    let forced = evaluator
        .lookup_forced_inline_expression_result(Some(child_subject))
        .expect("child persistent force-cache payload hits");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        evaluator.active_force_cache_nodes.pop(),
        Some(parent_node),
        "test-controlled active node stack should be balanced"
    );
    assert_eq!(evaluator.stats().cache_hits(), 1);
    assert_eq!(evaluator.stats().cache_misses(), 0);

    let child_key = crate::cache::DemandCacheKey::for_free_vars(
        child_identity,
        std::iter::empty::<DurableBlake3Hash>(),
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
fn source_backed_admitted_force_error_balances_active_force_cache_stack() {
    let source = "{ a = 1 / 0; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
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

    let error = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("admitted thunk body fails");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    assert!(
        evaluator.active_force_cache_nodes.is_empty(),
        "erroring body evaluation must pop the active force-cache node"
    );
    assert!(
        evaluator.stats().force_cache_memoization_admits() > 0,
        "helper-forced policy admission should reach the real force-cache path"
    );
    assert_eq!(evaluator.stats().force_cache_misses(), 1);
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "the admitted force must allocate its active expression node before the body error"
    );
}

#[test]
fn source_and_source_less_forced_inline_thunks_use_separate_cache_domains() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut source_backed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut source_backed, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(source_backed.stats().cache_misses(), 1);

    let mut source_less =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let forced = force_attr_a(&mut source_less, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        source_less.stats().cache_hits(),
        0,
        "source-less lowered-IR identity must not hit a source-backed node"
    );
    assert_eq!(source_less.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "source-backed and source-less domains should allocate separate demand nodes"
    );
}

#[test]
fn source_less_forced_inline_thunks_hit_shared_eval_cache_without_body_eval() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("first force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().thunks_forced(), 1);
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let root = second.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("second force succeeds from lowered-IR cache identity");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "source-less cache hits publish the scalar without evaluating the thunk body"
    );
    assert_eq!(second.stats().cache_hits(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "the same lowered IR fingerprint and node should reuse one demand node"
    );
}

#[test]
fn source_less_forced_inline_thunks_include_lowered_ir_in_cache_identity() {
    let first_ir = lower("{ a = 1 + 2; }");
    let second_ir = lower("{ a = 1 + 3; }");
    let first_a = symbol_for(&first_ir, b"a");
    let second_a = symbol_for(&second_ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&first_ir, TreeWalkOptions::new(), cache.clone());
    let root = first.eval_root().expect("first attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(first_a).expect("a exists")
    };
    let forced = first
        .force_admitted_value(first_ir.root, Span::new(0, 0), thunk_value)
        .expect("first force succeeds");
    assert_eq!(forced.as_int(), Ok(3));

    let mut second =
        TreeWalk::with_options_and_eval_cache(&second_ir, TreeWalkOptions::new(), cache.clone());
    let root = second.eval_root().expect("second attrset evaluates");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(second_a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(second_ir.root, Span::new(0, 0), thunk_value)
        .expect("second force succeeds");
    assert_eq!(forced.as_int(), Ok(4));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "different lowered IR artifacts must not reuse one cache entry"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different lowered IR fingerprints should allocate separate demand nodes"
    );
}

#[test]
fn source_less_forced_inline_thunks_include_path_base_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-path-base");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).expect("first dir exists");
    fs::create_dir_all(&second_dir).expect("second dir exists");
    let first_dir = fs::canonicalize(&first_dir).expect("first dir canonicalizes");
    let second_dir = fs::canonicalize(&second_dir).expect("second dir canonicalizes");
    let source = "{ a = ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for path_base in [&first_dir, &second_dir] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(path_base))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(
            path_value_bytes(&evaluator, forced),
            path_bytes(&path_base.join("target"))
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different path bases must not reuse a path payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different path bases must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_store_dir_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for store_dir in [&first_store, &second_store] {
        let mut options = TreeWalkOptions::new();
        options
            .set_store_dir(path_bytes(store_dir))
            .expect("store dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less store dirs must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different store dirs must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_home_dir_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-home-dir");
    let first_home = root.join("home-a");
    let second_home = root.join("home-b");
    fs::create_dir_all(&first_home).expect("first home exists");
    fs::create_dir_all(&second_home).expect("second home exists");
    fs::write(first_home.join("marker"), b"present").expect("first marker exists");
    let first_home = fs::canonicalize(&first_home).expect("first home canonicalizes");
    let second_home = fs::canonicalize(&second_home).expect("second home canonicalizes");
    let source = "{ a = builtins.pathExists ~/marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (home_dir, expected) in [(&first_home, true), (&second_home, false)] {
        let mut options = TreeWalkOptions::new();
        options
            .set_home_dir(path_bytes(home_dir))
            .expect("home dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_bool(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less home dirs must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        4,
        "different source-less home dirs should produce separate expression and input nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_eval_mode_in_cache_identity() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for mode in [EvalMode::Impure, EvalMode::Pure] {
        let options = TreeWalkOptions::with_eval_mode(mode);
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less eval modes must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different eval modes must not reuse one demand node"
    );
}

fn force_cache_identity_for_attr_a(ir: &Ir, source: &str) -> (CacheExprIdentity, IrId) {
    let a = symbol_for(ir, b"a");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        TreeWalkOptions::new(),
        "default.nix",
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
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    let body = thunk.body().expect("a is a node thunk");
    let identity = evaluator
        .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
        .expect("force-cache subject builds")
        .metadata_identity
        .expect("node thunk has metadata identity");
    (identity, body)
}

fn force_cache_identity_for_source_less_attr_a(ir: &Ir) -> (CacheExprIdentity, IrId) {
    let a = symbol_for(ir, b"a");
    let mut evaluator = TreeWalk::with_options_and_eval_cache(
        ir,
        TreeWalkOptions::new(),
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
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    let body = thunk.body().expect("a is a node thunk");
    let identity = evaluator
        .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
        .expect("force-cache subject builds")
        .metadata_identity
        .expect("node thunk has metadata identity");
    (identity, body)
}

#[test]
fn source_backed_force_cache_identities_include_node_span() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let (first_identity, body) = force_cache_identity_for_attr_a(&ir, source);

    let mut shifted = ir.clone();
    let mut nodes = shifted.arena.nodes().to_vec();
    nodes[body.index()].span = Span::new(100, 104);
    shifted.arena = IrArena::from_raw_parts(nodes, shifted.arena.child_pool().to_vec());
    let (shifted_identity, shifted_body) = force_cache_identity_for_attr_a(&shifted, source);

    assert_eq!(shifted_body, body);
    assert_ne!(
        shifted_identity, first_identity,
        "same source bytes and IR node id under a different node span must not reuse one demand node"
    );

    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &shifted,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &shifted, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "same source bytes and IR node id under a different node span must miss"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes and IR node id under different spans must allocate separate demand nodes"
    );
}

#[test]
fn source_less_force_cache_identities_include_node_span() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let (first_identity, body) = force_cache_identity_for_source_less_attr_a(&ir);
    let body_span = ir.arena.node(body).expect("body node exists").span;
    let fixed_module_hash = DurableBlake3Hash::for_bytes(b"source-less-node-span-canary");

    let mut shifted = ir.clone();
    let mut nodes = shifted.arena.nodes().to_vec();
    nodes[body.index()].span = Span::new(100, 104);
    shifted.arena = IrArena::from_raw_parts(nodes, shifted.arena.child_pool().to_vec());
    let (shifted_identity, shifted_body) = force_cache_identity_for_source_less_attr_a(&shifted);

    let fixed_module_first = TreeWalk::test_cache_expression_identity_for_module_hash_and_span(
        fixed_module_hash,
        body,
        body_span,
    );
    let fixed_module_shifted = TreeWalk::test_cache_expression_identity_for_module_hash_and_span(
        fixed_module_hash,
        body,
        Span::new(100, 104),
    );

    assert_eq!(shifted_body, body);
    assert_ne!(
        fixed_module_shifted, fixed_module_first,
        "same source-less module identity and IR node id under a different node span must not reuse one demand node"
    );
    assert_ne!(
        shifted_identity, first_identity,
        "same lowered IR node id under a different node span must not reuse one demand node"
    );

    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second =
        TreeWalk::with_options_and_eval_cache(&shifted, TreeWalkOptions::new(), cache.clone());
    let forced = force_attr_a(&mut second, &shifted, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "same lowered IR node id under a different node span must miss"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR node id under different spans must allocate separate demand nodes"
    );
}

#[test]
fn source_backed_forced_inline_thunks_include_path_base_in_cache_identity() {
    let root = unique_temp_dir("force-cache-path-base");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).expect("first dir exists");
    fs::create_dir_all(&second_dir).expect("second dir exists");
    let first_dir = fs::canonicalize(&first_dir).expect("first dir canonicalizes");
    let second_dir = fs::canonicalize(&second_dir).expect("second dir canonicalizes");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for path_base in [&first_dir, &second_dir] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(path_base))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
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
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different path bases must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_store_dir_in_cache_identity() {
    let root = unique_temp_dir("force-cache-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for store_dir in [&first_store, &second_store] {
        let mut options = TreeWalkOptions::new();
        options
            .set_store_dir(path_bytes(store_dir))
            .expect("store dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
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
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different store dirs must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_home_dir_in_cache_identity() {
    let root = unique_temp_dir("force-cache-home-dir");
    let first_home = root.join("home-a");
    let second_home = root.join("home-b");
    fs::create_dir_all(&first_home).expect("first home exists");
    fs::create_dir_all(&second_home).expect("second home exists");
    fs::write(first_home.join("marker"), b"present").expect("first marker exists");
    let first_home = fs::canonicalize(&first_home).expect("first home canonicalizes");
    let second_home = fs::canonicalize(&second_home).expect("second home canonicalizes");
    let source = "{ a = builtins.pathExists ~/marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (home_dir, expected) in [(&first_home, true), (&second_home, false)] {
        let mut options = TreeWalkOptions::new();
        options
            .set_home_dir(path_bytes(home_dir))
            .expect("home dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
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
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_bool(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different home dirs must not reuse a prior resolved pathExists input"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        4,
        "same source bytes under different home dirs must not reuse demand nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_eval_mode_in_cache_identity() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for mode in [EvalMode::Impure, EvalMode::Pure] {
        let options = TreeWalkOptions::with_eval_mode(mode);
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
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
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different eval modes must not reuse one demand node"
    );
}
