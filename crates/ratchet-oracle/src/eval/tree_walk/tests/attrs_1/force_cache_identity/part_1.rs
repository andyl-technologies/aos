//! Split-out tests (part_1). See parent module.

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

#[test]
fn dirty_same_runtime_pure_force_cache_hit_counts_early_cutoff() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut prime = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        shared_runtime.clone(),
    );
    let (primed, subject) = force_attr_a_with_force_cache_subject(&mut prime, &ir, a);
    assert_eq!(primed.as_int(), Ok(3));
    let identity = subject
        .lookup_identity
        .expect("source-backed pure attr has a lookup identity");
    let owner_key =
        DemandCacheKey::for_free_vars(identity, subject.free_var_value_hashes.iter().copied())
            .expect("owner key builds");
    let owner = {
        let runtime = shared_runtime.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        cache
            .graph()
            .node_id_for_key(owner_key)
            .expect("forced expression node exists")
    };
    {
        let mut runtime = shared_runtime.lock().expect("cache lock is valid");
        assert_eq!(
            runtime
                .test_mark_dirty_node(owner)
                .expect("node marks dirty"),
            Some(())
        );
        let cache = runtime.cache().expect("cache is enabled");
        assert_eq!(
            cache
                .graph()
                .node(owner)
                .expect("owner node exists")
                .freshness(),
            crate::cache::NodeFreshness::Dirty
        );
    }
    drop(prime);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        shared_runtime.clone(),
    );
    let (forced_again, _) = force_attr_a_with_force_cache_subject(&mut second, &ir, a);

    assert_eq!(forced_again.as_int(), Ok(3));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "dirty same-hash in-memory hit should replay without forcing the thunk body"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(
        second.stats().early_cutoffs(),
        1,
        "dirty same-hash in-memory hit should count local early cutoff"
    );
    let runtime = shared_runtime.lock().expect("cache lock is valid");
    assert_eq!(
        runtime
            .cache()
            .expect("cache is enabled")
            .graph()
            .node(owner)
            .expect("owner node exists")
            .freshness(),
        crate::cache::NodeFreshness::Clean
    );
}

#[test]
fn dirty_persistent_pure_force_cache_hit_counts_early_cutoff() {
    let persist_root = unique_temp_dir("force-cache-persistent-pure-dirty-cutoff");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "expr.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    drop(first);

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let prime_options = TreeWalkOptions::with_eval_cache_enabled(true);
    let mut prime = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        prime_options,
        "expr.nix",
        source,
        shared_runtime.clone(),
    );
    let (primed, subject) = force_attr_a_with_force_cache_subject(&mut prime, &ir, a);
    assert_eq!(primed.as_int(), Ok(3));
    let identity = subject
        .lookup_identity
        .expect("source-backed pure attr has a lookup identity");
    let owner_key =
        DemandCacheKey::for_free_vars(identity, subject.free_var_value_hashes.iter().copied())
            .expect("owner key builds");
    {
        let mut runtime = shared_runtime.lock().expect("cache lock is valid");
        assert_eq!(
            runtime
                .invalidate_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied()
                )
                .expect("payload invalidates"),
            Some(true)
        );
        assert!(
            runtime
                .lookup_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied()
                )
                .expect("payload lookup succeeds")
                .is_none(),
            "invalidated pure payload should no longer hit in memory"
        );
        let cache = runtime.cache().expect("cache is enabled");
        let owner = cache
            .graph()
            .node_id_for_key(owner_key)
            .expect("forced expression node remains");
        assert!(
            cache
                .graph()
                .node(owner)
                .expect("owner node exists")
                .value_hash()
                .is_some(),
            "invalidation should retain the prior same-value hash for reconsideration"
        );
        assert_eq!(
            cache
                .graph()
                .node(owner)
                .expect("owner node exists")
                .freshness(),
            crate::cache::NodeFreshness::Dirty
        );
    }
    drop(prime);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "expr.nix",
        source,
        shared_runtime,
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_int(), Ok(3));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "persistent hit should replay without forcing the thunk body"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(
        second.stats().early_cutoffs(),
        1,
        "empty-trace persistent hit runtime seeding should count same-hash dirty cutoff"
    );
    assert!(
        second.impure_input_trace().is_empty(),
        "pure persistent hit should use the empty verifying trace path"
    );

    fs::remove_dir_all(&persist_root).expect("persistent temp tree removed");
}

#[test]
fn observation_only_subject_allocates_active_node_without_lookup_replay() {
    let source = "1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let observation_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"observation-only-active-node",
        )),
        IrId::new(7),
    );
    let free_var_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"free-var"));
    let subject = ForceCacheSubject {
        lookup_identity: None,
        pure_observation_identity: None,
        impure_observation_identity: Some(observation_identity),
        metadata_identity: None,
        persistent_clear_identity: Some(observation_identity),
        free_var_value_hashes: vec![free_var_hash],
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    };
    let observed_node = {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                observation_identity,
                [free_var_hash],
                CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds"),
            )
            .expect("observation payload observes")
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

    let active_node = evaluator
        .active_force_cache_node_for_subject(Some(&subject))
        .expect("observation-only active node allocates");
    let replayed = evaluator.lookup_forced_inline_expression_result(Some(subject.clone()));

    assert_eq!(active_node, observed_node);
    assert!(
        replayed.is_none(),
        "observation-only subjects must not replay"
    );
    assert_eq!(evaluator.stats().force_cache_hits(), 0);
    let runtime = cache.lock().expect("cache lock is valid");
    let runtime_cache = runtime.cache().expect("cache is enabled");
    let key = crate::cache::DemandCacheKey::for_free_vars(observation_identity, [free_var_hash])
        .expect("observation key builds");
    assert_eq!(
        runtime_cache.graph().node_id_for_key(key),
        Some(active_node)
    );
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
        evaluator.active_memo_read_nodes.is_empty(),
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
fn source_backed_admitted_force_error_preserves_prior_memo_read_edges() {
    let source = "{ a = 1 / 0; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let stale_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"error-stale-memo-read-child",
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
    let parent_node = evaluator
        .active_force_cache_node_for_subject(Some(&subject))
        .expect("parent active node allocates");
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .cache_mut()
            .expect("cache is enabled")
            .record_memo_read_dependency(parent_node, stale_node)
            .expect("stale memo-read edge records");
    }

    let error = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("admitted thunk body fails");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    assert!(
        evaluator.active_memo_read_nodes.is_empty(),
        "erroring body evaluation must pop the active force-cache node"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    assert!(
        parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .expect("parent has prior memo-read edges")
            .contains(&stale_node),
        "body errors must not clear a prior successful memo-read group"
    );
    assert!(
        cache
            .graph()
            .node(stale_node)
            .expect("stale child node is present")
            .dependents()
            .contains(&parent_node)
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
