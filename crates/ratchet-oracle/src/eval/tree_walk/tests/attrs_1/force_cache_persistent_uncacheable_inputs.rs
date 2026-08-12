//! Persistent force-cache tests for uncacheable impure inputs.

use super::*;

fn persistent_runtime() -> Arc<Mutex<EvalCacheRuntime>> {
    Arc::new(Mutex::new(EvalCacheRuntime::enabled()))
}

fn current_time_options(time: i64, persist_root: &std::path::Path) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::with_current_time(time).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(persist_root);
    options
}

fn force_current_time(ir: &Ir, source: &str, a: Symbol, options: TreeWalkOptions) -> TreeWalk {
    let expected_time = options.current_time().expect("currentTime configured");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        options,
        "current-time.nix",
        source,
        persistent_runtime(),
    );
    let forced = force_attr_a(&mut evaluator, ir, a);
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 0);
    assert_eq!(evaluator.stats().force_cache_hits(), 0);
    assert_eq!(evaluator.stats().force_cache_misses(), 0);
    assert_eq!(
        evaluator.stats().thunks_forced(),
        1,
        "currentTime must force normally instead of replaying persistent values"
    );
    assert_eq!(forced.as_int(), Ok(expected_time));
    evaluator
}

#[test]
fn current_time_forced_expression_never_replays_persistent_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-current-time-no-replay");
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let first = force_current_time(
        &ir,
        source,
        a,
        current_time_options(1_700_000_000, &persist_root),
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "first currentTime forced-expression run",
    );
    drop(first);

    let same_time = force_current_time(
        &ir,
        source,
        a,
        current_time_options(1_700_000_000, &persist_root),
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "same-time currentTime forced-expression run",
    );
    drop(same_time);

    let changed_time = force_current_time(
        &ir,
        source,
        a,
        current_time_options(1_700_000_123, &persist_root),
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "changed-time currentTime forced-expression run",
    );
    drop(changed_time);

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn current_time_dependent_forced_expression_tombstones_stale_persistent_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-current-time-dependent-tombstone");
    let source = "{ a = builtins.currentTime + 1; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        current_time_options(1_700_000_000, &persist_root),
        "current-time-dependent.nix",
        source,
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("dependent currentTime node thunk has an observation subject")
    };
    assert!(
        subject.lookup_identity.is_none() && subject.metadata_identity.is_none(),
        "currentTime dependents must stay ineligible for hit selection and demand accounting"
    );
    let identity = subject
        .persistent_clear_identity
        .expect("dependent currentTime node thunk has a persistent clear identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload =
        persistent_path_exists_trace_payload(b"/tmp/aos-stale-current-time-dependent", true);
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("seed persistent demand records");
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

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("dependent currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_001));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "currentTime dependents must not replay stale persistent payloads"
    );
    assert_eq!(evaluator.stats().cache_misses(), 0);
    assert_eq!(
        evaluator.stats().thunks_forced(),
        1,
        "currentTime dependents must force normally"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(2, 3)),
        "uncacheable currentTime dependents should clear stale values without recording demand"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "uncacheable currentTime dependents clear the stale persistent value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .expect("persistent trace tombstone records")
            .payload()
            .is_tombstone(),
        "uncacheable currentTime dependents tombstone stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn current_time_unsupported_forced_expression_tombstones_stale_persistent_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-current-time-unsupported-tombstone");
    let nested_list = format!("{}0{}", "[".repeat(70), "]".repeat(70));
    let source = format!("{{ a = if builtins.currentTime > 0 then {nested_list} else 0; }}");
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");
    let runtime = persistent_runtime();
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        current_time_options(1_700_000_000, &persist_root),
        "current-time-unsupported.nix",
        source.as_bytes().to_vec(),
        Arc::clone(&runtime),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("unsupported currentTime node thunk has an observation subject")
    };
    assert!(
        subject.lookup_identity.is_none() && subject.metadata_identity.is_none(),
        "currentTime-tainted unsupported payloads must stay ineligible for hit selection"
    );
    let identity = subject
        .persistent_clear_identity
        .expect("unsupported currentTime node thunk has a persistent clear identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload =
        persistent_path_exists_trace_payload(b"/tmp/aos-stale-current-time-unsupported", true);

    {
        let mut cache = runtime.lock().expect("cache lock is valid");
        cache
            .observe_inline_expression_payload(
                identity,
                subject.free_var_value_hashes.iter().copied(),
                stale_payload.clone(),
            )
            .expect("stale runtime payload is seeded");
        assert!(
            cache
                .lookup_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                )
                .expect("runtime lookup succeeds")
                .is_some(),
            "stale runtime payload is present before forcing"
        );
    }

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("seed persistent demand records");
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

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("unsupported currentTime force succeeds");
    assert!(
        evaluator.heap().get_list(forced).is_ok(),
        "the currentTime branch returns the unsupported nested list"
    );
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "unsupported currentTime payloads must not replay stale runtime payloads"
    );
    assert_eq!(evaluator.stats().cache_misses(), 0);
    drop(evaluator);

    {
        let mut cache = runtime.lock().expect("cache lock is valid");
        assert!(
            cache
                .lookup_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                )
                .expect("runtime lookup succeeds")
                .is_none(),
            "unsupported currentTime recomputation invalidates stale runtime payloads"
        );
    }

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(2, 3)),
        "unsupported currentTime should clear stale values without recording demand"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "unsupported currentTime clears the stale persistent value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .expect("persistent trace tombstone records")
            .payload()
            .is_tombstone(),
        "unsupported currentTime tombstones stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
