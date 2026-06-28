//! Force-cache tests for ambient currentSystem, store, and time inputs.

use super::*;

#[test]
fn ambient_current_system_forced_inline_thunks_hit_with_matching_option_salt() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second =
        TreeWalk::with_options_and_source_and_eval_cache(&ir, options, "expr.nix", source, cache);
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "matching currentSystem option salt should permit a string payload hit"
    );
    assert_eq!(second.stats().cache_hits(), 1);
}

#[test]
fn ambient_current_system_forced_inline_thunks_include_current_system_in_cache_identity() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (system, expected) in [
        (b"x86_64-linux".as_slice(), b"x86_64-linux".as_slice()),
        (b"aarch64-linux".as_slice(), b"aarch64-linux".as_slice()),
    ] {
        let options =
            TreeWalkOptions::with_current_system(system.to_vec()).expect("currentSystem is valid");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "expr.nix",
            source,
            cache.clone(),
        );
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(
            evaluator
                .heap()
                .get_string(forced)
                .expect("currentSystem result is a string")
                .bytes(),
            expected
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different currentSystem values must not share one payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different currentSystem values should allocate separate expression nodes"
    );
}

#[test]
fn ambient_store_dir_forced_inline_thunks_hit_and_miss_by_store_dir_salt() {
    let root = unique_temp_dir("force-cache-ambient-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = builtins.storeDir; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_store_dir(path_bytes(&first_store))
        .expect("store dir is absolute");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("storeDir result is a string")
            .bytes(),
        path_bytes(&first_store).as_slice()
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached storeDir result rehydrates")
            .bytes(),
        path_bytes(&first_store).as_slice()
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "matching storeDir option salt should permit a string payload hit"
    );
    assert_eq!(second.stats().cache_hits(), 1);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_store_dir(path_bytes(&second_store))
        .expect("store dir is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(forced)
            .expect("changed storeDir result is a string")
            .bytes(),
        path_bytes(&second_store).as_slice()
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "different storeDir values must not share one payload"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different storeDir values should allocate separate expression nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_current_system_thunks_hit_with_matching_option_salt() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_eval_cache(&ir, options.clone(), cache.clone());
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached source-less currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "matching source-less currentSystem option salt should permit a string payload hit"
    );
    assert_eq!(second.stats().cache_hits(), 1);
}

#[test]
fn source_less_current_system_thunks_include_current_system_in_cache_identity() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (system, expected) in [
        (b"x86_64-linux".as_slice(), b"x86_64-linux".as_slice()),
        (b"aarch64-linux".as_slice(), b"aarch64-linux".as_slice()),
    ] {
        let options =
            TreeWalkOptions::with_current_system(system.to_vec()).expect("currentSystem is valid");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(
            evaluator
                .heap()
                .get_string(forced)
                .expect("currentSystem result is a string")
                .bytes(),
            expected
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less currentSystem values must not share one payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different source-less currentSystem values should allocate separate expression nodes"
    );
}

#[test]
fn ambient_current_time_forced_inline_thunks_record_uncacheable_trace_without_payload() {
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
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
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert!(!cache.is_empty(), "currentTime records an observation node");
    assert_eq!(
        cache.inline_payload_record_count(),
        0,
        "currentTime remains uncacheable even when the force body is observed"
    );
}

#[test]
fn source_less_current_time_thunks_record_uncacheable_trace_without_payload() {
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let forced = force_attr_a(&mut evaluator, &ir, a);

    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert!(!cache.is_empty(), "currentTime records an observation node");
    assert_eq!(
        cache.inline_payload_record_count(),
        0,
        "source-less currentTime remains uncacheable even when the force body is observed"
    );
}

#[test]
fn source_backed_current_time_tombstones_stale_persistent_payload() {
    let persist_root = unique_temp_dir("force-cache-persistent-stale-current-time-node");
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let mut options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_source(&ir, options, "expr.nix", source);
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
            .expect("a remains a suspended node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("currentTime node thunk has force-cache observation subject")
    };
    assert!(
        subject.lookup_identity.is_none() && subject.metadata_identity.is_none(),
        "currentTime node thunks must stay ineligible for hit selection and demand accounting"
    );
    let identity = subject
        .persistent_clear_identity
        .expect("currentTime node thunk has persistent clear identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload =
        persistent_path_exists_trace_payload(b"/tmp/aos-stale-current-time-node", true);
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
        .expect("currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "source-backed currentTime must not replay stale persistent payloads"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(2, 3)),
        "uncacheable currentTime should clear stale values without recording demand"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "uncacheable currentTime clears the stale persistent value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .expect("persistent trace tombstone records")
            .payload()
            .is_tombstone(),
        "uncacheable currentTime tombstones stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn reified_builtins_current_time_entry_is_lazy() {
    let ir = lower("builtins");
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("builtins evaluates");

    assert!(
        evaluator.impure_input_trace().is_empty(),
        "constructing the builtins attrset must not read currentTime"
    );
    let current_time = evaluator
        .symbols
        .intern(b"currentTime")
        .expect("currentTime symbol interns");
    let attrs = evaluator
        .heap()
        .get_attrs(root)
        .expect("builtins evaluates to attrs");
    let value = attrs
        .get(current_time)
        .expect("currentTime is present when configured");
    let thunk = evaluator
        .heap()
        .get_thunk(value)
        .expect("currentTime remains a delayed builtin attr thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn synthetic_builtin_attr_current_system_thunks_hit_with_matching_option_salt() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached synthetic currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().cache_hits(),
        1,
        "the reified builtins constant should hit at the synthetic builtin thunk"
    );
    assert_eq!(
        second.stats().thunks_forced(),
        2,
        "the outer attr thunk and reified builtins attrset still evaluate"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching synthetic builtin constants should share one demand node"
    );
}
