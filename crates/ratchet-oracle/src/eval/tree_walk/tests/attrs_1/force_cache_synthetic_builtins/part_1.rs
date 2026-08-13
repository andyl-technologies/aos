//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn disabled_eval_cache_skips_persistent_current_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-demand-disabled");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
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
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::from_previous_run(1)),
        "disabled eval-cache observation must not add current-run persistent demand counters"
    );
    assert_eq!(
        fs::metadata(persist.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64,
        "disabled eval-cache observation must not append extra persistent force metadata records"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "disabled eval-cache observation must not write persistent force value payloads"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        None,
        "disabled eval-cache observation must not write persistent force traces"
    );
    assert_eq!(
        fs::metadata(persist.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        0,
        "disabled eval-cache observation must not append any persistent force trace records"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn observation_only_current_time_skips_persistent_current_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-demand-current-time");
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_time = symbol_for(&ir, b"currentTime");
    let builtin = lookup_builtin(b"currentTime").expect("currentTime builtin is registered");
    let mut options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut evaluator =
        TreeWalk::with_options_and_source(&ir, options, "synthetic-current-time.nix", source);
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
            current_time,
            builtin,
        )
        .expect("synthetic currentTime observation identity builds");
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        None,
        "observation-only currentTime subjects must not write persistent demand counters"
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "observation-only synthetic currentTime canary",
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn observation_only_current_time_tombstones_stale_persistent_payload() {
    let persist_root = unique_temp_dir("force-cache-persistent-stale-current-time");
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_time = symbol_for(&ir, b"currentTime");
    let builtin = lookup_builtin(b"currentTime").expect("currentTime builtin is registered");
    let mut options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut evaluator =
        TreeWalk::with_options_and_source(&ir, options, "synthetic-current-time.nix", source);
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
            current_time,
            builtin,
        )
        .expect("synthetic currentTime observation identity builds");
    let key = PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<ValueHash>());
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload =
        persistent_path_exists_trace_payload(b"/tmp/aos-stale-current-time", true);

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
        "observation-only currentTime must not replay stale persistent payloads"
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
fn synthetic_builtin_attr_current_system_thunks_include_current_system_in_cache_identity() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
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
            "synthetic-builtins.nix",
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
            "different currentSystem values must not share one synthetic payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different currentSystem salts should allocate separate synthetic nodes"
    );
}

#[test]
fn synthetic_builtin_attr_force_identities_include_force_site_span() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let (first_identity, site) = synthetic_current_system_identity_for_attr_a(&ir, source);

    let mut shifted = ir.clone();
    let mut nodes = shifted.arena.nodes().to_vec();
    nodes[site.index()].span = Span::new(200, 214);
    shifted.arena = IrArena::from_raw_parts(nodes, shifted.arena.child_pool().to_vec());
    let (shifted_identity, shifted_site) =
        synthetic_current_system_identity_for_attr_a(&shifted, source);

    assert_eq!(shifted_site, site);
    assert_ne!(
        shifted_identity, first_identity,
        "same synthetic builtin force-site id under a different span must not reuse one node"
    );

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
        &shifted,
        options,
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &shifted, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("shifted currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "same synthetic builtin force-site id under a different span must miss"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same synthetic builtin force-site id under different spans must allocate separate nodes"
    );

    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut source_less_first =
        TreeWalk::with_options_and_eval_cache(&ir, options.clone(), cache.clone());
    let forced = force_attr_a(&mut source_less_first, &ir, a);
    assert_eq!(
        source_less_first
            .heap()
            .get_string(forced)
            .expect("source-less currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(source_less_first.stats().cache_misses(), 1);

    let mut source_less_second =
        TreeWalk::with_options_and_eval_cache(&shifted, options, cache.clone());
    let forced = force_attr_a(&mut source_less_second, &shifted, a);
    assert_eq!(
        source_less_second
            .heap()
            .get_string(forced)
            .expect("source-less shifted currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        source_less_second.stats().cache_hits(),
        0,
        "source-less synthetic builtin force-site span changes must miss"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "source-less synthetic builtin force-site span changes must allocate separate nodes"
    );
}

#[test]
fn source_less_synthetic_builtin_attr_current_system_thunks_hit_with_matching_option_salt() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
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

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached source-less synthetic currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().cache_hits(),
        1,
        "matching source-less synthetic builtin constants should hit"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching source-less synthetic builtin constants should share one node"
    );
}

#[test]
fn synthetic_builtin_attr_current_system_ignores_unrelated_option_identity_salts() {
    let root = unique_temp_dir("force-cache-synthetic-current-system-narrow-options");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    first_options
        .set_store_dir(path_bytes(&root.join("store-a")))
        .expect("store dir is absolute");
    first_options
        .set_search_path_base(path_bytes(&root.join("search-a")))
        .expect("search base is absolute");
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&root.join("nix-a")))
        .expect("nixPath entry configures");
    first_options
        .set_home_dir(path_bytes(&root.join("home-a")))
        .expect("home dir is absolute");
    first_options
        .set_current_time(1_700_000_000)
        .expect("currentTime is valid");
    first_options
        .set_corepkgs_path(path_bytes(&root.join("corepkgs-a")))
        .expect("corepkgs path is absolute");
    first_options
        .set_path_literal_base(path_bytes(&root.join("path-base-a")))
        .expect("path literal base is absolute");
    first_options
        .add_allowed_path(path_bytes(&root.join("allowed-a")))
        .expect("allowed path is absolute");
    first_options
        .add_allowed_uri(b"https://cache-a.example/".to_vec())
        .expect("allowed uri configures");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "synthetic-current-system-narrow-options.nix",
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

    let mut changed_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    changed_options
        .set_store_dir(path_bytes(&root.join("store-b")))
        .expect("store dir is absolute");
    changed_options
        .set_search_path_base(path_bytes(&root.join("search-b")))
        .expect("search base is absolute");
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&root.join("nix-b")))
        .expect("nixPath entry configures");
    changed_options
        .set_home_dir(path_bytes(&root.join("home-b")))
        .expect("home dir is absolute");
    changed_options
        .set_current_time(1_800_000_000)
        .expect("currentTime is valid");
    changed_options
        .set_corepkgs_path(path_bytes(&root.join("corepkgs-b")))
        .expect("corepkgs path is absolute");
    changed_options
        .set_path_literal_base(path_bytes(&root.join("path-base-b")))
        .expect("path literal base is absolute");
    changed_options
        .add_allowed_path(path_bytes(&root.join("allowed-b")))
        .expect("allowed path is absolute");
    changed_options
        .add_allowed_uri(b"https://cache-b.example/".to_vec())
        .expect("allowed uri configures");
    changed_options.set_eval_mode(EvalMode::Restricted);

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-current-system-narrow-options.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(forced)
            .expect("cached currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        changed.stats().cache_hits(),
        1,
        "unchanged currentSystem should hit across unrelated option changes"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "synthetic currentSystem should not allocate a second node for unrelated option changes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_nix_path_thunks_hit_and_miss_by_search_path_salt() {
    let root = unique_temp_dir("force-cache-synthetic-nix-path");
    let first_root = root.join("first");
    let second_root = root.join("second");
    fs::create_dir_all(&first_root).expect("first search root exists");
    fs::create_dir_all(&second_root).expect("second search root exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let first_root = root.join("first");
    let second_root = root.join("second");
    let source = "let b = builtins; in { a = b.nixPath; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("first nixPath entry configures");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        "synthetic-nix-path.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_single_nix_path_entry(&first, forced, b"pkg", &path_bytes(&first_root));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "synthetic-nix-path.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_single_nix_path_entry(&second, forced, b"pkg", &path_bytes(&first_root));
    assert_eq!(
        second.stats().cache_hits(),
        1,
        "matching nixPath option salt should permit a synthetic list payload hit"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_root))
        .expect("changed nixPath entry configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-nix-path.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_single_nix_path_entry(&changed, forced, b"pkg", &path_bytes(&second_root));
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "different nixPath option salts must not share one synthetic payload"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "changed nixPath options must allocate separate synthetic builtin nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_store_dir_thunks_hit_and_miss_by_store_dir_salt() {
    let root = unique_temp_dir("force-cache-synthetic-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "let b = builtins; in { a = b.storeDir; }";
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
        "synthetic-store-dir.nix",
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
        "synthetic-store-dir.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached synthetic storeDir result rehydrates")
            .bytes(),
        path_bytes(&first_store).as_slice()
    );
    assert_eq!(
        second.stats().cache_hits(),
        1,
        "matching storeDir option salt should permit a synthetic string payload hit"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_store_dir(path_bytes(&second_store))
        .expect("store dir is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-store-dir.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(forced)
            .expect("changed synthetic storeDir result is a string")
            .bytes(),
        path_bytes(&second_store).as_slice()
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "different storeDir values must not share one synthetic payload"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different storeDir salts should allocate separate synthetic nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_store_dir_ignores_unrelated_option_identity_salts() {
    let root = unique_temp_dir("force-cache-synthetic-store-dir-narrow-options");
    let store = root.join("store");
    let source = "let b = builtins; in { a = b.storeDir; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_store_dir(path_bytes(&store))
        .expect("store dir is absolute");
    first_options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    first_options
        .set_current_time(1_700_000_000)
        .expect("currentTime is valid");
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&root.join("nix-a")))
        .expect("nixPath entry configures");
    first_options
        .set_path_literal_base(path_bytes(&root.join("path-base-a")))
        .expect("path literal base is absolute");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "synthetic-store-dir-narrow-options.nix",
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
        path_bytes(&store).as_slice()
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_store_dir(path_bytes(&store))
        .expect("store dir is absolute");
    changed_options
        .set_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem is valid");
    changed_options
        .set_current_time(1_800_000_000)
        .expect("currentTime is valid");
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&root.join("nix-b")))
        .expect("nixPath entry configures");
    changed_options
        .set_path_literal_base(path_bytes(&root.join("path-base-b")))
        .expect("path literal base is absolute");
    changed_options.set_eval_mode(EvalMode::Pure);

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-store-dir-narrow-options.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(forced)
            .expect("cached storeDir result rehydrates")
            .bytes(),
        path_bytes(&store).as_slice()
    );
    assert_eq!(
        changed.stats().cache_hits(),
        1,
        "unchanged storeDir should hit across unrelated option changes"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "synthetic storeDir should not allocate a second node for unrelated option changes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}
