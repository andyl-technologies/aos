//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn synthetic_builtin_attr_immediate_constants_force_from_reified_attrset() {
    let source = "let b = builtins; in { t = b.true; f = b.false; n = b.null; }";
    let ir = lower(source);
    let t = symbol_for(&ir, b"t");
    let f = symbol_for(&ir, b"f");
    let n = symbol_for(&ir, b"n");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-immediates.nix",
        source,
        cache.clone(),
    );

    assert_eq!(force_attr(&mut evaluator, &ir, t, "t").as_bool(), Ok(true));
    assert_eq!(force_attr(&mut evaluator, &ir, f, "f").as_bool(), Ok(false));
    assert_eq!(force_attr(&mut evaluator, &ir, n, "n").as_null(), Ok(()));

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        3,
        "reified immediate constants should observe separate synthetic nodes"
    );
}

#[test]
fn synthetic_builtin_attr_immediate_constants_ignore_all_option_identity_salts() {
    let root = unique_temp_dir("force-cache-synthetic-immediate-narrow-options");
    let source = "let b = builtins; in { a = b.true; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_store_dir(path_bytes(&root.join("store-a")))
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
        "synthetic-immediate-narrow-options.nix",
        source,
        cache.clone(),
    );
    assert_eq!(force_attr_a(&mut first, &ir, a).as_bool(), Ok(true));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_store_dir(path_bytes(&root.join("store-b")))
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
    changed_options.set_reject_ambient_search_path(true);

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-immediate-narrow-options.nix",
        source,
        cache.clone(),
    );
    assert_eq!(force_attr_a(&mut changed, &ir, a).as_bool(), Ok(true));
    assert_eq!(
        changed.stats().cache_hits(),
        1,
        "immediate synthetic constants should hit across evaluator option changes"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "synthetic immediate constants should not allocate a second node for option changes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_version_constants_ignore_all_option_identity_salts() {
    let root = unique_temp_dir("force-cache-synthetic-version-narrow-options");
    let source = "let b = builtins; in { n = b.nixVersion; l = b.langVersion; }";
    let ir = lower(source);
    let n = symbol_for(&ir, b"n");
    let l = symbol_for(&ir, b"l");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_store_dir(path_bytes(&root.join("store-a")))
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
        "synthetic-version-narrow-options.nix",
        source,
        cache.clone(),
    );
    let nix_version = force_attr(&mut first, &ir, n, "n");
    assert_eq!(
        first
            .heap()
            .get_string(nix_version)
            .expect("nixVersion result is a string")
            .bytes(),
        PINNED_NIX_VERSION
    );
    assert_eq!(
        force_attr(&mut first, &ir, l, "l").as_int(),
        Ok(PINNED_NIX_LANG_VERSION)
    );
    assert_eq!(first.stats().cache_misses(), 2);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_store_dir(path_bytes(&root.join("store-b")))
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
    changed_options.set_reject_ambient_search_path(true);

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-version-narrow-options.nix",
        source,
        cache.clone(),
    );
    let nix_version = force_attr(&mut changed, &ir, n, "n");
    assert_eq!(
        changed
            .heap()
            .get_string(nix_version)
            .expect("cached nixVersion result rehydrates")
            .bytes(),
        PINNED_NIX_VERSION
    );
    assert_eq!(
        force_attr(&mut changed, &ir, l, "l").as_int(),
        Ok(PINNED_NIX_LANG_VERSION)
    );
    assert_eq!(
        changed.stats().cache_hits(),
        2,
        "version synthetic constants should hit across evaluator option changes"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "synthetic version constants should not allocate new nodes for option changes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_nix_path_ignores_unrelated_option_identity_salts() {
    let root = unique_temp_dir("force-cache-synthetic-nix-path-narrow-options");
    let nix_root = root.join("nix");
    let source = "let b = builtins; in { a = b.nixPath; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&nix_root))
        .expect("nixPath entry configures");
    first_options
        .set_store_dir(path_bytes(&root.join("store-a")))
        .expect("store dir is absolute");
    first_options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    first_options
        .set_current_time(1_700_000_000)
        .expect("currentTime is valid");
    first_options
        .add_allowed_uri(b"https://cache-a.example/".to_vec())
        .expect("allowed uri configures");
    first_options
        .set_path_literal_base(path_bytes(&root.join("path-base-a")))
        .expect("path literal base is absolute");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "synthetic-nix-path-narrow-options.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_single_nix_path_entry(&first, forced, b"pkg", &path_bytes(&nix_root));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&nix_root))
        .expect("nixPath entry configures");
    changed_options
        .set_store_dir(path_bytes(&root.join("store-b")))
        .expect("store dir is absolute");
    changed_options
        .set_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem is valid");
    changed_options
        .set_current_time(1_800_000_000)
        .expect("currentTime is valid");
    changed_options
        .add_allowed_uri(b"https://cache-b.example/".to_vec())
        .expect("allowed uri configures");
    changed_options
        .set_path_literal_base(path_bytes(&root.join("path-base-b")))
        .expect("path literal base is absolute");
    changed_options.set_eval_mode(EvalMode::Restricted);

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-nix-path-narrow-options.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_single_nix_path_entry(&changed, forced, b"pkg", &path_bytes(&nix_root));
    assert_eq!(
        changed.stats().cache_hits(),
        1,
        "unchanged visible nixPath should hit across unrelated option changes"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "synthetic nixPath should not allocate a second node for unrelated option changes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_nix_path_pure_mode_ignores_hidden_configured_entries() {
    let root = unique_temp_dir("force-cache-synthetic-nix-path-pure-hidden");
    let first_root = root.join("first");
    let second_root = root.join("second");
    let source = "let b = builtins; in { a = b.nixPath; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options.set_eval_mode(EvalMode::Pure);
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("first hidden nixPath entry configures");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "synthetic-nix-path-pure-hidden.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_empty_nix_path(&first, forced);
    assert_eq!(first.stats().cache_misses(), 1);

    let mut changed_options = TreeWalkOptions::new();
    changed_options.set_eval_mode(EvalMode::Pure);
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_root))
        .expect("second hidden nixPath entry configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-nix-path-pure-hidden.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_empty_nix_path(&changed, forced);
    assert_eq!(
        changed.stats().cache_hits(),
        1,
        "pure-mode builtins.nixPath should ignore hidden configured entries"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "hidden pure-mode nixPath entries should share one synthetic node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_dynamic_selection_keys_include_symbol() {
    let root = unique_temp_dir("force-cache-synthetic-builtin-symbol");
    let store_dir = root.join("store");
    let source = r#"let
      b = builtins;
      f = name: b.${name};
    in {
      sys = f "currentSystem";
      store = f "storeDir";
    }"#;
    let ir = lower(source);
    let sys = symbol_for(&ir, b"sys");
    let store = symbol_for(&ir, b"store");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options
        .set_store_dir(path_bytes(&store_dir))
        .expect("store dir is absolute");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins-dynamic.nix",
        source,
        cache.clone(),
    );

    let forced_sys = force_attr(&mut evaluator, &ir, sys, "sys");
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced_sys)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    let forced_store = force_attr(&mut evaluator, &ir, store, "store");
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced_store)
            .expect("storeDir result is a string")
            .bytes(),
        path_bytes(&store_dir).as_slice()
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different synthetic builtin symbols at one dynamic select site must miss"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "the synthetic key must distinguish builtin symbols at one force site"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_current_time_records_uncacheable_trace_without_payload() {
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-current-time.nix",
        source,
        cache.clone(),
    );
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
        "synthetic currentTime remains uncacheable even when it is observed"
    );
}

#[test]
fn synthetic_builtin_attr_current_time_ignores_and_invalidates_stale_payload() {
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-current-time.nix",
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
    let select_id = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let current_time = symbol_for(&ir, b"currentTime");
    let builtin = lookup_builtin(b"currentTime").expect("currentTime builtin is registered");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_time,
            builtin,
        )
        .expect("synthetic currentTime identity builds");

    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<ValueHash>(),
                CachedExpressionValue::immediate(Value::int(123))
                    .expect("stale payload is cacheable"),
            )
            .expect("stale payload is seeded");
        assert!(
            runtime
                .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>(),)
                .expect("seeded payload lookup succeeds")
                .is_some(),
            "stale payload should be present before forcing currentTime"
        );
    }

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "synthetic currentTime must not reuse stale payloads"
    );
    let mut runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime
            .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
            .expect("post-force lookup succeeds")
            .is_none(),
        "uncacheable currentTime observation should invalidate the stale payload"
    );
}

