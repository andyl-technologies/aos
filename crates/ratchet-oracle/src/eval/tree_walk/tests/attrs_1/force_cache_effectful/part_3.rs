//! Split-out tests (part_3). See parent module.

use super::*;

#[test]
fn first_class_get_env_hits_persistent_cache_across_unrelated_option_salts() {
    let persist_root = unique_temp_dir("force-cache-first-class-get-env-persist");
    let root = unique_temp_dir("force-cache-first-class-get-env-persist-salts");
    fs::create_dir_all(&root).expect("salt root exists");
    let root = fs::canonicalize(&root).expect("salt root canonicalizes");
    let source = r#"{ a = let target = "AOS_FORCE_CACHE_FIRST_CLASS_PERSIST"; f = builtins.getEnv; in f target; }"#;
    let source_name = "first-class-get-env-persist.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_PERSIST";
    let expected_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"persistent payload"))
            .expect("persistent getEnv fingerprint builds"),
    ];

    let configure_options =
        |env_value: &[u8], suffix: &str, eval_mode: EvalMode| -> TreeWalkOptions {
            let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
            options.set_persist_cache_root(&persist_root);
            options.set_env_var(env_name.to_vec(), env_value.to_vec());
            options
                .set_store_dir(path_bytes(&root.join(format!("store-{suffix}"))))
                .expect("store dir is absolute");
            options
                .set_search_path_base(path_bytes(&root.join(format!("search-{suffix}"))))
                .expect("search base is absolute");
            options
                .add_nix_path_entry(
                    b"pkg".to_vec(),
                    path_bytes(&root.join(format!("nix-{suffix}"))),
                )
                .expect("nixPath entry configures");
            options
                .set_path_literal_base(path_bytes(&root.join(format!("path-base-{suffix}"))))
                .expect("path base is absolute");
            options
                .set_home_dir(path_bytes(&root.join(format!("home-{suffix}"))))
                .expect("home is absolute");
            options
                .set_current_system(format!("{suffix}-linux").into_bytes())
                .expect("currentSystem configures");
            options
                .set_current_time(if suffix == "a" {
                    1_700_000_000
                } else {
                    1_800_000_000
                })
                .expect("currentTime configures");
            options.set_reject_ambient_search_path(suffix != "a");
            options.set_reject_unconfigured_impure_builtin_constants(suffix != "a");
            options.set_eval_mode(eval_mode);
            options
        };

    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"persistent payload", "a", EvalMode::Impure),
        source_name,
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demand_value = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        demand
            .heap()
            .get_string(demand_value)
            .expect("demand getEnv value is a string")
            .bytes(),
        b"persistent payload"
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"persistent payload", "a", EvalMode::Impure),
        source_name,
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        materialize
            .heap()
            .get_string(materialized)
            .expect("materialized getEnv value is a string")
            .bytes(),
        b"persistent payload"
    );
    assert_eq!(materialize.impure_input_trace(), expected_trace.as_slice());
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "second first-class getEnv demand should materialize a trace-backed child payload"
    );
    let trace_entry = assert_persistent_trace_log_contains(
        &persist_root,
        &expected_trace,
        "first-class getEnv materialization run",
    );
    materialize.advance_persist_eval_cache_run_boundary();
    drop(materialize);

    let hit_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut hit = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"persistent payload", "b", EvalMode::Restricted),
        source_name,
        source,
        hit_runtime.clone(),
    );
    let hit_value = force_attr_a(&mut hit, &ir, a);
    assert_eq!(
        hit.heap()
            .get_string(hit_value)
            .expect("persistent hit getEnv value is a string")
            .bytes(),
        b"persistent payload"
    );
    assert!(
        hit.stats().thunks_forced() > 0,
        "fresh-runtime first-class getEnv child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(hit.stats().force_cache_hits(), 1);
    assert_eq!(hit.stats().force_cache_misses(), 0);
    assert_eq!(hit.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        hit.persist_force_cache_hit_keys.as_slice(),
        &[trace_entry.0],
        "fresh-runtime first-class getEnv hit should load only the child-call metadata key"
    );
    assert_eq!(
        assert_persistent_trace_log_contains(
            &persist_root,
            &expected_trace,
            "fresh-runtime first-class getEnv hit",
        ),
        trace_entry,
        "fresh-runtime first-class getEnv hit should keep the original verifying trace live"
    );
    let hit_key = single_force_cache_impure_edge_owner_key(&hit_runtime, &expected_trace);
    drop(hit);

    let changed_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"changed persistent payload", "b", EvalMode::Restricted),
        source_name,
        source,
        changed_runtime.clone(),
    );
    let changed_value = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(changed_value)
            .expect("changed getEnv value is a string")
            .bytes(),
        b"changed persistent payload"
    );
    let changed_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"changed persistent payload"))
            .expect("changed persistent getEnv fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());
    let changed_key = single_force_cache_impure_edge_owner_key(&changed_runtime, &changed_trace);
    assert_eq!(
        changed_key, hit_key,
        "changed getEnv values must revalidate under the same child-call identity, not miss by value-salted key"
    );
    assert_eq!(
        changed.stats().force_cache_hits(),
        0,
        "changed persistent getEnv input must reject the stale child payload"
    );
    assert!(
        changed.stats().force_cache_misses() > 0,
        "changed persistent getEnv input should recompute after stale trace rejection"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("salt temp tree removed");
}

#[test]
fn first_class_get_env_pure_mode_separates_hidden_environment_identity() {
    let source = r#"{ a = let f = builtins.getEnv; in f "AOS_FORCE_CACHE_FIRST_CLASS_PURE"; }"#;
    let source_name = "first-class-get-env-pure-mode.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_get_env_apply_id(&ir);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_PURE";

    let mut impure_options = TreeWalkOptions::new();
    impure_options.set_env_var(env_name.to_vec(), b"visible".to_vec());
    let mut impure = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        impure_options,
        source_name,
        source,
        cache.clone(),
    );
    let impure_value = force_attr_a(&mut impure, &ir, a);
    assert_eq!(
        impure
            .heap()
            .get_string(impure_value)
            .expect("impure getEnv value is a string")
            .bytes(),
        b"visible"
    );
    let impure_key = first_class_get_env_child_key_for_evaluator(&mut impure, apply_id);

    let mut pure_options = TreeWalkOptions::new();
    pure_options.set_env_var(env_name.to_vec(), b"visible".to_vec());
    pure_options.set_eval_mode(EvalMode::Pure);
    let mut pure = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        pure_options,
        source_name,
        source,
        cache,
    );
    let pure_value = force_attr_a(&mut pure, &ir, a);
    assert_eq!(
        pure.heap()
            .get_string(pure_value)
            .expect("pure getEnv value is a string")
            .bytes(),
        b""
    );
    let pure_key = first_class_get_env_child_key_for_evaluator(&mut pure, apply_id);
    assert_ne!(
        pure_key, impure_key,
        "pure getEnv has no revalidation trace and must not share impure payload identities"
    );
    assert!(
        pure.impure_input_trace().is_empty(),
        "pure getEnv hides configured variables without recording an impure edge"
    );
    assert_eq!(
        pure.stats().force_cache_hits(),
        0,
        "pure getEnv must not replay the impure cached payload"
    );
}

#[test]
fn find_file_nix_path_thunks_revalidate_candidate_edges_before_hits_and_miss_on_option_change() {
    let root = unique_temp_dir("force-cache-find-file-nix-path");
    let first_root = root.join("first");
    let first_candidate = first_root.join("subdir");
    let second_root = root.join("second");
    let second_candidate = second_root.join("subdir");
    fs::create_dir_all(&first_candidate).expect("first candidate exists");
    fs::create_dir_all(&second_candidate).expect("second candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let first_root = root.join("first");
    let first_candidate = first_root.join("subdir");
    let second_root = root.join("second");
    let second_candidate = second_root.join("subdir");
    let source = "{ a = builtins.findFile builtins.nixPath \"pkg/subdir\"; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("search path entry configures");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&first_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("findFile nixPath candidate fingerprint builds"),
    ];

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);

    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&first_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    {
        let runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert!(
            cache.len() >= 2,
            "builtins.nixPath-backed findFile should allocate an expression node and candidate leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            1,
            "the expression node must depend on the observed builtins.nixPath findFile candidate"
        );
    }

    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&first_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable builtins.nixPath-backed findFile payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay builtins.nixPath-backed findFile candidate edges"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_root))
        .expect("changed search path entry configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_changed = force_attr_a(&mut changed, &ir, a);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&second_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed findFile nixPath candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&changed, forced_changed),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "changed nixPath option salt must not reuse the previous findFile payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_nix_path_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-find-file-nix-path-persist");
    let root = unique_temp_dir("force-cache-find-file-nix-path-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = builtins.findFile builtins.nixPath \"pkg/subdir\"; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("findFile nixPath candidate fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("findFile nixPath force succeeds");

    assert_eq!(path_value_bytes(&first, forced), path_bytes(&hit_candidate));
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
    assert!(
        first.stats().force_cache_misses() > 0,
        "the first persistent run should materialize the findFile nixPath payload"
    );
    drop(first);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable builtins.nixPath-backed findFile payloads from disk"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent hit revalidation must replay the builtins.nixPath findFile candidate edges"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_thunks_revalidate_candidate_edges_before_hits_and_miss_on_option_change() {
    let root = unique_temp_dir("force-cache-search-path-literal");
    let first_root = root.join("first");
    let first_candidate = first_root.join("subdir");
    let second_root = root.join("second");
    let second_candidate = second_root.join("subdir");
    fs::create_dir_all(&first_candidate).expect("first candidate exists");
    fs::create_dir_all(&second_candidate).expect("second candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let first_root = root.join("first");
    let first_candidate = first_root.join("subdir");
    let second_root = root.join("second");
    let second_candidate = second_root.join("subdir");
    let source = "{ a = <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("search path entry configures");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&first_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("search path candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&first_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime.cache().expect("cache is enabled").len() >= 2,
            "search-path literal should allocate an expression node and candidate leaf"
        );
    }

    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&first_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable search-path literal payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay search-path candidate edges"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_root))
        .expect("changed search path entry configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_changed = force_attr_a(&mut changed, &ir, a);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&second_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed search path candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&changed, forced_changed),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "changed nixPath option salt must not reuse the previous search-path payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn composed_search_path_literal_thunks_hit_and_miss_on_option_change() {
    let root = unique_temp_dir("force-cache-composed-search-path-literal");
    let first_root = root.join("first");
    let first_candidate = first_root.join("subdir");
    let second_root = root.join("second");
    let second_candidate = second_root.join("subdir");
    fs::create_dir_all(&first_candidate).expect("first candidate exists");
    fs::create_dir_all(&second_candidate).expect("second candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let first_root = root.join("first");
    let first_candidate = first_root.join("subdir");
    let second_root = root.join("second");
    let second_candidate = second_root.join("subdir");
    let source = "{ a = <pkg/subdir> == <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("search path entry configures");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);
    let first_fingerprint = ImpureInputFingerprint::path_exists_with_mode(
        &path_bytes(&first_candidate),
        ImpureInputMode::FindFileCandidate,
        true,
    )
    .expect("first search path candidate fingerprint builds");
    let expected_trace = vec![first_fingerprint.clone(), first_fingerprint];

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());

    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable composed search-path payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay each composed search-path candidate edge"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_root))
        .expect("changed search path entry configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_changed = force_attr_a(&mut changed, &ir, a);
    let changed_fingerprint = ImpureInputFingerprint::path_exists_with_mode(
        &path_bytes(&second_candidate),
        ImpureInputMode::FindFileCandidate,
        true,
    )
    .expect("changed search path candidate fingerprint builds");
    let changed_trace = vec![changed_fingerprint.clone(), changed_fingerprint];

    assert_eq!(forced_changed.as_bool(), Ok(true));
    assert_eq!(
        changed.stats().force_cache_hits(),
        0,
        "changed nixPath option salt must not reuse the previous composed search-path payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn composed_search_path_literal_equality_records_exact_force_cache_graph_edges() {
    let root = unique_temp_dir("force-cache-composed-search-path-exact-edges");
    let hit_root = root.join("hit");
    let left_candidate = hit_root.join("left");
    let right_candidate = hit_root.join("right");
    fs::create_dir_all(&left_candidate).expect("left candidate exists");
    fs::create_dir_all(&right_candidate).expect("right candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let left_candidate = hit_root.join("left");
    let right_candidate = hit_root.join("right");
    let source = "{ a = <pkg/left> == <pkg/right>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&left_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("left search path candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&right_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("right search path candidate fingerprint builds"),
    ];
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );

    let (forced, owner_key) = force_attr_a_with_impure_observation_key(&mut evaluator, &ir, a);

    assert_eq!(forced.as_bool(), Ok(false));
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    assert_force_cache_impure_edges_match_trace(&cache, owner_key, &expected_trace);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-search-path-literal-persist");
    let root = unique_temp_dir("force-cache-search-path-literal-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("search path candidate fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("search-path literal force succeeds");
    assert_eq!(path_value_bytes(&first, forced), path_bytes(&hit_candidate));
    drop(first);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable search-path literal payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}
