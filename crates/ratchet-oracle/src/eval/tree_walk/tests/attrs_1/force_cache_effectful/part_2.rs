//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn find_file_first_class_nix_path_hits_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-first-class-find-file-nix-path-persist");
    let root = unique_temp_dir("force-cache-first-class-find-file-nix-path-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = (let f = builtins.findFile builtins.nixPath; in f \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_find_file_apply_id(&ir);
    let builtin = lookup_builtin(b"findFile").expect("findFile builtin is registered");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("first-class findFile candidate fingerprint builds"),
    ];

    let mut demand_options = TreeWalkOptions::with_eval_cache_enabled(true);
    demand_options.set_persist_cache_root(&persist_root);
    demand_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        demand_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demand_forced = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demand_forced),
        path_bytes(&hit_candidate)
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        demand.stats().force_cache_misses(),
        0,
        "the first first-class findFile demand should only record memoization policy"
    );
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures for materialization");
    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        materialize_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        path_value_bytes(&materialize, materialized),
        path_bytes(&hit_candidate)
    );
    assert_eq!(materialize.impure_input_trace(), expected_trace.as_slice());
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "the second first-class findFile demand should materialize a cold trace-backed child payload"
    );
    let child_persist_key =
        first_class_primop_persist_key_for_current_node(&mut materialize, apply_id, builtin)
            .expect("first-class findFile child persistent subject builds");
    let trace_entry = assert_persistent_find_file_trace_log_contains(
        &persist_root,
        &expected_trace,
        "first-class builtins.nixPath findFile materialization run",
    );
    assert_eq!(
        trace_entry.0, child_persist_key,
        "the materialized persistent trace should belong to the first-class findFile child call"
    );
    drop(materialize);

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
    assert!(
        second.stats().thunks_forced() > 0,
        "fresh-runtime first-class child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        second.persist_force_cache_hit_keys.as_slice(),
        &[child_persist_key],
        "fresh-runtime first-class findFile hit should load only the child-call metadata key"
    );
    assert_eq!(
        assert_persistent_find_file_trace_log_contains(
            &persist_root,
            &expected_trace,
            "fresh-runtime first-class findFile hit",
        ),
        trace_entry,
        "fresh-runtime first-class findFile hit should keep the original verifying trace live"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_first_class_explicit_list_calls_hit_and_miss_on_path_change() {
    let first_root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-first");
    let second_root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-second");
    let first_candidate = first_root.join("hit").join("subdir");
    let second_candidate = second_root.join("hit").join("subdir");
    fs::create_dir_all(&first_candidate).expect("first candidate exists");
    fs::create_dir_all(&second_candidate).expect("second candidate exists");
    let first_root = fs::canonicalize(&first_root).expect("first root canonicalizes");
    let second_root = fs::canonicalize(&second_root).expect("second root canonicalizes");
    let first_candidate = first_root.join("hit").join("subdir");
    let second_candidate = second_root.join("hit").join("subdir");
    let source = "{ a = (let f = builtins.findFile; in f [ { prefix = \"pkg\"; path = ./hit; } ] \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let first_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&first_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("first explicit-list findFile candidate fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(path_bytes(&first_root))
        .expect("first path base configures");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let first_forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        path_value_bytes(&first, first_forced),
        path_bytes(&first_candidate)
    );
    assert_eq!(first.impure_input_trace(), first_trace.as_slice());
    drop(first);

    let mut admit_options = TreeWalkOptions::new();
    admit_options
        .set_path_literal_base(path_bytes(&first_root))
        .expect("matching path base configures");
    let mut admit = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        admit_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let admitted = force_attr_a(&mut admit, &ir, a);
    assert_eq!(
        path_value_bytes(&admit, admitted),
        path_bytes(&first_candidate)
    );
    assert!(
        admit.stats().thunks_forced() > 0,
        "the second first-class explicit-list findFile demand admits and computes the child call"
    );
    assert!(
        admit.stats().force_cache_misses() > 0,
        "the second first-class explicit-list findFile demand should materialize a child payload"
    );
    assert_eq!(admit.impure_input_trace(), first_trace.as_slice());
    drop(admit);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(path_bytes(&first_root))
        .expect("hit path base configures");
    let mut hit = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        hit_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let hit_forced = force_attr_a(&mut hit, &ir, a);
    assert_eq!(
        path_value_bytes(&hit, hit_forced),
        path_bytes(&first_candidate)
    );
    assert!(
        hit.stats().thunks_forced() > 0,
        "first-class explicit-list child-call hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(hit.stats().force_cache_hits(), 1);
    assert_eq!(hit.stats().force_cache_misses(), 0);
    assert_eq!(hit.impure_input_trace(), first_trace.as_slice());
    drop(hit);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&second_root))
        .expect("changed path base configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_forced = force_attr_a(&mut changed, &ir, a);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&second_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed explicit-list findFile candidate fingerprint builds"),
    ];
    assert_eq!(
        path_value_bytes(&changed, changed_forced),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        changed.stats().force_cache_hits(),
        0,
        "changed explicit-list path identity must not reuse the previous first-class findFile payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(first_root).expect("first temp tree removed");
    fs::remove_dir_all(second_root).expect("second temp tree removed");
}

#[test]
fn find_file_first_class_explicit_list_hits_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-persist");
    let root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-persistent-hit");
    let hit_candidate = root.join("hit").join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_candidate = root.join("hit").join("subdir");
    let source = "{ a = (let f = builtins.findFile; in f [ { prefix = \"pkg\"; path = ./hit; } ] \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_find_file_apply_id(&ir);
    let builtin = lookup_builtin(b"findFile").expect("findFile builtin is registered");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("explicit-list first-class findFile candidate fingerprint builds"),
    ];

    let mut demand_options = TreeWalkOptions::with_eval_cache_enabled(true);
    demand_options.set_persist_cache_root(&persist_root);
    demand_options
        .set_path_literal_base(path_bytes(&root))
        .expect("demand path base configures");
    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        demand_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demand_forced = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demand_forced),
        path_bytes(&hit_candidate)
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options
        .set_path_literal_base(path_bytes(&root))
        .expect("materialization path base configures");
    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        materialize_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        path_value_bytes(&materialize, materialized),
        path_bytes(&hit_candidate)
    );
    assert_eq!(materialize.impure_input_trace(), expected_trace.as_slice());
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "the second first-class explicit-list findFile demand should materialize a trace-backed child payload"
    );
    let child_persist_key =
        first_class_primop_persist_key_for_current_node(&mut materialize, apply_id, builtin)
            .expect("first-class explicit-list findFile child persistent subject builds");
    let trace_entry = assert_persistent_find_file_trace_log_contains(
        &persist_root,
        &expected_trace,
        "first-class explicit-list findFile materialization run",
    );
    assert_eq!(
        trace_entry.0, child_persist_key,
        "the materialized persistent trace should belong to the first-class explicit-list findFile child call"
    );
    materialize.advance_persist_eval_cache_run_boundary();
    drop(materialize);

    let second_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("hit path base configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        second_runtime.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "fresh-runtime first-class explicit-list child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    let child_key = first_class_primop_subject_key_for_current_node(&mut second, apply_id, builtin)
        .expect("first-class explicit-list findFile child subject builds after persistent hit");
    assert_force_cache_impure_edges_match_trace(&second_runtime, child_key, &expected_trace);
    assert_eq!(
        second.persist_force_cache_hit_keys.as_slice(),
        &[trace_entry.0],
        "fresh-runtime first-class explicit-list findFile hit should load only the trace-backed metadata key"
    );
    assert_eq!(
        assert_persistent_find_file_trace_log_contains(
            &persist_root,
            &expected_trace,
            "fresh-runtime first-class explicit-list findFile hit",
        ),
        trace_entry,
        "fresh-runtime first-class explicit-list findFile hit should keep the original verifying trace live"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_first_class_explicit_list_with_captured_entries_hits_child_call() {
    let root = unique_temp_dir("force-cache-first-class-find-file-captured-list");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let searchRoot = {}; in
         {{ a = (let f = builtins.findFile; in f [ {{ prefix = \"pkg\"; path = searchRoot; }} ] \"pkg/subdir\"); }}",
        nix_string_literal(&path_source(&hit_root)),
    );
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("captured first-class findFile candidate fingerprint builds"),
    ];

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache.clone(),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);
    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&hit_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    drop(evaluator);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "captured first-class explicit-list entries should not produce an enclosing whole-thunk hit"
    );
    assert_eq!(
        second.stats().force_cache_hits(),
        1,
        "the second captured first-class explicit-list demand should reuse already-recorded surrounding cache entries"
    );
    assert!(
        second.stats().force_cache_misses() > 0,
        "the second captured first-class explicit-list demand should still materialize the child-call payload"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    drop(second);

    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache.clone(),
    );
    let forced_third = force_attr_a(&mut third, &ir, a);
    assert_eq!(
        path_value_bytes(&third, forced_third),
        path_bytes(&hit_candidate)
    );
    assert!(
        third.stats().thunks_forced() > 0,
        "captured first-class explicit-list child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(
        third.stats().force_cache_hits(),
        1,
        "matching captured first-class explicit-list entries should hit the child-call payload"
    );
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_get_env_ignores_unrelated_option_identity_salts() {
    let root = unique_temp_dir("force-cache-first-class-get-env-narrow-options");
    fs::create_dir_all(&root).expect("temp root exists");
    let root = fs::canonicalize(&root).expect("temp root canonicalizes");
    let source = r#"{ a = let target = "AOS_FORCE_CACHE_FIRST_CLASS_NARROW"; f = builtins.getEnv; in f target; }"#;
    let source_name = "first-class-get-env-narrow-options.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_NARROW";
    let expected_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"shared getEnv payload"))
            .expect("getEnv fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::new();
    first_options.set_env_var(env_name.to_vec(), b"shared getEnv payload".to_vec());
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
        .set_path_literal_base(path_bytes(&root.join("path-base-a")))
        .expect("path base is absolute");
    first_options
        .set_home_dir(path_bytes(&root.join("home-a")))
        .expect("home is absolute");
    first_options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem configures");
    first_options
        .set_current_time(1_700_000_000)
        .expect("currentTime configures");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        source_name,
        source,
        cache.clone(),
    );
    let first_value = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(first_value)
            .expect("first getEnv value is a string")
            .bytes(),
        b"shared getEnv payload"
    );
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());

    let mut warm = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        source_name,
        source,
        cache.clone(),
    );
    let warm_value = force_attr_a(&mut warm, &ir, a);
    assert_eq!(
        warm.heap()
            .get_string(warm_value)
            .expect("warm getEnv value is a string")
            .bytes(),
        b"shared getEnv payload"
    );
    assert_eq!(warm.impure_input_trace(), expected_trace.as_slice());
    assert!(
        warm.stats().force_cache_hits() > 0,
        "same-option first-class getEnv replay should hit the child-call node"
    );
    let first_key = single_force_cache_impure_edge_owner_key(&cache, &expected_trace);

    let mut changed_options = TreeWalkOptions::new();
    changed_options.set_env_var(env_name.to_vec(), b"shared getEnv payload".to_vec());
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
        .set_path_literal_base(path_bytes(&root.join("path-base-b")))
        .expect("path base is absolute");
    changed_options
        .set_home_dir(path_bytes(&root.join("home-b")))
        .expect("home is absolute");
    changed_options
        .set_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem configures");
    changed_options
        .set_current_time(1_800_000_000)
        .expect("currentTime configures");
    changed_options.set_reject_ambient_search_path(true);
    changed_options.set_reject_unconfigured_impure_builtin_constants(true);
    changed_options.set_eval_mode(EvalMode::Restricted);

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        source_name,
        source,
        cache.clone(),
    );
    let changed_value = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(changed_value)
            .expect("changed getEnv value is a string")
            .bytes(),
        b"shared getEnv payload"
    );
    assert_eq!(changed.impure_input_trace(), expected_trace.as_slice());
    let changed_key = single_force_cache_impure_edge_owner_key(&cache, &expected_trace);
    assert_eq!(
        changed_key, first_key,
        "unrelated evaluator options must not salt first-class getEnv child-call keys"
    );
    assert!(
        changed.stats().force_cache_hits() > 0,
        "matching first-class getEnv child call should hit across unrelated option changes"
    );
    assert!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("cache is enabled")
            .graph()
            .node_id_for_key(first_key)
            .is_some(),
        "shared runtime should retain the first-class getEnv child-call node under the narrow key"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_get_env_changed_environment_misses_after_revalidation() {
    let source = r#"{ a = let target = "AOS_FORCE_CACHE_FIRST_CLASS_CHANGED"; f = builtins.getEnv; in f target; }"#;
    let source_name = "first-class-get-env-changed-env.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_CHANGED";

    let mut first_options = TreeWalkOptions::new();
    first_options.set_env_var(env_name.to_vec(), b"first".to_vec());
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        source_name,
        source,
        cache.clone(),
    );
    let first_value = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(first_value)
            .expect("first getEnv value is a string")
            .bytes(),
        b"first"
    );
    let first_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"first"))
            .expect("first getEnv fingerprint builds"),
    ];
    assert_eq!(first.impure_input_trace(), first_trace.as_slice());

    let mut warm = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        source_name,
        source,
        cache.clone(),
    );
    let warm_value = force_attr_a(&mut warm, &ir, a);
    assert_eq!(
        warm.heap()
            .get_string(warm_value)
            .expect("warm getEnv value is a string")
            .bytes(),
        b"first"
    );
    assert_eq!(warm.impure_input_trace(), first_trace.as_slice());
    assert!(
        warm.stats().force_cache_hits() > 0,
        "same-env first-class getEnv replay should hit the child-call node"
    );
    let first_key = single_force_cache_impure_edge_owner_key(&cache, &first_trace);

    let mut changed_options = TreeWalkOptions::new();
    changed_options.set_env_var(env_name.to_vec(), b"second".to_vec());

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        source_name,
        source,
        cache.clone(),
    );
    let changed_value = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(changed_value)
            .expect("changed getEnv value is a string")
            .bytes(),
        b"second"
    );
    let changed_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"second"))
            .expect("changed getEnv fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());
    let changed_key = single_force_cache_impure_edge_owner_key(&cache, &changed_trace);
    assert_eq!(
        changed_key, first_key,
        "getEnv values are revalidated impure inputs, not expression identity salts"
    );
    assert!(
        changed.stats().force_cache_misses() > 0,
        "changed getEnv input must reject the stale payload and recompute"
    );
}
