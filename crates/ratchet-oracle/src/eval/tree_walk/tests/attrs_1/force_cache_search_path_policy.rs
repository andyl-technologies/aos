//! Search-path force-cache canaries for filesystem access policy changes.

use super::*;

#[test]
fn search_path_literal_thunks_do_not_replay_across_allowed_path_policy() {
    let persist_root = unique_temp_dir("force-cache-search-path-allowed-policy-persist");
    let root = unique_temp_dir("force-cache-search-path-allowed-policy");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut allowed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    allowed_options.set_eval_mode(EvalMode::Restricted);
    allowed_options.set_persist_cache_root(&persist_root);
    allowed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    allowed_options
        .add_allowed_path(path_bytes(&hit_root))
        .expect("hit root configures as allowed");
    let mut allowed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        allowed_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value =
        seed_prior_persistent_demand_for_attr(&mut allowed, &ir, a, &persist_root, "a");
    let forced = allowed
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("allowed search-path literal force succeeds");
    assert_eq!(
        path_value_bytes(&allowed, forced),
        path_bytes(&hit_candidate)
    );
    drop(allowed);

    let mut replay_options = TreeWalkOptions::with_eval_cache_enabled(true);
    replay_options.set_eval_mode(EvalMode::Restricted);
    replay_options.set_persist_cache_root(&persist_root);
    replay_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures for replay");
    replay_options
        .add_allowed_path(path_bytes(&hit_root))
        .expect("matching allowed root configures for replay");
    let mut replay = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        replay_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let replayed = force_attr_a(&mut replay, &ir, a);

    assert_eq!(
        path_value_bytes(&replay, replayed),
        path_bytes(&hit_candidate)
    );
    assert_eq!(
        replay.stats().thunks_forced(),
        0,
        "same-policy fresh runtimes should rehydrate the search-path payload"
    );
    assert_eq!(replay.stats().cache_hits(), 1);
    assert_eq!(replay.stats().cache_misses(), 0);
    drop(replay);

    let mut denied_options = TreeWalkOptions::with_eval_cache_enabled(true);
    denied_options.set_eval_mode(EvalMode::Restricted);
    denied_options.set_persist_cache_root(&persist_root);
    denied_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures");
    let mut denied = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        denied_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root_value = denied.eval_root().expect("attrset evaluates");
    let denied_thunk = {
        let attrs = denied
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let error = denied
        .force_admitted_value(ir.root, Span::new(0, 0), denied_thunk)
        .expect_err("restricted policy rejects unallowed search-path candidate");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));
    assert_eq!(
        denied.stats().cache_hits(),
        0,
        "denied policy must not reuse a payload cached under a wider allowed-path policy"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn composed_search_path_literal_thunks_do_not_replay_across_allowed_path_policy() {
    let persist_root = unique_temp_dir("force-cache-composed-search-path-policy-persist");
    let root = unique_temp_dir("force-cache-composed-search-path-policy");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = <pkg/subdir> == <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut allowed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    allowed_options.set_eval_mode(EvalMode::Restricted);
    allowed_options.set_persist_cache_root(&persist_root);
    allowed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    allowed_options
        .add_allowed_path(path_bytes(&hit_root))
        .expect("hit root configures as allowed");
    let mut allowed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        allowed_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value =
        seed_prior_persistent_demand_for_attr(&mut allowed, &ir, a, &persist_root, "a");
    let forced = allowed
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("allowed composed search-path literal force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        allowed.impure_input_trace(),
        vec![
            ImpureInputFingerprint::path_exists_with_mode(
                &path_bytes(&hit_candidate),
                ImpureInputMode::FindFileCandidate,
                true,
            )
            .expect("search path candidate fingerprint builds"),
            ImpureInputFingerprint::path_exists_with_mode(
                &path_bytes(&hit_candidate),
                ImpureInputMode::FindFileCandidate,
                true,
            )
            .expect("repeated search path candidate fingerprint builds"),
        ]
        .as_slice()
    );
    drop(allowed);

    let mut replay_options = TreeWalkOptions::with_eval_cache_enabled(true);
    replay_options.set_eval_mode(EvalMode::Restricted);
    replay_options.set_persist_cache_root(&persist_root);
    replay_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures for replay");
    replay_options
        .add_allowed_path(path_bytes(&hit_root))
        .expect("matching allowed root configures for replay");
    let mut replay = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        replay_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let replayed = force_attr_a(&mut replay, &ir, a);

    assert_eq!(replayed.as_bool(), Ok(true));
    assert_eq!(
        replay.stats().thunks_forced(),
        0,
        "same-policy fresh runtimes should rehydrate the composed search-path payload"
    );
    assert_eq!(replay.stats().force_cache_hits(), 1);
    assert_eq!(replay.stats().cache_misses(), 0);
    drop(replay);

    let mut denied_options = TreeWalkOptions::with_eval_cache_enabled(true);
    denied_options.set_eval_mode(EvalMode::Restricted);
    denied_options.set_persist_cache_root(&persist_root);
    denied_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures");
    let mut denied = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        denied_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root_value = denied.eval_root().expect("attrset evaluates");
    let denied_thunk = {
        let attrs = denied
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let error = denied
        .force_admitted_value(ir.root, Span::new(0, 0), denied_thunk)
        .expect_err("restricted policy rejects unallowed composed search-path candidate");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));
    assert_eq!(
        denied.stats().force_cache_hits(),
        0,
        "denied policy must not reuse a composed payload cached under a wider allowed-path policy"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_nix_path_find_file_does_not_replay_across_allowed_path_policy() {
    let persist_root = unique_temp_dir("force-cache-first-class-nix-path-allowed-policy-persist");
    let root = unique_temp_dir("force-cache-first-class-nix-path-allowed-policy");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = (let f = builtins.findFile builtins.nixPath; in f \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_find_file_policy_options(&persist_root, &hit_root, true),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demanded = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demanded),
        path_bytes(&hit_candidate)
    );
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_find_file_policy_options(&persist_root, &hit_root, true),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        path_value_bytes(&materialize, materialized),
        path_bytes(&hit_candidate)
    );
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "second same-policy first-class nixPath findFile run should materialize a child payload"
    );
    materialize.advance_persist_eval_cache_run_boundary();
    drop(materialize);

    let mut replay = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_find_file_policy_options(&persist_root, &hit_root, true),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let replayed = force_attr_a(&mut replay, &ir, a);
    assert_eq!(
        path_value_bytes(&replay, replayed),
        path_bytes(&hit_candidate)
    );
    assert!(
        replay.stats().thunks_forced() > 0,
        "first-class child-call hits still evaluate the enclosing thunk"
    );
    assert_eq!(
        replay.stats().force_cache_hits(),
        1,
        "same-policy fresh runtimes should rehydrate the first-class nixPath findFile child payload"
    );
    assert_eq!(replay.stats().force_cache_misses(), 0);
    drop(replay);

    let mut denied = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_find_file_policy_options(&persist_root, &hit_root, false),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let error = force_attr_a_expect_err(
        &mut denied,
        &ir,
        a,
        "restricted policy rejects unallowed first-class nixPath findFile candidate",
    );
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));
    assert_eq!(
        denied.stats().force_cache_hits(),
        0,
        "denied policy must not reuse a first-class nixPath findFile payload cached under a wider allowed-path policy"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_explicit_list_find_file_does_not_replay_across_allowed_path_policy() {
    let persist_root =
        unique_temp_dir("force-cache-first-class-explicit-list-allowed-policy-persist");
    let root = unique_temp_dir("force-cache-first-class-explicit-list-allowed-policy");
    let hit_candidate = root.join("hit").join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = (let f = builtins.findFile; in f [ { prefix = \"pkg\"; path = ./hit; } ] \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_explicit_list_policy_options(&persist_root, &root, &hit_root, true),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demanded = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demanded),
        path_bytes(&hit_candidate)
    );
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_explicit_list_policy_options(&persist_root, &root, &hit_root, true),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        path_value_bytes(&materialize, materialized),
        path_bytes(&hit_candidate)
    );
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "second same-policy first-class explicit-list findFile run should materialize a child payload"
    );
    materialize.advance_persist_eval_cache_run_boundary();
    drop(materialize);

    let mut replay = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_explicit_list_policy_options(&persist_root, &root, &hit_root, true),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let replayed = force_attr_a(&mut replay, &ir, a);
    assert_eq!(
        path_value_bytes(&replay, replayed),
        path_bytes(&hit_candidate)
    );
    assert!(
        replay.stats().thunks_forced() > 0,
        "first-class child-call hits still evaluate the enclosing thunk"
    );
    assert_eq!(
        replay.stats().force_cache_hits(),
        1,
        "same-policy fresh runtimes should rehydrate the first-class explicit-list findFile child payload"
    );
    assert_eq!(replay.stats().force_cache_misses(), 0);
    drop(replay);

    let mut denied = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_class_explicit_list_policy_options(&persist_root, &root, &hit_root, false),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let error = force_attr_a_expect_err(
        &mut denied,
        &ir,
        a,
        "restricted policy rejects unallowed first-class explicit-list findFile candidate",
    );
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));
    assert_eq!(
        denied.stats().force_cache_hits(),
        0,
        "denied policy must not reuse a first-class explicit-list findFile payload cached under a wider allowed-path policy"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

fn first_class_find_file_policy_options(
    persist_root: &std::path::Path,
    hit_root: &std::path::Path,
    allow_hit_root: bool,
) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_eval_mode(EvalMode::Restricted);
    options.set_persist_cache_root(persist_root);
    options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(hit_root))
        .expect("search path entry configures");
    if allow_hit_root {
        options
            .add_allowed_path(path_bytes(hit_root))
            .expect("hit root configures as allowed");
    }
    options
}

fn first_class_explicit_list_policy_options(
    persist_root: &std::path::Path,
    root: &std::path::Path,
    hit_root: &std::path::Path,
    allow_hit_root: bool,
) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_eval_mode(EvalMode::Restricted);
    options.set_persist_cache_root(persist_root);
    options
        .set_path_literal_base(path_bytes(root))
        .expect("path literal base configures");
    if allow_hit_root {
        options
            .add_allowed_path(path_bytes(hit_root))
            .expect("hit root configures as allowed");
    }
    options
}

fn force_attr_a_expect_err(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    a: Symbol,
    context: &str,
) -> TreeWalkError {
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err(context)
}
