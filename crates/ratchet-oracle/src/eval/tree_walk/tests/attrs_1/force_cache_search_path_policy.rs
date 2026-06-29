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
