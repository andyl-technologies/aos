//! Persistent force-cache revalidation tests for effectful impure inputs.

use super::*;

fn persistent_runtime() -> Arc<Mutex<EvalCacheRuntime>> {
    Arc::new(Mutex::new(EvalCacheRuntime::enabled()))
}

#[test]
fn path_exists_bool_payload_hits_and_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-path-exists");
    let root = unique_temp_dir("force-cache-persistent-path-exists-source");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("pathExists force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    let second_forced = force_attr_a(&mut second, &ir, a);

    assert_eq!(second_forced.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable pathExists payloads should hit from persistent cache"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    let expected_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds")];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent pathExists hits must replay the revalidated existence edge"
    );
    drop(second);

    fs::remove_file(root.join("marker")).expect("marker removed");

    let mut changed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    changed_options.set_persist_cache_root(&persist_root);
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    let changed_forced = force_attr_a(&mut changed, &ir, a);

    assert_eq!(changed_forced.as_bool(), Ok(false));
    assert_eq!(
        changed.stats().thunks_forced(),
        1,
        "changed pathExists payloads should recompute after stale trace revalidation"
    );
    assert_eq!(changed.stats().cache_hits(), 0);
    assert_eq!(changed.stats().cache_misses(), 1);
    let changed_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, false).expect("fingerprint builds")];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
