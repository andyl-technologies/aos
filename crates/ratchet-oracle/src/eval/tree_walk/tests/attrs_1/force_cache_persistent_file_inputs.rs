//! Persistent force-cache revalidation tests for file-content impure inputs.

use super::*;

fn persistent_runtime() -> Arc<Mutex<EvalCacheRuntime>> {
    Arc::new(Mutex::new(EvalCacheRuntime::enabled()))
}

fn force_attr_a_context_free_string(evaluator: &mut TreeWalk, ir: &Ir, a: Symbol, expected: &[u8]) {
    let value = force_attr_a(evaluator, ir, a);
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("forced value is a string");
    assert_eq!(string.bytes(), expected);
    assert!(
        !string.has_context(),
        "readFile payloads must remain context-free"
    );
}

#[test]
fn read_file_string_payload_hits_and_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-read-file");
    let root = unique_temp_dir("force-cache-persistent-read-file-source");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
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
        .expect("readFile force succeeds");
    let first_string = first
        .heap()
        .get_string(forced)
        .expect("readFile result is a string");
    assert_eq!(first_string.bytes(), b"payload");
    assert!(
        !first_string.has_context(),
        "cold readFile payloads must be context-free"
    );
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
    force_attr_a_context_free_string(&mut second, &ir, a, b"payload");

    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFile payloads should hit from persistent cache"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, b"payload").expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent readFile hits must replay the revalidated content edge"
    );
    drop(second);

    fs::write(root.join("target"), b"changed").expect("target changes");

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
    force_attr_a_context_free_string(&mut changed, &ir, a, b"changed");

    assert_eq!(
        changed.stats().thunks_forced(),
        1,
        "changed readFile payloads should recompute after stale trace revalidation"
    );
    assert_eq!(changed.stats().cache_hits(), 0);
    assert_eq!(changed.stats().cache_misses(), 1);
    let changed_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, b"changed").expect("fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
