//! Persistent force-cache revalidation tests for import-backed attr thunks.

use super::*;

fn persistent_runtime() -> Arc<Mutex<EvalCacheRuntime>> {
    Arc::new(Mutex::new(EvalCacheRuntime::enabled()))
}

#[test]
fn import_backed_inline_thunks_hit_and_miss_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-import-backed");
    let root = unique_temp_dir("force-cache-persistent-import-backed-source");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&fs::canonicalize(root.join("dep.nix")).expect("dep canonicalizes"));
    let source = "{ a = import ./dep.nix; }";
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
    let parent_key = {
        let thunk = first
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended thunk");
        let subject = first
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("a force-cache subject builds");
        PersistNodeMetadataKey::for_expression(
            subject
                .metadata_identity
                .expect("a has a persistent metadata identity"),
            subject.free_var_value_hashes.iter().copied(),
        )
    };
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("import-backed force succeeds");
    assert_eq!(forced.as_int(), Ok(1));
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let persisted = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert!(
        persisted
            .lookup_node_materialized_value_hash(parent_key)
            .expect("parent metadata reads")
            .is_some(),
        "the import-backed parent must materialize after prior-run demand"
    );
    let parent_trace = persisted
        .lookup_node_trace(parent_key)
        .expect("parent trace reads")
        .expect("parent trace exists");
    assert!(
        !parent_trace.payload().is_tombstone(),
        "the import-backed parent trace must remain live"
    );
    assert_eq!(
        parent_trace.payload().memo_read_dependencies().len(),
        1,
        "the parent trace must retain its durable scalar import-root dependency"
    );
    drop(persisted);

    let mut probe_options = TreeWalkOptions::with_eval_cache_enabled(true);
    probe_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    probe_options.set_persist_cache_root(&persist_root);
    let mut probe = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        probe_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    let probe_root = probe.eval_root().expect("probe attrset evaluates");
    let probe_thunk = {
        let attrs = probe
            .heap()
            .get_attrs(probe_root)
            .expect("probe attrset is heap-owned");
        attrs.get(a).expect("probe a exists")
    };
    let probe_subject = {
        let thunk = probe
            .heap()
            .get_thunk(probe_thunk)
            .expect("probe a remains suspended");
        probe
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("probe a force-cache subject builds")
    };
    assert!(
        probe.force_cache_has_prior_persistent_demand(&probe_subject),
        "the replay subject must retain its prior-run demand"
    );
    assert_eq!(
        PersistNodeMetadataKey::for_expression(
            probe_subject
                .metadata_identity
                .expect("probe a has a persistent metadata identity"),
            probe_subject.free_var_value_hashes.iter().copied(),
        ),
        parent_key,
        "the replay subject must address the materialized parent"
    );
    let probe_hit = probe
        .lookup_forced_inline_expression_result(Some(probe_subject))
        .expect("the trace-verified parent payload replays");
    assert_eq!(probe_hit.as_int(), Ok(1));
    drop(probe);

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

    assert_eq!(second_forced.as_int(), Ok(1));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable import-backed payloads must replay without recomputation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    let expected_trace =
        vec![ImpureInputFingerprint::import(&dep_path, b"1").expect("fingerprint builds")];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent import hits must replay the revalidated source edge"
    );
    drop(second);

    fs::write(root.join("dep.nix"), b"2").expect("import source changes");

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

    assert_eq!(changed_forced.as_int(), Ok(2));
    assert_eq!(
        changed.stats().thunks_forced(),
        1,
        "changed import-backed payloads should recompute after stale trace revalidation"
    );
    assert_eq!(changed.stats().cache_hits(), 0);
    assert_eq!(changed.stats().cache_misses(), 1);
    let changed_trace =
        vec![ImpureInputFingerprint::import(&dep_path, b"2").expect("fingerprint builds")];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
