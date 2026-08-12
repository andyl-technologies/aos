//! Persistent force-cache revalidation tests for file-content impure inputs.

use super::*;

fn persistent_runtime() -> Arc<Mutex<EvalCacheRuntime>> {
    Arc::new(Mutex::new(EvalCacheRuntime::enabled()))
}

fn force_attr_a_context_free_string_value(evaluator: &mut TreeWalk, ir: &Ir, a: Symbol) -> Vec<u8> {
    let value = force_attr_a(evaluator, ir, a);
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("forced value is a string");
    assert!(
        !string.has_context(),
        "file-content string payloads must remain context-free"
    );
    string.bytes().to_vec()
}

fn force_attr_a_context_free_string(evaluator: &mut TreeWalk, ir: &Ir, a: Symbol, expected: &[u8]) {
    assert_eq!(
        force_attr_a_context_free_string_value(evaluator, ir, a),
        expected
    );
}

fn force_attr_a_with_impure_observation_and_persist_keys(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    a: Symbol,
) -> (Value, DemandCacheKey, PersistNodeMetadataKey) {
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
            .expect("a remains a suspended thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("a force-cache subject builds")
    };
    let runtime_key = DemandCacheKey::for_free_vars(
        subject
            .impure_observation_identity
            .expect("a has an impure observation identity"),
        subject.free_var_value_hashes.iter().copied(),
    )
    .expect("a force-cache impure observation key builds");
    let persist_key = PersistNodeMetadataKey::for_expression(
        subject
            .metadata_identity
            .expect("a has a persistent metadata identity"),
        subject.free_var_value_hashes.iter().copied(),
    );
    evaluator.record_force_cache_memoization_demand(&subject);
    evaluator.record_force_cache_memoization_demand(&subject);
    let forced = TreeWalk::force_value(evaluator, ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    (forced, runtime_key, persist_key)
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

#[test]
fn nested_multi_input_payload_hits_persistent_cache_and_records_exact_edges() {
    let persist_root = unique_temp_dir("force-cache-persistent-nested-multi-input");
    let root = unique_temp_dir("force-cache-persistent-nested-multi-input-source");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let first_missing_path = path_bytes(&root.join("first-missing"));
    let second_missing_path = path_bytes(&root.join("second-missing"));
    let target_path = path_bytes(&root.join("target"));
    fs::write(root.join("target"), first_missing_path.as_slice())
        .expect("nested path target writes");
    let source = "{ a = builtins.pathExists (builtins.readFile ./target) || builtins.pathExists ./second-missing; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, first_missing_path.as_slice())
            .expect("readFile fingerprint builds"),
        ImpureInputFingerprint::path_exists(&first_missing_path, false)
            .expect("nested pathExists fingerprint builds"),
        ImpureInputFingerprint::path_exists(&second_missing_path, false)
            .expect("second pathExists fingerprint builds"),
    ];

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
        .expect("nested multi-input force succeeds");
    assert_eq!(forced.as_bool(), Ok(false));
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let second_runtime = persistent_runtime();
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
        second_runtime.clone(),
    );
    let (forced_again, runtime_key, persist_key) =
        force_attr_a_with_impure_observation_and_persist_keys(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(false));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable composed impure payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        second.persist_force_cache_hit_keys.as_slice(),
        &[persist_key],
        "fresh-runtime composed impure hit should load only the attr-thunk metadata key"
    );
    assert_force_cache_impure_edges_match_trace(&second_runtime, runtime_key, &expected_trace);

    let expected_payload = PersistNodeTracePayload::from_impure_trace(expected_trace.iter())
        .expect("expected trace payload builds");
    let trace_entry = PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .lookup_node_trace(persist_key)
        .expect("persistent trace lookup succeeds")
        .expect("persistent trace exists");
    assert_eq!(trace_entry.key(), persist_key);
    assert_eq!(trace_entry.payload(), &expected_payload);

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn hash_file_string_payload_hits_and_misses_persistent_cache_after_binary_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-hash-file");
    let root = unique_temp_dir("force-cache-persistent-hash-file-source");
    let first_payload = b"payload\0\xffbytes";
    let changed_payload = b"changed\0\xffbytes";
    let first_expected_hash = b"0c53476b3465b87dc6e482d77b678d8dd704bef452d6ba52c6ca8a8e5327d34e";
    let changed_expected_hash = b"df2dbcd50d04442c424562c9836d698b33d0a3e2e9221367bcf69eb3db6bbbeb";
    fs::write(root.join("target"), first_payload).expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = r#"{ a = builtins.hashFile "sha256" ./target; }"#;
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
        .expect("hashFile force succeeds");
    let first_string = first
        .heap()
        .get_string(forced)
        .expect("hashFile result is a string");
    assert!(
        !first_string.has_context(),
        "cold hashFile payloads must be context-free"
    );
    let first_hash = first_string.bytes().to_vec();
    assert_eq!(first_hash.as_slice(), first_expected_hash);
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
    let second_hash = force_attr_a_context_free_string_value(&mut second, &ir, a);

    assert_eq!(second_hash.as_slice(), first_expected_hash);
    assert_eq!(second_hash, first_hash);
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable hashFile payloads should hit from persistent cache"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    let expected_trace = vec![
        ImpureInputFingerprint::hash_file(&target_path, first_payload).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent hashFile hits must replay the revalidated binary content edge"
    );
    drop(second);

    fs::write(root.join("target"), changed_payload).expect("target changes");

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
    let changed_hash = force_attr_a_context_free_string_value(&mut changed, &ir, a);

    assert_eq!(changed_hash.as_slice(), changed_expected_hash);
    assert_ne!(changed_hash, first_hash);
    assert_eq!(
        changed.stats().thunks_forced(),
        1,
        "changed hashFile payloads should recompute after stale trace revalidation"
    );
    assert_eq!(changed.stats().cache_hits(), 0);
    assert_eq!(changed.stats().cache_misses(), 1);
    let changed_trace = vec![
        ImpureInputFingerprint::hash_file(&target_path, changed_payload)
            .expect("fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
