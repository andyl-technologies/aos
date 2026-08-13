//! Split-out tests (part_6). See parent module.

use super::*;

#[test]
fn changed_find_file_candidate_trace_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-find-file-changed");
    let root = unique_temp_dir("force-cache-find-file-stale");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
    let missing_candidate = missing_root.join("subdir");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "{{ a = builtins.findFile [
             {{ prefix = \"pkg\"; path = {}; }}
             {{ prefix = \"pkg\"; path = {}; }}
           ] \"pkg/subdir\"; }}",
        nix_string_literal(&path_source(&missing_root)),
        nix_string_literal(&path_source(&hit_root)),
    );
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source.as_str(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("findFile force succeeds");
    assert_eq!(path_value_bytes(&first, forced), path_bytes(&hit_candidate));
    drop(first);

    fs::create_dir_all(&missing_candidate).expect("formerly missing candidate appears");

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source.as_str(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_changed = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_changed),
        path_bytes(&missing_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "stale persistent findFile traces should fall back to ordinary forcing"
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert!(second.stats().cache_misses() > 0);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed findFile candidate fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_find_file_nix_path_candidate_trace_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-find-file-nix-path-changed");
    let root = unique_temp_dir("force-cache-find-file-nix-path-stale");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
    let missing_candidate = missing_root.join("subdir");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = builtins.findFile builtins.nixPath \"pkg/subdir\"; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&missing_root))
        .expect("missing search path entry configures");
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("hit search path entry configures");
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
    let initial_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_candidate),
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("missing findFile nixPath candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("hit findFile nixPath candidate fingerprint builds"),
    ];
    assert_eq!(first.impure_input_trace(), initial_trace.as_slice());
    drop(first);

    fs::create_dir_all(&missing_candidate).expect("formerly missing candidate appears");

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&missing_root))
        .expect("missing search path entry configures");
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("hit search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_changed = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_changed),
        path_bytes(&missing_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "stale persistent builtins.nixPath-backed findFile traces should fall back to ordinary forcing"
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert!(second.stats().cache_misses() > 0);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed findFile nixPath candidate fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_search_path_literal_candidate_trace_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-search-path-changed");
    let root = unique_temp_dir("force-cache-search-path-stale");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
    let missing_candidate = missing_root.join("subdir");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&missing_root))
        .expect("missing search path entry configures");
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("hit search path entry configures");
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
    let initial_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_candidate),
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("missing search path candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("hit search path candidate fingerprint builds"),
    ];
    assert_eq!(first.impure_input_trace(), initial_trace.as_slice());
    drop(first);

    fs::create_dir_all(&missing_candidate).expect("formerly missing candidate appears");

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&missing_root))
        .expect("missing search path entry configures");
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("hit search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_changed = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_changed),
        path_bytes(&missing_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "stale persistent search-path literal traces should fall back to ordinary forcing"
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert!(second.stats().cache_misses() > 0);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed search path candidate fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_lexical_search_path_literal_candidate_trace_misses_persistent_cache_after_revalidation()
{
    let persist_root = unique_temp_dir("force-cache-persistent-lexical-search-path-changed");
    let root = unique_temp_dir("force-cache-lexical-search-path-stale");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
    let missing_candidate = missing_root.join("subdir");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let __nixPath = [
           {{ prefix = \"pkg\"; path = {}; }}
           {{ prefix = \"pkg\"; path = {}; }}
         ]; in {{ a = <pkg/subdir>; }}",
        nix_string_literal(&path_source(&missing_root)),
        nix_string_literal(&path_source(&hit_root)),
    );
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source.as_str(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("lexical search-path literal force succeeds");
    assert_eq!(path_value_bytes(&first, forced), path_bytes(&hit_candidate));
    let initial_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_candidate),
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("missing lexical search path candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("hit lexical search path candidate fingerprint builds"),
    ];
    assert_eq!(first.impure_input_trace(), initial_trace.as_slice());
    drop(first);

    fs::create_dir_all(&missing_candidate).expect("formerly missing candidate appears");

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source.as_str(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_changed = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_changed),
        path_bytes(&missing_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "stale persistent lexical search-path traces should fall back to ordinary forcing"
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert!(second.stats().cache_misses() > 0);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed lexical search path candidate fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_forced_inline_thunks_ignore_untraced_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-untraced");
    let root = unique_temp_dir("force-cache-persistent-effectful-untraced-source");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut seed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    seed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    seed_options.set_persist_cache_root(&persist_root);
    let mut seed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        seed_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let seed_root = seed.eval_root().expect("attrset evaluates");
    let seed_thunk_value = {
        let attrs = seed
            .heap()
            .get_attrs(seed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = seed
            .heap()
            .get_thunk(seed_thunk_value)
            .expect("a remains a suspended thunk");
        seed.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("force-cache subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("effectful thunk has metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let payload = CachedExpressionValue::immediate(Value::bool(true)).expect("payload builds");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("untraced payload materializes");
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("trace lookup succeeds"),
        None,
        "the seeded crash-window fixture intentionally has no trace"
    );
    drop(seed);
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    options.set_persist_cache_root(&persist_root);
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced = force_attr_a(&mut eval, &ir, a);

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        eval.stats().thunks_forced(),
        1,
        "untraced impure persistent values must recompute"
    );
    assert_eq!(eval.stats().cache_hits(), 0);
    assert_eq!(eval.stats().cache_misses(), 1);

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn tombstoned_effectful_forced_inline_thunks_miss_persistent_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-tombstone");
    let root = unique_temp_dir("force-cache-persistent-effectful-tombstone-source");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut seed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    seed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    seed_options.set_persist_cache_root(&persist_root);
    let mut seed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        seed_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let seed_root = seed.eval_root().expect("attrset evaluates");
    let seed_thunk_value = {
        let attrs = seed
            .heap()
            .get_attrs(seed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = seed
            .heap()
            .get_thunk(seed_thunk_value)
            .expect("a remains a suspended thunk");
        seed.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("force-cache subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("effectful thunk has metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let payload = CachedExpressionValue::immediate(Value::bool(true)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let marker_path = path_bytes(&root.join("marker"));
    let trace_payload = persistent_path_exists_trace_payload(&marker_path, true);
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    persist
        .record_node_trace(key, value_hash, &trace_payload)
        .expect("stale trace records");
    persist
        .record_node_trace_tombstone(key)
        .expect("trace tombstone records");
    drop(seed);
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    options.set_persist_cache_root(&persist_root);
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced = force_attr_a(&mut eval, &ir, a);

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        eval.stats().thunks_forced(),
        1,
        "tombstoned impure persistent values must recompute"
    );
    assert_eq!(eval.stats().cache_hits(), 0);
    assert_eq!(eval.stats().cache_misses(), 1);

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}
