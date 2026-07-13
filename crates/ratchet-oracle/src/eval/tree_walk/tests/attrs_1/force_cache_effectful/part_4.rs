//! Split-out tests (part_4). See parent module.

use super::*;

#[test]
fn composed_search_path_literal_thunks_hit_from_persistent_cache() {
    let persist_root = unique_temp_dir("force-cache-composed-search-path-literal-persist");
    let root = unique_temp_dir("force-cache-composed-search-path-literal-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = <pkg/subdir> == <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let hit_fingerprint = ImpureInputFingerprint::path_exists_with_mode(
        &path_bytes(&hit_candidate),
        ImpureInputMode::FindFileCandidate,
        true,
    )
    .expect("search path candidate fingerprint builds");
    let expected_trace = vec![hit_fingerprint.clone(), hit_fingerprint];

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
        .expect("composed search-path literal force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
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

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable composed search-path payloads from disk"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_with_lexical_nix_path_revalidates_candidate_edges_before_hits() {
    let root = unique_temp_dir("force-cache-search-path-lexical");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let __nixPath = [ {{ prefix = \"pkg\"; path = {}; }} ]; in
         {{ a = <pkg/subdir>; }}",
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
        .expect("lexical search path candidate fingerprint builds"),
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

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache,
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable lexical __nixPath search-path literal payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_with_lexical_nix_path_hits_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-search-path-lexical-persist");
    let root = unique_temp_dir("force-cache-search-path-lexical-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let __nixPath = [ {{ prefix = \"pkg\"; path = {}; }} ]; in
         {{ a = <pkg/subdir>; }}",
        nix_string_literal(&path_source(&hit_root)),
    );
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("lexical search path candidate fingerprint builds"),
    ];

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
    drop(first);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source.as_str(),
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
        "fresh runtimes should rehydrate stable lexical search-path payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_with_captured_lexical_nix_path_uses_free_variable_hashes() {
    let root = unique_temp_dir("force-cache-search-path-lexical-captured");
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
    let source = format!(
        "let f = root:
           let __nixPath = [ {{ prefix = \"pkg\"; path = root; }} ];
           in {{ a = <pkg/subdir>; }};
         in [ (f {}).a (f {}).a (f {}).a ]",
        nix_string_literal(&path_source(&first_root)),
        nix_string_literal(&path_source(&second_root)),
        nix_string_literal(&path_source(&first_root)),
    );
    let ir = lower(&source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache,
    );
    let root_value = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root_value)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
            list.get(2).expect("third result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured lexical search-path force succeeds");
    assert_eq!(
        path_value_bytes(&evaluator, first),
        path_bytes(&first_candidate)
    );
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured lexical search-path force succeeds");
    assert_eq!(
        path_value_bytes(&evaluator, second),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        evaluator.stats().force_cache_hits(),
        0,
        "different captured lexical search-path values must not false-hit"
    );

    let hits_before = evaluator.stats().force_cache_hits();
    let third = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[2])
        .expect("third captured lexical search-path force succeeds");
    assert_eq!(
        path_value_bytes(&evaluator, third),
        path_bytes(&first_candidate)
    );
    assert!(
        evaluator.stats().cache_hits() > hits_before,
        "matching captured lexical search-path values should reuse the prior payload"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn composed_search_path_literal_with_captured_lexical_nix_path_uses_free_variable_hashes() {
    let root = unique_temp_dir("force-cache-composed-search-path-lexical-captured");
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
    let source = format!(
        "let f = root:
           let __nixPath = [ {{ prefix = \"pkg\"; path = root; }} ];
           in {{ a = <pkg/subdir> == <pkg/subdir>; }};
         in [ (f {}).a (f {}).a (f {}).a ]",
        nix_string_literal(&path_source(&first_root)),
        nix_string_literal(&path_source(&second_root)),
        nix_string_literal(&path_source(&first_root)),
    );
    let ir = lower(&source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache,
    );
    let root_value = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root_value)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
            list.get(2).expect("third result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured lexical search-path equality force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    assert_eq!(
        evaluator.impure_input_trace(),
        vec![
            ImpureInputFingerprint::path_exists_with_mode(
                &path_bytes(&first_candidate),
                ImpureInputMode::FindFileCandidate,
                true,
            )
            .expect("first candidate fingerprint builds"),
            ImpureInputFingerprint::path_exists_with_mode(
                &path_bytes(&first_candidate),
                ImpureInputMode::FindFileCandidate,
                true,
            )
            .expect("first repeated candidate fingerprint builds"),
        ]
        .as_slice()
    );
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured lexical search-path equality force succeeds");
    assert_eq!(second.as_bool(), Ok(true));
    assert_eq!(
        evaluator.stats().force_cache_hits(),
        0,
        "different captured lexical search-path values must not false-hit"
    );

    let hits_before = evaluator.stats().force_cache_hits();
    let third = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[2])
        .expect("third captured lexical search-path equality force succeeds");
    assert_eq!(third.as_bool(), Ok(true));
    assert!(
        evaluator.stats().force_cache_hits() > hits_before,
        "matching captured lexical search-path values should reuse the prior composed payload"
    );
    let second_fingerprint = ImpureInputFingerprint::path_exists_with_mode(
        &path_bytes(&second_candidate),
        ImpureInputMode::FindFileCandidate,
        true,
    )
    .expect("second candidate fingerprint builds");
    assert!(
        evaluator.impure_input_trace().contains(&second_fingerprint),
        "changed captured lexical search-path value should evaluate against the second root"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_with_unhashable_lexical_nix_path_waits_for_free_variable_payload() {
    let root = unique_temp_dir("force-cache-search-path-lexical-unhashable");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let path_file = root.join("path.txt");
    fs::write(&path_file, path_bytes(&hit_root)).expect("path source exists");
    let source = r#"let __nixPath = [
        { prefix = "pkg"; path = builtins.readFile ./path.txt; }
    ]; in { a = <pkg/subdir>; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&path_bytes(&path_file), &path_bytes(&hit_root))
            .expect("readFile fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("lexical search path candidate fingerprint builds"),
    ];

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
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
    };
    assert!(
        subject.is_none(),
        "computed lexical search-path payloads must not build a force-cache subject"
    );
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");

    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&hit_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache,
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "lexical search-path values with computed payloads remain outside whole-thunk hit coverage"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn composed_search_path_literal_with_unhashable_lexical_nix_path_waits_for_free_variable_payload() {
    let root = unique_temp_dir("force-cache-composed-search-path-lexical-unhashable");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let path_file = root.join("path.txt");
    fs::write(&path_file, path_bytes(&hit_root)).expect("path source exists");
    let source = r#"let __nixPath = [
        { prefix = "pkg"; path = builtins.readFile ./path.txt; }
    ]; in { a = <pkg/subdir> == <pkg/subdir>; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&path_bytes(&path_file), &path_bytes(&hit_root))
            .expect("readFile fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("lexical search path candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("lexical repeated search path candidate fingerprint builds"),
    ];

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
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
    };
    assert!(
        subject.is_none(),
        "computed lexical search-path payloads must not build a composed force-cache subject"
    );
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache,
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert!(
        second.stats().thunks_forced() > 0,
        "composed lexical search-path values with computed payloads remain outside whole-thunk hit coverage"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn dirty_effectful_force_cache_hit_revalidates_and_counts_early_cutoff() {
    let root = unique_temp_dir("force-cache-effectful-dirty-cutoff");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let (forced, owner_key) = force_attr_a_with_impure_observation_key(&mut evaluator, &ir, a);
    assert_eq!(forced.as_bool(), Ok(true));

    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache_mut().expect("cache is enabled");
        let owner = cache
            .graph()
            .node_id_for_key(owner_key)
            .expect("forced expression node exists");
        cache
            .test_mark_dirty_node(owner)
            .expect("forced expression node marks dirty");
    }

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let (forced_again, second_owner_key) =
        force_attr_a_with_impure_observation_key(&mut second, &ir, a);

    assert_eq!(second_owner_key, owner_key);
    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "dirty same-input trace-backed payload should replay after revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().early_cutoffs(), 1);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_primop_child_misses_record_memo_read_edges() {
    let root = unique_temp_dir("force-cache-effectful-cold-memo-read");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "({ f = builtins.pathExists; }).f ./marker";
    let ir = lower(source);
    assert_eq!(
        ir.arena.node(ir.root).expect("root exists").kind,
        IrKind::Apply,
        "root is a first-class pathExists application"
    );
    let apply_id = ir.root;
    let path_id = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .find_map(|(index, node)| (node.kind == IrKind::Path).then(|| IrId::new(index as u32)))
        .expect("path literal is lowered");
    let builtin = lookup_builtin(b"pathExists").expect("pathExists builtin is registered");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let parent_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"effectful-primop-cold-memo-read-parent",
        )),
        IrId::new(1),
    );
    let parent_subject = ForceCacheSubject {
        lookup_identity: Some(parent_identity),
        pure_observation_identity: Some(parent_identity),
        impure_observation_identity: Some(parent_identity),
        metadata_identity: Some(parent_identity),
        persistent_clear_identity: Some(parent_identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    };

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let path_value = evaluator
        .eval_node(path_id)
        .expect("path argument evaluates");
    let path_hash = evaluator
        .force_cache_free_var_value_hash(path_value)
        .expect("path argument hashes for force-cache key");
    let primop_identity = evaluator
        .test_cache_first_class_primop_call_identity_for_current_node(apply_id, builtin)
        .expect("pathExists force-cache identity builds");
    let primop_subject = ForceCacheSubject {
        lookup_identity: Some(primop_identity),
        pure_observation_identity: None,
        impure_observation_identity: Some(primop_identity),
        metadata_identity: Some(primop_identity),
        persistent_clear_identity: Some(primop_identity),
        free_var_value_hashes: vec![path_hash],
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    evaluator.record_force_cache_memoization_demand(&primop_subject);
    evaluator.record_force_cache_memoization_demand(&primop_subject);
    let parent_node = evaluator
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");

    evaluator
        .active_memo_read_nodes
        .push(ActiveMemoReadNode::new(parent_node));
    let forced = evaluator
        .eval_node(apply_id)
        .expect("first-class pathExists call succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    let active = evaluator
        .active_memo_read_nodes
        .pop()
        .expect("test-controlled active node pops");
    assert_eq!(
        active.node(),
        parent_node,
        "test-controlled active node stack should be balanced"
    );
    evaluator.replace_active_memo_reads(active);

    let primop_key = crate::cache::DemandCacheKey::for_free_vars(
        primop_identity,
        primop_subject.free_var_value_hashes.iter().copied(),
    )
    .expect("pathExists runtime key builds");
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let primop_node = cache
        .graph()
        .node_id_for_key(primop_key)
        .expect("pathExists miss should allocate a runtime node");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    assert!(
        parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .expect("parent has memo-read edges")
            .contains(&primop_node),
        "a cold admitted pathExists call should become a memo-read dependency of its active parent"
    );
    let primop = cache
        .graph()
        .node(primop_node)
        .expect("pathExists node is present");
    assert!(
        primop.dependents().contains(&parent_node),
        "the primop node should record the active parent as a reverse dependent"
    );
    assert_eq!(
        primop
            .dependencies_in_group(crate::cache::DemandDependencyGroup::ImpureInput)
            .expect("pathExists has impure-input edges")
            .len(),
        1,
        "the pathExists expression should still depend on its observed input leaf"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

