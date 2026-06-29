//! Force-cache revalidation tests for pathExists attr thunks.

use super::*;

#[test]
fn effectful_forced_inline_thunks_revalidate_impure_edges_before_hits() {
    let root = unique_temp_dir("force-cache-effectful");
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
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    {
        let runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert_eq!(
            cache.len(),
            2,
            "pathExists force results now create an expression node and input leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            1,
            "the expression node must depend on the observed pathExists leaf"
        );
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
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_again = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("second force revalidates and hits");

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable effectful memo payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must remain visible to enclosing force traces"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_forced_inline_thunks_revalidate_candidate_edges_before_hits() {
    let root = unique_temp_dir("force-cache-find-file");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
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
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_root.join("subdir")),
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("missing findFile candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("hit findFile candidate fingerprint builds"),
    ];

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache.clone(),
    );
    let (forced, owner_key) = force_attr_a_with_impure_observation_key(&mut evaluator, &ir, a);

    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&hit_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    {
        let runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert!(
            cache.len() >= 3,
            "findFile force results now create an expression node and candidate input leaves"
        );
    }
    assert_force_cache_impure_edges_match_trace(&cache, owner_key, &expected_trace);

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
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable findFile payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay the findFile candidate edges"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_forced_inline_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-find-file-hit");
    let root = unique_temp_dir("force-cache-find-file-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
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
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_root.join("subdir")),
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("missing findFile candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("hit findFile candidate fingerprint builds"),
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
        .expect("findFile force succeeds");
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
        "fresh runtimes should rehydrate stable findFile payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent hit revalidation must replay the findFile candidate edges"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_explicit_list_with_captured_entries_waits_for_whole_thunk_hit() {
    let root = unique_temp_dir("force-cache-find-file-captured-list");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let searchRoot = {}; in
         {{ a = builtins.findFile [ {{ prefix = \"pkg\"; path = searchRoot; }} ] \"pkg/subdir\"; }}",
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
        .expect("captured findFile candidate fingerprint builds"),
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
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "captured explicit-list entries are still outside whole-thunk hit coverage"
    );
    assert!(second.stats().cache_misses() > 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_nix_path_thunks_wait_for_search_path_option_identity() {
    let persist_root = unique_temp_dir("force-cache-find-file-nix-path-persist");
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

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
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
        .expect("findFile nixPath candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&first_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    drop(evaluator);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_root))
        .expect("changed search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&second_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed findFile nixPath candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&second_candidate)
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert_eq!(second.impure_input_trace(), changed_trace.as_slice());
    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime.cache().expect("cache is enabled").is_empty(),
            "builtins.nixPath-backed findFile waits for search-path option identity"
        );
    }
    assert_persistent_force_cache_has_no_live_traces(
        &persist_root,
        "builtins.nixPath-backed findFile",
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
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
        DurableBlake3Hash::for_bytes(b"effectful-primop-cold-memo-read-parent"),
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

#[test]
fn changed_effectful_forced_inline_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-effectful-changed");
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
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("thunk force succeeds")
            .as_bool(),
        Ok(true)
    );

    fs::remove_file(root.join("marker")).expect("marker removed");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed force recomputes");

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_forced_inline_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-hit");
    let root = unique_temp_dir("force-cache-persistent-effectful");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let parent_identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"persistent-effectful-memo-read-parent"),
        IrId::new(9),
    );
    let parent_subject = ForceCacheSubject {
        lookup_identity: Some(parent_identity),
        pure_observation_identity: Some(parent_identity),
        impure_observation_identity: Some(parent_identity),
        metadata_identity: Some(parent_identity),
        persistent_clear_identity: Some(parent_identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    };

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
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
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
        shared_runtime.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let parent_node = second
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");
    second
        .active_memo_read_nodes
        .push(ActiveMemoReadNode::new(parent_node));
    let forced_again = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("persistent effectful hit succeeds");
    let active = second
        .active_memo_read_nodes
        .pop()
        .expect("test-controlled active node pops");
    assert_eq!(
        active.node(),
        parent_node,
        "test-controlled active node stack should be balanced"
    );
    second.replace_active_memo_reads(active);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable effectful payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent hit revalidation must remain visible to enclosing force traces"
    );
    drop(second);

    {
        let runtime = shared_runtime.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert_eq!(
            cache.len(),
            3,
            "persistent hits should seed the active parent, child expression node, and input leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            2,
            "the active parent depends on the child expression, which keeps its revalidated input edge"
        );
        let parent = cache
            .graph()
            .node(parent_node)
            .expect("parent node is present");
        let child_node = *parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .expect("parent has memo-read edges")
            .iter()
            .next()
            .expect("memo-read edge exists");
        assert!(parent.dependencies().contains(&child_node));
        let child = cache
            .graph()
            .node(child_node)
            .expect("child node is present");
        assert!(
            child
                .dependencies_in_group(crate::cache::DemandDependencyGroup::ImpureInput)
                .expect("child has impure-input edges")
                .iter()
                .next()
                .is_some(),
            "trace-backed persistent hit should preserve the revalidated impure-input edge"
        );
        assert!(child.dependents().contains(&parent_node));
    }

    fs::remove_dir_all(&persist_root).expect("persistent temp tree removed");

    let mut third_options = TreeWalkOptions::with_eval_cache_enabled(true);
    third_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "default.nix",
        source,
        shared_runtime,
    );
    let forced_from_memory = force_attr_a(&mut third, &ir, a);

    assert_eq!(forced_from_memory.as_bool(), Ok(true));
    assert_eq!(
        third.stats().thunks_forced(),
        0,
        "persistent-hit runtime seeding should allow later in-memory reuse"
    );
    assert_eq!(third.stats().cache_hits(), 1);
    assert_eq!(third.stats().cache_misses(), 0);
    assert_eq!(
        third.impure_input_trace(),
        expected_trace.as_slice(),
        "seeded runtime hits must still revalidate into the enclosing trace"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_effectful_forced_inline_thunks_miss_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-changed");
    let root = unique_temp_dir("force-cache-persistent-effectful-stale");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
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
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    drop(first);

    fs::remove_file(root.join("marker")).expect("marker removed");

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
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_changed = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(
        second.stats().thunks_forced(),
        1,
        "stale persistent traces should fall back to ordinary forcing"
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert_eq!(second.stats().cache_misses(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), false)
            .expect("fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

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
