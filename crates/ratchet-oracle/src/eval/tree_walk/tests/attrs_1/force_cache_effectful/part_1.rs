//! Split-out tests (part_1). See parent module.

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
    assert_eq!(second.stats().force_cache_hits(), 1);
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
fn find_file_explicit_list_with_captured_entries_hits_whole_thunk() {
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
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable captured explicit-list entries should hit the whole-thunk payload"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_lexical_nix_path_thunks_revalidate_candidate_edges_before_hits() {
    let root = unique_temp_dir("force-cache-find-file-lexical-nix-path");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let __nixPath = [ {{ prefix = \"pkg\"; path = {}; }} ]; in
         {{ a = builtins.findFile __nixPath \"pkg/subdir\"; }}",
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
        .expect("lexical nixPath candidate fingerprint builds"),
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
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable lexical __nixPath findFile payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_lexical_nix_path_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-find-file-lexical-nix-path-persist");
    let root = unique_temp_dir("force-cache-find-file-lexical-nix-path-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let __nixPath = [ {{ prefix = \"pkg\"; path = {}; }} ]; in
         {{ a = builtins.findFile __nixPath \"pkg/subdir\"; }}",
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
        .expect("lexical nixPath candidate fingerprint builds"),
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
        .expect("lexical findFile force succeeds");
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
        "fresh runtimes should rehydrate stable lexical findFile payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_first_class_nix_path_calls_hit_and_miss_on_option_change() {
    let root = unique_temp_dir("force-cache-find-file-first-class-nix-path");
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
    let source = "{ a = (let f = builtins.findFile builtins.nixPath; in f \"pkg/subdir\"); }";
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_find_file_apply_id(&ir);
    let builtin = lookup_builtin(b"findFile").expect("findFile builtin is registered");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("search path entry configures");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&first_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("first-class findFile candidate fingerprint builds"),
    ];

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);

    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&first_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());

    let mut admit_options = TreeWalkOptions::new();
    admit_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures");
    let mut admit = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        admit_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_for_write = force_attr_a(&mut admit, &ir, a);

    assert_eq!(
        path_value_bytes(&admit, forced_for_write),
        path_bytes(&first_candidate)
    );
    assert!(
        admit.stats().thunks_forced() > 0,
        "the second first-class findFile demand admits and computes the child call"
    );
    assert_eq!(admit.stats().cache_hits(), 0);
    assert_eq!(admit.stats().force_cache_misses(), 2);
    assert_eq!(admit.impure_input_trace(), expected_trace.as_slice());
    let child_key = first_class_primop_subject_key_for_current_node(&mut admit, apply_id, builtin)
        .expect("first-class findFile child subject builds");
    assert!(
        runtime_contains_node_key(&cache, child_key),
        "the admitted first-class findFile child call should have a runtime node"
    );

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures for hit");
    let mut hit = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        hit_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut hit, &ir, a);

    assert_eq!(
        path_value_bytes(&hit, forced_again),
        path_bytes(&first_candidate)
    );
    assert!(
        hit.stats().thunks_forced() > 0,
        "first-class findFile child-call hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(hit.stats().force_cache_hits(), 1);
    assert_eq!(hit.stats().force_cache_misses(), 0);
    assert_eq!(hit.impure_input_trace(), expected_trace.as_slice());

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_root))
        .expect("changed search path entry configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_changed = force_attr_a(&mut changed, &ir, a);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&second_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed first-class findFile candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&changed, forced_changed),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        changed.stats().force_cache_hits(),
        0,
        "changed nixPath argument hash must not reuse the previous first-class findFile payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_first_class_nix_path_records_exact_force_cache_graph_edges() {
    let root = unique_temp_dir("force-cache-find-file-first-class-nix-path-edge-exactness");
    let missing_root = root.join("missing");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&missing_root).expect("missing search root exists");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = (let f = builtins.findFile builtins.nixPath; in f \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_find_file_apply_id(&ir);
    let builtin = lookup_builtin(b"findFile").expect("findFile builtin is registered");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_root.join("subdir")),
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("missing first-class findFile candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("hit first-class findFile candidate fingerprint builds"),
    ];

    let mut demand_options = TreeWalkOptions::new();
    demand_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&missing_root))
        .expect("missing search path entry configures");
    demand_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("hit search path entry configures");
    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        demand_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let demanded = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demanded),
        path_bytes(&hit_candidate)
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    drop(demand);

    let mut admit_options = TreeWalkOptions::new();
    admit_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&missing_root))
        .expect("matching missing search path entry configures");
    admit_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching hit search path entry configures");
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
        path_bytes(&hit_candidate)
    );
    assert_eq!(admit.impure_input_trace(), expected_trace.as_slice());
    let child_key = first_class_primop_subject_key_for_current_node(&mut admit, apply_id, builtin)
        .expect("first-class findFile child subject builds");
    assert_force_cache_impure_edges_match_trace(&cache, child_key, &expected_trace);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_first_class_explicit_list_records_exact_force_cache_graph_edges() {
    let root = unique_temp_dir("force-cache-find-file-first-class-explicit-list-edge-exactness");
    let missing_root = root.join("missing");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&missing_root).expect("missing search root exists");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let missing_root = root.join("missing");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = (let f = builtins.findFile; in f [ { prefix = \"pkg\"; path = ./missing; } { prefix = \"pkg\"; path = ./hit; } ] \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_find_file_apply_id(&ir);
    let builtin = lookup_builtin(b"findFile").expect("findFile builtin is registered");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&missing_root.join("subdir")),
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("missing explicit-list first-class findFile candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("hit explicit-list first-class findFile candidate fingerprint builds"),
    ];

    let mut demand_options = TreeWalkOptions::new();
    demand_options
        .set_path_literal_base(path_bytes(&root))
        .expect("demand path base configures");
    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        demand_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let demanded = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demanded),
        path_bytes(&hit_candidate)
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    drop(demand);

    let mut admit_options = TreeWalkOptions::new();
    admit_options
        .set_path_literal_base(path_bytes(&root))
        .expect("admission path base configures");
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
        path_bytes(&hit_candidate)
    );
    assert_eq!(admit.impure_input_trace(), expected_trace.as_slice());
    let child_key = first_class_primop_subject_key_for_current_node(&mut admit, apply_id, builtin)
        .expect("first-class explicit-list findFile child subject builds");
    assert_force_cache_impure_edges_match_trace(&cache, child_key, &expected_trace);

    fs::remove_dir_all(root).expect("temp tree removed");
}
