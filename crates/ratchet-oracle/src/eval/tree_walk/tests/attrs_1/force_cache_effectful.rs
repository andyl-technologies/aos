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

#[test]
fn find_file_first_class_nix_path_hits_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-first-class-find-file-nix-path-persist");
    let root = unique_temp_dir("force-cache-first-class-find-file-nix-path-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = (let f = builtins.findFile builtins.nixPath; in f \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_find_file_apply_id(&ir);
    let builtin = lookup_builtin(b"findFile").expect("findFile builtin is registered");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("first-class findFile candidate fingerprint builds"),
    ];

    let mut demand_options = TreeWalkOptions::with_eval_cache_enabled(true);
    demand_options.set_persist_cache_root(&persist_root);
    demand_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        demand_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demand_forced = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demand_forced),
        path_bytes(&hit_candidate)
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        demand.stats().force_cache_misses(),
        0,
        "the first first-class findFile demand should only record memoization policy"
    );
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("matching search path entry configures for materialization");
    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        materialize_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        path_value_bytes(&materialize, materialized),
        path_bytes(&hit_candidate)
    );
    assert_eq!(materialize.impure_input_trace(), expected_trace.as_slice());
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "the second first-class findFile demand should materialize a cold trace-backed child payload"
    );
    let child_persist_key =
        first_class_primop_persist_key_for_current_node(&mut materialize, apply_id, builtin)
            .expect("first-class findFile child persistent subject builds");
    let trace_entry = assert_persistent_find_file_trace_log_contains(
        &persist_root,
        &expected_trace,
        "first-class builtins.nixPath findFile materialization run",
    );
    assert_eq!(
        trace_entry.0, child_persist_key,
        "the materialized persistent trace should belong to the first-class findFile child call"
    );
    drop(materialize);

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

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "fresh-runtime first-class child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        second.persist_force_cache_hit_keys.as_slice(),
        &[child_persist_key],
        "fresh-runtime first-class findFile hit should load only the child-call metadata key"
    );
    assert_eq!(
        assert_persistent_find_file_trace_log_contains(
            &persist_root,
            &expected_trace,
            "fresh-runtime first-class findFile hit",
        ),
        trace_entry,
        "fresh-runtime first-class findFile hit should keep the original verifying trace live"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_first_class_explicit_list_calls_hit_and_miss_on_path_change() {
    let first_root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-first");
    let second_root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-second");
    let first_candidate = first_root.join("hit").join("subdir");
    let second_candidate = second_root.join("hit").join("subdir");
    fs::create_dir_all(&first_candidate).expect("first candidate exists");
    fs::create_dir_all(&second_candidate).expect("second candidate exists");
    let first_root = fs::canonicalize(&first_root).expect("first root canonicalizes");
    let second_root = fs::canonicalize(&second_root).expect("second root canonicalizes");
    let first_candidate = first_root.join("hit").join("subdir");
    let second_candidate = second_root.join("hit").join("subdir");
    let source = "{ a = (let f = builtins.findFile; in f [ { prefix = \"pkg\"; path = ./hit; } ] \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let first_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&first_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("first explicit-list findFile candidate fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(path_bytes(&first_root))
        .expect("first path base configures");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let first_forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        path_value_bytes(&first, first_forced),
        path_bytes(&first_candidate)
    );
    assert_eq!(first.impure_input_trace(), first_trace.as_slice());
    drop(first);

    let mut admit_options = TreeWalkOptions::new();
    admit_options
        .set_path_literal_base(path_bytes(&first_root))
        .expect("matching path base configures");
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
        path_bytes(&first_candidate)
    );
    assert!(
        admit.stats().thunks_forced() > 0,
        "the second first-class explicit-list findFile demand admits and computes the child call"
    );
    assert!(
        admit.stats().force_cache_misses() > 0,
        "the second first-class explicit-list findFile demand should materialize a child payload"
    );
    assert_eq!(admit.impure_input_trace(), first_trace.as_slice());
    drop(admit);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(path_bytes(&first_root))
        .expect("hit path base configures");
    let mut hit = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        hit_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let hit_forced = force_attr_a(&mut hit, &ir, a);
    assert_eq!(
        path_value_bytes(&hit, hit_forced),
        path_bytes(&first_candidate)
    );
    assert!(
        hit.stats().thunks_forced() > 0,
        "first-class explicit-list child-call hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(hit.stats().force_cache_hits(), 1);
    assert_eq!(hit.stats().force_cache_misses(), 0);
    assert_eq!(hit.impure_input_trace(), first_trace.as_slice());
    drop(hit);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&second_root))
        .expect("changed path base configures");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_forced = force_attr_a(&mut changed, &ir, a);
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&second_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("changed explicit-list findFile candidate fingerprint builds"),
    ];
    assert_eq!(
        path_value_bytes(&changed, changed_forced),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        changed.stats().force_cache_hits(),
        0,
        "changed explicit-list path identity must not reuse the previous first-class findFile payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(first_root).expect("first temp tree removed");
    fs::remove_dir_all(second_root).expect("second temp tree removed");
}

#[test]
fn find_file_first_class_explicit_list_hits_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-persist");
    let root = unique_temp_dir("force-cache-first-class-find-file-explicit-list-persistent-hit");
    let hit_candidate = root.join("hit").join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_candidate = root.join("hit").join("subdir");
    let source = "{ a = (let f = builtins.findFile; in f [ { prefix = \"pkg\"; path = ./hit; } ] \"pkg/subdir\"); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_find_file_apply_id(&ir);
    let builtin = lookup_builtin(b"findFile").expect("findFile builtin is registered");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("explicit-list first-class findFile candidate fingerprint builds"),
    ];

    let mut demand_options = TreeWalkOptions::with_eval_cache_enabled(true);
    demand_options.set_persist_cache_root(&persist_root);
    demand_options
        .set_path_literal_base(path_bytes(&root))
        .expect("demand path base configures");
    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        demand_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demand_forced = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        path_value_bytes(&demand, demand_forced),
        path_bytes(&hit_candidate)
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options
        .set_path_literal_base(path_bytes(&root))
        .expect("materialization path base configures");
    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        materialize_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        path_value_bytes(&materialize, materialized),
        path_bytes(&hit_candidate)
    );
    assert_eq!(materialize.impure_input_trace(), expected_trace.as_slice());
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "the second first-class explicit-list findFile demand should materialize a trace-backed child payload"
    );
    let child_persist_key =
        first_class_primop_persist_key_for_current_node(&mut materialize, apply_id, builtin)
            .expect("first-class explicit-list findFile child persistent subject builds");
    let trace_entry = assert_persistent_find_file_trace_log_contains(
        &persist_root,
        &expected_trace,
        "first-class explicit-list findFile materialization run",
    );
    assert_eq!(
        trace_entry.0, child_persist_key,
        "the materialized persistent trace should belong to the first-class explicit-list findFile child call"
    );
    materialize.advance_persist_eval_cache_run_boundary();
    drop(materialize);

    let second_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_persist_cache_root(&persist_root);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("hit path base configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        second_runtime.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert!(
        second.stats().thunks_forced() > 0,
        "fresh-runtime first-class explicit-list child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    let child_key = first_class_primop_subject_key_for_current_node(&mut second, apply_id, builtin)
        .expect("first-class explicit-list findFile child subject builds after persistent hit");
    assert_force_cache_impure_edges_match_trace(&second_runtime, child_key, &expected_trace);
    assert_eq!(
        second.persist_force_cache_hit_keys.as_slice(),
        &[trace_entry.0],
        "fresh-runtime first-class explicit-list findFile hit should load only the trace-backed metadata key"
    );
    assert_eq!(
        assert_persistent_find_file_trace_log_contains(
            &persist_root,
            &expected_trace,
            "fresh-runtime first-class explicit-list findFile hit",
        ),
        trace_entry,
        "fresh-runtime first-class explicit-list findFile hit should keep the original verifying trace live"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_first_class_explicit_list_with_captured_entries_hits_child_call() {
    let root = unique_temp_dir("force-cache-first-class-find-file-captured-list");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = format!(
        "let searchRoot = {}; in
         {{ a = (let f = builtins.findFile; in f [ {{ prefix = \"pkg\"; path = searchRoot; }} ] \"pkg/subdir\"); }}",
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
        .expect("captured first-class findFile candidate fingerprint builds"),
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
    drop(evaluator);

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
        "captured first-class explicit-list entries should not produce an enclosing whole-thunk hit"
    );
    assert_eq!(
        second.stats().force_cache_hits(),
        1,
        "the second captured first-class explicit-list demand should reuse already-recorded surrounding cache entries"
    );
    assert!(
        second.stats().force_cache_misses() > 0,
        "the second captured first-class explicit-list demand should still materialize the child-call payload"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    drop(second);

    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source.as_str(),
        cache.clone(),
    );
    let forced_third = force_attr_a(&mut third, &ir, a);
    assert_eq!(
        path_value_bytes(&third, forced_third),
        path_bytes(&hit_candidate)
    );
    assert!(
        third.stats().thunks_forced() > 0,
        "captured first-class explicit-list child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(
        third.stats().force_cache_hits(),
        1,
        "matching captured first-class explicit-list entries should hit the child-call payload"
    );
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

fn first_class_find_file_apply_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            if node.kind != IrKind::Apply {
                return None;
            }
            let IrData::Pair { first, second } = node.data else {
                return None;
            };
            let first = ir.arena.node(first)?;
            let second = ir.arena.node(second)?;
            let IrData::Symbol(symbol) = second.data else {
                return None;
            };
            (matches!(first.kind, IrKind::Apply | IrKind::LocalVar)
                && second.kind == IrKind::Str
                && ir.symbols.resolve(symbol) == Some(b"pkg/subdir".as_slice()))
            .then(|| IrId::new(index as u32))
        })
        .expect("first-class findFile final apply exists")
}

fn first_class_primop_subject_key_for_current_node(
    evaluator: &mut TreeWalk,
    id: IrId,
    builtin: Builtin,
) -> Option<DemandCacheKey> {
    let identity =
        evaluator.test_cache_first_class_primop_call_identity_for_current_node(id, builtin)?;
    let value_hashes =
        evaluator.test_first_class_primop_arg_hashes_for_current_apply(id, builtin)?;
    DemandCacheKey::for_free_vars(identity, value_hashes.iter().copied()).ok()
}

fn first_class_primop_persist_key_for_current_node(
    evaluator: &mut TreeWalk,
    id: IrId,
    builtin: Builtin,
) -> Option<PersistNodeMetadataKey> {
    let identity =
        evaluator.test_cache_first_class_primop_call_identity_for_current_node(id, builtin)?;
    let value_hashes =
        evaluator.test_first_class_primop_arg_hashes_for_current_apply(id, builtin)?;
    Some(PersistNodeMetadataKey::for_expression(
        identity,
        value_hashes.iter().copied(),
    ))
}

fn first_class_get_env_apply_id(ir: &Ir) -> IrId {
    let apply_ids = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.kind == IrKind::Apply).then(|| IrId::new(index as u32)))
        .collect::<Vec<_>>();
    assert_eq!(
        apply_ids.len(),
        1,
        "test fixture should contain exactly one first-class getEnv apply"
    );
    apply_ids[0]
}

fn first_class_get_env_child_key_for_evaluator(
    evaluator: &mut TreeWalk,
    apply_id: IrId,
) -> DemandCacheKey {
    let builtin = lookup_builtin(b"getEnv").expect("getEnv builtin is registered");
    first_class_primop_subject_key_for_current_node(evaluator, apply_id, builtin)
        .expect("first-class getEnv child-call key builds")
}

fn assert_first_class_captured_arg_hits_child_call<C, A>(
    body: &str,
    source_name: &str,
    configure_options: C,
    expected_trace: Vec<ImpureInputFingerprint>,
    assert_value: A,
) where
    C: Fn(&mut TreeWalkOptions),
    A: Fn(&Ir, &mut TreeWalk, Value),
{
    let source = format!("{{ a = {body}; }}");
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for pass in 0..3 {
        let mut options = TreeWalkOptions::new();
        configure_options(&mut options);
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            source_name,
            source.as_str(),
            cache.clone(),
        );
        let value = force_attr_a(&mut evaluator, &ir, a);
        assert_value(&ir, &mut evaluator, value);
        assert_eq!(
            evaluator.impure_input_trace(),
            expected_trace.as_slice(),
            "first-class impure child-call trace should revalidate on every run"
        );
        if pass == 0 {
            assert_eq!(
                evaluator.stats().force_cache_hits(),
                0,
                "first run should compute the first-class child call cold"
            );
            assert!(
                evaluator.stats().force_cache_misses() > 0,
                "first run should record a cold first-class child-call miss"
            );
        } else if pass == 2 {
            assert!(
                evaluator.stats().thunks_forced() > 0,
                "the enclosing attr thunk must still evaluate when the child call hits"
            );
            assert_single_force_cache_impure_edge_owner_matches_trace(&cache, &expected_trace);
            assert!(
                evaluator.stats().force_cache_hits() > 0,
                "warm matching first-class child call should hit"
            );
            assert_eq!(
                evaluator.stats().force_cache_misses(),
                0,
                "fully warmed first-class child call should not miss"
            );
        }
    }
}

#[test]
fn first_class_get_env_ignores_unrelated_option_identity_salts() {
    let root = unique_temp_dir("force-cache-first-class-get-env-narrow-options");
    fs::create_dir_all(&root).expect("temp root exists");
    let root = fs::canonicalize(&root).expect("temp root canonicalizes");
    let source = r#"{ a = let target = "AOS_FORCE_CACHE_FIRST_CLASS_NARROW"; f = builtins.getEnv; in f target; }"#;
    let source_name = "first-class-get-env-narrow-options.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_NARROW";
    let expected_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"shared getEnv payload"))
            .expect("getEnv fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::new();
    first_options.set_env_var(env_name.to_vec(), b"shared getEnv payload".to_vec());
    first_options
        .set_store_dir(path_bytes(&root.join("store-a")))
        .expect("store dir is absolute");
    first_options
        .set_search_path_base(path_bytes(&root.join("search-a")))
        .expect("search base is absolute");
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&root.join("nix-a")))
        .expect("nixPath entry configures");
    first_options
        .set_path_literal_base(path_bytes(&root.join("path-base-a")))
        .expect("path base is absolute");
    first_options
        .set_home_dir(path_bytes(&root.join("home-a")))
        .expect("home is absolute");
    first_options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem configures");
    first_options
        .set_current_time(1_700_000_000)
        .expect("currentTime configures");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        source_name,
        source,
        cache.clone(),
    );
    let first_value = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(first_value)
            .expect("first getEnv value is a string")
            .bytes(),
        b"shared getEnv payload"
    );
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());

    let mut warm = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        source_name,
        source,
        cache.clone(),
    );
    let warm_value = force_attr_a(&mut warm, &ir, a);
    assert_eq!(
        warm.heap()
            .get_string(warm_value)
            .expect("warm getEnv value is a string")
            .bytes(),
        b"shared getEnv payload"
    );
    assert_eq!(warm.impure_input_trace(), expected_trace.as_slice());
    assert!(
        warm.stats().force_cache_hits() > 0,
        "same-option first-class getEnv replay should hit the child-call node"
    );
    let first_key = single_force_cache_impure_edge_owner_key(&cache, &expected_trace);

    let mut changed_options = TreeWalkOptions::new();
    changed_options.set_env_var(env_name.to_vec(), b"shared getEnv payload".to_vec());
    changed_options
        .set_store_dir(path_bytes(&root.join("store-b")))
        .expect("store dir is absolute");
    changed_options
        .set_search_path_base(path_bytes(&root.join("search-b")))
        .expect("search base is absolute");
    changed_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&root.join("nix-b")))
        .expect("nixPath entry configures");
    changed_options
        .set_path_literal_base(path_bytes(&root.join("path-base-b")))
        .expect("path base is absolute");
    changed_options
        .set_home_dir(path_bytes(&root.join("home-b")))
        .expect("home is absolute");
    changed_options
        .set_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem configures");
    changed_options
        .set_current_time(1_800_000_000)
        .expect("currentTime configures");
    changed_options.set_reject_ambient_search_path(true);
    changed_options.set_reject_unconfigured_impure_builtin_constants(true);
    changed_options.set_eval_mode(EvalMode::Restricted);

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        source_name,
        source,
        cache.clone(),
    );
    let changed_value = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(changed_value)
            .expect("changed getEnv value is a string")
            .bytes(),
        b"shared getEnv payload"
    );
    assert_eq!(changed.impure_input_trace(), expected_trace.as_slice());
    let changed_key = single_force_cache_impure_edge_owner_key(&cache, &expected_trace);
    assert_eq!(
        changed_key, first_key,
        "unrelated evaluator options must not salt first-class getEnv child-call keys"
    );
    assert!(
        changed.stats().force_cache_hits() > 0,
        "matching first-class getEnv child call should hit across unrelated option changes"
    );
    assert!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("cache is enabled")
            .graph()
            .node_id_for_key(first_key)
            .is_some(),
        "shared runtime should retain the first-class getEnv child-call node under the narrow key"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_get_env_changed_environment_misses_after_revalidation() {
    let source = r#"{ a = let target = "AOS_FORCE_CACHE_FIRST_CLASS_CHANGED"; f = builtins.getEnv; in f target; }"#;
    let source_name = "first-class-get-env-changed-env.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_CHANGED";

    let mut first_options = TreeWalkOptions::new();
    first_options.set_env_var(env_name.to_vec(), b"first".to_vec());
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        source_name,
        source,
        cache.clone(),
    );
    let first_value = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(first_value)
            .expect("first getEnv value is a string")
            .bytes(),
        b"first"
    );
    let first_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"first"))
            .expect("first getEnv fingerprint builds"),
    ];
    assert_eq!(first.impure_input_trace(), first_trace.as_slice());

    let mut warm = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        source_name,
        source,
        cache.clone(),
    );
    let warm_value = force_attr_a(&mut warm, &ir, a);
    assert_eq!(
        warm.heap()
            .get_string(warm_value)
            .expect("warm getEnv value is a string")
            .bytes(),
        b"first"
    );
    assert_eq!(warm.impure_input_trace(), first_trace.as_slice());
    assert!(
        warm.stats().force_cache_hits() > 0,
        "same-env first-class getEnv replay should hit the child-call node"
    );
    let first_key = single_force_cache_impure_edge_owner_key(&cache, &first_trace);

    let mut changed_options = TreeWalkOptions::new();
    changed_options.set_env_var(env_name.to_vec(), b"second".to_vec());

    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        source_name,
        source,
        cache.clone(),
    );
    let changed_value = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(changed_value)
            .expect("changed getEnv value is a string")
            .bytes(),
        b"second"
    );
    let changed_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"second"))
            .expect("changed getEnv fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());
    let changed_key = single_force_cache_impure_edge_owner_key(&cache, &changed_trace);
    assert_eq!(
        changed_key, first_key,
        "getEnv values are revalidated impure inputs, not expression identity salts"
    );
    assert!(
        changed.stats().force_cache_misses() > 0,
        "changed getEnv input must reject the stale payload and recompute"
    );
}

#[test]
fn first_class_get_env_hits_persistent_cache_across_unrelated_option_salts() {
    let persist_root = unique_temp_dir("force-cache-first-class-get-env-persist");
    let root = unique_temp_dir("force-cache-first-class-get-env-persist-salts");
    fs::create_dir_all(&root).expect("salt root exists");
    let root = fs::canonicalize(&root).expect("salt root canonicalizes");
    let source = r#"{ a = let target = "AOS_FORCE_CACHE_FIRST_CLASS_PERSIST"; f = builtins.getEnv; in f target; }"#;
    let source_name = "first-class-get-env-persist.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_PERSIST";
    let expected_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"persistent payload"))
            .expect("persistent getEnv fingerprint builds"),
    ];

    let configure_options =
        |env_value: &[u8], suffix: &str, eval_mode: EvalMode| -> TreeWalkOptions {
            let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
            options.set_persist_cache_root(&persist_root);
            options.set_env_var(env_name.to_vec(), env_value.to_vec());
            options
                .set_store_dir(path_bytes(&root.join(format!("store-{suffix}"))))
                .expect("store dir is absolute");
            options
                .set_search_path_base(path_bytes(&root.join(format!("search-{suffix}"))))
                .expect("search base is absolute");
            options
                .add_nix_path_entry(
                    b"pkg".to_vec(),
                    path_bytes(&root.join(format!("nix-{suffix}"))),
                )
                .expect("nixPath entry configures");
            options
                .set_path_literal_base(path_bytes(&root.join(format!("path-base-{suffix}"))))
                .expect("path base is absolute");
            options
                .set_home_dir(path_bytes(&root.join(format!("home-{suffix}"))))
                .expect("home is absolute");
            options
                .set_current_system(format!("{suffix}-linux").into_bytes())
                .expect("currentSystem configures");
            options
                .set_current_time(if suffix == "a" {
                    1_700_000_000
                } else {
                    1_800_000_000
                })
                .expect("currentTime configures");
            options.set_reject_ambient_search_path(suffix != "a");
            options.set_reject_unconfigured_impure_builtin_constants(suffix != "a");
            options.set_eval_mode(eval_mode);
            options
        };

    let mut demand = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"persistent payload", "a", EvalMode::Impure),
        source_name,
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let demand_value = force_attr_a(&mut demand, &ir, a);
    assert_eq!(
        demand
            .heap()
            .get_string(demand_value)
            .expect("demand getEnv value is a string")
            .bytes(),
        b"persistent payload"
    );
    assert_eq!(demand.impure_input_trace(), expected_trace.as_slice());
    demand.advance_persist_eval_cache_run_boundary();
    drop(demand);

    let mut materialize = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"persistent payload", "a", EvalMode::Impure),
        source_name,
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let materialized = force_attr_a(&mut materialize, &ir, a);
    assert_eq!(
        materialize
            .heap()
            .get_string(materialized)
            .expect("materialized getEnv value is a string")
            .bytes(),
        b"persistent payload"
    );
    assert_eq!(materialize.impure_input_trace(), expected_trace.as_slice());
    assert!(
        materialize.stats().force_cache_misses() > 0,
        "second first-class getEnv demand should materialize a trace-backed child payload"
    );
    let trace_entry = assert_persistent_trace_log_contains(
        &persist_root,
        &expected_trace,
        "first-class getEnv materialization run",
    );
    materialize.advance_persist_eval_cache_run_boundary();
    drop(materialize);

    let hit_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut hit = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"persistent payload", "b", EvalMode::Restricted),
        source_name,
        source,
        hit_runtime.clone(),
    );
    let hit_value = force_attr_a(&mut hit, &ir, a);
    assert_eq!(
        hit.heap()
            .get_string(hit_value)
            .expect("persistent hit getEnv value is a string")
            .bytes(),
        b"persistent payload"
    );
    assert!(
        hit.stats().thunks_forced() > 0,
        "fresh-runtime first-class getEnv child hits should not imply enclosing whole-thunk hits"
    );
    assert_eq!(hit.stats().force_cache_hits(), 1);
    assert_eq!(hit.stats().force_cache_misses(), 0);
    assert_eq!(hit.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        hit.persist_force_cache_hit_keys.as_slice(),
        &[trace_entry.0],
        "fresh-runtime first-class getEnv hit should load only the child-call metadata key"
    );
    assert_eq!(
        assert_persistent_trace_log_contains(
            &persist_root,
            &expected_trace,
            "fresh-runtime first-class getEnv hit",
        ),
        trace_entry,
        "fresh-runtime first-class getEnv hit should keep the original verifying trace live"
    );
    let hit_key = single_force_cache_impure_edge_owner_key(&hit_runtime, &expected_trace);
    drop(hit);

    let changed_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        configure_options(b"changed persistent payload", "b", EvalMode::Restricted),
        source_name,
        source,
        changed_runtime.clone(),
    );
    let changed_value = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(changed_value)
            .expect("changed getEnv value is a string")
            .bytes(),
        b"changed persistent payload"
    );
    let changed_trace = vec![
        ImpureInputFingerprint::get_env(env_name, Some(b"changed persistent payload"))
            .expect("changed persistent getEnv fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());
    let changed_key = single_force_cache_impure_edge_owner_key(&changed_runtime, &changed_trace);
    assert_eq!(
        changed_key, hit_key,
        "changed getEnv values must revalidate under the same child-call identity, not miss by value-salted key"
    );
    assert_eq!(
        changed.stats().force_cache_hits(),
        0,
        "changed persistent getEnv input must reject the stale child payload"
    );
    assert!(
        changed.stats().force_cache_misses() > 0,
        "changed persistent getEnv input should recompute after stale trace rejection"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("salt temp tree removed");
}

#[test]
fn first_class_get_env_pure_mode_separates_hidden_environment_identity() {
    let source = r#"{ a = let f = builtins.getEnv; in f "AOS_FORCE_CACHE_FIRST_CLASS_PURE"; }"#;
    let source_name = "first-class-get-env-pure-mode.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let apply_id = first_class_get_env_apply_id(&ir);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_PURE";

    let mut impure_options = TreeWalkOptions::new();
    impure_options.set_env_var(env_name.to_vec(), b"visible".to_vec());
    let mut impure = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        impure_options,
        source_name,
        source,
        cache.clone(),
    );
    let impure_value = force_attr_a(&mut impure, &ir, a);
    assert_eq!(
        impure
            .heap()
            .get_string(impure_value)
            .expect("impure getEnv value is a string")
            .bytes(),
        b"visible"
    );
    let impure_key = first_class_get_env_child_key_for_evaluator(&mut impure, apply_id);

    let mut pure_options = TreeWalkOptions::new();
    pure_options.set_env_var(env_name.to_vec(), b"visible".to_vec());
    pure_options.set_eval_mode(EvalMode::Pure);
    let mut pure = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        pure_options,
        source_name,
        source,
        cache,
    );
    let pure_value = force_attr_a(&mut pure, &ir, a);
    assert_eq!(
        pure.heap()
            .get_string(pure_value)
            .expect("pure getEnv value is a string")
            .bytes(),
        b""
    );
    let pure_key = first_class_get_env_child_key_for_evaluator(&mut pure, apply_id);
    assert_ne!(
        pure_key, impure_key,
        "pure getEnv has no revalidation trace and must not share impure payload identities"
    );
    assert!(
        pure.impure_input_trace().is_empty(),
        "pure getEnv hides configured variables without recording an impure edge"
    );
    assert_eq!(
        pure.stats().force_cache_hits(),
        0,
        "pure getEnv must not replay the impure cached payload"
    );
}

fn assert_single_force_cache_impure_edge_owner_matches_trace(
    runtime: &Arc<Mutex<EvalCacheRuntime>>,
    expected_trace: &[ImpureInputFingerprint],
) {
    let _ = single_force_cache_impure_edge_owner_key(runtime, expected_trace);
}

fn single_force_cache_impure_edge_owner_key(
    runtime: &Arc<Mutex<EvalCacheRuntime>>,
    expected_trace: &[ImpureInputFingerprint],
) -> DemandCacheKey {
    assert!(
        !expected_trace.is_empty(),
        "edge-exactness assertions require at least one input leaf"
    );
    let runtime = runtime.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let graph = cache.graph();
    let expected_leaf_nodes = expected_trace
        .iter()
        .map(|fingerprint| {
            let fingerprint = fingerprint
                .as_cacheable()
                .expect("expected trace is cacheable");
            let key = DemandCacheKey::for_impure_input(fingerprint.identity().hash());
            graph.node_id_for_key(key).unwrap_or_else(|| {
                panic!(
                    "cache graph contains no leaf node for {:?} input",
                    fingerprint.kind()
                )
            })
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected_leaf_nodes.len(),
        expected_trace.len(),
        "each observed input fingerprint should map to one distinct graph leaf"
    );

    let impure_edge_owners = (0..cache.len())
        .filter_map(|index| {
            let raw = u32::try_from(index).expect("test graph has u32-addressable nodes");
            let node = DemandNodeId::new(raw);
            let dependencies = graph
                .node(node)
                .expect("node exists")
                .dependencies_in_group(DemandDependencyGroup::ImpureInput)?;
            (!dependencies.is_empty()).then(|| (node, dependencies.clone()))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        impure_edge_owners.len(),
        1,
        "a single first-class child-call node should own the impure-input edge group"
    );
    let (owner, dependencies) = &impure_edge_owners[0];
    assert_eq!(
        dependencies, &expected_leaf_nodes,
        "the first-class child call should depend on exactly the observed input leaves"
    );
    for dependency in dependencies {
        assert!(
            graph
                .node(*dependency)
                .expect("dependency exists")
                .dependents()
                .contains(owner),
            "input leaf should record the first-class child call as a reverse dependent"
        );
    }
    graph.node(*owner).expect("edge owner exists").key()
}

fn runtime_contains_node_key(runtime: &Arc<Mutex<EvalCacheRuntime>>, key: DemandCacheKey) -> bool {
    runtime
        .lock()
        .expect("cache lock is valid")
        .cache()
        .expect("cache is enabled")
        .graph()
        .node_id_for_key(key)
        .is_some()
}

fn assert_persistent_find_file_trace_log_contains(
    persist_root: &Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> (PersistNodeMetadataKey, ValueHash) {
    assert_persistent_trace_log_contains(persist_root, expected_trace, context)
}

fn assert_persistent_trace_log_contains(
    persist_root: &Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> (PersistNodeMetadataKey, ValueHash) {
    let expected = expected_cacheable_trace(expected_trace, context);
    let persist = PersistCache::open(persist_root).expect("persistent cache opens");
    let metadata_entries = persist
        .node_metadata_index()
        .latest_entries()
        .expect("persistent node metadata entries load");
    let trace_entries = persist
        .node_trace_log()
        .latest_entries()
        .expect("persistent node trace entries load");
    let live_matches = trace_entries
        .iter()
        .filter_map(|entry| {
            if entry.payload().is_tombstone() || entry.payload().inputs() != expected.as_slice() {
                return None;
            }
            let metadata_links_trace = metadata_entries.iter().any(|metadata| {
                metadata.key() == entry.key()
                    && metadata.value().materialized_value_hash() == Some(entry.value_hash())
            });
            metadata_links_trace.then_some((entry.key(), entry.value_hash()))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        live_matches.len(),
        1,
        "{context} should persist exactly one live force-cache verifying trace for the expected inputs"
    );
    live_matches[0]
}

fn expected_cacheable_trace(
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> Vec<crate::cache::CacheableInputFingerprint> {
    expected_trace
        .iter()
        .map(|input| {
            input
                .as_cacheable()
                .unwrap_or_else(|| panic!("{context} expected trace should be cacheable"))
                .clone()
        })
        .collect()
}

#[test]
fn find_file_nix_path_thunks_revalidate_candidate_edges_before_hits_and_miss_on_option_change() {
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
        .expect("findFile nixPath candidate fingerprint builds"),
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
    {
        let runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert!(
            cache.len() >= 2,
            "builtins.nixPath-backed findFile should allocate an expression node and candidate leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            1,
            "the expression node must depend on the observed builtins.nixPath findFile candidate"
        );
    }

    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&first_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable builtins.nixPath-backed findFile payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay builtins.nixPath-backed findFile candidate edges"
    );

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
        .expect("changed findFile nixPath candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&changed, forced_changed),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "changed nixPath option salt must not reuse the previous findFile payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn find_file_nix_path_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-find-file-nix-path-persist");
    let root = unique_temp_dir("force-cache-find-file-nix-path-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = builtins.findFile builtins.nixPath \"pkg/subdir\"; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("findFile nixPath candidate fingerprint builds"),
    ];

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
        .expect("findFile nixPath force succeeds");

    assert_eq!(path_value_bytes(&first, forced), path_bytes(&hit_candidate));
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
    assert!(
        first.stats().force_cache_misses() > 0,
        "the first persistent run should materialize the findFile nixPath payload"
    );
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

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable builtins.nixPath-backed findFile payloads from disk"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent hit revalidation must replay the builtins.nixPath findFile candidate edges"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_thunks_revalidate_candidate_edges_before_hits_and_miss_on_option_change() {
    let root = unique_temp_dir("force-cache-search-path-literal");
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
    let source = "{ a = <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
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
        .expect("search path candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&evaluator, forced),
        path_bytes(&first_candidate)
    );
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime.cache().expect("cache is enabled").len() >= 2,
            "search-path literal should allocate an expression node and candidate leaf"
        );
    }

    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&first_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable search-path literal payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay search-path candidate edges"
    );

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
        .expect("changed search path candidate fingerprint builds"),
    ];

    assert_eq!(
        path_value_bytes(&changed, forced_changed),
        path_bytes(&second_candidate)
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "changed nixPath option salt must not reuse the previous search-path payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn composed_search_path_literal_thunks_hit_and_miss_on_option_change() {
    let root = unique_temp_dir("force-cache-composed-search-path-literal");
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
    let source = "{ a = <pkg/subdir> == <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
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
    let first_fingerprint = ImpureInputFingerprint::path_exists_with_mode(
        &path_bytes(&first_candidate),
        ImpureInputMode::FindFileCandidate,
        true,
    )
    .expect("first search path candidate fingerprint builds");
    let expected_trace = vec![first_fingerprint.clone(), first_fingerprint];

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());

    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_root))
        .expect("matching search path entry configures");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable composed search-path payloads should hit after candidate revalidation"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay each composed search-path candidate edge"
    );

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
    let changed_fingerprint = ImpureInputFingerprint::path_exists_with_mode(
        &path_bytes(&second_candidate),
        ImpureInputMode::FindFileCandidate,
        true,
    )
    .expect("changed search path candidate fingerprint builds");
    let changed_trace = vec![changed_fingerprint.clone(), changed_fingerprint];

    assert_eq!(forced_changed.as_bool(), Ok(true));
    assert_eq!(
        changed.stats().force_cache_hits(),
        0,
        "changed nixPath option salt must not reuse the previous composed search-path payload"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn composed_search_path_literal_equality_records_exact_force_cache_graph_edges() {
    let root = unique_temp_dir("force-cache-composed-search-path-exact-edges");
    let hit_root = root.join("hit");
    let left_candidate = hit_root.join("left");
    let right_candidate = hit_root.join("right");
    fs::create_dir_all(&left_candidate).expect("left candidate exists");
    fs::create_dir_all(&right_candidate).expect("right candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let left_candidate = hit_root.join("left");
    let right_candidate = hit_root.join("right");
    let source = "{ a = <pkg/left> == <pkg/right>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&hit_root))
        .expect("search path entry configures");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&left_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("left search path candidate fingerprint builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&right_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("right search path candidate fingerprint builds"),
    ];
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );

    let (forced, owner_key) = force_attr_a_with_impure_observation_key(&mut evaluator, &ir, a);

    assert_eq!(forced.as_bool(), Ok(false));
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    assert_force_cache_impure_edges_match_trace(&cache, owner_key, &expected_trace);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn search_path_literal_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-search-path-literal-persist");
    let root = unique_temp_dir("force-cache-search-path-literal-persistent-hit");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    fs::create_dir_all(&hit_candidate).expect("hit candidate exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let hit_root = root.join("hit");
    let hit_candidate = hit_root.join("subdir");
    let source = "{ a = <pkg/subdir>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&hit_candidate),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("search path candidate fingerprint builds"),
    ];

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
        .expect("search-path literal force succeeds");
    assert_eq!(path_value_bytes(&first, forced), path_bytes(&hit_candidate));
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

    assert_eq!(
        path_value_bytes(&second, forced_again),
        path_bytes(&hit_candidate)
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable search-path literal payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

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
fn first_class_path_exists_with_captured_path_hits_child_call() {
    let root = unique_temp_dir("force-cache-first-class-path-exists-captured-path");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let source = "let marker = ./marker; f = builtins.pathExists; in f marker";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds")];

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let first_value = first.eval_root().expect("first pathExists call succeeds");
    assert_eq!(first_value.as_bool(), Ok(true));
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        first.stats().force_cache_hits(),
        0,
        "the first captured pathExists demand should be a cold child-call evaluation"
    );
    assert!(
        first.stats().force_cache_misses() > 0,
        "the first captured pathExists demand should record a cold cache miss"
    );
    drop(first);

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
    let second_value = second.eval_root().expect("second pathExists call succeeds");
    assert_eq!(second_value.as_bool(), Ok(true));
    assert_eq!(
        second.stats().force_cache_hits(),
        1,
        "the second captured pathExists demand should reuse already-recorded surrounding cache entries"
    );
    assert!(
        second.stats().force_cache_misses() > 0,
        "the second captured pathExists demand should materialize the child-call payload"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    drop(second);

    let mut third_options = TreeWalkOptions::new();
    third_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let third_value = third.eval_root().expect("third pathExists call succeeds");
    assert_eq!(third_value.as_bool(), Ok(true));
    assert!(
        third.stats().force_cache_hits() > 0,
        "matching captured path aliases should hit cached force-cache payloads"
    );
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.impure_input_trace(), expected_trace.as_slice());
    drop(third);

    fs::remove_file(root.join("marker")).expect("marker removed");

    let changed_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, false).expect("fingerprint builds")];
    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache,
    );
    let changed_value = changed
        .eval_root()
        .expect("changed pathExists call succeeds");
    assert_eq!(changed_value.as_bool(), Ok(false));
    assert!(
        changed.stats().force_cache_misses() > 0,
        "stale captured pathExists traces should miss and recompute"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_hash_file_with_captured_algorithm_and_path_hits_child_call() {
    let root = unique_temp_dir("force-cache-first-class-hash-file-captured-args");
    fs::write(root.join("target"), b"hash file payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = r#"let
        algorithm = "sha256";
        target = ./target;
        f = builtins.hashFile;
      in f algorithm target"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_hash = b"4ae6266cc082134ea87e6fbf8b747c078f4e6d42f44179b8936f61a524133982";
    let expected_trace = vec![
        ImpureInputFingerprint::hash_file(&target_path, b"hash file payload")
            .expect("fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let first_value = first.eval_root().expect("first hashFile call succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(first_value)
            .expect("hashFile result is a string")
            .bytes(),
        expected_hash
    );
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        first.stats().force_cache_hits(),
        0,
        "the first captured hashFile demand should be a cold child-call evaluation"
    );
    assert!(
        first.stats().force_cache_misses() > 0,
        "the first captured hashFile demand should record cold cache misses"
    );
    drop(first);

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
    let second_value = second.eval_root().expect("second hashFile call succeeds");
    assert_eq!(
        second
            .heap()
            .get_string(second_value)
            .expect("hashFile result is a string")
            .bytes(),
        expected_hash
    );
    assert!(
        second.stats().force_cache_hits() > 0,
        "the second captured hashFile demand should reuse already-recorded surrounding cache entries"
    );
    assert!(
        second.stats().force_cache_misses() > 0,
        "the second captured hashFile demand should materialize the child-call payload"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    drop(second);

    let mut third_options = TreeWalkOptions::new();
    third_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "default.nix",
        source,
        cache,
    );
    let third_value = third.eval_root().expect("third hashFile call succeeds");
    assert_eq!(
        third
            .heap()
            .get_string(third_value)
            .expect("hashFile result is a string")
            .bytes(),
        expected_hash
    );
    assert!(
        third.stats().force_cache_hits() > 0,
        "matching captured hashFile args should hit cached force-cache payloads"
    );
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_unary_import_and_file_builtins_with_captured_args_hit_child_calls() {
    let root = unique_temp_dir("force-cache-first-class-unary-captured-args");
    fs::write(root.join("dep.nix"), b"7").expect("import source writes");
    fs::write(root.join("target"), b"read file payload").expect("target writes");
    fs::create_dir(root.join("dir")).expect("readDir directory creates");
    fs::write(root.join("dir").join("alpha"), b"entry").expect("readDir entry writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&root.join("dep.nix"));
    let target_path = path_bytes(&root.join("target"));
    let dir_path = path_bytes(&root.join("dir"));

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./dep.nix; f = import; in f target",
        "first-class-import-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![ImpureInputFingerprint::import(&dep_path, b"7").expect("import fingerprint builds")],
        |_, _, value| assert_eq!(value.as_int(), Ok(7)),
    );

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./target; f = builtins.readFile; in f target",
        "first-class-read-file-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![
            ImpureInputFingerprint::read_file(&target_path, b"read file payload")
                .expect("readFile fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("readFile result is a string")
                    .bytes(),
                b"read file payload"
            );
        },
    );

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./target; f = builtins.readFileType; in f target",
        "first-class-read-file-type-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![
            ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
                .expect("readFileType fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("readFileType result is a string")
                    .bytes(),
                b"regular"
            );
        },
    );

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./dir; f = builtins.readDir; in f target",
        "first-class-read-dir-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![
            ImpureInputFingerprint::read_dir(
                &dir_path,
                [DirEntryInput::new(b"alpha", FileTypeForInput::Regular)],
            )
            .expect("readDir fingerprint builds"),
        ],
        |_, evaluator, value| {
            let alpha = evaluator.symbols.intern(b"alpha").expect("alpha interns");
            let attrs = evaluator
                .heap()
                .get_attrs(value)
                .expect("readDir result is an attrset");
            let alpha_value = attrs.get(alpha).expect("alpha entry exists");
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(alpha_value)
                    .expect("alpha entry is a string")
                    .bytes(),
                b"regular"
            );
        },
    );

    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_CAPTURED_ARG";
    assert_first_class_captured_arg_hits_child_call(
        r#"let target = "AOS_FORCE_CACHE_FIRST_CLASS_CAPTURED_ARG"; f = builtins.getEnv; in f target"#,
        "first-class-get-env-captured-arg.nix",
        |options| {
            options.set_env_var(env_name.to_vec(), b"env payload".to_vec());
        },
        vec![
            ImpureInputFingerprint::get_env(env_name, Some(b"env payload"))
                .expect("getEnv fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("getEnv result is a string")
                    .bytes(),
                b"env payload"
            );
        },
    );

    let formal_env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_FORMAL_ARG";
    assert_first_class_captured_arg_hits_child_call(
        r#"({ target }: let f = builtins.getEnv; in f target)
          (builtins.fromJSON ''{"target":"AOS_FORCE_CACHE_FIRST_CLASS_FORMAL_ARG"}'')"#,
        "first-class-get-env-captured-formal-arg.nix",
        |options| {
            options.set_env_var(formal_env_name.to_vec(), b"formal env payload".to_vec());
        },
        vec![
            ImpureInputFingerprint::get_env(formal_env_name, Some(b"formal env payload"))
                .expect("formal getEnv fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("formal getEnv result is a string")
                    .bytes(),
                b"formal env payload"
            );
        },
    );

    let preforced_env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_PREFORCED_ARG";
    assert_first_class_captured_arg_hits_child_call(
        r#"let
          target = "AOS_FORCE_CACHE_FIRST_CLASS_PREFORCED_ARG";
          f = builtins.getEnv;
        in builtins.seq target (f target)"#,
        "first-class-get-env-captured-preforced-arg.nix",
        |options| {
            options.set_env_var(
                preforced_env_name.to_vec(),
                b"preforced env payload".to_vec(),
            );
        },
        vec![
            ImpureInputFingerprint::get_env(preforced_env_name, Some(b"preforced env payload"))
                .expect("preforced getEnv fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("preforced getEnv result is a string")
                    .bytes(),
                b"preforced env payload"
            );
        },
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
fn dirty_persistent_effectful_force_cache_hit_counts_early_cutoff() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-dirty-cutoff");
    let root = unique_temp_dir("force-cache-persistent-effectful-dirty");
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

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut prime_options = TreeWalkOptions::with_eval_cache_enabled(true);
    prime_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut prime = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        prime_options,
        "default.nix",
        source,
        shared_runtime.clone(),
    );
    let (primed, subject) = force_attr_a_with_impure_observation_subject(&mut prime, &ir, a);
    assert_eq!(primed.as_bool(), Ok(true));
    let identity = subject
        .lookup_identity
        .expect("trace-backed attr has a lookup identity");
    let owner_key =
        DemandCacheKey::for_free_vars(identity, subject.free_var_value_hashes.iter().copied())
            .expect("owner key builds");
    {
        let mut runtime = shared_runtime.lock().expect("cache lock is valid");
        assert_eq!(
            runtime
                .invalidate_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied()
                )
                .expect("payload invalidates"),
            Some(true)
        );
        let cache = runtime.cache().expect("cache is enabled");
        let owner = cache
            .graph()
            .node_id_for_key(owner_key)
            .expect("forced expression node remains");
        assert_eq!(
            cache
                .graph()
                .node(owner)
                .expect("owner node exists")
                .freshness(),
            crate::cache::NodeFreshness::Dirty
        );
    }
    drop(prime);

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
        shared_runtime,
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "persistent hit should replay without forcing the thunk body"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(
        second.stats().early_cutoffs(),
        1,
        "persistent hit runtime seeding should count same-hash dirty cutoff"
    );
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(&persist_root).expect("persistent temp tree removed");
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
