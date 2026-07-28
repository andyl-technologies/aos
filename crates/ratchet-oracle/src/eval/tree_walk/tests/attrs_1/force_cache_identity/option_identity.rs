//! Tree-walk option coverage for force-cache identities.

use super::*;

#[test]
fn source_backed_forced_inline_thunks_include_nix_compat_profile_in_cache_identity() {
    let first_options = TreeWalkOptions::new();
    let mut second_options = first_options.clone();
    second_options.set_nix_compat_profile(NixCompatProfile::Nix2_34_8);

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different Nix compatibility profiles must not reuse one demand node",
    );
}

#[test]
fn source_backed_forced_inline_thunks_include_reported_nix_version_in_cache_identity() {
    let first_options = TreeWalkOptions::new();
    let mut second_options = first_options.clone();
    second_options
        .set_reported_nix_version(b"2.24.12-custom".to_vec())
        .expect("non-empty reported version configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different reported Nix versions must not reuse one demand node",
    );
}

#[test]
fn source_backed_force_cache_identities_include_node_span() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let (first_identity, body) = force_cache_identity_for_attr_a(&ir, source);

    let mut shifted = ir.clone();
    let mut nodes = shifted.arena.nodes().to_vec();
    nodes[body.index()].span = Span::new(100, 104);
    shifted.arena = IrArena::from_raw_parts(nodes, shifted.arena.child_pool().to_vec());
    let (shifted_identity, shifted_body) = force_cache_identity_for_attr_a(&shifted, source);

    assert_eq!(shifted_body, body);
    assert_ne!(
        shifted_identity, first_identity,
        "same source bytes and IR node id under a different node span must not reuse one demand node"
    );

    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &shifted,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &shifted, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "same source bytes and IR node id under a different node span must miss"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes and IR node id under different spans must allocate separate demand nodes"
    );
}

#[test]
fn source_less_force_cache_identities_include_node_span() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let (first_identity, body) = force_cache_identity_for_source_less_attr_a(&ir);
    let body_span = ir.arena.node(body).expect("body node exists").span;
    let fixed_module_hash = DurableBlake3Hash::for_bytes(b"source-less-node-span-canary");

    let mut shifted = ir.clone();
    let mut nodes = shifted.arena.nodes().to_vec();
    nodes[body.index()].span = Span::new(100, 104);
    shifted.arena = IrArena::from_raw_parts(nodes, shifted.arena.child_pool().to_vec());
    let (shifted_identity, shifted_body) = force_cache_identity_for_source_less_attr_a(&shifted);

    let fixed_module_first = TreeWalk::test_cache_expression_identity_for_module_hash_and_span(
        fixed_module_hash,
        body,
        body_span,
    );
    let fixed_module_shifted = TreeWalk::test_cache_expression_identity_for_module_hash_and_span(
        fixed_module_hash,
        body,
        Span::new(100, 104),
    );

    assert_eq!(shifted_body, body);
    assert_ne!(
        fixed_module_shifted, fixed_module_first,
        "same source-less module identity and IR node id under a different node span must not reuse one demand node"
    );
    assert_ne!(
        shifted_identity, first_identity,
        "same lowered IR node id under a different node span must not reuse one demand node"
    );

    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second =
        TreeWalk::with_options_and_eval_cache(&shifted, TreeWalkOptions::new(), cache.clone());
    let forced = force_attr_a(&mut second, &shifted, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "same lowered IR node id under a different node span must miss"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR node id under different spans must allocate separate demand nodes"
    );
}

#[test]
fn source_backed_forced_inline_thunks_include_path_base_in_cache_identity() {
    let root = unique_temp_dir("force-cache-path-base");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).expect("first dir exists");
    fs::create_dir_all(&second_dir).expect("second dir exists");
    let first_dir = fs::canonicalize(&first_dir).expect("first dir canonicalizes");
    let second_dir = fs::canonicalize(&second_dir).expect("second dir canonicalizes");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for path_base in [&first_dir, &second_dir] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(path_base))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different path bases must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_store_dir_in_cache_identity() {
    let root = unique_temp_dir("force-cache-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for store_dir in [&first_store, &second_store] {
        let mut options = TreeWalkOptions::new();
        options
            .set_store_dir(path_bytes(store_dir))
            .expect("store dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different store dirs must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_search_path_base_in_cache_identity() {
    let root = unique_temp_dir("force-cache-search-path-base-salt");
    let first_base = root.join("first");
    let second_base = root.join("second");
    fs::create_dir_all(&first_base).expect("first base exists");
    fs::create_dir_all(&second_base).expect("second base exists");
    let first_base = fs::canonicalize(&first_base).expect("first base canonicalizes");
    let second_base = fs::canonicalize(&second_base).expect("second base canonicalizes");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_search_path_base(path_bytes(&first_base))
        .expect("first search-path base configures");
    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_search_path_base(path_bytes(&second_base))
        .expect("second search-path base configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different search-path bases must not reuse one demand node",
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_nix_path_in_cache_identity() {
    let root = unique_temp_dir("force-cache-nix-path-salt");
    let first_entry = root.join("first");
    let second_entry = root.join("second");
    fs::create_dir_all(&first_entry).expect("first entry exists");
    fs::create_dir_all(&second_entry).expect("second entry exists");
    let first_entry = fs::canonicalize(&first_entry).expect("first entry canonicalizes");
    let second_entry = fs::canonicalize(&second_entry).expect("second entry canonicalizes");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&first_entry))
        .expect("first nix path entry configures");
    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&second_entry))
        .expect("second nix path entry configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different nix_path entries must not reuse one demand node",
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_nix_path_prefix_in_cache_identity() {
    let root = unique_temp_dir("force-cache-nix-path-prefix-salt");
    let entry = root.join("entry");
    fs::create_dir_all(&entry).expect("entry exists");
    let entry = fs::canonicalize(&entry).expect("entry canonicalizes");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&entry))
        .expect("first nix path prefix configures");
    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"other".to_vec(), path_bytes(&entry))
        .expect("second nix path prefix configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different nix_path prefixes must not reuse one demand node",
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_nix_path_order_in_cache_identity() {
    let root = unique_temp_dir("force-cache-nix-path-order-salt");
    let first_entry = root.join("first");
    let second_entry = root.join("second");
    fs::create_dir_all(&first_entry).expect("first entry exists");
    fs::create_dir_all(&second_entry).expect("second entry exists");
    let first_entry = fs::canonicalize(&first_entry).expect("first entry canonicalizes");
    let second_entry = fs::canonicalize(&second_entry).expect("second entry canonicalizes");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"first".to_vec(), path_bytes(&first_entry))
        .expect("first entry configures");
    first_options
        .add_nix_path_entry(b"second".to_vec(), path_bytes(&second_entry))
        .expect("second entry configures");
    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"second".to_vec(), path_bytes(&second_entry))
        .expect("second entry configures");
    second_options
        .add_nix_path_entry(b"first".to_vec(), path_bytes(&first_entry))
        .expect("first entry configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under reordered nix_path entries must not reuse one demand node",
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_nix_path_entry_count_in_cache_identity() {
    let root = unique_temp_dir("force-cache-nix-path-count-salt");
    let first_entry = root.join("first");
    let second_entry = root.join("second");
    fs::create_dir_all(&first_entry).expect("first entry exists");
    fs::create_dir_all(&second_entry).expect("second entry exists");
    let first_entry = fs::canonicalize(&first_entry).expect("first entry canonicalizes");
    let second_entry = fs::canonicalize(&second_entry).expect("second entry canonicalizes");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_nix_path_entry(b"first".to_vec(), path_bytes(&first_entry))
        .expect("first entry configures");
    let mut second_options = first_options.clone();
    second_options
        .add_nix_path_entry(b"second".to_vec(), path_bytes(&second_entry))
        .expect("second entry configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different nix_path entry counts must not reuse one demand node",
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_corepkgs_path_in_cache_identity() {
    let root = unique_temp_dir("force-cache-corepkgs-salt");
    let first_corepkgs = root.join("corepkgs-a");
    let second_corepkgs = root.join("corepkgs-b");
    fs::create_dir_all(&first_corepkgs).expect("first corepkgs exists");
    fs::create_dir_all(&second_corepkgs).expect("second corepkgs exists");
    let first_corepkgs = fs::canonicalize(&first_corepkgs).expect("first corepkgs canonicalizes");
    let second_corepkgs =
        fs::canonicalize(&second_corepkgs).expect("second corepkgs canonicalizes");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_corepkgs_path(path_bytes(&first_corepkgs))
        .expect("first corepkgs path configures");
    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_corepkgs_path(path_bytes(&second_corepkgs))
        .expect("second corepkgs path configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different corepkgs paths must not reuse one demand node",
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_allowed_paths_in_cache_identity() {
    let root = unique_temp_dir("force-cache-allowed-paths-salt");
    let first_allowed = root.join("allowed-a");
    let second_allowed = root.join("allowed-b");
    fs::create_dir_all(&first_allowed).expect("first allowed path exists");
    fs::create_dir_all(&second_allowed).expect("second allowed path exists");
    let first_allowed = fs::canonicalize(&first_allowed).expect("first path canonicalizes");
    let second_allowed = fs::canonicalize(&second_allowed).expect("second path canonicalizes");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_allowed_path(path_bytes(&first_allowed))
        .expect("first allowed path configures");
    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_allowed_path(path_bytes(&second_allowed))
        .expect("second allowed path configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different allowed path roots must not reuse one demand node",
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_allowed_uris_in_cache_identity() {
    let mut first_options = TreeWalkOptions::new();
    first_options
        .add_allowed_uri(b"https://cache-a.example/".to_vec())
        .expect("first allowed URI configures");
    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_allowed_uri(b"https://cache-b.example/".to_vec())
        .expect("second allowed URI configures");

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different allowed URI prefixes must not reuse one demand node",
    );
}

#[test]
fn source_backed_forced_inline_thunks_include_ambient_search_path_rejection_in_cache_identity() {
    let first_options = TreeWalkOptions::new();
    let mut second_options = TreeWalkOptions::new();
    second_options.set_reject_ambient_search_path(true);

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different ambient search-path rejection must not reuse one demand node",
    );
}

#[test]
fn source_backed_forced_inline_thunks_include_impure_builtin_rejection_in_cache_identity() {
    let first_options = TreeWalkOptions::new();
    let mut second_options = TreeWalkOptions::new();
    second_options.set_reject_unconfigured_impure_builtin_constants(true);

    assert_source_backed_options_allocate_distinct_nodes(
        first_options,
        second_options,
        "same source bytes under different impure builtin rejection must not reuse one demand node",
    );
}

#[test]
fn source_backed_forced_inline_thunks_include_home_dir_in_cache_identity() {
    let root = unique_temp_dir("force-cache-home-dir");
    let first_home = root.join("home-a");
    let second_home = root.join("home-b");
    fs::create_dir_all(&first_home).expect("first home exists");
    fs::create_dir_all(&second_home).expect("second home exists");
    fs::write(first_home.join("marker"), b"present").expect("first marker exists");
    let first_home = fs::canonicalize(&first_home).expect("first home canonicalizes");
    let second_home = fs::canonicalize(&second_home).expect("second home canonicalizes");
    let source = "{ a = builtins.pathExists ~/marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (home_dir, expected) in [(&first_home, true), (&second_home, false)] {
        let mut options = TreeWalkOptions::new();
        options
            .set_home_dir(path_bytes(home_dir))
            .expect("home dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_bool(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different home dirs must not reuse a prior resolved pathExists input"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        4,
        "same source bytes under different home dirs must not reuse demand nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_eval_mode_in_cache_identity() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for mode in [EvalMode::Impure, EvalMode::Pure] {
        let options = TreeWalkOptions::with_eval_mode(mode);
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different eval modes must not reuse one demand node"
    );
}

fn assert_source_backed_options_allocate_distinct_nodes(
    first_options: TreeWalkOptions,
    second_options: TreeWalkOptions,
    message: &str,
) {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (index, options) in [first_options, second_options].into_iter().enumerate() {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
        if index == 1 {
            assert_eq!(evaluator.stats().cache_hits(), 0, "{message}");
        }
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "{message}"
    );
}
