//! Tree-walk evaluator tests: derivation cache parity canaries.

use super::*;

#[derive(Debug)]
struct CachedDerivationSurface {
    path: String,
    aterm: Vec<u8>,
    trace: Vec<ImpureInputFingerprint>,
    thunks_forced: u64,
    cache_hits: u64,
    force_cache_hits: u64,
    force_cache_misses: u64,
    persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
}

fn assert_derivation_surface_canaries_absent(
    surface_name: &str,
    surface: &CachedDerivationSurface,
    canaries: &[(String, Vec<u8>)],
) {
    assert_drv_surface_canaries_absent(surface_name, &surface.path, &surface.aterm, canaries);
}

fn assert_persistent_force_cache_trace_log_contains(
    persist_root: &Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> (PersistNodeMetadataKey, ValueHash) {
    let expected = expected_trace
        .iter()
        .map(|input| {
            input
                .as_cacheable()
                .unwrap_or_else(|| panic!("{context} expected trace should be cacheable"))
                .clone()
        })
        .collect::<Vec<_>>();
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

fn evaluate_cached_derivation_surface(
    ir: &Ir,
    source: &str,
    options: TreeWalkOptions,
    eval_cache: EvalCacheRuntime,
) -> CachedDerivationSurface {
    evaluate_cached_derivation_surface_with_cache(
        ir,
        source,
        options,
        Arc::new(Mutex::new(eval_cache)),
    )
}

fn evaluate_cached_derivation_surface_with_cache(
    ir: &Ir,
    source: &str,
    options: TreeWalkOptions,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
) -> CachedDerivationSurface {
    let attr_path = vec![b"pkg".to_vec()];
    let outcome = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        ir,
        &attr_path,
        options,
        "force-cache-impure-leaf-drv-surface.nix",
        source,
        None,
        eval_cache,
    )
    .expect("derivation attr-path eval succeeds");
    let [derivation] = outcome.derivations() else {
        panic!(
            "expected one recorded derivation, got {:?}",
            outcome.derivations()
        );
    };
    CachedDerivationSurface {
        path: derivation.absolute_path().to_owned(),
        aterm: derivation
            .aterm_bytes()
            .expect("static derivation has ATerm bytes")
            .to_vec(),
        trace: outcome.impure_input_trace().to_vec(),
        thunks_forced: outcome.stats().thunks_forced(),
        cache_hits: outcome.stats().cache_hits(),
        force_cache_hits: outcome.stats().force_cache_hits(),
        force_cache_misses: outcome.stats().force_cache_misses(),
        persist_force_cache_hit_keys: outcome.persist_force_cache_hit_keys().to_vec(),
    }
}

fn assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
    persist_prefix: &str,
    ir: &Ir,
    source: &str,
    expected_trace: Vec<ImpureInputFingerprint>,
    configure_options: impl Fn(&mut TreeWalkOptions),
) {
    let persist_root = unique_temp_dir(persist_prefix);

    let mut uncached_options = TreeWalkOptions::new();
    configure_options(&mut uncached_options);
    let uncached = evaluate_cached_derivation_surface(
        ir,
        source,
        uncached_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached.trace, expected_trace);
    assert_eq!(uncached.cache_hits, 0);
    assert_eq!(uncached.force_cache_hits, 0);
    assert_eq!(uncached.force_cache_misses, 0);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut first_options);
    first_options.set_persist_cache_root(&persist_root);
    let first =
        evaluate_cached_derivation_surface(ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert_eq!(first.trace, expected_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut materialize_options);
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_cached_derivation_surface(
        ir,
        source,
        materialize_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(materialize.path, uncached.path);
    assert_eq!(materialize.aterm, uncached.aterm);
    assert_eq!(materialize.trace, expected_trace);
    assert_eq!(materialize.cache_hits, 0);
    assert_eq!(materialize.force_cache_hits, 0);
    assert!(
        materialize.force_cache_misses > 0,
        "materializing run should miss before writing persistent force-cache payloads"
    );
    let expected_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &expected_trace,
        "materializing force-cache surface",
    );

    let mut hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut hit_options);
    hit_options.set_persist_cache_root(&persist_root);
    let hit =
        evaluate_cached_derivation_surface(ir, source, hit_options, EvalCacheRuntime::enabled());
    assert_eq!(hit.path, uncached.path);
    assert_eq!(hit.aterm, uncached.aterm);
    assert_eq!(hit.trace, expected_trace);
    assert!(
        hit.thunks_forced < materialize.thunks_forced,
        "fresh-runtime persistent hits should force fewer thunks than materializing recomputation"
    );
    assert!(hit.cache_hits > 0);
    assert!(hit.force_cache_hits > 0);
    assert_eq!(hit.force_cache_misses, 0);
    assert!(
        hit.persist_force_cache_hit_keys
            .contains(&expected_trace_entry.0),
        "fresh-runtime persistent hit should load the expected force-cache metadata key"
    );

    let canaries = persistent_force_cache_surface_canaries(&persist_root, &[&expected_trace]);
    assert_derivation_surface_canaries_absent("uncached force-cache surface", &uncached, &canaries);
    assert_derivation_surface_canaries_absent("cold force-cache surface", &first, &canaries);
    assert_derivation_surface_canaries_absent(
        "materializing force-cache surface",
        &materialize,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "persistent-hit force-cache surface",
        &hit,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

fn assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
    persist_prefix: &str,
    ir: &Ir,
    source: &str,
    first_trace: Vec<ImpureInputFingerprint>,
    changed_trace: Vec<ImpureInputFingerprint>,
    configure_options: impl Fn(&mut TreeWalkOptions),
    mutate_input: impl FnOnce(),
) {
    let persist_root = unique_temp_dir(persist_prefix);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut first_options);
    first_options.set_persist_cache_root(&persist_root);
    let first =
        evaluate_cached_derivation_surface(ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.trace, first_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut materialize_options);
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_cached_derivation_surface(
        ir,
        source,
        materialize_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(materialize.path, first.path);
    assert_eq!(materialize.aterm, first.aterm);
    assert_eq!(materialize.trace, first_trace);
    assert_eq!(materialize.cache_hits, 0);
    assert_eq!(materialize.force_cache_hits, 0);
    assert!(
        materialize.force_cache_misses > 0,
        "materializing stale baseline should miss before writing persistent force-cache payloads"
    );
    let first_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &first_trace,
        "materializing stale-miss baseline surface",
    );

    mutate_input();

    let mut uncached_changed_options = TreeWalkOptions::new();
    configure_options(&mut uncached_changed_options);
    let uncached_changed = evaluate_cached_derivation_surface(
        ir,
        source,
        uncached_changed_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached_changed.trace, changed_trace);
    assert_eq!(uncached_changed.cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_misses, 0);
    assert_ne!(uncached_changed.path, materialize.path);
    assert_ne!(uncached_changed.aterm, materialize.aterm);

    let stale_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut stale_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut stale_options);
    stale_options.set_persist_cache_root(&persist_root);
    let stale = evaluate_cached_derivation_surface_with_cache(
        ir,
        source,
        stale_options,
        stale_runtime.clone(),
    );
    assert_eq!(stale.path, uncached_changed.path);
    assert_eq!(stale.aterm, uncached_changed.aterm);
    assert_eq!(stale.trace, changed_trace);
    assert!(
        stale.force_cache_misses > 0,
        "stale persistent observations should report at least one force-cache miss"
    );
    assert!(
        stale.thunks_forced > 0,
        "stale persistent observations should fall back to ordinary forcing"
    );
    let changed_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_trace,
        "stale-miss recomputed force-cache surface",
    );
    assert_eq!(
        changed_trace_entry.0, first_trace_entry.0,
        "stale recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_trace_entry.1, first_trace_entry.1,
        "stale recomputation should materialize a changed force-cache value"
    );

    let mut same_runtime_hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut same_runtime_hit_options);
    same_runtime_hit_options.set_persist_cache_root(&persist_root);
    let same_runtime_hit = evaluate_cached_derivation_surface_with_cache(
        ir,
        source,
        same_runtime_hit_options,
        stale_runtime,
    );
    assert_eq!(same_runtime_hit.path, uncached_changed.path);
    assert_eq!(same_runtime_hit.aterm, uncached_changed.aterm);
    assert_eq!(same_runtime_hit.trace, changed_trace);
    assert!(same_runtime_hit.cache_hits > 0);
    assert!(same_runtime_hit.force_cache_hits > 0);
    assert_eq!(same_runtime_hit.force_cache_misses, 0);

    let mut fresh_runtime_hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut fresh_runtime_hit_options);
    fresh_runtime_hit_options.set_persist_cache_root(&persist_root);
    let fresh_runtime_hit = evaluate_cached_derivation_surface(
        ir,
        source,
        fresh_runtime_hit_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(fresh_runtime_hit.path, uncached_changed.path);
    assert_eq!(fresh_runtime_hit.aterm, uncached_changed.aterm);
    assert_eq!(fresh_runtime_hit.trace, changed_trace);
    assert!(fresh_runtime_hit.cache_hits > 0);
    assert!(fresh_runtime_hit.force_cache_hits > 0);
    assert_eq!(fresh_runtime_hit.force_cache_misses, 0);
    assert!(
        fresh_runtime_hit
            .persist_force_cache_hit_keys
            .contains(&changed_trace_entry.0),
        "fresh-runtime post-recompute hit should load the changed force-cache metadata key"
    );
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_trace,
            "fresh-runtime post-recompute force-cache surface",
        ),
        changed_trace_entry,
        "fresh-runtime post-recompute reuse should keep the changed force-cache trace live"
    );

    let canaries =
        persistent_force_cache_surface_canaries(&persist_root, &[&first_trace, &changed_trace]);
    assert_derivation_surface_canaries_absent("original force-cache surface", &first, &canaries);
    assert_derivation_surface_canaries_absent(
        "materializing force-cache surface",
        &materialize,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "changed uncached force-cache surface",
        &uncached_changed,
        &canaries,
    );
    assert_derivation_surface_canaries_absent("stale-miss force-cache surface", &stale, &canaries);
    assert_derivation_surface_canaries_absent(
        "same-runtime post-recompute force-cache surface",
        &same_runtime_hit,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "fresh-runtime post-recompute force-cache surface",
        &fresh_runtime_hit,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_first_class_import_force_cache_hit_and_stale_miss_preserve_drv_surfaces() {
    let root = unique_temp_dir("force-cache-import-drv-source");
    let imported = root.join("imported.nix");
    let original_source = br#""import payload""#;
    let changed_source = br#""changed import payload""#;
    fs::write(&imported, original_source).expect("import source writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let imported = fs::canonicalize(root.join("imported.nix")).expect("import path canonicalizes");
    let imported_path = path_bytes(&imported);
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-import-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.import ./imported.nix) ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::import(&imported_path, original_source)
            .expect("fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::import(&imported_path, changed_source)
            .expect("changed fingerprint builds"),
    ];

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-import-drv-surface-parity",
        &ir,
        source,
        expected_trace.clone(),
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
    );

    assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
        "force-cache-import-drv-stale-parity",
        &ir,
        source,
        expected_trace,
        changed_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
        || {
            fs::write(&imported, changed_source).expect("changed import source writes");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_file_force_cache_hit_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-file-drv-source");
    fs::write(root.join("input.txt"), b"read file payload").expect("input file writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let input_path = path_bytes(&root.join("input.txt"));
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-file-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFile ./input.txt) ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&input_path, b"read file payload")
            .expect("fingerprint builds"),
    ];

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-read-file-drv-surface-parity",
        &ir,
        source,
        expected_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_get_env_force_cache_hit_and_stale_miss_preserve_drv_surfaces() {
    let name = b"AOS_FORCE_CACHE_DRV_TEST";
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-get-env-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.getEnv "AOS_FORCE_CACHE_DRV_TEST") ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::get_env(name, Some(b"env payload")).expect("fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::get_env(name, Some(b"changed payload"))
            .expect("changed fingerprint builds"),
    ];

    let persist_root = unique_temp_dir("force-cache-get-env-drv-surface-parity");

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options.set_env_var(name.to_vec(), b"env payload".to_vec());
    let uncached = evaluate_cached_derivation_surface(
        &ir,
        source,
        uncached_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached.trace, expected_trace);
    assert_eq!(uncached.cache_hits, 0);
    assert_eq!(uncached.force_cache_hits, 0);
    assert_eq!(uncached.force_cache_misses, 0);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_env_var(name.to_vec(), b"env payload".to_vec());
    first_options.set_persist_cache_root(&persist_root);
    let first =
        evaluate_cached_derivation_surface(&ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert_eq!(first.trace, expected_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options.set_env_var(name.to_vec(), b"env payload".to_vec());
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_cached_derivation_surface(
        &ir,
        source,
        materialize_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(materialize.path, uncached.path);
    assert_eq!(materialize.aterm, uncached.aterm);
    assert_eq!(materialize.trace, expected_trace);
    assert_eq!(materialize.cache_hits, 0);
    assert_eq!(materialize.force_cache_hits, 0);
    assert_eq!(materialize.force_cache_misses, 1);
    let expected_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &expected_trace,
        "materializing getEnv surface",
    );

    let mut hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    hit_options.set_env_var(name.to_vec(), b"env payload".to_vec());
    hit_options.set_persist_cache_root(&persist_root);
    let hit =
        evaluate_cached_derivation_surface(&ir, source, hit_options, EvalCacheRuntime::enabled());
    assert_eq!(hit.path, uncached.path);
    assert_eq!(hit.aterm, uncached.aterm);
    assert_eq!(hit.trace, expected_trace);
    assert_eq!(hit.cache_hits, 1);
    assert_eq!(hit.force_cache_hits, 1);
    assert_eq!(hit.force_cache_misses, 0);
    assert!(
        hit.persist_force_cache_hit_keys
            .contains(&expected_trace_entry.0),
        "fresh-runtime getEnv hit should load the expected force-cache metadata key"
    );

    let mut uncached_changed_options = TreeWalkOptions::new();
    uncached_changed_options.set_env_var(name.to_vec(), b"changed payload".to_vec());
    let uncached_changed = evaluate_cached_derivation_surface(
        &ir,
        source,
        uncached_changed_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached_changed.trace, changed_trace);
    assert_eq!(uncached_changed.cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_misses, 0);
    assert_ne!(uncached_changed.path, uncached.path);
    assert_ne!(uncached_changed.aterm, uncached.aterm);

    let changed_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut changed_replay_options = TreeWalkOptions::with_eval_cache_enabled(true);
    changed_replay_options.set_env_var(name.to_vec(), b"changed payload".to_vec());
    changed_replay_options.set_persist_cache_root(&persist_root);
    let changed_replay = evaluate_cached_derivation_surface_with_cache(
        &ir,
        source,
        changed_replay_options,
        changed_runtime.clone(),
    );
    assert_eq!(changed_replay.path, uncached_changed.path);
    assert_eq!(changed_replay.aterm, uncached_changed.aterm);
    assert_eq!(changed_replay.trace, changed_trace);
    assert_eq!(changed_replay.cache_hits, 0);
    assert_eq!(changed_replay.force_cache_hits, 0);
    assert_eq!(changed_replay.force_cache_misses, 1);
    assert!(
        changed_replay.thunks_forced > 0,
        "stale persistent getEnv observations should fall back to ordinary forcing"
    );
    let changed_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_trace,
        "changed getEnv replay surface",
    );
    assert_eq!(
        changed_trace_entry.0, expected_trace_entry.0,
        "changed getEnv recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_trace_entry.1, expected_trace_entry.1,
        "changed getEnv recomputation should materialize a changed force-cache value"
    );

    let mut same_runtime_changed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    same_runtime_changed_options.set_env_var(name.to_vec(), b"changed payload".to_vec());
    same_runtime_changed_options.set_persist_cache_root(&persist_root);
    let same_runtime_changed = evaluate_cached_derivation_surface_with_cache(
        &ir,
        source,
        same_runtime_changed_options,
        changed_runtime,
    );
    assert_eq!(same_runtime_changed.path, uncached_changed.path);
    assert_eq!(same_runtime_changed.aterm, uncached_changed.aterm);
    assert_eq!(same_runtime_changed.trace, changed_trace);
    assert!(same_runtime_changed.cache_hits > 0);
    assert!(same_runtime_changed.force_cache_hits > 0);
    assert_eq!(same_runtime_changed.force_cache_misses, 0);

    let mut fresh_runtime_changed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    fresh_runtime_changed_options.set_env_var(name.to_vec(), b"changed payload".to_vec());
    fresh_runtime_changed_options.set_persist_cache_root(&persist_root);
    let fresh_runtime_changed = evaluate_cached_derivation_surface(
        &ir,
        source,
        fresh_runtime_changed_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(fresh_runtime_changed.path, uncached_changed.path);
    assert_eq!(fresh_runtime_changed.aterm, uncached_changed.aterm);
    assert_eq!(fresh_runtime_changed.trace, changed_trace);
    assert!(fresh_runtime_changed.cache_hits > 0);
    assert!(fresh_runtime_changed.force_cache_hits > 0);
    assert_eq!(fresh_runtime_changed.force_cache_misses, 0);
    assert!(
        fresh_runtime_changed
            .persist_force_cache_hit_keys
            .contains(&changed_trace_entry.0),
        "fresh-runtime changed getEnv hit should load the changed force-cache metadata key"
    );

    let canaries =
        persistent_force_cache_surface_canaries(&persist_root, &[&expected_trace, &changed_trace]);
    assert_derivation_surface_canaries_absent("uncached getEnv surface", &uncached, &canaries);
    assert_derivation_surface_canaries_absent("cold getEnv surface", &first, &canaries);
    assert_derivation_surface_canaries_absent(
        "materializing getEnv surface",
        &materialize,
        &canaries,
    );
    assert_derivation_surface_canaries_absent("same-env getEnv hit surface", &hit, &canaries);
    assert_derivation_surface_canaries_absent(
        "changed uncached getEnv surface",
        &uncached_changed,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "changed getEnv replay surface",
        &changed_replay,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "same-runtime changed getEnv hit surface",
        &same_runtime_changed,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "fresh-runtime changed getEnv hit surface",
        &fresh_runtime_changed,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_read_file_force_cache_stale_miss_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-file-drv-stale-source");
    fs::write(root.join("input.txt"), b"first payload").expect("input file writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let input_path = path_bytes(&root.join("input.txt"));
    let first_trace = vec![
        ImpureInputFingerprint::read_file(&input_path, b"first payload")
            .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::read_file(&input_path, b"changed payload")
            .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-file-drv-stale-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFile ./input.txt) ];
             };
           }"#;
    let ir = lower(source);

    assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
        "force-cache-read-file-drv-stale-parity",
        &ir,
        source,
        first_trace,
        changed_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
        || {
            fs::write(root.join("input.txt"), b"changed payload").expect("input file changes");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_hash_file_force_cache_hit_and_stale_miss_preserve_drv_surfaces() {
    let root = unique_temp_dir("force-cache-hash-file-drv-source");
    fs::write(root.join("input.txt"), b"first hash\0payload").expect("input file writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let input_path = path_bytes(&root.join("input.txt"));
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-hash-file-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.hashFile "sha256" ./input.txt) ];
             };
           }"#;
    let ir = lower(source);
    let first_trace = vec![
        ImpureInputFingerprint::hash_file(&input_path, b"first hash\0payload")
            .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::hash_file(&input_path, b"changed hash\0payload")
            .expect("changed fingerprint builds"),
    ];

    let persist_root = unique_temp_dir("force-cache-hash-file-drv-surface-parity");
    let configure_options = |options: &mut TreeWalkOptions| {
        options
            .set_path_literal_base(path_bytes(&root))
            .expect("path base configures");
    };

    let mut uncached_options = TreeWalkOptions::new();
    configure_options(&mut uncached_options);
    let uncached = evaluate_cached_derivation_surface(
        &ir,
        source,
        uncached_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached.trace, first_trace);
    assert_eq!(uncached.cache_hits, 0);
    assert_eq!(uncached.force_cache_hits, 0);
    assert_eq!(uncached.force_cache_misses, 0);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut first_options);
    first_options.set_persist_cache_root(&persist_root);
    let first =
        evaluate_cached_derivation_surface(&ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert_eq!(first.trace, first_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut materialize_options);
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_cached_derivation_surface(
        &ir,
        source,
        materialize_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(materialize.path, uncached.path);
    assert_eq!(materialize.aterm, uncached.aterm);
    assert_eq!(materialize.trace, first_trace);
    assert_eq!(materialize.cache_hits, 0);
    assert_eq!(materialize.force_cache_hits, 0);
    assert!(
        materialize.force_cache_misses > 0,
        "materializing hashFile surface should miss before writing persistent force-cache payloads"
    );
    let first_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &first_trace,
        "materializing hashFile force-cache surface",
    );

    let mut hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut hit_options);
    hit_options.set_persist_cache_root(&persist_root);
    let hit =
        evaluate_cached_derivation_surface(&ir, source, hit_options, EvalCacheRuntime::enabled());
    assert_eq!(hit.path, uncached.path);
    assert_eq!(hit.aterm, uncached.aterm);
    assert_eq!(hit.trace, first_trace);
    assert!(
        hit.thunks_forced < materialize.thunks_forced,
        "fresh-runtime hashFile persistent hits should force fewer thunks than materializing recomputation"
    );
    assert!(hit.cache_hits > 0);
    assert!(hit.force_cache_hits > 0);
    assert_eq!(hit.force_cache_misses, 0);
    assert!(
        hit.persist_force_cache_hit_keys
            .contains(&first_trace_entry.0),
        "fresh-runtime hashFile hit should load the expected force-cache metadata key"
    );

    fs::write(root.join("input.txt"), b"changed hash\0payload").expect("input file changes");

    let mut uncached_changed_options = TreeWalkOptions::new();
    configure_options(&mut uncached_changed_options);
    let uncached_changed = evaluate_cached_derivation_surface(
        &ir,
        source,
        uncached_changed_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached_changed.trace, changed_trace);
    assert_eq!(uncached_changed.cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_misses, 0);
    assert_ne!(uncached_changed.path, materialize.path);
    assert_ne!(uncached_changed.aterm, materialize.aterm);

    let stale_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut stale_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut stale_options);
    stale_options.set_persist_cache_root(&persist_root);
    let stale = evaluate_cached_derivation_surface_with_cache(
        &ir,
        source,
        stale_options,
        stale_runtime.clone(),
    );
    assert_eq!(stale.path, uncached_changed.path);
    assert_eq!(stale.aterm, uncached_changed.aterm);
    assert_eq!(stale.trace, changed_trace);
    assert!(
        stale.force_cache_misses > 0,
        "stale hashFile persistent observations should report at least one force-cache miss"
    );
    assert!(
        stale.thunks_forced > 0,
        "stale hashFile persistent observations should fall back to ordinary forcing"
    );
    let changed_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_trace,
        "stale-miss recomputed hashFile force-cache surface",
    );
    assert_eq!(
        changed_trace_entry.0, first_trace_entry.0,
        "stale hashFile recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_trace_entry.1, first_trace_entry.1,
        "stale hashFile recomputation should materialize a changed force-cache value"
    );

    let mut same_runtime_hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut same_runtime_hit_options);
    same_runtime_hit_options.set_persist_cache_root(&persist_root);
    let same_runtime_hit = evaluate_cached_derivation_surface_with_cache(
        &ir,
        source,
        same_runtime_hit_options,
        stale_runtime,
    );
    assert_eq!(same_runtime_hit.path, uncached_changed.path);
    assert_eq!(same_runtime_hit.aterm, uncached_changed.aterm);
    assert_eq!(same_runtime_hit.trace, changed_trace);
    assert!(same_runtime_hit.cache_hits > 0);
    assert!(same_runtime_hit.force_cache_hits > 0);
    assert_eq!(same_runtime_hit.force_cache_misses, 0);

    let mut fresh_runtime_hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut fresh_runtime_hit_options);
    fresh_runtime_hit_options.set_persist_cache_root(&persist_root);
    let fresh_runtime_hit = evaluate_cached_derivation_surface(
        &ir,
        source,
        fresh_runtime_hit_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(fresh_runtime_hit.path, uncached_changed.path);
    assert_eq!(fresh_runtime_hit.aterm, uncached_changed.aterm);
    assert_eq!(fresh_runtime_hit.trace, changed_trace);
    assert!(fresh_runtime_hit.cache_hits > 0);
    assert!(fresh_runtime_hit.force_cache_hits > 0);
    assert_eq!(fresh_runtime_hit.force_cache_misses, 0);
    assert!(
        fresh_runtime_hit
            .persist_force_cache_hit_keys
            .contains(&changed_trace_entry.0),
        "fresh-runtime post-recompute hashFile hit should load the changed force-cache metadata key"
    );
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_trace,
            "fresh-runtime post-recompute hashFile force-cache surface",
        ),
        changed_trace_entry,
        "fresh-runtime post-recompute hashFile reuse should keep the changed force-cache trace live"
    );

    let canaries =
        persistent_force_cache_surface_canaries(&persist_root, &[&first_trace, &changed_trace]);
    assert_derivation_surface_canaries_absent("original hashFile surface", &first, &canaries);
    assert_derivation_surface_canaries_absent(
        "materializing hashFile surface",
        &materialize,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "changed uncached hashFile surface",
        &uncached_changed,
        &canaries,
    );
    assert_derivation_surface_canaries_absent("stale-miss hashFile surface", &stale, &canaries);
    assert_derivation_surface_canaries_absent(
        "same-runtime post-recompute hashFile surface",
        &same_runtime_hit,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "fresh-runtime post-recompute hashFile surface",
        &fresh_runtime_hit,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_partial_hash_file_force_cache_hit_and_stale_miss_preserve_drv_surfaces() {
    let root = unique_temp_dir("force-cache-partial-hash-file-drv-source");
    fs::write(root.join("input.txt"), b"first partial hash\0payload").expect("input file writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let input_path = path_bytes(&root.join("input.txt"));
    let first_trace = vec![
        ImpureInputFingerprint::hash_file(&input_path, b"first partial hash\0payload")
            .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::hash_file(&input_path, b"changed partial hash\0payload")
            .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
             hash = b.hashFile "sha256";
           in {
             pkg = derivationStrict {
               name = "force-cache-partial-hash-file-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (hash ./input.txt) ];
             };
           }"#;
    let ir = lower(source);

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-partial-hash-file-drv-hit-parity",
        &ir,
        source,
        first_trace.clone(),
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
    );

    assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
        "force-cache-partial-hash-file-drv-stale-parity",
        &ir,
        source,
        first_trace,
        changed_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
        || {
            fs::write(root.join("input.txt"), b"changed partial hash\0payload")
                .expect("input file changes");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_dir_force_cache_hit_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-dir-drv-source");
    fs::create_dir(root.join("dir")).expect("directory creates");
    fs::write(root.join("dir").join("alpha"), b"data").expect("alpha writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let dir_path = path_bytes(&root.join("dir"));
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-dir-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readDir ./dir).alpha ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"alpha", FileTypeForInput::Regular)],
        )
        .expect("fingerprint builds"),
    ];

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-read-dir-drv-surface-parity",
        &ir,
        source,
        expected_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_dir_force_cache_stale_miss_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-dir-drv-stale-source");
    fs::create_dir(root.join("dir")).expect("directory creates");
    fs::write(root.join("dir").join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let dir_path = path_bytes(&root.join("dir"));
    let first_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"target", FileTypeForInput::Regular)],
        )
        .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"target", FileTypeForInput::Directory)],
        )
        .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-dir-drv-stale-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readDir ./dir).target ];
             };
           }"#;
    let ir = lower(source);

    assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
        "force-cache-read-dir-drv-stale-parity",
        &ir,
        source,
        first_trace,
        changed_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
        || {
            fs::remove_file(root.join("dir").join("target")).expect("target file removes");
            fs::create_dir(root.join("dir").join("target")).expect("target directory creates");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_file_type_force_cache_hit_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-file-type-drv-source");
    fs::write(root.join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-file-type-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFileType ./target) ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
            .expect("fingerprint builds"),
    ];

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-read-file-type-drv-surface-parity",
        &ir,
        source,
        expected_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_read_file_type_force_cache_stale_miss_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-read-file-type-drv-stale-source");
    fs::write(root.join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let first_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
            .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Directory)
            .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-read-file-type-drv-stale-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFileType ./target) ];
             };
           }"#;
    let ir = lower(source);

    assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
        "force-cache-read-file-type-drv-stale-parity",
        &ir,
        source,
        first_trace,
        changed_trace,
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base configures");
        },
        || {
            fs::remove_file(root.join("target")).expect("target file removes");
            fs::create_dir(root.join("target")).expect("target directory creates");
        },
    );

    fs::remove_dir_all(root).expect("source temp directory removes");
}
