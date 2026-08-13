//! Shared helpers for derivation force-cache surface tests.

use super::*;

#[derive(Debug)]
pub(super) struct CachedDerivationSurface {
    pub(super) path: String,
    pub(super) aterm: Vec<u8>,
    pub(super) trace: Vec<ImpureInputFingerprint>,
    pub(super) trace_complete: bool,
    pub(super) thunks_forced: u64,
    pub(super) cache_hits: u64,
    pub(super) force_cache_hits: u64,
    pub(super) force_cache_misses: u64,
    pub(super) persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
}

pub(super) fn assert_derivation_surface_canaries_absent(
    surface_name: &str,
    surface: &CachedDerivationSurface,
    canaries: &[(String, Vec<u8>)],
) {
    assert_drv_surface_canaries_absent(surface_name, &surface.path, &surface.aterm, canaries);
}

pub(super) fn assert_derivation_surface_has_input_source(
    surface_name: &str,
    surface: &CachedDerivationSurface,
    input_path_in_store: &[u8],
) {
    let parsed_derivation =
        nix_compat::derivation::Derivation::from_aterm_bytes(surface.aterm.as_slice())
            .expect("derivation ATerm parses");
    let input = nix_compat::store_path::StorePath::<String>::from_bytes(input_path_in_store)
        .expect("input store path parses");
    assert!(
        parsed_derivation.input_sources.contains(&input),
        "{surface_name} should add the referenced store path as a derivation input source"
    );
}

pub(super) fn assert_derivation_surface_lacks_input_source(
    surface_name: &str,
    surface: &CachedDerivationSurface,
    input_path_in_store: &[u8],
) {
    let parsed_derivation =
        nix_compat::derivation::Derivation::from_aterm_bytes(surface.aterm.as_slice())
            .expect("derivation ATerm parses");
    let input = nix_compat::store_path::StorePath::<String>::from_bytes(input_path_in_store)
        .expect("input store path parses");
    assert!(
        !parsed_derivation.input_sources.contains(&input),
        "{surface_name} should not retain the stale store path as a derivation input source"
    );
}

pub(super) fn assert_persistent_force_cache_trace_log_contains(
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

pub(super) fn evaluate_cached_derivation_surface(
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

pub(super) fn evaluate_cached_derivation_surface_with_cache(
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
        trace_complete: outcome.impure_input_trace_complete(),
        thunks_forced: outcome.stats().thunks_forced(),
        cache_hits: outcome.stats().cache_hits(),
        force_cache_hits: outcome.stats().force_cache_hits(),
        force_cache_misses: outcome.stats().force_cache_misses(),
        persist_force_cache_hit_keys: outcome.persist_force_cache_hit_keys().to_vec(),
    }
}

pub(super) fn assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
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

pub(super) fn assert_zero_input_force_hit_preserves_drv_surface(
    persist_prefix: &str,
    ir: &Ir,
    source: &str,
    surface_name: &str,
) {
    let persist_root = unique_temp_dir(persist_prefix);

    let uncached = evaluate_cached_derivation_surface(
        ir,
        source,
        TreeWalkOptions::new(),
        EvalCacheRuntime::disabled(),
    );
    assert!(uncached.trace.is_empty());
    assert_eq!(uncached.cache_hits, 0);
    assert_eq!(uncached.force_cache_hits, 0);
    assert_eq!(uncached.force_cache_misses, 0);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    let first =
        evaluate_cached_derivation_surface(ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert!(first.trace.is_empty());
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_cached_derivation_surface(
        ir,
        source,
        materialize_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(materialize.path, uncached.path);
    assert_eq!(materialize.aterm, uncached.aterm);
    assert!(materialize.trace.is_empty());
    assert_eq!(materialize.cache_hits, 0);
    assert_eq!(materialize.force_cache_hits, 0);
    assert!(
        materialize.force_cache_misses > 0,
        "materializing {surface_name} surface should miss before writing persistent force-cache payloads"
    );
    let trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &[],
        &format!("materializing {surface_name} force-cache surface"),
    );

    let mut hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    hit_options.set_persist_cache_root(&persist_root);
    let hit =
        evaluate_cached_derivation_surface(ir, source, hit_options, EvalCacheRuntime::enabled());
    assert_eq!(hit.path, uncached.path);
    assert_eq!(hit.aterm, uncached.aterm);
    assert!(hit.trace.is_empty());
    assert!(
        hit.thunks_forced < materialize.thunks_forced,
        "fresh-runtime {surface_name} persistent hits should force fewer thunks than materializing recomputation"
    );
    assert!(hit.cache_hits > 0);
    assert!(hit.force_cache_hits > 0);
    assert_eq!(hit.force_cache_misses, 0);
    assert!(
        hit.persist_force_cache_hit_keys.contains(&trace_entry.0),
        "fresh-runtime {surface_name} hit should load the expected force-cache metadata key"
    );

    let canaries = persistent_force_cache_surface_canaries(&persist_root, &[&[]]);
    assert_derivation_surface_canaries_absent(
        &format!("uncached {surface_name} surface"),
        &uncached,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        &format!("cold {surface_name} surface"),
        &first,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        &format!("materializing {surface_name} surface"),
        &materialize,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        &format!("persistent-hit {surface_name} surface"),
        &hit,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

pub(super) fn assert_cacheable_impure_leaf_force_stale_miss_preserves_drv_surface(
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
