//! Derivation force-cache surface tests for hashFile inputs.

use super::derivation_cache_support::*;
use super::*;

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
fn persistent_text_store_hash_file_force_cache_hit_preserves_drv_surfaces() {
    let source = r#"let
             b = builtins;
             payload = b.toFile "force-cache-text-store-hash-file-payload" "text store hash payload";
           in {
             pkg = derivationStrict {
               name = "force-cache-text-store-hash-file-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ payload (b.hashFile "sha256" payload) ];
             };
           }"#;
    let ir = lower(source);

    assert_zero_input_force_hit_preserves_drv_surface(
        "force-cache-text-store-hash-file-drv-hit-parity",
        &ir,
        source,
        "text-store hashFile",
    );
}
