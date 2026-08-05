//! Derivation force-cache surface tests for stale readFile inputs.

use super::derivation_cache_support::*;
use super::*;

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
fn persistent_context_read_file_force_cache_stale_miss_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-context-read-file-drv-stale-source");
    let first_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
    let changed_path = b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source";
    let first_contents = [
        b"context prefix ".as_slice(),
        first_path,
        b"/suffix".as_slice(),
    ]
    .concat();
    let changed_contents = [
        b"context prefix ".as_slice(),
        changed_path,
        b"/suffix".as_slice(),
    ]
    .concat();
    fs::write(root.join("input.txt"), &first_contents).expect("input file writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let input_path = path_bytes(&root.join("input.txt"));
    let first_trace = vec![
        ImpureInputFingerprint::read_file(&input_path, &first_contents)
            .expect("first fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::read_file(&input_path, &changed_contents)
            .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-context-read-file-drv-stale-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFile ./input.txt) ];
             };
           }"#;
    let ir = lower(source);
    let configure_options = |options: &mut TreeWalkOptions| {
        options
            .set_path_literal_base(path_bytes(&root))
            .expect("path base configures");
    };

    let persist_root = unique_temp_dir("force-cache-context-read-file-drv-stale-parity");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut first_options);
    first_options.set_persist_cache_root(&persist_root);
    let first =
        evaluate_cached_derivation_surface(&ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.trace, first_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);
    assert_derivation_surface_has_input_source(
        "first context readFile surface",
        &first,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source",
    );
    assert_derivation_surface_lacks_input_source(
        "first context readFile surface",
        &first,
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source",
    );

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut materialize_options);
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_cached_derivation_surface(
        &ir,
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
        "materializing context readFile baseline should miss before writing persistent force-cache payloads"
    );
    assert_derivation_surface_has_input_source(
        "materialized context readFile surface",
        &materialize,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source",
    );
    assert_derivation_surface_lacks_input_source(
        "materialized context readFile surface",
        &materialize,
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source",
    );
    let first_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &first_trace,
        "materializing context readFile baseline surface",
    );

    fs::write(root.join("input.txt"), &changed_contents).expect("input file changes");

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
    assert_derivation_surface_has_input_source(
        "changed uncached context readFile surface",
        &uncached_changed,
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source",
    );
    assert_derivation_surface_lacks_input_source(
        "changed uncached context readFile surface",
        &uncached_changed,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source",
    );

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
        "stale context readFile persistent observations should report at least one force-cache miss"
    );
    assert!(
        stale.thunks_forced > 0,
        "stale context readFile persistent observations should fall back to ordinary forcing"
    );
    assert_derivation_surface_has_input_source(
        "stale-miss context readFile surface",
        &stale,
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source",
    );
    assert_derivation_surface_lacks_input_source(
        "stale-miss context readFile surface",
        &stale,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source",
    );
    let changed_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_trace,
        "stale-miss recomputed context readFile force-cache surface",
    );
    assert_eq!(
        changed_trace_entry.0, first_trace_entry.0,
        "stale context readFile recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_trace_entry.1, first_trace_entry.1,
        "stale context readFile recomputation should materialize a changed force-cache value"
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
    assert_derivation_surface_has_input_source(
        "same-runtime post-recompute context readFile surface",
        &same_runtime_hit,
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source",
    );
    assert_derivation_surface_lacks_input_source(
        "same-runtime post-recompute context readFile surface",
        &same_runtime_hit,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source",
    );

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
        "fresh-runtime post-recompute context readFile hit should load the changed force-cache metadata key"
    );
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_trace,
            "fresh-runtime post-recompute context readFile force-cache surface",
        ),
        changed_trace_entry,
        "fresh-runtime post-recompute context readFile reuse should keep the changed force-cache trace live"
    );
    assert_derivation_surface_has_input_source(
        "fresh-runtime post-recompute context readFile surface",
        &fresh_runtime_hit,
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source",
    );
    assert_derivation_surface_lacks_input_source(
        "fresh-runtime post-recompute context readFile surface",
        &fresh_runtime_hit,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source",
    );

    let canaries =
        persistent_force_cache_surface_canaries(&persist_root, &[&first_trace, &changed_trace]);
    assert_derivation_surface_canaries_absent(
        "original context readFile surface",
        &first,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "materializing context readFile surface",
        &materialize,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "changed uncached context readFile surface",
        &uncached_changed,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "stale-miss context readFile surface",
        &stale,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "same-runtime post-recompute context readFile surface",
        &same_runtime_hit,
        &canaries,
    );
    assert_derivation_surface_canaries_absent(
        "fresh-runtime post-recompute context readFile surface",
        &fresh_runtime_hit,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
    fs::remove_dir_all(root).expect("source temp directory removes");
}
