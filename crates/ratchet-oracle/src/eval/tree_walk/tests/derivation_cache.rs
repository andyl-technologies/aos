//! Tree-walk evaluator tests: derivation cache parity canaries.

use super::derivation_cache_support::*;
use super::*;

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
fn persistent_context_read_file_force_cache_hit_preserves_drv_surfaces() {
    let root = unique_temp_dir("force-cache-context-read-file-drv-source");
    let referenced_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
    let contents = [
        b"context prefix ".as_slice(),
        referenced_path,
        b"/suffix".as_slice(),
    ]
    .concat();
    fs::write(root.join("input.txt"), &contents).expect("input file writes");
    let root = fs::canonicalize(root).expect("source root canonicalizes");
    let input_path = path_bytes(&root.join("input.txt"));
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-context-read-file-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (b.readFile ./input.txt) ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&input_path, &contents).expect("fingerprint builds"),
    ];
    let mut context_proof_options = TreeWalkOptions::new();
    context_proof_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let context_proof = evaluate_cached_derivation_surface(
        &ir,
        source,
        context_proof_options,
        EvalCacheRuntime::disabled(),
    );
    assert_derivation_surface_has_input_source(
        "context readFile surface",
        &context_proof,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source",
    );

    assert_cacheable_impure_leaf_force_hit_preserves_drv_surface(
        "force-cache-context-read-file-drv-surface-parity",
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
fn persistent_text_store_read_file_force_cache_hit_preserves_drv_surfaces() {
    let source = r#"let
             b = builtins;
             payload = b.toFile "force-cache-text-store-read-file-payload" "text store read payload";
           in {
             pkg = derivationStrict {
               name = "force-cache-text-store-read-file-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ payload (b.readFile payload) ];
             };
           }"#;
    let ir = lower(source);

    assert_zero_input_force_hit_preserves_drv_surface(
        "force-cache-text-store-read-file-drv-hit-parity",
        &ir,
        source,
        "text-store readFile",
    );
}

#[test]
fn persistent_text_store_import_force_cache_no_replay_preserves_drv_surfaces() {
    let persist_root = unique_temp_dir("force-cache-text-store-import-drv-no-replay");
    let source = r#"{
             pkg = derivationStrict {
               name = "force-cache-text-store-import-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [
                 (import (builtins.toFile
                   "force-cache-text-store-import-payload.nix"
                   "\"text store import payload\""))
               ];
             };
           }"#;
    let ir = lower(source);
    let uncached = evaluate_cached_derivation_surface(
        &ir,
        source,
        TreeWalkOptions::new(),
        EvalCacheRuntime::disabled(),
    );
    assert!(uncached.trace.is_empty());
    assert!(uncached.trace_complete);
    assert_eq!(uncached.cache_hits, 0);
    assert_eq!(uncached.force_cache_hits, 0);
    assert_eq!(uncached.force_cache_misses, 0);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    let first =
        evaluate_cached_derivation_surface(&ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert!(first.trace.is_empty());
    assert!(first.trace_complete);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut replay_options = TreeWalkOptions::with_eval_cache_enabled(true);
    replay_options.set_persist_cache_root(&persist_root);
    let replay = evaluate_cached_derivation_surface(
        &ir,
        source,
        replay_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(replay.path, uncached.path);
    assert_eq!(replay.aterm, uncached.aterm);
    assert!(replay.trace.is_empty());
    assert!(replay.trace_complete);
    assert_eq!(replay.cache_hits, 0);
    assert_eq!(replay.force_cache_hits, 0);
    assert_eq!(replay.force_cache_misses, 0);
    assert_persistent_force_cache_has_no_live_traces(
        &persist_root,
        "computed text-store import force-cache no-replay surface",
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
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
