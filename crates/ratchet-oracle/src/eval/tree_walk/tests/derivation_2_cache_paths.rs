//! Tree-walk evaluator tests for derivation cache path reuse.

use super::derivation_2_support::*;
use super::*;
use crate::cache::{
    CachedDerivationAtermPath, CachedDerivationOutputPath, CachedDerivationOutputPaths,
    CachedStaticDerivationOutputPathsPayload, MaterializationDecision, PersistBlobKey,
    PersistCache, PersistNodeMetadataKey,
};

#[test]
fn derivation_strict_observes_aterm_early_cutoff_in_eval_cache() {
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "same";
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (identity, free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());

    let first = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let first_cached_path = cache
        .lock()
        .expect("cache lock is valid")
        .lookup_derivation_aterm_path(identity, free_var_hashes.iter().copied(), &first.aterm)
        .expect("derivation ATerm path lookup succeeds")
        .expect("first derivation ATerm path is recorded");
    let second =
        eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let second_cached_path = cache
        .lock()
        .expect("cache lock is valid")
        .lookup_derivation_aterm_path(identity, free_var_hashes.iter().copied(), &second.aterm)
        .expect("derivation ATerm path lookup succeeds")
        .expect("second derivation ATerm path is recorded");

    assert_eq!(second.path, first.path);
    assert_eq!(second.aterm, first.aterm);
    assert_eq!(first_cached_path, first.path.as_bytes());
    assert_eq!(second_cached_path, second.path.as_bytes());
    assert_eq!(first.early_cutoffs, 0);
    assert_eq!(second.early_cutoffs, 1);
    assert_eq!((first.cache_hits, first.cache_misses), (0, 0));
    assert_eq!((second.cache_hits, second.cache_misses), (0, 0));
    assert_eq!((first.force_hits, first.force_misses), (0, 0));
    assert_eq!((second.force_hits, second.force_misses), (0, 0));
    assert_eq!(first.path_reuses, 0);
    assert_eq!(second.path_reuses, 1);
    assert_eq!(first.output_path_reuses, 0);
    assert_eq!(second.output_path_reuses, 1);
    assert!(first.text_path_calculations > 0);
    assert_eq!(second.text_path_calculations, 0);
    assert_eq!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("runtime is enabled")
            .len(),
        2
    );
}

#[test]
fn derivation_strict_reuses_aterm_paths_for_floating_and_impure_outputs() {
    for source in [
        r#"derivationStrict {
            name = "floating";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __contentAddressed = true;
            outputHashAlgo = "sha256";
            outputHashMode = "recursive";
        }"#,
        r#"derivationStrict {
            name = "impure";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __impure = true;
        }"#,
    ] {
        let ir = lower(source);
        let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
        let first =
            eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
        let second =
            eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());

        assert_eq!(second.path, first.path);
        assert_eq!(second.aterm, first.aterm);
        assert_eq!((first.cache_hits, first.cache_misses), (0, 0));
        assert_eq!((second.cache_hits, second.cache_misses), (0, 0));
        assert_eq!((first.force_hits, first.force_misses), (0, 0));
        assert_eq!((second.force_hits, second.force_misses), (0, 0));
        assert_eq!(first.path_reuses, 0);
        assert_eq!(second.path_reuses, 1);
        assert_eq!(first.output_path_reuses, 0);
        assert_eq!(second.output_path_reuses, 0);
    }
}

#[test]
fn derivation_strict_does_not_reuse_deferred_placeholder_drv_paths() {
    let source = r#"let
        base = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __contentAddressed = true;
            outputHashAlgo = "sha256";
            outputHashMode = "recursive";
        };
    in derivationStrict {
        name = "downstream";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        input = base.out;
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let first = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache.clone(),
    )
    .expect("first derivation graph evaluates");
    let second = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache,
    )
    .expect("second derivation graph evaluates");

    assert_eq!(first.derivations().len(), 2);
    assert_eq!(second.derivations().len(), 2);
    assert_eq!(first.stats().derivation_aterm_path_reuses(), 0);
    assert_eq!(second.stats().derivation_aterm_path_reuses(), 1);
    assert_eq!(second.stats().cache_hits(), 0);
    assert_eq!(second.stats().force_cache_hits(), 0);
}

#[test]
fn derivation_strict_cached_aterm_paths_miss_for_store_dir_mismatches() {
    let source = r#"derivationStrict {
        name = "floating";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        __contentAddressed = true;
        outputHashAlgo = "sha256";
        outputHashMode = "recursive";
    }"#;
    let ir = lower(source);
    let first_store = unique_temp_dir("derivation-aterm-path-first-store");
    let second_store = unique_temp_dir("derivation-aterm-path-second-store");
    let first_options =
        enabled_eval_cache_options_with_store_dir(first_store.as_os_str().as_bytes().to_vec());
    let second_options =
        enabled_eval_cache_options_with_store_dir(second_store.as_os_str().as_bytes().to_vec());
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let first = eval_single_derivation_with_cache(&ir, first_options, cache.clone());
    let second = eval_single_derivation_with_cache(&ir, second_options, cache);

    assert!(first.path.starts_with(&path_source(&first_store)));
    assert!(second.path.starts_with(&path_source(&second_store)));
    assert_eq!(first.aterm, second.aterm);
    assert_eq!(first.path_reuses, 0);
    assert_eq!(second.path_reuses, 0);
    assert_eq!(first.output_path_reuses, 0);
    assert_eq!(second.output_path_reuses, 0);
    fs::remove_dir_all(first_store).expect("first store temp directory removes");
    fs::remove_dir_all(second_store).expect("second store temp directory removes");
}

#[test]
fn derivation_strict_cached_aterm_paths_miss_for_invalid_cached_path_names() {
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "same";
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let first = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let (identity, free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());
    cache
        .lock()
        .expect("cache lock is valid")
        .observe_derivation_aterm_expression_path(
            identity,
            free_var_hashes.iter().copied(),
            &first.aterm,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrong.drv",
        )
        .expect("corrupt derivation ATerm path record writes");

    let second =
        eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let repaired_path = cache
        .lock()
        .expect("cache lock is valid")
        .lookup_derivation_aterm_path(identity, free_var_hashes.iter().copied(), &second.aterm)
        .expect("repaired path lookup succeeds")
        .expect("repaired path record exists");

    assert_eq!(second.path, first.path);
    assert_eq!(second.path_reuses, 0);
    assert_eq!(second.output_path_reuses, 1);
    assert_eq!(repaired_path, first.path.as_bytes());
}

#[test]
fn derivation_strict_cached_aterm_paths_miss_outside_configured_store() {
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "same";
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let first = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let (identity, free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());
    cache
        .lock()
        .expect("cache lock is valid")
        .observe_derivation_aterm_expression_path(
            identity,
            free_var_hashes.iter().copied(),
            &first.aterm,
            b"/different/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("outside-store derivation ATerm path record writes");

    let second =
        eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let repaired_path = cache
        .lock()
        .expect("cache lock is valid")
        .lookup_derivation_aterm_path(identity, free_var_hashes.iter().copied(), &second.aterm)
        .expect("repaired path lookup succeeds")
        .expect("repaired path record exists");

    assert_eq!(second.path, first.path);
    assert_eq!(second.path_reuses, 0);
    assert_eq!(second.output_path_reuses, 1);
    assert_eq!(repaired_path, first.path.as_bytes());
}

#[test]
fn derivation_strict_cached_static_output_paths_miss_for_invalid_cached_path_names() {
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let first = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let (identity, free_var_hashes) =
        static_derivation_outputs_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());
    let pre_output_aterm = static_derivation_pre_output_aterm();
    cache
        .lock()
        .expect("cache lock is valid")
        .observe_static_derivation_output_paths(
            identity,
            free_var_hashes.iter().copied(),
            &pre_output_aterm,
            CachedDerivationOutputPaths::new(
                [9; 32],
                vec![CachedDerivationOutputPath::new(
                    b"out".to_vec(),
                    b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrong".to_vec(),
                )],
            ),
        )
        .expect("corrupt static output path record writes");

    let second =
        eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let repaired = cache
        .lock()
        .expect("cache lock is valid")
        .lookup_static_derivation_output_paths(
            identity,
            free_var_hashes.iter().copied(),
            &pre_output_aterm,
        )
        .expect("repaired static output path lookup succeeds")
        .expect("repaired static output path record exists");

    assert_eq!(second.path, first.path);
    assert_eq!(second.aterm, first.aterm);
    assert_eq!(second.output_path_reuses, 0);
    assert_eq!(repaired.output_paths().len(), 1);
    assert_eq!(repaired.output_paths()[0].name(), b"out");
    assert!(repaired.output_paths()[0].path().ends_with(b"-x"));
    assert_ne!(
        repaired.output_paths()[0].path(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrong"
    );
}

#[test]
fn persistent_static_derivation_output_paths_reuse_preserves_drv_surface() {
    let persist_root = unique_temp_dir("static-output-path-persist");
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
    }"#;
    let ir = lower(source);
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );

    let mut first_options = enabled_eval_cache_options();
    first_options.set_persist_cache_root(&persist_root);
    let first = eval_single_derivation_with_cache(
        &ir,
        first_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    let mut hit_options = enabled_eval_cache_options();
    hit_options.set_persist_cache_root(&persist_root);
    let hit = eval_single_derivation_with_cache(
        &ir,
        hit_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(first.path, uncached.path);
    assert_eq!(hit.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert_eq!(hit.aterm, uncached.aterm);
    assert_eq!(first.output_path_reuses, 0);
    assert_eq!(hit.output_path_reuses, 1);
    assert!(first.hash_calculations > 0);
    assert_eq!(hit.hash_calculations, 0);
    assert_eq!(first.path_reuses, 0);
    assert_eq!(hit.path_reuses, 1);
    assert!(first.text_path_calculations > 0);
    assert_eq!(hit.text_path_calculations, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn disabled_eval_cache_option_skips_persistent_derivation_side_records() {
    let persist_root = unique_temp_dir("derivation-side-records-cache-disabled");
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
    }"#;
    let ir = lower(source);
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );

    let mut disabled_options = TreeWalkOptions::new();
    disabled_options.set_persist_cache_root(&persist_root);
    let disabled = eval_single_derivation_with_cache(
        &ir,
        disabled_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    assert_eq!(disabled.path, uncached.path);
    assert_eq!(disabled.aterm, uncached.aterm);
    assert_eq!(disabled.output_path_reuses, 0);
    assert_eq!(disabled.path_reuses, 0);
    let disabled_entries = fs::read_dir(&persist_root)
        .expect("persistent temp root is readable")
        .collect::<Result<Vec<_>, _>>()
        .expect("persistent temp root entries read");
    assert!(
        disabled_entries.is_empty(),
        "eval-cache-disabled derivation side records must not open or write the persistent root"
    );

    let mut cold_options = enabled_eval_cache_options();
    cold_options.set_persist_cache_root(&persist_root);
    let cold = eval_single_derivation_with_cache(
        &ir,
        cold_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    assert_eq!(cold.path, uncached.path);
    assert_eq!(cold.aterm, uncached.aterm);
    assert_eq!(cold.output_path_reuses, 0);
    assert_eq!(cold.path_reuses, 0);
    assert!(cold.hash_calculations > 0);
    assert!(cold.text_path_calculations > 0);

    let mut hit_options = enabled_eval_cache_options();
    hit_options.set_persist_cache_root(&persist_root);
    let hit = eval_single_derivation_with_cache(
        &ir,
        hit_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    assert_eq!(hit.path, uncached.path);
    assert_eq!(hit.aterm, uncached.aterm);
    assert_eq!(hit.output_path_reuses, 1);
    assert_eq!(hit.path_reuses, 1);
    assert_eq!(hit.hash_calculations, 0);
    assert_eq!(hit.text_path_calculations, 0);

    let mut disabled_after_seed_options = TreeWalkOptions::new();
    disabled_after_seed_options.set_persist_cache_root(&persist_root);
    let disabled_after_seed = eval_single_derivation_with_cache(
        &ir,
        disabled_after_seed_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    assert_eq!(disabled_after_seed.path, uncached.path);
    assert_eq!(disabled_after_seed.aterm, uncached.aterm);
    assert_eq!(disabled_after_seed.output_path_reuses, 0);
    assert_eq!(disabled_after_seed.path_reuses, 0);
    assert!(
        disabled_after_seed.hash_calculations > 0,
        "eval-cache-disabled derivations must ignore existing persistent static-output records"
    );
    assert!(
        disabled_after_seed.text_path_calculations > 0,
        "eval-cache-disabled derivations must ignore existing persistent ATerm path records"
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_static_derivation_output_paths_miss_for_aterm_mismatch_preserves_drv_surface() {
    let persist_root = unique_temp_dir("static-output-path-stale-aterm");
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
    }"#;
    let ir = lower(source);
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );
    let (identity, free_var_hashes) = static_derivation_outputs_cache_subject(
        &ir,
        enabled_eval_cache_options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let stale_payload = CachedStaticDerivationOutputPathsPayload::new(
        static_derivation_pre_output_aterm_with_env(Some("stale")),
        CachedDerivationOutputPaths::new(
            [9; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
            )],
        ),
    );
    let stale_value_hash = stale_payload.value_hash();
    let stale_payload_bytes = stale_payload
        .encode_persistent_payload()
        .expect("stale persistent static output payload encodes");
    {
        let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
        persist_cache
            .materialize_blob_indexed(
                PersistBlobKey::for_value(stale_value_hash.as_durable_hash()),
                &stale_payload_bytes,
                MaterializationDecision::Materialize,
            )
            .expect("stale persistent static output payload writes");
        persist_cache
            .record_node_materialized_value_hash(
                PersistNodeMetadataKey::for_expression(identity, free_var_hashes.iter().copied()),
                stale_value_hash,
            )
            .expect("stale persistent static output metadata writes");
    }

    let mut stale_options = enabled_eval_cache_options();
    stale_options.set_persist_cache_root(&persist_root);
    let stale_miss = eval_single_derivation_with_cache(
        &ir,
        stale_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    let mut repaired_options = enabled_eval_cache_options();
    repaired_options.set_persist_cache_root(&persist_root);
    let repaired_hit = eval_single_derivation_with_cache(
        &ir,
        repaired_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(stale_miss.path, uncached.path);
    assert_eq!(repaired_hit.path, uncached.path);
    assert_eq!(stale_miss.aterm, uncached.aterm);
    assert_eq!(repaired_hit.aterm, uncached.aterm);
    assert_eq!(stale_miss.output_path_reuses, 0);
    assert_eq!(repaired_hit.output_path_reuses, 1);
    assert!(stale_miss.hash_calculations > 0);
    assert_eq!(repaired_hit.hash_calculations, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_static_derivation_output_paths_miss_for_invalid_path_preserves_drv_surface() {
    let persist_root = unique_temp_dir("static-output-path-invalid-path");
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
    }"#;
    let ir = lower(source);
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );
    let (identity, free_var_hashes) = static_derivation_outputs_cache_subject(
        &ir,
        enabled_eval_cache_options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let pre_output_aterm = static_derivation_pre_output_aterm();
    let invalid_output_paths = CachedDerivationOutputPaths::new(
        [9; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrong".to_vec(),
        )],
    );
    let invalid_payload = CachedStaticDerivationOutputPathsPayload::new(
        pre_output_aterm.clone(),
        invalid_output_paths,
    );
    let invalid_value_hash = invalid_payload.value_hash();
    let invalid_payload_bytes = invalid_payload
        .encode_persistent_payload()
        .expect("invalid persistent static output payload encodes");
    {
        let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
        persist_cache
            .materialize_blob_indexed(
                PersistBlobKey::for_value(invalid_value_hash.as_durable_hash()),
                &invalid_payload_bytes,
                MaterializationDecision::Materialize,
            )
            .expect("invalid persistent static output payload writes");
        persist_cache
            .record_node_materialized_value_hash(
                PersistNodeMetadataKey::for_expression(identity, free_var_hashes.iter().copied()),
                invalid_value_hash,
            )
            .expect("invalid persistent static output metadata writes");
    }

    let mut invalid_options = enabled_eval_cache_options();
    invalid_options.set_persist_cache_root(&persist_root);
    let invalid_miss = eval_single_derivation_with_cache(
        &ir,
        invalid_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    let mut repaired_options = enabled_eval_cache_options();
    repaired_options.set_persist_cache_root(&persist_root);
    let repaired_hit = eval_single_derivation_with_cache(
        &ir,
        repaired_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(invalid_miss.path, uncached.path);
    assert_eq!(repaired_hit.path, uncached.path);
    assert_eq!(invalid_miss.aterm, uncached.aterm);
    assert_eq!(repaired_hit.aterm, uncached.aterm);
    assert_eq!(invalid_miss.output_path_reuses, 0);
    assert_eq!(repaired_hit.output_path_reuses, 1);
    assert!(invalid_miss.hash_calculations > 0);
    assert_eq!(repaired_hit.hash_calculations, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn derivation_strict_cached_aterm_path_reuse_preserves_drv_surfaces() {
    for (source, expected_output_path_reuses) in [
        (
            r#"derivationStrict {
            name = "static";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = "same";
        }"#,
            1,
        ),
        (
            r#"derivationStrict {
            name = "floating";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __contentAddressed = true;
            outputHashAlgo = "sha256";
            outputHashMode = "recursive";
        }"#,
            0,
        ),
        (
            r#"derivationStrict {
            name = "impure";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __impure = true;
        }"#,
            0,
        ),
    ] {
        let ir = lower(source);
        let uncached = eval_single_derivation_with_cache(
            &ir,
            TreeWalkOptions::new(),
            Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
        );
        let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
        let first =
            eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
        let reuse = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache);

        assert_eq!(first.path, uncached.path);
        assert_eq!(reuse.path, uncached.path);
        assert_eq!(first.aterm, uncached.aterm);
        assert_eq!(reuse.aterm, uncached.aterm);
        assert_eq!(uncached.path_reuses, 0);
        assert_eq!(first.path_reuses, 0);
        assert_eq!(reuse.path_reuses, 1);
        assert_eq!(uncached.output_path_reuses, 0);
        assert_eq!(first.output_path_reuses, 0);
        assert_eq!(reuse.output_path_reuses, expected_output_path_reuses);
        assert!(uncached.text_path_calculations > 0);
        assert!(first.text_path_calculations > 0);
        assert_eq!(reuse.text_path_calculations, 0);
        if expected_output_path_reuses > 0 {
            assert!(first.hash_calculations > 0);
            assert_eq!(reuse.hash_calculations, 0);
        }
    }
}

#[test]
fn persistent_derivation_aterm_path_reuse_preserves_drv_surface() {
    let persist_root = unique_temp_dir("derivation-aterm-path-persist");
    let source = r#"derivationStrict {
        name = "floating";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        __contentAddressed = true;
        outputHashAlgo = "sha256";
        outputHashMode = "recursive";
    }"#;
    let ir = lower(source);
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );

    let mut first_options = enabled_eval_cache_options();
    first_options.set_persist_cache_root(&persist_root);
    let first = eval_single_derivation_with_cache(
        &ir,
        first_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    let mut hit_options = enabled_eval_cache_options();
    hit_options.set_persist_cache_root(&persist_root);
    let hit = eval_single_derivation_with_cache(
        &ir,
        hit_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(first.path, uncached.path);
    assert_eq!(hit.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert_eq!(hit.aterm, uncached.aterm);
    assert_eq!(uncached.path_reuses, 0);
    assert_eq!(first.path_reuses, 0);
    assert_eq!(hit.path_reuses, 1);
    assert_eq!(first.output_path_reuses, 0);
    assert_eq!(hit.output_path_reuses, 0);
    assert!(first.text_path_calculations > 0);
    assert_eq!(hit.text_path_calculations, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_derivation_aterm_path_miss_for_aterm_mismatch_preserves_drv_surface() {
    let persist_root = unique_temp_dir("derivation-aterm-path-stale-aterm");
    let source = r#"derivationStrict {
        name = "floating";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        __contentAddressed = true;
        outputHashAlgo = "sha256";
        outputHashMode = "recursive";
    }"#;
    let ir = lower(source);
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );
    let (identity, free_var_hashes) = derivation_aterm_cache_subject(
        &ir,
        enabled_eval_cache_options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let stale_payload = CachedDerivationAtermPath::new(
        b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"stale\")])".to_vec(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-floating.drv".to_vec(),
    );
    let stale_value_hash = stale_payload.value_hash();
    let stale_payload_bytes = stale_payload
        .encode_persistent_payload()
        .expect("stale persistent payload encodes");
    {
        let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
        persist_cache
            .materialize_blob_indexed(
                PersistBlobKey::for_value(stale_value_hash.as_durable_hash()),
                &stale_payload_bytes,
                MaterializationDecision::Materialize,
            )
            .expect("stale persistent payload writes");
        persist_cache
            .record_node_materialized_value_hash(
                PersistNodeMetadataKey::for_expression(identity, free_var_hashes.iter().copied()),
                stale_value_hash,
            )
            .expect("stale persistent metadata writes");
    }

    let mut stale_options = enabled_eval_cache_options();
    stale_options.set_persist_cache_root(&persist_root);
    let stale_miss = eval_single_derivation_with_cache(
        &ir,
        stale_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    let mut repaired_options = enabled_eval_cache_options();
    repaired_options.set_persist_cache_root(&persist_root);
    let repaired_hit = eval_single_derivation_with_cache(
        &ir,
        repaired_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(stale_miss.path, uncached.path);
    assert_eq!(repaired_hit.path, uncached.path);
    assert_eq!(stale_miss.aterm, uncached.aterm);
    assert_eq!(repaired_hit.aterm, uncached.aterm);
    assert_eq!(stale_miss.path_reuses, 0);
    assert_eq!(repaired_hit.path_reuses, 1);
    assert!(stale_miss.text_path_calculations > 0);
    assert_eq!(repaired_hit.text_path_calculations, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_derivation_aterm_path_miss_for_invalid_path_preserves_drv_surface() {
    let persist_root = unique_temp_dir("derivation-aterm-path-invalid-path");
    let source = r#"derivationStrict {
        name = "floating";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        __contentAddressed = true;
        outputHashAlgo = "sha256";
        outputHashMode = "recursive";
    }"#;
    let ir = lower(source);
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );
    let (identity, free_var_hashes) = derivation_aterm_cache_subject(
        &ir,
        enabled_eval_cache_options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let invalid_payload = CachedDerivationAtermPath::new(
        uncached.aterm.clone(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrong.drv".to_vec(),
    );
    let invalid_value_hash = invalid_payload.value_hash();
    let invalid_payload_bytes = invalid_payload
        .encode_persistent_payload()
        .expect("invalid persistent payload encodes");
    {
        let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
        persist_cache
            .materialize_blob_indexed(
                PersistBlobKey::for_value(invalid_value_hash.as_durable_hash()),
                &invalid_payload_bytes,
                MaterializationDecision::Materialize,
            )
            .expect("invalid persistent payload writes");
        persist_cache
            .record_node_materialized_value_hash(
                PersistNodeMetadataKey::for_expression(identity, free_var_hashes.iter().copied()),
                invalid_value_hash,
            )
            .expect("invalid persistent metadata writes");
    }

    let mut invalid_options = enabled_eval_cache_options();
    invalid_options.set_persist_cache_root(&persist_root);
    let invalid_miss = eval_single_derivation_with_cache(
        &ir,
        invalid_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    let mut repaired_options = enabled_eval_cache_options();
    repaired_options.set_persist_cache_root(&persist_root);
    let repaired_hit = eval_single_derivation_with_cache(
        &ir,
        repaired_options,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(invalid_miss.path, uncached.path);
    assert_eq!(repaired_hit.path, uncached.path);
    assert_eq!(invalid_miss.aterm, uncached.aterm);
    assert_eq!(repaired_hit.aterm, uncached.aterm);
    assert_eq!(invalid_miss.path_reuses, 0);
    assert_eq!(repaired_hit.path_reuses, 1);
    assert!(invalid_miss.text_path_calculations > 0);
    assert_eq!(repaired_hit.text_path_calculations, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn derivation_strict_cached_static_closure_reuse_preserves_drv_surfaces() {
    let source = r#"let
        base = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = "same";
        };
        sibling = derivationStrict {
            name = "sibling";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = "same";
        };
    in derivationStrict {
        name = "downstream";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        input = base.out;
        other = sibling.drvPath;
    }"#;
    let ir = lower(source);
    let uncached = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        None,
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    )
    .expect("uncached static derivation graph evaluates");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let first = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache.clone(),
    )
    .expect("first cached static derivation graph evaluates");
    let reuse = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache.clone(),
    )
    .expect("reuse static derivation graph evaluates");
    let uncached_surfaces = derivation_surfaces(&uncached);

    assert_eq!(uncached_surfaces.len(), 3);
    assert!(
        uncached_surfaces
            .iter()
            .any(|(path, _)| path.ends_with("-base.drv"))
    );
    assert!(
        uncached_surfaces
            .iter()
            .any(|(path, _)| path.ends_with("-sibling.drv"))
    );
    assert!(
        uncached_surfaces
            .iter()
            .any(|(path, _)| path.ends_with("-downstream.drv"))
    );
    assert_eq!(derivation_surfaces(&first), uncached_surfaces);
    assert_eq!(derivation_surfaces(&reuse), uncached_surfaces);
    assert_eq!(uncached.stats().derivation_aterm_path_reuses(), 0);
    assert_eq!(uncached.stats().static_derivation_output_path_reuses(), 0);
    assert_eq!(first.stats().derivation_aterm_path_reuses(), 0);
    assert_eq!(first.stats().static_derivation_output_path_reuses(), 0);
    assert!(first.stats().derivation_hash_calculations() > 0);
    assert!(first.stats().derivation_text_path_calculations() > 0);
    assert_eq!(reuse.stats().derivation_aterm_path_reuses(), 3);
    assert_eq!(reuse.stats().static_derivation_output_path_reuses(), 3);
    assert!(
        reuse.stats().derivation_hash_calculations() < first.stats().derivation_hash_calculations()
    );
    assert!(
        reuse.stats().derivation_text_path_calculations()
            < first.stats().derivation_text_path_calculations()
    );
    assert_eq!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("runtime is enabled")
            .derivation_aterm_path_record_count(),
        3
    );
    assert_eq!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("runtime is enabled")
            .static_derivation_output_path_record_count(),
        3
    );
}
