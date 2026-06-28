//! Tree-walk evaluator tests for derivation cache path reuse.

use super::derivation_2_support::*;
use super::*;
use crate::cache::{
    CacheExprIdentity, CachedDerivationAtermPath, CachedDerivationOutputPath,
    CachedDerivationOutputPaths, CachedStaticDerivationOutputPathsPayload, DemandCacheKey,
    DemandDependencyGroup, DurableBlake3Hash, MaterializationDecision, NodeFreshness,
    PersistBlobKey, PersistCache, PersistNodeMetadataKey, ValueHash,
};

fn test_cache_identity(label: &[u8], node: u32) -> CacheExprIdentity {
    CacheExprIdentity::new(DurableBlake3Hash::for_bytes(label), IrId::new(node))
}

fn test_value_hash(label: &[u8]) -> ValueHash {
    ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(label))
}

fn attach_dirty_memo_read_supplier(
    runtime: &Arc<Mutex<EvalCacheRuntime>>,
    dependent_identity: CacheExprIdentity,
    dependent_free_var_hashes: &[DurableBlake3Hash],
    supplier_label: &'static [u8],
) {
    let mut runtime = runtime.lock().expect("cache lock is valid");
    let cache = runtime.cache_mut().expect("runtime is enabled");
    let supplier = cache
        .get_or_insert_expression_node(
            test_cache_identity(supplier_label, 9000),
            std::iter::empty::<DurableBlake3Hash>(),
            Some(test_value_hash(supplier_label)),
        )
        .expect("supplier node inserts");
    cache
        .test_mark_dirty_node(supplier)
        .expect("supplier node dirties");
    let dependent = cache
        .get_or_insert_expression_node(
            dependent_identity,
            dependent_free_var_hashes.iter().copied(),
            Some(test_value_hash(b"dirty-persistent-hit-dependent")),
        )
        .expect("dependent node inserts");
    cache
        .record_memo_read_dependency(dependent, supplier)
        .expect("dirty supplier memo-read edge records");
}

fn assert_no_persistent_materialized_value(
    persist_root: &std::path::Path,
    identity: CacheExprIdentity,
    free_var_value_hashes: &[DurableBlake3Hash],
    context: &str,
) {
    let persist = PersistCache::open(persist_root).expect("persistent cache opens");
    let key =
        PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(key)
            .expect("persistent metadata lookup succeeds"),
        None,
        "{context} should clear the live persistent side-record link"
    );
}

fn assert_persistent_materialized_value(
    persist_root: &std::path::Path,
    identity: CacheExprIdentity,
    free_var_value_hashes: &[DurableBlake3Hash],
    context: &str,
) {
    let persist = PersistCache::open(persist_root).expect("persistent cache opens");
    let key =
        PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
    assert!(
        persist
            .lookup_node_materialized_value_hash(key)
            .expect("persistent metadata lookup succeeds")
            .is_some(),
        "{context} should link a live persistent side-record payload"
    );
}

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
fn derivation_strict_final_aterm_node_records_child_memo_read_edges() {
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        args = [ "alpha" "beta" ];
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (identity, free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());

    let run = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());

    assert_eq!(run.path_reuses, 0);
    let parent_key = DemandCacheKey::for_free_vars(identity, free_var_hashes.iter().copied())
        .expect("derivation ATerm runtime key builds");
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let parent_node = cache
        .graph()
        .node_id_for_key(parent_key)
        .expect("final ATerm node is present");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("final ATerm graph node is present");
    let memo_reads = parent
        .dependencies_in_group(DemandDependencyGroup::MemoRead)
        .expect("final ATerm node has memo-read dependencies");
    assert!(
        !memo_reads.is_empty(),
        "forced derivation fields should become final ATerm memo-read dependencies"
    );
    for dependency in memo_reads {
        assert!(
            cache
                .graph()
                .node(*dependency)
                .expect("memo-read dependency node is present")
                .dependents()
                .contains(&parent_node),
            "memo-read dependencies should record the final ATerm node as a reverse dependent"
        );
    }
}

#[test]
fn derivation_strict_final_aterm_node_records_argument_memo_read_edges() {
    let source = r#"builtins.derivationStrict (
        let forced = [ "from-argument" ]; in
        builtins.seq forced {
            name = "x";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        }
    )"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (identity, free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());

    let run = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());

    assert_eq!(run.path_reuses, 0);
    let parent_key = DemandCacheKey::for_free_vars(identity, free_var_hashes.iter().copied())
        .expect("derivation ATerm runtime key builds");
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let parent_node = cache
        .graph()
        .node_id_for_key(parent_key)
        .expect("final ATerm node is present");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("final ATerm graph node is present");
    let memo_reads = parent
        .dependencies_in_group(DemandDependencyGroup::MemoRead)
        .expect("final ATerm node has memo-read dependencies");
    assert!(
        !memo_reads.is_empty(),
        "memoized reads used while producing the derivation argument should be captured"
    );
}

#[test]
fn derivation_strict_final_aterm_node_records_static_output_path_hits() {
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "same";
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (final_identity, final_free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());
    let (static_identity, static_free_var_hashes) =
        static_derivation_outputs_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());

    let first = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let second =
        eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());

    assert_eq!(second.path, first.path);
    assert_eq!(second.aterm, first.aterm);
    assert_eq!(second.output_path_reuses, 1);
    assert_eq!(second.path_reuses, 1);
    let final_key =
        DemandCacheKey::for_free_vars(final_identity, final_free_var_hashes.iter().copied())
            .expect("final ATerm runtime key builds");
    let static_key =
        DemandCacheKey::for_free_vars(static_identity, static_free_var_hashes.iter().copied())
            .expect("static output runtime key builds");
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let final_node = cache
        .graph()
        .node_id_for_key(final_key)
        .expect("final ATerm node is present");
    let static_node = cache
        .graph()
        .node_id_for_key(static_key)
        .expect("static output node is present");
    let final_graph_node = cache
        .graph()
        .node(final_node)
        .expect("final ATerm graph node is present");
    assert!(
        final_graph_node
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("final ATerm node has memo-read dependencies")
            .contains(&static_node),
        "reused static output paths should be a memo-read dependency of the final ATerm node"
    );
    assert!(
        cache
            .graph()
            .node(static_node)
            .expect("static output graph node is present")
            .dependents()
            .contains(&final_node),
        "the static output node should record the final ATerm node as a reverse dependent"
    );
}

#[test]
fn derivation_strict_revalidates_dirty_aterm_and_static_output_side_records() {
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "same";
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (final_identity, final_free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());
    let (static_identity, static_free_var_hashes) =
        static_derivation_outputs_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());

    let first = eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());
    let final_key =
        DemandCacheKey::for_free_vars(final_identity, final_free_var_hashes.iter().copied())
            .expect("final ATerm runtime key builds");
    let static_key =
        DemandCacheKey::for_free_vars(static_identity, static_free_var_hashes.iter().copied())
            .expect("static output runtime key builds");
    let (final_node, static_node) = {
        let mut runtime = cache.lock().expect("cache lock is valid");
        let cache_view = runtime.cache().expect("cache is enabled");
        let final_node = cache_view
            .graph()
            .node_id_for_key(final_key)
            .expect("final ATerm node is present");
        let static_node = cache_view
            .graph()
            .node_id_for_key(static_key)
            .expect("static output node is present");

        runtime
            .test_mark_dirty_node(static_node)
            .expect("static output node dirties")
            .expect("runtime is enabled");
        runtime
            .test_mark_dirty_node(final_node)
            .expect("final ATerm node dirties")
            .expect("runtime is enabled");

        let cache_view = runtime.cache().expect("cache is enabled");
        assert_eq!(
            cache_view
                .graph()
                .node(static_node)
                .expect("static output node is present")
                .freshness(),
            NodeFreshness::Dirty
        );
        assert_eq!(
            cache_view
                .graph()
                .node(final_node)
                .expect("final ATerm node is present")
                .freshness(),
            NodeFreshness::Dirty
        );
        (final_node, static_node)
    };

    let second =
        eval_single_derivation_with_cache(&ir, enabled_eval_cache_options(), cache.clone());

    assert_eq!(second.path, first.path);
    assert_eq!(second.aterm, first.aterm);
    assert_eq!(second.output_path_reuses, 1);
    assert_eq!(second.path_reuses, 1);
    assert_eq!(second.hash_calculations, 0);
    assert_eq!(second.text_path_calculations, 0);
    assert_eq!(second.early_cutoffs, 2);
    let runtime = cache.lock().expect("cache lock is valid");
    let cache_view = runtime.cache().expect("cache is enabled");
    assert_eq!(
        cache_view
            .graph()
            .node(static_node)
            .expect("static output node is present")
            .freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(
        cache_view
            .graph()
            .node(final_node)
            .expect("final ATerm node is present")
            .freshness(),
        NodeFreshness::Clean
    );
}

#[test]
fn derivation_strict_errors_preserve_prior_final_aterm_memo_read_edges() {
    let source = r#"derivationStrict {
        name = "broken";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        args = [ "child" ];
        bad = {};
    }"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (identity, free_var_hashes) =
        derivation_aterm_cache_subject(&ir, enabled_eval_cache_options(), cache.clone());
    let parent_node;
    let stale_node;
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        parent_node = runtime
            .get_or_insert_expression_node(identity, free_var_hashes.iter().copied(), None)
            .expect("parent node allocation succeeds")
            .expect("cache is enabled");
        stale_node = runtime
            .get_or_insert_expression_node(
                CacheExprIdentity::new(
                    DurableBlake3Hash::for_bytes(b"stale-derivation-aterm-memo-read"),
                    IrId::new(4096),
                ),
                std::iter::empty::<DurableBlake3Hash>(),
                None,
            )
            .expect("stale node allocation succeeds")
            .expect("cache is enabled");
        runtime
            .replace_memo_read_dependencies(parent_node, [stale_node])
            .expect("stale memo-read replacement succeeds")
            .expect("cache is enabled");
    }

    eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache.clone(),
    )
    .expect_err("invalid derivation field fails after forcing args");

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("final ATerm graph node is present");
    let memo_reads = parent
        .dependencies_in_group(DemandDependencyGroup::MemoRead)
        .expect("prior memo-read dependencies remain present");
    assert_eq!(
        memo_reads.len(),
        1,
        "failed derivationStrict must leave prior final ATerm memo-read edges unchanged"
    );
    assert!(
        memo_reads.contains(&stale_node),
        "failed derivationStrict should preserve the stale memo-read dependency"
    );
}

#[test]
fn derivation_strict_reuses_aterm_paths_for_floating_and_impure_outputs() {
    for (source, replayed_hash_derivation_modulo) in [
        (
            r#"derivationStrict {
            name = "floating";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __contentAddressed = true;
            outputHashAlgo = "sha256";
            outputHashMode = "recursive";
        }"#,
            true,
        ),
        (
            r#"derivationStrict {
            name = "impure";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __impure = true;
        }"#,
            false,
        ),
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
        if replayed_hash_derivation_modulo {
            assert!(first.hash_calculations > 0);
            assert_eq!(second.hash_calculations, 0);
        }
    }
}

#[test]
fn floating_ca_path_reuse_recomputes_modulo_with_deferred_inputs() {
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
        __contentAddressed = true;
        outputHashAlgo = "sha256";
        outputHashMode = "recursive";
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
    .expect("first floating derivation graph evaluates");
    let second = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache,
    )
    .expect("second floating derivation graph evaluates");

    assert_eq!(derivation_surfaces(&second), derivation_surfaces(&first));
    assert_eq!(first.stats().derivation_aterm_path_reuses(), 0);
    assert_eq!(second.stats().derivation_aterm_path_reuses(), 2);
    assert_eq!(second.stats().derivation_text_path_calculations(), 0);
    assert!(
        second.stats().derivation_hash_calculations() > 0,
        "floating-CA derivations with deferred inputs must recompute the modulo hash"
    );
    assert!(
        second.stats().derivation_hash_calculations()
            < first.stats().derivation_hash_calculations()
    );
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
fn derivation_strict_dirty_cached_aterm_path_validates_before_reuse_or_cutoff_stat() {
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
    let final_key = DemandCacheKey::for_free_vars(identity, free_var_hashes.iter().copied())
        .expect("final ATerm runtime key builds");
    let final_node = {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_derivation_aterm_expression_path(
                identity,
                free_var_hashes.iter().copied(),
                &first.aterm,
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrong.drv",
            )
            .expect("corrupt derivation ATerm path record writes");
        let final_node = runtime
            .cache()
            .expect("runtime is enabled")
            .graph()
            .node_id_for_key(final_key)
            .expect("final ATerm node is present");
        runtime
            .test_mark_dirty_node(final_node)
            .expect("final ATerm node dirties")
            .expect("runtime is enabled");
        final_node
    };

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
    assert_eq!(second.early_cutoffs, 0);
    assert_eq!(repaired_path, first.path.as_bytes());
    assert_eq!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("runtime is enabled")
            .graph()
            .node(final_node)
            .expect("final ATerm node is present")
            .freshness(),
        NodeFreshness::Clean
    );
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
fn persistent_static_derivation_output_paths_hit_rejects_dirty_runtime_supplier() {
    let persist_root = unique_temp_dir("static-output-path-dirty-supplier");
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
    }"#;
    let ir = lower(source);
    let options = || {
        let mut options = enabled_eval_cache_options();
        options.set_persist_cache_root(&persist_root);
        options
    };
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );
    let first = eval_single_derivation_with_cache(
        &ir,
        options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.output_path_reuses, 0);

    let dirty_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (identity, free_var_hashes) =
        static_derivation_outputs_cache_subject(&ir, options(), dirty_runtime.clone());
    attach_dirty_memo_read_supplier(
        &dirty_runtime,
        identity,
        &free_var_hashes,
        b"dirty-persistent-static-supplier",
    );
    let rejected = eval_single_derivation_with_cache(&ir, options(), dirty_runtime);

    assert_eq!(rejected.path, uncached.path);
    assert_eq!(rejected.aterm, uncached.aterm);
    assert_eq!(rejected.output_path_reuses, 0);
    assert!(
        rejected.hash_calculations > 0,
        "dirty supplier should make the persistent static-output hit fall back to output hashing"
    );
    assert_no_persistent_materialized_value(
        &persist_root,
        identity,
        &free_var_hashes,
        "dirty-supplier persistent static-output hit",
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn derivation_frame_close_dirty_supplier_clears_persistent_side_records() {
    let persist_root = unique_temp_dir("derivation-frame-close-dirty-supplier");
    let source = r#"derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        args = [ "alpha" "beta" ];
    }"#;
    let ir = lower(source);
    let options = || {
        let mut options = enabled_eval_cache_options();
        options.set_persist_cache_root(&persist_root);
        options
    };
    let (final_identity, final_free_var_hashes) = derivation_aterm_cache_subject(
        &ir,
        options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let (static_identity, static_free_var_hashes) = static_derivation_outputs_cache_subject(
        &ir,
        options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let first = eval_single_derivation_with_cache(
        &ir,
        options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    assert_eq!(first.path_reuses, 0);
    assert_eq!(first.output_path_reuses, 0);
    assert_persistent_materialized_value(
        &persist_root,
        final_identity,
        &final_free_var_hashes,
        "first-run final ATerm side record",
    );
    assert_persistent_materialized_value(
        &persist_root,
        static_identity,
        &static_free_var_hashes,
        "first-run static-output side record",
    );

    let runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let dirty_supplier = {
        let mut runtime = runtime.lock().expect("cache lock is valid");
        let cache = runtime.cache_mut().expect("cache is enabled");
        let supplier = cache
            .get_or_insert_expression_node(
                test_cache_identity(b"frame-close-dirty-supplier", 9100),
                std::iter::empty::<DurableBlake3Hash>(),
                Some(test_value_hash(b"frame-close-dirty-supplier")),
            )
            .expect("dirty supplier node inserts");
        cache
            .test_mark_dirty_node(supplier)
            .expect("dirty supplier node dirties");
        supplier
    };
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options(), runtime.clone());
    evaluator
        .with_active_derivation_aterm_memo_read_node(ir.root, |eval| {
            eval.record_enclosing_memo_read(dirty_supplier);
            Ok(())
        })
        .expect("derivation frame close succeeds");

    assert_no_persistent_materialized_value(
        &persist_root,
        final_identity,
        &final_free_var_hashes,
        "frame-close dirty-supplier final ATerm side record",
    );
    assert_no_persistent_materialized_value(
        &persist_root,
        static_identity,
        &static_free_var_hashes,
        "frame-close dirty-supplier static-output side record",
    );
    let final_key =
        DemandCacheKey::for_free_vars(final_identity, final_free_var_hashes.iter().copied())
            .expect("final ATerm runtime key builds");
    let runtime = runtime.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let final_node = cache
        .graph()
        .node_id_for_key(final_key)
        .expect("final ATerm node is present");
    assert_eq!(
        cache
            .graph()
            .node(final_node)
            .expect("final ATerm graph node is present")
            .freshness(),
        NodeFreshness::Dirty
    );

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
    for (source, expected_output_path_reuses, expected_hash_calculation_reuse) in [
        (
            r#"derivationStrict {
            name = "static";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = "same";
        }"#,
            1,
            true,
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
            true,
        ),
        (
            r#"derivationStrict {
            name = "impure";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __impure = true;
        }"#,
            0,
            false,
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
        if expected_hash_calculation_reuse {
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
    assert!(first.hash_calculations > 0);
    assert_eq!(hit.hash_calculations, 0);
    assert!(first.text_path_calculations > 0);
    assert_eq!(hit.text_path_calculations, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_derivation_aterm_path_hit_rejects_dirty_runtime_supplier() {
    let persist_root = unique_temp_dir("derivation-aterm-path-dirty-supplier");
    let source = r#"derivationStrict {
        name = "floating";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        __contentAddressed = true;
        outputHashAlgo = "sha256";
        outputHashMode = "recursive";
    }"#;
    let ir = lower(source);
    let options = || {
        let mut options = enabled_eval_cache_options();
        options.set_persist_cache_root(&persist_root);
        options
    };
    let uncached = eval_single_derivation_with_cache(
        &ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    );
    let first = eval_single_derivation_with_cache(
        &ir,
        options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.path_reuses, 0);

    let dirty_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let (identity, free_var_hashes) =
        derivation_aterm_cache_subject(&ir, options(), dirty_runtime.clone());
    attach_dirty_memo_read_supplier(
        &dirty_runtime,
        identity,
        &free_var_hashes,
        b"dirty-persistent-aterm-supplier",
    );
    let rejected = eval_single_derivation_with_cache(&ir, options(), dirty_runtime);

    assert_eq!(rejected.path, uncached.path);
    assert_eq!(rejected.aterm, uncached.aterm);
    assert_eq!(rejected.path_reuses, 0);
    assert!(
        rejected.text_path_calculations > 0,
        "dirty supplier should make the persistent ATerm path hit fall back to path calculation"
    );
    assert_no_persistent_materialized_value(
        &persist_root,
        identity,
        &free_var_hashes,
        "dirty-supplier persistent ATerm path hit",
    );

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
