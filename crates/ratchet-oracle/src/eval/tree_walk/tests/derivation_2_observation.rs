//! Tree-walk evaluator tests for derivation observation and import-cache surfaces.

use super::derivation_2_support::*;
use super::*;
use crate::cache::{
    DemandNodeId, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey, ValueHash,
};
use crate::string::NixString;

#[test]
fn derivation_strict_cached_aterm_path_reuse_preserves_deferred_surfaces() {
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
    let uncached = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        None,
        Arc::new(Mutex::new(EvalCacheRuntime::disabled())),
    )
    .expect("uncached derivation graph evaluates");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let first = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache.clone(),
    )
    .expect("first cached derivation graph evaluates");
    let reuse = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        None,
        cache,
    )
    .expect("reuse derivation graph evaluates");
    let uncached_surfaces = derivation_surfaces(&uncached);
    let first_surfaces = derivation_surfaces(&first);
    let reuse_surfaces = derivation_surfaces(&reuse);

    assert_eq!(uncached_surfaces.len(), 2);
    assert!(
        uncached_surfaces
            .iter()
            .any(|(path, _)| path.ends_with("-base.drv"))
    );
    assert!(
        uncached_surfaces
            .iter()
            .any(|(path, _)| path.ends_with("-downstream.drv"))
    );
    assert_eq!(first_surfaces, uncached_surfaces);
    assert_eq!(reuse_surfaces, uncached_surfaces);
    assert_eq!(uncached.stats().derivation_aterm_path_reuses(), 0);
    assert_eq!(first.stats().derivation_aterm_path_reuses(), 0);
    assert_eq!(reuse.stats().derivation_aterm_path_reuses(), 1);
}

#[test]
fn derivation_strict_records_precomputed_final_aterm_bytes() {
    fn assert_single_precomputed_aterm(source: &str, case_label: &str) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options_and_eval_cache(
            &ir,
            enabled_eval_cache_options(),
            Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
        );

        evaluator.eval_root().expect("derivation evaluates");

        let mut known_derivations = evaluator.known_derivations.iter();
        let (drv_path, known) = known_derivations
            .next()
            .unwrap_or_else(|| panic!("{case_label}: expected one known derivation, got none"));
        assert!(
            known_derivations.next().is_none(),
            "{case_label}: expected exactly one known derivation"
        );
        let cached_aterm = known
            .aterm_bytes
            .as_ref()
            .unwrap_or_else(|| panic!("{case_label}: expected precomputed final ATerm bytes"));
        let expected_aterm = match known.output_resolution {
            DerivationOutputResolution::StaticPaths => {
                evaluator.derivation_aterm_bytes(&known.derivation)
            }
            DerivationOutputResolution::FloatingCa(output) => {
                evaluator.floating_ca_derivation_aterm_bytes(&known.derivation, output, None)
            }
            DerivationOutputResolution::Impure(output) => {
                evaluator.impure_derivation_aterm_bytes(&known.derivation, output, None)
            }
            DerivationOutputResolution::DeferredPlaceholders => {
                panic!("{case_label}: deferred-placeholder derivation should not store ATerm bytes")
            }
        };
        assert_eq!(cached_aterm, &expected_aterm, "{case_label}");

        let snapshot = evaluator
            .derivation_snapshot()
            .expect("derivation snapshot builds");
        let [derivation] = snapshot.as_slice() else {
            panic!("{case_label}: expected one snapshot derivation, got {snapshot:?}");
        };
        assert_eq!(
            derivation.absolute_path(),
            evaluator.store_path_absolute_display(drv_path),
            "{case_label}"
        );
        assert_eq!(
            derivation.aterm_bytes(),
            Some(cached_aterm.as_slice()),
            "{case_label}: derivation snapshots should reuse stored final ATerm bytes"
        );
    }

    assert_single_precomputed_aterm(
        r#"derivationStrict {
            name = "static";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = "same";
        }"#,
        "static",
    );
    assert_single_precomputed_aterm(
        r#"derivationStrict {
            name = "floating";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __contentAddressed = true;
            outputHashAlgo = "sha256";
            outputHashMode = "recursive";
        }"#,
        "floating",
    );
    assert_single_precomputed_aterm(
        r#"derivationStrict {
            name = "impure";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __impure = true;
        }"#,
        "impure",
    );

    let deferred_source = r#"let
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
    let ir = lower(deferred_source);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(
        &ir,
        enabled_eval_cache_options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    evaluator
        .eval_root()
        .expect("deferred derivation graph evaluates");

    let mut saw_base = false;
    let mut saw_downstream = false;
    for (drv_path, known) in &evaluator.known_derivations {
        match drv_path.name().as_str() {
            "base.drv" => {
                saw_base = true;
                assert!(
                    matches!(
                        known.output_resolution,
                        DerivationOutputResolution::FloatingCa(_)
                    ),
                    "base should remain floating-CA"
                );
                assert!(
                    known.aterm_bytes.is_some(),
                    "floating-CA base derivation should store precomputed ATerm bytes"
                );
            }
            "downstream.drv" => {
                saw_downstream = true;
                assert_eq!(
                    known.output_resolution,
                    DerivationOutputResolution::DeferredPlaceholders
                );
                assert!(
                    known.aterm_bytes.is_none(),
                    "deferred-placeholder derivation should use fallback serialization"
                );
            }
            name => panic!("unexpected derivation name {name}"),
        }
    }
    assert!(saw_base, "expected base derivation");
    assert!(saw_downstream, "expected downstream derivation");
}

#[test]
fn derivation_strict_aterm_observation_separates_captured_free_vars() {
    let source = r#"let
        mk = env: (derivationStrict {
            name = "x";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = env;
        }).drvPath;
    in (mk "one") + (mk "two")"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        TreeWalkOptions::with_eval_cache_enabled(true),
        None,
        cache.clone(),
    )
    .expect("derivation evaluates");
    let derivation_hashes = outcome
        .derivations()
        .iter()
        .map(|derivation| {
            ValueHash::from_derivation_aterm_bytes(
                derivation
                    .aterm_bytes()
                    .expect("static derivation has ATerm bytes"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(derivation_hashes.len(), 2);
    assert_ne!(derivation_hashes[0], derivation_hashes[1]);

    assert_eq!(outcome.stats().early_cutoffs(), 0);
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("runtime is enabled");
    assert_eq!(
        cache.derivation_aterm_path_record_count(),
        2,
        "different captured arguments must allocate separate final path records"
    );
    assert_eq!(
        cache.static_derivation_output_path_record_count(),
        2,
        "different captured arguments must allocate separate static output records"
    );
}

#[test]
fn derivation_strict_aterm_observation_skips_disabled_runtime() {
    let source = r#"let d = derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "same";
    }; in d.drvPath"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::disabled()));
    let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        TreeWalkOptions::with_eval_cache_enabled(true),
        None,
        cache.clone(),
    )
    .expect("derivation evaluates");

    assert_eq!(outcome.stats().early_cutoffs(), 0);
    assert!(cache.lock().expect("cache lock is valid").cache().is_none());
}

#[test]
fn derivation_strict_aterm_observation_skips_with_scope() {
    let source = r#"with { envValue = "from-with"; }; let d = derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = envValue;
    }; in d.drvPath"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(
        &ir,
        TreeWalkOptions::with_eval_cache_enabled(true),
        None,
        cache.clone(),
    )
    .expect("derivation evaluates");
    let [derivation] = outcome.derivations() else {
        panic!(
            "expected one recorded derivation, got {:?}",
            outcome.derivations()
        );
    };
    let derivation_hash = ValueHash::from_derivation_aterm_bytes(
        derivation
            .aterm_bytes()
            .expect("static derivation has ATerm bytes"),
    );
    let runtime = cache.lock().expect("cache lock is valid");
    let graph = runtime.cache().expect("runtime is enabled").graph();
    let node_hashes = (0..graph.len())
        .filter_map(|index| {
            graph
                .node(DemandNodeId::new(
                    u32::try_from(index).expect("test graph indices fit in u32"),
                ))
                .expect("node index exists")
                .value_hash()
        })
        .collect::<Vec<_>>();

    assert_eq!(outcome.stats().early_cutoffs(), 0);
    assert!(
        !node_hashes.contains(&derivation_hash),
        "with-scoped derivationStrict observations must be skipped"
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn derivation_strict_gc_stress_and_tier_b_admission_report_default_drv_surfaces() {
    fn evaluate(source: &str, options: TreeWalkOptions) -> EvalOutcome {
        eval_whnf_owned_with_options(&lower(source), options).expect("derivation graph evaluates")
    }

    fn root_string_bytes(outcome: &EvalOutcome) -> Vec<u8> {
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("root value is a heap-owned string")
            .bytes()
            .to_vec()
    }

    fn stressed_options() -> TreeWalkOptions {
        let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
        options.set_heap_memory_budget(HeapMemoryBudget::new(1).expect("budget is non-zero"));
        options.set_heap_tier_b_transition_admission_enabled(true);
        options
    }

    let source = r#"let
        base = derivationStrict {
            name = "gc-base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            __contentAddressed = true;
            outputHashAlgo = "sha256";
            outputHashMode = "recursive";
        };
        downstream = derivationStrict {
            name = "gc-downstream";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            input = base.out;
            env = base.drvPath;
        };
    in downstream.drvPath"#;

    let default = evaluate(source, TreeWalkOptions::new());
    let stressed = evaluate(source, stressed_options());
    let admission = stressed
        .tier_b_transition_admission_report()
        .expect("stressed run applies Tier-B admission metadata");

    assert_eq!(default.derivations().len(), 2);
    assert_eq!(root_string_bytes(&stressed), root_string_bytes(&default));
    assert_eq!(
        derivation_surfaces(&stressed),
        derivation_surfaces(&default)
    );
    assert_eq!(
        stressed.heap().allocator_gc_stress_policy(),
        GcStressPolicy::every_safepoint()
    );
    assert_eq!(
        stressed.heap().permanent_allocator_gc_stress_policy(),
        GcStressPolicy::every_safepoint()
    );
    assert!(
        stressed.heap().allocation_safepoints().count() > 0,
        "GC-stress run should poll worker allocation safepoints"
    );
    assert!(
        stressed.heap().permanent_allocation_safepoints().count() > 0,
        "GC-stress run should poll permanent allocation safepoints"
    );
    assert!(
        stressed
            .memory_budget_action()
            .expect("stressed run records memory-budget pressure")
            .requests_tier_b()
    );
    assert!(
        admission.worker_records() > 0,
        "Tier-B admission should classify worker records"
    );
    assert!(
        admission.generation_rewrites() > 0,
        "Tier-B admission should rewrite generation metadata"
    );
    assert_eq!(
        stressed.stats().heap_tier_b_admission_worker_records(),
        admission.worker_records() as u64
    );
    assert_eq!(
        stressed
            .stats()
            .heap_tier_b_admission_permanent_shared_records(),
        admission.permanent_shared_records() as u64
    );
    assert_eq!(
        stressed.stats().heap_tier_b_admission_generation_rewrites(),
        admission.generation_rewrites() as u64
    );
}

#[test]
fn internal_cache_hash_canaries_do_not_reach_drv_surfaces() {
    let root = fs::canonicalize(unique_temp_dir("internal-hash-leak-canary-import"))
        .expect("temp directory canonicalizes");
    let parse_root = root.join("parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("imported.nix");
    let marker_path = root.join("marker");
    let imported_source = br#""imported-value""#;
    fs::write(&import_path, imported_source).expect("import source writes");
    fs::write(&marker_path, b"present").expect("marker writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!(
        r#"let
             b = builtins;
             imported = import {};
             forced = b.pathExists ./marker;
           in derivationStrict {{
             name = "leak-canary";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ (if forced then "present" else "missing") imported ];
           }}"#,
        import_path.display()
    );

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&parse_root);
    options.set_persist_cache_root(&persist_root);
    options.set_eval_cache_enabled(true);
    let ir = lower(&source);

    eval_whnf_owned_with_options(&ir, options.clone())
        .expect("canary derivation first run evaluates");
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("canary derivation evaluates");
    let derivation = outcome
        .derivations()
        .first()
        .expect("static derivation is recorded");
    let aterm = derivation
        .aterm_bytes()
        .expect("static derivation has ATerm bytes");

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let imported_parse_key = ParseCacheKey::for_source(
        imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let file_key = ParseFileKey::for_source(&import_realpath, imported_source);
    assert!(
        ParseCache::new(&parse_root)
            .entry_for_source(imported_source)
            .is_complete(),
        "canary import should write a parse-cache entry"
    );
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, imported_parse_key);
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert!(
        persist
            .lookup_file_artifact(artifact_key)
            .expect("persistent file-artifact lookup succeeds")
            .is_some(),
        "canary import should materialize a persistent file-artifact mapping"
    );
    let metadata_entries = persist
        .node_metadata_index()
        .latest_entries()
        .expect("persistent node metadata entries load");
    let materialized_value_hashes = metadata_entries
        .iter()
        .filter_map(|entry| entry.value().materialized_value_hash())
        .collect::<Vec<_>>();
    assert!(
        !materialized_value_hashes.is_empty(),
        "second canary run should materialize at least one forced-expression value"
    );
    let trace_entries = persist
        .node_trace_log()
        .latest_entries()
        .expect("persistent node trace entries load");
    let marker_fingerprint = ImpureInputFingerprint::path_exists(&path_bytes(&marker_path), true)
        .expect("marker pathExists fingerprint builds");
    let marker_cacheable_fingerprint = marker_fingerprint
        .as_cacheable()
        .expect("marker pathExists fingerprint is cacheable");
    assert!(
        trace_entries.iter().any(|entry| {
            !entry.payload().is_tombstone()
                && entry
                    .payload()
                    .inputs()
                    .contains(marker_cacheable_fingerprint)
        }),
        "canary should persist the marker pathExists forced-expression trace"
    );
    let hot_canary = NixString::from_bytes(b"leak-canary".to_vec())
        .structural_hash_xxh3()
        .raw_for_tests();
    let hot_decimal_canary = hot_canary.to_string();
    let hot_hex_canary = format!("{hot_canary:016x}");
    let hot_little_endian_canary = hot_canary.to_le_bytes();
    let hot_big_endian_canary = hot_canary.to_be_bytes();

    let mut canaries = Vec::new();
    canaries.extend(durable_hash_surface_canaries(
        "root parse-cache BLAKE3",
        root_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        imported_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "file-content BLAKE3",
        file_key.content_hash().as_durable_hash(),
    ));
    for entry in &metadata_entries {
        canaries.extend(durable_hash_surface_canaries(
            "force node metadata BLAKE3",
            entry.key().hash(),
        ));
    }
    for value_hash in &materialized_value_hashes {
        canaries.extend(durable_hash_surface_canaries(
            "force materialized value BLAKE3",
            value_hash.as_durable_hash(),
        ));
    }
    for entry in &trace_entries {
        canaries.extend(durable_hash_surface_canaries(
            "force trace value BLAKE3",
            entry.value_hash().as_durable_hash(),
        ));
        for input in entry.payload().inputs() {
            canaries.extend(durable_hash_surface_canaries(
                "force trace identity BLAKE3",
                input.identity().hash().as_durable_hash(),
            ));
            canaries.extend(durable_hash_surface_canaries(
                "force trace observation BLAKE3",
                input.observation_hash().as_durable_hash(),
            ));
        }
    }
    canaries.extend([
        (
            "hot xxh3 decimal".to_owned(),
            hot_decimal_canary.into_bytes(),
        ),
        ("hot xxh3 hex".to_owned(), hot_hex_canary.into_bytes()),
        (
            "hot xxh3 little-endian bytes".to_owned(),
            hot_little_endian_canary.to_vec(),
        ),
        (
            "hot xxh3 big-endian bytes".to_owned(),
            hot_big_endian_canary.to_vec(),
        ),
    ]);
    assert_drv_surface_canaries_absent(
        "internal hash leak canary derivation surface",
        derivation.absolute_path(),
        aterm,
        &canaries,
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn configured_import_cache_preserves_drv_surfaces() {
    fn evaluate_derivation_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (String, Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let _value = evaluator.eval_root().expect("derivation evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let derivations = evaluator
            .derivation_snapshot()
            .expect("derivation snapshot succeeds");
        let derivation = derivations
            .iter()
            .next()
            .expect("static derivation is recorded");
        let aterm = derivation
            .aterm_bytes()
            .expect("static derivation has ATerm bytes")
            .to_vec();
        (derivation.absolute_path().to_owned(), aterm, import_stats)
    }

    let root = fs::canonicalize(unique_temp_dir("import-cache-drv-surface-parity"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("imported.nix");
    let imported_source = br#""surface-value""#;
    fs::write(&import_path, imported_source).expect("import source writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!(
        r#"let
             imported = import {};
           in derivationStrict {{
             name = "cache-surface-parity";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ imported ];
           }}"#,
        import_path.display()
    );

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_path, uncached_aterm, uncached_stats) =
        evaluate_derivation_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));

    let mut miss_options = TreeWalkOptions::new();
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_path, miss_aterm, miss_stats) = evaluate_derivation_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_path, uncached_path);
    assert_eq!(miss_aterm, uncached_aterm);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_path, hit_aterm, hit_stats) = evaluate_derivation_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_path, uncached_path);
    assert_eq!(hit_aterm, uncached_aterm);
    let import_parse_key = ParseCacheKey::for_source(
        imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let import_file_key = ParseFileKey::for_source(&import_realpath, imported_source);
    let mut canaries = durable_hash_surface_canaries(
        "imported-file parse-cache BLAKE3",
        import_parse_key.as_durable_hash(),
    );
    canaries.extend(durable_hash_surface_canaries(
        "imported-file content BLAKE3",
        import_file_key.content_hash().as_durable_hash(),
    ));
    assert_drv_surface_canaries_absent(
        "uncached import-cache derivation surface",
        &uncached_path,
        &uncached_aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "cache-miss import-cache derivation surface",
        &miss_path,
        &miss_aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "persistent-hit import-cache derivation surface",
        &hit_path,
        &hit_aterm,
        &canaries,
    );
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(imported_source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}
