//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn persistent_force_cache_hit_preserves_drv_surfaces() {
    fn evaluate_derivation_surface(
        ir: &Ir,
        source: &str,
        options: TreeWalkOptions,
        eval_cache: EvalCacheRuntime,
    ) -> (String, Vec<u8>, u64, u64, u64) {
        let attr_path = vec![b"pkg".to_vec()];
        let outcome =
            eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
                ir,
                &attr_path,
                options,
                "force-cache-drv-surface.nix",
                source,
                None,
                Arc::new(Mutex::new(eval_cache)),
            )
            .expect("derivation attr-path eval succeeds");
        let [derivation] = outcome.derivations() else {
            panic!(
                "expected one recorded derivation, got {:?}",
                outcome.derivations()
            );
        };
        let aterm = derivation
            .aterm_bytes()
            .expect("static derivation has ATerm bytes")
            .to_vec();
        (
            derivation.absolute_path().to_owned(),
            aterm,
            outcome.stats().cache_hits(),
            outcome.stats().force_cache_hits(),
            outcome.stats().force_cache_misses(),
        )
    }

    let persist_root = unique_temp_dir("force-cache-drv-surface-parity");
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ b.currentSystem ];
             };
           }"#;
    let ir = lower(source);

    let uncached_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    let (
        uncached_path,
        uncached_aterm,
        uncached_cache_hits,
        uncached_force_hits,
        uncached_force_misses,
    ) = evaluate_derivation_surface(&ir, source, uncached_options, EvalCacheRuntime::disabled());
    assert_eq!(uncached_cache_hits, 0);
    assert_eq!(uncached_force_hits, 0);
    assert_eq!(uncached_force_misses, 0);

    let mut first_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    first_options.set_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    let (first_path, first_aterm, first_cache_hits, first_force_hits, first_force_misses) =
        evaluate_derivation_surface(&ir, source, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first_path, uncached_path);
    assert_eq!(first_aterm, uncached_aterm);
    assert_eq!(first_cache_hits, 0);
    assert_eq!(first_force_hits, 0);
    assert_eq!(first_force_misses, 1);

    let mut materialize_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    materialize_options.set_eval_cache_enabled(true);
    materialize_options.set_persist_cache_root(&persist_root);
    let (
        materialize_path,
        materialize_aterm,
        materialize_cache_hits,
        materialize_force_hits,
        materialize_force_misses,
    ) = evaluate_derivation_surface(
        &ir,
        source,
        materialize_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(materialize_path, uncached_path);
    assert_eq!(materialize_aterm, uncached_aterm);
    assert_eq!(materialize_cache_hits, 0);
    assert_eq!(materialize_force_hits, 0);
    assert_eq!(materialize_force_misses, 1);

    let mut hit_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    hit_options.set_eval_cache_enabled(true);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_path, hit_aterm, hit_cache_hits, hit_force_hits, hit_force_misses) =
        evaluate_derivation_surface(&ir, source, hit_options, EvalCacheRuntime::enabled());
    assert_eq!(hit_path, uncached_path);
    assert_eq!(hit_aterm, uncached_aterm);
    assert_eq!(hit_cache_hits, 1);
    assert_eq!(hit_force_hits, 1);
    assert_eq!(hit_force_misses, 0);

    let canaries = persistent_force_cache_surface_canaries(&persist_root, &[]);
    assert_drv_surface_canaries_absent(
        "uncached currentSystem force-cache surface",
        &uncached_path,
        &uncached_aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "cold currentSystem force-cache surface",
        &first_path,
        &first_aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "materializing currentSystem force-cache surface",
        &materialize_path,
        &materialize_aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "persistent-hit currentSystem force-cache surface",
        &hit_path,
        &hit_aterm,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("temp directory removes");
}

#[test]
fn persistent_effectful_force_cache_hit_preserves_drv_surfaces() {
    let persist_root = unique_temp_dir("force-cache-effectful-drv-surface-parity");
    let root = unique_temp_dir("force-cache-effectful-drv-source");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("source root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let expected_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds")];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-effectful-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (if b.pathExists ./marker then "present" else "missing") ];
             };
           }"#;
    let ir = lower(source);

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let uncached = evaluate_effectful_derivation_surface(
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
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    first_options.set_persist_cache_root(&persist_root);
    let first = evaluate_effectful_derivation_surface(
        &ir,
        source,
        first_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(first.path, uncached.path);
    assert_eq!(first.aterm, uncached.aterm);
    assert_eq!(first.trace, expected_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_effectful_derivation_surface(
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
    assert!(
        materialize.force_cache_misses > 0,
        "materializing pathExists run should miss before writing persistent force-cache payloads"
    );
    let expected_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &expected_trace,
        "materializing pathExists force-cache surface",
    );

    let mut hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    hit_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    hit_options.set_persist_cache_root(&persist_root);
    let hit = evaluate_effectful_derivation_surface(
        &ir,
        source,
        hit_options,
        EvalCacheRuntime::enabled(),
    );
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
        "fresh-runtime pathExists hit should load the expected force-cache metadata key"
    );

    let canaries = persistent_force_cache_surface_canaries(&persist_root, &[&expected_trace]);
    assert_drv_surface_canaries_absent(
        "uncached pathExists force-cache surface",
        &uncached.path,
        &uncached.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "cold pathExists force-cache surface",
        &first.path,
        &first.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "materializing pathExists force-cache surface",
        &materialize.path,
        &materialize.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "persistent-hit pathExists force-cache surface",
        &hit.path,
        &hit.aterm,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn persistent_current_time_force_cache_no_replay_preserves_drv_surfaces() {
    let persist_root = unique_temp_dir("force-cache-current-time-drv-surface-parity");
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-current-time-drv-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (builtins.toString b.currentTime) ];
             };
           }"#;
    let ir = lower(source);
    let expected_trace = vec![ImpureInputFingerprint::current_time()];

    let uncached_first_options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let uncached_first = evaluate_effectful_derivation_surface(
        &ir,
        source,
        uncached_first_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached_first.trace, expected_trace);
    assert_eq!(uncached_first.cache_hits, 0);
    assert_eq!(uncached_first.force_cache_hits, 0);
    assert_eq!(uncached_first.force_cache_misses, 0);
    assert_eq!(uncached_first.path_reuses, 0);
    assert_eq!(uncached_first.output_path_reuses, 0);
    assert!(uncached_first.hash_calculations > 0);
    assert!(uncached_first.text_path_calculations > 0);

    let mut first_options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    first_options.set_eval_cache_enabled(true);
    first_options.set_persist_cache_root(&persist_root);
    let first = evaluate_effectful_derivation_surface(
        &ir,
        source,
        first_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(first.path, uncached_first.path);
    assert_eq!(first.aterm, uncached_first.aterm);
    assert_eq!(first.trace, expected_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);
    assert_eq!(first.path_reuses, 0);
    assert_eq!(first.output_path_reuses, 0);
    assert!(first.hash_calculations > 0);
    assert!(first.text_path_calculations > 0);

    let mut replay_options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    replay_options.set_eval_cache_enabled(true);
    replay_options.set_persist_cache_root(&persist_root);
    let replay = evaluate_effectful_derivation_surface(
        &ir,
        source,
        replay_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(replay.path, uncached_first.path);
    assert_eq!(replay.aterm, uncached_first.aterm);
    assert_eq!(replay.trace, expected_trace);
    assert!(
        replay.thunks_forced > 0,
        "uncacheable currentTime should recompute instead of hitting persistent force cache"
    );
    assert_eq!(replay.cache_hits, 0);
    assert_eq!(replay.force_cache_hits, 0);
    assert_eq!(replay.force_cache_misses, 0);
    assert_eq!(replay.path_reuses, 0);
    assert_eq!(replay.output_path_reuses, 0);
    assert!(replay.hash_calculations > 0);
    assert!(replay.text_path_calculations > 0);

    let uncached_changed_options =
        TreeWalkOptions::with_current_time(1_700_000_123).expect("currentTime is valid");
    let uncached_changed = evaluate_effectful_derivation_surface(
        &ir,
        source,
        uncached_changed_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached_changed.trace, expected_trace);
    assert_eq!(uncached_changed.cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_misses, 0);
    assert_eq!(uncached_changed.path_reuses, 0);
    assert_eq!(uncached_changed.output_path_reuses, 0);
    assert!(uncached_changed.hash_calculations > 0);
    assert!(uncached_changed.text_path_calculations > 0);
    assert_ne!(uncached_changed.path, uncached_first.path);
    assert_ne!(uncached_changed.aterm, uncached_first.aterm);

    let mut changed_options =
        TreeWalkOptions::with_current_time(1_700_000_123).expect("currentTime is valid");
    changed_options.set_eval_cache_enabled(true);
    changed_options.set_persist_cache_root(&persist_root);
    let changed = evaluate_effectful_derivation_surface(
        &ir,
        source,
        changed_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(changed.path, uncached_changed.path);
    assert_eq!(changed.aterm, uncached_changed.aterm);
    assert_eq!(changed.trace, expected_trace);
    assert!(
        changed.thunks_forced > 0,
        "changed currentTime should recompute instead of reusing the old surface"
    );
    assert_eq!(changed.cache_hits, 0);
    assert_eq!(changed.force_cache_hits, 0);
    assert_eq!(changed.force_cache_misses, 0);
    assert_eq!(changed.path_reuses, 0);
    assert_eq!(changed.output_path_reuses, 0);
    assert!(changed.hash_calculations > 0);
    assert!(changed.text_path_calculations > 0);
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "uncacheable currentTime derivation canary",
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn current_time_derivation_taints_in_memory_side_record_nodes() {
    let source = r#"derivationStrict (let
             b = builtins;
           in {
             name = "force-cache-current-time-side-record";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             env = b.currentTime;
           })"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = || {
        let mut options =
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
        options.set_eval_cache_enabled(true);
        options
    };
    let (final_identity, final_free_var_hashes) =
        derivation_aterm_cache_subject(&ir, options(), cache.clone());
    let (static_identity, static_free_var_hashes) =
        static_derivation_outputs_cache_subject(&ir, options(), cache.clone());

    let run = eval_single_derivation_with_cache(&ir, options(), cache.clone());

    assert_eq!(run.path_reuses, 0);
    assert_eq!(run.output_path_reuses, 0);
    assert!(run.hash_calculations > 0);
    assert!(run.text_path_calculations > 0);
    let final_key =
        DemandCacheKey::for_free_vars(final_identity, final_free_var_hashes.iter().copied())
            .expect("final ATerm runtime key builds");
    let static_key =
        DemandCacheKey::for_free_vars(static_identity, static_free_var_hashes.iter().copied())
            .expect("static output runtime key builds");
    let runtime = cache.lock().expect("cache lock is valid");
    let cache_view = runtime.cache().expect("cache is enabled");
    let final_node = cache_view
        .graph()
        .node_id_for_key(final_key)
        .expect("final ATerm node is present");
    let static_node = cache_view
        .graph()
        .node_id_for_key(static_key)
        .expect("static output node is present");

    let final_graph_node = cache_view
        .graph()
        .node(final_node)
        .expect("final ATerm graph node is present");
    let static_graph_node = cache_view
        .graph()
        .node(static_node)
        .expect("static output graph node is present");
    assert_eq!(final_graph_node.freshness(), NodeFreshness::Dirty);
    assert_eq!(static_graph_node.freshness(), NodeFreshness::Dirty);
    assert_eq!(
        (
            cache_view.derivation_aterm_path_record_count(),
            cache_view.static_derivation_output_path_record_count()
        ),
        (0, 0)
    );
    drop(runtime);

    let second = eval_single_derivation_with_cache(&ir, options(), cache.clone());

    assert_eq!(second.path, run.path);
    assert_eq!(second.aterm, run.aterm);
    assert_eq!(second.path_reuses, 0);
    assert_eq!(second.output_path_reuses, 0);
    assert!(second.hash_calculations > 0);
    assert!(second.text_path_calculations > 0);
}

#[test]
fn current_time_derivation_skips_persistent_side_record_nodes() {
    let persist_root = unique_temp_dir("force-cache-current-time-side-record-persist");
    let source = r#"derivationStrict (let
             b = builtins;
           in {
             name = "force-cache-current-time-side-record";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             env = b.currentTime;
           })"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = || {
        let mut options =
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
        options.set_eval_cache_enabled(true);
        options.set_persist_cache_root(&persist_root);
        options
    };
    let (final_identity, final_free_var_hashes) =
        derivation_aterm_cache_subject(&ir, options(), cache.clone());
    let (static_identity, static_free_var_hashes) =
        static_derivation_outputs_cache_subject(&ir, options(), cache);

    let first = eval_single_derivation_with_cache(
        &ir,
        options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(first.path_reuses, 0);
    assert_eq!(first.output_path_reuses, 0);
    assert!(first.hash_calculations > 0);
    assert!(first.text_path_calculations > 0);
    assert_no_live_persistent_side_record(
        &persist_root,
        final_identity,
        &final_free_var_hashes,
        "direct currentTime final ATerm side-record first run",
    );
    assert_no_live_persistent_side_record(
        &persist_root,
        static_identity,
        &static_free_var_hashes,
        "direct currentTime static-output side-record first run",
    );

    let second = eval_single_derivation_with_cache(
        &ir,
        options(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );

    assert_eq!(second.path, first.path);
    assert_eq!(second.aterm, first.aterm);
    assert_eq!(second.path_reuses, 0);
    assert_eq!(second.output_path_reuses, 0);
    assert!(second.hash_calculations > 0);
    assert!(second.text_path_calculations > 0);
    assert_no_live_persistent_side_record(
        &persist_root,
        final_identity,
        &final_free_var_hashes,
        "direct currentTime final ATerm side-record fresh-runtime replay",
    );
    assert_no_live_persistent_side_record(
        &persist_root,
        static_identity,
        &static_free_var_hashes,
        "direct currentTime static-output side-record fresh-runtime replay",
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn nested_current_time_derivations_skip_persistent_side_record_nodes() {
    let persist_root = unique_temp_dir("force-cache-current-time-nested-side-record-persist");
    let source = r#"let
             b = builtins;
             inner = derivationStrict {
               name = "force-cache-current-time-nested-inner";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               env = b.currentTime;
             };
           in derivationStrict {
             name = "force-cache-current-time-nested-outer";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ inner.drvPath ];
           }"#;
    let ir = lower(source);
    let expected_trace = vec![ImpureInputFingerprint::current_time()];
    let options = |current_time| {
        let mut options = TreeWalkOptions::with_current_time(current_time)
            .expect("currentTime is valid for nested derivations");
        options.set_eval_cache_enabled(true);
        options.set_persist_cache_root(&persist_root);
        options
    };

    let first =
        evaluate_nested_current_time_derivations(&ir, options(1_700_000_000), "first nested run");
    assert_eq!(first.surfaces.len(), 2);
    assert_eq!(first.trace, expected_trace);
    assert_eq!(first.path_reuses, 0);
    assert_eq!(first.output_path_reuses, 0);
    assert!(first.hash_calculations > 0);
    assert!(first.text_path_calculations > 0);

    let replay =
        evaluate_nested_current_time_derivations(&ir, options(1_700_000_000), "replay nested run");
    assert_eq!(replay.surfaces, first.surfaces);
    assert_eq!(replay.trace, expected_trace);
    assert_eq!(replay.path_reuses, 0);
    assert_eq!(replay.output_path_reuses, 0);
    assert!(replay.hash_calculations > 0);
    assert!(replay.text_path_calculations > 0);

    let changed =
        evaluate_nested_current_time_derivations(&ir, options(1_700_000_123), "changed nested run");
    assert_ne!(changed.surfaces, first.surfaces);
    assert_eq!(changed.trace, expected_trace);
    assert_eq!(changed.path_reuses, 0);
    assert_eq!(changed.output_path_reuses, 0);
    assert!(changed.hash_calculations > 0);
    assert!(changed.text_path_calculations > 0);
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "nested uncacheable currentTime derivation canary",
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn persistent_effectful_force_cache_stale_miss_preserves_drv_surfaces() {
    let persist_root = unique_temp_dir("force-cache-effectful-drv-stale-parity");
    let root = unique_temp_dir("force-cache-effectful-drv-stale-source");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("source root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let present_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds")];
    let missing_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, false).expect("fingerprint builds")];
    let source = r#"let
             b = builtins;
           in {
             pkg = derivationStrict {
               name = "force-cache-effectful-drv-stale-surface";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ (if b.pathExists ./marker then "present" else "missing") ];
             };
           }"#;
    let ir = lower(source);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    first_options.set_persist_cache_root(&persist_root);
    let first = evaluate_effectful_derivation_surface(
        &ir,
        source,
        first_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(first.trace, present_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize = evaluate_effectful_derivation_surface(
        &ir,
        source,
        materialize_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(materialize.path, first.path);
    assert_eq!(materialize.aterm, first.aterm);
    assert_eq!(materialize.trace, present_trace);
    assert_eq!(materialize.cache_hits, 0);
    assert_eq!(materialize.force_cache_hits, 0);
    assert!(
        materialize.force_cache_misses > 0,
        "materializing pathExists baseline should miss before writing persistent force-cache payloads"
    );
    let present_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &present_trace,
        "materializing pathExists baseline surface",
    );

    fs::remove_file(root.join("marker")).expect("marker removed");

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let uncached_missing = evaluate_effectful_derivation_surface(
        &ir,
        source,
        uncached_options,
        EvalCacheRuntime::disabled(),
    );
    assert_eq!(uncached_missing.trace, missing_trace);
    assert_eq!(uncached_missing.cache_hits, 0);
    assert_eq!(uncached_missing.force_cache_hits, 0);
    assert_eq!(uncached_missing.force_cache_misses, 0);
    assert_ne!(uncached_missing.path, materialize.path);
    assert_ne!(uncached_missing.aterm, materialize.aterm);

    let stale_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut stale_options = TreeWalkOptions::with_eval_cache_enabled(true);
    stale_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    stale_options.set_persist_cache_root(&persist_root);
    let stale = evaluate_effectful_derivation_surface_with_cache(
        &ir,
        source,
        stale_options,
        stale_runtime.clone(),
    );
    assert_eq!(stale.path, uncached_missing.path);
    assert_eq!(stale.aterm, uncached_missing.aterm);
    assert_eq!(stale.trace, missing_trace);
    assert!(
        stale.force_cache_misses > 0,
        "stale pathExists observations should report at least one force-cache miss"
    );
    assert!(
        stale.thunks_forced > 0,
        "stale persistent observations should fall back to ordinary forcing"
    );
    let missing_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &missing_trace,
        "stale-miss pathExists surface",
    );
    assert_eq!(
        missing_trace_entry.0, present_trace_entry.0,
        "stale pathExists recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        missing_trace_entry.1, present_trace_entry.1,
        "stale pathExists recomputation should materialize a changed force-cache value"
    );

    let mut same_runtime_hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    same_runtime_hit_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    same_runtime_hit_options.set_persist_cache_root(&persist_root);
    let same_runtime_hit = evaluate_effectful_derivation_surface_with_cache(
        &ir,
        source,
        same_runtime_hit_options,
        stale_runtime,
    );
    assert_eq!(same_runtime_hit.path, uncached_missing.path);
    assert_eq!(same_runtime_hit.aterm, uncached_missing.aterm);
    assert_eq!(same_runtime_hit.trace, missing_trace);
    assert!(same_runtime_hit.cache_hits > 0);
    assert!(same_runtime_hit.force_cache_hits > 0);
    assert_eq!(same_runtime_hit.force_cache_misses, 0);

    let mut fresh_runtime_hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    fresh_runtime_hit_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    fresh_runtime_hit_options.set_persist_cache_root(&persist_root);
    let fresh_runtime_hit = evaluate_effectful_derivation_surface(
        &ir,
        source,
        fresh_runtime_hit_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(fresh_runtime_hit.path, uncached_missing.path);
    assert_eq!(fresh_runtime_hit.aterm, uncached_missing.aterm);
    assert_eq!(fresh_runtime_hit.trace, missing_trace);
    assert!(fresh_runtime_hit.cache_hits > 0);
    assert!(fresh_runtime_hit.force_cache_hits > 0);
    assert_eq!(fresh_runtime_hit.force_cache_misses, 0);
    assert!(
        fresh_runtime_hit
            .persist_force_cache_hit_keys
            .contains(&missing_trace_entry.0),
        "fresh-runtime changed pathExists hit should load the changed force-cache metadata key"
    );

    let canaries =
        persistent_force_cache_surface_canaries(&persist_root, &[&present_trace, &missing_trace]);
    assert_drv_surface_canaries_absent(
        "original pathExists force-cache surface",
        &first.path,
        &first.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "materializing pathExists force-cache surface",
        &materialize.path,
        &materialize.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "missing uncached pathExists force-cache surface",
        &uncached_missing.path,
        &uncached_missing.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "stale-miss pathExists force-cache surface",
        &stale.path,
        &stale.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "same-runtime post-recompute pathExists force-cache surface",
        &same_runtime_hit.path,
        &same_runtime_hit.aterm,
        &canaries,
    );
    assert_drv_surface_canaries_absent(
        "fresh-runtime post-recompute pathExists force-cache surface",
        &fresh_runtime_hit.path,
        &fresh_runtime_hit.aterm,
        &canaries,
    );

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
    fs::remove_dir_all(root).expect("source temp directory removes");
}
