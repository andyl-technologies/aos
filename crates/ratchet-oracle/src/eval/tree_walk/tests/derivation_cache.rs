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
}

fn evaluate_cached_derivation_surface(
    ir: &Ir,
    source: &str,
    options: TreeWalkOptions,
    eval_cache: EvalCacheRuntime,
) -> CachedDerivationSurface {
    let attr_path = vec![b"pkg".to_vec()];
    let outcome = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        ir,
        &attr_path,
        options,
        "force-cache-impure-leaf-drv-surface.nix",
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
    assert_eq!(materialize.force_cache_misses, 1);

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
    assert_eq!(hit.cache_hits, 1);
    assert_eq!(hit.force_cache_hits, 1);
    assert_eq!(hit.force_cache_misses, 0);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
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
