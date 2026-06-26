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
    assert_eq!(materialize.force_cache_misses, 1);

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

    let mut stale_options = TreeWalkOptions::with_eval_cache_enabled(true);
    configure_options(&mut stale_options);
    stale_options.set_persist_cache_root(&persist_root);
    let stale =
        evaluate_cached_derivation_surface(ir, source, stale_options, EvalCacheRuntime::enabled());
    assert_eq!(stale.path, uncached_changed.path);
    assert_eq!(stale.aterm, uncached_changed.aterm);
    assert_eq!(stale.trace, changed_trace);
    assert!(
        stale.thunks_forced > 0,
        "stale persistent observations should fall back to ordinary forcing"
    );

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
fn persistent_get_env_force_cache_no_replay_preserves_drv_surfaces() {
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

    let mut replay_options = TreeWalkOptions::with_eval_cache_enabled(true);
    replay_options.set_env_var(name.to_vec(), b"env payload".to_vec());
    replay_options.set_persist_cache_root(&persist_root);
    let replay = evaluate_cached_derivation_surface(
        &ir,
        source,
        replay_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(replay.path, uncached.path);
    assert_eq!(replay.aterm, uncached.aterm);
    assert_eq!(replay.trace, expected_trace);
    assert_eq!(replay.cache_hits, 0);
    assert_eq!(replay.force_cache_hits, 0);
    assert_eq!(replay.force_cache_misses, 0);
    assert!(
        replay.thunks_forced > 0,
        "current getEnv derivation surfaces should recompute rather than replay a force-cache hit"
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

    let mut changed_replay_options = TreeWalkOptions::with_eval_cache_enabled(true);
    changed_replay_options.set_env_var(name.to_vec(), b"changed payload".to_vec());
    changed_replay_options.set_persist_cache_root(&persist_root);
    let changed_replay = evaluate_cached_derivation_surface(
        &ir,
        source,
        changed_replay_options,
        EvalCacheRuntime::enabled(),
    );
    assert_eq!(changed_replay.path, uncached_changed.path);
    assert_eq!(changed_replay.aterm, uncached_changed.aterm);
    assert_eq!(changed_replay.trace, changed_trace);
    assert_eq!(changed_replay.cache_hits, 0);
    assert_eq!(changed_replay.force_cache_hits, 0);
    assert_eq!(changed_replay.force_cache_misses, 0);

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
