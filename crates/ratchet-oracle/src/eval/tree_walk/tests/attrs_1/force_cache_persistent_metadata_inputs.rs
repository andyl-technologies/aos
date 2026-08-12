//! Persistent force-cache revalidation tests for metadata-style impure inputs.

use super::*;

fn persistent_runtime() -> Arc<Mutex<EvalCacheRuntime>> {
    Arc::new(Mutex::new(EvalCacheRuntime::enabled()))
}

fn assert_persistent_hit_stats(evaluator: &TreeWalk, label: &str) {
    assert_eq!(
        evaluator.stats().thunks_forced(),
        0,
        "{label} should rehydrate from persistent cache after trace revalidation"
    );
    assert_eq!(evaluator.stats().cache_hits(), 1);
    assert_eq!(evaluator.stats().cache_misses(), 0);
}

fn assert_persistent_miss_stats(evaluator: &TreeWalk, label: &str) {
    assert_eq!(
        evaluator.stats().thunks_forced(),
        1,
        "{label} should recompute after stale persistent trace revalidation"
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 1);
}

#[test]
fn get_env_string_payload_hits_and_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-get-env");
    let source = r#"{ a = builtins.getEnv "AOS_FORCE_CACHE_TEST"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let name = b"AOS_FORCE_CACHE_TEST";

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options.set_env_var(name.to_vec(), b"first".to_vec());
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("getEnv force succeeds");
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options.set_env_var(name.to_vec(), b"first".to_vec());
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    force_attr_a_string(&mut second, &ir, a, b"first");

    assert_persistent_hit_stats(&second, "stable getEnv payload");
    let expected_trace =
        vec![ImpureInputFingerprint::get_env(name, Some(b"first")).expect("fingerprint builds")];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent getEnv hits must replay the revalidated edge"
    );
    drop(second);

    let mut changed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    changed_options.set_env_var(name.to_vec(), b"second".to_vec());
    changed_options.set_persist_cache_root(&persist_root);
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    force_attr_a_string(&mut changed, &ir, a, b"second");

    assert_persistent_miss_stats(&changed, "changed getEnv payload");
    let changed_trace =
        vec![ImpureInputFingerprint::get_env(name, Some(b"second")).expect("fingerprint builds")];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn read_dir_attrset_payload_hits_and_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-read-dir");
    let root = unique_temp_dir("force-cache-persistent-read-dir-source");
    fs::create_dir(root.join("dir")).expect("directory creates");
    fs::write(root.join("dir").join("alpha"), b"data").expect("alpha writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dir_path = path_bytes(&root.join("dir"));
    let source = "{ a = builtins.readDir ./dir; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("readDir force succeeds");
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    force_attr_a_attrs_strings(&mut second, &ir, a, &[(b"alpha", b"regular")]);

    assert_persistent_hit_stats(&second, "stable readDir payload");
    let expected_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"alpha", FileTypeForInput::Regular)],
        )
        .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent readDir hits must replay the revalidated edge"
    );
    drop(second);

    fs::write(root.join("dir").join("beta"), b"data").expect("beta writes");

    let mut changed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    changed_options.set_persist_cache_root(&persist_root);
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    force_attr_a_attrs_strings(
        &mut changed,
        &ir,
        a,
        &[(b"alpha", b"regular"), (b"beta", b"regular")],
    );

    assert_persistent_miss_stats(&changed, "changed readDir payload");
    let changed_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [
                DirEntryInput::new(b"alpha", FileTypeForInput::Regular),
                DirEntryInput::new(b"beta", FileTypeForInput::Regular),
            ],
        )
        .expect("fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn read_file_type_string_payload_hits_and_misses_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-read-file-type");
    let root = unique_temp_dir("force-cache-persistent-read-file-type-source");
    fs::write(root.join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFileType ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("readFileType force succeeds");
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    force_attr_a_string(&mut second, &ir, a, b"regular");

    assert_persistent_hit_stats(&second, "stable readFileType payload");
    let expected_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent readFileType hits must replay the revalidated edge"
    );
    drop(second);

    fs::remove_file(root.join("target")).expect("target file removes");
    fs::create_dir(root.join("target")).expect("target directory creates");

    let mut changed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    changed_options.set_persist_cache_root(&persist_root);
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        persistent_runtime(),
    );
    force_attr_a_string(&mut changed, &ir, a, b"directory");

    assert_persistent_miss_stats(&changed, "changed readFileType payload");
    let changed_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Directory)
            .expect("fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("source temp tree removed");
    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
