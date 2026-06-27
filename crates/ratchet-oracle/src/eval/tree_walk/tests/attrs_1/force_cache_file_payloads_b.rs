//! Force-cache payload tests for environment and filesystem attr thunks.

use super::*;

#[test]
fn changed_read_file_string_payload_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-string-payload-changed");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile string payload force succeeds");
    assert_eq!(
        eval.heap()
            .get_string(forced)
            .expect("readFile result is a string")
            .bytes(),
        b"payload"
    );

    fs::write(root.join("target"), b"changed").expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile string payload recomputes");
    let changed_string = changed
        .heap()
        .get_string(forced_changed)
        .expect("changed readFile result is a string");

    assert_eq!(changed_string.bytes(), b"changed");
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn get_env_string_payload_thunks_hit_and_miss_after_revalidation() {
    let source = r#"{ a = builtins.getEnv "AOS_FORCE_CACHE_TEST"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let name = b"AOS_FORCE_CACHE_TEST";
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options.set_env_var(name.to_vec(), b"first".to_vec());
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut eval, &ir, a, b"first");

    let mut second_options = TreeWalkOptions::new();
    second_options.set_env_var(name.to_vec(), b"first".to_vec());
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut second, &ir, a, b"first");

    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable getEnv payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace =
        vec![ImpureInputFingerprint::get_env(name, Some(b"first")).expect("fingerprint builds")];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay getEnv edges"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options.set_env_var(name.to_vec(), b"second".to_vec());
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut changed, &ir, a, b"second");

    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
    let changed_trace =
        vec![ImpureInputFingerprint::get_env(name, Some(b"second")).expect("fingerprint builds")];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());
}

#[test]
fn read_dir_attrset_payload_thunks_hit_and_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-dir-list-payload");
    fs::create_dir(root.join("dir")).expect("directory creates");
    fs::write(root.join("dir").join("alpha"), b"data").expect("alpha writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dir_path = path_bytes(&root.join("dir"));
    let source = "{ a = builtins.readDir ./dir; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(&mut eval, &ir, a, &[(b"alpha", b"regular")]);

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(&mut second, &ir, a, &[(b"alpha", b"regular")]);

    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readDir payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
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
        "cache-hit revalidation must replay readDir edges"
    );

    fs::write(root.join("dir").join("beta"), b"data").expect("beta writes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(
        &mut changed,
        &ir,
        a,
        &[(b"alpha", b"regular"), (b"beta", b"regular")],
    );

    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
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

    let mut fourth_options = TreeWalkOptions::new();
    fourth_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut fourth = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        fourth_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(
        &mut fourth,
        &ir,
        a,
        &[(b"alpha", b"regular"), (b"beta", b"regular")],
    );

    assert_eq!(
        fourth.stats().thunks_forced(),
        0,
        "stable multi-entry readDir payloads should hit after recomputation"
    );
    assert_eq!(fourth.stats().cache_hits(), 1);
    assert_eq!(fourth.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn read_file_type_string_payload_thunks_hit_and_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-type-string-payload");
    fs::write(root.join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFileType ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut eval, &ir, a, b"regular");

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut second, &ir, a, b"regular");

    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFileType payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFileType edges"
    );

    fs::remove_file(root.join("target")).expect("target file removes");
    fs::create_dir(root.join("target")).expect("target directory creates");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut changed, &ir, a, b"directory");

    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
    let changed_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Directory)
            .expect("fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_read_file_string_payload_thunks_hit_and_miss_after_revalidation() {
    let root = unique_temp_dir("source-less-force-cache-read-file-string-payload");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let forced = force_attr_a(&mut eval, &ir, a);
    assert_eq!(
        eval.heap()
            .get_string(forced)
            .expect("readFile result is a string")
            .bytes(),
        b"payload"
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_eval_cache(&ir, second_options, cache.clone());
    let second_forced = force_attr_a(&mut second, &ir, a);
    let second_string = second
        .heap()
        .get_string(second_forced)
        .expect("cached string payload rehydrates into second heap");

    assert_eq!(second_string.bytes(), b"payload");
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable source-less readFile payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, b"payload").expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "source-less cache-hit revalidation must replay readFile edges"
    );

    fs::write(root.join("target"), b"changed").expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_eval_cache(&ir, changed_options, cache.clone());
    let changed_forced = force_attr_a(&mut changed, &ir, a);
    let changed_string = changed
        .heap()
        .get_string(changed_forced)
        .expect("changed readFile result is a string");

    assert_eq!(changed_string.bytes(), b"changed");
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn read_file_context_string_payload_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-context-string-payload");
    let referenced_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
    let contents = [
        b"prefix ".as_slice(),
        referenced_path,
        b"/suffix".as_slice(),
    ]
    .concat();
    fs::write(root.join("target"), &contents).expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile context string payload force succeeds");
    let string = eval
        .heap()
        .get_string(forced)
        .expect("readFile result is a string");

    assert_eq!(string.bytes(), contents.as_slice());
    assert_eq!(
        string.context().elements(),
        &[ContextElement::opaque_path(referenced_path.to_vec()).expect("context path is valid")]
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let second_forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("readFile context string payload revalidates and hits");
    let second_string = second
        .heap()
        .get_string(second_forced)
        .expect("cached context string payload rehydrates into second heap");

    assert_eq!(second_string.bytes(), contents.as_slice());
    assert_eq!(
        second_string.context().elements(),
        &[ContextElement::opaque_path(referenced_path.to_vec()).expect("context path is valid")]
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFile context string payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, &contents).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFile edges for context string payloads"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_read_file_context_string_payload_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-context-string-payload-changed");
    let old_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
    let new_path = b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source";
    fs::write(root.join("target"), old_path).expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile context string payload force succeeds");
    let string = eval
        .heap()
        .get_string(forced)
        .expect("readFile result is a string");

    assert_eq!(
        string.context().elements(),
        &[ContextElement::opaque_path(old_path.to_vec()).expect("old context path is valid")]
    );

    fs::write(root.join("target"), new_path).expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let changed_forced = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile context string payload recomputes");
    let changed_string = changed
        .heap()
        .get_string(changed_forced)
        .expect("changed readFile result is a string");

    assert_eq!(changed_string.bytes(), new_path);
    assert_eq!(
        changed_string.context().elements(),
        &[ContextElement::opaque_path(new_path.to_vec()).expect("new context path is valid")]
    );
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}
