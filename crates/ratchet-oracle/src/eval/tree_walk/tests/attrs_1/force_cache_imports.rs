//! Force-cache revalidation tests for import-backed attr thunks.

use super::*;

#[test]
fn import_backed_inline_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&fs::canonicalize(root.join("dep.nix")).expect("dep canonicalizes"));
    let source = "{ a = import ./dep.nix; }";
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
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("import-backed force succeeds")
            .as_int(),
        Ok(1)
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
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("import-backed force revalidates and hits");

    assert_eq!(forced.as_int(), Ok(1));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable import-backed payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace =
        vec![ImpureInputFingerprint::import(&dep_path, b"1").expect("fingerprint builds")];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay the import source edge"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_import_backed_inline_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed-changed");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./dep.nix; }";
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
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("import-backed force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::write(root.join("dep.nix"), b"2").expect("import source changes");

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
        .expect("changed import-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn import_backed_inline_thunks_record_exact_force_cache_graph_edges() {
    let root = unique_temp_dir("force-cache-import-backed-edge-exactness");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&fs::canonicalize(root.join("dep.nix")).expect("dep canonicalizes"));
    let source = "{ a = import ./dep.nix; }";
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
    let (forced, owner_key) = force_attr_a_with_impure_observation_key(&mut eval, &ir, a);
    assert_eq!(forced.as_int(), Ok(1));
    let expected_trace =
        vec![ImpureInputFingerprint::import(&dep_path, b"1").expect("fingerprint builds")];

    assert_eq!(eval.impure_input_trace(), expected_trace.as_slice());
    assert_force_cache_impure_edges_match_trace(&cache, owner_key, &expected_trace);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn import_backed_path_payload_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed-path");
    let imported_source = br#"/tmp + "/imported-path""#;
    fs::write(root.join("dep.nix"), imported_source).expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&fs::canonicalize(root.join("dep.nix")).expect("dep canonicalizes"));
    let source = "{ a = import ./dep.nix; }";
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
    let first = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("import-backed path force succeeds");
    let first_path = eval.heap().get_path(first).expect("first result is a path");
    assert_eq!(first_path.bytes(), b"/tmp/imported-path");

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
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("import-backed path force revalidates and hits");
    let path = second
        .heap()
        .get_path(forced)
        .expect("cached value is rehydrated into this evaluator heap");

    assert_eq!(path.bytes(), b"/tmp/imported-path");
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable import-backed path payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::import(&dep_path, imported_source).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay the import source edge"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_import_backed_path_payload_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed-path-changed");
    fs::write(root.join("dep.nix"), br#"/tmp + "/imported-path""#).expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./dep.nix; }";
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
    let first = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("import-backed path force succeeds");
    let first_path = eval.heap().get_path(first).expect("first result is a path");
    assert_eq!(first_path.bytes(), b"/tmp/imported-path");

    fs::write(root.join("dep.nix"), br#"/tmp + "/changed-path""#).expect("import source changes");

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
        .expect("changed import-backed path force recomputes");
    let changed_path = changed
        .heap()
        .get_path(forced_changed)
        .expect("changed result is a path");

    assert_eq!(changed_path.bytes(), b"/tmp/changed-path");
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn import_cache_hits_keep_force_cache_impure_edges() {
    let root = unique_temp_dir("force-cache-import-hit-backed");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ warm = import ./dep.nix; a = import ./dep.nix; }";
    let ir = lower(source);
    let warm = symbol_for(&ir, b"warm");
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
    let (warm_thunk, a_thunk) = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        (
            attrs.get(warm).expect("warm exists"),
            attrs.get(a).expect("a exists"),
        )
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), warm_thunk)
            .expect("warm import force succeeds")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), a_thunk)
            .expect("cached import force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::write(root.join("dep.nix"), b"2").expect("import source changes");

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
        .expect("changed import-cache-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn symlinked_import_cache_hits_skip_force_cache_hits() {
    let root = unique_temp_dir("force-cache-import-cache-symlink-hit");
    fs::create_dir(root.join("real")).expect("real import directory creates");
    fs::create_dir(root.join("other")).expect("other import directory creates");
    fs::write(root.join("real").join("dep.nix"), b"1").expect("real import source writes");
    fs::write(root.join("other").join("dep.nix"), b"2").expect("other import source writes");
    std::os::unix::fs::symlink(root.join("real"), root.join("link"))
        .expect("import parent symlink creates");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ warm = import ./real/dep.nix; a = import ./link/dep.nix; }";
    let ir = lower(source);
    let warm = symbol_for(&ir, b"warm");
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
    let (warm_thunk, a_thunk) = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        (
            attrs.get(warm).expect("warm exists"),
            attrs.get(a).expect("a exists"),
        )
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), warm_thunk)
            .expect("safe import force succeeds")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), a_thunk)
            .expect("symlinked import-cache hit succeeds")
            .as_int(),
        Ok(1)
    );

    fs::remove_file(root.join("link")).expect("import parent symlink removes");
    std::os::unix::fs::symlink(root.join("other"), root.join("link"))
        .expect("import parent symlink retargets");

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
        .expect("retargeted symlink import-cache force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn symlinked_import_backed_inline_thunks_skip_force_cache_hits() {
    let root = unique_temp_dir("force-cache-import-symlink");
    fs::write(root.join("one.nix"), b"1").expect("first import source writes");
    fs::write(root.join("two.nix"), b"2").expect("second import source writes");
    std::os::unix::fs::symlink(root.join("one.nix"), root.join("dep.nix"))
        .expect("import symlink creates");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./dep.nix; }";
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
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("symlinked import-backed force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::remove_file(root.join("dep.nix")).expect("import symlink removes");
    std::os::unix::fs::symlink(root.join("two.nix"), root.join("dep.nix"))
        .expect("import symlink retargets");

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
        .expect("retargeted symlink import-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn symlinked_import_parent_inline_thunks_skip_force_cache_hits() {
    let root = unique_temp_dir("force-cache-import-parent-symlink");
    fs::create_dir(root.join("one")).expect("first import directory creates");
    fs::create_dir(root.join("two")).expect("second import directory creates");
    fs::write(root.join("one").join("dep.nix"), b"1").expect("first import source writes");
    fs::write(root.join("two").join("dep.nix"), b"2").expect("second import source writes");
    std::os::unix::fs::symlink(root.join("one"), root.join("link"))
        .expect("import parent symlink creates");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./link/dep.nix; }";
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
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("parent-symlinked import-backed force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::remove_file(root.join("link")).expect("import parent symlink removes");
    std::os::unix::fs::symlink(root.join("two"), root.join("link"))
        .expect("import parent symlink retargets");

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
        .expect("retargeted parent-symlinked import-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_descendant_forced_inline_thunks_record_impure_edges() {
    let root = unique_temp_dir("force-cache-effectful-descendant");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = if builtins.pathExists ./marker then 1 else 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_int(), Ok(1));
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert_eq!(
        cache.len(),
        2,
        "effectful descendants now create an expression node and input leaf"
    );
    assert_eq!(
        cache_nodes_with_dependencies(cache),
        1,
        "the expression node must depend on the descendant pathExists leaf"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}
