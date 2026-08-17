//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn source_less_forced_inline_thunks_include_lowered_ir_in_cache_identity() {
    let first_ir = lower("{ a = 1 + 2; }");
    let second_ir = lower("{ a = 1 + 3; }");
    let first_a = symbol_for(&first_ir, b"a");
    let second_a = symbol_for(&second_ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&first_ir, TreeWalkOptions::new(), cache.clone());
    let root = first.eval_root().expect("first attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(first_a).expect("a exists")
    };
    let forced = first
        .force_admitted_value(first_ir.root, Span::new(0, 0), thunk_value)
        .expect("first force succeeds");
    assert_eq!(forced.as_int(), Ok(3));

    let mut second =
        TreeWalk::with_options_and_eval_cache(&second_ir, TreeWalkOptions::new(), cache.clone());
    let root = second.eval_root().expect("second attrset evaluates");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(second_a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(second_ir.root, Span::new(0, 0), thunk_value)
        .expect("second force succeeds");
    assert_eq!(forced.as_int(), Ok(4));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "different lowered IR artifacts must not reuse one cache entry"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different lowered IR fingerprints should allocate separate demand nodes"
    );
}

#[test]
fn source_less_forced_inline_thunks_include_path_base_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-path-base");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).expect("first dir exists");
    fs::create_dir_all(&second_dir).expect("second dir exists");
    let first_dir = fs::canonicalize(&first_dir).expect("first dir canonicalizes");
    let second_dir = fs::canonicalize(&second_dir).expect("second dir canonicalizes");
    let source = "{ a = ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for path_base in [&first_dir, &second_dir] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(path_base))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(
            path_value_bytes(&evaluator, forced),
            path_bytes(&path_base.join("target"))
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different path bases must not reuse a path payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different path bases must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_store_dir_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for store_dir in [&first_store, &second_store] {
        let mut options = TreeWalkOptions::new();
        options
            .set_store_dir(path_bytes(store_dir))
            .expect("store dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less store dirs must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different store dirs must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_home_dir_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-home-dir");
    let first_home = root.join("home-a");
    let second_home = root.join("home-b");
    fs::create_dir_all(&first_home).expect("first home exists");
    fs::create_dir_all(&second_home).expect("second home exists");
    fs::write(first_home.join("marker"), b"present").expect("first marker exists");
    let first_home = fs::canonicalize(&first_home).expect("first home canonicalizes");
    let second_home = fs::canonicalize(&second_home).expect("second home canonicalizes");
    let source = "{ a = builtins.pathExists ~/marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (home_dir, expected) in [(&first_home, true), (&second_home, false)] {
        let mut options = TreeWalkOptions::new();
        options
            .set_home_dir(path_bytes(home_dir))
            .expect("home dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_bool(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less home dirs must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        4,
        "different source-less home dirs should produce separate expression and input nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_eval_mode_in_cache_identity() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for mode in [EvalMode::Impure, EvalMode::Pure] {
        let options = TreeWalkOptions::with_eval_mode(mode);
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less eval modes must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different eval modes must not reuse one demand node"
    );
}
