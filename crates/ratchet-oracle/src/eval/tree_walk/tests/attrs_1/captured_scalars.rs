//! Force-cache tests for captured scalar free variables.

use super::*;

#[test]
fn captured_context_free_let_string_thunks_use_free_variable_hashes() {
    let source = r#"let x = "s"; in { a = x == x; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
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

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "captured context-free let strings should create a demand node"
    );
}

#[test]
fn repeated_captured_slot_contributes_one_free_variable_hash() {
    let source = r#"let f = x: { a = (x == "s") && (x == "s"); }; in f "s""#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "repeated-capture-slot.nix",
        source,
        cache,
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("captured subject builds")
    };

    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "repeated reads of one captured slot must not duplicate key material"
    );
    assert_eq!(
        subject.memoization_admission,
        ForceCacheMemoizationAdmission::SelectedSubstrate,
        "the in-memory force cache retains first-demand captured admission"
    );
}

#[test]
fn persistent_cache_gates_captured_thunks_on_demand() {
    let source = r#"let f = x: { a = x == "s"; }; in f "s""#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let root = unique_temp_dir("persistent-captured-admission");
    let mut options = TreeWalkOptions::new();
    options.set_persist_cache_root(root);
    let mut evaluator = TreeWalk::with_options_and_source(&ir, options, "expr.nix", source);
    let value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = evaluator
        .heap()
        .get_attrs(value)
        .expect("attrset is heap-owned")
        .get(a)
        .expect("a exists");
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended thunk");
    let subject = evaluator
        .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
        .expect("captured persistent subject builds");

    assert_eq!(
        subject.memoization_admission,
        ForceCacheMemoizationAdmission::ConditionalThunk,
        "persistent capture must wait for demand evidence"
    );
}

#[test]
fn captured_context_free_string_thunks_use_free_variable_hashes() {
    let source = r#"let f = x: { a = x == "s"; }; in [ (f "s").a (f "t").a ]"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "string-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured string attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured string attr force succeeds");

    assert_eq!(second.as_bool(), Ok(false));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different captured string values must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different captured strings should create distinct demand nodes"
    );
}

#[test]
fn captured_context_free_string_thunks_hit_when_hashes_match() {
    let source = r#"let f = x: { a = x == "s"; }; in { a = (f "s").a; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "string-captures.nix",
            source,
            cache.clone(),
        );
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
            .expect("captured string force succeeds");
        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching captured string hashes should share one demand node"
    );
}

#[test]
fn captured_path_thunks_use_free_variable_hashes() {
    let source = r#"let f = x: { a = x == /tmp/a; }; in [ (f /tmp/a).a (f /tmp/b).a ]"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "path-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured path attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured path attr force succeeds");

    assert_eq!(second.as_bool(), Ok(false));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different captured path values must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different captured paths should create distinct demand nodes"
    );
}

#[test]
fn captured_path_thunks_hit_when_hashes_match() {
    let source = r#"let f = x: { a = x == /tmp/a; }; in { a = (f /tmp/a).a; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "path-captures.nix",
            source,
            cache.clone(),
        );
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
            .expect("captured path force succeeds");
        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching captured path hashes should share one demand node"
    );
}

#[test]
fn captured_string_and_path_values_do_not_share_free_variable_hashes() {
    let source = r#"let f = x: { a = x == x; }; in [ (f "/tmp/a").a (f /tmp/a).a ]"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "string-path-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("captured string attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("captured path attr force succeeds");

    assert_eq!(second.as_bool(), Ok(true));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "captured strings and paths with identical bytes must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "captured string and path values should create distinct demand nodes"
    );
}
