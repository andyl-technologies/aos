//! Split-out tests (part_3). See parent module.

use super::*;

#[test]
fn captured_nested_let_body_thunks_keep_transitive_live_binding_free_variables() {
    let source = "let f = x: unused: { a = let y = z + 1; z = x + 2; dead = unused + 10; in y + 3; }; in { first = f 1 8; second = f 5 8; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let first = symbol_for(&ir, b"first");
    let second = symbol_for(&ir, b"second");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-transitive-live-change.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let (first_thunk, second_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        (
            attrs.get(first).expect("first exists"),
            attrs.get(second).expect("second exists"),
        )
    };

    let first_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_thunk)
        .expect("first function result force succeeds");
    let second_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("second function result force succeeds");
    let (first_a, second_a) = {
        let first_attrs = evaluator
            .heap()
            .get_attrs(first_attrs_value)
            .expect("first function result is an attrset");
        let first_a = first_attrs.get(a).expect("first a exists");
        let second_attrs = evaluator
            .heap()
            .get_attrs(second_attrs_value)
            .expect("second function result is an attrset");
        let second_a = second_attrs.get(a).expect("second a exists");
        (first_a, second_a)
    };
    let first_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(first_a)
            .expect("first a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("first nested let body subject builds")
    };
    let second_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(second_a)
            .expect("second a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("second nested let body subject builds")
    };
    assert_eq!(
        first_subject.free_var_value_hashes.len(),
        1,
        "transitive live bindings should retain the first outer x capture only"
    );
    assert_eq!(
        second_subject.free_var_value_hashes.len(),
        1,
        "transitive live bindings should retain the second outer x capture only"
    );
    assert_ne!(
        first_subject.free_var_value_hashes, second_subject.free_var_value_hashes,
        "changed transitive live captures must produce distinct demand keys"
    );

    let first_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_a)
        .expect("first nested let body force succeeds");
    let second_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_a)
        .expect("second nested let body force succeeds");

    assert_eq!(first_forced.as_int(), Ok(7));
    assert_eq!(
        second_forced.as_int(),
        Ok(11),
        "changed transitive captures must not replay the first nested-let payload"
    );
    assert_eq!(
        evaluator.stats().force_cache_hits(),
        0,
        "distinct transitive live capture hashes must miss in one shared runtime"
    );
}

#[test]
fn captured_nested_let_body_thunks_drop_dead_transitive_binding_free_variables() {
    let source = "let f = unused: { a = let y = z + 1; z = 1; dead = unused + 10; in y + 3; }; in { first = f 1; second = f 5; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let first = symbol_for(&ir, b"first");
    let second = symbol_for(&ir, b"second");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-transitive-dead-change.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let (first_thunk, second_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        (
            attrs.get(first).expect("first exists"),
            attrs.get(second).expect("second exists"),
        )
    };

    let first_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_thunk)
        .expect("first function result force succeeds");
    let second_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("second function result force succeeds");
    let (first_a, second_a) = {
        let first_attrs = evaluator
            .heap()
            .get_attrs(first_attrs_value)
            .expect("first function result is an attrset");
        let first_a = first_attrs.get(a).expect("first a exists");
        let second_attrs = evaluator
            .heap()
            .get_attrs(second_attrs_value)
            .expect("second function result is an attrset");
        let second_a = second_attrs.get(a).expect("second a exists");
        (first_a, second_a)
    };
    let first_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(first_a)
            .expect("first a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("first nested let body subject builds")
    };
    let second_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(second_a)
            .expect("second a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("second nested let body subject builds")
    };
    assert!(
        first_subject.free_var_value_hashes.is_empty(),
        "dead transitive bindings must not enter the first nested-let demand key"
    );
    assert!(
        second_subject.free_var_value_hashes.is_empty(),
        "dead transitive bindings must not enter the second nested-let demand key"
    );

    let hits_before = evaluator.stats().force_cache_hits();
    let first_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_a)
        .expect("first nested let body force succeeds");
    let second_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_a)
        .expect("second nested let body force succeeds");

    assert_eq!(first_forced.as_int(), Ok(5));
    assert_eq!(second_forced.as_int(), Ok(5));
    assert!(
        evaluator.stats().force_cache_hits() > hits_before,
        "changing only a dead outer capture should reuse the first transitive nested-let payload"
    );
}

#[test]
fn captured_nested_let_body_thunks_fallback_to_prior_static_binding_traversal() {
    let source = "let used = 1; unused = 2; in { a = let y = let z = used + 1; in z; dead = unused + 10; in y + 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-fallback-static-traversal.nix",
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
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let body = thunk.body().expect("a has a lowered nested let body");
        let node = ir.arena.node(body).expect("nested let body exists");
        assert!(
            matches!(node.data, IrData::Let { .. }),
            "fixture must exercise a nested let body"
        );
        let env = thunk.env().expect("a captures the outer let frame");
        let slots = TreeWalk::captured_free_variable_slots(&ir, body, env.frames().len())
            .expect("fallback nested let free-variable slots collect");
        assert_eq!(
            slots.len(),
            2,
            "fallback should preserve the prior all-static-binding dependency set"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("fallback nested let body subject builds")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        2,
        "fallback nested let subject should preserve both outer captures"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("nested let body force succeeds");

    assert_eq!(forced.as_int(), Ok(5));
}

#[test]
fn captured_nested_let_body_thunks_hit_when_only_dead_outer_free_variables_change() {
    let source = "let f = unused: { a = let y = 1; dead = unused + 10; in y + 3; }; in { first = f 1; second = f 5; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let first = symbol_for(&ir, b"first");
    let second = symbol_for(&ir, b"second");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-dead-outer-change.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let (first_thunk, second_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        (
            attrs.get(first).expect("first exists"),
            attrs.get(second).expect("second exists"),
        )
    };

    let first_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_thunk)
        .expect("first function result force succeeds");
    let second_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("second function result force succeeds");
    let (first_a, second_a) = {
        let first_attrs = evaluator
            .heap()
            .get_attrs(first_attrs_value)
            .expect("first function result is an attrset");
        let first_a = first_attrs.get(a).expect("first a exists");
        let second_attrs = evaluator
            .heap()
            .get_attrs(second_attrs_value)
            .expect("second function result is an attrset");
        let second_a = second_attrs.get(a).expect("second a exists");
        (first_a, second_a)
    };
    let first_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(first_a)
            .expect("first a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("first nested let body subject builds")
    };
    let second_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(second_a)
            .expect("second a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("second nested let body subject builds")
    };
    assert!(
        first_subject.free_var_value_hashes.is_empty(),
        "dead outer captures must not enter the first nested-let demand key"
    );
    assert!(
        second_subject.free_var_value_hashes.is_empty(),
        "dead outer captures must not enter the second nested-let demand key"
    );

    let hits_before = evaluator.stats().force_cache_hits();
    let first_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_a)
        .expect("first nested let body force succeeds");
    let second_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_a)
        .expect("second nested let body force succeeds");

    assert_eq!(first_forced.as_int(), Ok(4));
    assert_eq!(second_forced.as_int(), Ok(4));
    assert!(
        evaluator.stats().force_cache_hits() > hits_before,
        "changing only a dead outer capture should reuse the first nested-let payload"
    );
}

#[test]
fn captured_nested_let_body_thunks_with_dynamic_binding_keys_do_not_build_force_cache_subjects() {
    let source = "let x = 1; in { a = let y = x + 2; in y + 3; }";
    let mut ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let y = symbol_for(&ir, b"y");
    let dynamic_key = ir.root;
    let nested_bindings = ir
        .arena
        .nodes()
        .iter()
        .find_map(|node| {
            let IrData::Let { bindings, .. } = node.data else {
                return None;
            };
            ir.bindings
                .get(bindings.start as usize..bindings.start as usize + bindings.len())?
                .iter()
                .any(|binding| matches!(binding.key, IrAttrPathSegment::Static(symbol) if symbol == y))
                .then_some(bindings)
        })
        .expect("lowered source should contain a nested let binding for y");
    let binding = ir
        .bindings
        .get_mut(nested_bindings.start as usize)
        .expect("nested let binding exists");
    binding.key = IrAttrPathSegment::Dynamic(dynamic_key);

    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-body-dynamic-key.nix",
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
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let body = thunk.body().expect("a has a lowered nested let body");
        let node = ir.arena.node(body).expect("nested let body exists");
        let IrData::Let { bindings, .. } = node.data else {
            panic!("fixture must exercise a nested let body");
        };
        assert!(
            ir.bindings
                .get(bindings.start as usize..bindings.start as usize + bindings.len())
                .expect("nested let bindings exist")
                .iter()
                .any(|binding| matches!(binding.key, IrAttrPathSegment::Dynamic(_))),
            "fixture must exercise a lowered nested let with a dynamic binding key"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "lowered nested lets with dynamic binding keys must not build demand keys"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "dynamic-key nested let subjects should skip expression node allocation"
    );
}

#[test]
fn dynamic_with_scoped_thunks_do_not_build_force_cache_subjects() {
    let source = "with { x = 1; }; { a = x + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "with-scoped-force-cache.nix",
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
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        assert!(
            !thunk
                .with_scope_env()
                .expect("a captures dynamic with scopes")
                .scopes()
                .is_empty(),
            "fixture must exercise a captured dynamic with scope"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "dynamic with-scoped thunks must not be hashed into demand keys"
    );
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("with-scoped attr force succeeds");

    assert_eq!(forced.as_int(), Ok(3));
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "forcing through a dynamic with scope may observe the closed with-scope attrset, but not the with-scoped thunk subject"
    );
}

#[test]
fn scoped_import_global_thunks_do_not_build_force_cache_subjects() {
    let root = fs::canonicalize(unique_temp_dir("force-cache-scoped-import-subject"))
        .expect("temp directory canonicalizes");
    fs::write(root.join("scoped.nix"), b"{ a = x + 1; }").expect("scoped import source writes");
    let source = "builtins.scopedImport { x = 2; } ./scoped.nix";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "scoped-import-force-cache.nix",
        source,
        cache.clone(),
    );
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let imported = evaluator.eval_root().expect("scoped import evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(imported)
            .expect("import result is an attrset");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        assert!(
            !thunk
                .scoped_global_env()
                .expect("a captures scoped-import globals")
                .scopes()
                .is_empty(),
            "fixture must exercise scoped-import globals"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "scoped-import global thunks must not be hashed into demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("scoped-import attr force succeeds");

    assert_eq!(forced.as_int(), Ok(3));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "scoped-import global thunk subjects should skip expression node allocation"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn captured_lambda_body_thunks_do_not_build_force_cache_subjects() {
    let source = "let x = 1; in { a = y: x + y; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-lambda-body.nix",
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
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let body = thunk.body().expect("a has a lowered lambda body");
        let node = ir.arena.node(body).expect("lambda body exists");
        assert!(
            matches!(node.data, IrData::Lambda { .. }),
            "fixture must exercise a lambda body"
        );
        assert!(
            subtree_contains_upval_capture(&ir, body),
            "fixture lambda body must contain an upvalue capture"
        );
        let env = thunk.env().expect("a captures the outer let frame");
        assert!(
            !env.frames().is_empty(),
            "fixture must capture a lexical frame"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured lambda bodies must not be hashed into demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured lambda body force succeeds");

    assert_eq!(forced.tag(), ValueTag::Lambda);
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "captured lambda-body thunk subjects should skip expression node allocation"
    );
}

#[test]
fn captured_recursive_attrset_body_thunks_do_not_build_force_cache_subjects() {
    let source = "let x = 1; in { a = rec { y = x; }; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-recursive-attrset-body.nix",
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
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let body = thunk.body().expect("a has a lowered attrset body");
        let node = ir.arena.node(body).expect("attrset body exists");
        assert!(
            matches!(
                node.data,
                IrData::AttrSet {
                    recursive: true,
                    ..
                }
            ),
            "fixture must exercise a recursive attrset body"
        );
        assert!(
            subtree_contains_upval_capture(&ir, body),
            "fixture recursive attrset body must contain an upvalue capture"
        );
        let env = thunk.env().expect("a captures the outer let frame");
        assert!(
            !env.frames().is_empty(),
            "fixture must capture a lexical frame"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured recursive attrset bodies must not be hashed into demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured recursive attrset body force succeeds");

    assert_eq!(forced.tag(), ValueTag::Attrs);
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "captured recursive-attrset thunk subjects should skip expression node allocation"
    );
}

#[test]
fn captured_empty_lists_use_free_variable_hashes() {
    let source = "let f = x: { a = x == x; }; in { a = (f []).a; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-list-captures.nix",
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
            .expect("captured empty list force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        !runtime.cache().expect("cache is enabled").is_empty(),
        "captured empty lists should create a demand node"
    );
}

#[test]
fn captured_replayable_lists_hit_when_hashes_match() {
    let source = "let f = x: { a = x == x; }; in { a = (f [ 1 true null ]).a; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "list-captures.nix",
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
            .expect("captured list force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
}

#[test]
fn captured_free_variable_thunks_admit_on_first_raw_force() {
    let source = r#"let f = x: { a = x == "value"; }; in { a = (f "value").a; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-first-demand.nix",
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
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured attr force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        evaluator.stats().force_cache_memoization_bypasses(),
        0,
        "captured free-variable subjects should not need helper pre-admission"
    );
    assert!(
        evaluator.stats().force_cache_memoization_admits() > 0,
        "captured free-variable subjects should admit on first raw force"
    );
    assert!(
        evaluator.stats().force_cache_misses() > 0,
        "first raw force should probe and populate the selected captured subject"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        !runtime.cache().expect("cache is enabled").is_empty(),
        "first raw force should allocate a captured expression node"
    );
}

#[test]
fn closed_composite_literal_thunks_admit_on_first_raw_force() {
    let source = "{ a = [ 1 true null ]; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "composite-first-demand.nix",
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
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("composite literal force succeeds");

    assert_eq!(
        evaluator
            .heap()
            .get_list(forced)
            .expect("forced value is a list")
            .len(),
        3
    );
    assert_eq!(evaluator.stats().force_cache_memoization_bypasses(), 0);
    assert_eq!(
        evaluator.stats().force_cache_memoization_admits(),
        1,
        "closed replayable composite literals should admit on first raw force"
    );
    assert_eq!(evaluator.stats().force_cache_misses(), 1);
    assert_eq!(evaluator.stats().force_cache_probes(), 1);
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "first raw force should allocate the closed composite expression node"
    );
}

