//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn captured_lambda_values_do_not_build_force_cache_subjects() {
    let source = "let x = y: y; in builtins.seq x { a = x == x; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-lambda-value.nix",
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
    let (captured_x, cached_x) =
        captured_fulfilled_slot_with_cached_tag(&evaluator, thunk_value, 0, 0, ValueTag::Lambda)
            .expect("x is a fulfilled lambda capture in the first let slot");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured lambda values must not be hashed into demand keys"
    );
    assert!(
        captured_fulfilled_slot_with_cached_tag(&evaluator, thunk_value, 0, 0, ValueTag::Lambda)
            .map(|(captured, cached)| captured.raw_eq(captured_x) && cached.raw_eq(cached_x))
            .unwrap_or(false),
        "probing the force-cache subject must not rewrite captured lambda thunks or payloads"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured lambda value force succeeds");

    assert_eq!(forced.as_bool(), Ok(false));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "captured lambda values need function payload policy before observation"
    );
}

#[test]
fn captured_primop_values_do_not_build_force_cache_subjects() {
    let source = "let x = builtins.length; in builtins.seq x { a = x == x; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-primop-value.nix",
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
    let (captured_x, cached_x) =
        captured_fulfilled_slot_with_cached_tag(&evaluator, thunk_value, 0, 0, ValueTag::Primop)
            .expect("x is a fulfilled primop capture in the first let slot");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured primop values must not be hashed into demand keys"
    );
    assert!(
        captured_fulfilled_slot_with_cached_tag(&evaluator, thunk_value, 0, 0, ValueTag::Primop)
            .map(|(captured, cached)| captured.raw_eq(captured_x) && cached.raw_eq(cached_x))
            .unwrap_or(false),
        "probing the force-cache subject must not rewrite captured primop thunks or payloads"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured primop value force succeeds");

    assert_eq!(forced.as_bool(), Ok(false));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "captured primop values need function payload policy before observation"
    );
}

#[test]
fn synthetic_apply_thunks_do_not_build_force_cache_subjects() {
    let source = "x: x + 1";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-apply-force-cache.nix",
        source,
        cache.clone(),
    );
    let function = evaluator.eval_root().expect("lambda evaluates");
    assert_eq!(function.tag(), ValueTag::Lambda);
    let thunk_value = evaluator
        .alloc_apply_thunk(
            ir.root,
            Span::new(0, source.len() as u32),
            ir.root,
            Span::new(0, source.len() as u32),
            function,
            ir.root,
            Value::int(2),
        )
        .expect("apply thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("synthetic apply thunk is heap-owned");
        assert!(matches!(thunk.kind(), EvalThunkKind::Apply { .. }));
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "synthetic apply thunks must not be hashed into demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, source.len() as u32), thunk_value)
        .expect("synthetic apply thunk force succeeds");

    assert_eq!(forced.as_int(), Ok(3));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "synthetic apply thunk subjects should skip expression node allocation"
    );
}

#[test]
fn synthetic_apply2_thunks_do_not_build_force_cache_subjects() {
    let source = "x: y: x + y";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-apply2-force-cache.nix",
        source,
        cache.clone(),
    );
    let function = evaluator.eval_root().expect("lambda evaluates");
    assert_eq!(function.tag(), ValueTag::Lambda);
    let thunk_value = evaluator
        .alloc_apply2_thunk(
            ir.root,
            Span::new(0, source.len() as u32),
            ir.root,
            Span::new(0, source.len() as u32),
            function,
            ir.root,
            Span::new(0, 1),
            Value::int(2),
            ir.root,
            Span::new(0, source.len() as u32),
            Value::int(3),
        )
        .expect("apply2 thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("synthetic apply2 thunk is heap-owned");
        assert!(matches!(thunk.kind(), EvalThunkKind::Apply2(_)));
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "synthetic apply2 thunks must not be hashed into demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, source.len() as u32), thunk_value)
        .expect("synthetic apply2 thunk force succeeds");

    assert_eq!(forced.as_int(), Ok(5));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "synthetic apply2 thunk subjects should skip expression node allocation"
    );
}

#[test]
fn synthetic_select_thunks_with_hashable_receivers_build_force_cache_subjects() {
    let source = "{ a = 1; }.a";
    let ir = lower(source);
    let path = {
        let node = ir.arena.node(ir.root).expect("root select exists");
        let IrData::Select { path, .. } = node.data else {
            panic!("root is a select");
        };
        path
    };
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-select-force-cache.nix",
        source,
        cache.clone(),
    );
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(7))], &evaluator.symbols)
        .expect("receiver attrs build");
    let receiver = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("receiver attrs allocate");
    let thunk_value = evaluator
        .alloc_select_thunk(
            ir.root,
            Span::new(0, source.len() as u32),
            ir.root,
            receiver,
            path,
        )
        .expect("select thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("synthetic select thunk is heap-owned");
        assert!(matches!(thunk.kind(), EvalThunkKind::Select { .. }));
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_some(),
        "synthetic select thunks over hashable receivers should build demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, source.len() as u32), thunk_value)
        .expect("synthetic select thunk force succeeds");

    assert_eq!(forced.as_int(), Ok(7));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        !runtime.cache().expect("cache is enabled").is_empty(),
        "synthetic select thunk subjects should allocate expression nodes"
    );
}

#[test]
fn synthetic_select_thunks_hit_when_receiver_hashes_match() {
    let source = "{ a = 1; }.a";
    let ir = lower(source);
    let path = {
        let node = ir.arena.node(ir.root).expect("root select exists");
        let IrData::Select { path, .. } = node.data else {
            panic!("root is a select");
        };
        path
    };
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "synthetic-select-force-cache-hit.nix",
            source,
            cache.clone(),
        );
        let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(7))], &evaluator.symbols)
            .expect("receiver attrs build");
        let receiver = evaluator
            .heap
            .alloc_attrs(0, attrs)
            .expect("receiver attrs allocate");
        let thunk_value = evaluator
            .alloc_select_thunk(
                ir.root,
                Span::new(0, source.len() as u32),
                ir.root,
                receiver,
                path,
            )
            .expect("select thunk allocates");
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, source.len() as u32), thunk_value)
            .expect("synthetic select thunk force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching selected receiver hashes should share one demand node"
    );
}

#[test]
fn synthetic_select_thunks_hit_when_unselected_receiver_siblings_change() {
    let source = "{ a = 1; b = 2; }.a";
    let ir = lower(source);
    let path = {
        let node = ir.arena.node(ir.root).expect("root select exists");
        let IrData::Select { path, .. } = node.data else {
            panic!("root is a select");
        };
        path
    };
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (unused_sibling, expected_hit) in [(2, false), (3, true)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "synthetic-select-unselected-sibling.nix",
            source,
            cache.clone(),
        );
        let attrs = FlatAttrs::new(
            vec![
                AttrEntry::new(a, Value::int(7)),
                AttrEntry::new(b, Value::int(unused_sibling)),
            ],
            &evaluator.symbols,
        )
        .expect("receiver attrs build");
        let receiver = evaluator
            .heap
            .alloc_attrs(0, attrs)
            .expect("receiver attrs allocate");
        let thunk_value = evaluator
            .alloc_select_thunk(
                ir.root,
                Span::new(0, source.len() as u32),
                ir.root,
                receiver,
                path,
            )
            .expect("select thunk allocates");
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, source.len() as u32), thunk_value)
            .expect("synthetic select thunk force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(
            evaluator.stats().cache_hits() > 0,
            expected_hit,
            "unselected receiver siblings should not dirty the selected path key"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching selected values should share one demand node even when siblings change"
    );
}

#[test]
fn synthetic_select_thunks_include_path_and_site_in_cache_key() {
    let source = "let r = { a = 1; b = 2; }; in { left = r.a; middle = r.b; right = r.a; }";
    let ir = lower(source);
    let select_a = static_selects_for_symbol(&ir, b"a");
    let select_b = static_selects_for_symbol(&ir, b"b");
    let [(first_a, path_a), (second_a, _)] = select_a.as_slice() else {
        panic!("expected two static .a select sites");
    };
    let [(_, path_b)] = select_b.as_slice() else {
        panic!("expected one static .b select site");
    };
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (select, path, expected, message) in [
        (*first_a, *path_a, 7, "first selected path should be cold"),
        (
            *first_a,
            *path_b,
            8,
            "changed selected path at the same site must not hit",
        ),
        (
            *second_a,
            *path_a,
            7,
            "changed select site for the same path must not hit",
        ),
    ] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "synthetic-select-path-site-force-cache.nix",
            source,
            cache.clone(),
        );
        let attrs = FlatAttrs::new(
            vec![
                AttrEntry::new(a, Value::int(7)),
                AttrEntry::new(b, Value::int(8)),
            ],
            &evaluator.symbols,
        )
        .expect("receiver attrs build");
        let receiver = evaluator
            .heap
            .alloc_attrs(0, attrs)
            .expect("receiver attrs allocate");
        let thunk_value = evaluator
            .alloc_select_thunk(
                select,
                Span::new(0, source.len() as u32),
                select,
                receiver,
                path,
            )
            .expect("select thunk allocates");
        let forced = evaluator
            .force_admitted_value(select, Span::new(0, source.len() as u32), thunk_value)
            .expect("synthetic select thunk force succeeds");

        assert_eq!(forced.as_int(), Ok(expected));
        assert_eq!(evaluator.stats().cache_hits(), 0, "{message}");
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        3,
        "select path and site should both separate otherwise matching receiver keys"
    );
}

#[test]
fn synthetic_select_thunks_include_receiver_hashes_in_cache_key() {
    let source = "{ a = 1; }.a";
    let ir = lower(source);
    let path = {
        let node = ir.arena.node(ir.root).expect("root select exists");
        let IrData::Select { path, .. } = node.data else {
            panic!("root is a select");
        };
        path
    };
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for selected in [7, 8] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "synthetic-select-force-cache-miss.nix",
            source,
            cache.clone(),
        );
        let attrs = FlatAttrs::new(
            vec![AttrEntry::new(a, Value::int(selected))],
            &evaluator.symbols,
        )
        .expect("receiver attrs build");
        let receiver = evaluator
            .heap
            .alloc_attrs(0, attrs)
            .expect("receiver attrs allocate");
        let thunk_value = evaluator
            .alloc_select_thunk(
                ir.root,
                Span::new(0, source.len() as u32),
                ir.root,
                receiver,
                path,
            )
            .expect("select thunk allocates");
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, source.len() as u32), thunk_value)
            .expect("synthetic select thunk force succeeds");

        assert_eq!(forced.as_int(), Ok(selected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "changed receiver hashes must not false-hit a stale selected value"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different selected receiver hashes should create distinct demand nodes"
    );
}

#[test]
fn synthetic_select_thunks_with_dynamic_paths_do_not_build_force_cache_subjects() {
    let source = r#"let key = "a"; in { a = 1; }.${key}"#;
    let ir = lower(source);
    let (select, path) = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            let IrData::Select { path, .. } = node.data else {
                return None;
            };
            let segments = ir.attr_paths.get(path.index())?;
            segments
                .iter()
                .any(|segment| matches!(segment, IrAttrPathSegment::Dynamic(_)))
                .then_some((IrId::new(index as u32), path))
        })
        .expect("lowered source should contain a dynamic select path");
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-select-dynamic-path.nix",
        source,
        cache.clone(),
    );
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(7))], &evaluator.symbols)
        .expect("receiver attrs build");
    let receiver = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("receiver attrs allocate");
    let thunk_value = evaluator
        .alloc_select_thunk(
            select,
            Span::new(0, source.len() as u32),
            select,
            receiver,
            path,
        )
        .expect("select thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("synthetic select thunk is heap-owned");
        assert!(matches!(thunk.kind(), EvalThunkKind::Select { .. }));
        evaluator.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, select), thunk)
    };
    assert!(
        subject.is_none(),
        "synthetic select thunks with dynamic paths must not build demand keys"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "dynamic select paths should skip expression node allocation"
    );
}

#[test]
fn synthetic_select_thunks_with_unhashable_receivers_do_not_build_force_cache_subjects() {
    let source = "{ a = 1; }.a";
    let ir = lower(source);
    let path = {
        let node = ir.arena.node(ir.root).expect("root select exists");
        let IrData::Select { path, .. } = node.data else {
            panic!("root is a select");
        };
        path
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-select-unhashable-receiver.nix",
        source,
        cache.clone(),
    );
    let receiver = evaluator
        .alloc_apply_thunk(
            ir.root,
            Span::new(0, source.len() as u32),
            ir.root,
            Span::new(0, source.len() as u32),
            Value::int(1),
            ir.root,
            Value::int(2),
        )
        .expect("unhashable receiver thunk allocates");
    let thunk_value = evaluator
        .alloc_select_thunk(
            ir.root,
            Span::new(0, source.len() as u32),
            ir.root,
            receiver,
            path,
        )
        .expect("select thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("synthetic select thunk is heap-owned");
        assert!(matches!(thunk.kind(), EvalThunkKind::Select { .. }));
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "synthetic select thunks over unhashable receivers must not build demand keys"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "unhashable select receivers should skip expression node allocation"
    );
}

#[test]
fn synthetic_select_thunks_with_unhashable_selected_values_do_not_build_force_cache_subjects() {
    let source = "{ a = 1; }.a";
    let ir = lower(source);
    let path = {
        let node = ir.arena.node(ir.root).expect("root select exists");
        let IrData::Select { path, .. } = node.data else {
            panic!("root is a select");
        };
        path
    };
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-select-unhashable-selected-value.nix",
        source,
        cache.clone(),
    );
    let selected = evaluator
        .alloc_apply_thunk(
            ir.root,
            Span::new(0, source.len() as u32),
            ir.root,
            Span::new(0, source.len() as u32),
            Value::int(1),
            ir.root,
            Value::int(2),
        )
        .expect("unhashable selected thunk allocates");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, selected)], &evaluator.symbols)
        .expect("receiver attrs build");
    let receiver = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("receiver attrs allocate");
    let thunk_value = evaluator
        .alloc_select_thunk(
            ir.root,
            Span::new(0, source.len() as u32),
            ir.root,
            receiver,
            path,
        )
        .expect("select thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("synthetic select thunk is heap-owned");
        assert!(matches!(thunk.kind(), EvalThunkKind::Select { .. }));
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "synthetic select thunks over unhashable selected values must not build demand keys"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "unhashable selected values should skip expression node allocation"
    );
}

#[test]
fn captured_static_selects_hit_when_unselected_receiver_siblings_change() {
    let (ir, used, unused) = captured_static_select_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (unused_value, expected_hit) in [(1, false), (2, true)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-projection.nix",
            "x.used",
            cache.clone(),
        );
        let thunk_value = captured_static_select_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Value::int(7),
            Value::int(unused_value),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("captured static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "captured static select subject should hash the selected value"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 6), thunk_value)
            .expect("captured static select force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(
            evaluator.stats().force_cache_hits() > 0,
            expected_hit,
            "unselected captured receiver siblings should not dirty the selected path key"
        );
    }
}

#[test]
fn captured_static_selects_miss_when_selected_binding_position_changes() {
    let (ir, used, unused) = captured_static_select_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (position, expected_hit) in [(Span::new(2, 6), false), (Span::new(3, 7), false)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-position-change.nix",
            "x.used",
            cache.clone(),
        );
        let thunk_value = captured_static_select_thunk_for_attrs_with_position(
            &mut evaluator,
            &ir,
            used,
            unused,
            Value::int(7),
            Some(AttrPosition::new(EvalModuleId::ROOT.as_u32(), position)),
            Value::int(1),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("positioned captured static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "positioned captured static selects should still project one selected-value hash"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 6), thunk_value)
            .expect("positioned captured static select force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(
            evaluator.stats().force_cache_hits() > 0,
            expected_hit,
            "changed selected binding positions must miss even when the selected value is unchanged"
        );
    }
}
