//! Force-cache subject tests for captured unsupported and synthetic values.

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
            Value::int(3),
        )
        .expect("apply2 thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("synthetic apply2 thunk is heap-owned");
        assert!(matches!(thunk.kind(), EvalThunkKind::Apply2 { .. }));
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

fn static_selects_for_symbol(ir: &Ir, name: &[u8]) -> Vec<(IrId, IrAttrPathId)> {
    ir.arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            let IrData::Select { path, .. } = node.data else {
                return None;
            };
            let segments = ir.attr_paths.get(path.index())?;
            if segments.len() != 1 {
                return None;
            }
            let IrAttrPathSegment::Static(symbol) = segments[0] else {
                return None;
            };
            (ir.symbols.resolve(symbol) == Some(name)).then_some((IrId::new(index as u32), path))
        })
        .collect()
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

fn captured_static_select_projection_ir() -> (Ir, Symbol, Symbol) {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let unused = symbols.intern(b"unused").expect("unused interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(1),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::Select,
                Span::new(0, 6),
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                    default: None,
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    (ir, used, unused)
}

fn captured_static_select_thunk_for_attrs(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    used: Symbol,
    unused: Symbol,
    selected_value: Value,
    unused_value: Value,
) -> Value {
    captured_static_select_thunk_for_attrs_with_position(
        evaluator,
        ir,
        used,
        unused,
        selected_value,
        None,
        unused_value,
    )
}

fn captured_static_select_thunk_for_attrs_with_position(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    used: Symbol,
    unused: Symbol,
    selected_value: Value,
    selected_position: Option<AttrPosition>,
    unused_value: Value,
) -> Value {
    let selected_entry = match selected_position {
        Some(position) => AttrEntry::with_position(used, selected_value, position),
        None => AttrEntry::new(used, selected_value),
    };
    let attrs = FlatAttrs::new(
        vec![selected_entry, AttrEntry::new(unused, unused_value)],
        &evaluator.symbols,
    )
    .expect("captured receiver attrs build");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured receiver attrs allocate");
    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("captured static select thunk allocates")
}

fn captured_static_select_default_projection_ir() -> (Ir, Symbol, Symbol) {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let unused = symbols.intern(b"unused").expect("unused interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(2),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::LocalVar,
                Span::new(10, 17),
                IrData::Local { slot: 1 },
            ),
            pure_node(
                IrKind::Select,
                Span::new(0, 17),
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                    default: Some(IrId::new(1)),
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    (ir, used, unused)
}

fn captured_static_select_default_nested_let_projection_ir() -> (Ir, Symbol, Symbol) {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let unused = symbols.intern(b"unused").expect("unused interns");
    let default = symbols.intern(b"default").expect("default interns");
    let path = IrAttrPathId::new(0);
    let nodes = vec![
        pure_node(
            IrKind::UpvalVar,
            Span::new(0, 1),
            IrData::Upval { depth: 1, slot: 0 },
        ),
        pure_node(
            IrKind::UpvalVar,
            Span::new(10, 17),
            IrData::Upval { depth: 1, slot: 1 },
        ),
        pure_node(
            IrKind::LocalVar,
            Span::new(27, 34),
            IrData::Local { slot: 0 },
        ),
        pure_node(
            IrKind::Select,
            Span::new(20, 34),
            IrData::Select {
                site: IrInlineCacheSiteId::new(0),
                receiver: IrId::new(0),
                path,
                default: Some(IrId::new(2)),
            },
        ),
        pure_node(
            IrKind::Let,
            Span::new(0, 34),
            IrData::Let {
                bindings: IrBindingSlice::new(0, 1),
                body: IrId::new(3),
                frame: Some(FrameId::new(0)),
            },
        ),
    ];
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
        root: IrId::new(4),
        arena,
        facts,
        symbols,
        frames: vec![FrameInfo {
            slot_count: 1,
            captures: Vec::new().into_boxed_slice(),
            rec: true,
            has_with: false,
        }]
        .into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: vec![Box::new([IrAttrPathSegment::Static(used)]) as Box<[IrAttrPathSegment]>]
            .into_boxed_slice(),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(default),
            position: Some(Span::new(4, 11)),
            value: IrId::new(1),
        }]
        .into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    (ir, used, unused)
}

fn captured_static_select_default_thunk_for_attrs(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    used: Symbol,
    unused: Symbol,
    selected_value: Option<Value>,
    unused_value: Value,
    default_value: Value,
) -> Value {
    let mut entries = Vec::new();
    if let Some(selected_value) = selected_value {
        entries.push(AttrEntry::new(used, selected_value));
    }
    entries.push(AttrEntry::new(unused, unused_value));
    let attrs = FlatAttrs::new(entries, &evaluator.symbols).expect("captured receiver attrs build");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured receiver attrs allocate");
    let frame = EvalFrame::new(2).expect("capture frame allocates");
    frame
        .set(0, captured)
        .expect("receiver capture frame slot sets");
    frame
        .set(1, default_value)
        .expect("default capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("captured defaulted static select thunk allocates")
}

fn unhashable_apply_thunk(evaluator: &mut TreeWalk, id: IrId) -> Value {
    evaluator
        .alloc_apply_thunk(
            id,
            Span::new(20, 21),
            id,
            Span::new(20, 21),
            Value::int(1),
            id,
            Value::int(2),
        )
        .expect("unhashable apply thunk allocates")
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

#[test]
fn captured_static_select_defaults_hit_when_present_branch_ignores_default_and_siblings() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (offset, expected_hit) in [(0, false), (10, true)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-present.nix",
            "x.used or default",
            cache.clone(),
        );
        let default_value = unhashable_apply_thunk(&mut evaluator, IrId::new(3 + offset));
        let unused_value = unhashable_apply_thunk(&mut evaluator, IrId::new(4 + offset));
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Some(Value::int(7)),
            unused_value,
            default_value,
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("present defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "present defaulted selects should hash only the selected branch"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 17), thunk_value)
            .expect("captured defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "unused defaults and siblings should not dirty a present selected path"
        );
        for lazy in [default_value, unused_value] {
            assert_eq!(
                evaluator
                    .heap()
                    .get_thunk(lazy)
                    .expect("lazy fixture thunk remains heap-owned")
                    .cell()
                    .state(),
                Ok(ThunkState::Suspended),
                "present select-default branch must not force unused inputs"
            );
        }
    }
}

#[test]
fn captured_static_select_defaults_present_nested_let_ignores_bound_default_capture() {
    let (ir, used, unused) = captured_static_select_default_nested_let_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (default_value, expected_hit) in [(11, false), (12, true)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-present-nested-let.nix",
            "let default = captured; in x.used or default",
            cache.clone(),
        );
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Some(Value::int(7)),
            Value::int(1),
            Value::int(default_value),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured nested-let defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("present nested-let defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "present nested-let defaults should hash only the selected branch"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 34), thunk_value)
            .expect("captured nested-let defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "bound default captures should not dirty a present selected path"
        );
    }
}

#[test]
fn captured_static_select_defaults_miss_when_present_selected_values_change() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for selected_value in [7, 8] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-present-change.nix",
            "x.used or default",
            cache.clone(),
        );
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Some(Value::int(selected_value)),
            Value::int(1),
            Value::int(99),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("present defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "present defaulted selects should hash the selected value"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 17), thunk_value)
            .expect("captured defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(selected_value));
        assert_eq!(
            evaluator.stats().force_cache_hits(),
            0,
            "changed selected values must not false-hit defaulted select payloads"
        );
    }
}

#[test]
fn captured_static_select_defaults_separate_present_and_missing_equal_values() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut present = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-default-branch-separation.nix",
        "x.used or default",
        cache.clone(),
    );
    let present_thunk = captured_static_select_default_thunk_for_attrs(
        &mut present,
        &ir,
        used,
        unused,
        Some(Value::int(7)),
        Value::int(1),
        Value::int(99),
    );
    let present_forced = present
        .force_admitted_value(ir.root, Span::new(0, 17), present_thunk)
        .expect("present defaulted select force succeeds");
    assert_eq!(present_forced.as_int(), Ok(7));

    let mut missing = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-default-branch-separation.nix",
        "x.used or default",
        cache.clone(),
    );
    let missing_thunk = captured_static_select_default_thunk_for_attrs(
        &mut missing,
        &ir,
        used,
        unused,
        None,
        Value::int(1),
        Value::int(7),
    );
    let subject = {
        let thunk = missing
            .heap()
            .get_thunk(missing_thunk)
            .expect("missing defaulted static select thunk is heap-owned");
        missing
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("missing defaulted static select subject builds")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        2,
        "missing branch should hash the branch marker and default capture"
    );
    let missing_forced = missing
        .force_admitted_value(ir.root, Span::new(0, 17), missing_thunk)
        .expect("missing defaulted select force succeeds");
    assert_eq!(missing_forced.as_int(), Ok(7));
    assert_eq!(
        missing.stats().force_cache_hits(),
        0,
        "present and missing branches must not share a payload even with equal results"
    );
}

#[test]
fn captured_static_select_present_defaults_do_not_scan_unused_unsupported_defaults() {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(2),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::AttrSet,
                Span::new(10, 15),
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 0),
                    recursive: true,
                    has_dynamic: false,
                    frame: None,
                },
            ),
            pure_node(
                IrKind::Select,
                Span::new(0, 15),
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                    default: Some(IrId::new(1)),
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-default-unsupported-present.nix",
        "x.used or rec {}",
        cache.clone(),
    );
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(used, Value::int(7))],
        &evaluator.symbols,
    )
    .expect("captured receiver attrs build");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured receiver attrs allocate");
    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame
        .set(0, captured)
        .expect("receiver capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    let thunk_value = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("captured defaulted static select thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("present defaulted static select thunk is heap-owned");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("present branch should not scan the unused unsupported default")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "present branch should key only on selected value plus branch marker"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 15), thunk_value)
        .expect("present defaulted static select force succeeds");
    assert_eq!(forced.as_int(), Ok(7));
}

#[test]
fn captured_static_select_defaults_missing_branch_hashes_default_capture() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (offset, default_value, expected_hit) in [(0, 11, false), (10, 11, true), (20, 12, false)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-missing.nix",
            "x.used or default",
            cache.clone(),
        );
        let unused_value = unhashable_apply_thunk(&mut evaluator, IrId::new(3 + offset));
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            None,
            unused_value,
            Value::int(default_value),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("missing defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            2,
            "missing defaulted selects should hash the missing branch and default capture"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 17), thunk_value)
            .expect("captured defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(default_value));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "missing defaulted selects should hit only when the default capture matches"
        );
        assert_eq!(
            evaluator
                .heap()
                .get_thunk(unused_value)
                .expect("unselected sibling remains heap-owned")
                .cell()
                .state(),
            Ok(ThunkState::Suspended),
            "missing defaulted selects should not force unselected receiver siblings"
        );
    }
}

#[test]
fn captured_static_select_defaults_missing_nested_let_hashes_bound_default_capture() {
    let (ir, used, unused) = captured_static_select_default_nested_let_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (default_value, expected_hit) in [(11, false), (11, true), (12, false)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-missing-nested-let.nix",
            "let default = captured; in x.used or default",
            cache.clone(),
        );
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            None,
            Value::int(1),
            Value::int(default_value),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured nested-let defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("missing nested-let defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            2,
            "missing nested-let defaults should hash the missing branch and bound default capture"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 34), thunk_value)
            .expect("captured nested-let defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(default_value));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "missing nested-let defaults should hit only when the bound default capture matches"
        );
    }
}

#[test]
fn captured_static_selects_miss_when_selected_values_change() {
    let (ir, used, unused) = captured_static_select_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for selected_value in [7, 8] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-selected-change.nix",
            "x.used",
            cache.clone(),
        );
        let thunk_value = captured_static_select_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Value::int(selected_value),
            Value::int(1),
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

        assert_eq!(forced.as_int(), Ok(selected_value));
        assert_eq!(
            evaluator.stats().force_cache_hits(),
            0,
            "changed selected values must not false-hit through the projected key"
        );
    }
}

#[test]
fn captured_static_selects_fallback_to_whole_receiver_without_forcing_suspended_receivers() {
    let source = "let x = { used = 7; unused = 1; }; in { a = x.used; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-suspended-receiver.nix",
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
    let captured_x = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let env = thunk.env().expect("a captures x");
        env.frames()[0].get(0).expect("x capture exists")
    };
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture is a thunk");
    assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));

    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("captured static select fallback subject builds")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "fallback subject should retain one whole-receiver hash"
    );
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture remains a thunk");
    assert_eq!(
        x_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "projection fallback must not force a suspended receiver"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured static select force succeeds");

    assert_eq!(forced.as_int(), Ok(7));
}

#[test]
fn captured_suspended_computed_thunks_do_not_build_force_cache_subjects() {
    let source = "let x = 1 + 2; in { a = x == 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-suspended-computed.nix",
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
    let captured_x = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let env = thunk.env().expect("a captures x");
        env.frames()[0].get(0).expect("x capture exists")
    };
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture is a thunk");
    assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));

    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured suspended computed thunks must not be hashed into demand keys"
    );
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture remains a thunk");
    assert_eq!(
        x_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "probing the captured force-cache subject must not force captured thunks"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured suspended computed force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "subjects with captured suspended computed thunks wait for canonical value hashes"
    );
}

#[test]
fn captured_nested_let_body_thunks_use_outer_free_variable_hashes() {
    let source = "let x = 1; in { a = let y = x + 2; in y + 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-nested-let-body.nix",
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
                .expect("nested let free-variable slots collect");
            assert_eq!(
                slots.len(),
                1,
                "nested let slot scan should retain exactly the outer x capture"
            );
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("nested let body subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "nested let subject should include exactly the outer x capture"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("nested let body force succeeds");

        assert_eq!(forced.as_int(), Ok(6));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
}

#[test]
fn captured_nested_let_body_thunks_miss_when_outer_free_variables_change() {
    let source = "let f = x: { a = let y = x + 2; in y + 3; }; in { first = f 1; second = f 5; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let first = symbol_for(&ir, b"first");
    let second = symbol_for(&ir, b"second");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-body-changed-capture.nix",
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
        "first nested let subject should include exactly the outer x capture"
    );
    assert_eq!(
        second_subject.free_var_value_hashes.len(),
        1,
        "second nested let subject should include exactly the outer x capture"
    );
    assert_ne!(
        first_subject.free_var_value_hashes, second_subject.free_var_value_hashes,
        "changed outer captures must produce distinct nested-let demand keys"
    );

    let first_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_a)
        .expect("first nested let body force succeeds");
    let second_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_a)
        .expect("second nested let body force succeeds");

    assert_eq!(first_forced.as_int(), Ok(6));
    assert_eq!(
        second_forced.as_int(),
        Ok(10),
        "changed lambda captures must not replay the first nested-let payload"
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "distinct nested-let capture hashes must miss in one shared runtime"
    );
}

#[test]
fn captured_nested_let_body_thunks_skip_dead_binding_free_variables() {
    let source =
        "let used = 1; unused = 2; in { a = let y = used + 2; dead = unused + 10; in y + 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-dead-binding.nix",
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
            .expect("nested let free-variable slots collect");
        assert_eq!(
            slots.len(),
            1,
            "dead nested let bindings must not pull unrelated outer captures into the demand key"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("nested let body subject builds")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "nested let subject should include only the used outer capture"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("nested let body force succeeds");

    assert_eq!(forced.as_int(), Ok(6));
}

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

// Builds synthetic position-free IR rather than parser-lowered source IR so
// attr position metadata does not block the replayable payload path under test.
