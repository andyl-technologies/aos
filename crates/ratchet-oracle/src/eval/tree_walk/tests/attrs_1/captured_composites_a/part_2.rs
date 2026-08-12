//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn captured_lazy_binding_has_attr_values_use_presence_hashes_without_forcing() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(1),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::HasAttr,
                Span::new(0, 5),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                },
            ),
            pure_node(IrKind::Int, Span::new(10, 11), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(14, 15), IrData::Int(0)),
            pure_node(
                IrKind::BinOp,
                Span::new(10, 15),
                IrData::Binary {
                    op: BinOpKind::Div,
                    lhs: IrId::new(2),
                    rhs: IrId::new(3),
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(a)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-lazy-binding-attrset-value.nix",
        "x ? a",
        cache.clone(),
    );
    let lazy_binding = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("lazy binding thunk allocates");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, lazy_binding)], &evaluator.symbols)
        .expect("lazy-binding attrset builds");
    assert_eq!(
        attrs.source_order(),
        attrs.iteration_order(),
        "fixture attrset must be source-order-canonical"
    );
    assert!(
        !attrset_has_binding_position(&attrs),
        "fixture attrset must not carry binding positions"
    );
    let captured_x = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("lazy-binding attrset allocates");
    let binding = {
        let attrs = evaluator
            .heap()
            .get_attrs(captured_x)
            .expect("captured payload is an attrset");
        attrs.get(a).expect("lazy binding exists")
    };
    let binding_thunk = evaluator
        .heap()
        .get_thunk(binding)
        .expect("lazy binding is a thunk");
    assert_eq!(binding_thunk.cell().state(), Ok(ThunkState::Suspended));

    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured_x).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    let thunk_value = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("lazy-binding attrset capture thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("static hasAttr subject builds from captured key presence")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "static hasAttr should hash captured key presence without hashing the binding value"
    );
    assert!(
        evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("capture thunk remains heap-owned")
            .env()
            .expect("capture thunk keeps an environment")
            .frames()[0]
            .get(0)
            .expect("captured lazy-binding attrset slot remains readable")
            .raw_eq(captured_x),
        "probing the force-cache subject must not rewrite captured attrset slots"
    );
    let binding_thunk = evaluator
        .heap()
        .get_thunk(binding)
        .expect("lazy binding remains a thunk");
    assert_eq!(
        binding_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "probing the force-cache subject must not force captured lazy bindings"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured lazy-binding attrset value force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let binding_thunk = evaluator
        .heap()
        .get_thunk(binding)
        .expect("lazy binding remains a thunk after hasAttr");
    assert_eq!(
        binding_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "hasAttr should not force captured lazy bindings"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "static hasAttr captured key-presence subjects should populate one demand node"
    );
}

#[test]
fn captured_has_attr_presence_hashes_follow_capture_aliases_without_forcing() {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(0),
        vec![
            pure_node(
                IrKind::HasAttr,
                Span::new(0, 8),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(1),
                    path,
                },
            ),
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(1)),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-hasattr-alias-presence.nix",
        "x ? used",
        cache.clone(),
    );
    let lazy_binding = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("lazy binding allocates");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(used, lazy_binding)], &evaluator.symbols)
        .expect("captured attrset builds");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured attrset allocates");
    let alias_frame = EvalFrame::new(1).expect("alias frame allocates");
    alias_frame.set(0, captured).expect("alias frame slot sets");
    let alias_env = EvalEnv::capture(&[alias_frame]).expect("alias env allocates");
    let alias = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(
            EvalModuleId::ROOT,
            IrId::new(1),
            alias_env,
        ))
        .expect("capture alias thunk allocates");
    let thunk_value = captured_has_attr_thunk(&mut evaluator, &ir, alias);
    let subject = captured_has_attr_subject(&evaluator, &ir, thunk_value)
        .expect("static hasAttr subject builds through a suspended capture alias");

    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "safe capture aliases should resolve to key-presence hashes"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(alias)
            .expect("alias remains heap-owned")
            .cell()
            .state(),
        Ok(ThunkState::Suspended),
        "probing hasAttr presence must not force capture aliases"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(lazy_binding)
            .expect("lazy binding remains heap-owned")
            .cell()
            .state(),
        Ok(ThunkState::Suspended),
        "probing hasAttr presence through an alias must not force bindings"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "subject probing alone should not allocate force-cache demand nodes"
    );
}

#[test]
fn captured_has_attr_presence_hashes_ignore_binding_value_changes() {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(0),
        vec![
            pure_node(
                IrKind::HasAttr,
                Span::new(0, 8),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(1),
                    path,
                },
            ),
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(16, 17), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(20, 21), IrData::Int(0)),
            pure_node(
                IrKind::BinOp,
                Span::new(16, 21),
                IrData::Binary {
                    op: BinOpKind::Div,
                    lhs: IrId::new(3),
                    rhs: IrId::new(4),
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-hasattr-presence-hashes.nix",
        "x ? used",
        cache.clone(),
    );
    let first_binding = first
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("first lazy binding allocates");
    let first_attrs = FlatAttrs::new(vec![AttrEntry::new(used, first_binding)], &first.symbols)
        .expect("first attrset builds");
    let first_capture = first
        .heap
        .alloc_attrs(0, first_attrs)
        .expect("first captured attrset allocates");
    let first_frame = EvalFrame::new(1).expect("first capture frame allocates");
    first_frame
        .set(0, first_capture)
        .expect("first capture frame slot sets");
    let first_env = EvalEnv::capture(&[first_frame]).expect("first capture env allocates");
    let first_thunk = first
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, first_env))
        .expect("first hasAttr thunk allocates");
    let first_hashes = {
        let thunk = first
            .heap()
            .get_thunk(first_thunk)
            .expect("first hasAttr is a node thunk");
        first
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("first hasAttr subject builds")
            .free_var_value_hashes
    };

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-hasattr-presence-hashes.nix",
        "x ? used",
        cache.clone(),
    );
    let second_binding = second
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(5)))
        .expect("second lazy binding allocates");
    let second_attrs = FlatAttrs::new(vec![AttrEntry::new(used, second_binding)], &second.symbols)
        .expect("second attrset builds");
    let second_capture = second
        .heap
        .alloc_attrs(0, second_attrs)
        .expect("second captured attrset allocates");
    let second_frame = EvalFrame::new(1).expect("second capture frame allocates");
    second_frame
        .set(0, second_capture)
        .expect("second capture frame slot sets");
    let second_env = EvalEnv::capture(&[second_frame]).expect("second capture env allocates");
    let second_thunk = second
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, second_env))
        .expect("second hasAttr thunk allocates");
    let second_hashes = {
        let thunk = second
            .heap()
            .get_thunk(second_thunk)
            .expect("second hasAttr is a node thunk");
        second
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("second hasAttr subject builds")
            .free_var_value_hashes
    };

    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-hasattr-presence-hashes.nix",
        "x ? used",
        cache.clone(),
    );
    let third_attrs = FlatAttrs::new(Vec::new(), &third.symbols).expect("third attrset builds");
    let third_capture = third
        .heap
        .alloc_attrs(0, third_attrs)
        .expect("third captured attrset allocates");
    let third_frame = EvalFrame::new(1).expect("third capture frame allocates");
    third_frame
        .set(0, third_capture)
        .expect("third capture frame slot sets");
    let third_env = EvalEnv::capture(&[third_frame]).expect("third capture env allocates");
    let third_thunk = third
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, third_env))
        .expect("third hasAttr thunk allocates");
    let third_hashes = {
        let thunk = third
            .heap()
            .get_thunk(third_thunk)
            .expect("third hasAttr is a node thunk");
        third
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("third hasAttr subject builds")
            .free_var_value_hashes
    };

    assert_eq!(
        first_hashes, second_hashes,
        "present key hashes should ignore the captured binding value"
    );
    assert_ne!(
        first_hashes, third_hashes,
        "missing key hashes must not hit present-key payloads"
    );

    let first_forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), first_thunk)
        .expect("first hasAttr force succeeds");
    assert_eq!(first_forced.as_bool(), Ok(true));

    let hits_before_second = second.stats().force_cache_hits();
    let second_forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("second hasAttr force succeeds");
    assert_eq!(second_forced.as_bool(), Ok(true));
    assert!(
        second.stats().force_cache_hits() > hits_before_second,
        "second present-key force should hit despite the changed lazy binding value"
    );
    let second_binding_thunk = second
        .heap()
        .get_thunk(second_binding)
        .expect("second lazy binding remains heap-owned");
    assert_eq!(
        second_binding_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "cache hit must not force the changed lazy binding"
    );

    let hits_before_third = third.stats().force_cache_hits();
    let third_forced = third
        .force_admitted_value(ir.root, Span::new(0, 0), third_thunk)
        .expect("third hasAttr force succeeds");
    assert_eq!(third_forced.as_bool(), Ok(false));
    assert_eq!(
        third.stats().force_cache_hits(),
        hits_before_third,
        "missing-key force must not reuse the present-key payload"
    );
}

#[test]
fn captured_has_attr_dynamic_paths_do_not_build_presence_subjects() {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(0),
        vec![
            pure_node(
                IrKind::HasAttr,
                Span::new(0, 13),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(1),
                    path,
                },
            ),
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(IrKind::Str, Span::new(5, 11), IrData::Symbol(used)),
            pure_node(IrKind::Int, Span::new(16, 17), IrData::Int(1)),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Dynamic(IrId::new(2))])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-hasattr-dynamic-path.nix",
        "x ? ${used}",
        cache.clone(),
    );
    let lazy_binding = evaluator
        .alloc_apply_thunk(
            IrId::new(3),
            Span::new(16, 17),
            IrId::new(3),
            Span::new(16, 17),
            Value::int(1),
            IrId::new(3),
            Value::int(2),
        )
        .expect("unhashable lazy binding allocates");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(used, lazy_binding)], &evaluator.symbols)
        .expect("captured attrset builds");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured attrset allocates");
    let thunk_value = captured_has_attr_thunk(&mut evaluator, &ir, captured);
    let subject = captured_has_attr_subject(&evaluator, &ir, thunk_value);

    assert!(
        subject.is_none(),
        "dynamic hasAttr paths must not use key-presence-only demand keys"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(lazy_binding)
            .expect("lazy binding remains heap-owned")
            .cell()
            .state(),
        Ok(ThunkState::Suspended),
        "probing a dynamic hasAttr subject must not force captured bindings"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "dynamic hasAttr fallback should skip when the receiver hash is unavailable"
    );
}

#[test]
fn captured_has_attr_unresolved_receivers_do_not_build_presence_subjects() {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(0),
        vec![
            pure_node(
                IrKind::HasAttr,
                Span::new(0, 8),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(1),
                    path,
                },
            ),
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-hasattr-unresolved-receiver.nix",
        "x ? used",
        cache.clone(),
    );
    let captured = evaluator
        .alloc_apply_thunk(
            ir.root,
            Span::new(0, 8),
            ir.root,
            Span::new(0, 8),
            Value::int(1),
            ir.root,
            Value::int(2),
        )
        .expect("unresolved receiver thunk allocates");
    let thunk_value = captured_has_attr_thunk(&mut evaluator, &ir, captured);
    let subject = captured_has_attr_subject(&evaluator, &ir, thunk_value);

    assert!(
        subject.is_none(),
        "unresolved captured receivers must fall back instead of guessing key presence"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(captured)
            .expect("captured receiver remains heap-owned")
            .cell()
            .state(),
        Ok(ThunkState::Suspended),
        "probing hasAttr presence must not force unresolved captured receivers"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "unresolved receivers should not allocate force-cache demand nodes"
    );
}

#[test]
fn captured_has_attr_nested_unresolved_intermediates_do_not_build_presence_subjects() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let b = symbols.intern(b"b").expect("b interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(0),
        vec![
            pure_node(
                IrKind::HasAttr,
                Span::new(0, 10),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(1),
                    path,
                },
            ),
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(IrKind::Int, Span::new(14, 15), IrData::Int(1)),
        ],
        symbols,
        vec![Box::new([
            IrAttrPathSegment::Static(a),
            IrAttrPathSegment::Static(b),
        ])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-hasattr-nested-unresolved-intermediate.nix",
        "x ? a.b",
        cache.clone(),
    );
    let lazy_intermediate = evaluator
        .alloc_apply_thunk(
            IrId::new(2),
            Span::new(14, 15),
            IrId::new(2),
            Span::new(14, 15),
            Value::int(1),
            IrId::new(2),
            Value::int(2),
        )
        .expect("unresolved intermediate thunk allocates");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(a, lazy_intermediate)],
        &evaluator.symbols,
    )
    .expect("captured attrset builds");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured attrset allocates");
    let thunk_value = captured_has_attr_thunk(&mut evaluator, &ir, captured);
    let subject = captured_has_attr_subject(&evaluator, &ir, thunk_value);

    assert!(
        subject.is_none(),
        "nested hasAttr paths must skip presence keys when an intermediate is unresolved"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(lazy_intermediate)
            .expect("lazy intermediate remains heap-owned")
            .cell()
            .state(),
        Ok(ThunkState::Suspended),
        "probing a nested hasAttr subject must not force unresolved intermediates"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "unresolved nested intermediates should not allocate force-cache demand nodes"
    );
}

#[test]
fn captured_closed_literal_lazy_binding_attrsets_build_force_cache_subjects_without_forcing() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(1),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::HasAttr,
                Span::new(0, 5),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                },
            ),
            pure_node(IrKind::Int, Span::new(10, 11), IrData::Int(1)),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(a)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-closed-literal-lazy-binding-attrset-value.nix",
        "x ? a",
        cache.clone(),
    );
    let lazy_binding = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("lazy binding thunk allocates");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, lazy_binding)], &evaluator.symbols)
        .expect("lazy-binding attrset builds");
    let captured_x = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("lazy-binding attrset allocates");
    let binding_thunk = evaluator
        .heap()
        .get_thunk(lazy_binding)
        .expect("lazy binding is a thunk");
    assert_eq!(binding_thunk.cell().state(), Ok(ThunkState::Suspended));

    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured_x).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    let thunk_value = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("lazy-binding attrset capture thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("hasAttr is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_some(),
        "captured closed literal lazy-binding attrsets should hash into demand keys"
    );
    let binding_thunk = evaluator
        .heap()
        .get_thunk(lazy_binding)
        .expect("lazy binding remains a thunk");
    assert_eq!(
        binding_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "probing the force-cache subject must not force closed literal lazy bindings"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured closed literal lazy-binding attrset value force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    let binding_thunk = evaluator
        .heap()
        .get_thunk(lazy_binding)
        .expect("lazy binding remains a thunk after hasAttr");
    assert_eq!(
        binding_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "hasAttr should not force captured closed literal lazy bindings"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "captured closed literal lazy-binding attrsets should create one demand node"
    );
}
