//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn captured_unsupported_heap_values_wait_for_canonical_value_hashes() {
    let source = "let f = x: { a = builtins.length x == 1; }; in f [ (1 / 0) ]";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "unsupported-captures.nix",
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
        let mut captured = None;
        for frame in env.frames().iter() {
            for slot in 0..8 {
                let Ok(value) = frame.get(slot) else {
                    continue;
                };
                if lazy_element_list_capture_state(&evaluator, &ir, value).is_some() {
                    captured = Some(value);
                    break;
                }
            }
        }
        captured.expect("x lazy-element list capture exists")
    };
    let captured_state = lazy_element_list_capture_state(&evaluator, &ir, captured_x)
        .expect("x lazy-element list capture has a state");
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
        "captured lazy-element lists must not be hashed into demand keys"
    );
    assert_eq!(
        lazy_element_list_capture_state(&evaluator, &ir, captured_x),
        Some(captured_state),
        "probing the force-cache subject must not change captured lazy-element lists"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured unsupported heap value force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "captured lazy-element lists need element payloads before observation"
    );
}

#[test]
fn captured_lazy_element_list_values_do_not_build_force_cache_subjects() {
    let ir = manual_ir(
        IrId::new(2),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::List,
                Span::new(5, 7),
                IrData::Children(IrChildSlice::new(0, 0)),
            ),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 7),
                IrData::Binary {
                    op: BinOpKind::Concat,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
            pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(16, 17), IrData::Int(0)),
            pure_node(
                IrKind::BinOp,
                Span::new(12, 17),
                IrData::Binary {
                    op: BinOpKind::Div,
                    lhs: IrId::new(3),
                    rhs: IrId::new(4),
                },
            ),
        ],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-lazy-element-list-value.nix",
        "x ++ []",
        cache.clone(),
    );
    let lazy_element = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(5)))
        .expect("lazy element thunk allocates");
    let captured_x = evaluator
        .heap
        .alloc_list(NixList::new(vec![lazy_element]))
        .expect("lazy-element list allocates");
    assert_eq!(
        lazy_element_list_capture_state(&evaluator, &ir, captured_x),
        Some(LazyElementListCaptureState::DirectList)
    );
    let element_thunk = evaluator
        .heap()
        .get_thunk(lazy_element)
        .expect("lazy element is a thunk");
    assert_eq!(element_thunk.cell().state(), Ok(ThunkState::Suspended));

    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured_x).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    let thunk_value = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("lazy-element list capture thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("concat is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured lazy-element lists must not be hashed into demand keys"
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
            .expect("captured lazy-element list slot remains readable")
            .raw_eq(captured_x),
        "probing the force-cache subject must not rewrite captured list slots"
    );
    assert_eq!(
        lazy_element_list_capture_state(&evaluator, &ir, captured_x),
        Some(LazyElementListCaptureState::DirectList),
        "probing the force-cache subject must not force captured lazy elements"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured lazy-element list value force succeeds");
    let list = evaluator
        .heap()
        .get_list(forced)
        .expect("concat result is heap-owned");
    assert_eq!(list.len(), 1);
    let element = list.get(0).expect("lazy result element exists");
    assert!(element.raw_eq(lazy_element));
    let element_thunk = evaluator
        .heap()
        .get_thunk(element)
        .expect("lazy result element remains a thunk");
    assert_eq!(
        element_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "list concat should not force captured lazy elements"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "captured lazy-element lists need element payloads before observation"
    );
}

#[test]
fn captured_closed_literal_lazy_element_lists_build_force_cache_subjects_without_forcing() {
    let ir = manual_ir(
        IrId::new(2),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::List,
                Span::new(5, 7),
                IrData::Children(IrChildSlice::new(0, 0)),
            ),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 7),
                IrData::Binary {
                    op: BinOpKind::Concat,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
            pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(1)),
        ],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-closed-literal-lazy-element-list-value.nix",
        "x ++ []",
        cache.clone(),
    );
    let lazy_element = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("lazy element thunk allocates");
    let captured_x = evaluator
        .heap
        .alloc_list(NixList::new(vec![lazy_element]))
        .expect("lazy-element list allocates");
    let element_thunk = evaluator
        .heap()
        .get_thunk(lazy_element)
        .expect("lazy element is a thunk");
    assert_eq!(element_thunk.cell().state(), Ok(ThunkState::Suspended));

    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured_x).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    let thunk_value = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("lazy-element list capture thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("concat is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_some(),
        "captured closed literal lazy-element lists should hash into demand keys"
    );
    let element_thunk = evaluator
        .heap()
        .get_thunk(lazy_element)
        .expect("lazy element remains a thunk");
    assert_eq!(
        element_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "probing the force-cache subject must not force closed literal lazy elements"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured closed literal lazy-element list value force succeeds");
    let list = evaluator
        .heap()
        .get_list(forced)
        .expect("concat result is heap-owned");
    let element = list.get(0).expect("lazy result element exists");
    assert!(element.raw_eq(lazy_element));
    let element_thunk = evaluator
        .heap()
        .get_thunk(element)
        .expect("lazy result element remains a thunk");
    assert_eq!(
        element_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "list concat should not force captured closed literal lazy elements"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "captured closed literal lazy-element lists should create one demand node"
    );
}
#[test]
fn captured_root_position_bearing_attrset_values_use_free_variable_hashes() {
    let source = "let x = { a = 1; }; in builtins.seq x { a = x.a == 1; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-position-attrset-value.nix",
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
            captured_fulfilled_slot_with_cached_tag(&evaluator, thunk_value, 0, 0, ValueTag::Attrs)
                .expect("x is a fulfilled attrset capture in the first let slot");
        let attrs = evaluator
            .heap()
            .get_attrs(cached_x)
            .expect("x cached payload is an attrset");
        assert!(
            attrset_has_binding_position(attrs),
            "fixture must carry attr binding positions"
        );
        assert!(
            attrs.iter_by_symbol().all(|entry| entry
                .position
                .map(|position| position.module == EvalModuleId::ROOT.as_u32())
                .unwrap_or(true)),
            "fixture positions must belong to the root module"
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a is a node thunk");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("captured root positioned attrset subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "captured root positioned attrsets should hash into demand keys"
        );
        assert!(
            captured_fulfilled_slot_with_cached_tag(&evaluator, thunk_value, 0, 0, ValueTag::Attrs)
                .map(|(captured, cached)| captured.raw_eq(captured_x) && cached.raw_eq(cached_x))
                .unwrap_or(false),
            "probing the force-cache subject must not rewrite captured attrset thunks or payloads"
        );

        let hits_before = evaluator.stats().cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured position-bearing attrset value force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(
            evaluator.stats().cache_hits() > hits_before,
            expected_hit,
            "second run should hit through the captured root positioned attrset hash"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").len() >= 2,
        "captured root positioned attrset and dependent result should populate force-cache payloads"
    );
}

#[test]
fn captured_imported_position_bearing_attrset_values_use_source_salted_free_variable_hashes() {
    let root = fs::canonicalize(unique_temp_dir(
        "force-cache-captured-imported-positioned-attrs",
    ))
    .expect("source root canonicalizes");
    fs::write(root.join("dep-a.nix"), b"{ b = 1; }").expect("first import source writes");
    fs::write(root.join("dep-b.nix"), b"{ b = 1; }").expect("second import source writes");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut dep_a_hash = None;

    for (dep_file, expected_hit) in [
        ("dep-a.nix", false),
        ("dep-b.nix", false),
        ("dep-a.nix", true),
    ] {
        let source = format!("let x = import ./{dep_file}; in builtins.seq x {{ a = x.b == 1; }}");
        let ir = lower(&source);
        let a = symbol_for(&ir, b"a");
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(&root))
            .expect("path base configures");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source.as_str(),
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
        let (_, cached_x) =
            captured_fulfilled_slot_with_cached_tag(&evaluator, thunk_value, 0, 0, ValueTag::Attrs)
                .expect("x is a fulfilled imported attrset capture in the first let slot");
        let b = evaluator.symbols.intern(b"b").expect("b interns");
        let attrs = evaluator
            .heap()
            .get_attrs(cached_x)
            .expect("x cached payload is an attrset");
        let position = attrs
            .get_entry(b)
            .expect("b entry exists")
            .position
            .expect("imported binding has a source position");
        assert_ne!(
            position.module,
            EvalModuleId::ROOT.as_u32(),
            "fixture must carry a non-root binding position"
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a is a node thunk");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("captured imported positioned attrset subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "captured imported positioned attrsets should hash into demand keys"
        );
        let capture_hash = subject.free_var_value_hashes[0];
        match (dep_file, dep_a_hash) {
            ("dep-a.nix", None) => dep_a_hash = Some(capture_hash),
            ("dep-a.nix", Some(hash)) => assert_eq!(
                capture_hash, hash,
                "matching imported source should reuse the same captured value hash"
            ),
            ("dep-b.nix", Some(hash)) => assert_ne!(
                capture_hash, hash,
                "different imported source identities must change the captured value hash"
            ),
            ("dep-b.nix", None) => panic!("dep-a source hash should be recorded first"),
            _ => unreachable!("test fixture only uses dep-a.nix and dep-b.nix"),
        }

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured imported positioned attrset value force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "second run should hit through the source-salted imported positioned attrset hash"
        );
    }
    assert!(
        cache
            .lock()
            .expect("cache lock is valid")
            .cache()
            .expect("cache is enabled")
            .len()
            > 0,
        "captured imported positioned attrsets should populate source-salted force-cache payloads"
    );

    fs::remove_dir_all(root).expect("source temp tree removed");
}

#[test]
fn captured_root_positioned_attrsets_in_imported_bodies_use_source_salted_free_variable_hashes() {
    let root = fs::canonicalize(unique_temp_dir(
        "force-cache-imported-body-captured-root-positioned-attrs",
    ))
    .expect("source root canonicalizes");
    fs::write(root.join("dep.nix"), b"x: { a = x.b == 1; }").expect("import source writes");
    let source = "(import ./dep.nix) { b = 1; }";
    let ir = lower(source);
    let mut root_a_hash = None;
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for (source_name, expected_hit) in [
        ("root-a.nix", false),
        ("root-b.nix", false),
        ("root-a.nix", true),
    ] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(&root))
            .expect("path base configures");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            source_name,
            source,
            cache.clone(),
        );
        let root_value = evaluator.eval_root().expect("attrset evaluates");
        let a = evaluator.symbols.intern(b"a").expect("a interns");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root_value)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a is a node thunk");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("captured root positioned attrset subject builds in imported body")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "root-positioned captures in imported bodies should hash with source identity"
        );
        let capture_hash = subject.free_var_value_hashes[0];
        match (source_name, root_a_hash) {
            ("root-a.nix", None) => root_a_hash = Some(capture_hash),
            ("root-a.nix", Some(hash)) => assert_eq!(
                capture_hash, hash,
                "matching caller root source should reuse the same captured value hash"
            ),
            ("root-b.nix", Some(hash)) => assert_ne!(
                capture_hash, hash,
                "different caller root source identities must change the captured value hash"
            ),
            ("root-b.nix", None) => panic!("root-a source hash should be recorded first"),
            _ => unreachable!("test fixture only uses root-a.nix and root-b.nix"),
        }

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured root positioned attrset in imported body force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "source-salted positioned captures should hit only for the matching root source"
        );
    }

    fs::remove_dir_all(root).expect("source temp tree removed");
}

#[test]
fn captured_root_positioned_attrsets_in_imported_unsafe_get_attr_pos_bodies_stay_uncached() {
    let root = fs::canonicalize(unique_temp_dir(
        "force-cache-imported-unsafe-get-attr-pos-captured-root-positioned-attrs",
    ))
    .expect("source root canonicalizes");
    fs::write(
        root.join("dep.nix"),
        b"x: { a = (builtins.unsafeGetAttrPos \"b\" x).file; }",
    )
    .expect("import source writes");
    let source = "(import ./dep.nix) { b = 1; }";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for source_name in ["root-a.nix", "root-b.nix", "root-a.nix"] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(&root))
            .expect("path base configures");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            source_name,
            source,
            cache.clone(),
        );
        let root_value = evaluator.eval_root().expect("attrset evaluates");
        let a = evaluator.symbols.intern(b"a").expect("a interns");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root_value)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
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
            "unsafeGetAttrPos bodies are not in the force-cache whitelist"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured root positioned attrset in unsafeGetAttrPos body force succeeds");
        let file_string = evaluator
            .heap()
            .get_string(forced)
            .expect("unsafeGetAttrPos file is a string");
        assert_eq!(
            file_string.bytes(),
            source_name.as_bytes(),
            "uncached unsafeGetAttrPos body must read the current caller-root binding position"
        );
    }

    fs::remove_dir_all(root).expect("source temp tree removed");
}

#[test]
fn captured_source_order_attrset_values_build_force_cache_subjects() {
    let mut symbols = SymbolTable::new();
    let c = symbols.intern(b"c").expect("c interns");
    let b = symbols.intern(b"b").expect("b interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(3),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::Select,
                Span::new(0, 3),
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                    default: None,
                },
            ),
            pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 7),
                IrData::Binary {
                    op: BinOpKind::Eq,
                    lhs: IrId::new(1),
                    rhs: IrId::new(2),
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(b)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-source-order-attrset-value.nix",
        "x.b == 1",
        cache.clone(),
    );
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(c, Value::int(2)),
            AttrEntry::new(b, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("source-order attrset builds");
    assert_ne!(
        attrs.source_order(),
        attrs.iteration_order(),
        "fixture must carry source-order-observable attrset metadata"
    );
    assert!(
        !attrset_has_binding_position(&attrs),
        "fixture must use generated attrset entries without source positions"
    );
    let captured_x = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("source-order attrset allocates");
    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured_x).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    let thunk_value = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("source-order attrset capture thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_some(),
        "captured source-order-observable attrsets should hash into demand keys"
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
            .expect("captured source-order attrset slot remains readable")
            .raw_eq(captured_x),
        "probing the force-cache subject must not rewrite captured attrset slots"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured source-order attrset value force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "captured source-order attrsets should create one demand node"
    );
}

