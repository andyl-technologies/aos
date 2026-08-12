//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn search_path_forced_inline_thunks_rehydrate_after_impure_input_edges() {
    let root = unique_temp_dir("force-cache-search-path");
    let target = root.join("target");
    fs::create_dir_all(&target).expect("target dir exists");
    let target = fs::canonicalize(&target).expect("target canonicalizes");
    let source = "{ a = <pkg> == <pkg>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&target))
        .expect("search-path entry is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "expr.nix",
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
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&target),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("findFile candidate trace builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            &path_bytes(&target),
            ImpureInputMode::FindFileCandidate,
            true,
        )
        .expect("cached findFile candidate trace builds"),
    ];

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(evaluator.impure_input_trace(), expected_trace.as_slice());
    {
        let runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert!(
            cache.len() >= 2,
            "search-path literal equality should allocate an expression node and candidate leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            1,
            "the expression node must own the observed search-path candidate leaf"
        );
    }

    let mut second_options = TreeWalkOptions::new();
    second_options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&target))
        .expect("matching search-path entry is valid");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "expr.nix",
        source,
        cache,
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "search-path literal equality should rehydrate after candidate revalidation"
    );
    assert_eq!(second.stats().force_cache_hits(), 1);
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn pipe_forced_inline_thunks_wait_for_application_cache_keys() {
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let frames = vec![FrameInfo {
        slot_count: 1,
        captures: Vec::new().into_boxed_slice(),
        rec: false,
        has_with: false,
    }];
    let ir = manual_ir_with_symbols_and_frames(
        IrId::new(5),
        vec![
            pure_node(
                IrKind::Formal,
                Span::new(0, 1),
                IrData::Formal {
                    name: x,
                    default: None,
                },
            ),
            pure_node(IrKind::Int, Span::new(3, 4), IrData::Int(3)),
            pure_node(
                IrKind::Lambda,
                Span::new(0, 4),
                IrData::Lambda {
                    pattern: IrId::new(0),
                    body: IrId::new(1),
                    frame: Some(FrameId::new(0)),
                },
            ),
            pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 9),
                IrData::Binary {
                    op: BinOpKind::PipeRight,
                    lhs: IrId::new(3),
                    rhs: IrId::new(2),
                },
            ),
            pure_node(
                IrKind::ThunkAlloc,
                Span::new(0, 9),
                IrData::Node(IrId::new(4)),
            ),
        ],
        symbols,
        frames,
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        "{ a = 1 |> f; }",
        cache.clone(),
    );
    let forced = evaluator
        .eval_root()
        .expect("thunked pipe root evaluates to weak head normal form");

    assert_eq!(forced.as_int(), Ok(3));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "pipe operators evaluate as application and need application cache keys"
    );
}

#[test]
fn context_free_string_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = "cached " + "string"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "string-result.nix",
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
            .expect("string thunk force succeeds");
        let string = evaluator
            .heap()
            .get_string(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(string.bytes(), b"cached string");
        assert!(!string.has_context());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching context-free string results should share one demand node"
    );
}

#[test]
fn context_string_result_thunks_hit_after_heap_rehydration() {
    let root = unique_temp_dir("force-cache-context-string-result");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = r#"{ a = "${./target}"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(&root))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "context-string-result.nix",
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
            .expect("context string thunk force succeeds");
        let string = evaluator
            .heap()
            .get_string(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert!(string.has_context());
        assert_eq!(string.context().len(), 1);
        let element = &string.context().elements()[0];
        assert_eq!(element.kind(), ContextKind::OpaquePath);
        assert_eq!(element.path(), string.bytes());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching context-bearing string results should share one demand node"
    );
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn path_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = /tmp + "/cached-path"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "path-result.nix",
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
            .expect("path thunk force succeeds");
        let path = evaluator
            .heap()
            .get_path(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(path.bytes(), b"/tmp/cached-path");
        assert!(!path.has_context());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching path results should share one demand node"
    );
}

#[test]
fn empty_list_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = [ ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-list-result.nix",
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
            .expect("empty list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert!(list.is_empty());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching empty list results should share one demand node"
    );
}

#[test]
fn strict_list_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = [ 1 true null ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "strict-list-result.nix",
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
            .expect("strict list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(list.len(), 3);
        assert_eq!(list.get(0).expect("first element exists").as_int(), Ok(1));
        assert_eq!(
            list.get(1).expect("second element exists").as_bool(),
            Ok(true)
        );
        assert_eq!(list.get(2).expect("third element exists").as_null(), Ok(()));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching strict list results should share one demand node"
    );
}

#[test]
fn strict_list_result_thunks_with_heap_elements_hit_after_heap_rehydration() {
    let source = r#"{ a = [ "x" "y" ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "strict-list-heap-result.nix",
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
            .expect("strict heap-backed list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(list.len(), 2);
        let string = evaluator
            .heap()
            .get_string(list.get(0).expect("first element exists"))
            .expect("first element is a string");
        assert_eq!(string.bytes(), b"x");
        let second = evaluator
            .heap()
            .get_string(list.get(1).expect("second element exists"))
            .expect("second element is a string");
        assert_eq!(second.bytes(), b"y");
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching strict heap-backed list results should share one demand node"
    );
}

#[test]
fn non_empty_list_literals_with_non_replayable_lazy_elements_allocate_node_without_payload_hits() {
    let source = r#"{ a = [ (1 / 0) ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for _ in 0..2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "lazy-list-result.nix",
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
            .expect("lazy list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("list is heap-owned");

        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0).expect("element exists").tag(), ValueTag::Thunk);
        assert_eq!(evaluator.stats().cache_hits(), 0);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert_eq!(
        cache.len(),
        1,
        "non-replayable lazy list literals still allocate the force demand node"
    );
    assert_eq!(
        cache.inline_payload_record_count(),
        0,
        "list literals with non-replayable lazy elements must not store reusable inline payloads"
    );
}

#[test]
fn empty_attrset_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = { }; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-attrs-result.nix",
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
            .expect("empty attrset thunk force succeeds");
        let attrs = evaluator
            .heap()
            .get_attrs(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert!(attrs.is_empty());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching empty attrset results should share one demand node"
    );
}

#[test]
fn strict_attrset_payloads_rehydrate_after_heap_lookup() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"force-strict-attrs-result",
        )),
        IrId::new(14),
    );
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let b = first.symbols.intern(b"b").expect("b interns");
    let c = first.symbols.intern(b"c").expect("c interns");
    let string = first
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("string allocates");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(b, Value::int(1)), AttrEntry::new(c, string)],
        &first.symbols,
    )
    .expect("attrs build");
    let value = first.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    first.observe_forced_inline_expression_result(
        Some(subject.clone()),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );
    drop(first);

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject))
        .expect("strict attrset payload hits");
    let b = second.symbols.intern(b"b").expect("b interns");
    let c = second.symbols.intern(b"c").expect("c interns");
    let attrs = second
        .heap()
        .get_attrs(hit)
        .expect("strict attrset rehydrates into this evaluator heap");
    assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(1));
    let string = second
        .heap()
        .get_string(attrs.get(c).expect("c exists"))
        .expect("c is a string");
    assert_eq!(string.bytes(), b"x");
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
}

#[test]
fn strict_attrset_payloads_preserve_position_bearing_attrsets_in_memory() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"force-position-attrs-result",
        )),
        IrId::new(15),
    );
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: Some(EvalModuleId::ROOT),
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let expected_position = AttrPosition::new(0, Span::new(0, 1));
    let attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            a,
            Value::int(1),
            expected_position,
        )],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");

    evaluator.observe_forced_inline_expression_result(
        Some(subject.clone()),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );

    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert_eq!(
            runtime.cache().expect("cache is enabled").len(),
            1,
            "position-bearing attrsets should populate the in-memory payload cache"
        );
    }

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject))
        .expect("position-bearing attrset payload hits");
    let a = second.symbols.intern(b"a").expect("a interns");
    let attrs = second
        .heap()
        .get_attrs(hit)
        .expect("position-bearing attrset rehydrates into this evaluator heap");
    assert_eq!(attrs.get(a).expect("a exists").as_int(), Ok(1));
    assert!(
        attrset_has_binding_position(attrs),
        "position-bearing attrset payload hits must retain binding positions"
    );
    assert_eq!(
        attrs.get_entry(a).expect("a entry exists").position,
        Some(expected_position),
        "position-bearing attrset payload hits must retain exact binding provenance"
    );
}

#[test]
fn source_backed_position_bearing_attrset_literals_hit_force_cache_payloads() {
    let source = r#"{ a = { b = 1; }; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "position-bearing-attrs-result.nix",
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
            assert_eq!(node.kind, IrKind::AttrSet);
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("position-bearing attrset subject builds")
        };
        assert!(subject.lookup_identity.is_some());
        assert!(subject.pure_observation_identity.is_some());
        assert!(subject.free_var_value_hashes.is_empty());
        assert_eq!(
            subject.memoization_admission,
            ForceCacheMemoizationAdmission::SelectedSubstrate,
            "position-bearing attrsets should pre-admit once payloads carry positions"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("position-bearing attrset thunk force succeeds");
        let attrs = evaluator
            .heap()
            .get_attrs(forced)
            .expect("forced value is an attrset");

        assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(1));
        assert!(
            attrset_has_binding_position(attrs),
            "source-backed literal bindings must carry positions"
        );
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert!(
            evaluator.stats().force_cache_memoization_admits() > 0,
            "position-bearing attrset force must reach an admitted cache probe"
        );
        assert_eq!(evaluator.stats().force_cache_probes(), 1);
        if expected_hit {
            assert_eq!(evaluator.stats().force_cache_hits(), 1);
            assert_eq!(evaluator.stats().force_cache_misses(), 0);
        } else {
            assert_eq!(evaluator.stats().force_cache_hits(), 0);
            assert_eq!(evaluator.stats().force_cache_misses(), 1);
        }
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "source-backed position-bearing attrset literals should use one in-memory payload"
    );
}
