//! Split-out tests (part_3). See parent module.

use super::*;

#[test]
fn unsafe_get_attr_pos_observes_position_bearing_attrsets_from_force_cache_payloads() {
    let source = r#"{ a = { b = 1; }; }"#;
    let source_name = "position-bearing-attrs-position.nix";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let (expected_line, expected_column) = source_line_column(source, "b = 1");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            source_name,
            source,
            cache.clone(),
        );
        let file = evaluator.symbols.intern(b"file").expect("file interns");
        let line = evaluator.symbols.intern(b"line").expect("line interns");
        let column = evaluator.symbols.intern(b"column").expect("column interns");
        let root = evaluator.eval_root().expect("attrset evaluates");
        let a_thunk = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(a_thunk)
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

        let forced_a = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), a_thunk)
            .expect("position-bearing attrset thunk force succeeds");
        let attrs = evaluator
            .heap()
            .get_attrs(forced_a)
            .expect("forced value is an attrset");
        assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(1));
        assert!(
            attrset_has_binding_position(attrs),
            "source-backed literal bindings must carry positions"
        );
        assert_eq!(evaluator.stats().force_cache_probes(), 1);
        if expected_hit {
            assert_eq!(evaluator.stats().force_cache_hits(), 1);
            assert_eq!(evaluator.stats().force_cache_misses(), 0);
        } else {
            assert_eq!(evaluator.stats().force_cache_hits(), 0);
            assert_eq!(evaluator.stats().force_cache_misses(), 1);
        }
        assert!(
            evaluator.stats().force_cache_memoization_admits() > 0,
            "position-bearing attrset force must reach an admitted cache probe"
        );

        let position = evaluator
            .eval_unsafe_get_attr_pos_attrs_value(
                ir.root,
                Span::new(0, 0),
                b,
                ir.root,
                Span::new(0, source.len() as u32),
                forced_a,
            )
            .expect("unsafeGetAttrPos succeeds");
        let position_attrs = evaluator
            .heap()
            .get_attrs(position)
            .expect("unsafeGetAttrPos returns an attrset");
        let file_value = position_attrs.get(file).expect("file exists");
        let file_string = evaluator
            .heap()
            .get_string(file_value)
            .expect("file is a string");
        assert_eq!(file_string.bytes(), source_name.as_bytes());
        assert_eq!(
            position_attrs.get(line).expect("line exists").as_int(),
            Ok(expected_line as i64)
        );
        assert_eq!(
            position_attrs.get(column).expect("column exists").as_int(),
            Ok(expected_column as i64)
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "observably positioned attrsets should populate in-memory force-cache payloads"
    );
}

#[test]
fn source_ordered_attrset_payloads_rehydrate_after_heap_lookup() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"force-source-order-attrs-result",
        )),
        IrId::new(16),
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
    let mut evaluator =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let c = evaluator.symbols.intern(b"c").expect("c interns");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(c, Value::int(2)),
            AttrEntry::new(b, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    assert_ne!(attrs.source_order(), attrs.iteration_order());
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
    drop(evaluator);

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject))
        .expect("source-order attrset payload hits");
    assert_source_order_attrset_ints(&second, hit, &[(b"c", 2), (b"b", 1)]);
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
}

#[test]
fn non_empty_attrset_literals_with_non_replayable_lazy_bindings_allocate_node_without_payload_hits()
{
    let source = r#"{ a = { b = (1 / 0); }; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for _ in 0..2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "lazy-attrs-result.nix",
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
            .expect("lazy attrset thunk force succeeds");
        let attrs = evaluator
            .heap()
            .get_attrs(forced)
            .expect("attrset is heap-owned");

        assert_eq!(attrs.get(b).expect("b exists").tag(), ValueTag::Thunk);
        assert_eq!(evaluator.stats().cache_hits(), 0);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert_eq!(
        cache.len(),
        1,
        "non-replayable lazy attrset literals still allocate the force demand node"
    );
    assert_eq!(
        cache.inline_payload_record_count(),
        0,
        "attrset literals with non-replayable lazy bindings must not store reusable inline payloads"
    );
}
