//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn captured_replayable_lists_miss_when_hashes_differ() {
    let source = r#"
let f = x: { a = builtins.elemAt x 0 == 1; };
in [ (f [ 1 ]).a (f [ 2 ]).a ]
"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "list-captures.nix",
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
        .expect("first captured list attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured list attr force succeeds");

    assert_eq!(second.as_bool(), Ok(false));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different captured list values must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").len() >= 2,
        "different captured lists should create distinct demand nodes"
    );
}

#[test]
fn captured_empty_attrsets_use_free_variable_hashes() {
    let source = "let f = x: { a = x == x; }; in { a = (f {}).a; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-attrs-captures.nix",
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
            .expect("captured empty attrset force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        !runtime.cache().expect("cache is enabled").is_empty(),
        "captured empty attrsets should create a demand node"
    );
}

#[test]
fn materialized_replayable_attrset_capture_hashes_key_runtime_payloads() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"force-captured-attrs-result",
        )),
        IrId::new(17),
    );
    let subject_for = |hash| ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: vec![hash],
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let a = first.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(1))], &first.symbols)
        .expect("attrs build");
    let attrs = first.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    let first_hash = first
        .force_cache_free_var_value_hash(attrs)
        .expect("replayable attrset hashes");
    first.observe_forced_inline_expression_result(
        Some(subject_for(first_hash)),
        Value::bool(true),
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );
    drop(first);

    let mut second =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let a = second.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(1))], &second.symbols)
        .expect("attrs build");
    let attrs = second.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    let same_hash = second
        .force_cache_free_var_value_hash(attrs)
        .expect("matching replayable attrset hashes");
    assert_eq!(same_hash, first_hash);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject_for(same_hash)))
        .expect("matching captured attrset hash hits");
    assert_eq!(hit.as_bool(), Ok(true));
    assert_eq!(second.stats().cache_hits(), 1);
    drop(second);

    let mut changed = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let a = changed.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(2))], &changed.symbols)
        .expect("attrs build");
    let attrs = changed.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    let changed_hash = changed
        .force_cache_free_var_value_hash(attrs)
        .expect("changed replayable attrset hashes");
    assert_ne!(changed_hash, first_hash);
    assert!(
        changed
            .lookup_forced_inline_expression_result(Some(subject_for(changed_hash)))
            .is_none(),
        "different captured attrset hashes must miss"
    );
}

#[test]
fn materialized_empty_attrsets_are_free_variable_hashable() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let attrs = evaluator
        .heap
        .alloc_attrs(0, FlatAttrs::empty())
        .expect("empty attrset allocates");

    assert!(evaluator.force_cache_free_var_value_hash(attrs).is_some());
}

#[test]
fn materialized_non_empty_attrsets_are_free_variable_hashable() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(1))], &evaluator.symbols)
        .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrset allocates");

    assert!(evaluator.force_cache_free_var_value_hash(attrs).is_some());
}

#[test]
fn materialized_root_position_bearing_attrsets_are_free_variable_hashable() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            a,
            Value::int(1),
            AttrPosition::new(EvalModuleId::ROOT.as_u32(), Span::new(0, 1)),
        )],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrset allocates");

    assert!(evaluator.force_cache_free_var_value_hash(attrs).is_some());
}

#[test]
fn materialized_imported_position_bearing_attrsets_are_free_variable_hashable() {
    let root = fs::canonicalize(unique_temp_dir(
        "force-cache-materialized-imported-positioned-attrs",
    ))
    .expect("source root canonicalizes");
    fs::write(root.join("dep.nix"), b"{ b = 1; }").expect("import source writes");
    let source = "import ./dep.nix";
    let ir = lower(source);
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let mut evaluator = TreeWalk::with_options_and_source(&ir, options, "default.nix", source);
    let attrs_value = evaluator.eval_root().expect("imported attrset evaluates");
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let attrs = evaluator
        .heap()
        .get_attrs(attrs_value)
        .expect("imported value is an attrset");
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

    assert!(
        evaluator
            .force_cache_free_var_value_hash(attrs_value)
            .is_some()
    );

    fs::remove_dir_all(root).expect("source temp tree removed");
}

#[test]
fn materialized_unknown_module_position_bearing_attrsets_are_not_free_variable_hashable_yet() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            a,
            Value::int(1),
            AttrPosition::new(EvalModuleId::ROOT.as_u32() + 1, Span::new(0, 1)),
        )],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrset allocates");

    assert_eq!(evaluator.force_cache_free_var_value_hash(attrs), None);
}

#[test]
fn materialized_source_order_attrsets_are_free_variable_hashable_and_order_sensitive() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let c = evaluator.symbols.intern(b"c").expect("c interns");
    let source_ordered = FlatAttrs::new(
        vec![
            AttrEntry::new(c, Value::int(2)),
            AttrEntry::new(b, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    assert_ne!(
        source_ordered.source_order(),
        source_ordered.iteration_order()
    );
    let source_ordered = evaluator
        .heap
        .alloc_attrs(0, source_ordered)
        .expect("attrset allocates");
    let first_hash = evaluator
        .force_cache_free_var_value_hash(source_ordered)
        .expect("source-order attrset hashes");

    let same = FlatAttrs::new(
        vec![
            AttrEntry::new(c, Value::int(2)),
            AttrEntry::new(b, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("matching attrs build");
    assert_ne!(same.source_order(), same.iteration_order());
    let same = evaluator
        .heap
        .alloc_attrs(0, same)
        .expect("matching attrset allocates");
    assert_eq!(
        evaluator
            .force_cache_free_var_value_hash(same)
            .expect("matching source-order attrset hashes"),
        first_hash
    );

    let lexicographic = FlatAttrs::new(
        vec![
            AttrEntry::new(b, Value::int(1)),
            AttrEntry::new(c, Value::int(2)),
        ],
        &evaluator.symbols,
    )
    .expect("lexicographic attrs build");
    assert_eq!(
        lexicographic.source_order(),
        lexicographic.iteration_order()
    );
    let lexicographic = evaluator
        .heap
        .alloc_attrs(0, lexicographic)
        .expect("lexicographic attrset allocates");
    assert_ne!(
        evaluator
            .force_cache_free_var_value_hash(lexicographic)
            .expect("lexicographic attrset hashes"),
        first_hash,
        "source-order metadata must participate in the capture hash"
    );
}

#[test]
fn materialized_non_empty_lists_are_free_variable_hashable() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("list allocates");

    assert!(evaluator.force_cache_free_var_value_hash(list).is_some());
}

#[test]
fn suspended_computed_thunk_cells_are_not_free_variable_hashable() {
    let ir = lower("{ a = 1 + 2; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

    assert_eq!(evaluator.force_cache_free_var_value_hash(thunk_value), None);
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is still a thunk");
    assert_eq!(
        thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "hashing a captured suspended thunk cell must not force it"
    );
}

#[test]
fn suspended_recursive_alias_thunk_cells_are_not_free_variable_hashable() {
    for source in ["rec { a = a; }", "rec { a = b; b = a; }"] {
        let ir = lower(source);
        let a = symbol_for(&ir, b"a");
        let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

        assert_eq!(
            evaluator.force_cache_free_var_value_hash(thunk_value),
            None,
            "recursive alias thunk cells must not recurse while building free-variable hashes"
        );
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is still a thunk");
        assert_eq!(
            thunk.cell().state(),
            Ok(ThunkState::Suspended),
            "hashing a recursive alias thunk cell must not force it"
        );
    }
}

#[test]
fn suspended_closed_literal_thunk_cells_are_free_variable_hashable_without_forcing() {
    let ir = lower("{ a = [ 1 true null ]; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

    assert!(
        evaluator
            .force_cache_free_var_value_hash(thunk_value)
            .is_some()
    );
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is still a thunk");
    assert_eq!(
        thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "hashing a suspended closed literal thunk cell must not force it"
    );
}

#[test]
fn fulfilled_thunk_cells_use_cached_free_variable_hashes() {
    let ir = lower("{ a = 1 + 2; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
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
    assert_eq!(forced.as_int(), Ok(3));

    assert_eq!(
        evaluator.force_cache_free_var_value_hash(thunk_value),
        evaluator.force_cache_free_var_value_hash(forced)
    );
}

#[test]
fn fulfilled_replayable_attrset_thunk_cells_use_cached_free_variable_hashes() {
    let ir = lower(r#"{ a = builtins.fromJSON ''{"a":1,"b":[true,null]}''; }"#);
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
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
    assert_eq!(forced.tag(), ValueTag::Attrs);

    assert_eq!(
        evaluator
            .force_cache_free_var_value_hash(thunk_value)
            .expect("fulfilled attrset thunk cell hashes"),
        evaluator
            .force_cache_free_var_value_hash(forced)
            .expect("forced replayable attrset hashes")
    );
}

#[test]
fn materialized_context_bearing_string_captures_use_canonical_free_variable_hashes() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let source =
        ContextElement::opaque_path(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec())
            .expect("opaque context builds");
    let output = ContextElement::single_output(
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg.drv".to_vec(),
        b"out".to_vec(),
    )
    .expect("output context builds");
    let first_context = StringContext::new(vec![output.clone(), source.clone(), output.clone()]);
    let same_context = StringContext::new(vec![source, output]);
    let different_context =
        opaque_capture_context(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-other");
    let first = evaluator
        .heap
        .alloc_string(NixString::new(b"s".to_vec(), first_context))
        .expect("first context string allocates");
    let same = evaluator
        .heap
        .alloc_string(NixString::new(b"s".to_vec(), same_context))
        .expect("same context string allocates");
    let different = evaluator
        .heap
        .alloc_string(NixString::new(b"s".to_vec(), different_context))
        .expect("different context string allocates");
    let context_free = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"s".to_vec()))
        .expect("context-free string allocates");
    let hash = evaluator
        .force_cache_free_var_value_hash(first)
        .expect("context-bearing string hashes");

    assert_eq!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(same)
            .expect("same context-bearing string hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(different)
            .expect("different context-bearing string hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(context_free)
            .expect("context-free string hashes")
    );
}

#[test]
fn materialized_context_bearing_path_captures_use_canonical_free_variable_hashes() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let context = opaque_capture_context(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source");
    let different_context =
        opaque_capture_context(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-other");
    let first = evaluator
        .heap
        .alloc_path(NixString::new(b"/tmp/seed".to_vec(), context.clone()))
        .expect("first context path allocates");
    let same = evaluator
        .heap
        .alloc_path(NixString::new(b"/tmp/seed".to_vec(), context.clone()))
        .expect("same context path allocates");
    let different = evaluator
        .heap
        .alloc_path(NixString::new(b"/tmp/seed".to_vec(), different_context))
        .expect("different context path allocates");
    let context_free = evaluator
        .heap
        .alloc_path(NixString::from_bytes(b"/tmp/seed".to_vec()))
        .expect("context-free path allocates");
    let context_string = evaluator
        .heap
        .alloc_string(NixString::new(b"/tmp/seed".to_vec(), context))
        .expect("context string allocates");
    let hash = evaluator
        .force_cache_free_var_value_hash(first)
        .expect("context-bearing path hashes");

    assert_eq!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(same)
            .expect("same context-bearing path hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(different)
            .expect("different context-bearing path hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(context_free)
            .expect("context-free path hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(context_string)
            .expect("context-bearing string hashes")
    );
}

#[test]
fn materialized_capture_hashes_are_cached_on_heap_records() {
    let ir = lower("[ 1 true null ]");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let string = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"seed".to_vec()))
        .expect("string allocates");
    let same_string = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"seed".to_vec()))
        .expect("same string allocates");
    let path = evaluator
        .heap
        .alloc_path(NixString::from_bytes(b"/tmp/seed".to_vec()))
        .expect("path allocates");
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![string, Value::int(7)]))
        .expect("list allocates");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(a, Value::int(1)),
            AttrEntry::new(b, Value::bool(true)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let positioned_attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            a,
            Value::int(1),
            AttrPosition::new(EvalModuleId::ROOT.as_u32(), Span::new(0, 1)),
        )],
        &evaluator.symbols,
    )
    .expect("positioned attrs build");
    let positioned_attrs = evaluator
        .heap
        .alloc_attrs(0, positioned_attrs)
        .expect("positioned attrs allocate");
    let closed_literal_thunk = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(ir.root))
        .expect("closed literal thunk allocates");
    let lazy_list = evaluator
        .heap
        .alloc_list(NixList::new(vec![closed_literal_thunk]))
        .expect("lazy list allocates");

    assert!(string.raw_eq(same_string));
    assert_eq!(
        evaluator
            .heap()
            .cached_captured_value_hash(string)
            .expect("string record exists"),
        None
    );
    let string_hash = evaluator
        .force_cache_free_var_value_hash(string)
        .expect("string hashes");

    assert_eq!(
        evaluator
            .heap()
            .cached_captured_value_hash(same_string)
            .expect("same string record exists"),
        Some(string_hash)
    );
    assert_eq!(
        evaluator
            .force_cache_free_var_value_hash(same_string)
            .expect("same string reuses cached hash"),
        string_hash
    );

    let path_hash = evaluator
        .force_cache_free_var_value_hash(path)
        .expect("path hashes");
    assert_eq!(
        evaluator
            .heap()
            .cached_captured_value_hash(path)
            .expect("path record exists"),
        Some(path_hash)
    );

    let list_hash = evaluator
        .force_cache_free_var_value_hash(list)
        .expect("list hashes");
    assert_eq!(
        evaluator
            .heap()
            .cached_captured_value_hash(list)
            .expect("list record exists"),
        Some(list_hash)
    );

    let attrs_hash = evaluator
        .force_cache_free_var_value_hash(attrs)
        .expect("attrs hash");
    assert_eq!(
        evaluator
            .heap()
            .cached_captured_value_hash(attrs)
            .expect("attrs record exists"),
        Some(attrs_hash)
    );

    let positioned_hash = evaluator
        .force_cache_free_var_value_hash(positioned_attrs)
        .expect("positioned attrs hash");
    assert_eq!(
        evaluator
            .heap()
            .cached_captured_value_hash(positioned_attrs)
            .expect("positioned attrs record exists"),
        Some(positioned_hash)
    );

    let lazy_list_hash = evaluator
        .force_cache_free_var_value_hash(lazy_list)
        .expect("closed-literal lazy list hashes");
    assert_eq!(
        evaluator
            .heap()
            .cached_captured_value_hash(lazy_list)
            .expect("lazy list record exists"),
        Some(lazy_list_hash)
    );
    let thunk = evaluator
        .heap()
        .get_thunk(closed_literal_thunk)
        .expect("closed literal thunk exists");
    assert_eq!(
        thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "hashing a list containing a closed literal thunk must not force it"
    );
}

