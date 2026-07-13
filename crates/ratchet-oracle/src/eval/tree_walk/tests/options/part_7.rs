//! Split-out tests (part_7). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_cat_attrs_direct_list_result_skips_active_env_roots() {
    let root = IrId::new(0);
    let name_node = IrId::new(1);
    let list_node = IrId::new(2);
    let span = Span::new(0, 0);
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"a").expect("a interns");
    let ir = manual_ir_with_symbols(
        root,
        vec![
            pure_node(IrKind::Null, span, IrData::None),
            pure_node(IrKind::Str, span, IrData::Symbol(key)),
            pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 }),
        ],
        symbols,
    );
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let attrs = FlatAttrs::new(vec![AttrEntry::new(key, Value::int(1))], &evaluator.symbols)
        .expect("attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![attrs_value]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];
    let frame = EvalFrame::new(1).expect("active frame allocates");
    frame.set(0, input).expect("active frame slot sets");

    evaluator.env.push(frame);
    evaluator.active_root_eval_node = Some(root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(root, span, &mut roots, |eval| {
            eval.eval_cat_attrs_primop(root, span, name_node, list_node)
        })
        .expect("direct catAttrs list result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;
    evaluator.env.pop();

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "direct catAttrs result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active catAttrs environment roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("direct catAttrs result is heap-owned");
    assert_eq!(list.len(), 1);
    assert_eq!(list.get(0).expect("catAttrs value exists").as_int(), Ok(1));
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("direct catAttrs list allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_partition_list_results_skip_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let right_key = evaluator.symbols.intern(b"right").expect("right interns");
    let wrong_key = evaluator.symbols.intern(b"wrong").expect("wrong interns");
    let skipped = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("skipped string allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1), skipped, Value::int(2)]))
        .expect("input list allocates");
    let predicate_symbol = evaluator.symbols.intern(b"isInt").expect("isInt interns");
    let predicate_builtin = lookup_builtin(b"isInt").expect("isInt builtin exists");
    let predicate = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(predicate_symbol, predicate_builtin))
        .expect("predicate primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, predicate),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active partition argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_partition_elements(
            ir.root,
            span,
            ir.root,
            span,
            predicate,
            ir.root,
            span,
            vec![Value::int(1), skipped, Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("partition result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 2,
        "partition right/wrong lists did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active partition argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("partition result is heap-owned");
    let right = attrs.get(right_key).expect("right partition exists");
    let wrong = attrs.get(wrong_key).expect("wrong partition exists");
    let right = evaluator
        .heap()
        .get_list(right)
        .expect("right partition is heap-owned");
    assert_eq!(right.len(), 2);
    assert_eq!(
        right.get(0).expect("first right value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        right.get(1).expect("second right value exists").as_int(),
        Ok(2)
    );
    let wrong = evaluator
        .heap()
        .get_list(wrong)
        .expect("wrong partition is heap-owned");
    assert_eq!(wrong.len(), 1);
    assert!(wrong.get(0).expect("wrong value exists").raw_eq(skipped));
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert_eq!(
        permanent_safepoints.count(),
        permanent_safepoints_before + 3,
        "partition result did not record the two list safepoints plus attrs safepoint"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("partition attrs allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_concat_map_result_skips_active_argument_roots() {
    let ir = lower("x: x");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("identity function allocates");
    assert_eq!(function.tag(), ValueTag::Lambda);
    let skipped = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("skipped string allocates");
    let first = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("first input list allocates");
    let second = evaluator
        .heap
        .alloc_list(NixList::new(vec![skipped, Value::int(2)]))
        .expect("second input list allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![first, second]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active concatMap argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_concat_map_elements(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![first, second],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("concatMap result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "concatMap result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active concatMap argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("concatMap result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first concatMap value exists").as_int(),
        Ok(1)
    );
    assert!(
        list.get(1)
            .expect("second concatMap value exists")
            .raw_eq(skipped)
    );
    assert_eq!(
        list.get(2).expect("third concatMap value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "concatMap result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("concatMap list allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_group_by_bucket_lists_skip_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let int_key = evaluator.symbols.intern(b"int").expect("int interns");
    let string_key = evaluator.symbols.intern(b"string").expect("string interns");
    let string_value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("string input allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![
            Value::int(1),
            string_value,
            Value::int(2),
        ]))
        .expect("input list allocates");
    let function_symbol = evaluator.symbols.intern(b"typeOf").expect("typeOf interns");
    let function_builtin = lookup_builtin(b"typeOf").expect("typeOf builtin exists");
    let function = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(function_symbol, function_builtin))
        .expect("function primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active groupBy argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_group_by_elements(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![Value::int(1), string_value, Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("groupBy result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 2,
        "groupBy bucket lists did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active groupBy argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("groupBy result is heap-owned");
    let int_group = attrs.get(int_key).expect("int group exists");
    let string_group = attrs.get(string_key).expect("string group exists");
    let int_group = evaluator
        .heap()
        .get_list(int_group)
        .expect("int group is heap-owned");
    assert_eq!(int_group.len(), 2);
    assert_eq!(
        int_group
            .get(0)
            .expect("first int group value exists")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        int_group
            .get(1)
            .expect("second int group value exists")
            .as_int(),
        Ok(2)
    );
    let string_group = evaluator
        .heap()
        .get_list(string_group)
        .expect("string group is heap-owned");
    assert_eq!(string_group.len(), 1);
    assert!(
        string_group
            .get(0)
            .expect("string group value exists")
            .raw_eq(string_value)
    );
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert!(
        permanent_safepoints.count() >= permanent_safepoints_before + 3,
        "groupBy result did not record at least the two bucket-list safepoints plus attrs safepoint"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("groupBy attrs allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_sort_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let comparator_symbol = evaluator
        .symbols
        .intern(b"lessThan")
        .expect("lessThan interns");
    let comparator_builtin = lookup_builtin(b"lessThan").expect("lessThan builtin exists");
    let comparator = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(
            comparator_symbol,
            comparator_builtin,
        ))
        .expect("comparator primop allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![
            Value::int(3),
            Value::int(1),
            Value::int(2),
        ]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, comparator),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active sort argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_sort_elements(
            ir.root,
            span,
            ir.root,
            span,
            comparator,
            ir.root,
            span,
            vec![Value::int(3), Value::int(1), Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("sort result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "sort result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active sort argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("sort result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first sorted value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second sorted value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        list.get(2).expect("third sorted value exists").as_int(),
        Ok(3)
    );
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert!(
        permanent_safepoints.count() >= permanent_safepoints_before + 1,
        "sort result allocation did not record a permanent safepoint"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("sort list allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_generic_closure_empty_result_routes_through_list_wrapper() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let start_set = evaluator
        .heap
        .alloc_list(NixList::new(Vec::new()))
        .expect("startSet list allocates");
    let start_set_symbol = evaluator
        .symbols
        .intern(START_SET_ATTR)
        .expect("startSet interns");
    let argument_attrs = FlatAttrs::new(
        vec![AttrEntry::new(start_set_symbol, start_set)],
        &evaluator.symbols,
    )
    .expect("genericClosure argument attrs build");
    let argument = evaluator
        .heap
        .alloc_attrs(0, argument_attrs)
        .expect("genericClosure argument attrs allocate");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_generic_closure_primop(ir.root, span, ir.root, span, argument)
        })
        .expect("genericClosure empty result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "genericClosure empty result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root changed while routing genericClosure empty result"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("genericClosure empty result is heap-owned");
    assert!(list.is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_generic_closure_result_routes_through_list_wrapper() {
    let ir = lower("item: if item.key == 1 then [ { key = 2; } ] else []");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let operator = evaluator
        .eval_node(ir.root)
        .expect("genericClosure operator allocates");
    assert_eq!(operator.tag(), ValueTag::Lambda);
    let key_symbol = evaluator.symbols.intern(b"key").expect("key interns");
    let item_attrs = FlatAttrs::new(
        vec![AttrEntry::new(key_symbol, Value::int(1))],
        &evaluator.symbols,
    )
    .expect("item attrs build");
    let item = evaluator
        .heap
        .alloc_attrs(0, item_attrs)
        .expect("item attrs allocate");
    let start_set = evaluator
        .heap
        .alloc_list(NixList::new(vec![item]))
        .expect("startSet list allocates");
    let start_set_symbol = evaluator
        .symbols
        .intern(START_SET_ATTR)
        .expect("startSet interns");
    let operator_symbol = evaluator
        .symbols
        .intern(OPERATOR_ATTR)
        .expect("operator interns");
    let argument_attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(start_set_symbol, start_set),
            AttrEntry::new(operator_symbol, operator),
        ],
        &evaluator.symbols,
    )
    .expect("genericClosure argument attrs build");
    let argument = evaluator
        .heap
        .alloc_attrs(0, argument_attrs)
        .expect("genericClosure argument attrs allocate");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_generic_closure_primop(ir.root, span, ir.root, span, argument)
        })
        .expect("genericClosure result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 3,
        "genericClosure generated lists and final result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root changed while routing genericClosure result"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let result_items = {
        let result = evaluator
            .heap()
            .get_list(value)
            .expect("genericClosure result is heap-owned");
        assert_eq!(result.len(), 2);
        [
            result.get(0).expect("first result item exists"),
            result.get(1).expect("second result item exists"),
        ]
    };
    assert!(result_items[0].raw_eq(item));
    let generated = evaluator
        .heap()
        .get_attrs(result_items[1])
        .expect("generated item is heap-owned");
    let generated_key = generated.get(key_symbol).expect("generated key exists");
    assert_eq!(
        evaluator
            .force_value(ir.root, span, generated_key)
            .expect("generated key forces")
            .as_int(),
        Ok(2)
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("genericClosure result safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

