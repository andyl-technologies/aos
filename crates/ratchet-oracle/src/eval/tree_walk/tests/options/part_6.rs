//! Split-out tests (part_6). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_formal_set_auto_call_empty_arg_skips_non_attrset_root_dispatch() {
    let ir = lower("{ selected ? 7 }: selected");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let lambda = evaluator.eval_root().expect("formal-set lambda allocates");
    assert_eq!(lambda.tag(), ValueTag::Lambda);
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.auto_call_formal_set_lambda(ir.root, span, lambda)
        })
        .expect("formal-set auto-call evaluates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while auto-call empty attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.as_int(), Ok(7));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "formal-set auto-call should record exactly one permanent attrset safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("formal-set auto-call attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    let stats = evaluator.attr_telemetry.order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_get_context_empty_result_skips_primop_composite_dispatch() {
    let ir = lower(r#"builtins.getContext "x""#);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress getContext evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated getContext attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("getContext result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "getContext evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("getContext result attrset allocation safepoint records");
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
fn gc_stress_eval_root_list_string_result_helpers_skip_interned_composite_roots() {
    let cases: &[(&str, &[u8])] = &[
        (r#"builtins.concatStringsSep "," [ "a" "b" ]"#, b"a,b"),
        (r#"builtins.replaceStrings [ "a" ] [ "b" ] "ca""#, b"cb"),
    ];

    for (source, expected) in cases {
        assert_gc_stress_root_string_result_skips_dispatch(source, expected);
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_strict_unary_attr_names_list_result_skips_composite_input_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let z = evaluator.symbols.intern(b"z").expect("z interns");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(z, Value::int(2)),
            AttrEntry::new(a, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_strict_unary_primop_value(
                ir.root,
                span,
                StrictUnaryPrimOp::AttrNames,
                ir.root,
                span,
                attrs_value,
            )
        })
        .expect("attrNames helper list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while attrNames input attrset root was live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("attrNames result is heap-owned");
    assert_eq!(list.len(), 2);
    let first = evaluator
        .heap()
        .get_string(list.get(0).expect("first attr name exists"))
        .expect("first attr name is a string");
    let second = evaluator
        .heap()
        .get_string(list.get(1).expect("second attr name exists"))
        .expect("second attr name is a string");
    assert_eq!(first.bytes(), b"a");
    assert_eq!(second.bytes(), b"z");
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "attrNames input attrset root should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("attrNames list allocation safepoint records");
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
fn gc_stress_strict_unary_attr_values_list_result_skips_composite_input_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let z = evaluator.symbols.intern(b"z").expect("z interns");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(z, Value::int(2)),
            AttrEntry::new(a, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_strict_unary_primop_value(
                ir.root,
                span,
                StrictUnaryPrimOp::AttrValues,
                ir.root,
                span,
                attrs_value,
            )
        })
        .expect("attrValues helper list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while attrValues input attrset root was live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("attrValues result is heap-owned");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.get(0).expect("first attr value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second attr value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "attrValues input attrset root should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("attrValues list allocation safepoint records");
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
fn gc_stress_strict_unary_tail_list_result_skips_composite_input_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![
            Value::int(0),
            Value::int(1),
            Value::bool(true),
        ]))
        .expect("input list allocates");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_strict_unary_primop_value(
                ir.root,
                span,
                StrictUnaryPrimOp::Tail,
                ir.root,
                span,
                input,
            )
        })
        .expect("tail helper list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while tail input list root was live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("tail result is heap-owned");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.get(0).expect("first tail value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second tail value exists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "tail input list root should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("tail list allocation safepoint records");
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
fn gc_stress_alloc_tree_walk_list_skips_active_primop_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[EvalPrimOpArg::new(ir.root, span, Value::int(9))],
        )
        .expect("active primop roots push");
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_tree_walk_list(ir.root, span, NixList::new(vec![Value::int(1)]))
        })
        .expect("list wrapper allocates with active primop roots");
    evaluator.pop_active_primop_arg_roots();
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated despite active primop roots"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("list wrapper result is heap-owned");
    assert_eq!(list.len(), 1);
    assert_eq!(list.get(0).expect("list value exists").as_int(), Ok(1));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "list wrapper allocation did not record exactly one permanent safepoint"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "active first-class primop argument roots should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("list allocation safepoint records");
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
fn gc_stress_list_concat_result_skips_composite_input_roots() {
    let ir = lower("[ 1 ] ++ [ 2 true ]");
    let node = ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let left = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("left list allocates");
    let right = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(2), Value::bool(true)]))
        .expect("right list allocates");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, node.span, &mut roots, |eval| {
            eval.concat_lists(ir.root, node, left, right)
        })
        .expect("list concat result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "list concat result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while list concat input list roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("list concat result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first concat value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second concat value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        list.get(2).expect("third concat value exists").as_bool(),
        Ok(true)
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("list concat allocation safepoint records");
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
fn gc_stress_concat_lists_primop_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let first = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("first list allocates");
    let second = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(2), Value::bool(true)]))
        .expect("second list allocates");
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
        .push_active_primop_arg_roots(ir.root, span, &[EvalPrimOpArg::new(ir.root, span, input)])
        .expect("active concatLists argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_concat_lists_primop(ir.root, span, ir.root, span, input)
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("concatLists result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "concatLists result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active concatLists argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("concatLists result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0)
            .expect("first concatLists value exists")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1)
            .expect("second concatLists value exists")
            .as_int(),
        Ok(2)
    );
    assert_eq!(
        list.get(2)
            .expect("third concatLists value exists")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "concatLists result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("concatLists list allocation safepoint records");
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
fn gc_stress_cat_attrs_list_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let key = evaluator.symbols.intern(b"a").expect("a interns");
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

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(ir.root, span, &[EvalPrimOpArg::new(ir.root, span, input)])
        .expect("active catAttrs argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_cat_attrs_primop_value(
            ir.root,
            span,
            key,
            EvalPrimOpArg::new(ir.root, span, input),
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("catAttrs list result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "catAttrs result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active catAttrs argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("catAttrs result is heap-owned");
    assert_eq!(list.len(), 1);
    assert_eq!(list.get(0).expect("catAttrs value exists").as_int(), Ok(1));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "catAttrs result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("catAttrs list allocation safepoint records");
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
