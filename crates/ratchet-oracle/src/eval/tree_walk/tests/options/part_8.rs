//! Split-out tests (part_8). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_map_attrs_symbol_names_preserve_live_locals() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    // FV-3: the GC-stress scan machinery operates on record-table worker
    // objects; select the scaffolding placement before any allocation so
    // the late stress-policy install below sees a record population.
    evaluator
        .heap
        .use_record_worker_closures_for_gc_scaffolding();
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(31)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(37)))
        .expect("right value thunk allocates");

    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
        .expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(
        !a_function.raw_eq(function),
        "first mapAttrs function handle was not relocated before thunk capture"
    );
    assert!(
        !b_function.raw_eq(function),
        "second mapAttrs function handle was not written back after relocation"
    );
    evaluator
        .heap()
        .get_lambda(a_function)
        .expect("first mapAttrs function remains heap-owned");
    evaluator
        .heap()
        .get_lambda(b_function)
        .expect("second mapAttrs function remains heap-owned");
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(
        !a_value.raw_eq(left),
        "current mapAttrs value was not relocated before thunk capture"
    );
    assert!(
        !b_value.raw_eq(right),
        "unprocessed mapAttrs entry tail was not written back after relocation"
    );
    assert_eq!(a_value.tag(), ValueTag::Thunk);
    assert_eq!(b_value.tag(), ValueTag::Thunk);
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "mapAttrs should dispatch the two symbol-name string allocations"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_map_attrs_symbol_names_dispatch_with_active_function_argument_root() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    // FV-3: the GC-stress scan machinery operates on record-table worker
    // objects; select the scaffolding placement before any allocation so
    // the late stress-policy install below sees a record population.
    evaluator
        .heap
        .use_record_worker_closures_for_gc_scaffolding();
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(41)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(43)))
        .expect("right value thunk allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(47)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, Value::int(2)),
            ],
        )
        .expect("active mapAttrs argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
    });
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while active function argument root was admitted"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(
        !a_function.raw_eq(function),
        "first mapAttrs function argument was not relocated before thunk capture"
    );
    assert!(
        !b_function.raw_eq(function),
        "second mapAttrs function argument was not written back after relocation"
    );
    evaluator
        .heap()
        .get_lambda(a_function)
        .expect("first mapAttrs function remains heap-owned");
    evaluator
        .heap()
        .get_lambda(b_function)
        .expect("second mapAttrs function remains heap-owned");
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(
        !a_value.raw_eq(left),
        "current mapAttrs value was not relocated before thunk capture"
    );
    assert!(
        !b_value.raw_eq(right),
        "unprocessed mapAttrs entry tail was not written back after relocation"
    );
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count()
            >= permanent_safepoints_before + 3,
        "mapAttrs result did not record expected permanent allocations"
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "admitted mapAttrs function argument should allow the two symbol-name string dispatches"
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
fn gc_stress_map_attrs_symbol_names_skip_unregistered_active_argument_root() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(61)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(67)))
        .expect("right value thunk allocates");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        &evaluator.symbols,
    )
    .expect("input attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("input attrs allocate");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(71)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, attrs_value),
            ],
        )
        .expect("active mapAttrs argument roots push");
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
    });
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while unregistered active mapAttrs argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(a_function.raw_eq(function));
    assert!(b_function.raw_eq(function));
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(a_value.raw_eq(left));
    assert!(b_value.raw_eq(right));
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "unregistered active mapAttrs argument root should block symbol-name dispatch"
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
fn gc_stress_map_attrs_symbol_names_skip_nested_active_argument_frames() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(51)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(53)))
        .expect("right value thunk allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(57)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[EvalPrimOpArg::new(ir.root, span, Value::int(1))],
        )
        .expect("outer active argument roots push");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, Value::int(2)),
            ],
        )
        .expect("inner active mapAttrs argument roots push");
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
    });
    evaluator.pop_active_primop_arg_roots();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while nested active primop argument frames were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(a_function.raw_eq(function));
    assert!(b_function.raw_eq(function));
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(a_value.raw_eq(left));
    assert!(b_value.raw_eq(right));
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "nested active primop argument frames should block mapAttrs symbol-name dispatch"
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
fn gc_stress_zip_attrs_with_symbol_names_preserve_values_lists() {
    let ir = lower("name: values: values");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("zipAttrsWith function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(41)))
        .expect("left value thunk allocates");
    let middle = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(43)))
        .expect("middle value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(47)))
        .expect("right value thunk allocates");
    let first_attrs = FlatAttrs::new(
        vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, middle)],
        &evaluator.symbols,
    )
    .expect("first attrs build");
    let first = evaluator
        .heap
        .alloc_attrs(0, first_attrs)
        .expect("first attrs allocate");
    let second_attrs = FlatAttrs::new(vec![AttrEntry::new(a_key, right)], &evaluator.symbols)
        .expect("second attrs build");
    let second = evaluator
        .heap
        .alloc_attrs(0, second_attrs)
        .expect("second attrs allocate");

    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .alloc_zipped_attrs_with(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            span,
            vec![first, second],
        )
        .expect("zipAttrsWith result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("zipAttrsWith result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_values) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_values) = apply2_thunk_values(&evaluator, b_thunk);

    evaluator
        .heap()
        .get_lambda(a_function)
        .expect("first zipAttrsWith function remains heap-owned");
    evaluator
        .heap()
        .get_lambda(b_function)
        .expect("second zipAttrsWith function remains heap-owned");
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    let a_items = {
        let list = evaluator
            .heap()
            .get_list(a_values)
            .expect("a grouped values are heap-owned");
        assert_eq!(list.len(), 2);
        [
            list.get(0).expect("first a value exists"),
            list.get(1).expect("second a value exists"),
        ]
    };
    let b_item = {
        let list = evaluator
            .heap()
            .get_list(b_values)
            .expect("b grouped values are heap-owned");
        assert_eq!(list.len(), 1);
        list.get(0).expect("b value exists")
    };
    assert_eq!(a_items[0].tag(), ValueTag::Thunk);
    assert_eq!(a_items[1].tag(), ValueTag::Thunk);
    assert_eq!(b_item.tag(), ValueTag::Thunk);
    evaluator
        .heap()
        .get_thunk(a_items[0])
        .expect("first zipAttrsWith grouped value remains heap-owned");
    evaluator
        .heap()
        .get_thunk(a_items[1])
        .expect("second zipAttrsWith grouped value remains heap-owned");
    evaluator
        .heap()
        .get_thunk(b_item)
        .expect("remaining zipAttrsWith group tail remains heap-owned");
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 5,
        "zipAttrsWith should allocate two grouped value lists, two symbol-name strings, and the final attrset"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "zipAttrsWith symbol-name safepoints should remain blocked by live composite input roots"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("zipAttrsWith final attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_zip_attrs_with_direct_root_value_lists_preserve_live_locals() {
    let ir = lower(
        r#"
builtins.zipAttrsWith (name: values: values) [
  { a = "left"; b = "middle"; }
  { a = "right"; }
]
"#,
    );
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .eval_root()
        .expect("root zipAttrsWith evaluates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();

    assert!(
        wrapper_calls_after >= wrapper_calls_before + 2,
        "root zipAttrsWith grouped value lists did not route through the tree-walk list wrapper"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("zipAttrsWith result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let a_values = evaluator
        .force_value(ir.root, span, a_thunk)
        .expect("a grouped values thunk forces");
    let b_values = evaluator
        .force_value(ir.root, span, b_thunk)
        .expect("b grouped values thunk forces");
    let a_items = {
        let list = evaluator
            .heap()
            .get_list(a_values)
            .expect("a grouped values are heap-owned");
        assert_eq!(list.len(), 2);
        [
            list.get(0).expect("first a value exists"),
            list.get(1).expect("second a value exists"),
        ]
    };
    let b_item = {
        let list = evaluator
            .heap()
            .get_list(b_values)
            .expect("b grouped values are heap-owned");
        assert_eq!(list.len(), 1);
        list.get(0).expect("b value exists")
    };
    let first_a = evaluator
        .force_value(ir.root, span, a_items[0])
        .expect("first a grouped value forces");
    let second_a = evaluator
        .force_value(ir.root, span, a_items[1])
        .expect("second a grouped value forces");
    let b = evaluator
        .force_value(ir.root, span, b_item)
        .expect("b grouped value forces");

    assert_heap_string_bytes(&evaluator, first_a, b"left");
    assert_heap_string_bytes(&evaluator, second_a, b"right");
    assert_heap_string_bytes(&evaluator, b, b"middle");
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_zip_attrs_with_value_lists_skip_active_argument_roots() {
    let ir = lower("name: values: values");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("zipAttrsWith function allocates");
    assert_eq!(function.tag(), ValueTag::Lambda);
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let first_attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(a_key, Value::int(1)),
            AttrEntry::new(b_key, Value::int(2)),
        ],
        &evaluator.symbols,
    )
    .expect("first attrs build");
    let first = evaluator
        .heap
        .alloc_attrs(0, first_attrs)
        .expect("first attrs allocate");
    let second_attrs = FlatAttrs::new(
        vec![AttrEntry::new(a_key, Value::int(3))],
        &evaluator.symbols,
    )
    .expect("second attrs build");
    let second = evaluator
        .heap
        .alloc_attrs(0, second_attrs)
        .expect("second attrs allocate");
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
                EvalPrimOpArg::new(ir.root, span, Value::int(2)),
            ],
        )
        .expect("active zipAttrsWith argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_zipped_attrs_with(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            span,
            vec![first, second],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("zipAttrsWith result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 2,
        "zipAttrsWith grouped value lists did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active zipAttrsWith argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("zipAttrsWith result is heap-owned");
    let a_value = attrs.get(a_key).expect("a result exists");
    let b_value = attrs.get(b_key).expect("b result exists");
    let a_values = zipped_apply2_second_argument(&evaluator, a_value);
    let b_values = zipped_apply2_second_argument(&evaluator, b_value);
    let a_values = evaluator
        .heap()
        .get_list(a_values)
        .expect("a grouped values list is heap-owned");
    assert_eq!(a_values.len(), 2);
    assert_eq!(
        a_values.get(0).expect("first a value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        a_values.get(1).expect("second a value exists").as_int(),
        Ok(3)
    );
    let b_values = evaluator
        .heap()
        .get_list(b_values)
        .expect("b grouped values list is heap-owned");
    assert_eq!(b_values.len(), 1);
    assert_eq!(b_values.get(0).expect("b value exists").as_int(), Ok(2));
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert!(
        permanent_safepoints.count() >= permanent_safepoints_before + 3,
        "zipAttrsWith result did not record expected permanent allocations after grouped value-list wrapper calls"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("zipAttrsWith attrs allocation safepoint records");
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
