//! Split-out tests (part_9). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_filter_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
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
        .expect("active filter argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_filter_elements(
            ir.root,
            span,
            ir.root,
            span,
            predicate,
            ir.root,
            vec![Value::int(1), skipped, Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("filter result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "filter result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active filter argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("filter result is heap-owned");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.get(0).expect("first filter value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second filter value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "filter result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("filter list allocation safepoint records");
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
fn gc_stress_filter_map_empty_direct_results_route_through_list_wrapper() {
    for (label, eval_empty_result) in [
        (
            "filter",
            TreeWalk::eval_filter_primop
                as fn(&mut TreeWalk, IrId, Span, IrId, IrId) -> Result<Value, TreeWalkError>,
        ),
        (
            "map",
            TreeWalk::eval_map_primop
                as fn(&mut TreeWalk, IrId, Span, IrId, IrId) -> Result<Value, TreeWalkError>,
        ),
    ] {
        let ir = lower("[]");
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
        let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
        let value = evaluator
            .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
                eval_empty_result(eval, ir.root, span, ir.root, ir.root)
            })
            .expect("empty direct list builtin result evaluates under GC stress");
        let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
        evaluator.active_root_eval_node = None;

        assert_eq!(
            wrapper_calls_after,
            wrapper_calls_before + 2,
            "{label} input literal and empty result did not route through the tree-walk list wrapper"
        );
        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert_eq!(roots[0].tag(), ValueTag::Thunk);
        assert_eq!(value.tag(), ValueTag::List);
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("empty direct result is heap-owned");
        assert!(list.is_empty());
        assert!(evaluator.thunk_resolve_card_table().is_empty());
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_filter_map_empty_primop_value_results_route_through_list_wrapper() {
    for (label, eval_empty_result) in [
        (
            "filter",
            TreeWalk::eval_filter_primop_value
                as fn(
                    &mut TreeWalk,
                    IrId,
                    Span,
                    EvalPrimOpArg,
                    EvalPrimOpArg,
                ) -> Result<Value, TreeWalkError>,
        ),
        (
            "map",
            TreeWalk::eval_map_primop_value
                as fn(
                    &mut TreeWalk,
                    IrId,
                    Span,
                    EvalPrimOpArg,
                    EvalPrimOpArg,
                ) -> Result<Value, TreeWalkError>,
        ),
    ] {
        let ir = lower("null");
        let span = ir.arena.node(ir.root).expect("root exists").span;
        let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
        let input = evaluator
            .heap
            .alloc_list(NixList::new(Vec::new()))
            .expect("empty input list allocates");
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
                eval_empty_result(
                    eval,
                    ir.root,
                    span,
                    EvalPrimOpArg::new(ir.root, span, Value::int(1)),
                    EvalPrimOpArg::new(ir.root, span, input),
                )
            })
            .expect("empty primop-value list builtin result evaluates under GC stress");
        let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
        evaluator.active_root_eval_node = None;

        assert_eq!(
            wrapper_calls_after,
            wrapper_calls_before + 1,
            "{label} empty primop-value result did not route through the tree-walk list wrapper"
        );
        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert!(
            roots[0].raw_eq(local_source),
            "registered root changed while routing empty {label} primop-value result"
        );
        assert_eq!(value.tag(), ValueTag::List);
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("empty primop-value result is heap-owned");
        assert!(list.is_empty());
        assert!(evaluator.thunk_resolve_card_table().is_empty());
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_mapped_list_result_skips_apply_thunk_fields() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function_symbol = evaluator.symbols.intern(b"isInt").expect("isInt interns");
    let function_builtin = lookup_builtin(b"isInt").expect("isInt builtin exists");
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
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_list(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![Value::int(1), Value::bool(true)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    let value = result.expect("mapped list result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "mapped list result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while mapped apply-thunk fields were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("mapped list result is heap-owned");
    assert_eq!(list.len(), 2);
    for index in 0..2 {
        assert_eq!(
            list.get(index).expect("mapped element exists").tag(),
            ValueTag::Thunk
        );
    }
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "mapped list allocation did not record exactly one permanent safepoint"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "mapped apply-thunk fields should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("mapped list allocation safepoint records");
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
fn gc_stress_generated_list_result_skips_apply_thunk_fields() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let generator_symbol = evaluator.symbols.intern(b"isInt").expect("isInt interns");
    let generator_builtin = lookup_builtin(b"isInt").expect("isInt builtin exists");
    let generator = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(generator_symbol, generator_builtin))
        .expect("generator primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
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
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_generated_list(ir.root, span, ir.root, span, generator, ir.root, 2)
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    let value = result.expect("generated list result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "generated list result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated apply-thunk fields were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("generated list result is heap-owned");
    assert_eq!(list.len(), 2);
    for index in 0..2 {
        assert_eq!(
            list.get(index).expect("generated element exists").tag(),
            ValueTag::Thunk
        );
    }
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "generated list allocation did not record exactly one permanent safepoint"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "generated apply-thunk fields should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("generated list allocation safepoint records");
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
fn gc_stress_eval_root_reflected_context_result_helpers_skip_interned_composite_roots() {
    assert_gc_stress_root_string_result_skips_dispatch(
        r#"builtins.appendContext "x" { "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; }; }"#,
        b"x",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_context_string_result_helpers_dispatch_permanent_noop_bridge() {
    type ContextStringHelper =
        fn(&mut TreeWalk, IrId, Span, IrId, Span, Value) -> Result<Value, TreeWalkError>;
    let cases: &[(&str, ContextStringHelper)] = &[
        (
            "builtins.addDrvOutputDependencies \"x\"",
            TreeWalk::eval_add_drv_output_dependencies_primop,
        ),
        (
            "builtins.unsafeDiscardOutputDependency \"x\"",
            TreeWalk::eval_unsafe_discard_output_dependency_primop,
        ),
        (
            "builtins.unsafeDiscardStringContext \"x\"",
            TreeWalk::eval_unsafe_discard_string_context_primop,
        ),
    ];

    for (source, helper) in cases {
        let ir = lower(source);
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("context helper argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::with_options(
            &ir,
            TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
        );
        let context_path = b"/nix/store/context.drv".to_vec();
        let source_element = if source.contains("unsafeDiscardOutputDependency") {
            ContextElement::deep_derivation(context_path).expect("source context builds")
        } else {
            ContextElement::opaque_path(context_path).expect("source context builds")
        };
        let source_context =
            StringContext::singleton(source_element).expect("source context allocates");
        let source_string = evaluator
            .heap
            .alloc_string(NixString::new(b"x".to_vec(), source_context))
            .expect("source string allocates");
        let local_source = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(7)))
            .expect("registered local thunk allocates");
        let mut roots = [local_source];

        let permanent_safepoints_before =
            evaluator.heap().permanent_allocation_safepoints().count();
        let permanent_dispatches_before = evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len();
        evaluator.active_root_eval_node = Some(ir.root);
        let value = evaluator
            .with_transient_value_stack_roots(ir.root, root.span, &mut roots, |eval| {
                helper(
                    eval,
                    ir.root,
                    root.span,
                    argument,
                    argument_span,
                    source_string,
                )
            })
            .expect("context string helper evaluates under GC stress");
        evaluator.active_root_eval_node = None;

        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert!(
            !roots[0].raw_eq(local_source),
            "registered root was not relocated while evaluating {source}"
        );
        assert_eq!(roots[0].tag(), ValueTag::Thunk);
        assert_eq!(value.tag(), ValueTag::String);
        assert_eq!(
            evaluator
                .heap()
                .generation(value)
                .expect("context result string generation is known"),
            HeapGeneration::Permanent
        );
        assert_eq!(
            evaluator
                .heap()
                .get_string(value)
                .expect("context result string is heap-owned")
                .bytes(),
            b"x"
        );
        assert_eq!(
            evaluator.heap().permanent_allocation_safepoints().count(),
            permanent_safepoints_before + 1,
            "{source} should allocate exactly one context result string"
        );
        assert_eq!(
            &evaluator.gc_stress_permanent_root_allocation_dispatches()
                [permanent_dispatches_before..],
            &[RuntimeAllocationEntryPoint::AosAllocString],
            "{source} should dispatch exactly one permanent context result string allocation"
        );
        let permanent_safepoint = evaluator
            .heap()
            .permanent_allocation_safepoints()
            .last()
            .expect("context result string allocation safepoint records");
        assert_eq!(
            permanent_safepoint.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocString
        );
        assert_eq!(
            permanent_safepoint.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEverySafepoint)
        );
        assert!(evaluator.thunk_resolve_card_table().is_empty());
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_lambda_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct lambda node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::Lambda);
    assert_eq!(evaluator.heap().len(), 1);
    assert_eq!(evaluator.heap().allocation_safepoints().count(), 1);
    let final_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct lambda allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_primop_allocation_dispatches_reserved_writeback_bridge() {
    let ir = lower("builtins.length");
    let default_outcome = eval_whnf_owned(&ir).expect("default primop evaluates");

    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let value = evaluator.eval_root().expect("GC-stress primop evaluates");

    assert_eq!(value.tag(), ValueTag::Primop);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("primop generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(evaluator.heap().len(), default_outcome.heap().len() + 1);
    let source_value = evaluator
        .heap()
        .test_record_value(0)
        .expect("original primop source record exists")
        .expect("original primop source value rebuilds");
    let destination_value = evaluator
        .heap()
        .test_record_value(1)
        .expect("reserved primop destination record exists")
        .expect("reserved primop destination value rebuilds");
    assert!(!source_value.raw_eq(value));
    assert!(destination_value.raw_eq(value));
    assert_eq!(
        evaluator.heap().allocation_safepoints().count(),
        default_outcome.heap().allocation_safepoints().count() + 1
    );
    let final_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("final primop reserved allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocRaw
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );

    let empty_list = evaluator
        .heap
        .alloc_list(NixList::empty())
        .expect("empty list allocates");
    let applied = evaluator
        .apply_value(ir.root, Span::new(0, 0), value, empty_list)
        .expect("relocated length primop applies");
    assert_eq!(applied.as_int(), Ok(0));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_primop_allocation_dispatch_skips_captured_argument_primops() {
    let ir = lower("builtins.substring \"abcdef\"");
    let default_outcome = eval_whnf_owned(&ir).expect("default partial primop evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress partial primop evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Primop);
    let primop = outcome
        .heap()
        .get_primop(outcome.value())
        .expect("partial primop is heap-owned");
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].value().tag(), ValueTag::String);
    assert_eq!(outcome.heap().len(), default_outcome.heap().len());
    assert_eq!(
        outcome.heap().allocation_safepoints().count(),
        default_outcome.heap().allocation_safepoints().count()
    );
    let final_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("partial primop allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocRaw
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_primop_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("builtins.map");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct primop node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::Primop);
    assert_eq!(evaluator.heap().len(), 1);
    assert_eq!(evaluator.heap().allocation_safepoints().count(), 1);
    let final_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct primop allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocRaw
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_thunk_allocation_dispatches_reserved_forwarding_bridge() {
    let body = IrId::new(0);
    let root = IrId::new(1);
    let ir = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(7)),
            pure_node(IrKind::ThunkAlloc, Span::new(0, 1), IrData::Node(body)),
        ],
    );
    let default_outcome = eval_whnf_owned(&ir).expect("default root thunk alloc evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress root thunk alloc evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.heap().len(), default_outcome.heap().len() + 1);
    let source_value = outcome
        .heap()
        .test_record_value(0)
        .expect("original thunk source record exists")
        .expect("original thunk source value rebuilds");
    let destination_value = outcome
        .heap()
        .test_record_value(1)
        .expect("reserved thunk destination record exists")
        .expect("reserved thunk destination value rebuilds");
    assert_eq!(source_value.tag(), ValueTag::Thunk);
    assert_eq!(destination_value.tag(), ValueTag::Thunk);
    assert!(!source_value.raw_eq(destination_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("root thunk destination generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(
        outcome.heap().allocation_safepoints().count(),
        default_outcome.heap().allocation_safepoints().count() + 1
    );
    let final_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("final root thunk reserved allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

