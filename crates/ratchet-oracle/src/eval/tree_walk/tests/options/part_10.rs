//! Split-out tests (part_10). See parent module.

use super::*;

#[test]
fn gc_polling_preserves_nonmoving_config_provenance_until_later_access() {
    let source = r#"
      ({ config, ... }: config.nested)
      { config = { nested = { value = 7; }; }; }
    "#;
    let ir = lower(source);
    let observer = OptionReadObserver::default();
    let mut options = TreeWalkOptions::default();
    options.set_option_read_observer(observer.clone());
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        options,
        b"option-gc-stress.nix".to_vec(),
        source.as_bytes().to_vec(),
    );
    let original = evaluator
        .eval_root()
        .expect("config-derived attrset evaluates to WHNF");
    let original_identity = original.relocation_sensitive_identity_bits();
    assert_eq!(
        observer.provenance(original),
        vec![vec![b"nested".to_vec()]]
    );
    let carrier = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(ir.root))
        .expect("flat provenance carrier allocates");
    evaluator.propagate_option_provenance(carrier, &[original]);
    assert_eq!(observer.provenance(carrier), vec![vec![b"nested".to_vec()]]);

    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut roots = [carrier];
    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_json(
                ir.root,
                span,
                JsonValue::Array(vec![JsonValue::Null, JsonValue::Bool(true)]),
            )
        })
        .expect("JSON array allocation exercises GC polling and allocation churn");
    evaluator.active_root_eval_node = None;

    let rooted_carrier = roots[0];
    assert_eq!(
        rooted_carrier.relocation_sensitive_identity_bits(),
        carrier.relocation_sensitive_identity_bits(),
        "the production flat typed-head carrier is nonmoving"
    );
    assert_eq!(
        observer.provenance(rooted_carrier),
        vec![vec![b"nested".to_vec()]]
    );
    assert_eq!(
        original.relocation_sensitive_identity_bits(),
        original_identity,
        "the WHNF attrset remains in permanent storage"
    );

    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::disabled());
    assert_eq!(
        observer.provenance(original),
        vec![vec![b"nested".to_vec()]]
    );

    let key = evaluator
        .symbols
        .intern(b"value")
        .expect("attribute name interns");
    let selected = evaluator
        .heap
        .get_attrs(original)
        .expect("nonmoving root remains an attrset")
        .get(key)
        .expect("value attribute exists");
    evaluator.record_option_attr_access(original, key, Some(selected));

    assert!(observer.snapshot().iter().any(|read| {
        read.source == b"option-gc-stress.nix"
            && read.path == [b"nested".to_vec(), b"value".to_vec()]
    }));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_list_allocation_dispatches_dirty_card_writeback_bridge() {
    let ir = lower("[ (x: x) ]");
    let default_outcome = eval_whnf_owned(&ir).expect("default list evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress list evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::List);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("list generation is known"),
        HeapGeneration::Permanent
    );
    assert!(outcome.heap().len() > default_outcome.heap().len());

    let element = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root list is heap-owned");
        list.get(0).expect("list element exists")
    };
    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(
        outcome
            .heap()
            .generation(element)
            .expect("element generation is known"),
        HeapGeneration::Young
    );
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert!(thunk_values.iter().any(|value| value.raw_eq(element)));
    assert!(
        thunk_values
            .iter()
            .filter(|value| !value.raw_eq(element))
            .count()
            >= 1
    );

    assert!(
        outcome.heap().allocation_safepoints().count()
            > default_outcome.heap().allocation_safepoints().count()
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("reserved thunk allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        outcome.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count()
    );
    let final_permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root list allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_list_accumulator_thunk_allocations_publish_accumulated_roots() {
    let ir = lower("[ (x: x) (y: y) ]");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress multi-element list evaluates with local accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::List);
    let elements = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root list is heap-owned");
        vec![
            list.get(0).expect("first list element exists"),
            list.get(1).expect("second list element exists"),
        ]
    };
    for element in &elements {
        assert_eq!(element.tag(), ValueTag::Thunk);
        assert_eq!(
            outcome
                .heap()
                .generation(*element)
                .expect("element generation is known"),
            HeapGeneration::Young
        );
    }
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    for element in &elements {
        assert!(thunk_values.iter().any(|value| value.raw_eq(*element)));
    }
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) > elements.len());
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root list allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_list_accumulator_allocation_node_clears_after_child_error() {
    let span = Span::new(0, 1);
    let body = IrId::new(0);
    let first_child = IrId::new(1);
    let error_child = IrId::new(2);
    let root = IrId::new(3);
    let ir = empty_ir(
        root,
        IrArena::from_raw_parts(
            vec![
                pure_node(IrKind::Int, span, IrData::Int(7)),
                pure_node(IrKind::ThunkAlloc, span, IrData::Node(body)),
                pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 }),
                pure_node(
                    IrKind::List,
                    span,
                    IrData::Children(IrChildSlice::new(0, 2)),
                ),
            ],
            vec![first_child, error_child],
        ),
    );
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let error = evaluator
        .eval_root()
        .expect_err("invalid list child reports evaluation error");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingEnvironment { id: error_child }
    );
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert!(heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values) >= 1);
    assert_eq!(evaluator.active_root_eval_node, None);
    assert_eq!(evaluator.active_gc_stress_accumulator_allocation_node, None);
    assert!(evaluator.transient_value_stack_roots().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_list_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("[ (x: x) ]");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct list node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::List);
    let element = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("root list is heap-owned");
        list.get(0).expect("list element exists")
    };
    assert_eq!(element.tag(), ValueTag::Thunk);
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), 1);
    assert_eq!(
        thunk_values
            .iter()
            .filter(|value| value.raw_eq(element))
            .count(),
        1
    );
    assert!(evaluator.heap().allocation_safepoints().count() >= 1);
    let final_worker_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct list worker allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("direct list allocation safepoint records");
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
fn gc_stress_eval_root_attrs_allocation_dispatches_dirty_card_writeback_bridge() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let default_outcome = eval_whnf_owned(&ir).expect("default attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress attrset evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("attrset generation is known"),
        HeapGeneration::Permanent
    );
    assert!(outcome.heap().len() > default_outcome.heap().len());

    let attr_value = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(attr_value.tag(), ValueTag::Thunk);
    assert_eq!(
        outcome
            .heap()
            .generation(attr_value)
            .expect("attr value generation is known"),
        HeapGeneration::Young
    );
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert!(thunk_values.iter().any(|value| value.raw_eq(attr_value)));
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) >= 1);

    assert!(
        outcome.heap().allocation_safepoints().count()
            > default_outcome.heap().allocation_safepoints().count()
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("reserved thunk allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        outcome.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count()
    );
    let final_permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root attrset allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_attrs_accumulator_thunk_allocations_publish_accumulated_roots() {
    let ir = lower("{ a = x: x; b = y: y; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress multi-attr attrset evaluates with local accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let attr_values = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    let values = [attr_values.0, attr_values.1];
    for value in values {
        assert_eq!(value.tag(), ValueTag::Thunk);
        assert_eq!(
            outcome
                .heap()
                .generation(value)
                .expect("attr value generation is known"),
            HeapGeneration::Young
        );
    }
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    for value in values {
        assert!(thunk_values.iter().any(|record| record.raw_eq(value)));
    }
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) > values.len());
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_dynamic_attrs_accumulator_thunk_allocations_publish_accumulated_roots() {
    let ir = lower(r#"{ a = x: x; ${"b"} = y: y; }"#);
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress dynamic-key attrset evaluates with local accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let attr_values = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    let values = [attr_values.0, attr_values.1];
    for value in values {
        assert_eq!(value.tag(), ValueTag::Thunk);
        assert_eq!(
            outcome
                .heap()
                .generation(value)
                .expect("attr value generation is known"),
            HeapGeneration::Young
        );
    }
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    for value in values {
        assert!(thunk_values.iter().any(|record| record.raw_eq(value)));
    }
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) > values.len());
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root dynamic-key attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_mixed_inherited_attrs_accumulator_thunk_allocations_publish_select_roots() {
    let ir = lower("{ inherit ({ a = 1; }) a; b = x: x; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let default_outcome = eval_whnf_owned(&ir).expect("default mixed inherited attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress mixed inherited attrset evaluates with local accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let (selected, ordinary) = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("inherited attr exists"),
            attrs.get(b).expect("ordinary attr exists"),
        )
    };
    assert_eq!(selected.tag(), ValueTag::Thunk);
    let selected_thunk = outcome
        .heap()
        .get_thunk(selected)
        .expect("inherited select is a heap-owned thunk");
    assert!(matches!(
        selected_thunk.kind(),
        EvalThunkKind::Select { .. }
    ));
    assert_eq!(ordinary.tag(), ValueTag::Thunk);
    assert_eq!(
        outcome
            .heap()
            .generation(ordinary)
            .expect("ordinary attr value generation is known"),
        HeapGeneration::Young
    );

    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert!(thunk_values.iter().any(|value| value.raw_eq(selected)));
    assert!(thunk_values.iter().any(|value| value.raw_eq(ordinary)));
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) >= 1);
    assert!(
        outcome.heap().allocation_safepoints().count()
            > default_outcome.heap().allocation_safepoints().count()
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("ordinary attr thunk allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_dynamic_attr_key_expression_preserves_registered_roots() {
    let ir = lower(r#"{ inherit ({ a = 1; }) a; ${"b"} = 2; }"#);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let default_outcome =
        eval_whnf_owned(&ir).expect("default dynamic inherited attrset evaluates");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(97)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress dynamic inherited attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while dynamic attr key expression was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (selected, dynamic_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("inherited attr exists"),
            attrs.get(b).expect("dynamic attr exists"),
        )
    };
    assert_eq!(selected.tag(), ValueTag::Thunk);
    let selected_thunk = evaluator
        .heap()
        .get_thunk(selected)
        .expect("inherited select is a heap-owned thunk");
    assert!(matches!(
        selected_thunk.kind(),
        EvalThunkKind::Select { .. }
    ));
    assert_eq!(dynamic_value.as_int(), Ok(2));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count(),
        "dynamic-key expression should not add an extra permanent allocation safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root attrset allocation safepoint records");
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
fn gc_stress_recursive_override_binding_assembly_preserves_registered_roots() {
    let ir = lower(r#"rec { a = x: x; __overrides = { b = y: y; }; ${"c"} = z: z; }"#);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let c = symbol_for(&ir, b"c");
    let overrides = symbol_for(&ir, b"__overrides");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(98)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress recursive override attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while recursive override binding assembly was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_value, b_value, c_value, overrides_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("override b exists"),
            attrs.get(c).expect("dynamic c exists"),
            attrs.get(overrides).expect("__overrides exists"),
        )
    };
    assert_eq!(overrides_value.tag(), ValueTag::Thunk);
    for value in [a_value, b_value, c_value] {
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap()
            .get_thunk(value)
            .expect("binding value is a heap-owned thunk");
        assert!(thunk.env().is_some_and(|env| !env.frames().is_empty()));
    }
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(
        heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values),
        0
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
fn gc_stress_let_binding_assembly_preserves_registered_roots() {
    let ir = lower("let a = x: x; b = y: y; in { inherit a b; }");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(99)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress let binding attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while let binding assembly was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_value, b_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    for value in [a_value, b_value] {
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap()
            .get_thunk(value)
            .expect("binding value is a heap-owned thunk");
        assert!(thunk.env().is_some_and(|env| !env.frames().is_empty()));
    }
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(
        heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values),
        0
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
fn gc_stress_lambda_default_binding_assembly_preserves_registered_roots() {
    let ir = lower("let captured = x: x; in ({ a ? captured, b ? (y: y) }: { inherit a b; }) { }");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(100)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress lambda default attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while lambda default binding assembly was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_value, b_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    for value in [a_value, b_value] {
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap()
            .get_thunk(value)
            .expect("default value is a heap-owned thunk");
        assert!(thunk.env().is_some_and(|env| !env.frames().is_empty()));
    }
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(
        heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values),
        0
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}
