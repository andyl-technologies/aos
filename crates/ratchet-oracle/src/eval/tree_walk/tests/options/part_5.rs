//! Split-out tests (part_5). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_remove_attrs_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.removeAttrs { keep = 7; drop = 1; } [ \"drop\" ]");
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

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress removeAttrs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated removeAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let keep_key = evaluator.symbols.intern(b"keep").expect("keep key interns");
    let drop_key = evaluator.symbols.intern(b"drop").expect("drop key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("removeAttrs result is heap-owned");
    assert_eq!(attrs.len(), 1);
    assert_eq!(
        attrs.get(keep_key).expect("keep attr exists").as_int(),
        Ok(7)
    );
    assert!(attrs.get(drop_key).is_none());
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("removeAttrs result attrset allocation safepoint records");
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
fn gc_stress_eval_root_intersect_attrs_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.intersectAttrs { keep = 0; missing = 0; } { keep = 7; drop = 1; }");
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

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress intersectAttrs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated intersectAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let keep_key = evaluator.symbols.intern(b"keep").expect("keep key interns");
    let drop_key = evaluator.symbols.intern(b"drop").expect("drop key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("intersectAttrs result is heap-owned");
    assert_eq!(attrs.len(), 1);
    assert_eq!(
        attrs.get(keep_key).expect("keep attr exists").as_int(),
        Ok(7)
    );
    assert!(attrs.get(drop_key).is_none());
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("intersectAttrs result attrset allocation safepoint records");
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
fn gc_stress_map_attrs_empty_result_allocates_and_skips_primop_composite_dispatch() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let input = evaluator
        .heap
        .alloc_attrs_with_repr_metadata(99, AttrSetReprKind::Flat, FlatAttrs::empty())
        .expect("metadata-distinct empty input attrs allocate");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_map_attrs_primop_value(
                ir.root,
                span,
                EvalPrimOpArg::new(ir.root, span, Value::int(0)),
                EvalPrimOpArg::new(ir.root, span, input),
            )
        })
        .expect("GC-stress mapAttrs result allocates");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated mapAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert!(
        !value.raw_eq(input),
        "empty mapAttrs result reused the input attrset instead of allocating"
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("mapAttrs result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "mapAttrs result should allocate exactly one permanent attrset"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("mapAttrs result attrset allocation safepoint records");
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
fn gc_stress_eval_root_zip_attrs_with_empty_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.zipAttrsWith (_name: values: values) []");
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
        .expect("GC-stress zipAttrsWith evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated zipAttrsWith attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("zipAttrsWith result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "zipAttrsWith evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("zipAttrsWith result attrset allocation safepoint records");
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
fn gc_stress_eval_root_list_to_attrs_empty_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.listToAttrs []");
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
        .expect("GC-stress listToAttrs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated listToAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("listToAttrs result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "listToAttrs evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("listToAttrs result attrset allocation safepoint records");
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
fn gc_stress_eval_root_group_by_empty_result_skips_primop_composite_dispatch() {
    let ir = lower(r#"builtins.groupBy (_value: "group") []"#);
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
        .expect("GC-stress groupBy evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated groupBy attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("groupBy result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "groupBy evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("groupBy result attrset allocation safepoint records");
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
fn gc_stress_eval_root_function_args_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.functionArgs ({ a, b ? (1 / 0) }: a)");
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
        .expect("GC-stress functionArgs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated functionArgs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let a_key = evaluator.symbols.intern(b"a").expect("a key interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("functionArgs result is heap-owned");
    assert_eq!(attrs.len(), 2);
    assert_eq!(
        attrs.get(a_key).expect("a attr exists").as_bool(),
        Ok(false)
    );
    assert_eq!(attrs.get(b_key).expect("b attr exists").as_bool(), Ok(true));
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "functionArgs evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("functionArgs result attrset allocation safepoint records");
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
fn gc_stress_eval_root_serializer_scalar_results_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches("builtins.toJSON 123", b"123");
    assert_gc_stress_root_string_result_dispatches(
        "builtins.toXML 1",
        b"<?xml version='1.0' encoding='utf-8'?>\n<expr>\n  <int value=\"1\" />\n</expr>\n",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_json_array_result_dispatches_permanent_noop_bridge() {
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
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_json(
                ir.root,
                span,
                JsonValue::Array(vec![
                    JsonValue::Number(JsonNumber::from(1)),
                    JsonValue::Bool(true),
                    JsonValue::Null,
                ]),
            )
        })
        .expect("JSON array list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating JSON array list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("JSON array list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("JSON array result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first JSON value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second JSON value exists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        list.get(2).expect("third JSON value exists").as_null(),
        Ok(())
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("JSON array list allocation safepoint records");
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

#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_toml_array_result_dispatches_permanent_noop_bridge() {
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
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_toml(
                ir.root,
                span,
                TomlValue::Array(vec![
                    TomlValue::Integer(1),
                    TomlValue::Boolean(true),
                    TomlValue::Float(2.5),
                ]),
            )
        })
        .expect("TOML array list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating TOML array list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("TOML array list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("TOML array result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first TOML value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second TOML value exists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        list.get(2)
            .expect("third TOML value exists")
            .as_float()
            .map(f64::to_bits),
        Ok(2.5f64.to_bits())
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("TOML array list allocation safepoint records");
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
fn gc_stress_json_empty_object_result_skips_primop_composite_dispatch() {
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
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_json(ir.root, span, JsonValue::Object(serde_json::Map::new()))
        })
        .expect("JSON empty object attrset allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated JSON object attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("JSON object attrset generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("JSON object result is heap-owned");
    assert_eq!(attrs.len(), 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("JSON object attrset allocation safepoint records");
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
fn gc_stress_toml_empty_table_result_skips_primop_composite_dispatch() {
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
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_toml(ir.root, span, TomlValue::Table(Default::default()))
        })
        .expect("TOML empty table attrset allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated TOML table attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("TOML table attrset generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("TOML table result is heap-owned");
    assert_eq!(attrs.len(), 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("TOML table attrset allocation safepoint records");
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
fn gc_stress_eval_root_codec_empty_attrset_results_skip_argument_node_dispatch() {
    for (source, name) in [
        (r#"builtins.fromJSON "{}""#, "fromJSON"),
        (r#"builtins.fromTOML """#, "fromTOML"),
    ] {
        let ir = lower(source);
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
        let permanent_safepoints_before =
            evaluator.heap().permanent_allocation_safepoints().count();

        let value = evaluator
            .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
            .expect("GC-stress codec primop evaluates");

        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert!(
            roots[0].raw_eq(local_source),
            "registered root relocated while {name} result allocation used a non-root argument id"
        );
        assert_eq!(roots[0].tag(), ValueTag::Thunk);
        assert_eq!(value.tag(), ValueTag::Attrs);
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("codec result is heap-owned");
        assert_eq!(attrs.len(), 0);
        assert!(
            evaluator.heap().permanent_allocation_safepoints().count()
                > permanent_safepoints_before,
            "{name} evaluation should record permanent allocations"
        );
        let permanent_safepoint = evaluator
            .heap()
            .permanent_allocation_safepoints()
            .last()
            .expect("codec result attrset allocation safepoint records");
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
}

