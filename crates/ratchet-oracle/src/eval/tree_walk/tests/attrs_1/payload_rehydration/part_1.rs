//! Split-out tests (part_1). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_context_free_payload_replay_string_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let payload = CachedExpressionValue::context_free_string(b"cached string".to_vec());
    let subject = replay_allocation_subject(ir.root, b"gc-stress-context-free-replay-string");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("context-free payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached string payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed string generation is known"),
        HeapGeneration::Permanent
    );
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("replayed value is a string");
    assert_eq!(string.bytes(), b"cached string");
    assert!(!string.has_context());
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocString],
        "context-free string payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay string allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_context_payload_replay_string_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("opaque context path is valid"),
    )
    .expect("string context builds");
    let payload =
        CachedExpressionValue::context_string(b"context string".to_vec(), context.clone());
    let subject = replay_allocation_subject(ir.root, b"gc-stress-context-replay-string");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("context payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached context string payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed context string generation is known"),
        HeapGeneration::Permanent
    );
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("replayed value is a string");
    assert_eq!(string.bytes(), b"context string");
    assert!(string.has_context());
    assert_eq!(string.context(), &context);
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocString],
        "context string payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay context string allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_context_free_payload_replay_path_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let payload = CachedExpressionValue::path(b"/tmp/cached-path".to_vec());
    let subject = replay_allocation_subject(ir.root, b"gc-stress-context-free-replay-path");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("context-free path payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached path payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Path);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed path generation is known"),
        HeapGeneration::Permanent
    );
    let path = evaluator
        .heap()
        .get_path(value)
        .expect("replayed value is a path");
    assert_eq!(path.bytes(), b"/tmp/cached-path");
    assert!(!path.has_context());
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocString],
        "context-free path payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay path allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_context_payload_replay_path_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("opaque context path is valid"),
    )
    .expect("path context builds");
    let payload =
        CachedExpressionValue::context_path(b"/nix/store/context-path".to_vec(), context.clone());
    let subject = replay_allocation_subject(ir.root, b"gc-stress-context-replay-path");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("context path payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached context path payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Path);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed context path generation is known"),
        HeapGeneration::Permanent
    );
    let path = evaluator
        .heap()
        .get_path(value)
        .expect("replayed value is a path");
    assert_eq!(path.bytes(), b"/nix/store/context-path");
    assert!(path.has_context());
    assert_eq!(path.context(), &context);
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocString],
        "context path payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay context path allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_empty_payload_replay_list_dispatches_permanent_noop_bridge() {
    let ir = lower("[ ]");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let payload = CachedExpressionValue::empty_list();
    let subject = replay_allocation_subject(ir.root, b"gc-stress-empty-replay-list");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("empty list payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached empty list payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed empty list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("replayed value is a list");
    assert!(list.is_empty());
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocList],
        "empty list payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay empty list allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_strict_payload_replay_list_dispatches_permanent_noop_bridge() {
    let ir = lower("[ 1 ]");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let payload = CachedExpressionValue::strict_list(vec![
        CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
        CachedExpressionValue::immediate(Value::bool(true)).expect("bool payload builds"),
    ]);
    let subject = replay_allocation_subject(ir.root, b"gc-stress-strict-replay-list");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("strict list payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached strict list payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed strict list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("replayed value is a list");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.get(0).expect("first list element exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second list element exists").as_bool(),
        Ok(true)
    );
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocList],
        "strict list payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay strict list allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_empty_payload_replay_attrs_dispatches_permanent_noop_bridge() {
    let ir = lower("{ }");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let payload = CachedExpressionValue::empty_attrs();
    let subject = replay_allocation_subject(ir.root, b"gc-stress-empty-replay-attrs");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("empty attrset payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached empty attrset payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed empty attrs generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("replayed value is an attrset");
    assert!(attrs.is_empty());
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocAttrs],
        "empty attrset payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay empty attrs allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_strict_payload_replay_attrs_dispatches_permanent_noop_bridge() {
    let ir = lower("{ a = 1; b = 2; }");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let payload = CachedExpressionValue::strict_attrs(vec![
        (
            b"a".to_vec(),
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
        ),
        (
            b"b".to_vec(),
            CachedExpressionValue::immediate(Value::bool(true)).expect("bool payload builds"),
        ),
    ])
    .expect("attr payload builds");
    let subject = replay_allocation_subject(ir.root, b"gc-stress-strict-replay-attrs");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("strict attrset payload replay allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while replaying cached strict attrset payload"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed strict attrs generation is known"),
        HeapGeneration::Permanent
    );
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("replayed value is an attrset");
    assert_eq!(attrs.get(a).expect("a binding exists").as_int(), Ok(1));
    assert_eq!(attrs.get(b).expect("b binding exists").as_bool(), Ok(true));
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[RuntimeAllocationEntryPoint::AosAllocAttrs],
        "strict attrset payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay strict attrs allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
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
fn gc_stress_payload_replay_attrs_skip_non_attrset_origin_dispatch() {
    let ir = lower("[ ]");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let payload = CachedExpressionValue::empty_attrs();
    let subject = replay_allocation_subject(ir.root, b"gc-stress-non-attr-origin-replay-attrs");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_for_cached_expression_payload_for_subject(payload, &subject)
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id: ir.root }, span)
                })
        })
        .expect("attrset payload replay allocates with non-attrset origin");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root was relocated despite non-attrset replay origin gate"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(
        evaluator
            .heap()
            .generation(roots[0])
            .expect("registered root generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("replayed attrs generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("replayed value is an attrset");
    assert!(attrs.is_empty());
    assert_replay_permanent_allocation_shape(
        &evaluator,
        permanent_safepoints_before,
        permanent_dispatches_before,
        1,
        &[],
        "non-attrset-origin attrset payload replay",
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("payload replay attrs allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

