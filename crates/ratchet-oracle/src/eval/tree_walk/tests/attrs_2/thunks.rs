//! Thunk and strictness tests for tree-walk attr evaluation.

use super::*;
use crate::attrs::repr::AttrSetReprKind;
use crate::attrs::telemetry::{HistogramBucket, ShapeMultiplicityBucket};
use crate::eval::heap::EvalThunkForceStorageMode;
use crate::heap::{GcHeapAddress, HeapGeneration};
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

fn heap_record_forwarding_slot_count(heap: &EvalHeap, values: &[Value]) -> usize {
    values
        .iter()
        .filter(|value| {
            heap.minor_gc_forwarding_value_at(gc_address(**value))
                .expect("forwarding slot lookup succeeds")
                .is_some()
        })
        .count()
}

#[test]
fn shared_thunks_emit_trace_once_when_forced_repeatedly() {
    for (source, expected) in [
        (
            "let x = builtins.trace \"let\" 1; in x + x",
            &b"trace: let\n"[..],
        ),
        (
            "(x: x + x) (builtins.trace \"arg\" 1)",
            &b"trace: arg\n"[..],
        ),
        (
            "let xs = [ (builtins.trace \"list\" 1) ]; in (builtins.elemAt xs 0) + (builtins.elemAt xs 0)",
            &b"trace: list\n"[..],
        ),
        (
            "let set = { x = builtins.trace \"attr\" 1; }; in set.x + set.x",
            &b"trace: attr\n"[..],
        ),
    ] {
        let ir = lower(source);
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.capture_stderr();
        let value = evaluator
            .eval_root()
            .expect("shared thunk expression evaluates");
        assert_eq!(value.as_int(), Ok(2), "{source}");
        let stderr = evaluator.captured_stderr();
        assert_eq!(stderr, expected, "{source}");
    }
}

#[test]
fn failed_thunks_reset_and_are_retried() {
    let source = "let x = builtins.trace \"retry\" (builtins.throw \"boom\"); \
                      a = builtins.tryEval x; \
                      b = builtins.tryEval x; \
                      in if a.success == false && b.success == false then 1 else 0";
    let ir = lower(source);
    let mut evaluator = TreeWalk::new(&ir);
    evaluator.capture_stderr();
    let value = evaluator
        .eval_root()
        .expect("tryEval catches both failed thunk forces");
    assert_eq!(value.as_int(), Ok(1));
    let stderr = evaluator.captured_stderr();
    assert_eq!(stderr, b"trace: retry\ntrace: retry\n");
}

#[test]
fn strict_operand_evaluation_forces_direct_thunk_alloc_results() {
    let body = IrId::new(0);
    let lhs = IrId::new(1);
    let rhs = IrId::new(2);
    let root = IrId::new(3);
    let ir = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(IrKind::ThunkAlloc, Span::new(0, 1), IrData::Node(body)),
            pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(2)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 5),
                IrData::Binary {
                    op: BinOpKind::Add,
                    lhs,
                    rhs,
                },
            ),
        ],
    );

    assert_eq!(
        eval_whnf(&ir)
            .expect("strict operand thunk is forced")
            .as_int(),
        Ok(3)
    );
}

fn first_thunk_alloc_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .position(|node| node.kind == IrKind::ThunkAlloc)
        .map(|index| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        .expect("test IR contains a thunk allocation")
}

fn first_inherit_select_thunk_alloc_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            let IrData::Node(body) = node.data else {
                return None;
            };
            let body = ir.arena.node(body)?;
            (node.kind == IrKind::ThunkAlloc && body.kind == IrKind::Select)
                .then(|| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        })
        .expect("test IR contains an inherited select thunk")
}

fn mark_all_thunk_allocs_strict(ir: &mut Ir) {
    let thunk_ids: Vec<IrId> = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (node.kind == IrKind::ThunkAlloc)
                .then(|| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        })
        .collect();
    for id in thunk_ids {
        *ir.facts.get_mut(id).expect("thunk fact exists") = crate::compile::ExprFacts {
            strictness: crate::compile::Strictness::DemandedBeforeEffect,
            cardinality: crate::compile::Cardinality::Many,
            escape: crate::compile::Escape::Escapes,
        };
    }
}

#[test]
fn conservative_thunk_alloc_facts_keep_lazy_thunks() {
    let ir = lower("[ (1 + 6) ]");

    let outcome = eval_whnf_owned(&ir).expect("conservative thunk alloc evaluates");
    let element = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };

    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().thunks_elided(), 0);
    let thunk = outcome
        .heap()
        .get_thunk(element)
        .expect("element is a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn gc_stress_list_element_thunk_allocation_dispatches_reserved_forwarding_bridge() {
    let ir = lower("[ (1 + 6) ]");
    let default_outcome = eval_whnf_owned(&ir).expect("default thunk alloc evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress thunk alloc evaluates");
    let element = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };

    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(
        outcome
            .heap()
            .generation(element)
            .expect("element generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().thunks_elided(), 0);
    let thunk = outcome
        .heap()
        .get_thunk(element)
        .expect("element is a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    let thunk_values = outcome
        .heap()
        .test_record_values()
        .map(|value| value.expect("heap record value rebuilds"))
        .filter(|value| value.tag() == ValueTag::Thunk)
        .collect::<Vec<_>>();
    assert!(thunk_values.iter().any(|value| value.raw_eq(element)));
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) >= 1);

    assert!(
        outcome.heap().allocation_safepoints().count()
            > default_outcome.heap().allocation_safepoints().count()
    );
    let final_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("final thunk allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

#[test]
fn single_entry_thunk_plan_uses_direct_force_storage_without_parallel_payload_or_cache_publish() {
    let mut ir = lower("[ (1 + 6) ]");
    let thunk_alloc = first_thunk_alloc_id(&ir);
    let thunk_span = ir
        .arena
        .node(thunk_alloc)
        .expect("thunk alloc node exists")
        .span;
    *ir.facts.get_mut(thunk_alloc).expect("thunk fact exists") = crate::compile::ExprFacts {
        strictness: crate::compile::Strictness::Unknown,
        cardinality: crate::compile::Cardinality::Once,
        escape: crate::compile::Escape::NoEscape,
    };

    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );
    let value = evaluator
        .eval_root()
        .expect("single-entry thunk alloc evaluates");
    let element = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };

    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(evaluator.stats().thunks_allocated(), 1);
    assert_eq!(evaluator.stats().thunks_elided(), 0);
    {
        let thunk = evaluator
            .heap()
            .get_thunk(element)
            .expect("element is a heap-owned thunk");
        assert_eq!(
            thunk.force_storage_mode(),
            EvalThunkForceStorageMode::SingleEntry
        );
        assert!(thunk.parallel_payload_cell().is_none());
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    }

    let forced = evaluator
        .force_value(thunk_alloc, thunk_span, element)
        .expect("single-entry thunk forces directly");
    assert_eq!(forced.as_int(), Ok(7));
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);

    let thunk = evaluator
        .heap()
        .get_thunk(element)
        .expect("element remains a heap-owned thunk");
    assert_eq!(
        thunk.force_storage_mode(),
        EvalThunkForceStorageMode::SingleEntry
    );
    assert!(thunk.parallel_payload_cell().is_none());
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn analyzer_produced_direct_body_let_thunk_uses_single_entry_storage() {
    let mut ir = lower("let x = 1 + 6; in x");
    let thunk_alloc = first_thunk_alloc_id(&ir);
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let facts = ir
        .facts
        .get(thunk_alloc)
        .expect("analyzed thunk fact exists");
    assert_eq!(
        facts.cardinality,
        crate::compile::Cardinality::Once,
        "direct body use proves single entry"
    );
    assert_eq!(
        facts.escape,
        crate::compile::Escape::NoEscape,
        "direct body use proves frame locality"
    );
    assert_eq!(
        facts.strictness,
        crate::compile::Strictness::Demanded,
        "the demanded slot earns the S1 fan-out hint, which keeps the thunk lazy"
    );

    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );
    let value = evaluator
        .eval_root()
        .expect("annotated direct-body let evaluates");

    assert_eq!(value.as_int(), Ok(7));
    assert_eq!(evaluator.stats().thunks_allocated(), 1);
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);
    let thunk_values = evaluator
        .heap()
        .test_record_values()
        .map(|value| value.expect("heap record value rebuilds"))
        .filter(|value| value.tag() == ValueTag::Thunk)
        .collect::<Vec<_>>();
    assert_eq!(thunk_values.len(), 1);
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_values[0])
        .expect("let binding thunk remains allocated");
    assert_eq!(
        thunk.force_storage_mode(),
        EvalThunkForceStorageMode::SingleEntry
    );
    assert!(thunk.parallel_payload_cell().is_none());
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn single_entry_thunk_force_errors_leave_compatibility_cell_suspended() {
    let mut ir = lower("[ (1 / 0) ]");
    let thunk_alloc = first_thunk_alloc_id(&ir);
    let thunk_span = ir
        .arena
        .node(thunk_alloc)
        .expect("thunk alloc node exists")
        .span;
    *ir.facts.get_mut(thunk_alloc).expect("thunk fact exists") = crate::compile::ExprFacts {
        strictness: crate::compile::Strictness::Unknown,
        cardinality: crate::compile::Cardinality::Once,
        escape: crate::compile::Escape::NoEscape,
    };

    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options.set_parallel_thunk_payloads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator
        .eval_root()
        .expect("single-entry throwing thunk list allocates");
    let element = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };

    let error = evaluator
        .force_value(thunk_alloc, thunk_span, element)
        .expect_err("single-entry thunk body throws");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);

    let thunk = evaluator
        .heap()
        .get_thunk(element)
        .expect("element remains a heap-owned thunk");
    assert_eq!(
        thunk.force_storage_mode(),
        EvalThunkForceStorageMode::SingleEntry
    );
    assert!(thunk.parallel_payload_cell().is_none());
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn demanded_absent_thunk_plan_currently_allocates_update_storage() {
    let mut ir = lower("[ (1 + 6) ]");
    let thunk_alloc = first_thunk_alloc_id(&ir);
    *ir.facts.get_mut(thunk_alloc).expect("thunk fact exists") = crate::compile::ExprFacts {
        strictness: crate::compile::Strictness::Unknown,
        cardinality: crate::compile::Cardinality::Absent,
        escape: crate::compile::Escape::NoEscape,
    };

    let outcome = eval_whnf_owned(&ir).expect("absent demanded thunk alloc evaluates");
    let element = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };

    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().thunks_elided(), 0);
    let thunk = outcome
        .heap()
        .get_thunk(element)
        .expect("element is a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn demanded_thunk_allocation_rejects_missing_fact_records() {
    let mut ir = lower("[ (1 + 6) ]");
    let thunk_alloc = first_thunk_alloc_id(&ir);
    ir.facts = IrFacts::conservative(thunk_alloc.index());

    let error = eval_whnf_owned(&ir).expect_err("missing thunk facts reject");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::ThunkAllocation {
            id: thunk_alloc,
            source: crate::eval::TreeWalkThunkAllocationError::Downgrade(
                crate::compile::FrameLocalThunkDowngradeError::MissingFact { id: thunk_alloc },
            ),
        }
    );
}

#[test]
fn strict_thunk_alloc_facts_evaluate_eagerly() {
    for (escape, label) in [
        (crate::compile::Escape::Escapes, "eager"),
        (crate::compile::Escape::NoEscape, "scalar"),
    ] {
        let mut ir = lower("[ (1 + 6) ]");
        let thunk_alloc = first_thunk_alloc_id(&ir);
        *ir.facts.get_mut(thunk_alloc).expect("thunk fact exists") = crate::compile::ExprFacts {
            strictness: crate::compile::Strictness::DemandedBeforeEffect,
            cardinality: crate::compile::Cardinality::Many,
            escape,
        };

        let outcome = eval_whnf_owned(&ir).expect("strict thunk alloc evaluates");
        let element = {
            let list = outcome
                .heap()
                .get_list(outcome.value())
                .expect("root is a heap-owned list");
            list.get(0).expect("element exists")
        };

        assert_eq!(element.as_int(), Ok(7), "{label}");
        assert_eq!(outcome.stats().thunks_allocated(), 0, "{label}");
        assert_eq!(outcome.stats().thunks_elided(), 1, "{label}");
    }
}

#[test]
fn strictness_analysis_elides_direct_lambda_argument_thunk() {
    let mut ir = lower("(x: x + 1) (1 + 2)");
    crate::compile::annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    let outcome = eval_whnf_owned(&ir).expect("annotated direct lambda evaluates");

    assert_eq!(outcome.value().as_int(), Ok(4));
    assert_eq!(outcome.stats().thunks_allocated(), 0);
    assert_eq!(outcome.stats().thunks_elided(), 1);
}

#[test]
fn strictness_analysis_elides_direct_formal_set_argument_thunk() {
    let mut ir = lower("({}: 1) {}");
    crate::compile::annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    let outcome = eval_whnf_owned(&ir).expect("annotated formal-set lambda evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.stats().thunks_allocated(), 0);
    assert_eq!(outcome.stats().thunks_elided(), 1);
}

#[test]
fn strictness_analysis_keeps_foldl_empty_initial_accumulator_lazy() {
    let mut ir = lower(r#"builtins.foldl' (acc: x: acc + x) (builtins.throw "initial") []"#);
    crate::compile::annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    let outcome = eval_whnf_owned(&ir).expect("annotated empty foldl' evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

#[test]
fn attr_update_records_active_merge_telemetry() {
    let ir = lower("(({ a = 1; } // { b = 2; a = 3; }) // { c = 4; }).c");

    let outcome = eval_whnf_owned(&ir).expect("nested attr update evaluates");

    assert_eq!(outcome.value().as_int(), Ok(4));
    assert_eq!(outcome.stats().shape_transitions(), 6);
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 5);
    assert_eq!(snapshot.flat_decisions, 5);
    assert_eq!(snapshot.hamt_decisions, 0);
    assert_eq!(snapshot.update_merges, 2);
    assert_eq!(snapshot.flat_update_merges, 2);
    assert_eq!(snapshot.hamt_update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 3);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    assert_eq!(
        &*snapshot.left_len_distribution,
        &[
            HistogramBucket { value: 1, count: 1 },
            HistogramBucket { value: 2, count: 1 },
        ],
    );
    assert_eq!(
        &*snapshot.right_len_distribution,
        &[
            HistogramBucket { value: 1, count: 1 },
            HistogramBucket { value: 2, count: 1 },
        ],
    );
    assert_eq!(
        &*snapshot.result_len_upper_bound_distribution,
        &[HistogramBucket { value: 3, count: 2 }],
    );
    assert_eq!(
        &*snapshot.override_chain_depth_distribution,
        &[
            HistogramBucket { value: 1, count: 1 },
            HistogramBucket { value: 2, count: 1 },
        ],
    );

    let census = outcome
        .attr_telemetry()
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 5);
    assert_eq!(census.distinct_shapes, 5);
    let mut key_counts = census
        .shapes
        .iter()
        .map(|entry| entry.key_count)
        .collect::<Vec<_>>();
    key_counts.sort_unstable();
    assert_eq!(key_counts, vec![1, 1, 2, 2, 3],);
    assert_eq!(
        census.multiplicity.as_ref(),
        &[ShapeMultiplicityBucket {
            instances_per_shape: 1,
            shape_count: 5,
        }],
    );
}

#[test]
fn static_attrset_literals_record_repr_decision_telemetry() {
    let ir = lower(
        "builtins.deepSeq [
            { a = 1; }
            { b = 2; a = 3; }
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("static attrsets evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    assert_eq!(outcome.stats().shape_transitions(), 3);
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.hamt_decisions, 0);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 2);
    assert_eq!(snapshot.reasons.small_shape_stable, 0);
    assert!(snapshot.result_len_upper_bound_distribution.is_empty());

    let census = outcome
        .attr_telemetry()
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 2);
    assert_eq!(census.distinct_shapes, 2);
    assert_eq!(
        census
            .shapes
            .iter()
            .map(|entry| entry.key_count)
            .collect::<Vec<_>>(),
        vec![1, 2],
    );
    assert_eq!(
        census.multiplicity.as_ref(),
        &[ShapeMultiplicityBucket {
            instances_per_shape: 1,
            shape_count: 2,
        }],
    );
}

#[test]
fn dynamic_attrset_literals_record_dynamic_repr_decisions() {
    let ir = lower(r#"let name = "a"; in ({ ${name} = 1; }).a"#);

    let outcome = eval_whnf_owned(&ir).expect("dynamic attrset evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.stats().shape_transitions(), 1);
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);

    let census = outcome
        .attr_telemetry()
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 1);
    assert_eq!(census.distinct_shapes, 1);
    assert_eq!(census.shapes[0].key_count, 1);
}

#[test]
fn recursive_static_attrsets_record_static_repr_decisions() {
    let ir = lower("rec { a = 1; }.a");

    let outcome = eval_whnf_owned(&ir).expect("recursive static attrset evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 1);
}

#[test]
fn recursive_overrides_record_dynamic_repr_decisions() {
    let ir = lower(r#"let name = "a"; in rec { a = 1; __overrides = { ${name} = 2; }; }.a"#);

    let outcome = eval_whnf_owned(&ir).expect("recursive override attrset evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
}

#[test]
fn static_recursive_overrides_record_static_inner_and_dynamic_outer_decisions() {
    let ir = lower("rec { a = 1; __overrides = { a = 2; }; }.a");

    let outcome = eval_whnf_owned(&ir).expect("static recursive override attrset evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 1);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
}

#[test]
fn null_skipped_dynamic_attrsets_record_dynamic_repr_decisions() {
    let ir = lower("({ ${null} = 1; a = 2; }).a");

    let outcome = eval_whnf_owned(&ir).expect("null-skipped dynamic attrset evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
}

#[test]
fn large_dynamic_attrsets_record_projected_hamt_repr_decisions() {
    let bindings = (0..65)
        .map(|index| format!(r#""k{index}" = {index};"#))
        .collect::<Vec<_>>()
        .join(" ");
    let source = format!(r#"let key = "selected"; in {{ ${{key}} = 99; {bindings} }}.selected"#);
    let ir = lower(&source);

    let outcome = eval_whnf_owned(&ir).expect("large dynamic attrset evaluates");

    assert_eq!(outcome.value().as_int(), Ok(99));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 0);
    assert_eq!(snapshot.hamt_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.large_dynamic_construction, 1);
}

#[test]
fn large_dynamic_attrset_heap_metadata_records_hamt_repr() {
    let bindings = (0..65)
        .map(|index| format!(r#""k{index}" = {index};"#))
        .collect::<Vec<_>>()
        .join(" ");
    let source = format!(r#"let key = "selected"; in {{ ${{key}} = 99; {bindings} }}"#);
    let ir = lower(&source);
    let selected = symbol_for(&ir, b"selected");

    let outcome = eval_whnf_owned(&ir).expect("large dynamic attrset evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");
    let attrs = outcome
        .heap()
        .get_attrs(outcome.value())
        .expect("result attrs remain flat-readable");

    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
    assert_eq!(
        attrs.get(selected).expect("selected exists").as_int(),
        Ok(99)
    );
}

#[test]
fn hamt_classified_update_chain_attr_names_preserve_raw_byte_order() {
    let attrs_source =
        "(((({ z = 1; } // { A = 2; }) // { aa = 3; }) // { _ = 4; }) // { a = 5; })";
    let names_source = format!("builtins.attrNames {attrs_source}");

    assert_eq!(
        eval_list_string_bytes(&names_source),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );

    let ir = lower(attrs_source);
    let outcome = eval_whnf_owned(&ir).expect("HAMT-classified update chain evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");

    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
}

#[test]
fn list_to_attrs_records_dynamic_repr_decision() {
    let ir = lower(
        r#"builtins.deepSeq (builtins.listToAttrs [
            { name = "b"; value = 2; }
            { name = "a"; value = 1; }
        ]) 0"#,
    );

    let outcome = eval_whnf_owned(&ir).expect("listToAttrs evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    assert_eq!(outcome.stats().shape_transitions(), 4);
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 3);
    assert_eq!(snapshot.flat_decisions, 3);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 2);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);

    let census = outcome
        .attr_telemetry()
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 3);
    assert_eq!(census.distinct_shapes, 2);
    let mut key_counts = census
        .shapes
        .iter()
        .map(|entry| (entry.key_count, entry.instances))
        .collect::<Vec<_>>();
    key_counts.sort_unstable();
    assert_eq!(key_counts, vec![(2, 1), (2, 2)]);
}

#[test]
fn attr_filter_builtins_record_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.removeAttrs { a = 1; b = 2; } [ \"b\" ])
            (builtins.intersectAttrs { a = 0; } { a = 1; b = 2; })
            (let remove = builtins.removeAttrs { a = 1; b = 2; }; in remove [ \"b\" ])
            (let intersect = builtins.intersectAttrs { a = 0; }; in intersect { a = 1; b = 2; })
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("attr filter builtins evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 10);
    assert_eq!(snapshot.flat_decisions, 10);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 6);
    assert_eq!(snapshot.reasons.small_shape_stable, 4);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 4);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn map_attrs_records_dynamic_repr_decisions_for_empty_and_non_empty_results() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.mapAttrs (_name: value: value + 1) { a = 1; })
            (builtins.mapAttrs (_name: value: value) {})
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("mapAttrs evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 4);
    assert_eq!(snapshot.flat_decisions, 4);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 2);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn zip_attrs_with_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.zipAttrsWith (_name: values: values) [ { a = 1; } { b = 2; } ])
            (let zip = builtins.zipAttrsWith (_name: values: values); in zip [ { c = 3; } ])
            (builtins.zipAttrsWith (_name: values: values) [])
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("zipAttrsWith evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 6);
    assert_eq!(snapshot.flat_decisions, 6);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 3);
    assert_eq!(snapshot.reasons.small_shape_stable, 3);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 3);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn attr_position_builtins_record_dynamic_repr_decisions() {
    let source = "builtins.deepSeq [
            (builtins.unsafeGetAttrPos \"a\" { a = 1; })
            __curPos
        ] 0";

    let outcome = eval_owned_with_source(b"/source.nix", source);

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 3);
    assert_eq!(snapshot.flat_decisions, 3);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 1);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn partition_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.partition (value: value < 2) [ 1 2 ])
            (let partition = builtins.partition (value: value < 2); in partition [ 1 2 ])
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("partition evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn group_by_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.groupBy (value: if value < 2 then \"small\" else \"large\") [ 1 2 ])
            (let group = builtins.groupBy (value: \"all\"); in group [ 3 ])
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("groupBy evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn function_args_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.functionArgs ({ a, b ? 1 }: a))
            (let functionArgs = builtins.functionArgs; in functionArgs builtins.length)
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("functionArgs evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn codec_attrsets_record_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.fromJSON ''{\"a\":{\"b\":1}}'')
            (builtins.fromTOML \"a = 1\\n[nested]\\nb = 2\")
            (builtins.fromTOML \"a = 1979-05-27T07:32:00Z\")
        ] 0",
    );
    let options = TreeWalkOptions::with_parse_toml_timestamps(true);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("codec attrsets evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 6);
    assert_eq!(snapshot.flat_decisions, 6);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 6);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 6);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn path_surface_attrsets_record_dynamic_repr_decisions() {
    let root = unique_temp_dir("attr-telemetry-read-dir");
    fs::write(root.join("alpha"), b"alpha").expect("readDir fixture writes");
    let source = format!(
        "builtins.deepSeq [
            (builtins.parseDrvName \"pkg-1.0\")
            (builtins.readDir {})
            builtins.nixPath
        ] 0",
        nix_string_literal(&path_source(&root))
    );
    let options = search_path_options(b"nixpkgs", &root);
    let ir = lower(&source);

    let outcome =
        eval_whnf_owned_with_options(&ir, options).expect("path surface attrsets evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 3);
    assert_eq!(snapshot.flat_decisions, 3);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 3);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 3);
    assert_eq!(stats.mismatched, 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn try_eval_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.tryEval 1)
            (let tryEval = builtins.tryEval; in tryEval (builtins.throw \"boom\"))
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("tryEval results evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn get_context_records_dynamic_repr_decisions() {
    let ir = lower("builtins.getContext \"x\"");
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
        .expect("getContext argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let context = StringContext::new(vec![
        ContextElement::opaque_path(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src".to_vec())
            .expect("source context is valid"),
        ContextElement::single_output(
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv".to_vec(),
            b"out".to_vec(),
        )
        .expect("output context is valid"),
        ContextElement::deep_derivation(
            b"/nix/store/cccccccccccccccccccccccccccccccc-deep.drv".to_vec(),
        )
        .expect("deep context is valid"),
    ]);
    let value = evaluator
        .heap
        .alloc_string(NixString::new(b"x".to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_get_context_primop(ir.root, root.span, argument, argument_span, value)
        .expect("getContext evaluates");

    let attrs = evaluator
        .heap
        .get_attrs(result)
        .expect("getContext result is attrs");
    assert_eq!(attrs.len(), 3);
    let metadata = evaluator
        .heap
        .get_attrs_metadata(result)
        .expect("getContext result metadata exists");
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let keys = attrs
        .iter_lexicographic()
        .map(|entry| {
            evaluator
                .symbols
                .resolve(entry.key)
                .expect("getContext key resolves")
                .to_vec()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        vec![
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src".to_vec(),
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv".to_vec(),
            b"/nix/store/cccccccccccccccccccccccccccccccc-deep.drv".to_vec(),
        ],
    );
    let snapshot = evaluator
        .attr_telemetry
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 4);
    assert_eq!(snapshot.flat_decisions, 4);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 4);
    let stats = evaluator.attr_telemetry.order_parity_stats();
    assert_eq!(stats.matched, 4);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn active_flat_selects_record_slow_select_telemetry() {
    let ir = lower(
        "builtins.deepSeq [
            ({ a = 1; }).a
            (({}).missing or 2)
            ({ a = 1; } ? a)
            ({} ? missing)
            (with { a = 1; }; a)
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("active flat selects evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.hamt_hits, 0);
    assert_eq!(counts.hamt_misses, 0);
    assert_eq!(counts.shaped_hits, 3);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn repeated_static_select_site_uses_shaped_inline_cache_for_projected_flat_receivers() {
    let ir = lower("let f = x: x.a; in (f { a = 1; }) + (f { a = 2; })");

    let outcome = eval_whnf_owned(&ir).expect("repeated static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn repeated_static_select_site_uses_hamt_inline_cache_for_projected_hamt_receivers() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             select = x: x.f;
         in (select base) + (select base)",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(12));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.hamt_select_sites.distinguished_hamt, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.hamt_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.cached_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.hamt_hits, 2);
    assert_eq!(counts.hamt_misses, 0);
}

#[test]
fn repeated_static_select_site_separates_projected_shapes_with_different_slots() {
    let ir = lower("let seed = { a = 0; }; f = x: x.b; in (f { b = 1; }) + (f { a = 0; b = 2; })");

    let outcome = eval_whnf_owned(&ir).expect("shifted static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.polymorphic, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn polymorphic_static_select_defaults_keep_shaped_cache_after_missing_receiver() {
    let ir = lower(
        "let f = x: x.b or 10;
         in (f { b = 1; })
          + (f { a = 0; b = 2; })
          + (f { c = 0; })
          + (f { b = 3; })
          + (f { a = 0; b = 4; })
          + (f { c = 5; })",
    );

    let outcome = eval_whnf_owned(&ir).expect("polymorphic hit-miss-hit-miss select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(30));
    assert_eq!(outcome.stats().inline_cache_hits(), 2);
    assert_eq!(outcome.stats().inline_cache_misses(), 4);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.polymorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 4);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn projected_shaped_select_site_becomes_megamorphic_after_cap_overflow() {
    // The default shaped PIC cap is four entries; the fifth distinct projected
    // shape drives the active bridge into the megamorphic terminal state.
    let ir = lower(
        "let f = x: x.a;
         in (f { a = 1; })
          + (f { b = 0; a = 2; })
          + (f { c = 0; a = 3; })
          + (f { d = 0; a = 4; })
          + (f { e = 0; a = 5; })",
    );

    let outcome = eval_whnf_owned(&ir).expect("megamorphic projected-shaped select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(15));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 5);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.megamorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.megamorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 5);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 5);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.shaped_hits, 5);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn megamorphic_static_select_defaults_stay_slow_after_missing_receivers() {
    let ir = lower(
        "let f = x: x.a or 10;
         in (f { a = 1; })
          + (f { b = 0; a = 2; })
          + (f { c = 0; a = 3; })
          + (f { d = 0; a = 4; })
          + (f { e = 0; a = 5; })
          + (f { missing = 0; })
          + (f { missing = 1; })
          + (f { a = 6; })",
    );

    let outcome = eval_whnf_owned(&ir).expect("megamorphic hit-miss-hit select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(41));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 8);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.megamorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.megamorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 6);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 6);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 6);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn repeated_static_select_defaults_preserve_hit_then_miss_semantics() {
    let ir = lower("let f = x: x.a or 10; in (f { a = 1; }) + (f {})");

    let outcome = eval_whnf_owned(&ir).expect("hit-then-miss default select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(11));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_select_defaults_keep_shaped_cache_after_missing_receiver() {
    let ir = lower("let f = x: x.a or 10; in (f { a = 1; }) + (f { b = 2; }) + (f { a = 3; })");

    let outcome = eval_whnf_owned(&ir).expect("hit-miss-hit default select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(14));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_select_defaults_preserve_miss_then_hit_semantics() {
    let ir = lower("let f = x: x.a or 10; in (f {}) + (f { a = 2; })");

    let outcome = eval_whnf_owned(&ir).expect("miss-then-hit default select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(12));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_select_defaults_use_hamt_inline_cache_for_projected_hamt_misses() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             select = x: x.missing or 10;
         in (select base) + (select base)",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT static select misses");

    assert_eq!(outcome.value().as_int(), Ok(20));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.hamt_select_sites.distinguished_hamt, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.hamt_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.cached_misses, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.hamt_hits, 0);
    assert_eq!(counts.hamt_misses, 2);
}

#[test]
fn dynamic_select_site_stays_on_slow_select_path() {
    let ir = lower(r#"let f = name: set: set.${name}; in (f "a" { a = 1; }) + (f "b" { b = 2; })"#);

    let outcome = eval_whnf_owned(&ir).expect("repeated dynamic select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 0);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 2);
    assert_eq!(counts.flat_misses, 0);
}

#[test]
fn multi_segment_static_select_caches_each_path_index_separately() {
    let ir = lower("let f = x: x.a.b; in (f { a = { b = 1; }; }) + (f { a = { b = 2; }; })");

    let outcome = eval_whnf_owned(&ir).expect("multi-segment static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 2);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 2);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn repeated_static_has_attr_site_uses_shaped_inline_cache_for_projected_flat_receivers() {
    let ir = lower("let f = x: x ? a; in if (f { a = 1; }) && (f { a = 2; }) then 1 else 0");

    let outcome = eval_whnf_owned(&ir).expect("repeated static hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn repeated_static_has_attr_site_keeps_shaped_cache_after_missing_receiver() {
    let ir = lower(
        "let f = x: x ? a;
         in if (f { a = 1; })
            then if (f { b = 2; })
                 then 0
                 else if (f { a = 3; }) then 1 else 0
            else 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("hit-miss-hit static hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_has_attr_site_keeps_projected_shaped_misses_uncached() {
    let ir = lower("let f = x: x ? missing; in if (f {}) || (f {}) then 1 else 0");

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-shaped hasAttr misses");

    assert_eq!(outcome.value().as_int(), Ok(0));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.uninitialized, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 0);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn polymorphic_static_has_attr_keeps_shaped_cache_after_missing_receivers() {
    let ir = lower(
        "let f = x: x ? b;
         in (if (f { b = 1; }) then 1 else 0)
          + (if (f { a = 0; b = 2; }) then 2 else 0)
          + (if (f { c = 0; }) then 0 else 4)
          + (if (f { c = 1; }) then 0 else 8)
          + (if (f { b = 3; }) then 16 else 0)
          + (if (f { a = 0; b = 4; }) then 32 else 0)",
    );

    let outcome = eval_whnf_owned(&ir).expect("polymorphic hit-miss-hit-miss hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(63));
    assert_eq!(outcome.stats().inline_cache_hits(), 2);
    assert_eq!(outcome.stats().inline_cache_misses(), 4);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.polymorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 4);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn megamorphic_static_has_attr_stays_slow_after_missing_receivers() {
    let ir = lower(
        "let f = x: x ? a;
         in (if (f { a = 1; }) then 1 else 0)
          + (if (f { b = 0; a = 2; }) then 2 else 0)
          + (if (f { c = 0; a = 3; }) then 3 else 0)
          + (if (f { d = 0; a = 4; }) then 4 else 0)
          + (if (f { e = 0; a = 5; }) then 5 else 0)
          + (if (f { missing = 0; }) then 0 else 10)
          + (if (f { missing = 1; }) then 0 else 20)
          + (if (f { a = 6; }) then 6 else 0)",
    );

    let outcome = eval_whnf_owned(&ir).expect("megamorphic hit-miss-hit hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(51));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 8);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.megamorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.megamorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 6);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 6);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 6);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn repeated_static_has_attr_site_uses_hamt_inline_cache_for_projected_hamt_receivers() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             has = x: x ? f;
         in if (has base) && (has base) then 1 else 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.hamt_select_sites.distinguished_hamt, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.hamt_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.cached_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.hamt_hits, 2);
    assert_eq!(counts.hamt_misses, 0);
}

#[test]
fn repeated_static_has_attr_site_uses_hamt_inline_cache_for_projected_hamt_misses() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             has = x: x ? missing;
         in if (has base) || (has base) then 1 else 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT hasAttr misses");

    assert_eq!(outcome.value().as_int(), Ok(0));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.hamt_select_sites.distinguished_hamt, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.hamt_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.cached_misses, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.hamt_hits, 0);
    assert_eq!(counts.hamt_misses, 2);
}

#[test]
fn attr_update_telemetry_tracks_projected_hamt_left_state() {
    let ir = lower(
        "((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; }).f",
    );

    let outcome = eval_whnf_owned(&ir).expect("deep attr update chain evaluates");

    assert_eq!(outcome.value().as_int(), Ok(6));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 11);
    assert_eq!(snapshot.flat_decisions, 9);
    assert_eq!(snapshot.hamt_decisions, 2);
    assert_eq!(snapshot.update_merges, 5);
    assert_eq!(snapshot.flat_update_merges, 3);
    assert_eq!(snapshot.hamt_update_merges, 2);
    assert_eq!(snapshot.hamt_inserted, 2);
    assert_eq!(snapshot.hamt_replaced, 0);
    assert_eq!(snapshot.reasons.static_literal, 6);
    assert_eq!(snapshot.reasons.small_shape_stable, 3);
    assert_eq!(snapshot.reasons.deep_override_chain, 1);
    assert_eq!(snapshot.reasons.left_already_hamt, 1);
}

#[test]
fn attr_update_heap_metadata_records_projected_hamt_repr() {
    let ir = lower(
        "((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; })",
    );
    let f = symbol_for(&ir, b"f");

    let outcome = eval_whnf_owned(&ir).expect("deep attr update chain evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");
    let attrs = outcome
        .heap()
        .get_attrs(outcome.value())
        .expect("result attrs remain flat-readable");

    assert_eq!(metadata.shape(), 0);
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
    assert_eq!(attrs.get(f).expect("f exists").as_int(), Ok(6));
}

#[test]
fn static_attrset_heap_metadata_records_projected_shape() {
    let ir = lower("{ b = 2; a = 1; }");

    let outcome = eval_whnf_owned(&ir).expect("static attrset evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");

    assert_eq!(metadata.shape(), 0);
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let census = outcome
        .attr_telemetry()
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 1);
    assert_eq!(census.shapes.len(), 1);
    assert_eq!(census.shapes[0].key_count, 2);
}

#[test]
fn projected_shape_static_attr_names_and_values_preserve_raw_byte_order() {
    let attrs_source = "{ z = 1; A = 2; aa = 3; _ = 4; a = 5; }";
    let names_source = format!("builtins.attrNames {attrs_source}");
    let values_source = format!("builtins.attrValues {attrs_source}");

    assert_eq!(
        eval_list_string_bytes(&names_source),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(eval_list_ints(&values_source), vec![2, 4, 5, 3, 1]);

    let ir = lower(attrs_source);
    let outcome = eval_whnf_owned(&ir).expect("projected-shape static attrset evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
}

#[test]
fn attr_names_and_values_record_projected_shape_order_parity_telemetry() {
    let ir = lower(
        "
        let attrs = { z = 1; A = 2; aa = 3; _ = 4; a = 5; };
        in builtins.length (builtins.attrNames attrs)
           + builtins.length (builtins.attrValues attrs)
        ",
    );
    let outcome = eval_whnf_owned(&ir).expect("attr order-parity sample evaluates");

    assert_eq!(outcome.value().as_int(), Ok(10));
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn map_attrs_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let attrs_source = "{ z = 1; A = 2; aa = 3; _ = 4; a = 5; }";
    let names_source =
        format!("builtins.attrNames (builtins.mapAttrs (_name: value: value + 1) {attrs_source})");
    let values_source = format!(
        "builtins.concatStringsSep \",\" \
         (builtins.attrValues (builtins.mapAttrs (name: _value: name) {attrs_source}))"
    );

    let expected_order = vec![
        b"A".to_vec(),
        b"_".to_vec(),
        b"a".to_vec(),
        b"aa".to_vec(),
        b"z".to_vec(),
    ];
    assert_eq!(eval_list_string_bytes(&names_source), expected_order);
    assert_eq!(eval_string_bytes(&values_source), b"A,_,a,aa,z");

    let ir = lower(&format!(
        "builtins.mapAttrs (_name: value: value + 1) {attrs_source}"
    ));
    let outcome = eval_whnf_owned(&ir).expect("mapAttrs projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("mapAttrs result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn zip_attrs_with_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let zip_source = r#"
        builtins.zipAttrsWith
          (name: values: name + ":" + builtins.toString (builtins.length values))
          [ { z = 1; A = 2; } { aa = 3; _ = 4; a = 5; A = 6; } ]
    "#;
    let names_source = format!("builtins.attrNames ({zip_source})");
    let values_source =
        format!("builtins.concatStringsSep \",\" (builtins.attrValues ({zip_source}))");

    assert_eq!(
        eval_list_string_bytes(&names_source),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(eval_string_bytes(&values_source), b"A:2,_:1,a:1,aa:1,z:1");

    let ir = lower(zip_source);
    let outcome = eval_whnf_owned(&ir).expect("zipAttrsWith projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("zipAttrsWith result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn attr_filter_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let attrs_source = "{ z = 1; A = 2; aa = 3; _ = 4; a = 5; }";
    let remove_source = format!("builtins.removeAttrs {attrs_source} [ \"aa\" ]");
    let intersect_source =
        format!("builtins.intersectAttrs {{ _ = 0; z = 0; A = 0; missing = 0; }} {attrs_source}");

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({remove_source})")),
        vec![b"A".to_vec(), b"_".to_vec(), b"a".to_vec(), b"z".to_vec()],
    );
    assert_eq!(
        eval_list_ints(&format!("builtins.attrValues ({remove_source})")),
        vec![2, 4, 5, 1],
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({intersect_source})")),
        vec![b"A".to_vec(), b"_".to_vec(), b"z".to_vec()],
    );
    assert_eq!(
        eval_list_ints(&format!("builtins.attrValues ({intersect_source})")),
        vec![2, 4, 1],
    );

    for source in [remove_source, intersect_source] {
        let ir = lower(&source);
        let outcome = eval_whnf_owned(&ir).expect("attr filter result evaluates");
        let metadata = outcome
            .heap()
            .get_attrs_metadata(outcome.value())
            .expect("attr filter result metadata exists");

        assert!(metadata.projected_shape().is_some());
        assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
        let stats = outcome.attr_telemetry().order_parity_stats();
        assert_eq!(stats.matched, 1, "{source}");
        assert_eq!(stats.mismatched, 0, "{source}");
    }
}

#[test]
fn partition_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let source = "builtins.partition (value: value < 3) [ 3 1 2 4 ]";

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
        vec![b"right".to_vec(), b"wrong".to_vec()],
    );
    assert_eq!(eval_list_ints(&format!("({source}).right")), vec![1, 2]);
    assert_eq!(eval_list_ints(&format!("({source}).wrong")), vec![3, 4]);

    let ir = lower(source);
    let outcome = eval_whnf_owned(&ir).expect("partition projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("partition result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn codec_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let json_source = r#"builtins.fromJSON ''{"z":1,"A":2,"aa":3,"_":4,"a":5}''"#;
    let toml_source = r#"builtins.fromTOML "z = 1
A = 2
aa = 3
_ = 4
a = 5
""#;

    for source in [json_source, toml_source] {
        assert_eq!(
            eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
            vec![
                b"A".to_vec(),
                b"_".to_vec(),
                b"a".to_vec(),
                b"aa".to_vec(),
                b"z".to_vec(),
            ],
            "{source}",
        );
        assert_eq!(
            eval_list_ints(&format!("builtins.attrValues ({source})")),
            vec![2, 4, 5, 3, 1],
            "{source}",
        );

        let ir = lower(source);
        let outcome = eval_whnf_owned(&ir).expect("codec projected-shape result evaluates");
        let metadata = outcome
            .heap()
            .get_attrs_metadata(outcome.value())
            .expect("codec result metadata exists");

        assert!(metadata.projected_shape().is_some(), "{source}");
        assert_eq!(metadata.repr(), AttrSetReprKind::Flat, "{source}");
        let stats = outcome.attr_telemetry().order_parity_stats();
        assert_eq!(stats.matched, 1, "{source}");
        assert_eq!(stats.mismatched, 0, "{source}");
    }
}

#[test]
fn path_surface_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let root = unique_temp_dir("path-surface-order");
    fs::write(root.join("a"), b"regular").expect("regular file writes");
    fs::create_dir(root.join("_")).expect("underscore directory creates");
    std::os::unix::fs::symlink(root.join("a"), root.join("0")).expect("symlink creates");
    fs::create_dir(root.join("aa")).expect("aa directory creates");
    fs::write(root.join("z"), b"regular").expect("z file writes");

    let parse_source = r#"builtins.parseDrvName "pkg-1.0""#;
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({parse_source})")),
        vec![b"name".to_vec(), b"version".to_vec()],
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrValues ({parse_source})")),
        vec![b"pkg".to_vec(), b"1.0".to_vec()],
    );
    let parse_outcome =
        eval_whnf_owned(&lower(parse_source)).expect("parseDrvName result evaluates");
    let parse_metadata = parse_outcome
        .heap()
        .get_attrs_metadata(parse_outcome.value())
        .expect("parseDrvName result metadata exists");
    assert!(parse_metadata.projected_shape().is_some());
    assert_eq!(parse_metadata.repr(), AttrSetReprKind::Flat);
    let parse_stats = parse_outcome.attr_telemetry().order_parity_stats();
    assert_eq!(parse_stats.matched, 1);
    assert_eq!(parse_stats.mismatched, 0);

    let read_source = format!(
        "builtins.readDir {}",
        nix_string_literal(&path_source(&root))
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({read_source})")),
        vec![
            b"0".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrValues ({read_source})")),
        vec![
            b"symlink".to_vec(),
            b"directory".to_vec(),
            b"regular".to_vec(),
            b"directory".to_vec(),
            b"regular".to_vec(),
        ],
    );
    let read_outcome = eval_whnf_owned(&lower(&read_source)).expect("readDir result evaluates");
    let read_metadata = read_outcome
        .heap()
        .get_attrs_metadata(read_outcome.value())
        .expect("readDir result metadata exists");
    assert!(read_metadata.projected_shape().is_some());
    assert_eq!(read_metadata.repr(), AttrSetReprKind::Flat);
    let read_stats = read_outcome.attr_telemetry().order_parity_stats();
    assert_eq!(read_stats.matched, 1);
    assert_eq!(read_stats.mismatched, 0);

    let options = search_path_options(b"pkg", &root);
    assert_eq!(
        eval_list_string_bytes_with_options(
            "builtins.attrNames (builtins.head builtins.nixPath)",
            options.clone(),
        ),
        vec![b"path".to_vec(), b"prefix".to_vec()],
    );
    assert_eq!(
        eval_list_string_bytes_with_options(
            "builtins.attrValues (builtins.head builtins.nixPath)",
            options.clone(),
        ),
        vec![path_bytes(&root), b"pkg".to_vec()],
    );
    let nix_path_ir = lower("builtins.nixPath");
    let nix_path_outcome =
        eval_whnf_owned_with_options(&nix_path_ir, options).expect("nixPath result evaluates");
    let nix_path_entry = {
        let list = nix_path_outcome
            .heap()
            .get_list(nix_path_outcome.value())
            .expect("nixPath result is a list");
        list.get(0).expect("nixPath entry exists")
    };
    let nix_path_metadata = nix_path_outcome
        .heap()
        .get_attrs_metadata(nix_path_entry)
        .expect("nixPath entry metadata exists");
    assert!(nix_path_metadata.projected_shape().is_some());
    assert_eq!(nix_path_metadata.repr(), AttrSetReprKind::Flat);
    let nix_path_stats = nix_path_outcome.attr_telemetry().order_parity_stats();
    assert_eq!(nix_path_stats.matched, 1);
    assert_eq!(nix_path_stats.mismatched, 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn function_args_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let source = r#"builtins.functionArgs ({ z ? (throw "z"), A, aa ? 1, _, a ? 2 }: A)"#;

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval(&format!(
            "builtins.attrValues ({source}) == [ false false true true true ]"
        ))
        .as_bool(),
        Ok(true),
    );

    let ir = lower(source);
    let outcome = eval_whnf_owned(&ir).expect("functionArgs projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("functionArgs result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn list_to_attrs_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let list_source = r#"[
        { name = "z"; value = 1; }
        { name = "A"; value = 2; }
        { name = "aa"; value = 3; }
        { name = "_"; value = 4; }
        { name = "a"; value = 5; }
        { name = "a"; value = 99; }
    ]"#;
    let attrs_source = format!("builtins.listToAttrs {list_source}");

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({attrs_source})")),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval_list_ints(&format!("builtins.attrValues ({attrs_source})")),
        vec![2, 4, 5, 3, 1],
    );

    let ir = lower(&attrs_source);
    let outcome = eval_whnf_owned(&ir).expect("listToAttrs projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("listToAttrs result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn group_by_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let source = r#"
        builtins.groupBy
          (value:
            if value == "z" then "z"
            else if value == "A" then "A"
            else if value == "aa" then "aa"
            else if value == "_" then "_"
            else "a")
          [ "z" "A" "aa" "_" "a" "A" ]
    "#;

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval(&format!("builtins.length ({source}).A")).as_int(),
        Ok(2),
    );

    let ir = lower(source);
    let outcome = eval_whnf_owned(&ir).expect("groupBy projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("groupBy result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn force_cache_payload_replay_preserves_attr_repr_metadata() {
    let ir = lower(
        "((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; })",
    );
    let f = symbol_for(&ir, b"f");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_root()
        .expect("deep attr update chain evaluates");
    let payload = evaluator
        .force_cache_payload_for_value(value)
        .expect("HAMT-projected attrs capture as a cache payload");

    let mut replay = TreeWalk::new(&ir);
    let value = replay
        .value_for_cached_expression_payload_for_test(payload)
        .expect("cached attr payload replays");
    let metadata = replay
        .heap()
        .get_attrs_metadata(value)
        .expect("replayed metadata exists");
    let attrs = replay
        .heap()
        .get_attrs(value)
        .expect("replayed attrs remain flat-readable");

    assert_eq!(metadata.shape(), 0);
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
    assert_eq!(attrs.get(f).expect("f exists").as_int(), Ok(6));
    assert_eq!(replay.stats.shape_transitions(), 6);

    let census = replay
        .attr_telemetry
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 1);
    assert_eq!(census.distinct_shapes, 1);
    assert_eq!(census.shapes[0].key_count, 6);
}

#[test]
fn attr_update_telemetry_records_hamt_replacements_from_dispatch_bridge() {
    let ir = lower(
        "((((({ a = 1; b = 2; } // { c = 3; }) // { d = 4; }) // { e = 5; }) // { a = 50; }) // { c = 60; }).c",
    );

    let outcome = eval_whnf_owned(&ir).expect("deep replacement attr update chain evaluates");

    assert_eq!(outcome.value().as_int(), Ok(60));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.update_merges, 5);
    assert_eq!(snapshot.hamt_update_merges, 2);
    assert_eq!(snapshot.hamt_inserted, 0);
    assert_eq!(snapshot.hamt_replaced, 2);
    assert_eq!(snapshot.reasons.deep_override_chain, 1);
    assert_eq!(snapshot.reasons.left_already_hamt, 1);
}

#[test]
fn attr_update_telemetry_does_not_attach_reused_result_depth_to_canonical_attrs() {
    let ir = lower(
        "let base = { a = 1; }; noop = base // {}; in builtins.seq noop ((base // { b = 2; }).b)",
    );

    let outcome = eval_whnf_owned(&ir).expect("reused attr update result evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.update_merges, 2);
    assert_eq!(
        &*snapshot.override_chain_depth_distribution,
        &[HistogramBucket { value: 1, count: 2 }],
    );
}

#[test]
fn attr_update_telemetry_keys_projected_state_by_module() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let span = Span::new(0, 0);
    let module = evaluator
        .push_module(
            IrId::new(0),
            span,
            lower("1"),
            b"/tmp".to_vec(),
            b"/tmp/imported.nix".to_vec(),
            b"1".to_vec(),
        )
        .expect("test module loads");

    evaluator
        .with_current_module(module, |eval| {
            eval.record_attr_update_telemetry(IrId::new(10), span, IrId::new(1), 1, 1);
            eval.record_attr_update_telemetry(IrId::new(11), span, IrId::new(10), 2, 1);
            eval.record_attr_update_telemetry(IrId::new(12), span, IrId::new(11), 3, 1);
            eval.record_attr_update_telemetry(IrId::new(13), span, IrId::new(12), 4, 1);
            Ok(())
        })
        .expect("imported module telemetry records");
    evaluator.record_attr_update_telemetry(IrId::new(20), span, IrId::new(13), 1, 1);

    let snapshot = evaluator
        .attr_telemetry
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 5);
    assert_eq!(snapshot.flat_decisions, 4);
    assert_eq!(snapshot.hamt_decisions, 1);
    assert_eq!(snapshot.reasons.small_shape_stable, 4);
    assert_eq!(snapshot.reasons.deep_override_chain, 1);
    assert_eq!(snapshot.reasons.left_already_hamt, 0);
    assert_eq!(
        &*snapshot.override_chain_depth_distribution,
        &[
            HistogramBucket { value: 1, count: 2 },
            HistogramBucket { value: 2, count: 1 },
            HistogramBucket { value: 3, count: 1 },
            HistogramBucket { value: 4, count: 1 },
        ],
    );
}

#[test]
fn strictness_analysis_preserves_unreached_dynamic_attr_path_ordering() {
    let mut select_ir = lower("({}).${\"a\"}.${1 / 0} or 2");
    crate::compile::annotate_strictness(&mut select_ir).expect("strictness analysis succeeds");
    let select = eval_whnf_owned(&select_ir).expect("unreached dynamic select key stays lazy");
    assert_eq!(select.value().as_int(), Ok(2));

    let mut has_attr_ir = lower("({} ? missing.${1 / 0})");
    crate::compile::annotate_strictness(&mut has_attr_ir).expect("strictness analysis succeeds");
    let has_attr = eval_whnf_owned(&has_attr_ir).expect("unreached dynamic hasAttr key stays lazy");
    assert_eq!(has_attr.value().as_bool(), Ok(false));
}

#[test]
fn strict_attr_binding_facts_do_not_preempt_dynamic_attr_name_errors() {
    let mut ir = lower(r#"({ a = builtins.throw "value"; ${builtins.throw "key"} = 1; }).a"#);
    mark_all_thunk_allocs_strict(&mut ir);

    let error = eval_whnf_owned(&ir).expect_err("dynamic key error wins");

    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown dynamic key error");
    };
    assert_eq!(message, b"key");
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_let_frame_initialization() {
    let mut ir = lower("let x = y; y = 7; in x");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward let reference evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_recursive_attr_frame_initialization() {
    let mut ir = lower("(rec { a = b; b = 7; }).a");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward rec attr reference evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_formal_default_initialization() {
    let mut ir = lower("({ a ? b, b }: a) { b = 2; }");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward formal default evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
}

#[test]
fn strict_inherited_select_binding_facts_stay_lazy_during_attrset_assembly() {
    let mut ir = lower("{ inherit ({ a = 1 + 6; }) a; }");
    let a = symbol_for(&ir, b"a");
    let inherited_select = first_inherit_select_thunk_alloc_id(&ir);
    *ir.facts
        .get_mut(inherited_select)
        .expect("inherited select fact exists") = crate::compile::ExprFacts {
        strictness: crate::compile::Strictness::DemandedBeforeEffect,
        cardinality: crate::compile::Cardinality::Many,
        escape: crate::compile::Escape::Escapes,
    };

    let outcome = eval_whnf_owned(&ir).expect("strict inherited select evaluates");
    let attr_value = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root is a heap-owned attrset");
        attrs.get(a).expect("a exists")
    };

    assert_eq!(attr_value.tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

#[test]
fn forcing_errors_reset_thunks_to_suspended() {
    let ir = lower("{ a = 1 / 0; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::new(&ir);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let error = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("division by zero remains a force error");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("thunk remains heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert!(
        thunk
            .cell()
            .cached_value()
            .expect("suspended thunk has no invalid state")
            .is_none()
    );
}
