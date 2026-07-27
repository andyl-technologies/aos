//! Split-out tests (part_1). See parent module.

use super::*;

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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
fn analyzer_produced_consumed_position_let_thunk_uses_single_entry_storage() {
    // The binding is forced in place by the `+` operand position: consumed
    // during the frame's own execution, so the per-frame reachability proof
    // admits single-entry storage. (The former direct-body shape
    // `let x = ...; in x` now fails closed: its frame result can be cached
    // as a raw handle by an enclosing update thunk and re-forced.)
    let mut ir = lower("let x = 1 + 6; in x + 1");
    let thunk_alloc = first_thunk_alloc_id(&ir);
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let facts = ir
        .facts
        .get(thunk_alloc)
        .expect("analyzed thunk fact exists");
    assert_eq!(
        facts.cardinality,
        crate::compile::Cardinality::Once,
        "single operand use proves single entry"
    );
    assert_eq!(
        facts.escape,
        crate::compile::Escape::NoEscape,
        "consumed operand use proves frame locality"
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
        .expect("annotated consumed-position let evaluates");

    assert_eq!(value.as_int(), Ok(8));
    assert_eq!(evaluator.stats().thunks_allocated(), 1);
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);
    // FV-3: production thunks are flat worker closures, not records.
    let thunk_values = evaluator
        .heap()
        .test_flat_closure_values()
        .map(|value| value.expect("flat closure value rebuilds"))
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
fn demand_position_lexical_alias_reuses_the_referenced_thunk() {
    let ir = lower("let x = x; in [ x ]");

    let outcome = eval_whnf_owned(&ir).expect("list construction keeps x lazy");
    let element = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };

    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_allocated(), 1);
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

// P0 re-force fast path (RFC-0007): a second force of an already-`Forced`
// serial thunk is served before `share_thunk`'s Arc mint and the `begin_force`
// claim, so it returns the identical cached value while minting zero new
// force-state sidecar Arcs.
#[test]
fn second_force_of_forced_serial_thunk_hits_reforce_fast_path_without_new_state_arcs() {
    let ir = lower("[ (1 + 2) ]");
    let thunk_alloc = first_thunk_alloc_id(&ir);
    let thunk_span = ir
        .arena
        .node(thunk_alloc)
        .expect("thunk alloc node exists")
        .span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let value = evaluator.eval_root().expect("list evaluates");
    let element = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(element)
            .expect("element is a heap thunk")
            .force_storage_mode(),
        EvalThunkForceStorageMode::Serial,
        "list element is a plain serial thunk with a publishable cache",
    );

    let first = evaluator
        .force_value(thunk_alloc, thunk_span, element)
        .expect("first force succeeds");
    assert_eq!(first.as_int(), Ok(3));
    let after_first = evaluator.stats();
    assert_eq!(after_first.thunks_forced(), 1);
    assert_eq!(after_first.reforce_fast_path_hits(), 0);
    let state_arcs_after_first = after_first.campaign().thunk_state_arc_clones;
    assert_eq!(
        state_arcs_after_first, 0,
        "the serial stable-arena force borrows the thunk without cloning sidecar Arcs",
    );

    let second = evaluator
        .force_value(thunk_alloc, thunk_span, element)
        .expect("second force succeeds");
    assert!(second.raw_eq(first), "re-force returns the identical value");
    let after_second = evaluator.stats();
    assert_eq!(
        after_second.thunks_forced(),
        1,
        "the body ran exactly once; the re-force never reached the claim",
    );
    assert_eq!(after_second.reforce_fast_path_hits(), 1);
    assert_eq!(after_second.thunk_cache_hits(), 1);
    assert_eq!(
        after_second.campaign().thunk_state_arc_clones,
        state_arcs_after_first,
        "the pre-share re-force mints no new force-state sidecar Arc",
    );
}

// P0 re-force fast path (RFC-0007): a single-entry thunk re-evaluates its body
// on every force and never publishes a cached result, so it must bypass the
// re-force fast path and keep re-running.
#[test]
fn single_entry_thunk_reevaluates_on_each_force_and_skips_reforce_fast_path() {
    let mut ir = lower("[ (1 + 2) ]");
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
    let mut options = TreeWalkOptions::new();
    options.set_parallel_thunk_payloads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("list evaluates");
    let element = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(element)
            .expect("element is a heap thunk")
            .force_storage_mode(),
        EvalThunkForceStorageMode::SingleEntry,
        "consumed-once frame-local element earns single-entry storage",
    );

    let first = evaluator
        .force_value(thunk_alloc, thunk_span, element)
        .expect("first force succeeds");
    assert_eq!(first.as_int(), Ok(3));
    let second = evaluator
        .force_value(thunk_alloc, thunk_span, element)
        .expect("second force succeeds");
    assert_eq!(second.as_int(), Ok(3));

    let stats = evaluator.stats();
    assert_eq!(
        stats.single_entry_thunks_forced(),
        2,
        "single-entry storage re-runs the body on each force",
    );
    assert_eq!(
        stats.reforce_fast_path_hits(),
        0,
        "single-entry thunks never publish a cache to short-circuit on",
    );
    assert_eq!(stats.thunk_cache_hits(), 0);
}
