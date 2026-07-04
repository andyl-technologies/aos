//! Thunk and strictness tests for tree-walk attr evaluation.

use super::*;
use crate::attrs::telemetry::HistogramBucket;

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
            strictness: crate::compile::Strictness::Strict,
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
fn strict_thunk_alloc_facts_evaluate_eagerly() {
    for (escape, label) in [
        (crate::compile::Escape::Escapes, "eager"),
        (crate::compile::Escape::NoEscape, "scalar"),
    ] {
        let mut ir = lower("[ (1 + 6) ]");
        let thunk_alloc = first_thunk_alloc_id(&ir);
        *ir.facts.get_mut(thunk_alloc).expect("thunk fact exists") = crate::compile::ExprFacts {
            strictness: crate::compile::Strictness::Strict,
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
}

#[test]
fn dynamic_attrset_literals_record_dynamic_repr_decisions() {
    let ir = lower(r#"let name = "a"; in ({ ${name} = 1; }).a"#);

    let outcome = eval_whnf_owned(&ir).expect("dynamic attrset evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
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
fn list_to_attrs_records_dynamic_repr_decision() {
    let ir = lower(
        r#"builtins.deepSeq (builtins.listToAttrs [
            { name = "b"; value = 2; }
            { name = "a"; value = 1; }
        ]) 0"#,
    );

    let outcome = eval_whnf_owned(&ir).expect("listToAttrs evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 3);
    assert_eq!(snapshot.flat_decisions, 3);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 2);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
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
}

#[test]
fn zip_attrs_with_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.zipAttrsWith (_name: values: values) [ { a = 1; } { b = 2; } ])
            (let zip = builtins.zipAttrsWith (_name: values: values); in zip [ { c = 3; } ])
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("zipAttrsWith evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 5);
    assert_eq!(snapshot.flat_decisions, 5);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 3);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
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
    assert_eq!(counts.flat_hits, 3);
    assert_eq!(counts.flat_misses, 2);
    assert_eq!(counts.hamt_hits, 0);
    assert_eq!(counts.hamt_misses, 0);
    assert_eq!(counts.shaped_hits, 0);
    assert_eq!(counts.shaped_misses, 0);
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
    assert_eq!(snapshot.reasons.static_literal, 6);
    assert_eq!(snapshot.reasons.small_shape_stable, 3);
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
        strictness: crate::compile::Strictness::Strict,
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
