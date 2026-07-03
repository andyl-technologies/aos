//! Strictness analysis tests.

use super::*;

#[test]
fn strictness_rejects_fact_table_length_mismatches() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let mut overlong = Ir {
        root: IrId::new(0),
        arena: arena.clone(),
        facts: IrFacts::conservative(2),
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    overlong
        .facts
        .get_mut(IrId::new(1))
        .expect("stale fact exists")
        .strictness = Strictness::Strict;

    let error = annotate_strictness(&mut overlong).expect_err("overlong fact table rejects");

    assert_eq!(
        error,
        StrictnessAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 2,
        }
    );
    assert_eq!(strictness(&overlong, IrId::new(1)), Strictness::Strict);

    let mut short = Ir {
        root: IrId::new(0),
        arena,
        facts: IrFacts::conservative(0),
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_strictness(&mut short).expect_err("short fact table rejects");

    assert_eq!(
        error,
        StrictnessAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 0,
        }
    );
}

#[test]
fn strictness_rejects_malformed_payloads_before_marking_facts() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Null,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::None,
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_strictness(&mut ir).expect_err("invalid payload rejects");

    assert!(matches!(
        error,
        StrictnessAnalysisError::InvalidPayload {
            id,
            kind: IrKind::LocalVar,
            expected: "local slot payload",
        } if id == IrId::new(1)
    ));
    assert_eq!(strictness(&ir, ir.root), Strictness::Unknown);
}

#[test]
fn strictness_marks_root_and_guaranteed_strict_children_only() {
    let ir = annotate("if 1 == 1 then [ (1 / 0) ] else 0");
    let root = ir.root;
    assert_eq!(strictness(&ir, root), Strictness::Strict);
    let IrData::Triple {
        first: condition,
        second: then_branch,
        third: else_branch,
    } = node(&ir, root).data
    else {
        panic!("if payload expected");
    };

    assert_eq!(strictness(&ir, condition), Strictness::Strict);
    assert_eq!(strictness(&ir, then_branch), Strictness::Unknown);
    assert_eq!(strictness(&ir, else_branch), Strictness::Unknown);

    let elements = list_elements(&ir, then_branch);
    assert_eq!(strictness(&ir, elements[0]), Strictness::Unknown);
}

#[test]
fn strictness_keeps_lazy_list_elements_unknown_under_whnf_list_demand() {
    let ir = annotate("builtins.length [ (1 / 0) ]");
    let args = primop_args(&ir, ir.root);
    let list = args[0];
    assert_eq!(strictness(&ir, list), Strictness::Strict);

    let elements = list_elements(&ir, list);
    assert_eq!(node(&ir, elements[0]).kind, IrKind::ThunkAlloc);
    assert_eq!(strictness(&ir, elements[0]), Strictness::Unknown);
}

#[test]
fn strictness_skips_higher_order_callbacks_that_empty_inputs_can_avoid() {
    let map_ir = annotate("builtins.map (builtins.throw \"function\") []");
    let map_args = primop_args(&map_ir, map_ir.root);
    assert_eq!(strictness(&map_ir, map_args[0]), Strictness::Unknown);
    assert_eq!(strictness(&map_ir, map_args[1]), Strictness::Strict);

    let sort_ir = annotate("builtins.sort (builtins.throw \"comparator\") []");
    let sort_args = primop_args(&sort_ir, sort_ir.root);
    assert_eq!(strictness(&sort_ir, sort_args[0]), Strictness::Unknown);
    assert_eq!(strictness(&sort_ir, sort_args[1]), Strictness::Strict);
}

#[test]
fn strictness_keeps_option_dependent_trace_verbose_message_unknown() {
    let trace_ir = annotate("builtins.trace (builtins.throw \"message\") 1");
    let trace_args = primop_args(&trace_ir, trace_ir.root);
    assert_eq!(strictness(&trace_ir, trace_args[0]), Strictness::Strict);
    assert_eq!(strictness(&trace_ir, trace_args[1]), Strictness::Unknown);

    let verbose_ir = annotate("builtins.traceVerbose (builtins.throw \"message\") 1");
    let verbose_args = primop_args(&verbose_ir, verbose_ir.root);
    assert_eq!(
        strictness(&verbose_ir, verbose_args[0]),
        Strictness::Unknown
    );
    assert_eq!(
        strictness(&verbose_ir, verbose_args[1]),
        Strictness::Unknown
    );
}

#[test]
fn strictness_keeps_foldl_empty_initial_accumulator_lazy() {
    let ir = annotate("builtins.foldl' (builtins.throw \"op\") (builtins.throw \"initial\") []");
    let args = primop_args(&ir, ir.root);

    assert_eq!(strictness(&ir, args[0]), Strictness::Strict);
    assert_eq!(strictness(&ir, args[1]), Strictness::Unknown);
    assert_eq!(strictness(&ir, args[2]), Strictness::Strict);
}

#[test]
fn strictness_does_not_mark_assert_body_as_unconditionally_demanded() {
    let ir = annotate("assert false; builtins.throw \"body\"");
    let IrData::Pair {
        first: condition,
        second: body,
    } = node(&ir, ir.root).data
    else {
        panic!("assert payload expected");
    };

    assert_eq!(strictness(&ir, condition), Strictness::Strict);
    assert_eq!(strictness(&ir, body), Strictness::Unknown);
}

#[test]
fn strictness_marks_dynamic_attr_keys_but_not_attr_values() {
    let ir = annotate("({ ${builtins.throw \"key\"} = 1 / 0; }).a");
    let IrData::Select { receiver, .. } = node(&ir, ir.root).data else {
        panic!("select payload expected");
    };
    let IrData::AttrSet { bindings, .. } = node(&ir, receiver).data else {
        panic!("attrset payload expected");
    };
    let binding = ir.bindings[bindings.start as usize];
    let IrAttrPathSegment::Dynamic(key) = binding.key else {
        panic!("dynamic binding key expected");
    };

    assert_eq!(strictness(&ir, key), Strictness::Strict);
    assert_eq!(strictness(&ir, binding.value), Strictness::Unknown);
}

#[test]
fn strictness_marks_only_leading_dynamic_select_segments() {
    let leading_ir = annotate(r#"({ a = 1; }).${builtins.throw "key"}"#);
    let IrData::Select {
        path: leading_path, ..
    } = node(&leading_ir, leading_ir.root).data
    else {
        panic!("select payload expected");
    };
    let leading_segments = attr_path_segments(&leading_ir, leading_path);
    let IrAttrPathSegment::Dynamic(leading_key) = leading_segments[0] else {
        panic!("leading dynamic select segment expected");
    };
    assert_eq!(strictness(&leading_ir, leading_key), Strictness::Strict);

    let nested_ir = annotate(r#"({ a = {}; }).missing.${builtins.throw "key"}"#);
    let IrData::Select {
        path: nested_path, ..
    } = node(&nested_ir, nested_ir.root).data
    else {
        panic!("select payload expected");
    };
    let nested_segments = attr_path_segments(&nested_ir, nested_path);
    let IrAttrPathSegment::Dynamic(nested_key) = nested_segments[1] else {
        panic!("nested dynamic select segment expected");
    };
    assert_eq!(strictness(&nested_ir, nested_key), Strictness::Unknown);
}

#[test]
fn strictness_marks_only_leading_dynamic_has_attr_segments() {
    let leading_ir = annotate(r#"({} ? ${builtins.throw "key"})"#);
    let IrData::HasAttr {
        path: leading_path, ..
    } = node(&leading_ir, leading_ir.root).data
    else {
        panic!("hasAttr payload expected");
    };
    let leading_segments = attr_path_segments(&leading_ir, leading_path);
    let IrAttrPathSegment::Dynamic(leading_key) = leading_segments[0] else {
        panic!("leading dynamic hasAttr segment expected");
    };
    assert_eq!(strictness(&leading_ir, leading_key), Strictness::Strict);

    let nested_ir = annotate(r#"({} ? missing.${builtins.throw "key"})"#);
    let IrData::HasAttr {
        path: nested_path, ..
    } = node(&nested_ir, nested_ir.root).data
    else {
        panic!("hasAttr payload expected");
    };
    let nested_segments = attr_path_segments(&nested_ir, nested_path);
    let IrAttrPathSegment::Dynamic(nested_key) = nested_segments[1] else {
        panic!("nested dynamic hasAttr segment expected");
    };
    assert_eq!(strictness(&nested_ir, nested_key), Strictness::Unknown);
}

#[test]
fn strictness_marks_direct_lambda_argument_thunk_when_body_demands_parameter() {
    let mut ir = lowered("(x: x + 1) (1 + 2)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::ThunkAlloc);

    let report = annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    assert!(report.nodes_marked_strict > 0);
    assert_eq!(strictness(&ir, argument), Strictness::Strict);
}

#[test]
fn strictness_marks_direct_lambda_argument_through_intervening_frame() {
    let mut ir = lowered("(x: let y = 1; in x + y) (1 + 2)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    assert_eq!(strictness(&ir, argument), Strictness::Strict);
}

#[test]
fn strictness_marks_direct_lambda_argument_in_recursive_dynamic_key() {
    let mut ir = lowered(r#"(x: rec { ${x} = 1; }) (builtins.throw "key")"#);
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    assert_eq!(strictness(&ir, argument), Strictness::Strict);
}

#[test]
fn strictness_keeps_direct_lambda_argument_lazy_when_body_ignores_parameter() {
    let ir = annotate("(x: 1) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::ThunkAlloc);
    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_keeps_direct_lambda_argument_lazy_across_nested_lambda() {
    let ir = annotate("(x: (y: x + y)) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_respects_nested_lambda_parameter_shadowing() {
    let ir = annotate("(x: (x: x) 1) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_respects_shadowing_frames_in_direct_lambda_probe() {
    let ir = annotate("(x: let x = 1; in x) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}
