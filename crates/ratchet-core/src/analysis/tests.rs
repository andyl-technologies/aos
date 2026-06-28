//! Tests for IR analysis passes.

use super::*;
use crate::ir::{
    Cardinality, EffectClass, Escape, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrBinding,
    IrBindingSlice, IrData, IrFacts, IrId, IrKind, IrNode, Strictness, lower,
};
use crate::resolve;
use crate::syntax::{Span, SymbolTable, parse_str};

fn lowered(source: &str) -> Ir {
    lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
        .expect("IR lowers")
}

fn node(ir: &Ir, id: IrId) -> &crate::ir::IrNode {
    ir.arena.node(id).expect("IR node exists")
}

fn strictness(ir: &Ir, id: IrId) -> Strictness {
    ir.facts.get(id).expect("fact exists").strictness
}

fn cardinality(ir: &Ir, id: IrId) -> Cardinality {
    ir.facts.get(id).expect("fact exists").cardinality
}

fn escape(ir: &Ir, id: IrId) -> Escape {
    ir.facts.get(id).expect("fact exists").escape
}

fn annotate(source: &str) -> Ir {
    let mut ir = lowered(source);
    annotate_strictness(&mut ir).expect("strictness analysis succeeds");
    ir
}

fn annotate_usage(source: &str) -> Ir {
    let mut ir = lowered(source);
    annotate_cardinality(&mut ir).expect("cardinality analysis succeeds");
    ir
}

fn annotate_allocations(source: &str) -> Ir {
    let mut ir = lowered(source);
    annotate_escape(&mut ir).expect("escape analysis succeeds");
    ir
}

fn primop_args(ir: &Ir, id: IrId) -> Vec<IrId> {
    let IrData::PrimOp { args, .. } = node(ir, id).data else {
        panic!("primop payload expected");
    };
    ir.arena
        .child_slice(args)
        .expect("primop args exist")
        .to_vec()
}

fn list_elements(ir: &Ir, id: IrId) -> Vec<IrId> {
    let IrData::Children(children) = node(ir, id).data else {
        panic!("list payload expected");
    };
    ir.arena
        .child_slice(children)
        .expect("list children exist")
        .to_vec()
}

fn let_binding_values(ir: &Ir, id: IrId) -> Vec<IrId> {
    let IrData::Let { bindings, .. } = node(ir, id).data else {
        panic!("let payload expected");
    };
    let start = bindings.start as usize;
    let end = start + bindings.len();
    ir.bindings[start..end]
        .iter()
        .map(|binding| binding.value)
        .collect()
}

fn attr_path_segments(ir: &Ir, path: IrAttrPathId) -> Vec<IrAttrPathSegment> {
    ir.attr_paths
        .get(path.index())
        .expect("attribute path exists")
        .to_vec()
}

#[test]
fn cardinality_marks_simple_let_binding_once() {
    let ir = annotate_usage("let x = 1 + 2; in x");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
}

#[test]
fn cardinality_marks_unreferenced_let_binding_absent() {
    let ir = annotate_usage("let x = 1 / 0; in 1");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Absent);
}

#[test]
fn cardinality_keeps_multi_use_let_binding_many() {
    let ir = annotate_usage("let x = 1 + 2; in x + x");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_counts_let_binding_value_uses() {
    let ir = annotate_usage("let x = 1; y = x; in y");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Once);
}

#[test]
fn cardinality_stays_conservative_across_nested_frames() {
    let ir = annotate_usage("let x = 1; in (y: x + y)");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_resets_stale_facts_when_frame_becomes_incomplete() {
    let mut ir = lowered("let x = 1; in (y: x + y)");
    let bindings = let_binding_values(&ir, ir.root);
    ir.facts
        .get_mut(bindings[0])
        .expect("binding fact exists")
        .cardinality = Cardinality::Once;

    annotate_cardinality(&mut ir).expect("cardinality analysis succeeds");

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_rejects_malformed_local_var_payloads() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"x").expect("symbol interns");
    let nodes = vec![
        IrNode::new(
            IrKind::Int,
            Span::new(8, 9),
            EffectClass::pure(),
            IrData::Int(1),
        ),
        IrNode::new(
            IrKind::LocalVar,
            Span::new(16, 17),
            EffectClass::pure(),
            IrData::None,
        ),
        IrNode::new(
            IrKind::Let,
            Span::new(0, 17),
            EffectClass::pure(),
            IrData::Let {
                bindings: IrBindingSlice::new(0, 1),
                body: IrId::new(1),
                frame: None,
            },
        ),
    ];
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    let mut ir = Ir {
        root: IrId::new(2),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value: IrId::new(0),
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };

    let error = annotate_cardinality(&mut ir).expect_err("invalid local payload errors");

    assert!(matches!(
        error,
        CardinalityAnalysisError::InvalidPayload {
            id,
            kind: IrKind::LocalVar,
            expected: "local slot payload",
        } if id == IrId::new(1)
    ));
}

#[test]
fn escape_marks_allocation_free_scalar_literals_no_escape() {
    for source in ["1", "1.5", "true", "null"] {
        let ir = annotate_allocations(source);
        assert_eq!(escape(&ir, ir.root), Escape::NoEscape, "{source}");
    }
}

#[test]
fn escape_keeps_heap_and_thunk_values_escaping() {
    let string_ir = annotate_allocations("\"value\"");
    assert_eq!(escape(&string_ir, string_ir.root), Escape::Escapes);

    let list_ir = annotate_allocations("[ (1 + 2) ]");
    assert_eq!(escape(&list_ir, list_ir.root), Escape::Escapes);
    let elements = list_elements(&list_ir, list_ir.root);
    assert_eq!(escape(&list_ir, elements[0]), Escape::Escapes);
}

#[test]
fn escape_resets_stale_no_escape_facts_for_unproven_nodes() {
    let mut ir = lowered("\"value\"");
    ir.facts.get_mut(ir.root).expect("root fact exists").escape = Escape::NoEscape;

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, ir.root), Escape::Escapes);
}

#[test]
fn escape_rejects_malformed_scalar_payloads() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    let mut ir = Ir {
        root: IrId::new(0),
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_escape(&mut ir).expect_err("invalid scalar payload errors");

    assert!(matches!(
        error,
        EscapeAnalysisError::InvalidPayload {
            id,
            kind: IrKind::Int,
            expected: "integer payload",
        } if id == IrId::new(0)
    ));
}

#[test]
fn escape_scrubs_stale_no_escape_facts_before_validation_errors() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"value").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::Str,
                Span::new(2, 9),
                EffectClass::pure(),
                IrData::Symbol(symbol),
            ),
        ],
        Vec::new(),
    );
    let mut facts = IrFacts::conservative(arena.nodes().len());
    facts
        .get_mut(IrId::new(1))
        .expect("second fact exists")
        .escape = Escape::NoEscape;
    let mut ir = Ir {
        root: IrId::new(0),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_escape(&mut ir).expect_err("invalid scalar payload errors");

    assert!(matches!(
        error,
        EscapeAnalysisError::InvalidPayload {
            id,
            kind: IrKind::Int,
            expected: "integer payload",
        } if id == IrId::new(0)
    ));
    assert_eq!(escape(&ir, IrId::new(1)), Escape::Escapes);
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
