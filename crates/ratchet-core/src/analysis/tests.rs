//! Tests for IR analysis passes.

use super::*;
use crate::ir::{
    Cardinality, EffectClass, Escape, ExprFacts, Ir, IrArena, IrAttrPathId, IrAttrPathSegment,
    IrBinding, IrBindingSlice, IrChildSlice, IrData, IrDialectOp, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrLowerOptions, IrNode, IrShape, IrWithChain, Strictness,
    annotate_ir, lower, lower_with_options,
};
use crate::resolve;
use crate::scope::{FrameId, FrameInfo};
use crate::syntax::{Span, SymbolTable, parse_str};

const TEST_WITH_VAR_OP: IrDialectOp = IrDialectOp::new(1);

/// The Nix dialect's `derivationStrict` op key (`NIX_OP_DERIVATION_STRICT`),
/// installed so tests exercise the production `DialectNode` lowering shape.
const TEST_DERIVATION_STRICT_OP: IrDialectOp = IrDialectOp::new(1);

fn test_derivation_dialect_op(
    _name: Option<&[u8]>,
    direct: crate::builtins::BuiltinDirect,
) -> Option<IrDialectOp> {
    match direct {
        crate::builtins::BuiltinDirect::DerivationStrict => Some(TEST_DERIVATION_STRICT_OP),
        _ => None,
    }
}

fn lowered(source: &str) -> Ir {
    lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
        .expect("IR lowers")
}

/// Lowers with the Nix dialect's `derivationStrict` op installed, so the
/// boundary appears as `IrData::DialectNode` exactly as `nix_lower` produces.
fn lowered_with_derivation_op(source: &str) -> Ir {
    let resolved = resolve(parse_str(source).expect("source parses")).expect("source resolves");
    lower_with_options(
        resolved,
        IrLowerOptions::new().with_builtin_dialect_op(test_derivation_dialect_op),
    )
    .expect("IR lowers")
}

fn lowered_with_dynamic_scope(source: &str) -> Ir {
    let resolved = resolve(parse_str(source).expect("source parses")).expect("source resolves");
    lower_with_options(
        resolved,
        IrLowerOptions::new().with_dynamic_scope_var_op(|| Some(TEST_WITH_VAR_OP)),
    )
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

fn annotate_with_derivation_op(source: &str) -> Ir {
    let mut ir = lowered_with_derivation_op(source);
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

fn full_laziness_candidates(source: &str) -> Vec<FullLazinessCandidate> {
    let ir = lowered(source);
    analyze_full_laziness(&ir)
        .expect("full-laziness analysis succeeds")
        .candidates
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
fn cardinality_counts_if_branches_as_mutually_exclusive() {
    let ir = annotate_usage("let x = 1 + 2; in if true then x else x");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
}

#[test]
fn cardinality_sums_if_condition_with_branch_uses() {
    let ir = annotate_usage("let x = true; in if x then x else false");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_keeps_incomplete_if_branches_conservative() {
    let ir = annotate_usage("let x = 1; in if true then (y: x + y) else x");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_resets_stale_facts_when_if_branch_becomes_incomplete() {
    let mut ir = lowered("let x = 1; in if true then (y: x + y) else x");
    let bindings = let_binding_values(&ir, ir.root);
    ir.facts
        .get_mut(bindings[0])
        .expect("binding fact exists")
        .cardinality = Cardinality::Once;

    annotate_cardinality(&mut ir).expect("cardinality analysis succeeds");

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
fn cardinality_skips_absent_binding_value_uses() {
    let ir = annotate_usage("let x = 1 + 2; y = x; in 0");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Absent);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Absent);
}

#[test]
fn cardinality_propagates_transitive_demanded_binding_values() {
    let ir = annotate_usage("let x = 1 + 2; y = x; z = y; in z");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Once);
    assert_eq!(cardinality(&ir, bindings[2]), Cardinality::Once);
}

#[test]
fn cardinality_does_not_count_dead_sibling_binding_values() {
    let ir = annotate_usage("let x = 1 + 2; y = x; z = x; in y");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Once);
    assert_eq!(cardinality(&ir, bindings[2]), Cardinality::Absent);
}

#[test]
fn cardinality_counts_many_entry_binding_value_once_for_shared_thunk() {
    let ir = annotate_usage("let x = 1 + 2; y = x; in y + y");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Many);
}

#[test]
fn cardinality_keeps_recursive_alias_cycle_conservative() {
    let ir = annotate_usage("let x = y; y = x; in x");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Once);
}

#[test]
fn cardinality_resets_stale_facts_when_binding_value_becomes_absent() {
    let mut ir = lowered("let x = 1 + 2; y = x; in 0");
    let bindings = let_binding_values(&ir, ir.root);
    ir.facts
        .get_mut(bindings[0])
        .expect("binding fact exists")
        .cardinality = Cardinality::Once;

    annotate_cardinality(&mut ir).expect("cardinality analysis succeeds");

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Absent);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Absent);
}

#[test]
fn cardinality_saturates_uses_inside_escaping_lambda_values() {
    // The closure bound to `y` may be called any number of times, so `x`
    // saturates to many -- but `y` itself is still proven once instead of
    // the whole frame being abandoned.
    let ir = annotate_usage("let x = 1; y = (z: x + z); in y");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Once);
}

#[test]
fn cardinality_saturates_uses_inside_escaping_lambda_bodies() {
    let ir = annotate_usage("let x = 1; in (y: x + y)");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_ignores_lambdas_that_do_not_use_the_frame() {
    // Pre-widening, any lambda in the frame poisoned every binding to many.
    let ir = annotate_usage("let x = 1 + 2; f = (y: y); in x");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
    assert_eq!(cardinality(&ir, bindings[1]), Cardinality::Absent);
}

#[test]
fn cardinality_counts_directly_applied_lambda_bodies_once() {
    let ir = annotate_usage("let x = 1 + 2; in (y: x + y) 3");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
}

#[test]
fn cardinality_sums_directly_applied_lambda_body_uses() {
    let ir = annotate_usage("let x = 1 + 2; in (y: x + y) x");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_counts_through_nested_let_frames() {
    let ir = annotate_usage("let x = 1 + 2; in let y = x; in y");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
}

#[test]
fn cardinality_counts_nested_let_values_as_upper_bound() {
    // Both nested binding values reference `x`; each nested update thunk runs
    // at most once, so the upper bound is two entries -> many.
    let ir = annotate_usage("let x = 1 + 2; in let y = x; z = x; in y");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Many);
}

#[test]
fn cardinality_counts_through_recursive_attrset_frames() {
    let ir = annotate_usage("let x = 1 + 2; in rec { a = x; b = a; }");
    let bindings = let_binding_values(&ir, ir.root);

    assert_eq!(cardinality(&ir, bindings[0]), Cardinality::Once);
}

#[test]
fn cardinality_counts_attrset_binding_uses() {
    let ir = annotate_usage("let x = 1 + 2; in { a = x; b = x; }");
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

fn annotate_captures(source: &str) -> Ir {
    let mut ir = lowered(source);
    annotate_capture_plans(&mut ir).expect("capture analysis succeeds");
    ir
}

fn flat_plan_slots(ir: &Ir, id: IrId) -> Vec<(u16, u16)> {
    match ir.facts.capture_plan(id) {
        Some(crate::ir::CapturePlan::Flat(slots)) => slots
            .iter()
            .map(|capture| (capture.depth, capture.slot))
            .collect(),
        other => panic!("expected flat capture plan, got {other:?}"),
    }
}

fn lambda_nodes(ir: &Ir) -> Vec<IrId> {
    (0..ir.arena.nodes().len() as u32)
        .map(IrId::new)
        .filter(|id| node(ir, *id).kind == IrKind::Lambda)
        .collect()
}

#[test]
fn capture_plans_cover_lambda_and_thunk_sites() {
    let ir = annotate_captures("let a = 1 + 1; in (x: a + x)");
    let mut planned_lambdas = 0;
    let mut planned_thunks = 0;
    for index in 0..ir.arena.nodes().len() as u32 {
        let id = IrId::new(index);
        let kind = node(&ir, id).kind;
        let plan = ir.facts.capture_plan(id);
        match kind {
            IrKind::Lambda => {
                assert!(plan.is_some(), "lambda site {id:?} must carry a plan");
                planned_lambdas += 1;
            }
            IrKind::ThunkAlloc => {
                assert!(plan.is_some(), "thunk site {id:?} must carry a plan");
                planned_thunks += 1;
            }
            _ => assert!(plan.is_none(), "non-site {id:?} must not carry a plan"),
        }
    }
    assert!(planned_lambdas >= 1);
    assert!(planned_thunks >= 1);
}

#[test]
fn capture_plans_translate_nested_lambda_coordinates() {
    // `x: y: x` — the inner lambda captures the outer parameter at depth 0
    // of its allocation environment; the outer lambda captures nothing.
    let ir = annotate_captures("x: y: x");
    let lambdas = lambda_nodes(&ir);
    assert_eq!(lambdas.len(), 2);
    let mut slot_sets: Vec<Vec<(u16, u16)>> = lambdas
        .iter()
        .map(|id| flat_plan_slots(&ir, *id))
        .collect();
    slot_sets.sort();
    assert_eq!(slot_sets, vec![vec![], vec![(0, 0)]]);
}

#[test]
fn capture_plans_assign_constant_indices_to_captured_reads() {
    let ir = annotate_captures("let a = 1 + 1; in (x: a + x)");
    let lambda = *lambda_nodes(&ir).first().expect("lambda exists");
    let accesses: Vec<_> = ir
        .facts
        .flat_capture_accesses()
        .iter()
        .enumerate()
        .filter_map(|(index, access)| access.map(|access| (IrId::new(index as u32), access)))
        .collect();

    assert_eq!(accesses.len(), 1, "only `a` crosses the lambda frame");
    assert_eq!(accesses[0].1.site, lambda);
    assert_eq!(accesses[0].1.index, 0);
    assert!(matches!(node(&ir, accesses[0].0).data, IrData::Upval { .. }));
}

#[test]
fn capture_indices_belong_to_the_nearest_nested_closure() {
    let ir = annotate_captures("x: y: x");
    let lambdas = lambda_nodes(&ir);
    let inner = lambdas
        .iter()
        .copied()
        .find(|id| !flat_plan_slots(&ir, *id).is_empty())
        .expect("inner capturing lambda exists");
    let accesses: Vec<_> = ir
        .facts
        .flat_capture_accesses()
        .iter()
        .flatten()
        .copied()
        .collect();

    assert_eq!(accesses.len(), 1);
    assert_eq!(accesses[0].site, inner);
    assert_eq!(accesses[0].index, 0);
}

#[test]
fn capture_plans_record_thunk_free_variables() {
    // `b`'s deferred body reads `a` from the frame active at allocation.
    let ir = annotate_captures("let a = 1; b = a + 1; in b");
    let bindings = let_binding_values(&ir, ir.root);
    assert_eq!(flat_plan_slots(&ir, bindings[1]), vec![(0, 0)]);
}

#[test]
fn capture_plans_flow_transitively_through_nested_closures() {
    // The thunk body allocates a lambda that reads two enclosing frames; both
    // coordinates surface in the thunk's own plan, shifted to its boundary.
    let ir = annotate_captures("let a = 1; in let b = 2; c = (x: a + b + x); in c");
    let bindings = let_binding_values(
        &ir,
        {
            // The outer let's body is the inner let.
            let IrData::Let { body, .. } = node(&ir, ir.root).data else {
                panic!("outer let expected");
            };
            body
        },
    );
    // Binding `c` is slot 1 of the inner let: its thunk reads `b` from its
    // own frame (depth 0) and `a` from the outer frame (depth 1).
    assert_eq!(flat_plan_slots(&ir, bindings[1]), vec![(0, 0), (1, 0)]);
}

#[test]
fn capture_plans_decline_dynamic_scope_probes() {
    let ir = {
        let mut ir = lowered_with_dynamic_scope("with { a = 1; }; (x: a)");
        annotate_capture_plans(&mut ir).expect("capture analysis succeeds");
        ir
    };
    let declined = lambda_nodes(&ir)
        .into_iter()
        .filter(|id| {
            matches!(
                ir.facts.capture_plan(*id),
                Some(crate::ir::CapturePlan::SharedChain(
                    crate::ir::SharedChainReason::DynamicScope
                ))
            )
        })
        .count();
    assert_eq!(declined, 1);
}

#[test]
fn capture_plans_cap_flat_width() {
    // Eleven distinct free variables exceed the configured flat-width ceiling.
    let source = "let a=1; b=2; c=3; d=4; e=5; f=6; g=7; h=8; i=9; j=10; k=11; \
                  in (x: a+b+c+d+e+f+g+h+i+j+k)";
    let ir = annotate_captures(source);
    let lambdas = lambda_nodes(&ir);
    assert_eq!(lambdas.len(), 1);
    assert_eq!(
        ir.facts.capture_plan(lambdas[0]),
        Some(&crate::ir::CapturePlan::SharedChain(
            crate::ir::SharedChainReason::TooManyFreeVars
        ))
    );
}

/// Cross-validates the capture walk against the resolver: for every lambda
/// site with a flat plan, the plan's coordinate set must equal the resolver's
/// independently computed frame capture set.
#[test]
fn capture_plans_match_resolver_lambda_captures() {
    for source in [
        "x: y: x",
        "let a = 1; in (x: a + x)",
        "let a = 1; b = 2; in (x: (y: a + y) (x + b))",
        "let f = x: x + 1; in f 2",
        "let a = 1; in let b = a; in (x: a + b)",
        "({ x ? 1, y ? x }: x + y) {}",
        "let lib = { inc = x: x + 1; }; in lib.inc 2",
        "let a = 1; in rec { m = x: a + x; n = m; }",
    ] {
        let ir = annotate_captures(source);
        for id in lambda_nodes(&ir) {
            let IrData::Lambda { frame, .. } = node(&ir, id).data else {
                panic!("lambda payload expected");
            };
            let Some(frame) = frame else {
                continue;
            };
            let plan_slots = flat_plan_slots(&ir, id);
            // Resolver capture coordinates are body-relative (depth counts
            // the lambda's own parameter frame); the plan is relative to the
            // allocation environment, one frame shallower.
            let mut resolver_slots: Vec<(u16, u16)> = ir.frames[frame.index()]
                .captures
                .iter()
                .map(|capture| {
                    assert!(
                        capture.depth >= 1,
                        "{source}: resolver capture inside the lambda's own frame"
                    );
                    (capture.depth - 1, capture.slot)
                })
                .collect();
            resolver_slots.sort_unstable();
            resolver_slots.dedup();
            assert_eq!(plan_slots, resolver_slots, "{source}: lambda {id:?}");
        }
    }
}

#[test]
fn cardinality_rejects_fact_table_length_mismatches() {
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
        .cardinality = Cardinality::Once;

    let error = annotate_cardinality(&mut overlong).expect_err("overlong fact table rejects");

    assert_eq!(
        error,
        CardinalityAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 2,
        }
    );
    assert_eq!(cardinality(&overlong, IrId::new(1)), Cardinality::Once);

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

    let error = annotate_cardinality(&mut short).expect_err("short fact table rejects");

    assert_eq!(
        error,
        CardinalityAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 0,
        }
    );
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
fn cardinality_rejects_unreachable_malformed_payloads_before_marking_facts() {
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
            IrKind::Null,
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
        IrNode::new(
            IrKind::LocalVar,
            Span::new(18, 19),
            EffectClass::pure(),
            IrData::None,
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
        } if id == IrId::new(3)
    ));
    assert_eq!(cardinality(&ir, IrId::new(0)), Cardinality::Many);
}

#[test]
fn full_laziness_reports_closed_pure_let_bindings_under_simple_lambdas() {
    let ir = lowered("x: let y = 1 + 2; in y + x");
    let report = analyze_full_laziness(&ir).expect("full-laziness analysis succeeds");

    assert_eq!(report.candidates.len(), 1);
    let candidate = report.candidates[0];
    assert_eq!(node(&ir, candidate.lambda).kind, IrKind::Lambda);
    assert_eq!(node(&ir, candidate.let_node).kind, IrKind::Let);
    assert_eq!(candidate.binding_index, 0);
    assert!(matches!(candidate.key, IrAttrPathSegment::Static(_)));
    assert_eq!(node(&ir, candidate.value).kind, IrKind::ThunkAlloc);
    let IrData::Node(body) = node(&ir, candidate.value).data else {
        panic!("candidate thunk body expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::BinOp);
}

#[test]
fn full_laziness_keeps_parameter_dependent_and_frame_values_conservative() {
    for source in [
        "x: let y = x + 1; in y",
        "x: let y = [ (1 + 2) ]; in y",
        "x: let y = z: 1; in y",
    ] {
        assert!(
            full_laziness_candidates(source).is_empty(),
            "{source} should stay conservative"
        );
    }
}

#[test]
fn full_laziness_ignores_non_simple_lambda_patterns() {
    assert!(full_laziness_candidates("{ x }: let y = 1; in y").is_empty());
}

#[test]
fn full_laziness_does_not_scan_inside_rejected_lazy_binding_values() {
    assert!(full_laziness_candidates("x: let y = (let z = 1 + 2; in z); in y").is_empty());
}

#[test]
fn full_laziness_does_not_discover_lambdas_inside_rejected_lazy_binding_values() {
    assert!(full_laziness_candidates("x: let y = (z: let w = 1 + 2; in w); in y").is_empty());
}

#[test]
fn full_laziness_rejects_dynamic_scope_probes_as_closed_values() {
    let ir = lowered_with_dynamic_scope("x: with { y = x; }; let z = y; in z");
    let report = analyze_full_laziness(&ir).expect("full-laziness analysis succeeds");

    assert!(report.candidates.is_empty());
}

#[test]
fn full_laziness_keeps_effectful_root_thunks_conservative() {
    let mut symbols = SymbolTable::new();
    let arg = symbols.intern(b"x").expect("argument symbol interns");
    let binding = symbols.intern(b"y").expect("binding symbol interns");
    let nodes = vec![
        IrNode::new(
            IrKind::Int,
            Span::new(9, 10),
            EffectClass::pure(),
            IrData::Int(1),
        ),
        IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(9, 10),
            EffectClass::new(7, false),
            IrData::Node(IrId::new(0)),
        ),
        IrNode::new(
            IrKind::Int,
            Span::new(14, 15),
            EffectClass::pure(),
            IrData::Int(2),
        ),
        IrNode::new(
            IrKind::Let,
            Span::new(3, 15),
            EffectClass::pure(),
            IrData::Let {
                bindings: IrBindingSlice::new(0, 1),
                body: IrId::new(2),
                frame: None,
            },
        ),
        IrNode::new(
            IrKind::Formal,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Formal {
                name: arg,
                default: None,
            },
        ),
        IrNode::new(
            IrKind::Lambda,
            Span::new(0, 15),
            EffectClass::pure(),
            IrData::Lambda {
                pattern: IrId::new(4),
                body: IrId::new(3),
                frame: None,
            },
        ),
    ];
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
        root: IrId::new(5),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(binding),
            position: None,
            value: IrId::new(1),
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };

    let report = analyze_full_laziness(&ir).expect("full-laziness analysis succeeds");

    assert!(report.candidates.is_empty());
}

#[test]
fn full_laziness_keeps_dynamic_let_keys_conservative() {
    let mut symbols = SymbolTable::new();
    let arg = symbols.intern(b"x").expect("argument symbol interns");
    let nodes = vec![
        IrNode::new(
            IrKind::Int,
            Span::new(9, 10),
            EffectClass::pure(),
            IrData::Int(1),
        ),
        IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(9, 10),
            EffectClass::pure(),
            IrData::Node(IrId::new(0)),
        ),
        IrNode::new(
            IrKind::Int,
            Span::new(4, 5),
            EffectClass::pure(),
            IrData::Int(0),
        ),
        IrNode::new(
            IrKind::Int,
            Span::new(14, 15),
            EffectClass::pure(),
            IrData::Int(2),
        ),
        IrNode::new(
            IrKind::Let,
            Span::new(3, 15),
            EffectClass::pure(),
            IrData::Let {
                bindings: IrBindingSlice::new(0, 1),
                body: IrId::new(3),
                frame: None,
            },
        ),
        IrNode::new(
            IrKind::Formal,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Formal {
                name: arg,
                default: None,
            },
        ),
        IrNode::new(
            IrKind::Lambda,
            Span::new(0, 15),
            EffectClass::pure(),
            IrData::Lambda {
                pattern: IrId::new(5),
                body: IrId::new(4),
                frame: None,
            },
        ),
    ];
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
        root: IrId::new(6),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Dynamic(IrId::new(2)),
            position: None,
            value: IrId::new(1),
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };

    let report = analyze_full_laziness(&ir).expect("full-laziness analysis succeeds");

    assert!(report.candidates.is_empty());
}

#[test]
fn full_laziness_rejects_malformed_child_slices() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::List,
            Span::new(0, 2),
            EffectClass::pure(),
            IrData::Children(IrChildSlice::new(7, 1)),
        )],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
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

    let error = analyze_full_laziness(&ir).expect_err("invalid child slice errors");

    assert!(matches!(
        error,
        FullLazinessAnalysisError::InvalidChildSlice {
            id,
            slice,
        } if id == IrId::new(0) && slice == IrChildSlice::new(7, 1)
    ));
}

#[test]
fn full_laziness_rejects_invalid_attrset_shapes() {
    let mut symbols = SymbolTable::new();
    let shape_key = symbols.intern(b"shape").expect("shape symbol interns");
    let binding_key = symbols.intern(b"binding").expect("binding symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(12, 13),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 13),
                EffectClass::pure(),
                IrData::AttrSet {
                    shape: crate::ir::IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(binding_key),
            position: None,
            value: IrId::new(0),
        }]
        .into_boxed_slice(),
        shapes: vec![IrShape::new(vec![shape_key].into_boxed_slice())].into_boxed_slice(),
    };

    let error = analyze_full_laziness(&ir).expect_err("invalid attrset shape errors");

    assert!(matches!(
        error,
        FullLazinessAnalysisError::InvalidAttrSetShape {
            id,
            shape,
        } if id == IrId::new(1) && shape == crate::ir::IrShapeId::new(0)
    ));
}

#[test]
fn full_laziness_rejects_plain_attrset_frames() {
    let mut symbols = SymbolTable::new();
    let binding_key = symbols.intern(b"binding").expect("binding symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(12, 13),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 13),
                EffectClass::pure(),
                IrData::AttrSet {
                    shape: crate::ir::IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: Some(FrameId::new(0)),
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: vec![FrameInfo {
            slot_count: 0,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]
        .into_boxed_slice(),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(binding_key),
            position: None,
            value: IrId::new(0),
        }]
        .into_boxed_slice(),
        shapes: vec![IrShape::new(vec![binding_key].into_boxed_slice())].into_boxed_slice(),
    };

    let error = analyze_full_laziness(&ir).expect_err("plain attrset frame errors");

    assert!(matches!(
        error,
        FullLazinessAnalysisError::InvalidAttrSetFrame { id } if id == IrId::new(1)
    ));
}

#[test]
fn full_laziness_rejects_invalid_with_chains() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"x").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::DialectScopeVar {
                op: TEST_WITH_VAR_OP,
                site: IrInlineCacheSiteId::new(0),
                symbol,
                chain: 7,
            },
        )],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
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

    let error = analyze_full_laziness(&ir).expect_err("invalid with-chain errors");

    assert!(matches!(
        error,
        FullLazinessAnalysisError::InvalidWithChain {
            id,
            chain: 7,
        } if id == IrId::new(0)
    ));
}

#[test]
fn full_laziness_validates_with_chain_scope_nodes() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"x").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::DialectScopeVar {
                    op: TEST_WITH_VAR_OP,
                    site: IrInlineCacheSiteId::new(0),
                    symbol,
                    chain: 0,
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::None,
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
        root: IrId::new(0),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: vec![IrWithChain::new(vec![IrId::new(1)].into_boxed_slice())]
            .into_boxed_slice(),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = analyze_full_laziness(&ir).expect_err("invalid with-chain scope errors");

    assert!(matches!(
        error,
        FullLazinessAnalysisError::InvalidPayload {
            id,
            kind: IrKind::Int,
            expected: "integer payload",
        } if id == IrId::new(1)
    ));
}

#[test]
fn full_laziness_rejects_malformed_payloads() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::BinOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    let ir = Ir {
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

    let error = analyze_full_laziness(&ir).expect_err("invalid payload errors");

    assert!(matches!(
        error,
        FullLazinessAnalysisError::InvalidPayload {
            id,
            kind: IrKind::BinOp,
            expected: "binary payload",
        } if id == IrId::new(0)
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
fn escape_propagates_no_escape_bodies_to_strict_wrapping_thunks() {
    let mut ir = lowered("(x: x) (builtins.sub 3 1)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    let IrData::Node(body) = node(&ir, argument).data else {
        panic!("thunk body expected");
    };

    annotate_ir(&mut ir).expect("analysis succeeds");

    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
    assert_eq!(escape(&ir, body), Escape::NoEscape);
    assert_eq!(escape(&ir, argument), Escape::NoEscape);
}

#[test]
fn escape_marks_unreferenced_let_thunks_frame_local() {
    // No slot reference exists, so the reachability proof is vacuous: the
    // thunk dies with its frame. Sharing still resolves to omission through
    // the absent cardinality, never to single-entry storage.
    let mut ir = lowered("let x = builtins.sub 3 1; in 1");
    let binding = let_binding_values(&ir, ir.root)[0];
    let IrData::Node(body) = node(&ir, binding).data else {
        panic!("thunk body expected");
    };

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, body), Escape::NoEscape);
    assert_eq!(escape(&ir, binding), Escape::NoEscape);
}

#[test]
fn escape_keeps_direct_body_let_thunks_conservative() {
    // The result clause fails closed: an enclosing update thunk whose body
    // is this `let` caches the raw handle, and every cache re-read re-forces
    // it — a single-entry representation would re-evaluate. (This binding is
    // `DemandedBeforeEffect`, so its thunk elides eagerly anyway.)
    let mut ir = lowered("let x = builtins.sub 3 1; in x");
    let binding = let_binding_values(&ir, ir.root)[0];

    annotate_ir(&mut ir).expect("analysis succeeds");

    assert_eq!(cardinality(&ir, binding), Cardinality::Once);
    assert_eq!(escape(&ir, binding), Escape::Escapes);
    assert_eq!(
        frame_local_single_entry_thunk_downgrade(&ir, binding).expect("preflight succeeds"),
        FrameLocalThunkDowngrade::KeepUpdate(FrameLocalThunkUpdateReason::EscapesFrame)
    );
}

#[test]
fn escape_marks_consumed_position_let_thunks_frame_local() {
    // Every reference is forced in place during the frame's own execution:
    // operator operands, condition positions, select receivers, and
    // consumed-signature primop arguments.
    for source in [
        "let x = 1 + 2; in x + 1",
        "let x = 1 + 2; in if builtins.lessThan x 3 then 1 else 2",
        "let x = { a = 1; }; in x.a",
        "let x = [ 1 2 ]; in builtins.length x",
        "let x = 1 + 2; in builtins.lessThan 1 x",
    ] {
        let mut ir = lowered(source);
        let binding = let_binding_values(&ir, ir.root)[0];

        annotate_ir(&mut ir).expect("analysis succeeds");

        assert_eq!(escape(&ir, binding), Escape::NoEscape, "{source}");
    }
}

#[test]
fn escape_declines_retaining_position_let_thunks() {
    for source in [
        // Result flow: the frame result can be cached as a raw handle.
        "let x = 1 + 2; in x",
        "let x = 1 + 2; in if true then x else 1",
        // Containers retain their elements.
        "let x = 1 + 2; in [ x ]",
        "let x = 1 + 2; in { a = x; }",
        // Unknown call argument and callee (functor protocol).
        "let x = 1 + 2; in (f: f x) (y: y)",
        "let x = z: z; in x 1",
        // Closure capture (S7).
        "let x = 1 + 2; in (y: x + y) 1",
        // Retained-signature primop argument (interned attribute name).
        r#"let x = "a" + "b"; in builtins.hasAttr x { ab = 1; }"#,
        // Interning through string interpolation.
        r#"let x = 1 + 2; in "${toString x}""#,
        // `with` scrutinee is retained in the dynamic scope.
        "let x = { a = 1; }; in with x; 2",
    ] {
        let mut ir = lowered(source);
        let binding = let_binding_values(&ir, ir.root)[0];

        annotate_ir(&mut ir).expect("analysis succeeds");

        assert_eq!(escape(&ir, binding), Escape::Escapes, "{source}");
    }
}

#[test]
fn escape_declines_self_referential_and_sibling_captured_slots() {
    for source in [
        // Self-reference through the binding's own thunk body.
        "let x = x; in 1",
        // A sibling thunk body captures the slot beyond this execution.
        "let x = 1 + 2; y = x + 1; in 1",
    ] {
        let mut ir = lowered(source);
        let binding = let_binding_values(&ir, ir.root)[0];

        annotate_ir(&mut ir).expect("analysis succeeds");

        assert_eq!(escape(&ir, binding), Escape::Escapes, "{source}");
    }
}

#[test]
fn escape_keeps_let_thunks_published_into_lists_conservative() {
    let mut ir = lowered("let x = builtins.sub 3 1; in [ x ]");
    let binding = let_binding_values(&ir, ir.root)[0];

    annotate_ir(&mut ir).expect("analysis succeeds");

    assert_eq!(cardinality(&ir, binding), Cardinality::Once);
    assert_eq!(escape(&ir, binding), Escape::Escapes);
    assert_eq!(
        frame_local_single_entry_thunk_downgrade(&ir, binding).expect("preflight succeeds"),
        FrameLocalThunkDowngrade::KeepUpdate(FrameLocalThunkUpdateReason::EscapesFrame)
    );
}

#[test]
fn escape_keeps_let_thunks_captured_by_sibling_bindings_conservative() {
    let mut ir = lowered("let x = builtins.sub 3 1; y = x; in x");
    let binding = let_binding_values(&ir, ir.root)[0];

    annotate_ir(&mut ir).expect("analysis succeeds");

    assert_eq!(escape(&ir, binding), Escape::Escapes);
}

#[test]
fn escape_keeps_dynamic_key_direct_body_let_thunks_conservative() {
    let root = IrId::new(3);
    let (mut ir, thunk) = raw_direct_body_let_thunk_ir(root, None, Box::new([]));
    ir.bindings[0].key = IrAttrPathSegment::Dynamic(IrId::new(0));

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, thunk), Escape::Escapes);
}

#[test]
fn escape_keeps_raw_aliased_direct_body_let_thunks_conservative() {
    let thunk = IrId::new(1);
    let root = IrId::new(3);
    let (mut ir, thunk) = raw_direct_body_let_thunk_ir(root, Some(thunk), Box::new([]));

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, thunk), Escape::Escapes);
}

#[test]
fn escape_keeps_root_aliased_direct_body_let_thunks_conservative() {
    let thunk = IrId::new(1);
    let (mut ir, thunk) = raw_direct_body_let_thunk_ir(thunk, None, Box::new([]));

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, thunk), Escape::Escapes);
}

#[test]
fn escape_keeps_with_chain_aliased_direct_body_let_thunks_conservative() {
    let thunk = IrId::new(1);
    let root = IrId::new(3);
    let (mut ir, thunk) =
        raw_direct_body_let_thunk_ir(root, None, Box::new([IrWithChain::new(Box::new([thunk]))]));

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, thunk), Escape::Escapes);
}

fn raw_direct_body_let_thunk_ir(
    root: IrId,
    alias_child: Option<IrId>,
    with_chains: Box<[IrWithChain]>,
) -> (Ir, IrId) {
    let span = Span::new(0, 1);
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let body = IrId::new(0);
    let thunk = IrId::new(1);
    let local = IrId::new(2);
    let mut nodes = vec![
        IrNode::new(IrKind::Int, span, EffectClass::pure(), IrData::Int(1)),
        IrNode::new(
            IrKind::ThunkAlloc,
            span,
            EffectClass::pure(),
            IrData::Node(body),
        ),
        IrNode::new(
            IrKind::LocalVar,
            span,
            EffectClass::pure(),
            IrData::Local { slot: 0 },
        ),
        IrNode::new(
            IrKind::Let,
            span,
            EffectClass::pure(),
            IrData::Let {
                bindings: IrBindingSlice::new(0, 1),
                body: local,
                frame: None,
            },
        ),
    ];
    let mut children = Vec::new();
    if let Some(alias_child) = alias_child {
        children.push(alias_child);
        nodes.push(IrNode::new(
            IrKind::List,
            span,
            EffectClass::pure(),
            IrData::Children(IrChildSlice::new(0, 1)),
        ));
    }
    let arena = IrArena::from_raw_parts(nodes, children);
    let ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains,
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(x),
            position: None,
            value: thunk,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    (ir, thunk)
}

#[test]
fn escape_keeps_strict_and_captured_wrapping_thunks_conservative() {
    let mut ir = lowered("(x: builtins.seq x [ x ]) (builtins.sub 3 1)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    let IrData::Node(body) = node(&ir, argument).data else {
        panic!("thunk body expected");
    };

    annotate_ir(&mut ir).expect("analysis succeeds");

    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
    assert_eq!(escape(&ir, body), Escape::NoEscape);
    assert_eq!(escape(&ir, argument), Escape::Escapes);
}

#[test]
fn escape_marks_strict_unique_aggregate_scalar_primop_arguments_no_escape() {
    let mut length_ir = lowered("builtins.length [ (1 / 0) ]");
    let length_args = primop_args(&length_ir, length_ir.root);
    let list = length_args[0];

    annotate_ir(&mut length_ir).expect("analysis succeeds");

    assert_eq!(node(&length_ir, list).kind, IrKind::List);
    assert_eq!(strictness(&length_ir, list), Strictness::DemandedBeforeEffect);
    assert_eq!(escape(&length_ir, list), Escape::NoEscape);

    let mut has_attr_ir = lowered(r#"builtins.hasAttr "a" { a = 1; }"#);
    let has_attr_args = primop_args(&has_attr_ir, has_attr_ir.root);
    let attrset = has_attr_args[1];

    annotate_ir(&mut has_attr_ir).expect("analysis succeeds");

    assert_eq!(node(&has_attr_ir, attrset).kind, IrKind::AttrSet);
    assert_eq!(strictness(&has_attr_ir, attrset), Strictness::DemandedBeforeEffect);
    assert_eq!(escape(&has_attr_ir, attrset), Escape::NoEscape);
}

#[test]
fn escape_keeps_lazy_aggregate_scalar_primop_arguments_conservative() {
    let mut ir = lowered("let x = [ ]; in 1");
    let binding = let_binding_values(&ir, ir.root)[0];
    let IrData::Node(list) = node(&ir, binding).data else {
        panic!("thunk body expected");
    };

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(node(&ir, list).kind, IrKind::List);
    assert_eq!(strictness(&ir, list), Strictness::Unknown);
    assert_eq!(escape(&ir, list), Escape::Escapes);
}

#[test]
fn escape_keeps_shared_aggregate_scalar_primop_arguments_conservative() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::List,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(0, 0)),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 1),
                },
            ),
        ],
        vec![list],
    );
    let mut ir = Ir {
        root: list,
        arena,
        facts: IrFacts::conservative(2),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    ir.facts.get_mut(list).expect("list fact exists").strictness = Strictness::DemandedBeforeEffect;

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, list), Escape::Escapes);
    assert_eq!(escape(&ir, primop), Escape::NoEscape);
}

#[test]
fn escape_keeps_with_chain_aggregate_scalar_primop_arguments_conservative() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::List,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(0, 0)),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 1),
                },
            ),
        ],
        vec![list],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(2),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([IrWithChain::new(Box::new([list]))]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    ir.facts.get_mut(list).expect("list fact exists").strictness = Strictness::DemandedBeforeEffect;

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, list), Escape::Escapes);
    assert_eq!(escape(&ir, primop), Escape::NoEscape);
}

#[test]
fn escape_rejects_malformed_with_chain_scope_references_for_aggregates() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let missing_scope = IrId::new(99);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::List,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(0, 0)),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 1),
                },
            ),
        ],
        vec![list],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(2),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([IrWithChain::new(Box::new([missing_scope]))]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    ir.facts.get_mut(list).expect("list fact exists").strictness = Strictness::DemandedBeforeEffect;

    let error = annotate_escape(&mut ir).expect_err("malformed with-chain scope rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidNode { id: missing_scope }
    );
}

#[test]
fn escape_keeps_dynamic_attr_path_aggregate_scalar_primop_arguments_conservative() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let receiver = IrId::new(2);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::List,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(0, 0)),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 1),
                },
            ),
            IrNode::new(
                IrKind::Null,
                Span::new(3, 7),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::HasAttr,
                Span::new(0, 7),
                EffectClass::pure(),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path: IrAttrPathId::new(0),
                },
            ),
        ],
        vec![list],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(4),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Dynamic(list)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    ir.facts.get_mut(list).expect("list fact exists").strictness = Strictness::DemandedBeforeEffect;

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, list), Escape::Escapes);
    assert_eq!(escape(&ir, primop), Escape::NoEscape);
}

#[test]
fn escape_keeps_shared_strict_wrapping_thunks_conservative() {
    let body = IrId::new(0);
    let thunk = IrId::new(1);
    let aggregate = IrId::new(6);
    let mut ir = raw_identity_thunk_ir(aggregate, thunk, Box::new([]));

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, body), Escape::NoEscape);
    assert_eq!(escape(&ir, thunk), Escape::Escapes);
}

#[test]
fn escape_keeps_root_strict_wrapping_thunks_conservative() {
    let body = IrId::new(0);
    let thunk = IrId::new(1);
    let mut ir = raw_identity_thunk_ir(thunk, body, Box::new([]));

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, body), Escape::NoEscape);
    assert_eq!(escape(&ir, thunk), Escape::Escapes);
}

#[test]
fn escape_keeps_with_chain_strict_wrapping_thunks_conservative() {
    let body = IrId::new(0);
    let thunk = IrId::new(1);
    let apply = IrId::new(5);
    let mut ir =
        raw_identity_thunk_ir(apply, body, Box::new([IrWithChain::new(Box::new([thunk]))]));

    annotate_escape(&mut ir).expect("escape analysis succeeds");

    assert_eq!(escape(&ir, body), Escape::NoEscape);
    assert_eq!(escape(&ir, thunk), Escape::Escapes);
}

#[test]
fn escape_rejects_malformed_with_chain_scope_references_for_strict_thunks() {
    let body = IrId::new(0);
    let apply = IrId::new(5);
    let missing_scope = IrId::new(99);
    let mut ir = raw_identity_thunk_ir(
        apply,
        body,
        Box::new([IrWithChain::new(Box::new([missing_scope]))]),
    );

    let error = annotate_escape(&mut ir).expect_err("malformed with-chain scope rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidNode { id: missing_scope }
    );
}

fn raw_identity_thunk_ir(root: IrId, aggregate_child: IrId, with_chains: Box<[IrWithChain]>) -> Ir {
    let span = Span::new(0, 1);
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let body = IrId::new(0);
    let thunk = IrId::new(1);
    let pattern = IrId::new(2);
    let lambda_body = IrId::new(3);
    let lambda = IrId::new(4);
    let nodes = vec![
        IrNode::new(IrKind::Int, span, EffectClass::pure(), IrData::Int(1)),
        IrNode::new(
            IrKind::ThunkAlloc,
            span,
            EffectClass::pure(),
            IrData::Node(body),
        ),
        IrNode::new(
            IrKind::Formal,
            span,
            EffectClass::pure(),
            IrData::Formal {
                name: x,
                default: None,
            },
        ),
        IrNode::new(
            IrKind::LocalVar,
            span,
            EffectClass::pure(),
            IrData::Local { slot: 0 },
        ),
        IrNode::new(
            IrKind::Lambda,
            span,
            EffectClass::pure(),
            IrData::Lambda {
                pattern,
                body: lambda_body,
                frame: None,
            },
        ),
        IrNode::new(
            IrKind::Apply,
            span,
            EffectClass::pure(),
            IrData::Pair {
                first: lambda,
                second: thunk,
            },
        ),
        IrNode::new(
            IrKind::List,
            span,
            EffectClass::pure(),
            IrData::Children(IrChildSlice::new(0, 1)),
        ),
    ];
    let mut ir = Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, vec![aggregate_child]),
        facts: IrFacts::conservative(7),
        symbols,
        frames: Box::new([]),
        with_chains,
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    ir.facts
        .get_mut(thunk)
        .expect("thunk fact exists")
        .strictness = Strictness::DemandedBeforeEffect;
    ir
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
fn escape_rejects_malformed_aggregate_binding_value_references() {
    let attrset = IrId::new(0);
    let key_node = IrId::new(1);
    let primop = IrId::new(2);
    let missing_value = IrId::new(99);
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"a").expect("key symbol interns");
    let symbol = symbols.intern(b"hasAttr").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::AttrSet {
                    shape: crate::ir::IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
            IrNode::new(
                IrKind::Str,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Symbol(key),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 2),
                },
            ),
        ],
        vec![key_node, attrset],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(3),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([IrBinding {
            key: IrAttrPathSegment::Static(key),
            position: None,
            value: missing_value,
        }]),
        shapes: Box::new([IrShape::new(Box::new([key]))]),
    };
    ir.facts
        .get_mut(attrset)
        .expect("attrset fact exists")
        .strictness = Strictness::DemandedBeforeEffect;

    let error = annotate_escape(&mut ir).expect_err("malformed binding value rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidNode { id: missing_value }
    );
}

#[test]
fn escape_rejects_malformed_dynamic_binding_key_references() {
    let attrset = IrId::new(0);
    let value = IrId::new(1);
    let key_node = IrId::new(2);
    let primop = IrId::new(3);
    let missing_key = IrId::new(99);
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"a").expect("key symbol interns");
    let symbol = symbols.intern(b"hasAttr").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::AttrSet {
                    shape: crate::ir::IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: true,
                    frame: None,
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(4, 5),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Str,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Symbol(key),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 2),
                },
            ),
        ],
        vec![key_node, attrset],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(4),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([IrBinding {
            key: IrAttrPathSegment::Dynamic(missing_key),
            position: None,
            value,
        }]),
        shapes: Box::new([IrShape::new(Box::new([]))]),
    };
    ir.facts
        .get_mut(attrset)
        .expect("attrset fact exists")
        .strictness = Strictness::DemandedBeforeEffect;

    let error = annotate_escape(&mut ir).expect_err("malformed dynamic key rejects");

    assert_eq!(error, EscapeAnalysisError::InvalidNode { id: missing_key });
}

#[test]
fn escape_rejects_malformed_dynamic_attr_path_segment_references() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let receiver = IrId::new(2);
    let path = IrAttrPathId::new(0);
    let missing_segment = IrId::new(99);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::List,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(0, 0)),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 1),
                },
            ),
            IrNode::new(
                IrKind::Null,
                Span::new(3, 7),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::HasAttr,
                Span::new(0, 7),
                EffectClass::pure(),
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                },
            ),
        ],
        vec![list],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(4),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Dynamic(missing_segment)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    ir.facts.get_mut(list).expect("list fact exists").strictness = Strictness::DemandedBeforeEffect;

    let error = annotate_escape(&mut ir).expect_err("malformed attr path segment rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidNode {
            id: missing_segment
        }
    );
}

#[test]
fn escape_rejects_fact_table_length_mismatches() {
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
        .escape = Escape::NoEscape;

    let error = annotate_escape(&mut overlong).expect_err("overlong fact table rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 2,
        }
    );
    assert_eq!(escape(&overlong, IrId::new(1)), Escape::NoEscape);

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

    let error = annotate_escape(&mut short).expect_err("short fact table rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 0,
        }
    );
}

mod dead_binding;
mod escape_signature;
mod scalar_replacement;
mod strictness;
mod thunk_sharing;
mod worker_wrapper;
