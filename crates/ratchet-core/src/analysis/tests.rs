//! Tests for IR analysis passes.

mod split_1;
mod split_2;

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
    let mut slot_sets: Vec<Vec<(u16, u16)>> =
        lambdas.iter().map(|id| flat_plan_slots(&ir, *id)).collect();
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
    assert!(matches!(
        node(&ir, accesses[0].0).data,
        IrData::Upval { .. }
    ));
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
    let bindings = let_binding_values(&ir, {
        // The outer let's body is the inner let.
        let IrData::Let { body, .. } = node(&ir, ir.root).data else {
            panic!("outer let expected");
        };
        body
    });
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

mod chunk_e;
mod dead_binding;
mod escape_signature;
mod scalar_replacement;
mod strictness;
mod thunk_sharing;
mod worker_wrapper;
