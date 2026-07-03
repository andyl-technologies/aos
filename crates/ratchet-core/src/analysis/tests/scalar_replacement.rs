//! Scalar replacement planning tests.

use super::*;

fn set_facts(ir: &mut Ir, id: IrId, facts: ExprFacts) {
    *ir.facts.get_mut(id).expect("fact exists") = facts;
}

fn strict_no_escape() -> ExprFacts {
    ExprFacts {
        strictness: Strictness::Strict,
        cardinality: Cardinality::Many,
        escape: Escape::NoEscape,
    }
}

#[test]
fn scalar_replacement_plan_admits_strict_no_escape_scalars() {
    let mut ir = lowered("if true then 1 else null");
    let IrData::Triple {
        first,
        second,
        third,
    } = node(&ir, ir.root).data
    else {
        panic!("if payload expected");
    };
    for id in [first, second, third] {
        set_facts(&mut ir, id, strict_no_escape());
    }

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert_eq!(plan.node_count(), ir.arena.nodes().len());
    assert_eq!(plan.scalar_candidate_count(), 3);
    assert_eq!(plan.replacements().len(), 3);
    assert_eq!(plan.replacements()[0].node(), first);
    assert_eq!(plan.replacements()[0].kind(), ScalarReplacementKind::Bool);
    assert_eq!(plan.replacements()[1].node(), second);
    assert_eq!(plan.replacements()[1].kind(), ScalarReplacementKind::Int);
    assert_eq!(plan.replacements()[2].node(), third);
    assert_eq!(plan.replacements()[2].kind(), ScalarReplacementKind::Null);
    assert!(plan.retained().is_empty());
}

#[test]
fn scalar_replacement_plan_retains_scalars_without_required_proofs() {
    let mut ir = lowered("1.5");
    let root = ir.root;
    set_facts(
        &mut ir,
        root,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        },
    );

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.scalar_candidate_count(), 1);
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(plan.retained()[0].node(), root);
    assert_eq!(
        plan.retained()[0].reason(),
        ScalarReplacementRetentionReason::MissingProofs {
            strictness: Strictness::Unknown,
            escape: Escape::NoEscape
        }
    );
}

#[test]
fn scalar_replacement_plan_retains_scalars_without_escape_proof() {
    let mut ir = lowered("1");
    let root = ir.root;
    set_facts(
        &mut ir,
        root,
        ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        },
    );

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.scalar_candidate_count(), 1);
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(plan.retained()[0].node(), root);
    assert_eq!(
        plan.retained()[0].reason(),
        ScalarReplacementRetentionReason::MissingProofs {
            strictness: Strictness::Strict,
            escape: Escape::Escapes
        }
    );
}

#[test]
fn scalar_replacement_plan_retains_unsupported_strict_no_escape_nodes() {
    let mut ir = lowered("\"value\"");
    let root = ir.root;
    set_facts(&mut ir, root, strict_no_escape());

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.scalar_candidate_count(), 0);
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(plan.retained()[0].node(), root);
    assert_eq!(
        plan.retained()[0].reason(),
        ScalarReplacementRetentionReason::UnsupportedNodeKind { kind: IrKind::Str }
    );
}

#[test]
fn scalar_replacement_plan_rejects_missing_facts() {
    let ir = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )],
            Vec::new(),
        ),
        facts: IrFacts::conservative(0),
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = scalar_replacement_plan(&ir).expect_err("missing facts reject");

    assert_eq!(
        error,
        ScalarReplacementError::MissingFact { id: IrId::new(0) }
    );
}

#[test]
fn scalar_replacement_plan_rejects_invalid_scalar_payloads() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let ir = Ir {
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

    let error = scalar_replacement_plan(&ir).expect_err("invalid scalar payload rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidPayload {
            id: IrId::new(0),
            kind: IrKind::Bool,
            expected: "boolean payload"
        }
    );
}
