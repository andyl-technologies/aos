//! Tests for per-node IR analysis facts.

use super::*;

#[test]
fn expr_facts_default_to_conservative_choices() {
    let facts = ExprFacts::default();

    assert_eq!(facts.strictness, Strictness::Unknown);
    assert_eq!(facts.cardinality, Cardinality::Many);
    assert_eq!(facts.escape, Escape::Escapes);
    assert_eq!(facts, ExprFacts::conservative());
    assert_eq!(facts.binding_lowering(), BindingLowering::Thunk);
    assert_eq!(facts.thunk_sharing(), ThunkSharing::Update);
}

#[test]
fn lowered_ir_carries_conservative_facts_for_each_node() {
    let ir = lowered("let x = 1 + 2; in x");

    assert_eq!(ir.facts.len(), ir.arena.nodes().len());
    assert!(!ir.facts.is_empty());
    assert!(
        ir.facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative())
    );
    assert_eq!(ir.node_facts(ir.root), Some(ExprFacts::conservative()));
    assert_eq!(ir.node_facts(IrId::new(u32::MAX)), None);
}

#[test]
fn fact_table_is_mutable_by_ir_id_for_future_analysis_passes() {
    let mut facts = IrFacts::conservative(2);
    let root = IrId::new(1);
    let root_facts = facts.get_mut(root).expect("root fact exists");

    root_facts.strictness = Strictness::Strict;
    root_facts.cardinality = Cardinality::Once;
    root_facts.escape = Escape::NoEscape;

    assert_eq!(
        facts.get(root),
        Some(ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        })
    );
    assert_eq!(facts.get(IrId::new(3)), None);
}

#[test]
fn annotate_ir_runs_current_fact_producers() {
    let mut ir = lowered("1");

    let report = annotate_ir(&mut ir).expect("IR annotation succeeds");

    assert_eq!(report.strictness.nodes_marked_strict, 1);
    assert_eq!(report.cardinality.nodes_marked_absent, 0);
    assert_eq!(report.cardinality.nodes_marked_once, 0);
    assert_eq!(report.escape.nodes_marked_no_escape, 1);
    assert_eq!(
        ir.node_facts(ir.root),
        Some(ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        })
    );
}

#[test]
fn annotate_ir_refreshes_from_conservative_facts() {
    let mut ir = lowered("\"value\"");
    let root_facts = ir.facts.get_mut(ir.root).expect("root fact exists");
    root_facts.cardinality = Cardinality::Absent;
    root_facts.escape = Escape::NoEscape;

    annotate_ir(&mut ir).expect("IR annotation succeeds");

    assert_eq!(
        ir.node_facts(ir.root),
        Some(ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        })
    );
}

#[test]
fn annotate_ir_leaves_conservative_facts_after_analysis_error() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let mut facts = IrFacts::conservative(arena.nodes().len());
    facts
        .get_mut(IrId::new(0))
        .expect("root fact exists")
        .strictness = Strictness::Strict;
    facts
        .get_mut(IrId::new(0))
        .expect("root fact exists")
        .cardinality = Cardinality::Absent;
    facts
        .get_mut(IrId::new(0))
        .expect("root fact exists")
        .escape = Escape::NoEscape;
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

    let error = annotate_ir(&mut ir).expect_err("invalid payload errors");

    assert!(error.to_string().contains("invalid payload"));
    assert_eq!(ir.node_facts(ir.root), Some(ExprFacts::conservative()));
}

#[test]
fn binding_lowering_requires_positive_strictness_and_escape_proofs() {
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        }
        .binding_lowering(),
        BindingLowering::Thunk
    );
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        }
        .binding_lowering(),
        BindingLowering::Eager
    );
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        }
        .binding_lowering(),
        BindingLowering::Scalar
    );
}

#[test]
fn thunk_sharing_requires_cardinality_and_frame_locality_proofs() {
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::Escapes,
        }
        .thunk_sharing(),
        ThunkSharing::Update
    );
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        }
        .thunk_sharing(),
        ThunkSharing::Update
    );
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        }
        .thunk_sharing(),
        ThunkSharing::SingleEntry
    );
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        }
        .thunk_sharing(),
        ThunkSharing::Omit
    );
    assert_eq!(
        ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Absent,
            escape: Escape::NoEscape,
        }
        .thunk_sharing(),
        ThunkSharing::Update
    );
}
