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

    root_facts.strictness = Strictness::DemandedBeforeEffect;
    root_facts.cardinality = Cardinality::Once;
    root_facts.escape = Escape::NoEscape;

    assert_eq!(
        facts.get(root),
        Some(ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
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
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        })
    );
    assert_eq!(report.dependency_footprint.strict_nodes(), &[ir.root]);
    assert!(report.dependency_footprint.frame_captures().is_empty());
}

#[test]
fn annotate_ir_reports_dependency_footprint_in_canonical_order() {
    let mut branch_ir = lowered("if true then 1 else null");
    let IrData::Triple {
        first: condition,
        second: then_branch,
        third: else_branch,
    } = node(&branch_ir, branch_ir.root).data
    else {
        panic!("if payload expected");
    };
    let branch_root = branch_ir.root;

    let branch_report = annotate_ir(&mut branch_ir).expect("IR annotation succeeds");
    // Per-execution demand semantics also prove the branches: each inherits
    // the root's forced position on its own path.
    let mut expected_strict_nodes = vec![branch_root, condition, then_branch, else_branch];
    expected_strict_nodes.sort_by_key(|id| id.as_u32());

    assert_eq!(
        branch_report.dependency_footprint.strict_nodes(),
        expected_strict_nodes.as_slice()
    );
    assert!(
        branch_report
            .dependency_footprint
            .strict_nodes()
            .windows(2)
            .all(|window| window[0].as_u32() < window[1].as_u32())
    );

    let mut ir = lowered("let x = 1; f = y: x + y; in f 41");
    let report = annotate_ir(&mut ir).expect("IR annotation succeeds");
    assert_eq!(report.dependency_footprint.frame_captures().len(), 1);
    assert_eq!(
        report.dependency_footprint.frame_captures()[0].frame(),
        crate::FrameId::new(1)
    );
    assert_eq!(
        report.dependency_footprint.frame_captures()[0].captures(),
        &[crate::Upvalue { depth: 1, slot: 0 }]
    );
}

#[test]
fn annotate_ir_canonicalizes_raw_dependency_footprint_captures() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([
            crate::FrameInfo {
                slot_count: 0,
                captures: Box::new([]),
                rec: false,
                has_with: false,
            },
            crate::FrameInfo {
                slot_count: 2,
                captures: Box::new([
                    crate::Upvalue { depth: 2, slot: 1 },
                    crate::Upvalue { depth: 1, slot: 0 },
                    crate::Upvalue { depth: 1, slot: 0 },
                ]),
                rec: false,
                has_with: false,
            },
            crate::FrameInfo {
                slot_count: 1,
                captures: Box::new([
                    crate::Upvalue { depth: 3, slot: 0 },
                    crate::Upvalue { depth: 2, slot: 7 },
                ]),
                rec: false,
                has_with: false,
            },
        ]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let report = annotate_ir(&mut ir).expect("IR annotation succeeds");
    let frame_captures = report.dependency_footprint.frame_captures();

    assert_eq!(frame_captures.len(), 2);
    assert_eq!(frame_captures[0].frame(), crate::FrameId::new(1));
    assert_eq!(
        frame_captures[0].captures(),
        &[
            crate::Upvalue { depth: 1, slot: 0 },
            crate::Upvalue { depth: 2, slot: 1 }
        ]
    );
    assert_eq!(frame_captures[1].frame(), crate::FrameId::new(2));
    assert_eq!(
        frame_captures[1].captures(),
        &[
            crate::Upvalue { depth: 2, slot: 7 },
            crate::Upvalue { depth: 3, slot: 0 }
        ]
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
            strictness: Strictness::DemandedBeforeEffect,
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
        .strictness = Strictness::DemandedBeforeEffect;
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
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        }
        .binding_lowering(),
        BindingLowering::Eager
    );
    assert_eq!(
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
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
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Absent,
            escape: Escape::NoEscape,
        }
        .thunk_sharing(),
        ThunkSharing::Update
    );
}
