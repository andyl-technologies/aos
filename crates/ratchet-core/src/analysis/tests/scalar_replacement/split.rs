//! Split-out `scalar_replacement.rs` test group (split).

use super::*;

#[test]
fn scalar_replacement_plan_retains_dynamic_attr_path_aggregate_despite_forged_proofs() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let receiver = IrId::new(2);
    let has_attr = IrId::new(3);
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
    set_facts(&mut ir, list, strict_no_escape());

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert_eq!(has_attr, IrId::new(3));
    assert_eq!(plan.aggregate_candidate_count(), 0);
    assert!(
        !plan
            .replacements()
            .iter()
            .any(|replacement| replacement.node() == list)
    );
    assert!(plan.retained().iter().any(|retention| {
        retention.node() == list
            && retention.reason()
                == ScalarReplacementRetentionReason::UnsupportedAggregateConsumer {
                    kind: IrKind::List,
                }
    }));
}

#[test]
fn scalar_replacement_plan_rejects_invalid_attr_path_ids() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let receiver = IrId::new(2);
    let has_attr = IrId::new(3);
    let path = IrAttrPathId::new(5);
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
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("invalid attr path id rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidAttrPath { id: has_attr, path }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_dynamic_attr_path_segments() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let receiver = IrId::new(2);
    let missing = IrId::new(99);
    let path = IrAttrPathId::new(0);
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
        attr_paths: vec![vec![IrAttrPathSegment::Dynamic(missing)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("malformed attr path segment rejects");

    assert_eq!(error, ScalarReplacementError::InvalidNode { id: missing });
}

#[test]
fn scalar_replacement_plan_retains_aggregate_consumed_by_conservative_primop() {
    let mut ir = lowered("builtins.seq [ 1 ] true");
    let args = primop_args(&ir, ir.root);
    let list = args[0];
    set_facts(&mut ir, list, strict_no_escape());

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert_eq!(plan.aggregate_candidate_count(), 0);
    assert!(
        !plan
            .replacements()
            .iter()
            .any(|replacement| replacement.node() == list)
    );
    assert!(plan.retained().iter().any(|retention| {
        retention.node() == list
            && retention.reason()
                == ScalarReplacementRetentionReason::UnsupportedAggregateConsumer {
                    kind: IrKind::List,
                }
    }));
}

#[test]
fn scalar_replacement_plan_retains_conservative_primops_despite_facts() {
    let mut ir = lowered("builtins.toString 1");
    let root = ir.root;
    assert_eq!(node(&ir, root).kind, IrKind::PrimOp);
    set_facts(&mut ir, root, strict_no_escape());

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.scalar_candidate_count(), 1);
    assert!(plan.retained().iter().any(|retention| {
        retention.node() == root
            && retention.reason()
                == ScalarReplacementRetentionReason::UnsupportedNodeKind {
                    kind: IrKind::PrimOp,
                }
    }));
}

#[test]
fn scalar_replacement_plan_rejects_missing_primop_child_nodes() {
    let missing = IrId::new(99);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"isInt").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp {
                symbol,
                args: IrChildSlice::new(0, 1),
            },
        )],
        vec![missing],
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    let root = ir.root;
    set_facts(&mut ir, root, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("missing primop child rejects");

    assert_eq!(error, ScalarReplacementError::InvalidNode { id: missing });
}

#[test]
fn scalar_replacement_plan_rejects_invalid_primop_child_slices() {
    let args = IrChildSlice::new(1, 1);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"isInt").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp { symbol, args },
        )],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    let root = ir.root;
    set_facts(&mut ir, root, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("invalid primop child slice rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidChildSlice {
            id: root,
            slice: args
        }
    );
}

#[test]
fn scalar_replacement_plan_rejects_invalid_primop_symbols() {
    let symbol = crate::syntax::Symbol::new(99);
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp {
                symbol,
                args: IrChildSlice::new(0, 0),
            },
        )],
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
    let root = ir.root;
    set_facts(&mut ir, root, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("invalid primop symbol rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidSymbol { id: root, symbol }
    );
}

#[test]
fn scalar_replacement_plan_rejects_wrong_arity_primop_scalars() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"isInt").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp {
                symbol,
                args: IrChildSlice::new(0, 0),
            },
        )],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    let root = ir.root;
    set_facts(&mut ir, root, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("wrong primop arity rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidPrimOpArity {
            id: root,
            symbol,
            expected: 1,
            actual: 0
        }
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
