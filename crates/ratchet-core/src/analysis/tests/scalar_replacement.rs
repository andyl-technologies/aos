//! Scalar replacement planning tests.

use super::*;

fn set_facts(ir: &mut Ir, id: IrId, facts: ExprFacts) {
    *ir.facts.get_mut(id).expect("fact exists") = facts;
}

fn strict_no_escape() -> ExprFacts {
    ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
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
            strictness: Strictness::DemandedBeforeEffect,
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
            strictness: Strictness::DemandedBeforeEffect,
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
fn scalar_replacement_plan_rejects_fact_table_length_mismatches() {
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
    set_facts(&mut overlong, IrId::new(1), strict_no_escape());

    let error = scalar_replacement_plan(&overlong).expect_err("overlong fact table rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidFactTableLength {
            expected: 1,
            actual: 2,
        }
    );

    let short = Ir {
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

    let error = scalar_replacement_plan(&short).expect_err("short fact table rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidFactTableLength {
            expected: 1,
            actual: 0,
        }
    );
}

#[test]
fn scalar_replacement_plan_admits_strict_no_escape_primop_scalars() {
    let mut ir = annotate_allocations("builtins.isInt 1");
    let root = ir.root;
    assert_eq!(node(&ir, root).kind, IrKind::PrimOp);
    ir.facts.get_mut(root).expect("root fact exists").strictness = Strictness::DemandedBeforeEffect;

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert_eq!(plan.scalar_candidate_count(), 2);
    assert_eq!(plan.replacements().len(), 1);
    assert_eq!(plan.replacements()[0].node(), root);
    assert_eq!(
        plan.replacements()[0].kind(),
        ScalarReplacementKind::PrimOpImmediateScalar
    );
}

#[test]
fn scalar_replacement_plan_admits_strict_no_escape_aggregate_scalar_primop_arguments() {
    let mut length_ir = lowered("builtins.length [ (1 / 0) ]");
    let length_args = primop_args(&length_ir, length_ir.root);
    let list = length_args[0];

    annotate_ir(&mut length_ir).expect("analysis succeeds");
    let length_plan =
        scalar_replacement_plan(&length_ir).expect("scalar replacement plan succeeds");

    assert_eq!(length_plan.aggregate_candidate_count(), 1);
    assert!(
        length_plan
            .replacements()
            .iter()
            .any(|replacement| replacement.node() == list
                && replacement.kind() == ScalarReplacementKind::ListAggregate)
    );
    assert!(
        length_plan
            .replacements()
            .iter()
            .any(|replacement| replacement.node() == length_ir.root
                && replacement.kind() == ScalarReplacementKind::PrimOpImmediateScalar)
    );

    let mut has_attr_ir = lowered(r#"builtins.hasAttr "a" { a = 1; }"#);
    let has_attr_args = primop_args(&has_attr_ir, has_attr_ir.root);
    let attrset = has_attr_args[1];

    annotate_ir(&mut has_attr_ir).expect("analysis succeeds");
    let has_attr_plan =
        scalar_replacement_plan(&has_attr_ir).expect("scalar replacement plan succeeds");

    assert_eq!(has_attr_plan.aggregate_candidate_count(), 1);
    assert!(
        has_attr_plan
            .replacements()
            .iter()
            .any(|replacement| replacement.node() == attrset
                && replacement.kind() == ScalarReplacementKind::AttrSetAggregate)
    );
}

#[test]
fn scalar_replacement_plan_retains_shared_aggregate_despite_forged_proofs() {
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
    set_facts(&mut ir, list, strict_no_escape());

    let plan = scalar_replacement_plan(&ir).expect("scalar replacement plan succeeds");

    assert_eq!(primop, IrId::new(1));
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
fn scalar_replacement_plan_rejects_malformed_list_aggregate_payloads() {
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
                IrData::None,
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
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("malformed list payload rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidPayload {
            id: list,
            kind: IrKind::List,
            expected: "list child slice"
        }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_list_aggregate_children() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let missing_child = IrId::new(99);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::List,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(0, 1)),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(1, 1),
                },
            ),
        ],
        vec![missing_child, list],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(2),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("malformed list child rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidNode { id: missing_child }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_unrelated_child_slices_during_aggregate_scan() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let unrelated = IrId::new(2);
    let missing_child = IrId::new(99);
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
                IrKind::List,
                Span::new(3, 5),
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(1, 1)),
            ),
        ],
        vec![list, missing_child],
    );
    let mut ir = Ir {
        root: primop,
        arena,
        facts: IrFacts::conservative(3),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir)
        .expect_err("malformed unrelated child slice rejects during aggregate scan");

    assert_eq!(unrelated, IrId::new(2));
    assert_eq!(
        error,
        ScalarReplacementError::InvalidNode { id: missing_child }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_attrset_aggregate_bindings() {
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
    set_facts(&mut ir, attrset, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("malformed attrset binding rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidNode { id: missing_value }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_unrelated_dynamic_keys_during_aggregate_scan() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let attrset = IrId::new(2);
    let value = IrId::new(3);
    let missing_key = IrId::new(99);
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
                IrKind::AttrSet,
                Span::new(3, 8),
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
                IrKind::Null,
                Span::new(6, 7),
                EffectClass::pure(),
                IrData::None,
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
        bindings: Box::new([IrBinding {
            key: IrAttrPathSegment::Dynamic(missing_key),
            position: None,
            value,
        }]),
        shapes: Box::new([IrShape::new(Box::new([]))]),
    };
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir)
        .expect_err("malformed unrelated dynamic key rejects during aggregate scan");

    assert_eq!(attrset, IrId::new(2));
    assert_eq!(
        error,
        ScalarReplacementError::InvalidNode { id: missing_key }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_unrelated_binding_values_during_aggregate_scan() {
    let list = IrId::new(0);
    let primop = IrId::new(1);
    let attrset = IrId::new(2);
    let missing_value = IrId::new(99);
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"a").expect("key symbol interns");
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
                IrKind::AttrSet,
                Span::new(3, 8),
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
        vec![list],
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
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir)
        .expect_err("malformed unrelated binding value rejects during aggregate scan");

    assert_eq!(attrset, IrId::new(2));
    assert_eq!(
        error,
        ScalarReplacementError::InvalidNode { id: missing_value }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_attrset_aggregate_shapes() {
    let attrset = IrId::new(0);
    let key_node = IrId::new(1);
    let primop = IrId::new(2);
    let shape = crate::ir::IrShapeId::new(7);
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
                    shape,
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
            value: key_node,
        }]),
        shapes: Box::new([]),
    };
    set_facts(&mut ir, attrset, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("malformed attrset shape rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidShape { id: attrset, shape }
    );
}

#[test]
fn scalar_replacement_plan_rejects_malformed_attrset_aggregate_binding_slices() {
    let attrset = IrId::new(0);
    let key_node = IrId::new(1);
    let primop = IrId::new(2);
    let bindings = IrBindingSlice::new(1, 1);
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
                    bindings,
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
            value: key_node,
        }]),
        shapes: Box::new([IrShape::new(Box::new([key]))]),
    };
    set_facts(&mut ir, attrset, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("malformed binding slice rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidBindingSlice {
            id: attrset,
            slice: bindings
        }
    );
}

#[test]
fn scalar_replacement_plan_retains_with_chain_aggregate_despite_forged_proofs() {
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
fn scalar_replacement_plan_rejects_malformed_with_chain_scope_references() {
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
    set_facts(&mut ir, list, strict_no_escape());

    let error = scalar_replacement_plan(&ir).expect_err("malformed with-chain scope rejects");

    assert_eq!(
        error,
        ScalarReplacementError::InvalidNode { id: missing_scope }
    );
}

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
