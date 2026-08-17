//! Dead-binding elimination planning tests.

use super::*;

fn set_facts(ir: &mut Ir, id: IrId, facts: ExprFacts) {
    *ir.facts.get_mut(id).expect("fact exists") = facts;
}

#[test]
fn dead_binding_plan_eliminates_absent_unknown_let_bindings() {
    let mut ir = lowered("let x = 1 / 0; y = 2; in y");
    annotate_cardinality(&mut ir).expect("cardinality analysis succeeds");
    let bindings = let_binding_values(&ir, ir.root);

    let plan = dead_binding_elimination_plan(&ir).expect("dead-binding plan succeeds");

    assert_eq!(plan.let_count(), 1);
    assert_eq!(plan.binding_count(), 2);
    assert_eq!(plan.eliminations().len(), 1);
    assert_eq!(plan.eliminations()[0].let_node(), ir.root);
    assert_eq!(plan.eliminations()[0].binding_index(), 0);
    assert_eq!(plan.eliminations()[0].value(), bindings[0]);
    assert_eq!(
        plan.eliminations()[0].replacement(),
        DeadBindingReplacement::DummyFrameSlot
    );
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(plan.retained()[0].binding_index(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        DeadBindingRetentionReason::RequiredByCardinality {
            cardinality: Cardinality::Once,
        }
    );
}

#[test]
fn dead_binding_plan_retains_many_use_bindings() {
    let mut ir = lowered("let x = 1 + 2; in x + x");
    annotate_cardinality(&mut ir).expect("cardinality analysis succeeds");

    let plan = dead_binding_elimination_plan(&ir).expect("dead-binding plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        DeadBindingRetentionReason::RequiredByCardinality {
            cardinality: Cardinality::Many,
        }
    );
}

#[test]
fn dead_binding_plan_retains_absent_strict_conflicts() {
    let mut ir = lowered("let x = 1 + 2; in 1");
    let binding = let_binding_values(&ir, ir.root)[0];
    set_facts(
        &mut ir,
        binding,
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        },
    );

    let plan = dead_binding_elimination_plan(&ir).expect("dead-binding plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        DeadBindingRetentionReason::AbsentButStrict
    );
}

#[test]
fn dead_binding_plan_retains_dynamic_binding_keys() {
    let key = IrId::new(0);
    let value = IrId::new(1);
    let root = IrId::new(2);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(4, 5),
                EffectClass::pure(),
                IrData::Int(2),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body: value,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut facts = IrFacts::conservative(arena.nodes().len());
    facts.get_mut(value).expect("value fact exists").cardinality = Cardinality::Absent;
    let ir = Ir {
        root,
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Dynamic(key),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };

    let plan = dead_binding_elimination_plan(&ir).expect("dead-binding plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(
        plan.retained()[0].reason(),
        DeadBindingRetentionReason::DynamicBindingKey { key }
    );
}

#[test]
fn dead_binding_plan_rejects_short_fact_tables() {
    let value = IrId::new(1);
    let root = IrId::new(2);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(4, 5),
                EffectClass::pure(),
                IrData::Int(2),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body: value,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"x").expect("symbol interns");
    let ir = Ir {
        root,
        arena,
        facts: IrFacts::conservative(1),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };

    let error = dead_binding_elimination_plan(&ir).expect_err("short fact table rejects");

    assert_eq!(
        error,
        DeadBindingEliminationError::InvalidFactTableLength {
            expected: 3,
            actual: 1,
        }
    );
}

#[test]
fn dead_binding_plan_rejects_overlong_fact_tables() {
    let key = IrId::new(0);
    let value = IrId::new(1);
    let root = IrId::new(2);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(4, 5),
                EffectClass::pure(),
                IrData::Int(2),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body: key,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let ir = Ir {
        root,
        arena,
        facts: IrFacts::conservative(4),
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Dynamic(key),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };

    let error = dead_binding_elimination_plan(&ir)
        .expect_err("overlong fact table rejects before planning");

    assert_eq!(
        error,
        DeadBindingEliminationError::InvalidFactTableLength {
            expected: 3,
            actual: 4,
        }
    );
}

#[test]
fn dead_binding_plan_rejects_invalid_static_key_symbols() {
    let value = IrId::new(0);
    let root = IrId::new(1);
    let symbol = crate::syntax::Symbol::new(99);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body: value,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        value,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        },
    );

    let error = dead_binding_elimination_plan(&ir).expect_err("invalid static key rejects");

    assert_eq!(error, DeadBindingEliminationError::InvalidSymbol { symbol });
}

#[test]
fn dead_binding_plan_rejects_malformed_absent_value_payloads() {
    let value = IrId::new(0);
    let body = IrId::new(1);
    let root = IrId::new(2);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(4, 8),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(13, 14),
                EffectClass::pure(),
                IrData::Int(7),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 14),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"dead").expect("symbol interns");
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        value,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        },
    );

    let error = dead_binding_elimination_plan(&ir).expect_err("malformed value rejects");

    assert_eq!(
        error,
        DeadBindingEliminationError::InvalidPayload {
            id: value,
            kind: IrKind::ThunkAlloc,
            expected: "thunk body",
        }
    );
}

#[test]
fn dead_binding_plan_rejects_dangling_absent_thunk_bodies() {
    let value = IrId::new(0);
    let body = IrId::new(1);
    let root = IrId::new(2);
    let missing_body = IrId::new(99);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(4, 8),
                EffectClass::pure(),
                IrData::Node(missing_body),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(13, 14),
                EffectClass::pure(),
                IrData::Int(7),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 14),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"dead").expect("symbol interns");
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        value,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        },
    );

    let error = dead_binding_elimination_plan(&ir).expect_err("dangling thunk body rejects");

    assert_eq!(
        error,
        DeadBindingEliminationError::InvalidNode { id: missing_body }
    );
}

#[test]
fn dead_binding_plan_retains_dangling_thunk_bodies_required_by_cardinality() {
    let value = IrId::new(0);
    let body = IrId::new(1);
    let root = IrId::new(2);
    let missing_body = IrId::new(99);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(4, 8),
                EffectClass::pure(),
                IrData::Node(missing_body),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(13, 14),
                EffectClass::pure(),
                IrData::Int(7),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 14),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"kept").expect("symbol interns");
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        value,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::Escapes,
        },
    );

    let plan = dead_binding_elimination_plan(&ir).expect("retained dangling thunk succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        DeadBindingRetentionReason::RequiredByCardinality {
            cardinality: Cardinality::Once,
        }
    );
}

#[test]
fn dead_binding_plan_retains_dangling_absent_but_strict_thunk_bodies() {
    let value = IrId::new(0);
    let body = IrId::new(1);
    let root = IrId::new(2);
    let missing_body = IrId::new(99);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(4, 8),
                EffectClass::pure(),
                IrData::Node(missing_body),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(13, 14),
                EffectClass::pure(),
                IrData::Int(7),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 14),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"strict").expect("symbol interns");
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        value,
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        },
    );

    let plan = dead_binding_elimination_plan(&ir).expect("strict dangling thunk succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        DeadBindingRetentionReason::AbsentButStrict
    );
}

#[test]
fn dead_binding_plan_retains_dangling_thunk_bodies_for_dynamic_keys() {
    let key = IrId::new(0);
    let value = IrId::new(1);
    let root = IrId::new(2);
    let missing_body = IrId::new(99);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(4, 8),
                EffectClass::pure(),
                IrData::Node(missing_body),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body: key,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Dynamic(key),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        value,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        },
    );

    let plan = dead_binding_elimination_plan(&ir).expect("dynamic-key dangling thunk succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        DeadBindingRetentionReason::DynamicBindingKey { key }
    );
}

#[test]
fn dead_binding_plan_rejects_invalid_dynamic_key_value_nodes() {
    let key = IrId::new(0);
    let value = IrId::new(99);
    let root = IrId::new(1);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body: key,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Dynamic(key),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };

    let error = dead_binding_elimination_plan(&ir)
        .expect_err("dynamic-key binding with invalid value node rejects");

    assert_eq!(
        error,
        DeadBindingEliminationError::InvalidNode { id: value }
    );
}

#[test]
fn dead_binding_plan_rejects_invalid_let_payloads() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Let,
            Span::new(0, 1),
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

    let error = dead_binding_elimination_plan(&ir).expect_err("invalid payload rejects");

    assert_eq!(
        error,
        DeadBindingEliminationError::InvalidPayload {
            id: IrId::new(0),
            kind: IrKind::Let,
            expected: "let payload",
        }
    );
}

#[test]
fn dead_binding_plan_rejects_missing_let_body_nodes() {
    let value = IrId::new(0);
    let root = IrId::new(1);
    let missing_body = IrId::new(99);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Let,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body: missing_body,
                    frame: None,
                },
            ),
        ],
        Vec::new(),
    );
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"x").expect("symbol interns");
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(symbol),
            position: None,
            value,
        }]
        .into_boxed_slice(),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        value,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        },
    );

    let error = dead_binding_elimination_plan(&ir).expect_err("missing let body rejects");

    assert_eq!(
        error,
        DeadBindingEliminationError::InvalidNode { id: missing_body }
    );
}
