//! Single-entry thunk downgrade tests.

use super::*;

fn first_let_binding_value(source: &str) -> (Ir, IrId) {
    let ir = lowered(source);
    let binding = let_binding_values(&ir, ir.root)[0];
    assert_eq!(node(&ir, binding).kind, IrKind::ThunkAlloc);
    (ir, binding)
}

fn set_facts(ir: &mut Ir, id: IrId, facts: ExprFacts) {
    *ir.facts.get_mut(id).expect("fact exists") = facts;
}

fn thunk_body(ir: &Ir, id: IrId) -> IrId {
    let IrData::Node(body) = node(ir, id).data else {
        panic!("thunk body expected");
    };
    body
}

#[test]
fn single_entry_downgrade_requires_once_and_no_escape() {
    let (mut ir, thunk) = first_let_binding_value("let x = 1 + 2; in x");
    let body = thunk_body(&ir, thunk);
    set_facts(
        &mut ir,
        thunk,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        },
    );

    let decision =
        frame_local_single_entry_thunk_downgrade(&ir, thunk).expect("downgrade preflight succeeds");

    let FrameLocalThunkDowngrade::SingleEntry(single_entry) = decision else {
        panic!("single-entry downgrade expected");
    };
    assert_eq!(single_entry.thunk(), thunk);
    assert_eq!(single_entry.body(), body);
}

#[test]
fn escaping_once_thunk_keeps_update_state() {
    let (mut ir, thunk) = first_let_binding_value("let x = 1 + 2; in x");
    set_facts(
        &mut ir,
        thunk,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::Escapes,
        },
    );

    let decision =
        frame_local_single_entry_thunk_downgrade(&ir, thunk).expect("downgrade preflight succeeds");

    assert_eq!(
        decision,
        FrameLocalThunkDowngrade::KeepUpdate(FrameLocalThunkUpdateReason::EscapesFrame)
    );
}

#[test]
fn frame_local_many_entry_thunk_keeps_update_state() {
    let (mut ir, thunk) = first_let_binding_value("let x = 1 + 2; in x + x");
    set_facts(
        &mut ir,
        thunk,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        },
    );

    let decision =
        frame_local_single_entry_thunk_downgrade(&ir, thunk).expect("downgrade preflight succeeds");

    assert_eq!(
        decision,
        FrameLocalThunkDowngrade::KeepUpdate(FrameLocalThunkUpdateReason::CardinalityNotOnce {
            cardinality: Cardinality::Many
        })
    );
}

#[test]
fn absent_unknown_thunk_is_omitted_not_single_entry() {
    let (mut ir, thunk) = first_let_binding_value("let x = 1 / 0; in 1");
    set_facts(
        &mut ir,
        thunk,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::NoEscape,
        },
    );

    let decision =
        frame_local_single_entry_thunk_downgrade(&ir, thunk).expect("downgrade preflight succeeds");

    assert_eq!(decision, FrameLocalThunkDowngrade::Omit);
}

#[test]
fn absent_strict_conflict_keeps_update_state() {
    let (mut ir, thunk) = first_let_binding_value("let x = 1 + 2; in x");
    set_facts(
        &mut ir,
        thunk,
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Absent,
            escape: Escape::NoEscape,
        },
    );

    let decision =
        frame_local_single_entry_thunk_downgrade(&ir, thunk).expect("downgrade preflight succeeds");

    assert_eq!(
        decision,
        FrameLocalThunkDowngrade::KeepUpdate(FrameLocalThunkUpdateReason::AbsentButStrict)
    );
}

#[test]
fn non_thunk_nodes_are_rejected() {
    let ir = lowered("1 + 2");

    let error =
        frame_local_single_entry_thunk_downgrade(&ir, ir.root).expect_err("non-thunk nodes reject");

    assert!(matches!(
        error,
        FrameLocalThunkDowngradeError::NotThunkAlloc {
            id,
            kind: IrKind::BinOp,
        } if id == ir.root
    ));
}

#[test]
fn malformed_thunk_payload_is_rejected() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
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

    let error = frame_local_single_entry_thunk_downgrade(&ir, ir.root)
        .expect_err("malformed thunk payload rejects");

    assert_eq!(
        error,
        FrameLocalThunkDowngradeError::InvalidPayload {
            id: ir.root,
            expected: "thunk body"
        }
    );
}

#[test]
fn dangling_thunk_body_is_rejected() {
    let missing_body = IrId::new(999);
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Node(missing_body),
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
    set_facts(
        &mut ir,
        root,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        },
    );

    let error = frame_local_single_entry_thunk_downgrade(&ir, root)
        .expect_err("dangling thunk body rejects");

    assert_eq!(
        error,
        FrameLocalThunkDowngradeError::MissingThunkBody {
            id: root,
            body: missing_body
        }
    );
}

#[test]
fn self_referential_thunk_body_is_rejected() {
    let root = IrId::new(0);
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Node(root),
        )],
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
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        root,
        ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        },
    );

    let error = frame_local_single_entry_thunk_downgrade(&ir, root)
        .expect_err("self-referential thunk body rejects");

    assert_eq!(
        error,
        FrameLocalThunkDowngradeError::SelfReferentialThunkBody { id: root }
    );
}
