//! Split-out `tests.rs` test group (split_2).

use super::*;

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

