//! Split-out `tests.rs` test group (split_1).

use super::*;

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
fn full_laziness_rejects_scoped_global_probes_and_applications() {
    for source in ["x: let y = __nixPath; in y", "x: let y = typeOf 1; in y"] {
        assert!(
            full_laziness_candidates(source).is_empty(),
            "{source} must not float across scoped-global changes"
        );
    }
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
