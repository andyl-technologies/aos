//! Tree-walk evaluator tests: attrs 3.

use super::*;

#[test]
fn invalid_with_chain_metadata_is_reported() {
    let mut symbols = SymbolTable::new();
    let missing = symbols.intern(b"missing").expect("symbol interns");
    let root = IrId::new(0);
    let span = Span::new(0, 7);
    let invalid_chain = manual_ir_with_with_chains(
        root,
        vec![pure_node(
            IrKind::PrimOp,
            span,
            IrData::DialectScopeVar {
                op: aos_nix_dialect::NIX_OP_WITH_VAR,
                site: IrInlineCacheSiteId::new(0),
                symbol: missing,
                chain: 0,
            },
        )],
        symbols.clone(),
        Vec::new(),
    );
    let error = eval_whnf(&invalid_chain).expect_err("missing with chain is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidWithChain { id: root, chain: 0 }
    );
    assert_eq!(error.span(), span);

    let scope = IrId::new(1);
    let missing_scope = manual_ir_with_with_chains(
        root,
        vec![
            pure_node(
                IrKind::PrimOp,
                span,
                IrData::DialectScopeVar {
                    op: aos_nix_dialect::NIX_OP_WITH_VAR,
                    site: IrInlineCacheSiteId::new(0),
                    symbol: missing,
                    chain: 0,
                },
            ),
            pure_node(IrKind::AttrSet, Span::new(10, 12), IrData::None),
        ],
        symbols,
        vec![IrWithChain::new(vec![scope].into_boxed_slice())],
    );
    let error = eval_whnf(&missing_scope).expect_err("inactive with scope is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingWithScope { id: root, scope }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_environment_accesses_are_reported() {
    let root = IrId::new(0);
    let span = Span::new(0, 1);
    let local_ir = manual_ir(
        root,
        vec![pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 })],
    );
    let local_error = eval_whnf(&local_ir).expect_err("local needs an environment");

    assert_eq!(
        local_error.kind(),
        TreeWalkErrorKind::MissingEnvironment { id: root }
    );
    assert_eq!(local_error.span(), span);

    let upval_ir = manual_ir(
        root,
        vec![pure_node(
            IrKind::UpvalVar,
            span,
            IrData::Upval { depth: 0, slot: 0 },
        )],
    );
    let upval_error = eval_whnf(&upval_ir).expect_err("upvalue needs an environment");

    assert_eq!(
        upval_error.kind(),
        TreeWalkErrorKind::InvalidUpvalueDepth {
            id: root,
            depth: 0,
            frames: 0,
        }
    );
    assert_eq!(upval_error.span(), span);
}

#[test]
fn invalid_let_frame_metadata_is_reported() {
    let root = IrId::new(0);
    let body = IrId::new(1);
    let span = Span::new(0, 10);
    let missing_frame = manual_ir(
        root,
        vec![
            pure_node(
                IrKind::Let,
                span,
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 0),
                    body,
                    frame: None,
                },
            ),
            pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
        ],
    );
    let missing_error = eval_whnf(&missing_frame).expect_err("let frame metadata must exist");

    assert_eq!(
        missing_error.kind(),
        TreeWalkErrorKind::MissingFrameMetadata { id: root }
    );
    assert_eq!(missing_error.span(), span);

    let frame = FrameId::new(0);
    let invalid_frame = manual_ir(
        root,
        vec![
            pure_node(
                IrKind::Let,
                span,
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 0),
                    body,
                    frame: Some(frame),
                },
            ),
            pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
        ],
    );
    let invalid_error = eval_whnf(&invalid_frame).expect_err("frame id must resolve");

    assert_eq!(
        invalid_error.kind(),
        TreeWalkErrorKind::InvalidFrameId {
            id: root,
            frame: frame.as_u32(),
        }
    );
    assert_eq!(invalid_error.span(), span);
}

#[test]
fn dead_binding_elision_preflights_malformed_thunk_payload() {
    let mut symbols = SymbolTable::new();
    let dead_key = symbols.intern(b"dead").expect("symbol interns");
    let dead = IrId::new(0);
    let body = IrId::new(1);
    let root = IrId::new(2);
    let frame = FrameId::new(0);
    let dead_span = Span::new(4, 8);
    let arena = IrArena::from_raw_parts(
        vec![
            pure_node(IrKind::ThunkAlloc, dead_span, IrData::None),
            pure_node(IrKind::Int, Span::new(13, 14), IrData::Int(7)),
            pure_node(
                IrKind::Let,
                Span::new(0, 14),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body,
                    frame: Some(frame),
                },
            ),
        ],
        Vec::new(),
    );
    let mut facts = IrFacts::conservative(arena.nodes().len());
    facts
        .get_mut(dead)
        .expect("dead binding fact exists")
        .cardinality = crate::compile::Cardinality::Absent;
    let ir = Ir {
        root,
        arena,
        facts,
        symbols,
        frames: vec![FrameInfo {
            slot_count: 1,
            captures: Vec::new().into_boxed_slice(),
            rec: false,
            has_with: false,
        }]
        .into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(dead_key),
            position: None,
            value: dead,
        }]
        .into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let error = eval_whnf(&ir).expect_err("omitted thunk payload is preflighted");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPayload {
            id: dead,
            kind: IrKind::ThunkAlloc,
            expected: "thunk body",
        }
    );
    assert_eq!(error.span(), dead_span);
}

#[test]
fn dead_binding_plan_failure_falls_back_to_lazy_binding_allocation() {
    let mut symbols = SymbolTable::new();
    let dead_key = symbols.intern(b"dead").expect("symbol interns");
    let dead_body = IrId::new(0);
    let dead = IrId::new(1);
    let body = IrId::new(2);
    let root = IrId::new(3);
    let frame = FrameId::new(0);
    let arena = IrArena::from_raw_parts(
        vec![
            pure_node(IrKind::Int, Span::new(7, 8), IrData::Int(1)),
            pure_node(IrKind::ThunkAlloc, Span::new(7, 8), IrData::Node(dead_body)),
            pure_node(IrKind::Int, Span::new(13, 14), IrData::Int(7)),
            pure_node(
                IrKind::Let,
                Span::new(0, 14),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 1),
                    body,
                    frame: Some(frame),
                },
            ),
        ],
        Vec::new(),
    );
    let ir = Ir {
        root,
        arena,
        facts: IrFacts::conservative(0),
        symbols,
        frames: vec![FrameInfo {
            slot_count: 1,
            captures: Vec::new().into_boxed_slice(),
            rec: false,
            has_with: false,
        }]
        .into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(dead_key),
            position: None,
            value: dead,
        }]
        .into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let outcome = eval_whnf_owned(&ir).expect("planner failure remains conservative");

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

#[test]
fn invalid_string_symbols_are_reported() {
    let root = IrId::new(0);
    let symbol = Symbol::new(99);
    let span = Span::new(3, 8);
    let ir = manual_ir(
        root,
        vec![pure_node(IrKind::Str, span, IrData::Symbol(symbol))],
    );
    let error = eval_whnf_owned(&ir).expect_err("string symbol must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_list_child_slices_are_reported() {
    let root = IrId::new(0);
    let slice = IrChildSlice::new(7, 1);
    let span = Span::new(0, 2);
    let ir = manual_ir(
        root,
        vec![pure_node(IrKind::List, span, IrData::Children(slice))],
    );
    let error = eval_whnf_owned(&ir).expect_err("list child slice must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidChildSlice { id: root, slice }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_has_attr_paths_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(2);
    let span = Span::new(0, 5);
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("symbol interns");
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::HasAttr,
                span,
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_select_paths_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(2);
    let span = Span::new(0, 5);
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("symbol interns");
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::Select,
                span,
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                    default: None,
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn empty_has_attr_paths_are_invalid_ir() {
    let receiver = IrId::new(2);
    let root = IrId::new(3);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(0)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 5),
                IrData::Binary {
                    op: BinOpKind::Div,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
            pure_node(
                IrKind::HasAttr,
                span,
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("empty attr paths are malformed IR");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn empty_select_paths_are_invalid_ir() {
    let receiver = IrId::new(2);
    let root = IrId::new(3);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(0)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 5),
                IrData::Binary {
                    op: BinOpKind::Div,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
            pure_node(
                IrKind::Select,
                span,
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                    default: None,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("empty attr paths are malformed IR");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_has_attr_static_symbols_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let symbol = Symbol::new(99);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::HasAttr,
                span,
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([IrAttrPathSegment::Static(symbol)])],
    );
    let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_select_static_symbols_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let symbol = Symbol::new(99);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::Select,
                span,
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                    default: None,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([IrAttrPathSegment::Static(symbol)])],
    );
    let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_attrset_binding_slices_are_reported() {
    let root = IrId::new(0);
    let slice = IrBindingSlice::new(7, 1);
    let span = Span::new(0, 2);
    let ir = manual_ir(
        root,
        vec![pure_node(
            IrKind::AttrSet,
            span,
            IrData::AttrSet {
                shape: IrShapeId::new(0),
                bindings: slice,
                recursive: false,
                has_dynamic: false,
                frame: None,
            },
        )],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset binding slice must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidBindingSlice { id: root, slice }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_attrset_shape_ids_are_reported() {
    let root = IrId::new(0);
    let shape = IrShapeId::new(0);
    let span = Span::new(0, 2);
    let ir = manual_ir(
        root,
        vec![pure_node(
            IrKind::AttrSet,
            span,
            IrData::AttrSet {
                shape,
                bindings: IrBindingSlice::new(0, 0),
                recursive: false,
                has_dynamic: false,
                frame: None,
            },
        )],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset shape must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidShapeId { id: root, shape }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_recursive_attrset_frame_metadata_is_reported() {
    fn recursive_attrset_ir(frame: Option<FrameId>, frames: Vec<FrameInfo>) -> Ir {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let value = IrId::new(0);
        let root = IrId::new(1);
        let mut ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    Span::new(0, 10),
                    IrData::AttrSet {
                        shape: IrShapeId::new(0),
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: true,
                        has_dynamic: false,
                        frame,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Static(a),
                position: None,
                value,
            }],
            vec![IrShape::new(vec![a].into_boxed_slice())],
        );
        ir.frames = frames.into_boxed_slice();
        ir
    }

    let missing_frame = recursive_attrset_ir(None, Vec::new());
    let missing_error =
        eval_whnf_owned(&missing_frame).expect_err("recursive attrset frame must exist");

    assert_eq!(
        missing_error.kind(),
        TreeWalkErrorKind::MissingFrameMetadata { id: IrId::new(1) }
    );
    assert_eq!(missing_error.span(), Span::new(0, 10));

    let frame = FrameId::new(0);
    let invalid_frame = recursive_attrset_ir(Some(frame), Vec::new());
    let invalid_error = eval_whnf_owned(&invalid_frame).expect_err("frame id must resolve");

    assert_eq!(
        invalid_error.kind(),
        TreeWalkErrorKind::InvalidFrameId {
            id: IrId::new(1),
            frame: frame.as_u32(),
        }
    );
    assert_eq!(invalid_error.span(), Span::new(0, 10));

    let mismatch = recursive_attrset_ir(
        Some(frame),
        vec![FrameInfo {
            slot_count: 2,
            captures: Vec::new().into_boxed_slice(),
            rec: true,
            has_with: false,
        }],
    );
    let mismatch_error = eval_whnf_owned(&mismatch).expect_err("frame slots must match bindings");

    assert_eq!(
        mismatch_error.kind(),
        TreeWalkErrorKind::AttrSetFrameSlotMismatch {
            id: IrId::new(1),
            frame_slots: 2,
            bindings: 1,
        }
    );
    assert_eq!(mismatch_error.span(), Span::new(0, 10));
}

#[test]
fn attrset_shape_length_mismatches_are_reported() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("symbol interns");
    let value = IrId::new(0);
    let root = IrId::new(1);
    let shape = IrShapeId::new(0);
    let span = Span::new(0, 8);
    let ir = manual_ir_with_attr_tables(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
            pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape,
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        symbols,
        vec![IrBinding {
            key: IrAttrPathSegment::Static(a),
            position: None,
            value,
        }],
        vec![IrShape::new(Vec::new().into_boxed_slice())],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset shape length must match bindings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::AttrSetShapeLengthMismatch {
            id: root,
            shape,
            shape_keys: 0,
            binding_keys: 1,
        }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn attrset_shape_key_mismatches_are_reported() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a symbol interns");
    let b = symbols.intern(b"b").expect("b symbol interns");
    let value = IrId::new(0);
    let root = IrId::new(1);
    let shape = IrShapeId::new(0);
    let span = Span::new(0, 8);
    let ir = manual_ir_with_attr_tables(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
            pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape,
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        symbols,
        vec![IrBinding {
            key: IrAttrPathSegment::Static(a),
            position: None,
            value,
        }],
        vec![IrShape::new(vec![b].into_boxed_slice())],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset shape keys must match bindings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::AttrSetShapeKeyMismatch {
            id: root,
            shape,
            index: 0,
            expected: b,
            actual: a,
        }
    );
    assert_eq!(error.span(), span);
}
