//! Parse artifact validation tests.

use super::*;

#[test]
fn serialization_remaps_symbols_to_file_local_ids() {
    let mut shifted_symbols = SymbolTable::new();
    shifted_symbols
        .intern(b"unused")
        .expect("unused symbol interns");
    let shifted_x = shifted_symbols.intern(b"x").expect("x symbol interns");
    let shifted = resolved_single_symbol(shifted_symbols, shifted_x);

    let mut local_symbols = SymbolTable::new();
    let local_x = local_symbols.intern(b"x").expect("local x interns");
    let local = resolved_single_symbol(local_symbols, local_x);

    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let entry = cache.entry_for_source(b"symbol-remap");
    let meta = ParseCacheMeta::for_resolved(
        cache.schema_version(),
        Some("expr.nix".to_owned()),
        &shifted,
    )
    .expect("metadata counts file-local symbols");
    assert_eq!(meta.symbol_count, 1);

    entry
        .write_resolved(&shifted, &meta)
        .expect("shifted artifact writes");
    let loaded = entry.read_resolved().expect("shifted artifact reads");
    assert_eq!(loaded.symbols.symbols(), &[b"x".to_vec()]);
    assert_eq!(loaded.arena.nodes(), local.arena.nodes());
    assert_eq!(
        loaded.scopes.inherit_resolutions(),
        local.scopes.inherit_resolutions()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn duplicate_serialized_symbols_are_rejected() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SYMBOL_MAGIC);
    write_u32(&mut bytes, ARTIFACT_VERSION);
    write_u32(&mut bytes, 2);
    write_u32(&mut bytes, 1);
    bytes.push(b'a');
    write_u32(&mut bytes, 1);
    bytes.push(b'a');

    let error = decode_symbols(&bytes).expect_err("duplicate symbol is invalid");
    assert!(error.contains("duplicate symbol"));
}

#[test]
fn resolved_artifact_validation_rejects_out_of_range_node_frame_ids() {
    let resolved = resolved_single_symbol_with_scopes(ScopeTables::from_raw_parts(
        Vec::new(),
        vec![Some(FrameId::new(0))],
        Vec::new(),
        Vec::new(),
        vec![None],
    ));
    let symbols = resolved.symbols.clone();
    let bytes = encode_resolved_ir(&resolved).expect("resolved artifact encodes");
    let error = decode_resolved_ir(&bytes, symbols).expect_err("invalid frame id is rejected");

    assert!(error.contains("frame id out of range"), "{error}");
}

#[test]
fn resolved_artifact_validation_rejects_out_of_range_node_inherit_ids() {
    let resolved = resolved_single_symbol_with_scopes(ScopeTables::from_raw_parts(
        Vec::new(),
        vec![None],
        Vec::new(),
        Vec::new(),
        vec![Some(InheritGroupId::new(0))],
    ));
    let symbols = resolved.symbols.clone();
    let bytes = encode_resolved_ir(&resolved).expect("resolved artifact encodes");
    let error = decode_resolved_ir(&bytes, symbols).expect_err("invalid inherit id is rejected");

    assert!(error.contains("inherit id out of range"), "{error}");
}

#[test]
fn lowered_ir_rejects_inconsistent_node_payload_and_effect() {
    let invalid_payload = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Null,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(true),
            )],
            Vec::new(),
        ),
        facts: IrFacts::conservative(1),
        symbols: SymbolTable::new(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_payload).expect("invalid payload encodes");
    let error = decode_lowered_ir(&bytes, SymbolTable::new())
        .expect_err("invalid kind/data pair is rejected");
    assert!(error.contains("invalid IR data"));

    let invalid_effect = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 16),
                EffectClass::pure(),
                IrData::DialectNode {
                    op: aos_nix_dialect::NIX_OP_DERIVATION_STRICT,
                    argument: IrId::new(0),
                },
            )],
            Vec::new(),
        ),
        facts: IrFacts::conservative(1),
        symbols: SymbolTable::new(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_effect).expect("invalid effect encodes");
    let error =
        decode_lowered_ir(&bytes, SymbolTable::new()).expect_err("invalid node effect is rejected");
    assert!(error.contains("invalid IR effect"));

    let mut symbols = SymbolTable::new();
    let type_of = symbols.intern(b"typeOf").expect("typeOf interns");
    let invalid_primop_effect = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(16, 20),
                    EffectClass::pure(),
                    IrData::Bool(true),
                ),
                IrNode::new(
                    IrKind::PrimOp,
                    Span::new(0, 20),
                    EffectClass::new(1, false),
                    IrData::PrimOp {
                        symbol: type_of,
                        args: IrChildSlice::new(0, 1),
                    },
                ),
            ],
            vec![IrId::new(0)],
        ),
        facts: IrFacts::conservative(2),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_primop_effect).expect("invalid primop effect encodes");
    let error = decode_lowered_ir(&bytes, symbols).expect_err("pure primop effect is rejected");
    assert!(error.contains("invalid IR effect"));

    let mut symbols = SymbolTable::new();
    let derivation_strict = symbols
        .intern(b"derivationStrict")
        .expect("derivationStrict interns");
    let derivation_as_primop = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(20, 24),
                    EffectClass::pure(),
                    IrData::Bool(false),
                ),
                IrNode::new(
                    IrKind::PrimOp,
                    Span::new(0, 24),
                    EffectClass::new(1, false),
                    IrData::PrimOp {
                        symbol: derivation_strict,
                        args: IrChildSlice::new(0, 1),
                    },
                ),
            ],
            vec![IrId::new(0)],
        ),
        facts: IrFacts::conservative(2),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&derivation_as_primop).expect("derivation primop encodes");
    let error =
        decode_lowered_ir(&bytes, symbols).expect_err("derivationStrict is not a normal primop");
    assert!(error.contains("unknown IR primop symbol"));

    let mut symbols = SymbolTable::new();
    let future = symbols.intern(b"futurePrimop").expect("future interns");
    let unknown_primop = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(20, 24),
                    EffectClass::pure(),
                    IrData::Bool(false),
                ),
                IrNode::new(
                    IrKind::PrimOp,
                    Span::new(0, 24),
                    EffectClass::pure(),
                    IrData::PrimOp {
                        symbol: future,
                        args: IrChildSlice::new(0, 1),
                    },
                ),
            ],
            vec![IrId::new(0)],
        ),
        facts: IrFacts::conservative(2),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&unknown_primop).expect("unknown primop encodes");
    let error = decode_lowered_ir(&bytes, symbols).expect_err("unknown primop is rejected");
    assert!(error.contains("unknown IR primop symbol"));
}

#[test]
fn lowered_ir_validation_rejects_fact_count_mismatch() {
    let ir = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Null,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        ),
        facts: IrFacts::conservative(0),
        symbols: SymbolTable::new(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };

    let error = validate_lowered_ir_artifact(&ir).expect_err("mismatched fact count is rejected");
    assert!(error.contains("fact count"), "{error}");
}

#[test]
fn lowered_ir_rejects_inconsistent_attrset_shapes() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let b = symbols.intern(b"b").expect("b interns");
    let static_binding = IrBinding {
        key: IrAttrPathSegment::Static(a),
        position: None,
        value: IrId::new(0),
    };
    let invalid_shape = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 9),
                EffectClass::pure(),
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            )],
            Vec::new(),
        ),
        facts: IrFacts::conservative(1),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![static_binding].into_boxed_slice(),
        shapes: vec![IrShape::new(vec![b].into_boxed_slice())].into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_shape).expect("invalid shape encodes");
    let error =
        decode_lowered_ir(&bytes, symbols.clone()).expect_err("invalid attrset shape is rejected");
    assert!(error.contains("shape does not match"));

    let invalid_dynamic_flag = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 9),
                EffectClass::pure(),
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: true,
                    frame: None,
                },
            )],
            Vec::new(),
        ),
        facts: IrFacts::conservative(1),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![static_binding].into_boxed_slice(),
        shapes: vec![IrShape::new(vec![a].into_boxed_slice())].into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_dynamic_flag).expect("invalid flag encodes");
    let error =
        decode_lowered_ir(&bytes, symbols).expect_err("invalid attrset dynamic flag is rejected");
    assert!(error.contains("dynamic flag"));
}
