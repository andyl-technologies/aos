//! Rejection coverage for unsupported attribute-operation lowering shapes.

use super::*;

#[test]
fn select_lowering_rejects_unsupported_shapes() {
    let dynamic_path_ir = attr_lookup_ir(
        AttrLookupFixtureKind::Select,
        1,
        Some(vec![IrAttrPathSegment::Dynamic(IrId::new(0))]),
    );
    let select_default_ir = attr_lookup_ir(AttrLookupFixtureKind::SelectWithDefault, 1, None);
    let non_local_receiver_ir =
        attr_lookup_ir(AttrLookupFixtureKind::SelectNonLocalReceiver, 1, None);

    let dynamic_path_error =
        lower_select_local_slot_ir_thunk_body(&dynamic_path_ir, dynamic_path_ir.root)
            .expect_err("dynamic attr path is rejected");
    // `a.b or default` is now a supported shape: the lowerer emits the
    // default-carrying select. This previously expected an error and predates
    // the or-default support.
    lower_select_local_slot_ir_thunk_body(&select_default_ir, select_default_ir.root)
        .expect("select with a default lowers");
    let non_local_receiver_error =
        lower_select_local_slot_ir_thunk_body(&non_local_receiver_ir, non_local_receiver_ir.root)
            .expect_err("non-local attr receiver is rejected");

    assert!(matches!(
        dynamic_path_error,
        JitLowerError::UnsupportedAttrPathSegment {
            path,
            index: 0,
            segment: IrAttrPathSegment::Dynamic(dynamic),
        } if path == IrAttrPathId::new(0) && dynamic == IrId::new(0)
    ));
    assert!(matches!(
        non_local_receiver_error,
        JitLowerError::UnsupportedAttrReceiver {
            receiver,
            kind: IrKind::Int,
        } if receiver == IrId::new(0)
    ));
}

#[test]
fn has_attr_lowering_rejects_unsupported_shapes() {
    let dynamic_path_ir = attr_lookup_ir(
        AttrLookupFixtureKind::HasAttr,
        1,
        Some(vec![IrAttrPathSegment::Dynamic(IrId::new(0))]),
    );
    let multi_segment_static_path_ir = attr_lookup_ir(
        AttrLookupFixtureKind::HasAttr,
        1,
        Some(vec![
            IrAttrPathSegment::Static(Symbol::new(0)),
            IrAttrPathSegment::Static(Symbol::new(0)),
        ]),
    );
    let non_local_receiver_ir =
        attr_lookup_ir(AttrLookupFixtureKind::HasAttrNonLocalReceiver, 1, None);

    let dynamic_path_error =
        lower_has_attr_local_slot_ir_thunk_body(&dynamic_path_ir, dynamic_path_ir.root)
            .expect_err("dynamic attr path is rejected");
    let multi_segment_static_path_error = lower_has_attr_local_slot_ir_thunk_body(
        &multi_segment_static_path_ir,
        multi_segment_static_path_ir.root,
    )
    .expect_err("multi-segment static attr path is rejected");
    let non_local_receiver_error =
        lower_has_attr_local_slot_ir_thunk_body(&non_local_receiver_ir, non_local_receiver_ir.root)
            .expect_err("non-local attr receiver is rejected");

    assert!(matches!(
        dynamic_path_error,
        JitLowerError::UnsupportedAttrPathSegment {
            path,
            index: 0,
            segment: IrAttrPathSegment::Dynamic(dynamic),
        } if path == IrAttrPathId::new(0) && dynamic == IrId::new(0)
    ));
    assert!(matches!(
        multi_segment_static_path_error,
        JitLowerError::UnsupportedAttrPathLength { path, len }
            if path == IrAttrPathId::new(0) && len == 2
    ));
    assert!(matches!(
        non_local_receiver_error,
        JitLowerError::UnsupportedAttrReceiver {
            receiver,
            kind: IrKind::Int,
        } if receiver == IrId::new(0)
    ));
}

#[test]
fn update_lowering_rejects_unsupported_shapes() {
    let non_update_arena = binary_local_slots_arena(BinOpKind::Add, 1, 2);
    let non_local_operand_arena = IrArena::from_raw_parts(
        vec![
            local_var_node(1),
            IrNode::new(
                IrKind::Int,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Int(9),
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: BinOpKind::Update,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    let missing_operand_arena = IrArena::from_raw_parts(
        vec![
            local_var_node(1),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: BinOpKind::Update,
                    lhs: IrId::new(0),
                    rhs: IrId::new(9),
                },
            ),
        ],
        Vec::new(),
    );
    let malformed_payload_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::BinOp,
            Span::new(0, 3),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let non_update_error = lower_update_local_slots_ir_thunk_body(&non_update_arena, IrId::new(2))
        .expect_err("non-update binary operator is rejected");
    let non_local_operand_error =
        lower_update_local_slots_ir_thunk_body(&non_local_operand_arena, IrId::new(2))
            .expect_err("non-local update operand is rejected");
    let missing_operand_error =
        lower_update_local_slots_ir_thunk_body(&missing_operand_arena, IrId::new(1))
            .expect_err("missing update operand is rejected");
    let malformed_payload_error =
        lower_update_local_slots_ir_thunk_body(&malformed_payload_arena, IrId::new(0))
            .expect_err("malformed update payload is rejected");

    assert!(matches!(
        non_update_error,
        JitLowerError::UnsupportedUpdateOp { op: BinOpKind::Add }
    ));
    assert!(matches!(
        non_local_operand_error,
        JitLowerError::UnsupportedUpdateOperand {
            operand,
            kind: IrKind::Int,
        } if operand == IrId::new(1)
    ));
    assert!(matches!(
        missing_operand_error,
        JitLowerError::MissingUpdateOperand { operand } if operand == IrId::new(9)
    ));
    assert!(matches!(
        malformed_payload_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::BinOp,
            data: IrData::None,
            expected: "attr update binary payload",
        }
    ));
}
