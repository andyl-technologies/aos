//! Unit tests for the tier-1 CLIF lowerer (moved from `lower.rs` verbatim).

use super::*;

#[test]
fn tier1_ir_thunk_body_artifact_selects_literal_and_env_get_paths() {
    let literal_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );
    let literal_artifact = lower_tier1_ir_thunk_body_artifact(&literal_arena, IrId::new(0))
        .expect("tier-1 selector lowers literal root");

    assert_eq!(
        iconst_words(literal_artifact.function()),
        vec![ValueTag::Bool as u64, Value::bool(true).payload_bits()]
    );
    assert!(literal_artifact.function().dfg.ext_funcs.is_empty());

    let local_arena = IrArena::from_raw_parts(vec![local_var_node(19)], Vec::new());
    let local_artifact = lower_tier1_ir_thunk_body_artifact(&local_arena, IrId::new(0))
        .expect("tier-1 selector lowers local root through env-get");

    assert_eq!(local_artifact.function().dfg.ext_funcs.len(), 1);
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    assert_eq!(iconst_words(local_artifact.function()), vec![19]);
}

#[test]
fn tier1_ir_thunk_body_lowers_wrapped_local_body() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(23),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let function = lower_tier1_ir_thunk_body(&arena, IrId::new(1))
        .expect("tier-1 selector lowers wrapped local root");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
    assert_eq!(function.dfg.ext_funcs.len(), 1);
    imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    assert_eq!(iconst_words(&function), vec![23]);
}

#[test]
fn tier1_ir_thunk_body_artifact_selects_apply_path() {
    let arena = apply_local_slots_arena(41, 43);

    let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("tier-1 selector lowers local-slot apply");

    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![41, 43]);
}

#[test]
fn tier1_ir_thunk_body_artifact_selects_wrapped_apply_path() {
    let arena = apply_local_slots_thunk_arena(44, 45);

    let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(3))
        .expect("tier-1 selector lowers wrapped local-slot apply");

    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(3))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![44, 45]);
}

#[test]
fn force_aware_tier1_ir_thunk_body_artifact_preserves_literals_and_forces_local_slots() {
    let literal_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 2),
            EffectClass::pure(),
            IrData::Int(29),
        )],
        Vec::new(),
    );
    let literal_artifact =
        lower_force_aware_tier1_ir_thunk_body_artifact(&literal_arena, IrId::new(0))
            .expect("force-aware selector preserves literal lowering");

    assert_eq!(
        iconst_words(literal_artifact.function()),
        vec![ValueTag::Int as u64, Value::int(29).payload_bits()]
    );
    assert!(literal_artifact.function().dfg.ext_funcs.is_empty());

    let local_arena = IrArena::from_raw_parts(vec![local_var_node(31)], Vec::new());
    let local_artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&local_arena, IrId::new(0))
        .expect("force-aware selector lowers local root through env-get and force");

    assert_eq!(local_artifact.function().dfg.ext_funcs.len(), 4);
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_jit_stack_map_enter(),
    );
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_jit_stack_map_exit(),
    );
    assert_eq!(iconst_words(local_artifact.function()), vec![31, 0, 1]);
}

#[test]
fn force_aware_tier1_ir_thunk_body_artifact_selects_apply_without_extra_force() {
    let arena = apply_local_slots_arena(47, 53);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("force-aware selector lowers local-slot apply through apply helper");

    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![47, 53]);
}

#[test]
fn force_aware_tier1_ir_thunk_body_artifact_selects_wrapped_apply_without_extra_force() {
    let arena = apply_local_slots_thunk_arena(54, 55);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&arena, IrId::new(3))
        .expect("force-aware selector lowers wrapped local-slot apply through apply helper");

    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(3))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![54, 55]);
}

#[test]
fn full_ir_tier1_selectors_accept_static_select_roots() {
    let ir = static_select_ir(61);

    let Err(arena_only_error) = lower_force_aware_tier1_ir_thunk_body_artifact(&ir.arena, ir.root)
    else {
        panic!("arena-only force-aware selector should reject select roots");
    };
    assert!(matches!(
        arena_only_error,
        JitLowerError::UnsupportedIrRoot {
            kind: IrKind::Select
        } | JitLowerError::UnsupportedIrBody {
            kind: IrKind::Select
        }
    ));

    let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR selector lowers static select root");
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );

    let force_aware_artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers static select root");
    assert_eq!(
        force_aware_artifact.function().dfg.ext_funcs.len(),
        artifact.function().dfg.ext_funcs.len()
    );
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
}

#[test]
fn full_ir_tier1_selectors_accept_static_select_literal_defaults() {
    let ir = static_select_default_ir(66, IrId::new(2), vec![literal_int_node(99)]);

    let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR selector lowers static select root with literal default");
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 6);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
    assert!(all_iconst_words(artifact.function()).contains(&(ValueTag::Int as u64)));
    assert!(all_iconst_words(artifact.function()).contains(&Value::int(99).payload_bits()));

    let wrapped_default_ir = static_select_default_ir(
        67,
        IrId::new(3),
        vec![
            literal_int_node(99),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(12, 14),
                EffectClass::pure(),
                IrData::Node(IrId::new(2)),
            ),
        ],
    );
    let force_aware_artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(
        &wrapped_default_ir,
        wrapped_default_ir.root,
    )
    .expect("force-aware full-IR selector lowers select with wrapped literal default");
    assert_eq!(force_aware_artifact.function().dfg.ext_funcs.len(), 6);
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
    assert!(
        all_iconst_words(force_aware_artifact.function()).contains(&Value::int(99).payload_bits())
    );
}

#[test]
fn full_ir_tier1_selectors_reject_non_literal_select_defaults() {
    let ir = static_select_default_ir(68, IrId::new(2), vec![local_var_node(69)]);

    let Err(error) = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root) else {
        panic!("non-literal select default is outside the bounded lowerer");
    };

    assert!(matches!(
        error,
        JitLowerError::UnsupportedSelectDefault { default } if default == IrId::new(2)
    ));
}

#[test]
fn full_ir_tier1_selectors_accept_static_has_attr_roots() {
    let ir = static_has_attr_ir(63);

    let Err(arena_only_error) = lower_force_aware_tier1_ir_thunk_body_artifact(&ir.arena, ir.root)
    else {
        panic!("arena-only force-aware selector should reject hasAttr roots");
    };
    assert!(matches!(
        arena_only_error,
        JitLowerError::UnsupportedIrRoot {
            kind: IrKind::HasAttr
        } | JitLowerError::UnsupportedIrBody {
            kind: IrKind::HasAttr
        }
    ));

    let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR selector lowers static hasAttr root");
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );

    let force_aware_artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers static hasAttr root");
    assert_eq!(
        force_aware_artifact.function().dfg.ext_funcs.len(),
        artifact.function().dfg.ext_funcs.len()
    );
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
}

#[test]
fn full_ir_tier1_selectors_accept_wrapped_static_select_roots() {
    let ir = wrapped_static_select_ir(62);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers wrapped static select root");
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(2))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
}

#[test]
fn full_ir_tier1_selectors_accept_wrapped_static_has_attr_roots() {
    let ir = wrapped_static_has_attr_ir(64);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers wrapped static hasAttr root");
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(2))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
}

#[test]
fn force_aware_tier1_ir_thunk_body_lowers_wrapped_local_body() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(37),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let function = lower_force_aware_tier1_ir_thunk_body(&arena, IrId::new(1))
        .expect("force-aware selector lowers wrapped local root");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
    assert_eq!(function.dfg.ext_funcs.len(), 4);
    imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_enter(),
    );
    imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_exit(),
    );
    assert_eq!(iconst_words(&function), vec![37, 0, 1]);
}

#[test]
fn tier1_ir_thunk_body_artifact_reports_unsupported_selector_shapes() {
    let root_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Str,
                Span::new(1, 6),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let Err(root_error) = lower_tier1_ir_thunk_body_artifact(&root_arena, IrId::new(0)) else {
        panic!("unsupported direct root is rejected");
    };
    let Err(body_error) = lower_force_aware_tier1_ir_thunk_body_artifact(&body_arena, IrId::new(1))
    else {
        panic!("unsupported wrapped body is rejected");
    };

    assert!(matches!(root_error, JitLowerError::UnsupportedIrRoot { kind } if kind == IrKind::Str));
    assert!(matches!(body_error, JitLowerError::UnsupportedIrBody { kind } if kind == IrKind::Str));
}

#[test]
fn tier1_ir_thunk_body_artifact_reports_selector_shape_malformed_roots() {
    let missing_root_arena = IrArena::new();
    let missing_body_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Node(IrId::new(9)),
        )],
        Vec::new(),
    );
    let malformed_wrapper_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let Err(missing_root_error) =
        lower_tier1_ir_thunk_body_artifact(&missing_root_arena, IrId::new(7))
    else {
        panic!("missing selector root is rejected");
    };
    let Err(missing_body_error) =
        lower_force_aware_tier1_ir_thunk_body_artifact(&missing_body_arena, IrId::new(0))
    else {
        panic!("missing selector body is rejected");
    };
    let Err(malformed_wrapper_error) =
        lower_tier1_ir_thunk_body_artifact(&malformed_wrapper_arena, IrId::new(0))
    else {
        panic!("malformed selector wrapper is rejected");
    };

    assert!(
        matches!(missing_root_error, JitLowerError::MissingIrNode { root } if root == IrId::new(7))
    );
    assert!(
        matches!(missing_body_error, JitLowerError::MissingIrBody { body } if body == IrId::new(9))
    );
    assert!(matches!(
        malformed_wrapper_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data: IrData::None,
            expected: "body node",
        }
    ));
}

#[test]
fn tier1_ir_thunk_body_artifact_reports_selector_payload_mismatches() {
    let mismatched_literal_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let mismatched_local_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let mismatched_body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Bool,
                Span::new(1, 5),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let Err(literal_error) =
        lower_tier1_ir_thunk_body_artifact(&mismatched_literal_arena, IrId::new(0))
    else {
        panic!("mismatched selector literal is rejected");
    };
    let Err(local_error) =
        lower_force_aware_tier1_ir_thunk_body_artifact(&mismatched_local_arena, IrId::new(0))
    else {
        panic!("mismatched selector local slot is rejected");
    };
    let Err(body_error) = lower_tier1_ir_thunk_body_artifact(&mismatched_body_arena, IrId::new(1))
    else {
        panic!("mismatched selector thunk body is rejected");
    };

    assert!(matches!(
        literal_error,
        JitLowerError::MismatchedConstantData {
            kind: IrKind::Int,
            data: IrData::None,
        }
    ));
    assert!(matches!(
        local_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data: IrData::None,
            expected: "local slot payload",
        }
    ));
    assert!(matches!(
        body_error,
        JitLowerError::MismatchedBodyConstantData {
            kind: IrKind::Bool,
            data: IrData::None,
        }
    ));
}
