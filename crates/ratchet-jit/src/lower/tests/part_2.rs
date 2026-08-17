//! Unit tests for the tier-1 CLIF lowerer (moved from `lower.rs` verbatim).

use super::*;

// A literal-root case is `Value::float`, which the Candidate-C carrier boxes
// (no inline constructor), so this float-literal lowering test is baseline-only.
#[test]
fn constant_ir_root_thunk_body_lowers_real_literal_ir_artifacts() {
    let cases = [
        ("42", Value::int(42)),
        ("2.5", Value::float(2.5)),
        ("false", Value::bool(false)),
        ("null", Value::null()),
    ];

    for (source, expected_value) in cases {
        let ir = lowered_ir(source);
        let function = lower_constant_ir_root_thunk_body(&ir).expect("literal IR artifact lowers");

        assert_eq!(
            iconst_words(&function),
            vec![expected_value.tag() as u64, expected_value.payload_bits()]
        );
    }
}

#[test]
fn constant_ir_root_thunk_body_uses_nonzero_artifact_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Str,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(7, 9),
                EffectClass::pure(),
                IrData::Int(11),
            ),
        ],
        Vec::new(),
    );
    let ir = minimal_ir(IrId::new(1), arena);

    let function = lower_constant_ir_root_thunk_body(&ir).expect("nonzero literal root lowers");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
    assert_eq!(
        iconst_words(&function),
        vec![ValueTag::Int as u64, Value::int(11).payload_bits()]
    );
}

#[test]
fn constant_ir_root_thunk_body_artifact_records_nonzero_artifact_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Str,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(7, 9),
                EffectClass::pure(),
                IrData::Int(13),
            ),
        ],
        Vec::new(),
    );
    let ir = minimal_ir(IrId::new(1), arena);

    let artifact =
        lower_constant_ir_root_thunk_body_artifact(&ir).expect("IR root artifact lowers");

    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(
        iconst_words(artifact.function()),
        vec![ValueTag::Int as u64, Value::int(13).payload_bits()]
    );
}

#[test]
fn constant_ir_root_thunk_body_rejects_missing_artifact_root() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let ir = minimal_ir(IrId::new(5), arena);

    let error =
        lower_constant_ir_root_thunk_body(&ir).expect_err("missing artifact root is rejected");

    assert!(matches!(error, JitLowerError::MissingIrNode { root } if root == IrId::new(5)));
}

#[test]
fn env_get_ir_thunk_body_imports_env_helper_signature() {
    let arena = IrArena::from_raw_parts(vec![local_var_node(3)], Vec::new());

    let function =
        lower_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("local var root lowers");
    let (_func_ref, import) = single_imported_function(&function);
    let expected_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
            .expect("env-get helper signature is core-owned"),
    )
    .expect("env-get signature lowers to CLIF");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(0)));
    assert_eq!(
        imported_user_external_name(&function, import),
        clif_external_name_for_aos_env_get()
    );
    assert_eq!(
        function.dfg.signatures[import.signature],
        expected_signature
    );
    assert!(!import.colocated);
}

#[test]
fn env_get_ir_thunk_body_calls_env_helper_with_entry_env_and_slot() {
    let arena = IrArena::from_raw_parts(vec![local_var_node(5)], Vec::new());

    let function =
        lower_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("local var root lowers");
    let (env_get, _import) = single_imported_function(&function);
    let call = single_call_inst(&function);
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[call] else {
        panic!("lowered env-get function emits a direct call");
    };

    assert_eq!(func_ref, env_get);
    assert_eq!(
        opcodes(&function),
        vec![Opcode::Iconst, Opcode::Call, Opcode::Return]
    );
    assert_eq!(
        function.dfg.inst_args(call)[0],
        entry_block_values(&function)[1]
    );
    assert_eq!(
        function.dfg.value_type(function.dfg.inst_args(call)[1]),
        types::I32
    );
    assert_eq!(iconst_words(&function), vec![5]);
    assert_eq!(return_operands(&function), function.dfg.inst_results(call));
    verify_clif_function(&function).expect("env-get function verifies independently");
}

#[test]
fn env_get_ir_thunk_body_lowers_direct_local_thunk_alloc_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(7),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let artifact = lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(1))
        .expect("direct local thunk allocation lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(iconst_words(artifact.function()), vec![7]);
}

#[test]
fn env_get_ir_thunk_body_rejects_mismatched_local_payload() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("local var without local payload is malformed");

    assert!(matches!(
        error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data: IrData::None,
            expected: "local slot payload",
        }
    ));
}

#[test]
fn env_get_ir_thunk_body_rejects_unsupported_roots_and_bodies() {
    let root_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(1, 2),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let root_error = lower_env_get_ir_thunk_body(&root_arena, IrId::new(0))
        .expect_err("non-local root is not covered by env-get lowering");
    let body_error = lower_env_get_ir_thunk_body(&body_arena, IrId::new(1))
        .expect_err("non-local thunk body is not covered by env-get lowering");

    assert!(
        matches!(root_error, JitLowerError::UnsupportedEnvRoot { kind } if kind == IrKind::Int)
    );
    assert!(
        matches!(body_error, JitLowerError::UnsupportedEnvBody { kind } if kind == IrKind::Int)
    );
}

#[test]
fn env_get_ir_thunk_body_rejects_missing_thunk_body() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Node(IrId::new(9)),
        )],
        Vec::new(),
    );

    let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("missing local thunk body is rejected");

    assert!(matches!(error, JitLowerError::MissingIrBody { body } if body == IrId::new(9)));
}

#[test]
fn env_get_ir_thunk_body_rejects_malformed_thunk_alloc_payload() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("local thunk allocation without body node is malformed");

    assert!(matches!(
        error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data: IrData::None,
            expected: "body node",
        }
    ));
}

#[test]
fn forced_env_get_ir_thunk_body_imports_env_get_and_force_signatures() {
    let arena = IrArena::from_raw_parts(vec![local_var_node(11)], Vec::new());

    let function = lower_forced_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect("forced local var root lowers");
    let env_get_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let force_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let expected_env_get_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
            .expect("env-get helper signature is core-owned"),
    )
    .expect("env-get signature lowers to CLIF");
    let expected_force_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_FORCE_SYMBOL)
            .expect("force helper signature is core-owned"),
    )
    .expect("force signature lowers to CLIF");

    assert_eq!(
        function.dfg.signatures[env_get_import.1.signature],
        expected_env_get_signature
    );
    assert_eq!(
        function.dfg.signatures[force_import.1.signature],
        expected_force_signature
    );
}

#[test]
fn forced_env_get_ir_thunk_body_lowers_direct_local_thunk_alloc_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(17),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(1))
        .expect("direct forced local thunk allocation lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(
        artifact.function().dfg.ext_funcs.len(),
        4,
        "forced env-get artifacts import env-get, force, and stack-map brackets"
    );
}

#[test]
fn apply_local_slots_ir_thunk_body_imports_env_get_and_apply_signatures() {
    let arena = apply_local_slots_arena(2, 5);

    let function = lower_apply_local_slots_ir_thunk_body(&arena, IrId::new(2))
        .expect("direct local-slot apply lowers");
    let env_get_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let apply_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_apply());
    let expected_env_get_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
            .expect("env-get helper signature is core-owned"),
    )
    .expect("env-get signature lowers to CLIF");
    let expected_apply_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_APPLY_SYMBOL)
            .expect("apply helper signature is core-owned"),
    )
    .expect("apply signature lowers to CLIF");

    assert_eq!(
        function.dfg.signatures[env_get_import.1.signature],
        expected_env_get_signature
    );
    assert_eq!(
        function.dfg.signatures[apply_import.1.signature],
        expected_apply_signature
    );
}

#[test]
fn apply_local_slots_ir_thunk_body_reads_function_and_argument_then_calls_apply() {
    let arena = apply_local_slots_arena(3, 8);

    let function = lower_apply_local_slots_ir_thunk_body(&arena, IrId::new(2))
        .expect("direct local-slot apply lowers");
    let (env_get, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let (apply, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_apply());
    let calls = call_insts(&function);
    assert_eq!(calls.len(), 3);
    let function_env_get_call = calls[0];
    let argument_env_get_call = calls[1];
    let apply_call = calls[2];
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[function_env_get_call] else {
        panic!("apply lowerer emits function env-get call first");
    };
    assert_eq!(func_ref, env_get);
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[argument_env_get_call] else {
        panic!("apply lowerer emits argument env-get call second");
    };
    assert_eq!(func_ref, env_get);
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[apply_call] else {
        panic!("apply lowerer emits apply call third");
    };
    assert_eq!(func_ref, apply);

    assert_eq!(
        opcodes(&function),
        vec![
            Opcode::Iconst,
            Opcode::Call,
            Opcode::Iconst,
            Opcode::Call,
            Opcode::Call,
            Opcode::Return,
        ]
    );
    assert_eq!(iconst_words(&function), vec![3, 8]);
    assert_eq!(
        function.dfg.inst_args(function_env_get_call)[0],
        entry_block_values(&function)[1]
    );
    assert_eq!(
        function.dfg.inst_args(argument_env_get_call)[0],
        entry_block_values(&function)[1]
    );
    assert_eq!(
        function
            .dfg
            .value_type(function.dfg.inst_args(function_env_get_call)[1]),
        types::I32
    );
    assert_eq!(
        function
            .dfg
            .value_type(function.dfg.inst_args(argument_env_get_call)[1]),
        types::I32
    );
    assert_eq!(
        function.dfg.inst_args(apply_call),
        &[
            entry_block_values(&function)[0],
            function.dfg.inst_results(function_env_get_call)[0],
            function.dfg.inst_results(function_env_get_call)[1],
            function.dfg.inst_results(argument_env_get_call)[0],
            function.dfg.inst_results(argument_env_get_call)[1],
        ]
    );
    assert_eq!(
        return_operands(&function),
        function.dfg.inst_results(apply_call)
    );
    verify_clif_function(&function).expect("apply function verifies independently");
}

#[test]
fn apply_local_slots_ir_thunk_body_lowers_direct_apply_thunk_alloc_root() {
    let arena = apply_local_slots_thunk_arena(13, 21);

    let artifact = lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(3))
        .expect("direct apply thunk allocation lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(3))
    );
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
    assert_eq!(iconst_words(artifact.function()), vec![13, 21]);
}

#[test]
fn apply_local_slots_ir_thunk_body_rejects_unsupported_roots_and_bodies() {
    let root_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(1, 2),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let root_error = lower_apply_local_slots_ir_thunk_body(&root_arena, IrId::new(0))
        .expect_err("non-apply root is not covered by apply lowering");
    let body_error = lower_apply_local_slots_ir_thunk_body(&body_arena, IrId::new(1))
        .expect_err("non-apply thunk body is not covered by apply lowering");

    assert!(
        matches!(root_error, JitLowerError::UnsupportedApplyRoot { kind } if kind == IrKind::Int)
    );
    assert!(
        matches!(body_error, JitLowerError::UnsupportedApplyBody { kind } if kind == IrKind::Int)
    );
}

#[test]
fn apply_local_slots_ir_thunk_body_rejects_malformed_wrappers() {
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

    let missing_body_error =
        lower_apply_local_slots_ir_thunk_body(&missing_body_arena, IrId::new(0))
            .expect_err("missing apply thunk body is rejected");
    let malformed_wrapper_error =
        lower_apply_local_slots_ir_thunk_body(&malformed_wrapper_arena, IrId::new(0))
            .expect_err("apply thunk allocation without body node is malformed");

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
fn apply_local_slots_ir_thunk_body_rejects_malformed_apply_payloads_and_children() {
    let malformed_payload_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Apply,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let missing_child_arena = IrArena::from_raw_parts(
        vec![
            local_var_node(1),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(9),
                },
            ),
        ],
        Vec::new(),
    );
    let unsupported_child_arena = IrArena::from_raw_parts(
        vec![
            local_var_node(1),
            IrNode::new(
                IrKind::Int,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Int(2),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    let malformed_child_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            ),
            local_var_node(2),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );

    let malformed_payload_error =
        lower_apply_local_slots_ir_thunk_body(&malformed_payload_arena, IrId::new(0))
            .expect_err("apply without pair payload is rejected");
    let missing_child_error =
        lower_apply_local_slots_ir_thunk_body(&missing_child_arena, IrId::new(1))
            .expect_err("apply with missing child is rejected");
    let unsupported_child_error =
        lower_apply_local_slots_ir_thunk_body(&unsupported_child_arena, IrId::new(2))
            .expect_err("apply with non-local child is rejected");
    let malformed_child_error =
        lower_apply_local_slots_ir_thunk_body(&malformed_child_arena, IrId::new(2))
            .expect_err("apply with malformed local child is rejected");

    assert!(matches!(
        malformed_payload_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::Apply,
            data: IrData::None,
            expected: "application pair payload",
        }
    ));
    assert!(
        matches!(missing_child_error, JitLowerError::MissingApplyChild { child } if child == IrId::new(9))
    );
    assert!(matches!(
        unsupported_child_error,
        JitLowerError::UnsupportedApplyChild {
            child,
            kind: IrKind::Int,
        } if child == IrId::new(1)
    ));
    assert!(matches!(
        malformed_child_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data: IrData::None,
            expected: "local slot payload",
        }
    ));
}
