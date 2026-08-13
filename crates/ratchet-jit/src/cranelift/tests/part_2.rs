//! Cranelift finalize/execute tests (moved verbatim from `cranelift.rs`).

use super::*;

#[test]
fn registered_tier1_slot_preflight_installs_forced_env_get_artifact_with_candidates() {
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            5,
        ),
    ]);

    let preflight = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
        forced_env_get_artifact(7),
        &candidates,
    )
    .expect("registered tier-1 forced env-get slot preflight builds");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().is_tier1_installed());
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(preflight.finalized_function().compiled_code_ptr())
    );
    assert_eq!(preflight.finalization().artifact_runtime_imports().len(), 4);
    assert!(
        preflight
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        preflight
            .finalization()
            .imported_symbol_for("aos_force")
            .is_some()
    );
    assert!(
        preflight
            .finalization()
            .registration_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(
        preflight
            .finalization()
            .registration_gap_for_symbol("aos_force")
            .is_none()
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_tier1_slot_preflight_installs_update_artifact_with_candidates() {
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            5,
        ),
        synthetic_address_candidate(
            "aos_update",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            7,
        ),
    ]);

    let preflight = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
        update_artifact(7, 9),
        &candidates,
    )
    .expect("registered tier-1 update slot preflight builds");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.2.thunk_body"
    );
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().is_tier1_installed());
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(preflight.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(preflight.finalization().artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update"
        ]
    );
    assert!(
        preflight
            .finalization()
            .imported_symbol_for("aos_update")
            .is_some()
    );
    assert!(
        preflight
            .finalization()
            .registered_symbol_for("aos_update")
            .is_some()
    );
    assert!(
        preflight
            .finalization()
            .registration_gap_for_symbol("aos_update")
            .is_none()
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_tier1_slot_preflight_installs_constant_artifact_with_registration_gaps() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::int(21)).expect("constant artifact lowers");

    let preflight = jit_cranelift_registered_tier1_slot_preflight_with_candidates(artifact, &[])
        .expect("registered constant tier-1 slot preflight builds");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.constant_smoke.thunk_body"
    );
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(preflight.finalized_function().compiled_code_ptr())
    );
    assert!(
        preflight
            .finalization()
            .artifact_runtime_imports()
            .is_empty()
    );
    assert!(preflight.finalization().registered_symbols().is_empty());
    assert!(matches!(
        preflight
            .finalization()
            .registration_gap_for_symbol("aos_env_get"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                ..
            }
        )
    ));
    assert!(!preflight.finalization().is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_tier1_slot_preflight_requires_candidates_for_artifact_imports() {
    let Err(error) =
        jit_cranelift_registered_tier1_slot_preflight_with_candidates(env_get_artifact(7), &[])
    else {
        panic!("registered tier-1 env-get slot requires env helper candidate");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn registered_tier1_slot_preflight_preserves_unresolved_artifact_import_readiness() {
    let Err(error) = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
        artifact_with_unknown_runtime_helper_import(),
        &[],
    ) else {
        panic!("unresolved artifact import must stay a readiness error");
    };

    let JitCraneliftModuleSetupError::Readiness(
        JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
    ) = error
    else {
        panic!("expected unresolved artifact-import readiness error");
    };

    assert!(preflight.artifact_runtime_imports().is_empty());
    assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
    assert!(!preflight.is_complete());
}

#[test]
fn registered_tier1_slot_preflight_rejects_wrong_kind_candidates_for_artifact_imports() {
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Builtin,
        3,
    )];

    let Err(error) = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
        env_get_artifact(7),
        &candidates,
    ) else {
        panic!("wrong-kind env helper candidate must not satisfy artifact imports");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn promotion_preflight_records_cold_invocation_without_lowering_unsupported_root() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("cold unsupported root does not lower");

    assert!(!result.did_compile());
    assert_eq!(
        result.decision(),
        TierUpDecision::StayInTier(JitTier::Tier0Oracle)
    );
    assert_eq!(result.slot().invocation_counter().invocations(), 1);
    assert_eq!(result.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(result.promoted_preflight().is_none());
    assert!(!result.owns_encapsulated_module());
}

#[test]
fn promotion_preflight_compiles_literal_root_at_threshold() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 2),
            EffectClass::pure(),
            IrData::Int(99),
        )],
        Vec::new(),
    );
    let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("threshold literal root compiles");

    assert!(result.did_compile());
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    assert_eq!(
        result.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = result
        .promoted_preflight()
        .expect("promotion result owns compiled preflight");
    assert_eq!(
        promoted.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn promotion_preflight_compiles_multi_use_before_threshold() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(false),
        )],
        Vec::new(),
    );
    let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
    )
    .expect("multi-use literal root compiles");

    assert!(result.did_compile());
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(false, true))
    );
    assert_eq!(result.slot().invocation_counter().invocations(), 1);
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(result.promoted_preflight().is_some());
}

#[test]
fn promotion_preflight_installed_slot_skips_repeat_compilation() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let mut slot = JitTieredCodeSlot::with_counter(TierUpCounter::new(u64::MAX));
    let code_ptr = JitCompiledCodePointer::from_non_null(NonNull::dangling());
    slot.install_tier1_code(code_ptr)
        .expect("test tier-1 metadata installs");

    let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
        slot,
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
    )
    .expect("installed slot does not recompile");

    assert!(!result.did_compile());
    assert_eq!(
        result.decision(),
        TierUpDecision::StayInTier(JitTier::Tier1Baseline)
    );
    assert_eq!(result.slot().invocation_counter().invocations(), u64::MAX);
    assert_eq!(result.slot().tier1_code_ptr(), Some(code_ptr));
    assert!(result.promoted_preflight().is_none());
}

#[test]
fn promotion_preflight_reports_lowering_error_only_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    );
    let Err(error) = result else {
        panic!("promoted unsupported root reports lowering error");
    };

    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(
        error.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    let JitCraneliftModuleSetupError::LowerTier1Artifact { root, source } = error.setup_error()
    else {
        panic!("expected tier-1 lowering error");
    };
    assert_eq!(*root, IrId::new(0));
    assert!(matches!(
        source,
        JitLowerError::UnsupportedIrRoot { kind: IrKind::Str }
    ));
}

#[test]
fn registered_promotion_preflight_records_cold_invocation_without_lowering_unsupported_root() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &[],
    )
    .expect("cold unsupported root does not lower");

    assert!(!result.did_compile());
    assert_eq!(
        result.decision(),
        TierUpDecision::StayInTier(JitTier::Tier0Oracle)
    );
    assert_eq!(result.slot().invocation_counter().invocations(), 1);
    assert_eq!(result.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(result.promoted_preflight().is_none());
    assert!(!result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_compiles_env_get_root_at_threshold_with_candidate() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 9 },
        )],
        Vec::new(),
    );
    let env_get_address = synthetic_runtime_import_address();
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
        env_get_address,
    )];

    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &candidates,
    )
    .expect("threshold env-get root compiles with registered helper");

    assert!(result.did_compile());
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    assert_eq!(
        result.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = result
        .promoted_preflight()
        .expect("promotion result owns registered compiled preflight");
    assert_eq!(
        promoted.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 1);
    assert_eq!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .expect("env helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        env_get_address
    );
    assert!(
        promoted
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_compiles_apply_root_with_candidates() {
    let arena = apply_arena(4, 6);
    let candidates = [
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_apply",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl),
            7,
        ),
    ];

    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
        &candidates,
    )
    .expect("threshold apply root compiles with registered helpers");

    assert!(result.did_compile());
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = result
        .promoted_preflight()
        .expect("promotion result owns registered compiled preflight");
    assert_eq!(
        promoted.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(2))
    );
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(JitModuleArtifactRuntimeImport::symbol_name)
            .collect::<Vec<_>>(),
        ["aos_env_get", "aos_apply"]
    );
    assert!(
        promoted
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        promoted
            .finalization()
            .imported_symbol_for("aos_apply")
            .is_some()
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_apply")
            .is_some()
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_compiles_update_root_with_candidates() {
    let arena = update_arena(4, 6);
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            5,
        ),
        synthetic_address_candidate(
            "aos_update",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            7,
        ),
    ]);

    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
        &candidates,
    )
    .expect("threshold update root compiles with registered helpers");

    assert!(result.did_compile());
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = result
        .promoted_preflight()
        .expect("promotion result owns registered compiled preflight");
    assert_eq!(
        promoted.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(2))
    );
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted.finalization().artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update"
        ]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_update")
            .is_some()
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_compiles_wrapped_env_get_root_with_candidate() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(1)),
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(1, 5),
                EffectClass::pure(),
                IrData::Local { slot: 11 },
            ),
        ],
        Vec::new(),
    );
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
        synthetic_runtime_import_address(),
    )];

    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
        &candidates,
    )
    .expect("wrapped env-get root compiles with registered helper");

    assert!(result.did_compile());
    let promoted = result
        .promoted_preflight()
        .expect("promotion result owns registered compiled preflight");
    assert_eq!(
        promoted.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(0))
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 1);
    assert!(
        promoted
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_compiles_literal_root_without_candidates() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );
    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
        &[],
    )
    .expect("multi-use literal root compiles without runtime candidates");

    assert!(result.did_compile());
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(false, true))
    );
    let promoted = result
        .promoted_preflight()
        .expect("promotion result owns registered compiled preflight");
    assert!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .is_empty()
    );
    assert!(promoted.finalization().registered_symbols().is_empty());
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_compiles_wrapped_literal_root_without_candidates() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(1)),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(1, 5),
                EffectClass::pure(),
                IrData::Int(123),
            ),
        ],
        Vec::new(),
    );

    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
        &[],
    )
    .expect("wrapped literal root compiles without runtime candidates");

    assert!(result.did_compile());
    let promoted = result
        .promoted_preflight()
        .expect("promotion result owns registered compiled preflight");
    assert_eq!(
        promoted.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(0))
    );
    assert!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .is_empty()
    );
    assert!(promoted.finalization().registered_symbols().is_empty());
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_reports_missing_candidate_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 9 },
        )],
        Vec::new(),
    );
    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &[],
    );
    let Err(error) = result else {
        panic!("promoted env-get root requires registered env helper");
    };

    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(
        error.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        error.setup_error()
    else {
        panic!("expected artifact runtime-import registration guard");
    };
    assert_eq!(symbol_names, &["aos_env_get".to_owned()]);
}
