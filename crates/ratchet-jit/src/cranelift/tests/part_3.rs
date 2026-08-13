//! Cranelift finalize/execute tests (moved verbatim from `cranelift.rs`).

use super::*;

#[test]
fn registered_lowered_ir_promotion_preflight_installs_static_select_root() {
    let ir = static_select_ir(9);
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
            "aos_select_ic",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            7,
        ),
    ]);

    let result =
        jit_cranelift_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &ir,
            ir.root,
            &candidates,
        )
        .expect("full-IR registered promotion finalizes static select");

    assert!(result.did_compile());
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = result
        .promoted_preflight()
        .expect("promotion owns registered tier-1 preflight");
    assert_eq!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(JitModuleArtifactRuntimeImport::symbol_name)
            .collect::<Vec<_>>(),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_select_ic"
        ]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_some()
    );
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
}

#[test]
fn registered_lowered_ir_promotion_preflight_installs_update_root() {
    let ir = update_ir(9, 11);
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

    let result =
        jit_cranelift_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &ir,
            ir.root,
            &candidates,
        )
        .expect("full-IR registered promotion finalizes bounded update");

    assert!(result.did_compile());
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = result
        .promoted_preflight()
        .expect("promotion owns registered tier-1 preflight");
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
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
}

#[test]
fn force_aware_registered_promotion_preflight_records_cold_invocation_without_lowering() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
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
fn force_aware_registered_promotion_preflight_compiles_literal_root_without_candidates() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );
    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(0),
            &[],
        )
        .expect("force-aware literal root compiles without runtime candidates");

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
fn force_aware_registered_lowered_ir_promotion_preflight_installs_static_select_root() {
    let ir = static_select_ir(13);
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            11,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            13,
        ),
        synthetic_address_candidate(
            "aos_select_ic",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            17,
        ),
    ]);

    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &candidates,
        )
        .expect("full-IR force-aware promotion finalizes static select");

    assert_eq!(
        result.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    let promoted = result
        .promoted_preflight()
        .expect("promotion owns registered tier-1 preflight");
    assert_eq!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(JitModuleArtifactRuntimeImport::symbol_name)
            .collect::<Vec<_>>(),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_select_ic"
        ]
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
            .registered_symbol_for("aos_force")
            .is_some()
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_some()
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_apply")
            .is_none()
    );
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn force_aware_registered_lowered_ir_promotion_preflight_installs_update_root() {
    let ir = update_ir(13, 15);
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            11,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            13,
        ),
        synthetic_address_candidate(
            "aos_update",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            17,
        ),
    ]);

    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &candidates,
        )
        .expect("full-IR force-aware promotion finalizes bounded update");

    assert_eq!(
        result.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    let promoted = result
        .promoted_preflight()
        .expect("promotion owns registered tier-1 preflight");
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
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn force_aware_registered_promotion_preflight_installs_forced_env_slot() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 9 },
        )],
        Vec::new(),
    );
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

    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &candidates,
        )
        .expect("force-aware env-slot promotion finalizes with registered helpers");

    assert_eq!(
        result.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    assert!(result.did_compile());
    let promoted = result
        .promoted_preflight()
        .expect("promotion owns registered tier-1 preflight");
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 4);
    assert!(
        promoted
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        promoted
            .finalization()
            .imported_symbol_for("aos_force")
            .is_some()
    );
    assert_eq!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .expect("env helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        3
    );
    assert_eq!(
        promoted
            .finalization()
            .registered_symbol_for("aos_force")
            .expect("force helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        5
    );
    assert!(
        promoted
            .finalization()
            .registration_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(
        promoted
            .finalization()
            .registration_gap_for_symbol("aos_force")
            .is_none()
    );
    assert!(!promoted.finalization().is_complete());
    assert!(result.owns_encapsulated_module());
}

#[test]
fn force_aware_registered_promotion_preflight_preserves_wrapped_apply_helper_boundary() {
    let arena = wrapped_apply_arena(10, 12);
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

    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(3),
            &candidates,
        )
        .expect("force-aware wrapped apply promotion finalizes with apply helper");

    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(false, true))
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(result.did_compile());
    let promoted = result
        .promoted_preflight()
        .expect("promotion owns registered tier-1 preflight");
    assert_eq!(
        promoted.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(3))
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
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_force")
            .is_none()
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn force_aware_registered_promotion_preflight_requires_force_candidate() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 9 },
        )],
        Vec::new(),
    );
    let candidates = with_stack_map_candidates([synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
        3,
    )]);

    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &candidates,
        );
    let Err(error) = result else {
        panic!("force-aware env-slot promotion requires a force helper candidate");
    };

    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(error.slot().tier1_code_ptr().is_none());
    assert_eq!(
        error.decision().reasons(),
        Some(TierUpReasons::new(true, false))
    );
    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        error.setup_error()
    else {
        panic!("expected force helper registration guard");
    };
    assert_eq!(symbol_names, &["aos_force".to_owned()]);
}

#[test]
fn force_aware_registered_promotion_preflight_forces_wrapped_env_slot() {
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

    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(0),
            &candidates,
        )
        .expect("wrapped force-aware env-slot promotion finalizes with registered helpers");

    assert_eq!(
        result.decision().reasons(),
        Some(TierUpReasons::new(false, true))
    );
    assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(result.did_compile());
    let promoted = result
        .promoted_preflight()
        .expect("promotion owns registered tier-1 preflight");
    assert_eq!(
        result.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 4);
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_force")
            .is_some()
    );
    assert!(result.owns_encapsulated_module());
}

#[test]
fn force_aware_registered_promotion_preflight_reports_malformed_local_payload_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let result =
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &[],
        );
    let Err(error) = result else {
        panic!("hot malformed local root reports a lowering error");
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
        panic!("expected force-aware lowering error");
    };
    assert_eq!(*root, IrId::new(0));
    assert!(matches!(
        source,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data: IrData::None,
            expected: "local slot payload",
        }
    ));
}

#[test]
fn registered_promotion_preflight_installed_slot_skips_repeat_compilation() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 9 },
        )],
        Vec::new(),
    );
    let mut slot = JitTieredCodeSlot::with_counter(TierUpCounter::new(u64::MAX));
    let code_ptr = JitCompiledCodePointer::from_non_null(NonNull::dangling());
    slot.install_tier1_code(code_ptr)
        .expect("test tier-1 metadata installs");

    let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        slot,
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
        &[],
    )
    .expect("installed registered slot does not recompile");

    assert!(!result.did_compile());
    assert_eq!(
        result.decision(),
        TierUpDecision::StayInTier(JitTier::Tier1Baseline)
    );
    assert_eq!(result.slot().invocation_counter().invocations(), u64::MAX);
    assert_eq!(result.slot().tier1_code_ptr(), Some(code_ptr));
    assert!(result.promoted_preflight().is_none());
    assert!(!result.owns_encapsulated_module());
}

#[test]
fn registered_promotion_preflight_reports_lowering_error_only_after_promotion() {
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
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &[],
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
fn complete_module_setup_refuses_current_runtime_symbol_gaps() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::null()).expect("constant artifact lowers");
    let Err(error) = jit_cranelift_module_setup_for_artifact(&artifact) else {
        panic!("runtime-symbol gaps must block complete JIT module setup");
    };

    let JitCraneliftModuleSetupError::Readiness(
        JitModuleReadinessError::IncompleteRuntimeSymbols { preflight },
    ) = error
    else {
        panic!("expected incomplete readiness error");
    };

    assert!(
        preflight
            .declaration_for_symbol("nix.builtin.derivationStrict")
            .is_some()
    );
    assert!(preflight.declaration_for_symbol("aos_force").is_some());
    assert!(
        preflight
            .declaration_for_symbol("aos_blackhole_check")
            .is_some()
    );
    assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
}
