//! Tier-1 JIT promotion/registration tests (moved verbatim from `tests.rs`).

use super::*;

#[test]
fn jit_runtime_symbol_address_candidates_feed_registered_env_promotion() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 1 },
        )],
        Vec::new(),
    );

    let promotion = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        candidate_preflight.address_candidates(),
    )
    .expect("registered env promotion accepts runtime address candidates");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_records_cold_invocation_without_lowering() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("cold unsupported root does not lower");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(promotion.promoted_preflight().is_none());
    assert!(!promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_keeps_cold_path_before_candidates() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        || {
            Err(
                NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                    symbol_name: "aos_env_get",
                },
            )
        },
    )
    .expect("cold attempt returns before address candidates are needed");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_reports_candidate_failure_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let result = nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        || {
            Err(
                NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                    symbol_name: "aos_env_get",
                },
            )
        },
    );

    let Err(error) = result else {
        panic!("promotion should require address candidates");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    let NixJitRegisteredTier1PromotionError::AddressCandidates { source, .. } = error else {
        panic!("expected address candidate failure");
    };
    assert!(matches!(
        source,
        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
            symbol_name: "aos_env_get"
        }
    ));
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_uses_runtime_candidates() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("aos-nix wrapper promotes env slot with runtime candidates");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_promotion_preflight_keeps_cold_path_before_candidates() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let promotion =
        nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            || {
                Err(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_force",
                    },
                )
            },
        )
        .expect("cold force-aware attempt returns before address candidates are needed");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(promotion.promoted_preflight().is_none());
    assert!(!promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_promotion_reports_candidate_failure_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let result =
        nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            || {
                Err(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_force",
                    },
                )
            },
        );

    let Err(error) = result else {
        panic!("promotion should require address candidates");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    let NixJitRegisteredTier1PromotionError::AddressCandidates { source, .. } = error else {
        panic!("expected address candidate failure");
    };
    assert!(matches!(
        source,
        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
            symbol_name: "aos_force"
        }
    ));
}

#[test]
fn nix_jit_force_aware_registered_tier1_promotion_preflight_promotes_literals() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );

    let promotion = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
    )
    .expect("force-aware literal root promotes through oracle bridge");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .is_empty()
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_promotion_preflight_installs_forced_env_slot() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    assert!(
        candidate_preflight
            .address_candidate_for("aos_env_get")
            .is_some()
    );
    assert!(
        candidate_preflight
            .address_candidate_for("aos_force")
            .is_some()
    );
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let promotion = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("force-aware env-slot promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 4);
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_force")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_force")
                    .expect("force candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_promotion_keeps_cold_path_before_candidates() {
    let ir = minimal_ir(
        IrId::new(0),
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        ),
    );

    let promotion =
        nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidate_source(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            || {
                Err(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_select_ic",
                    },
                )
            },
        )
        .expect("cold full-IR attempt returns before address candidates are needed");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(promotion.promoted_preflight().is_none());
    assert!(!promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_promotion_installs_static_select() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(9);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-select promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_select_ic"]
    );
    for symbol_name in ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_select_ic"] {
        assert!(
            promoted
                .finalization()
                .registered_symbol_for(symbol_name)
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("runtime candidate exists")
                        .address()),
            "{symbol_name} should be registered from runtime address candidates"
        );
    }
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_promotion_installs_static_select_scalar_default() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_scalar_default_ir(12, 99);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-select default promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_has_attr", "aos_select_ic"]
    );
    for symbol_name in ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_has_attr", "aos_select_ic"] {
        assert!(
            promoted
                .finalization()
                .registered_symbol_for(symbol_name)
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("runtime candidate exists")
                        .address()),
            "{symbol_name} should be registered from runtime address candidates"
        );
    }
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_promotion_installs_static_has_attr() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(10);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-hasAttr promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_has_attr"]
    );
    for symbol_name in ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_has_attr"] {
        assert!(
            promoted
                .finalization()
                .registered_symbol_for(symbol_name)
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("runtime candidate exists")
                        .address()),
            "{symbol_name} should be registered from runtime address candidates"
        );
    }
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_promotion_installs_update() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = update_ir(10, 12);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir.arena,
        ir.root,
    )
    .expect("update promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_update"]
    );
    for symbol_name in ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_update"] {
        assert!(
            promoted
                .finalization()
                .registered_symbol_for(symbol_name)
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("runtime candidate exists")
                        .address()),
            "{symbol_name} should be registered from runtime address candidates"
        );
    }
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_install_plan_carries_static_select_pointer_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(11);

    let plan = nix_jit_registered_tier1_install_plan_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-select install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_select_ic"]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_select_ic")
                    .expect("select candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_full_ir_install_plan_carries_static_has_attr_pointer_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(14);

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-hasAttr install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_has_attr"]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_has_attr")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_has_attr")
                    .expect("hasAttr candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_full_ir_install_plan_carries_static_select_pointer_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(13);

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-select install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_select_ic"]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_select_ic")
                    .expect("select candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}
