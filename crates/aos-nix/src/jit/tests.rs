use ratchet_core::{EffectClass, IrArena, IrData, IrId, IrKind, IrNode, syntax::Span};
use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCraneliftModuleSetupError, JitTier, JitTieredCodeSlot,
    TierUpCounter, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
};

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
    .expect("registered env promotion accepts oracle helper address candidates");

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
fn nix_jit_registered_tier1_promotion_preflight_uses_oracle_candidates() {
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
    .expect("aos-nix wrapper promotes env slot with oracle candidates");

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
fn nix_jit_force_aware_registered_tier1_promotion_preflight_reports_missing_force_candidate() {
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
            .is_none()
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

    let result = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    );
    let Err(error) = result else {
        panic!("force-aware env-slot promotion requires an aos_force candidate");
    };

    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(error.slot().tier1_code_ptr().is_none());
    let NixJitRegisteredTier1PromotionError::Cranelift(source) = error else {
        panic!("expected Cranelift promotion failure");
    };
    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        source.setup_error()
    else {
        panic!("expected force helper registration guard");
    };
    assert_eq!(symbol_names, &["aos_force".to_owned()]);
}

#[test]
fn nix_jit_force_aware_promotion_reports_missing_force_candidate_for_wrapped_slot() {
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

    let result = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    );
    let Err(error) = result else {
        panic!("wrapped force-aware env-slot promotion requires an aos_force candidate");
    };

    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(error.slot().tier1_code_ptr().is_none());
    let NixJitRegisteredTier1PromotionError::Cranelift(source) = error else {
        panic!("expected Cranelift promotion failure");
    };
    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        source.setup_error()
    else {
        panic!("expected force helper registration guard");
    };
    assert_eq!(symbol_names, &["aos_force".to_owned()]);
}

#[test]
fn nix_jit_registered_tier1_install_plan_records_cold_slot_without_pointer() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let plan = nix_jit_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("cold unsupported root records slot state");

    assert!(!plan.did_compile());
    assert!(!plan.is_ready_for_install());
    assert_eq!(plan.slot().invocation_counter().invocations(), 1);
    assert_eq!(plan.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(plan.tier1_code_ptr().is_none());
    assert!(plan.promoted_preflight().is_none());
    assert!(!plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_install_plan_carries_promoted_slot_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 3 },
        )],
        Vec::new(),
    );

    let plan = nix_jit_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("env slot root builds a registered install plan");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
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
    assert!(plan.owns_encapsulated_module());
}
