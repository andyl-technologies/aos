use ratchet_core::{
    EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    syntax::Span,
};
use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitTier, JitTieredCodeSlot, TierUpCounter,
    TierUpDemandHint, TierUpPolicy,
    jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
    jit_runtime_symbol_registration_preflight_with_candidates,
};

use super::*;

#[test]
fn jit_runtime_symbol_address_candidate_preflight_projects_oracle_helper_addresses() {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");

    let env_get = preflight
        .address_candidate_for("aos_env_get")
        .expect("environment helper has a Rust-callable address candidate");

    assert_eq!(
        env_get.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess)
    );
    assert_ne!(env_get.address().as_nonzero_usize().get(), 0);
    assert!(preflight.missing_binding_for("aos_env_get").is_none());
    assert!(preflight.missing_binding_for("aos_force").is_some());
    assert!(!preflight.is_complete());
}

#[test]
fn jit_runtime_symbol_address_candidates_feed_jit_registration_preflight() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");

    let registration = jit_runtime_symbol_registration_preflight_with_candidates(
        candidate_preflight.address_candidates(),
    )
    .expect("JIT registration preflight accepts oracle helper address candidates");

    assert!(
        registration
            .binding_for_symbol("aos_env_get")
            .is_some_and(|binding| binding.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(registration.gap_for_symbol("aos_env_get").is_none());
    assert!(!registration.is_complete());
}

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
