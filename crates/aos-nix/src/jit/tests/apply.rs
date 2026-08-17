use ratchet_core::{EffectClass, IrArena, IrData, IrId, IrKind, IrNode, syntax::Span};
use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCraneliftRegisteredTier1SlotPreflight, JitTier,
    JitTieredCodeSlot, TierUpCounter, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
};

use crate::jit::{
    nix_jit_force_aware_registered_tier1_install_plan_for_ir_root,
    nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root,
    nix_jit_registered_tier1_install_plan_for_ir_root,
    nix_jit_registered_tier1_promotion_preflight_for_ir_root,
    nix_jit_runtime_symbol_address_candidate_preflight,
};

fn apply_arena(function_slot: u32, argument_slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local {
                    slot: function_slot,
                },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local {
                    slot: argument_slot,
                },
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
    )
}

fn artifact_runtime_import_names(
    preflight: &JitCraneliftRegisteredTier1SlotPreflight,
) -> Vec<&str> {
    preflight
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect()
}

#[test]
fn jit_runtime_symbol_address_candidates_feed_registered_apply_promotion() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);

    let promotion = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
        candidate_preflight.address_candidates(),
    )
    .expect("registered apply promotion accepts runtime address candidates");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_apply"]
    );
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
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_apply")
                    .expect("apply candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_uses_runtime_apply_candidates() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
    )
    .expect("aos-nix wrapper promotes apply root with runtime candidates");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_apply"]
    );
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
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_apply")
                    .expect("apply candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_promotion_preflight_installs_apply_root() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    assert!(
        candidate_preflight
            .address_candidate_for("aos_env_get")
            .is_some()
    );
    assert!(
        candidate_preflight
            .address_candidate_for("aos_apply")
            .is_some()
    );
    let arena = apply_arena(4, 6);

    let promotion = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
    )
    .expect("force-aware apply promotion finalizes with runtime address candidates");

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
        ["aos_env_get", "aos_apply"]
    );
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
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_apply")
                    .expect("apply candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_install_plan_carries_apply_slot_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);

    let plan = nix_jit_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
    )
    .expect("apply root builds a registered install plan");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_apply"]
    );
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
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_apply")
                    .expect("apply candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_install_plan_carries_apply_slot_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
    )
    .expect("force-aware apply install plan finalizes with runtime address candidates");

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
        ["aos_env_get", "aos_apply"]
    );
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
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_apply")
                    .expect("apply candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}
