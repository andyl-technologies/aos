use ratchet_core::{EffectClass, IrArena, IrData, IrId, IrKind, IrNode, syntax::Span};
use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCraneliftRegisteredTier1SlotPreflight, JitTier,
    JitTieredCodeSlot, TierUpCounter, TierUpDemandHint, TierUpPolicy,
};
use ratchet_oracle::eval::EvalThunk;

use crate::jit::{
    NixJitThunkInstallGap, NixJitTier1ConformanceGap,
    nix_jit_force_aware_tier1_conformance_readiness_for_ir_root,
    nix_jit_runtime_symbol_address_candidate_preflight,
    nix_jit_tier1_conformance_readiness_for_ir_root,
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

fn hot_slot() -> JitTieredCodeSlot {
    JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1))
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
fn tier1_conformance_readiness_reports_apply_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);
    let thunk = EvalThunk::new(IrId::new(2));

    let readiness = nix_jit_tier1_conformance_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
        &thunk,
    )
    .expect("apply JIT conformance readiness report builds");

    assert!(
        readiness
            .thunk_install_readiness()
            .install_plan()
            .did_compile()
    );
    assert_eq!(
        readiness
            .thunk_install_readiness()
            .install_plan()
            .slot()
            .current_tier(),
        JitTier::Tier1Baseline
    );
    assert!(!readiness.is_ready_for_jit_enabled_harness());
    assert!(!readiness.safe_preconditions_met());
    assert!(
        readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolRegistration {
            missing_count: readiness.runtime_symbol_registration().gaps().len(),
        })
    );
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
    }));
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
    }));
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
    }));
    let promoted = readiness
        .thunk_install_readiness()
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
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
}

#[test]
fn force_aware_tier1_conformance_readiness_reports_apply_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);
    let thunk = EvalThunk::new(IrId::new(2));

    let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
        &thunk,
    )
    .expect("force-aware apply JIT conformance readiness report builds");

    assert!(
        readiness
            .thunk_install_readiness()
            .install_plan()
            .did_compile()
    );
    assert_eq!(
        readiness
            .thunk_install_readiness()
            .install_plan()
            .slot()
            .invocation_counter()
            .invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(
        readiness
            .thunk_install_readiness()
            .install_plan()
            .slot()
            .current_tier(),
        JitTier::Tier1Baseline
    );
    assert!(!readiness.is_ready_for_jit_enabled_harness());
    assert!(!readiness.safe_preconditions_met());
    assert!(
        readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolRegistration {
            missing_count: readiness.runtime_symbol_registration().gaps().len(),
        })
    );
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
    }));
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
    }));
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
    }));
    let promoted = readiness
        .thunk_install_readiness()
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
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
}
