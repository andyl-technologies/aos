//! Conformance-scan tests (moved verbatim; helpers in the parent module).

use super::*;

#[test]
fn tier1_conformance_readiness_reports_update_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = update_ir(18, 19);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_tier1_conformance_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir.arena,
        ir.root,
        &thunk,
    )
    .expect("update conformance readiness report builds");

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
    let artifact_runtime_imports = promoted
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(
        artifact_runtime_imports,
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
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_update")
                    .expect("update candidate exists")
                    .address())
    );
}

#[test]
fn force_aware_tier1_conformance_readiness_reports_static_select_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(14);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_lowered_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
        &thunk,
    )
    .expect("force-aware full-IR static-select conformance readiness report builds");

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
    let artifact_runtime_imports = promoted
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(
        artifact_runtime_imports,
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
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_select_ic")
                    .expect("select candidate exists")
                    .address())
    );
}

#[test]
fn force_aware_tier1_conformance_readiness_reports_static_has_attr_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(16);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_lowered_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
        &thunk,
    )
    .expect("force-aware full-IR static-hasAttr conformance readiness report builds");

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
    let artifact_runtime_imports = promoted
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(
        artifact_runtime_imports,
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr"
        ]
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
}

#[test]
fn tier1_conformance_readiness_reports_static_select_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(15);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_tier1_conformance_readiness_for_lowered_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
        &thunk,
    )
    .expect("full-IR static-select conformance readiness report builds");

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
    let artifact_runtime_imports = promoted
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(
        artifact_runtime_imports,
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
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_select_ic")
                    .expect("select candidate exists")
                    .address())
    );
}

#[test]
fn tier1_conformance_readiness_reports_static_has_attr_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(17);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_tier1_conformance_readiness_for_lowered_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
        &thunk,
    )
    .expect("full-IR static-hasAttr conformance readiness report builds");

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
    let artifact_runtime_imports = promoted
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(
        artifact_runtime_imports,
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr"
        ]
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
}
