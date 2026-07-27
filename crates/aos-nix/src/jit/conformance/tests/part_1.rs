//! Conformance-scan tests (moved verbatim; helpers in the parent module).

use super::*;

#[test]
fn literal_native_differential_matches_direct_scalar_values() {
    let cases = [
        (int_arena(-17), Value::int(-17)),
        #[cfg(not(feature = "candidate_c_value"))]
        (float_arena(-13.5), Value::float(-13.5)),
        (bool_arena(false), Value::bool(false)),
        (null_arena(), Value::null()),
    ];

    for (arena, expected) in cases {
        let differential = nix_jit_literal_native_differential_for_ir_root(&arena, IrId::new(0))
            .expect("literal native differential succeeds");

        assert_eq!(differential.root(), IrId::new(0));
        assert!(differential.values_match());
        assert!(differential.owns_encapsulated_module());
        assert!(differential.oracle_value().raw_eq(expected));
        assert!(differential.native_value().raw_eq(expected));
        assert_eq!(
            differential
                .native_invocation()
                .finalization()
                .artifact()
                .source(),
            JitClifArtifactSource::IrRoot(IrId::new(0))
        );
        assert_eq!(
            differential
                .native_invocation()
                .finalized_function()
                .symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
    }
}

#[test]
fn literal_native_differential_matches_direct_thunk_bool_value() {
    let arena = thunk_alloc_bool_arena(true);

    let differential = nix_jit_literal_native_differential_for_ir_root(&arena, IrId::new(1))
        .expect("direct thunk literal native differential succeeds");

    assert_eq!(differential.root(), IrId::new(1));
    assert!(differential.values_match());
    assert!(differential.oracle_value().raw_eq(Value::bool(true)));
    assert!(differential.native_value().raw_eq(Value::bool(true)));
    assert_eq!(
        differential
            .native_invocation()
            .finalization()
            .artifact()
            .source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
}

#[test]
fn literal_native_differential_rejects_unsupported_root_before_native_call() {
    let arena = local_var_arena(2);

    let Err(error) = nix_jit_literal_native_differential_for_ir_root(&arena, IrId::new(0)) else {
        panic!("local variables are not no-import literal differential inputs");
    };

    assert!(matches!(
        error,
        NixJitLiteralNativeDifferentialError::ProjectOracleLiteral {
            root,
            source: JitLowerError::UnsupportedIrRoot {
                kind: IrKind::LocalVar
            }
        } if root == IrId::new(0)
    ));
}

#[test]
fn tier1_conformance_readiness_reports_current_runtime_and_publish_gaps() {
    let arena = local_var_arena(3);
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_tier1_conformance_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("JIT conformance readiness report builds");

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
    assert!(readiness.runtime_symbol_registration().gaps().len() > 0);
    assert!(
        readiness
            .runtime_symbol_registration()
            .native_export_missing_bindings()
            .len()
            > 0
    );
    assert!(
        readiness
            .runtime_symbol_registration()
            .address_provenance_gaps()
            .is_empty()
    );
    assert!(
        readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolRegistration {
            missing_count: readiness.runtime_symbol_registration().gaps().len(),
        })
    );
    assert!(
        readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolNativeExport {
            missing_count: readiness
                .runtime_symbol_registration()
                .native_export_missing_bindings()
                .len(),
        })
    );
    assert!(
        !readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolAddressProvenance {
            missing_count: 0,
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
}

#[test]
fn tier1_conformance_readiness_keeps_cold_no_compile_gap() {
    let arena = string_arena();
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_tier1_conformance_readiness_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("cold JIT conformance readiness report builds");

    assert!(
        !readiness
            .thunk_install_readiness()
            .install_plan()
            .did_compile()
    );
    assert!(!readiness.is_ready_for_jit_enabled_harness());
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::Tier1CodeNotCompiled,
    }));
    assert_eq!(
        readiness
            .thunk_install_readiness()
            .install_plan()
            .slot()
            .invocation_counter()
            .invocations(),
        1
    );
}

#[test]
fn force_aware_tier1_conformance_readiness_reports_literal_publish_gaps() {
    let arena = bool_arena(true);
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("force-aware literal JIT conformance readiness report builds");

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
}

#[test]
fn force_aware_tier1_conformance_readiness_keeps_cold_no_compile_gap() {
    let arena = string_arena();
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("cold force-aware JIT conformance readiness report builds");

    assert!(
        !readiness
            .thunk_install_readiness()
            .install_plan()
            .did_compile()
    );
    assert!(!readiness.is_ready_for_jit_enabled_harness());
    assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
        gap: NixJitThunkInstallGap::Tier1CodeNotCompiled,
    }));
    assert_eq!(
        readiness
            .thunk_install_readiness()
            .install_plan()
            .slot()
            .invocation_counter()
            .invocations(),
        1
    );
}

#[test]
fn force_aware_tier1_conformance_readiness_reports_forced_env_slot_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = local_var_arena(9);
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("force-aware env-slot JIT conformance readiness report builds");

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
}

#[test]
fn force_aware_tier1_conformance_readiness_reports_update_publish_gaps() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = update_ir(12, 13);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir.arena,
        ir.root,
        &thunk,
    )
    .expect("force-aware update conformance readiness report builds");

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
