//! Runtime-symbol registration tests (moved verbatim from `tests.rs`).

use super::*;

#[test]
fn nix_jit_runtime_symbol_registration_preflight_uses_runtime_candidates() {
    let registration = nix_jit_runtime_symbol_registration_preflight()
        .expect("Nix JIT registration preflight builds");
    let candidates = registration.address_candidate_preflight();
    let native_export = registration.native_export_preflight();

    for symbol_name in EXPECTED_ALLOCATION_SYMBOLS {
        assert!(
            registration
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == candidates
                        .address_candidate_for(symbol_name)
                        .expect("allocation candidate exists")
                        .address())
        );
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }

    assert!(
        registration
            .binding_for_symbol("aos_env_get")
            .is_some_and(|binding| binding.address()
                == candidates
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(registration.gap_for_symbol("aos_env_get").is_none());
    for symbol_name in EXPECTED_CALL_CONTROL_SYMBOLS {
        assert!(
            registration
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == candidates
                        .address_candidate_for(symbol_name)
                        .expect("call-control candidate exists")
                        .address())
        );
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            registration
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == candidates
                        .address_candidate_for(symbol_name)
                        .expect("attrset-access candidate exists")
                        .address())
        );
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }
    assert!(
        registration
            .binding_for_symbol("aos_gc_write_barrier")
            .is_some_and(|binding| binding.address()
                == candidates
                    .address_candidate_for("aos_gc_write_barrier")
                    .expect("write-barrier candidate exists")
                    .address())
    );
    assert!(
        registration
            .gap_for_symbol("aos_gc_write_barrier")
            .is_none()
    );
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        assert!(
            registration
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == candidates
                        .address_candidate_for(symbol_name)
                        .expect("force candidate exists")
                        .address())
        );
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }
    assert!(matches!(
        registration.gap_for_symbol("aos_deopt"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Deoptimization),
            ..
        })
    ));
    assert!(matches!(
        registration.gap_for_symbol("aos_throw"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl),
            ..
        })
    ));
    assert!(!registration.is_complete());
    assert_eq!(
        registration.registration_preflight().bindings().len(),
        registration.bindings().len()
    );
    assert_eq!(
        native_export.missing_bindings(),
        registration.native_export_missing_bindings()
    );
    assert!(!native_export.is_complete());
    assert_eq!(
        registration.address_provenance_gaps().len(),
        candidates
            .address_provenance()
            .iter()
            .filter(|provenance| provenance.is_rust_callable_helper())
            .count()
    );
    assert!(registration.address_provenance_gaps().is_empty());
    for symbol_name in EXPECTED_RUNTIME_FFI_ALLOCATION_SYMBOLS {
        assert!(
            candidates
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_ALLOCATION_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(
                    |gap| gap.kind() == RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation)
                )
        );
    }
    assert!(
        candidates
            .address_provenance_for_symbol("aos_env_get")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        candidates
            .address_provenance_for_symbol("aos_apply")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        candidates
            .address_provenance_for_symbol("aos_force")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        candidates
            .address_provenance_for_symbol("aos_blackhole_check")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        candidates
            .address_provenance_for_symbol("aos_force_deep")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        candidates
            .address_provenance_for_symbol("aos_gc_write_barrier")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    for symbol_name in EXPECTED_RUNTIME_FFI_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            candidates
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
    assert!(
        registration
            .address_provenance_gap_for_symbol("aos_env_get")
            .is_none()
    );
    for symbol_name in EXPECTED_RUNTIME_FFI_CALL_CONTROL_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_FORCE_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_WRITE_BARRIER_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_FORCE_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(|gap| gap.kind()
                    == RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl))
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(
                    |gap| gap.kind() == RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
                )
        );
    }
    for symbol_name in EXPECTED_ALLOCATION_SYMBOLS {
        let entrypoint = RuntimeAllocationEntryPoint::from_symbol_name(symbol_name)
            .expect("expected allocation symbol maps to an entry point");
        assert!(
            registration
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::Allocation)
                        && gap
                            .missing_exported_allocation_blockers()
                            .is_some_and(|blockers| blockers == entrypoint.native_export_blockers())
                })
        );
    }
    assert!(
        registration
            .native_export_gap_for_symbol("aos_env_get")
            .is_some_and(|gap| {
                gap.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::EnvironmentAccess)
                    && gap
                        .missing_exported_env_access_blockers()
                        .is_some_and(|blockers| !blockers.is_empty())
            })
    );
    for symbol_name in EXPECTED_CALL_CONTROL_SYMBOLS {
        assert!(
            registration
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role()
                        == Some(RuntimeHelperRole::CallControl)
                        && gap
                            .missing_exported_call_control_blockers()
                            .is_some_and(|blockers| {
                                blockers
                                    == RuntimeApplyEntryPoint::AosApply.native_export_blockers()
                            })
                })
        );
    }
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        let entrypoint = RuntimeAttrAccessEntryPoint::from_symbol_name(symbol_name)
            .expect("expected attrset-access symbol maps to an entry point");
        assert!(
            registration
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role()
                        == Some(RuntimeHelperRole::AttrsetAccess)
                        && gap
                            .missing_exported_attrset_access_blockers()
                            .is_some_and(|blockers| blockers == entrypoint.native_export_blockers())
                })
        );
    }
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        let entrypoint = RuntimeForcingEntryPoint::from_symbol_name(symbol_name)
            .expect("expected forcing symbol maps to an entry point");
        assert!(
            registration
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role()
                        == Some(RuntimeHelperRole::ForcingControl)
                        && gap
                            .missing_exported_forcing_blockers()
                            .is_some_and(|blockers| blockers == entrypoint.native_export_blockers())
                })
        );
    }
    assert!(
        registration
            .native_export_gap_for_symbol("aos_gc_write_barrier")
            .is_some_and(|gap| {
                gap.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::WriteBarrier)
                    && gap
                        .missing_exported_write_barrier_blockers()
                        .is_some_and(|blockers| {
                            blockers
                                == RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier
                                    .native_export_blockers()
                        })
            })
    );
}

#[test]
fn nix_jit_runtime_symbol_registration_plan_preserves_incomplete_preflight() {
    let error = nix_jit_runtime_symbol_registration_plan()
        .expect_err("current runtime-symbol registration remains incomplete");

    let NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
        missing_count,
        preflight,
    } = error
    else {
        panic!("expected incomplete registration plan");
    };

    assert_eq!(
        missing_count,
        preflight.gaps().len()
            + preflight.native_export_missing_bindings().len()
            + preflight.address_provenance_gaps().len()
    );
    assert!(missing_count > 0);
    assert!(!preflight.is_complete());
    assert!(preflight.address_provenance_gaps().is_empty());
    for symbol_name in EXPECTED_ALLOCATION_SYMBOLS {
        let entrypoint = RuntimeAllocationEntryPoint::from_symbol_name(symbol_name)
            .expect("expected allocation symbol maps to an entry point");
        assert!(preflight.gap_for_symbol(symbol_name).is_none());
        assert!(
            preflight
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == preflight
                        .address_candidate_preflight()
                        .address_candidate_for(symbol_name)
                        .expect("allocation candidate exists")
                        .address())
        );
        assert_eq!(
            preflight
                .address_candidate_preflight()
                .address_candidate_for(symbol_name)
                .expect("allocation candidate exists")
                .address()
                .as_nonzero_usize()
                .get(),
            allocation_native_wrapper_address(symbol_name)
        );
        assert!(
            preflight
                .address_candidate_preflight()
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
        assert!(
            preflight
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::Allocation)
                        && gap
                            .missing_exported_allocation_blockers()
                            .is_some_and(|blockers| blockers == entrypoint.native_export_blockers())
                })
        );
    }
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        assert!(preflight.gap_for_symbol(symbol_name).is_none());
    }
    for symbol_name in EXPECTED_CALL_CONTROL_SYMBOLS {
        assert!(preflight.gap_for_symbol(symbol_name).is_none());
    }
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        assert!(preflight.gap_for_symbol(symbol_name).is_none());
    }
    assert!(matches!(
        preflight.gap_for_symbol("aos_deopt"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Deoptimization),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_throw"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl),
            ..
        })
    ));
    assert!(
        preflight
            .binding_for_symbol("aos_env_get")
            .is_some_and(|binding| binding.address()
                == preflight
                    .address_candidate_preflight()
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_env_get")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_apply")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_force")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_blackhole_check")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_force_deep")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_gc_write_barrier")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    for symbol_name in EXPECTED_RUNTIME_FFI_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            preflight
                .address_candidate_preflight()
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        assert!(
            preflight
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == preflight
                        .address_candidate_preflight()
                        .address_candidate_for(symbol_name)
                        .expect("force candidate exists")
                        .address())
        );
        assert!(
            preflight
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| gap.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::ForcingControl))
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_FORCE_SYMBOLS {
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_CALL_CONTROL_SYMBOLS {
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_WRITE_BARRIER_SYMBOLS {
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_FORCE_SYMBOLS {
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(|gap| gap.kind()
                    == RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl))
        );
    }
    for symbol_name in EXPECTED_CALL_CONTROL_SYMBOLS {
        assert!(
            preflight
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == preflight
                        .address_candidate_preflight()
                        .address_candidate_for(symbol_name)
                        .expect("call-control candidate exists")
                        .address())
        );
        assert!(
            preflight
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role()
                        == Some(RuntimeHelperRole::CallControl)
                        && gap
                            .missing_exported_call_control_blockers()
                            .is_some_and(|blockers| {
                                blockers
                                    == RuntimeApplyEntryPoint::AosApply.native_export_blockers()
                            })
                })
        );
    }
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        let entrypoint = RuntimeAttrAccessEntryPoint::from_symbol_name(symbol_name)
            .expect("expected attrset-access symbol maps to an entry point");
        assert!(
            preflight
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == preflight
                        .address_candidate_preflight()
                        .address_candidate_for(symbol_name)
                        .expect("attrset-access candidate exists")
                        .address())
        );
        assert!(
            preflight
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role()
                        == Some(RuntimeHelperRole::AttrsetAccess)
                        && gap
                            .missing_exported_attrset_access_blockers()
                            .is_some_and(|blockers| blockers == entrypoint.native_export_blockers())
                })
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(
                    |gap| gap.kind() == RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
                )
        );
    }
    assert!(
        preflight
            .native_export_gap_for_symbol("aos_env_get")
            .is_some_and(|gap| gap.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::EnvironmentAccess))
    );
    assert!(
        preflight
            .address_provenance_gap_for_symbol("aos_env_get")
            .is_none()
    );
}
