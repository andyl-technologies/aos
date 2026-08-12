//! Runtime-symbol registration tests (moved verbatim from `tests.rs`).

use super::*;

#[test]
fn jit_runtime_symbol_address_candidate_preflight_projects_runtime_addresses() {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");

    for symbol_name in EXPECTED_ALLOCATION_SYMBOLS {
        let allocation = preflight
            .address_candidate_for(symbol_name)
            .expect("allocation helper has a native-wrapper address candidate");
        assert_eq!(
            allocation.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation)
        );
        assert_eq!(
            allocation.address().as_nonzero_usize().get(),
            allocation_native_wrapper_address(symbol_name)
        );
        assert_ne!(
            allocation.address().as_nonzero_usize().get(),
            allocation_rust_callable_address(symbol_name)
        );
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(|provenance| {
                    provenance.is_runtime_ffi_native_wrapper()
                        && provenance.kind()
                            == RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation)
                })
        );
        assert!(preflight.missing_binding_for(symbol_name).is_none());
    }

    let env_get = preflight
        .address_candidate_for("aos_env_get")
        .expect("environment helper has a native-wrapper address candidate");

    assert_eq!(
        env_get.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess)
    );
    assert_eq!(
        env_get.address().as_nonzero_usize().get(),
        env_native_wrapper_address()
    );
    assert_ne!(
        env_get.address().as_nonzero_usize().get(),
        env_rust_callable_address()
    );
    assert!(
        preflight
            .address_provenance_for_symbol("aos_env_get")
            .is_some_and(|provenance| {
                provenance.is_runtime_ffi_native_wrapper()
                    && provenance.kind()
                        == RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess)
            })
    );
    assert!(preflight.missing_binding_for("aos_env_get").is_none());
    let apply = preflight
        .address_candidate_for("aos_apply")
        .expect("apply helper has a native-wrapper address candidate");
    assert_eq!(
        apply.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl)
    );
    assert_eq!(
        apply.address().as_nonzero_usize().get(),
        apply_native_wrapper_address()
    );
    assert_ne!(
        apply.address().as_nonzero_usize().get(),
        apply_rust_callable_address()
    );
    assert!(
        preflight
            .address_provenance_for_symbol("aos_apply")
            .is_some_and(|provenance| {
                provenance.is_runtime_ffi_native_wrapper()
                    && provenance.kind()
                        == RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl)
            })
    );
    assert!(preflight.missing_binding_for("aos_apply").is_none());
    let blackhole = preflight
        .address_candidate_for("aos_blackhole_check")
        .expect("blackhole helper has a native-wrapper address candidate");
    assert_eq!(
        blackhole.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
    );
    assert_eq!(
        blackhole.address().as_nonzero_usize().get(),
        blackhole_native_wrapper_address()
    );
    assert_ne!(
        blackhole.address().as_nonzero_usize().get(),
        blackhole_rust_callable_address()
    );
    assert!(
        preflight
            .address_provenance_for_symbol("aos_blackhole_check")
            .is_some_and(|provenance| {
                provenance.is_runtime_ffi_native_wrapper()
                    && provenance.kind()
                        == RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
            })
    );
    assert!(
        preflight
            .missing_binding_for("aos_blackhole_check")
            .is_none()
    );
    let write_barrier = preflight
        .address_candidate_for("aos_gc_write_barrier")
        .expect("write-barrier helper has a native-wrapper address candidate");
    assert_eq!(
        write_barrier.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::WriteBarrier)
    );
    assert_eq!(
        write_barrier.address().as_nonzero_usize().get(),
        write_barrier_native_wrapper_address()
    );
    assert_ne!(
        write_barrier.address().as_nonzero_usize().get(),
        write_barrier_rust_callable_address()
    );
    assert!(
        preflight
            .address_provenance_for_symbol("aos_gc_write_barrier")
            .is_some_and(|provenance| {
                provenance.is_runtime_ffi_native_wrapper()
                    && provenance.kind()
                        == RuntimeSymbolKind::Helper(RuntimeHelperRole::WriteBarrier)
            })
    );
    assert!(
        preflight
            .missing_binding_for("aos_gc_write_barrier")
            .is_none()
    );
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        let attr_access = preflight
            .address_candidate_for(symbol_name)
            .expect("attrset-access helper has a native-wrapper address candidate");
        assert_eq!(
            attr_access.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
        );
        assert_eq!(
            attr_access.address().as_nonzero_usize().get(),
            attr_access_native_wrapper_address(symbol_name)
        );
        assert_ne!(
            attr_access.address().as_nonzero_usize().get(),
            attr_access_rust_callable_address(symbol_name)
        );
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(|provenance| {
                    provenance.is_runtime_ffi_native_wrapper()
                        && provenance.kind()
                            == RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
                })
        );
        assert!(preflight.missing_binding_for(symbol_name).is_none());
    }
    let force = preflight
        .address_candidate_for("aos_force")
        .expect("force helper has a native-wrapper address candidate");
    assert_eq!(
        force.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
    );
    assert_eq!(
        force.address().as_nonzero_usize().get(),
        force_native_wrapper_address()
    );
    assert_ne!(
        force.address().as_nonzero_usize().get(),
        force_rust_callable_address()
    );
    assert!(
        preflight
            .address_provenance_for_symbol("aos_force")
            .is_some_and(|provenance| {
                provenance.is_runtime_ffi_native_wrapper()
                    && provenance.kind()
                        == RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
            })
    );
    assert!(preflight.missing_binding_for("aos_force").is_none());
    let force_deep = preflight
        .address_candidate_for("aos_force_deep")
        .expect("force-deep helper has a native-wrapper address candidate");
    assert_eq!(
        force_deep.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
    );
    assert_eq!(
        force_deep.address().as_nonzero_usize().get(),
        force_deep_native_wrapper_address()
    );
    assert_ne!(
        force_deep.address().as_nonzero_usize().get(),
        force_deep_rust_callable_address()
    );
    assert!(
        preflight
            .address_provenance_for_symbol("aos_force_deep")
            .is_some_and(|provenance| {
                provenance.is_runtime_ffi_native_wrapper()
                    && provenance.kind()
                        == RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
            })
    );
    assert!(preflight.missing_binding_for("aos_force_deep").is_none());
    let runtime_ffi_symbols = preflight
        .address_provenance()
        .iter()
        .filter(|provenance| provenance.is_runtime_ffi_native_wrapper())
        .map(NixJitRuntimeSymbolAddressProvenance::symbol_name)
        .collect::<Vec<_>>();
    let expected_runtime_ffi_symbols = runtime_native_wrapper_symbols();
    assert_eq!(runtime_ffi_symbols, expected_runtime_ffi_symbols);
    assert_eq!(runtime_ffi_symbols, EXPECTED_RUNTIME_FFI_SYMBOLS);
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        let force = preflight
            .address_candidate_for(symbol_name)
            .expect("force helper has an address candidate");
        assert_eq!(
            force.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
        );
        assert_ne!(force.address().as_nonzero_usize().get(), 0);
        assert!(preflight.missing_binding_for(symbol_name).is_none());
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_FORCE_SYMBOLS {
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_ALLOCATION_SYMBOLS {
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_ALLOCATION_SYMBOLS {
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_rust_callable_helper)
        );
    }
    for symbol_name in EXPECTED_RUNTIME_FFI_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_rust_callable_helper)
        );
    }
    for symbol_name in EXPECTED_RUST_CALLABLE_FORCE_SYMBOLS {
        assert!(
            preflight
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_rust_callable_helper)
        );
    }
    assert!(!preflight.is_complete());
}

#[test]
fn jit_runtime_symbol_address_candidate_preflight_projects_allocation_helpers() {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let allocation_candidates = preflight
        .allocation_address_candidates()
        .collect::<Vec<_>>();
    let allocation_symbols = allocation_candidates
        .iter()
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();

    assert_eq!(allocation_symbols, EXPECTED_ALLOCATION_SYMBOLS);
    for candidate in allocation_candidates {
        assert_eq!(
            candidate.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation)
        );
        assert_eq!(
            candidate.address().as_nonzero_usize().get(),
            allocation_native_wrapper_address(candidate.symbol_name())
        );
        assert_ne!(
            candidate.address().as_nonzero_usize().get(),
            allocation_rust_callable_address(candidate.symbol_name())
        );
        assert!(
            preflight
                .address_provenance_for_symbol(candidate.symbol_name())
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
        assert!(
            preflight
                .missing_binding_for(candidate.symbol_name())
                .is_none()
        );
    }
}

#[test]
fn jit_runtime_symbol_address_candidate_preflight_filters_helper_roles() {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let allocation_symbols = preflight
        .helper_role_address_candidates(RuntimeHelperRole::Allocation)
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();
    let allocation_convenience_symbols = preflight
        .allocation_address_candidates()
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();
    let env_access_symbols = preflight
        .helper_role_address_candidates(RuntimeHelperRole::EnvironmentAccess)
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();
    let call_control_symbols = preflight
        .helper_role_address_candidates(RuntimeHelperRole::CallControl)
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();
    let attrset_access_symbols = preflight
        .helper_role_address_candidates(RuntimeHelperRole::AttrsetAccess)
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();
    let write_barrier_symbols = preflight
        .helper_role_address_candidates(RuntimeHelperRole::WriteBarrier)
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();
    let forcing_symbols = preflight
        .helper_role_address_candidates(RuntimeHelperRole::ForcingControl)
        .map(|candidate| candidate.symbol_name())
        .collect::<Vec<_>>();

    assert_eq!(allocation_symbols, EXPECTED_ALLOCATION_SYMBOLS);
    assert_eq!(allocation_convenience_symbols, allocation_symbols);
    assert_eq!(call_control_symbols, EXPECTED_CALL_CONTROL_SYMBOLS);
    assert_eq!(attrset_access_symbols, EXPECTED_ATTRSET_ACCESS_SYMBOLS);
    assert_eq!(env_access_symbols, EXPECTED_ENV_ACCESS_SYMBOLS);
    assert_eq!(forcing_symbols, EXPECTED_FORCE_SYMBOLS);
    assert_eq!(write_barrier_symbols, EXPECTED_WRITE_BARRIER_SYMBOLS);
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        assert!(preflight.missing_binding_for(symbol_name).is_none());
    }
    for symbol_name in EXPECTED_ALLOCATION_SYMBOLS
        .iter()
        .chain(EXPECTED_ENV_ACCESS_SYMBOLS)
        .chain(EXPECTED_CALL_CONTROL_SYMBOLS)
        .chain(EXPECTED_ATTRSET_ACCESS_SYMBOLS)
        .chain(EXPECTED_FORCE_SYMBOLS)
        .chain(EXPECTED_WRITE_BARRIER_SYMBOLS)
    {
        let candidate = preflight
            .address_candidate_for(symbol_name)
            .expect("role-filtered candidate exists");
        assert_ne!(candidate.address().as_nonzero_usize().get(), 0);
        assert!(preflight.missing_binding_for(symbol_name).is_none());
    }
}

#[test]
fn jit_runtime_symbol_address_candidates_feed_jit_registration_preflight() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");

    let registration = jit_runtime_symbol_registration_preflight_with_candidates(
        candidate_preflight.address_candidates(),
    )
    .expect("JIT registration preflight accepts runtime address candidates");

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
    for symbol_name in EXPECTED_CALL_CONTROL_SYMBOLS {
        assert!(
            registration
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == candidate_preflight
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
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("attrset-access candidate exists")
                        .address())
        );
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        assert!(
            registration
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("force candidate exists")
                        .address())
        );
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }
    assert!(!registration.is_complete());
}

#[test]
fn jit_runtime_symbol_allocation_candidates_feed_jit_registration_preflight() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let allocation_candidates = candidate_preflight
        .allocation_address_candidates()
        .cloned()
        .collect::<Vec<_>>();
    let registration =
        jit_runtime_symbol_registration_preflight_with_candidates(&allocation_candidates)
            .expect("JIT registration preflight accepts oracle allocation address candidates");

    for symbol_name in EXPECTED_ALLOCATION_SYMBOLS {
        assert!(
            registration
                .binding_for_symbol(symbol_name)
                .is_some_and(|binding| binding.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("allocation candidate exists")
                        .address())
        );
        assert_eq!(
            candidate_preflight
                .address_candidate_for(symbol_name)
                .expect("allocation candidate exists")
                .address()
                .as_nonzero_usize()
                .get(),
            allocation_native_wrapper_address(symbol_name)
        );
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }
}

#[test]
fn helper_binding_falls_back_to_rust_callable_without_native_wrapper() {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_env_get")
        .expect("oracle env Rust callable exists");

    let (candidate, provenance) =
        jit_address_candidate_for_helper_binding(binding, &BTreeMap::new())
            .expect("fallback Rust-callable candidate builds");

    assert_eq!(candidate.symbol_name(), "aos_env_get");
    assert_eq!(
        candidate.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess)
    );
    assert_eq!(
        candidate.address().as_nonzero_usize().get(),
        env_rust_callable_address()
    );
    assert!(provenance.is_rust_callable_helper());
}
