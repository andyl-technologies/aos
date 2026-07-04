use ratchet_core::{RuntimeHelperRole, RuntimeSymbolKind};
use ratchet_jit::{
    JitRuntimeSymbolRegistrationGap, jit_runtime_symbol_registration_preflight_with_candidates,
};
use ratchet_oracle::runtime::helpers::runtime_symbol_rust_callable_preflight;
use ratchet_runtime_ffi::env::runtime_env_access_native_wrapper_bindings;
use ratchet_runtime_ffi::force::runtime_forcing_native_wrapper_bindings;

use super::*;

const EXPECTED_ALLOCATION_SYMBOLS: &[&str] = &[
    "aos_alloc_attrs",
    "aos_alloc_cons",
    "aos_alloc_lambda",
    "aos_alloc_list",
    "aos_alloc_raw",
    "aos_alloc_string",
    "aos_alloc_thunk",
];

const EXPECTED_ENV_ACCESS_SYMBOLS: &[&str] = &["aos_env_get"];
const EXPECTED_CALL_CONTROL_SYMBOLS: &[&str] = &["aos_apply"];
const EXPECTED_ATTRSET_ACCESS_SYMBOLS: &[&str] = &["aos_has_attr", "aos_select_ic", "aos_update"];
const EXPECTED_FORCE_SYMBOLS: &[&str] = &["aos_blackhole_check", "aos_force", "aos_force_deep"];
const EXPECTED_RUNTIME_FFI_FORCE_SYMBOLS: &[&str] =
    &["aos_blackhole_check", "aos_force", "aos_force_deep"];
const EXPECTED_RUST_CALLABLE_FORCE_SYMBOLS: &[&str] = &[];
const EXPECTED_WRITE_BARRIER_SYMBOLS: &[&str] = &["aos_gc_write_barrier"];

#[test]
fn jit_runtime_symbol_address_candidate_preflight_projects_runtime_addresses() {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");

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
        .expect("apply helper has a Rust-callable address candidate");
    assert_eq!(
        apply.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl)
    );
    assert_ne!(apply.address().as_nonzero_usize().get(), 0);
    assert!(
        preflight
            .address_provenance_for_symbol("aos_apply")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_rust_callable_helper)
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
    assert_eq!(
        runtime_ffi_symbols,
        [
            "aos_blackhole_check",
            "aos_env_get",
            "aos_force",
            "aos_force_deep"
        ]
    );
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        let attr_access = preflight
            .address_candidate_for(symbol_name)
            .expect("attrset-access helper has a Rust-callable address candidate");
        assert_eq!(
            attr_access.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
        );
        assert_ne!(attr_access.address().as_nonzero_usize().get(), 0);
        assert!(preflight.missing_binding_for(symbol_name).is_none());
    }
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
        assert_ne!(candidate.address().as_nonzero_usize().get(), 0);
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
    for symbol_name in EXPECTED_ENV_ACCESS_SYMBOLS
        .iter()
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
        assert!(registration.gap_for_symbol(symbol_name).is_none());
    }
}

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
    assert!(
        candidates
            .address_provenance_for_symbol("aos_env_get")
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
        registration
            .address_provenance_gap_for_symbol("aos_env_get")
            .is_none()
    );
    for symbol_name in EXPECTED_RUNTIME_FFI_FORCE_SYMBOLS {
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
    for symbol_name in EXPECTED_CALL_CONTROL_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(
                    |gap| gap.kind() == RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl)
                )
        );
    }
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            registration
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(
                    |gap| gap.kind() == RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
                )
        );
    }
    assert!(
        registration
            .native_export_gap_for_symbol("aos_alloc_attrs")
            .is_some_and(|gap| {
                gap.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::Allocation)
                    && gap
                        .missing_exported_allocation_blockers()
                        .is_some_and(|blockers| !blockers.is_empty())
            })
    );
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
                            .is_some_and(|blockers| !blockers.is_empty())
                })
        );
    }
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
        assert!(
            registration
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role()
                        == Some(RuntimeHelperRole::AttrsetAccess)
                        && gap
                            .missing_exported_attrset_access_blockers()
                            .is_some_and(|blockers| !blockers.is_empty())
                })
        );
    }
    for symbol_name in EXPECTED_FORCE_SYMBOLS {
        assert!(
            registration
                .native_export_gap_for_symbol(symbol_name)
                .is_some_and(|gap| {
                    gap.missing_exported_c_abi_wrapper_role()
                        == Some(RuntimeHelperRole::ForcingControl)
                        && gap
                            .missing_exported_forcing_blockers()
                            .is_some_and(|blockers| !blockers.is_empty())
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
                        .is_some_and(|blockers| !blockers.is_empty())
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
                .is_some_and(|gap| gap.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::CallControl))
        );
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_some_and(
                    |gap| gap.kind() == RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl)
                )
        );
    }
    for symbol_name in EXPECTED_ATTRSET_ACCESS_SYMBOLS {
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
                .is_some_and(|gap| gap.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::AttrsetAccess))
        );
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

fn env_native_wrapper_address() -> usize {
    runtime_env_access_native_wrapper_bindings()
        .into_iter()
        .find(|binding| binding.symbol_name() == "aos_env_get")
        .expect("runtime FFI env wrapper exists")
        .address()
        .as_ptr() as usize
}

fn force_native_wrapper_address() -> usize {
    runtime_forcing_native_wrapper_bindings()
        .into_iter()
        .find(|binding| binding.symbol_name() == "aos_force")
        .expect("runtime FFI force wrapper exists")
        .address()
        .as_ptr() as usize
}

fn force_deep_native_wrapper_address() -> usize {
    runtime_forcing_native_wrapper_bindings()
        .into_iter()
        .find(|binding| binding.symbol_name() == "aos_force_deep")
        .expect("runtime FFI force-deep wrapper exists")
        .address()
        .as_ptr() as usize
}

fn blackhole_native_wrapper_address() -> usize {
    runtime_forcing_native_wrapper_bindings()
        .into_iter()
        .find(|binding| binding.symbol_name() == "aos_blackhole_check")
        .expect("runtime FFI blackhole-check wrapper exists")
        .address()
        .as_ptr() as usize
}

fn env_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_env_get")
        .expect("oracle env Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::EnvironmentAccess(binding) => {
            binding.address().as_ptr() as usize
        }
        _ => panic!("aos_env_get is an environment-access helper"),
    }
}

fn blackhole_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_blackhole_check")
        .expect("oracle blackhole-check Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr() as usize,
        _ => panic!("aos_blackhole_check is a forcing helper"),
    }
}

fn force_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_force")
        .expect("oracle force Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr() as usize,
        _ => panic!("aos_force is a forcing helper"),
    }
}

fn force_deep_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_force_deep")
        .expect("oracle force-deep Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr() as usize,
        _ => panic!("aos_force_deep is a forcing helper"),
    }
}
