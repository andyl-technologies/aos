//! Runtime-helper binding inventory tests (part_1), split from `super`.

use super::super::*;
use super::*;

#[test]
fn runtime_helper_bindings_match_core_bound_helper_roles() {
    let bound_symbols = runtime_helper_bindings()
        .iter()
        .copied()
        .map(|binding| (binding.symbol_name(), binding.role()))
        .collect::<Vec<_>>();
    let core_bound_symbols = runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| {
            // `aos_upval_get` is an EnvironmentAccess helper, but like
            // `aos_deopt` it is wired directly through the JIT and the
            // runtime-FFI standalone wrapper rather than modeled as an oracle
            // helper binding, so it is not part of `runtime_helper_bindings`.
            symbol.name() != "aos_upval_get"
                && (matches!(
                    symbol.role(),
                    RuntimeHelperRole::Allocation
                        | RuntimeHelperRole::CallControl
                        | RuntimeHelperRole::EnvironmentAccess
                        | RuntimeHelperRole::WriteBarrier
                ) || matches!(
                    symbol.name(),
                    "aos_blackhole_check"
                        | "aos_force"
                        | "aos_force_deep"
                        | "aos_has_attr"
                        | "aos_select_ic"
                        | "aos_update"
                ))
        })
        .map(|symbol| (symbol.name(), symbol.role()))
        .collect::<Vec<_>>();

    assert_eq!(bound_symbols, core_bound_symbols);
}

#[test]
fn runtime_helper_bindings_preserve_family_abi_inventories() {
    let allocation_signatures = runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::allocation_signature)
        .collect::<Vec<_>>();
    let call_control_signatures = runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::call_control_signature)
        .collect::<Vec<_>>();
    let env_access_signatures = runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::env_access_signature)
        .collect::<Vec<_>>();
    let attrset_access_signatures = runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::attrset_access_signature)
        .collect::<Vec<_>>();
    let forcing_signatures = runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::forcing_signature)
        .collect::<Vec<_>>();
    let write_barrier_signatures = runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::write_barrier_signature)
        .collect::<Vec<_>>();

    assert_eq!(
        allocation_signatures.as_slice(),
        runtime_allocation_abi_signatures()
    );
    assert_eq!(
        call_control_signatures.as_slice(),
        runtime_apply_abi_signatures()
    );
    assert_eq!(
        attrset_access_signatures.as_slice(),
        runtime_attr_access_abi_signatures()
    );
    assert_eq!(
        env_access_signatures.as_slice(),
        runtime_env_access_abi_signatures()
    );
    assert_eq!(
        forcing_signatures.as_slice(),
        runtime_forcing_abi_signatures()
    );
    assert_eq!(
        write_barrier_signatures.as_slice(),
        runtime_write_barrier_abi_signatures()
    );
}

#[test]
fn runtime_helper_bindings_have_core_runtime_call_signatures() {
    let helper_core_signatures = runtime_helper_bindings()
        .iter()
        .copied()
        .map(|binding| {
            (
                binding.symbol_name(),
                binding
                    .core_call_signature()
                    .expect("bound helper has a core runtime call signature"),
            )
        })
        .collect::<Vec<_>>();
    let core_signatures = runtime_helper_call_signatures()
        .iter()
        .copied()
        .map(|signature| {
            let RuntimeCallableKind::Helper { symbol } = signature.callable() else {
                panic!("helper call signature must carry helper callable metadata");
            };
            (symbol.name(), signature)
        })
        .collect::<Vec<_>>();

    for binding in helper_core_signatures {
        assert!(
            core_signatures.contains(&binding),
            "{} bound helper has matching core runtime-call metadata",
            binding.0
        );
    }
    assert_eq!(
        RuntimeHelperBinding::from_symbol_name("aos_env_get")
            .and_then(RuntimeHelperBinding::core_call_signature)
            .map(|signature| {
                let RuntimeCallableKind::Helper { symbol } = signature.callable() else {
                    panic!("helper call signature must carry helper callable metadata");
                };
                (symbol.name(), signature)
            }),
        core_signatures
            .iter()
            .copied()
            .find(|(symbol_name, _)| *symbol_name == "aos_env_get")
    );
}

#[test]
fn runtime_helper_bindings_pin_failure_conventions() {
    let helper_conventions = runtime_helper_bindings()
        .iter()
        .copied()
        .map(|binding| (binding.symbol_name(), binding.failure_convention()))
        .collect::<Vec<_>>();

    assert_eq!(
        helper_conventions,
        vec![
            (
                "aos_alloc_attrs",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_alloc_cons",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_alloc_lambda",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_alloc_list",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_alloc_raw",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_alloc_string",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_alloc_thunk",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            ("aos_apply", RuntimeHelperFailureConvention::TrapToEvaluator,),
            (
                "aos_blackhole_check",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_env_get",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            ("aos_force", RuntimeHelperFailureConvention::TrapToEvaluator,),
            (
                "aos_force_deep",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_gc_write_barrier",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_has_attr",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_select_ic",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
            (
                "aos_update",
                RuntimeHelperFailureConvention::TrapToEvaluator,
            ),
        ]
    );
}

#[test]
fn runtime_helper_rust_callable_bindings_preserve_family_inventories() {
    let helper_callables = runtime_helper_rust_callable_bindings();
    let expected_callables = runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::rust_callable_binding)
        .collect::<Vec<_>>();

    assert_eq!(helper_callables, expected_callables);
    assert_eq!(
        helper_callables
            .iter()
            .copied()
            .map(RuntimeHelperRustCallableBinding::helper_binding)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_helper_bindings()
    );

    for callable in helper_callables {
        assert_eq!(
            RuntimeHelperBinding::from_symbol_name(callable.symbol_name()),
            Some(callable.helper_binding())
        );
        assert_eq!(
            callable.helper_binding().rust_callable_binding(),
            Some(callable)
        );
        match callable.role() {
            RuntimeHelperRole::Allocation => {
                assert!(callable.allocation_callable().is_some());
                assert!(callable.call_control_callable().is_none());
                assert!(callable.attrset_access_callable().is_none());
                assert!(callable.env_access_callable().is_none());
                assert!(callable.forcing_callable().is_none());
                assert!(callable.write_barrier_callable().is_none());
            }
            RuntimeHelperRole::CallControl => {
                assert!(callable.allocation_callable().is_none());
                assert!(callable.call_control_callable().is_some());
                assert!(callable.attrset_access_callable().is_none());
                assert!(callable.env_access_callable().is_none());
                assert!(callable.forcing_callable().is_none());
                assert!(callable.write_barrier_callable().is_none());
            }
            RuntimeHelperRole::AttrsetAccess => {
                assert!(callable.allocation_callable().is_none());
                assert!(callable.call_control_callable().is_none());
                assert!(callable.attrset_access_callable().is_some());
                assert!(callable.env_access_callable().is_none());
                assert!(callable.forcing_callable().is_none());
                assert!(callable.write_barrier_callable().is_none());
            }
            RuntimeHelperRole::EnvironmentAccess => {
                assert!(callable.allocation_callable().is_none());
                assert!(callable.call_control_callable().is_none());
                assert!(callable.attrset_access_callable().is_none());
                assert!(callable.env_access_callable().is_some());
                assert!(callable.forcing_callable().is_none());
                assert!(callable.write_barrier_callable().is_none());
            }
            RuntimeHelperRole::ForcingControl => {
                assert!(callable.allocation_callable().is_none());
                assert!(callable.call_control_callable().is_none());
                assert!(callable.attrset_access_callable().is_none());
                assert!(callable.env_access_callable().is_none());
                assert!(callable.forcing_callable().is_some());
                assert!(callable.write_barrier_callable().is_none());
            }
            RuntimeHelperRole::WriteBarrier => {
                assert!(callable.allocation_callable().is_none());
                assert!(callable.call_control_callable().is_none());
                assert!(callable.attrset_access_callable().is_none());
                assert!(callable.env_access_callable().is_none());
                assert!(callable.forcing_callable().is_none());
                assert!(callable.write_barrier_callable().is_some());
            }
            role => panic!("unexpected callable helper role: {role:?}"),
        }
    }
}

#[test]
fn runtime_helper_rust_callable_preflight_covers_bound_helpers() {
    let preflight = runtime_helper_rust_callable_preflight();

    assert!(preflight.is_complete());
    assert_eq!(
        preflight.callable_bindings(),
        runtime_helper_rust_callable_bindings().as_slice()
    );
    assert!(preflight.missing_bindings().is_empty());
}

#[test]
fn runtime_helper_bindings_round_trip_only_bound_helper_symbols() {
    for binding in runtime_helper_bindings().iter().copied() {
        assert_eq!(
            RuntimeHelperBinding::from_symbol_name(binding.symbol_name()),
            Some(binding)
        );
    }

    for symbol in runtime_helper_symbols().iter().copied().filter(|symbol| {
        !matches!(
            symbol.role(),
            RuntimeHelperRole::Allocation
                | RuntimeHelperRole::CallControl
                | RuntimeHelperRole::EnvironmentAccess
                | RuntimeHelperRole::WriteBarrier
        ) && !matches!(
            symbol.name(),
            "aos_blackhole_check"
                | "aos_force"
                | "aos_force_deep"
                | "aos_has_attr"
                | "aos_select_ic"
                | "aos_update"
        )
    }) {
        assert_eq!(
            RuntimeHelperBinding::from_symbol_name(symbol.name()),
            None,
            "{} is not bound by the safe runtime helper manifest",
            symbol.name()
        );
    }
    assert_eq!(
        RuntimeHelperBinding::from_symbol_name("nix.builtin.derivationStrict"),
        None
    );
}

#[test]
fn runtime_symbol_binding_manifest_preserves_core_symbol_order() {
    let core_manifest = runtime_symbol_manifest().expect("core manifest builds");
    let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");

    let core_symbols = core_manifest
        .iter()
        .map(|entry| entry.name())
        .collect::<Vec<_>>();
    let binding_symbols = binding_manifest
        .iter()
        .map(RuntimeSymbolBindingManifestEntry::symbol_name)
        .collect::<Vec<_>>();

    assert_eq!(binding_symbols, core_symbols);
}

#[test]
fn runtime_symbol_binding_manifest_marks_bound_helpers() {
    let manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
    let bound_helpers = manifest
        .iter()
        .filter_map(|entry| match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                Some((entry.symbol_name(), binding))
            }
            RuntimeSymbolBindingStatus::UnboundHelper(_) | RuntimeSymbolBindingStatus::Builtin => {
                None
            }
        })
        .collect::<Vec<_>>();
    let expected_helpers = runtime_helper_bindings()
        .iter()
        .copied()
        .map(|binding| (binding.symbol_name(), binding))
        .collect::<Vec<_>>();

    assert_eq!(bound_helpers, expected_helpers);
}

#[test]
fn runtime_symbol_binding_manifest_marks_unbound_helpers_and_builtins() {
    let manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");

    assert!(matches!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "aos_env_get")
            .map(RuntimeSymbolBindingManifestEntry::status),
        Some(RuntimeSymbolBindingStatus::BoundHelper(binding))
            if binding.role() == RuntimeHelperRole::EnvironmentAccess
    ));
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "aos_force")
            .map(RuntimeSymbolBindingManifestEntry::status),
        Some(RuntimeSymbolBindingStatus::BoundHelper(
            RuntimeHelperBinding::Forcing(RuntimeForcingEntryPoint::AosForce.abi_signature())
        ))
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "aos_force_deep")
            .map(RuntimeSymbolBindingManifestEntry::status),
        Some(RuntimeSymbolBindingStatus::BoundHelper(
            RuntimeHelperBinding::Forcing(RuntimeForcingEntryPoint::AosForceDeep.abi_signature())
        ))
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "aos_apply")
            .map(RuntimeSymbolBindingManifestEntry::status),
        Some(RuntimeSymbolBindingStatus::BoundHelper(
            RuntimeHelperBinding::CallControl(RuntimeApplyEntryPoint::AosApply.abi_signature())
        ))
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "aos_blackhole_check")
            .map(RuntimeSymbolBindingManifestEntry::status),
        Some(RuntimeSymbolBindingStatus::BoundHelper(
            RuntimeHelperBinding::Forcing(
                RuntimeForcingEntryPoint::AosBlackholeCheck.abi_signature()
            )
        ))
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "nix.builtin.derivationStrict")
            .map(RuntimeSymbolBindingManifestEntry::status),
        Some(RuntimeSymbolBindingStatus::Builtin)
    );
}

#[test]
fn runtime_symbol_binding_manifest_bound_symbols_match_safe_inventory() {
    let manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
    let bound_symbols = manifest
        .iter()
        .filter_map(|entry| match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(_) => Some(entry.symbol_name()),
            RuntimeSymbolBindingStatus::UnboundHelper(_) | RuntimeSymbolBindingStatus::Builtin => {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    let helper_binding_symbols = runtime_helper_bindings()
        .iter()
        .copied()
        .map(RuntimeHelperBinding::symbol_name)
        .collect::<BTreeSet<_>>();

    assert_eq!(bound_symbols, helper_binding_symbols);
}

#[test]
fn runtime_symbol_registration_preflight_reports_current_gaps() {
    let preflight = runtime_symbol_registration_preflight().expect("registration preflight builds");
    let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");

    assert!(!preflight.is_complete());
    assert_eq!(preflight.helper_bindings(), runtime_helper_bindings());
    assert_eq!(
        preflight.helper_bindings().len() + preflight.missing_bindings().len(),
        binding_manifest.len()
    );
    assert!(
        preflight
            .missing_bindings()
            .windows(2)
            .all(|window| { window[0].symbol_name() < window[1].symbol_name() })
    );
    assert!(
        preflight
            .helper_bindings()
            .iter()
            .any(|binding| binding.symbol_name() == "aos_force"
                && binding.role() == RuntimeHelperRole::ForcingControl)
    );
    assert!(
        preflight
            .helper_bindings()
            .iter()
            .any(|binding| binding.symbol_name() == "aos_force_deep"
                && binding.role() == RuntimeHelperRole::ForcingControl)
    );
    assert!(preflight.helper_bindings().iter().any(|binding| {
        binding.symbol_name() == "aos_apply" && binding.role() == RuntimeHelperRole::CallControl
    }));
    assert!(preflight.helper_bindings().iter().any(|binding| {
        binding.symbol_name() == "aos_blackhole_check"
            && binding.role() == RuntimeHelperRole::ForcingControl
    }));
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "nix.builtin.derivationStrict" && missing.helper_role().is_none()
    }));
}

#[test]
fn runtime_symbol_abi_signature_preflight_combines_helpers_and_builtins() {
    let signature_preflight =
        runtime_symbol_abi_signature_preflight().expect("signature preflight builds");
    let registration_preflight =
        runtime_symbol_registration_preflight().expect("registration preflight builds");
    let builtin_preflight =
        runtime_builtin_call_preflight().expect("builtin call preflight builds");
    let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
    let (expected_signature_bindings, expected_missing_bindings) =
        expected_runtime_symbol_abi_signature_projection(&binding_manifest, &builtin_preflight);
    let helper_symbols = signature_preflight
        .signature_bindings()
        .iter()
        .filter_map(RuntimeSymbolAbiSignatureBinding::helper_binding)
        .map(RuntimeHelperBinding::symbol_name)
        .collect::<Vec<_>>();
    let builtin_symbols = signature_preflight
        .signature_bindings()
        .iter()
        .filter_map(RuntimeSymbolAbiSignatureBinding::builtin_call_binding)
        .map(|binding| binding.symbol_name())
        .collect::<Vec<_>>();

    assert!(!signature_preflight.is_complete());
    assert_eq!(
        signature_preflight.signature_bindings().len()
            + signature_preflight.missing_bindings().len(),
        binding_manifest.len()
    );
    assert_eq!(
        helper_symbols,
        registration_preflight
            .helper_bindings()
            .iter()
            .copied()
            .map(RuntimeHelperBinding::symbol_name)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        signature_preflight.signature_bindings(),
        expected_signature_bindings.as_slice()
    );
    for binding in signature_preflight.signature_bindings() {
        assert!(
            binding.core_call_signature().is_some(),
            "{} has core runtime-call metadata",
            binding.symbol_name()
        );
    }
    assert_eq!(
        signature_preflight.missing_bindings(),
        expected_missing_bindings.as_slice()
    );
    assert_eq!(
        builtin_symbols,
        builtin_preflight
            .call_bindings()
            .iter()
            .map(|binding| binding.symbol_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn runtime_symbol_abi_signature_preflight_reports_current_gaps() {
    let signature_preflight =
        runtime_symbol_abi_signature_preflight().expect("signature preflight builds");

    assert!(
        signature_preflight
            .signature_bindings()
            .iter()
            .any(|binding| {
                binding.helper_binding().is_some_and(|helper| {
                    helper.symbol_name() == "aos_env_get"
                        && helper.role() == RuntimeHelperRole::EnvironmentAccess
                })
            })
    );
    assert!(
        signature_preflight
            .signature_bindings()
            .iter()
            .any(|binding| {
                binding.builtin_call_binding().is_some_and(|builtin| {
                    builtin.symbol_name() == "nix.builtin.derivationStrict" && builtin.arity() == 1
                })
            })
    );
    assert!(
        signature_preflight
            .signature_bindings()
            .iter()
            .any(|binding| {
                binding.helper_binding().is_some_and(|helper| {
                    helper.symbol_name() == "aos_apply"
                        && helper.role() == RuntimeHelperRole::CallControl
                })
            })
    );
    assert!(
        signature_preflight
            .signature_bindings()
            .iter()
            .any(|binding| {
                binding.helper_binding().is_some_and(|helper| {
                    helper.symbol_name() == "aos_force"
                        && helper.role() == RuntimeHelperRole::ForcingControl
                })
            })
    );
    assert!(
        signature_preflight
            .signature_bindings()
            .iter()
            .any(|binding| {
                binding.helper_binding().is_some_and(|helper| {
                    helper.symbol_name() == "aos_force_deep"
                        && helper.role() == RuntimeHelperRole::ForcingControl
                })
            })
    );
    assert!(
        signature_preflight
            .signature_bindings()
            .iter()
            .any(|binding| {
                binding.helper_binding().is_some_and(|helper| {
                    helper.symbol_name() == "aos_blackhole_check"
                        && helper.role() == RuntimeHelperRole::ForcingControl
                })
            })
    );
    assert!(
        signature_preflight
            .missing_bindings()
            .iter()
            .any(|missing| {
                missing.symbol_name() == "nix.builtin.true"
                    && missing.builtin_missing_binding().is_some_and(|builtin| {
                        builtin.symbol_name() == "nix.builtin.true"
                            && builtin.builtin_name() == b"true"
                            && builtin.unsupported_arity().is_none()
                    })
            })
    );
    assert!(
        signature_preflight
            .missing_bindings()
            .iter()
            .all(|missing| missing.symbol_name() != "nix.builtin.derivationStrict")
    );
}
