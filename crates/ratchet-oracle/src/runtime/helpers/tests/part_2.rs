//! Runtime-helper binding inventory tests (part_2), split from `super`.

use super::super::*;
use super::*;

#[test]
fn runtime_symbol_abi_signature_preflight_converts_complete_report_to_plan() {
    let helper_binding = runtime_helper_bindings()
        .first()
        .copied()
        .expect("runtime helper inventory has at least one binding");
    let signature_bindings = vec![RuntimeSymbolAbiSignatureBinding::Helper(helper_binding)];
    let preflight = RuntimeSymbolAbiSignaturePreflight::new(signature_bindings.clone(), Vec::new());

    let plan = preflight
        .into_abi_signature_plan()
        .expect("complete ABI-signature preflight converts");

    assert_eq!(plan.signature_bindings(), signature_bindings.as_slice());
}

#[test]
fn runtime_symbol_abi_signature_plan_rejects_until_all_symbols_have_metadata() {
    let error = runtime_symbol_abi_signature_plan()
        .expect_err("current ABI-signature plan rejects incomplete metadata");
    let RuntimeSymbolAbiSignaturePlanError::Incomplete {
        missing_count,
        preflight,
    } = error
    else {
        panic!("expected incomplete ABI-signature plan error");
    };

    assert_eq!(missing_count, preflight.missing_bindings().len());
    assert!(!preflight.is_complete());
    assert!(preflight.signature_bindings().iter().any(|binding| {
        binding.builtin_call_binding().is_some_and(|builtin| {
            builtin.symbol_name() == "nix.builtin.derivationStrict" && builtin.arity() == 1
        })
    }));
    assert!(preflight.signature_bindings().iter().any(|binding| {
        binding.helper_binding().is_some_and(|helper| {
            helper.symbol_name() == "aos_apply" && helper.role() == RuntimeHelperRole::CallControl
        })
    }));
    assert!(preflight.signature_bindings().iter().any(|binding| {
        binding.helper_binding().is_some_and(|helper| {
            helper.symbol_name() == "aos_force"
                && helper.role() == RuntimeHelperRole::ForcingControl
        })
    }));
    assert!(preflight.signature_bindings().iter().any(|binding| {
        binding.helper_binding().is_some_and(|helper| {
            helper.symbol_name() == "aos_force_deep"
                && helper.role() == RuntimeHelperRole::ForcingControl
        })
    }));
    assert!(preflight.signature_bindings().iter().any(|binding| {
        binding.helper_binding().is_some_and(|helper| {
            helper.symbol_name() == "aos_blackhole_check"
                && helper.role() == RuntimeHelperRole::ForcingControl
        })
    }));
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "nix.builtin.true"
            && missing
                .builtin_missing_binding()
                .is_some_and(|builtin| builtin.builtin_name() == b"true")
    }));
}

#[test]
fn runtime_symbol_native_target_candidate_preflight_projects_helper_candidates_and_gaps() {
    let candidate_preflight = runtime_symbol_native_target_candidate_preflight()
        .expect("native target candidate preflight builds");
    let abi_preflight =
        runtime_symbol_abi_signature_preflight().expect("ABI-signature preflight builds");
    let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
    let abi_candidate_symbols = abi_preflight
        .signature_bindings()
        .iter()
        .filter_map(RuntimeSymbolAbiSignatureBinding::helper_binding)
        .filter(|binding| binding.rust_callable_binding().is_some())
        .map(|binding| binding.symbol_name())
        .collect::<BTreeSet<_>>();
    let expected_candidate_symbols = binding_manifest
        .iter()
        .map(RuntimeSymbolBindingManifestEntry::symbol_name)
        .filter(|symbol| abi_candidate_symbols.contains(symbol))
        .collect::<Vec<_>>();
    let expected_missing_symbols = binding_manifest
        .iter()
        .map(RuntimeSymbolBindingManifestEntry::symbol_name)
        .filter(|symbol| !abi_candidate_symbols.contains(symbol))
        .collect::<Vec<_>>();
    let candidate_symbols = candidate_preflight
        .candidate_bindings()
        .iter()
        .map(RuntimeSymbolNativeTargetCandidateBinding::symbol_name)
        .collect::<Vec<_>>();
    let missing_symbols = candidate_preflight
        .missing_bindings()
        .iter()
        .map(RuntimeSymbolNativeTargetCandidateMissingBinding::symbol_name)
        .collect::<Vec<_>>();

    assert!(!candidate_preflight.is_complete());
    assert_eq!(
        candidate_preflight.candidate_bindings().len()
            + candidate_preflight.missing_bindings().len(),
        binding_manifest.len()
    );
    assert_eq!(candidate_symbols, expected_candidate_symbols);
    assert_eq!(missing_symbols, expected_missing_symbols);

    for target in candidate_preflight.candidate_bindings() {
        match target.helper_role() {
            RuntimeHelperRole::Allocation => {
                assert!(target.symbol_name().starts_with("aos_alloc_"))
            }
            RuntimeHelperRole::CallControl => {
                assert_eq!(target.symbol_name(), "aos_apply")
            }
            RuntimeHelperRole::AttrsetAccess => {
                assert!(matches!(
                    target.symbol_name(),
                    "aos_has_attr" | "aos_select_ic" | "aos_update"
                ))
            }
            RuntimeHelperRole::EnvironmentAccess => {
                assert_eq!(target.symbol_name(), "aos_env_get")
            }
            RuntimeHelperRole::ForcingControl => {
                assert!(matches!(
                    target.symbol_name(),
                    "aos_blackhole_check" | "aos_force" | "aos_force_deep"
                ))
            }
            RuntimeHelperRole::WriteBarrier => {
                assert_eq!(target.symbol_name(), "aos_gc_write_barrier")
            }
            role => panic!("unexpected native-target candidate helper role: {role:?}"),
        }
    }
}

#[test]
fn runtime_symbol_native_target_candidate_projection_requires_abi_signature_metadata() {
    let helper_binding = runtime_helper_bindings()
        .iter()
        .copied()
        .find(|binding| binding.rust_callable_binding().is_some())
        .expect("runtime helper inventory has at least one callable binding");
    let target_symbol = helper_binding.symbol_name().to_owned();
    let target_role = helper_binding.role();
    let abi_preflight =
        runtime_symbol_abi_signature_preflight().expect("ABI-signature preflight builds");
    let mut signature_bindings = abi_preflight.signature_bindings().to_vec();
    let target_index = signature_bindings
        .iter()
        .position(|binding| binding.symbol_name() == target_symbol)
        .expect("callable helper has ABI-signature metadata");
    let removed_binding = signature_bindings.remove(target_index);
    let RuntimeSymbolAbiSignatureBinding::Helper(_) = removed_binding else {
        panic!("removed callable helper ABI binding must be helper metadata");
    };
    let mut missing_bindings = abi_preflight.missing_bindings().to_vec();
    missing_bindings.push(RuntimeSymbolAbiMissingBinding::helper(
        target_symbol.clone(),
        target_role,
    ));
    let synthetic_abi_preflight =
        RuntimeSymbolAbiSignaturePreflight::new(signature_bindings, missing_bindings);
    let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
    let candidate_preflight =
        project_native_target_candidate_preflight(&binding_manifest, &synthetic_abi_preflight);
    let target_gap = candidate_preflight
        .missing_bindings()
        .iter()
        .find(|missing| missing.symbol_name() == target_symbol)
        .expect("callable helper without ABI metadata remains a candidate gap");

    assert!(
        candidate_preflight
            .candidate_bindings()
            .iter()
            .all(|candidate| candidate.symbol_name() != target_symbol)
    );
    assert_eq!(target_gap.missing_helper_callable_role(), None);
    assert!(target_gap.missing_abi_signature().is_some_and(|gap| {
        gap.symbol_name() == target_symbol && gap.helper_role() == Some(target_role)
    }));
}

#[test]
fn runtime_symbol_native_target_candidate_preflight_reports_current_wrapper_gaps() {
    let candidate_preflight = runtime_symbol_native_target_candidate_preflight()
        .expect("native target candidate preflight builds");
    let builtin_preflight =
        runtime_builtin_call_preflight().expect("builtin call preflight builds");
    let missing_builtin_wrappers = candidate_preflight
        .missing_bindings()
        .iter()
        .filter_map(RuntimeSymbolNativeTargetCandidateMissingBinding::missing_builtin_wrapper)
        .map(|binding| binding.symbol_name())
        .collect::<Vec<_>>();
    let missing_builtin_wrapper_blockers = candidate_preflight
        .missing_bindings()
        .iter()
        .filter_map(
            RuntimeSymbolNativeTargetCandidateMissingBinding::missing_builtin_wrapper_blockers,
        )
        .collect::<Vec<_>>();

    assert_eq!(
        missing_builtin_wrappers,
        builtin_preflight
            .call_bindings()
            .iter()
            .map(|binding| binding.symbol_name())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        missing_builtin_wrapper_blockers.len(),
        builtin_preflight.call_bindings().len()
    );
    assert!(
        missing_builtin_wrapper_blockers
            .iter()
            .all(|blockers| *blockers == runtime_builtin_native_wrapper_blockers())
    );
    assert!(missing_builtin_wrapper_blockers.iter().all(|blockers| {
        blockers.contains(&RuntimeBuiltinNativeWrapperBlocker::MissingWrapperBody)
    }));
    assert!(missing_builtin_wrapper_blockers.iter().all(|blockers| {
        blockers.contains(
            &RuntimeBuiltinNativeWrapperBlocker::ArgumentForcingContractBindingUnimplemented,
        )
    }));
    assert!(missing_builtin_wrapper_blockers.iter().all(|blockers| {
        blockers
            .contains(&RuntimeBuiltinNativeWrapperBlocker::EvaluatorCallFrameBindingUnimplemented)
    }));
    assert!(missing_builtin_wrapper_blockers.iter().all(|blockers| {
        blockers.contains(
            &RuntimeBuiltinNativeWrapperBlocker::ActiveArgumentRootRegistrationUnimplemented,
        )
    }));
    assert!(missing_builtin_wrapper_blockers.iter().all(|blockers| {
        blockers.contains(
            &RuntimeBuiltinNativeWrapperBlocker::NativeValueReturnMaterializationUnimplemented,
        )
    }));
    assert!(
        candidate_preflight
            .candidate_bindings()
            .iter()
            .any(|candidate| {
                candidate.symbol_name() == "aos_apply"
                    && candidate.helper_role() == RuntimeHelperRole::CallControl
            })
    );
    assert!(
        candidate_preflight
            .candidate_bindings()
            .iter()
            .any(|candidate| {
                candidate.symbol_name() == "aos_force"
                    && candidate.helper_role() == RuntimeHelperRole::ForcingControl
            })
    );
    assert!(
        candidate_preflight
            .candidate_bindings()
            .iter()
            .any(|candidate| {
                candidate.symbol_name() == "aos_force_deep"
                    && candidate.helper_role() == RuntimeHelperRole::ForcingControl
            })
    );
    assert!(
        candidate_preflight
            .candidate_bindings()
            .iter()
            .any(|candidate| {
                candidate.symbol_name() == "aos_blackhole_check"
                    && candidate.helper_role() == RuntimeHelperRole::ForcingControl
            })
    );
    assert!(
        candidate_preflight
            .missing_bindings()
            .iter()
            .any(|missing| {
                missing.missing_abi_signature().is_some_and(|gap| {
                    gap.symbol_name() == "nix.builtin.true"
                        && gap
                            .builtin_missing_binding()
                            .is_some_and(|builtin| builtin.builtin_name() == b"true")
                })
            })
    );
    assert!(
        candidate_preflight
            .missing_bindings()
            .iter()
            .any(|missing| {
                missing
                    .missing_builtin_wrapper()
                    .is_some_and(|binding| binding.symbol_name() == "nix.builtin.derivationStrict")
            })
    );
    assert!(
        candidate_preflight
            .missing_bindings()
            .iter()
            .all(|missing| missing.missing_helper_callable_role().is_none())
    );
}

#[test]
fn runtime_symbol_native_target_candidate_preflight_converts_complete_report_to_plan() {
    let helper_binding = runtime_helper_bindings()
        .iter()
        .copied()
        .find(|binding| binding.rust_callable_binding().is_some())
        .expect("runtime helper inventory has at least one callable binding");
    let candidate_bindings = vec![RuntimeSymbolNativeTargetCandidateBinding::helper(
        helper_binding,
    )];
    let preflight =
        RuntimeSymbolNativeTargetCandidatePreflight::new(candidate_bindings.clone(), Vec::new());

    let plan = preflight
        .into_native_target_candidate_plan()
        .expect("complete native-target candidate preflight converts");

    assert_eq!(plan.candidate_bindings(), candidate_bindings.as_slice());
}

#[test]
fn runtime_symbol_native_target_candidate_plan_rejects_until_all_symbols_are_candidates() {
    let error = runtime_symbol_native_target_candidate_plan()
        .expect_err("current native-target candidate plan rejects incomplete metadata");
    let RuntimeSymbolNativeTargetCandidatePlanError::Incomplete {
        missing_count,
        preflight,
    } = error
    else {
        panic!("expected incomplete native-target candidate plan error");
    };

    assert_eq!(missing_count, preflight.missing_bindings().len());
    assert!(!preflight.is_complete());
    assert!(preflight.candidate_bindings().iter().any(|candidate| {
        candidate.symbol_name() == "aos_alloc_attrs"
            && candidate.helper_role() == RuntimeHelperRole::Allocation
    }));
    assert!(preflight.candidate_bindings().iter().any(|candidate| {
        candidate.symbol_name() == "aos_env_get"
            && candidate.helper_role() == RuntimeHelperRole::EnvironmentAccess
    }));
    assert!(preflight.candidate_bindings().iter().any(|candidate| {
        candidate.symbol_name() == "aos_apply"
            && candidate.helper_role() == RuntimeHelperRole::CallControl
    }));
    assert!(preflight.candidate_bindings().iter().any(|candidate| {
        candidate.symbol_name() == "aos_force"
            && candidate.helper_role() == RuntimeHelperRole::ForcingControl
    }));
    assert!(preflight.candidate_bindings().iter().any(|candidate| {
        candidate.symbol_name() == "aos_force_deep"
            && candidate.helper_role() == RuntimeHelperRole::ForcingControl
    }));
    assert!(preflight.candidate_bindings().iter().any(|candidate| {
        candidate.symbol_name() == "aos_blackhole_check"
            && candidate.helper_role() == RuntimeHelperRole::ForcingControl
    }));
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing
            .missing_builtin_wrapper()
            .is_some_and(|binding| binding.symbol_name() == "nix.builtin.derivationStrict")
    }));
}
