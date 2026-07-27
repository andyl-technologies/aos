//! JIT symbol-manifest tests (moved verbatim from `symbols.rs`).

use std::num::NonZeroUsize;

use ratchet_core::{
    RuntimeCallableKind, RuntimeHelperRole, RuntimeSymbolKind, runtime_builtin_call_preflight,
    runtime_helper_call_signature, runtime_helper_call_signatures, runtime_primop_call_signature,
    runtime_symbol_manifest,
};

use super::*;
use crate::abi::clif_signature_for_runtime_call;

fn synthetic_address(raw: usize) -> JitRuntimeSymbolAddress {
    JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).expect("test address is non-zero"))
}

fn synthetic_address_candidate(
    symbol_name: &str,
    kind: RuntimeSymbolKind,
    raw: usize,
) -> JitRuntimeSymbolAddressCandidate {
    JitRuntimeSymbolAddressCandidate::new(symbol_name.to_owned(), kind, synthetic_address(raw))
}

#[test]
fn jit_runtime_symbol_inventory_mirrors_core_manifest() {
    let inventory = jit_runtime_symbol_inventory().expect("JIT runtime symbol inventory builds");
    let core_manifest = runtime_symbol_manifest().expect("core runtime symbol manifest builds");

    assert_eq!(inventory.symbols(), core_manifest.as_slice());
}

#[test]
fn jit_runtime_symbol_inventory_preserves_representative_kinds() {
    let inventory = jit_runtime_symbol_inventory().expect("JIT runtime symbol inventory builds");

    assert!(inventory.contains_symbol("aos_alloc_attrs"));
    assert_eq!(
        inventory.symbol_kind("aos_alloc_attrs"),
        Some(RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation))
    );
    assert!(inventory.contains_symbol("nix.builtin.derivationStrict"));
    assert_eq!(
        inventory.symbol_kind("nix.builtin.derivationStrict"),
        Some(RuntimeSymbolKind::Builtin)
    );
    assert_eq!(inventory.symbol_kind("missing.runtime.symbol"), None);
}

#[test]
fn jit_runtime_symbol_inventory_keeps_core_ordering() {
    let inventory = jit_runtime_symbol_inventory().expect("JIT runtime symbol inventory builds");

    assert!(
        inventory
            .symbols()
            .windows(2)
            .all(|window| window[0].name() < window[1].name())
    );
    assert!(
        inventory
            .symbols()
            .iter()
            .any(|symbol| matches!(symbol.kind(), RuntimeSymbolKind::Builtin))
    );
    assert!(
        inventory
            .symbols()
            .iter()
            .any(|symbol| matches!(symbol.kind(), RuntimeSymbolKind::Helper(_)))
    );
}

#[test]
fn jit_runtime_symbol_declaration_preflight_declares_callable_builtins() {
    let preflight = jit_runtime_symbol_declaration_preflight()
        .expect("JIT symbol declaration preflight builds");
    let declaration = preflight
        .declaration_for_symbol("nix.builtin.derivationStrict")
        .expect("callable builtin has a CLIF declaration");
    let expected_signature =
        clif_signature_for_runtime_call(runtime_primop_call_signature(1).expect("arity lowers"))
            .expect("arity 1 CLIF signature lowers");

    assert_eq!(declaration.symbol_name(), "nix.builtin.derivationStrict");
    assert_eq!(declaration.kind(), RuntimeSymbolKind::Builtin);
    assert_eq!(declaration.signature(), &expected_signature);
}

#[test]
fn jit_runtime_symbol_declaration_preflight_declares_core_owned_helpers() {
    let preflight = jit_runtime_symbol_declaration_preflight()
        .expect("JIT symbol declaration preflight builds");
    let allocation_declaration = preflight
        .declaration_for_symbol("aos_alloc_attrs")
        .expect("core-owned allocation helper has a CLIF declaration");
    let apply_declaration = preflight
        .declaration_for_symbol("aos_apply")
        .expect("core-owned apply helper has a CLIF declaration");
    let deopt_declaration = preflight
        .declaration_for_symbol("aos_deopt")
        .expect("core-owned deopt helper has a CLIF declaration");
    let env_get_declaration = preflight
        .declaration_for_symbol("aos_env_get")
        .expect("core-owned environment helper has a CLIF declaration");
    let write_barrier_declaration = preflight
        .declaration_for_symbol("aos_gc_write_barrier")
        .expect("core-owned write-barrier helper has a CLIF declaration");
    let force_declaration = preflight
        .declaration_for_symbol("aos_force")
        .expect("core-owned force helper has a CLIF declaration");
    let force_deep_declaration = preflight
        .declaration_for_symbol("aos_force_deep")
        .expect("core-owned deep-force helper has a CLIF declaration");
    let blackhole_check_declaration = preflight
        .declaration_for_symbol("aos_blackhole_check")
        .expect("core-owned blackhole-check helper has a CLIF declaration");
    let has_attr_declaration = preflight
        .declaration_for_symbol("aos_has_attr")
        .expect("core-owned has-attr helper has a CLIF declaration");
    let select_ic_declaration = preflight
        .declaration_for_symbol("aos_select_ic")
        .expect("core-owned select-IC helper has a CLIF declaration");
    let update_declaration = preflight
        .declaration_for_symbol("aos_update")
        .expect("core-owned update helper has a CLIF declaration");
    let throw_declaration = preflight
        .declaration_for_symbol("aos_throw")
        .expect("core-owned throw helper has a CLIF declaration");
    let expected_allocation = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_alloc_attrs")
            .expect("allocation helper signature is core-owned"),
    )
    .expect("allocation helper signature lowers");
    let expected_apply = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_apply").expect("apply helper signature is core-owned"),
    )
    .expect("apply helper signature lowers");
    let expected_deopt = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_deopt").expect("deopt helper signature is core-owned"),
    )
    .expect("deopt helper signature lowers");
    let expected_env_get = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_env_get")
            .expect("environment helper signature is core-owned"),
    )
    .expect("environment helper signature lowers");
    let expected_write_barrier = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_gc_write_barrier")
            .expect("write-barrier helper signature is core-owned"),
    )
    .expect("write-barrier helper signature lowers");
    let expected_force = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_force").expect("force helper signature is core-owned"),
    )
    .expect("force helper signature lowers");
    let expected_force_deep = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_force_deep")
            .expect("deep-force helper signature is core-owned"),
    )
    .expect("deep-force helper signature lowers");
    let expected_blackhole_check = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_blackhole_check")
            .expect("blackhole-check helper signature is core-owned"),
    )
    .expect("blackhole-check helper signature lowers");
    let expected_has_attr = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_has_attr")
            .expect("has-attr helper signature is core-owned"),
    )
    .expect("has-attr helper signature lowers");
    let expected_select_ic = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_select_ic")
            .expect("select-IC helper signature is core-owned"),
    )
    .expect("select-IC helper signature lowers");
    let expected_update = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_update").expect("update helper signature is core-owned"),
    )
    .expect("update helper signature lowers");
    let expected_throw = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_throw").expect("throw helper signature is core-owned"),
    )
    .expect("throw helper signature lowers");

    assert_eq!(
        allocation_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation)
    );
    assert_eq!(allocation_declaration.signature(), &expected_allocation);
    assert_eq!(
        apply_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl)
    );
    assert_eq!(apply_declaration.signature(), &expected_apply);
    assert_eq!(
        deopt_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::Deoptimization)
    );
    assert_eq!(deopt_declaration.signature(), &expected_deopt);
    assert_eq!(
        env_get_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess)
    );
    assert_eq!(env_get_declaration.signature(), &expected_env_get);
    assert_eq!(
        write_barrier_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::WriteBarrier)
    );
    assert_eq!(
        write_barrier_declaration.signature(),
        &expected_write_barrier
    );
    assert_eq!(
        force_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
    );
    assert_eq!(force_declaration.signature(), &expected_force);
    assert_eq!(
        force_deep_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
    );
    assert_eq!(force_deep_declaration.signature(), &expected_force_deep);
    assert_eq!(
        blackhole_check_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
    );
    assert_eq!(
        blackhole_check_declaration.signature(),
        &expected_blackhole_check
    );
    assert_eq!(
        has_attr_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
    );
    assert_eq!(has_attr_declaration.signature(), &expected_has_attr);
    assert_eq!(
        select_ic_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
    );
    assert_eq!(select_ic_declaration.signature(), &expected_select_ic);
    assert_eq!(
        update_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
    );
    assert_eq!(update_declaration.signature(), &expected_update);
    assert_eq!(
        throw_declaration.kind(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl)
    );
    assert_eq!(throw_declaration.signature(), &expected_throw);
    assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_none());
    assert!(preflight.gap_for_symbol("aos_apply").is_none());
    assert!(preflight.gap_for_symbol("aos_deopt").is_none());
    assert!(preflight.gap_for_symbol("aos_env_get").is_none());
    assert!(preflight.gap_for_symbol("aos_gc_write_barrier").is_none());
    assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
    assert!(preflight.gap_for_symbol("aos_force").is_none());
    assert!(preflight.gap_for_symbol("aos_force_deep").is_none());
    assert!(preflight.gap_for_symbol("aos_has_attr").is_none());
    assert!(preflight.gap_for_symbol("aos_select_ic").is_none());
    assert!(preflight.gap_for_symbol("aos_update").is_none());
    assert!(preflight.gap_for_symbol("aos_throw").is_none());
}

#[test]
fn jit_runtime_symbol_declaration_preflight_reports_unshaped_helper_gaps() {
    let preflight = jit_runtime_symbol_declaration_preflight()
        .expect("JIT symbol declaration preflight builds");

    for (symbol_name, role) in [
        ("aos_try_begin", RuntimeHelperRole::ErrorControl),
        ("aos_try_end", RuntimeHelperRole::ErrorControl),
    ] {
        assert!(matches!(
            preflight.gap_for_symbol(symbol_name),
            Some(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: gap_role,
                    ..
                }
            ) if *gap_role == role
        ));
        assert!(preflight.declaration_for_symbol(symbol_name).is_none());
    }
}

#[test]
fn jit_runtime_symbol_declaration_preflight_reports_value_only_builtin_gaps() {
    let preflight = jit_runtime_symbol_declaration_preflight()
        .expect("JIT symbol declaration preflight builds");

    assert!(matches!(
        preflight.gap_for_symbol("nix.builtin.true"),
        Some(JitRuntimeSymbolDeclarationGap::BuiltinValueOnly {
            builtin_name: b"true",
            ..
        })
    ));
    assert!(
        preflight
            .declaration_for_symbol("nix.builtin.true")
            .is_none()
    );
}

#[test]
fn jit_runtime_symbol_declaration_preflight_matches_core_builtin_call_counts() {
    let preflight = jit_runtime_symbol_declaration_preflight()
        .expect("JIT symbol declaration preflight builds");
    let builtin_preflight =
        runtime_builtin_call_preflight().expect("core builtin call preflight builds");

    assert!(!preflight.is_complete());
    assert_eq!(
        preflight.declarations().len(),
        builtin_preflight.call_bindings().len() + runtime_helper_call_signatures().len()
    );
    for binding in builtin_preflight.call_bindings() {
        assert!(
            preflight
                .declaration_for_symbol(binding.symbol_name())
                .is_some(),
            "{} has a JIT CLIF declaration",
            binding.symbol_name()
        );
    }
    for signature in runtime_helper_call_signatures() {
        let RuntimeCallableKind::Helper { symbol } = signature.callable() else {
            panic!("helper signature uses helper callable kind");
        };
        assert!(
            preflight.declaration_for_symbol(symbol.name()).is_some(),
            "{} has a JIT CLIF declaration",
            symbol.name()
        );
    }
}

#[test]
fn jit_runtime_symbol_registration_preflight_reports_missing_native_addresses() {
    let declaration_preflight = jit_runtime_symbol_declaration_preflight()
        .expect("JIT symbol declaration preflight builds");
    let preflight = jit_runtime_symbol_registration_preflight()
        .expect("JIT symbol registration preflight builds");

    assert!(preflight.bindings().is_empty());
    assert!(!preflight.is_complete());
    assert_eq!(
        preflight.gaps().len(),
        declaration_preflight.declarations().len() + declaration_preflight.gaps().len()
    );
    assert!(matches!(
        preflight.gap_for_symbol("aos_alloc_attrs"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_apply"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_deopt"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Deoptimization),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_env_get"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("nix.builtin.derivationStrict"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Builtin,
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_force"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_has_attr"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_select_ic"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            ..
        })
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_update"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
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
}

#[test]
fn jit_runtime_symbol_registration_preflight_binds_synthetic_candidates_in_manifest_order() {
    let candidates = [
        synthetic_address_candidate(
            "nix.builtin.derivationStrict",
            RuntimeSymbolKind::Builtin,
            2,
        ),
        synthetic_address_candidate(
            "aos_alloc_attrs",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
            1,
        ),
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
    ];
    let preflight = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
        .expect("JIT symbol registration preflight builds");
    let binding_symbols = preflight
        .bindings()
        .iter()
        .map(JitRuntimeSymbolRegistrationBinding::symbol_name)
        .collect::<Vec<_>>();

    assert_eq!(
        binding_symbols,
        vec![
            "aos_alloc_attrs",
            "aos_env_get",
            "nix.builtin.derivationStrict"
        ]
    );
    assert_eq!(
        preflight
            .binding_for_symbol("aos_alloc_attrs")
            .expect("allocation helper candidate binds")
            .address()
            .as_nonzero_usize()
            .get(),
        1
    );
    assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_none());
    assert_eq!(
        preflight
            .binding_for_symbol("aos_env_get")
            .expect("environment helper candidate binds")
            .address()
            .as_nonzero_usize()
            .get(),
        3
    );
    assert!(preflight.gap_for_symbol("aos_env_get").is_none());
    assert!(matches!(
        preflight.gap_for_symbol("aos_force"),
        Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
            kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            ..
        })
    ));
}

#[test]
fn jit_runtime_symbol_registration_preflight_reports_kind_mismatches() {
    let candidates = [synthetic_address_candidate(
        "aos_alloc_attrs",
        RuntimeSymbolKind::Builtin,
        1,
    )];
    let preflight = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
        .expect("JIT symbol registration preflight builds");

    assert!(preflight.binding_for_symbol("aos_alloc_attrs").is_none());
    assert!(matches!(
        preflight.gap_for_symbol("aos_alloc_attrs"),
        Some(JitRuntimeSymbolRegistrationGap::NativeAddressKindMismatch {
            declaration_kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
            candidate_kind: RuntimeSymbolKind::Builtin,
            ..
        })
    ));
}

#[test]
fn jit_runtime_symbol_registration_preflight_keeps_declaration_gaps_before_addresses() {
    let candidates = [
        synthetic_address_candidate(
            "aos_blackhole_check",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            1,
        ),
        synthetic_address_candidate(
            "aos_has_attr",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            2,
        ),
        synthetic_address_candidate(
            "aos_try_begin",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl),
            3,
        ),
        synthetic_address_candidate(
            "aos_try_end",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl),
            4,
        ),
        synthetic_address_candidate(
            "aos_update",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            5,
        ),
    ];
    let preflight = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
        .expect("JIT symbol registration preflight builds");

    for (symbol_name, role) in [
        ("aos_try_begin", RuntimeHelperRole::ErrorControl),
        ("aos_try_end", RuntimeHelperRole::ErrorControl),
    ] {
        assert!(preflight.binding_for_symbol(symbol_name).is_none());
        assert!(matches!(
            preflight.gap_for_symbol(symbol_name),
            Some(JitRuntimeSymbolRegistrationGap::Declaration(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: gap_role,
                    ..
                }
            )) if *gap_role == role
        ));
    }
    assert!(
        preflight
            .binding_for_symbol("aos_blackhole_check")
            .is_some()
    );
    assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
    assert!(preflight.binding_for_symbol("aos_has_attr").is_some());
    assert!(preflight.gap_for_symbol("aos_has_attr").is_none());
    assert!(preflight.binding_for_symbol("aos_update").is_some());
    assert!(preflight.gap_for_symbol("aos_update").is_none());
}

#[test]
fn jit_runtime_symbol_registration_preflight_rejects_duplicate_candidates() {
    let candidates = [
        synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 1),
        synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 2),
    ];
    let Err(error) = jit_runtime_symbol_registration_preflight_with_candidates(&candidates) else {
        panic!("duplicate address candidates must be rejected");
    };

    assert!(matches!(
        error,
        JitRuntimeSymbolRegistrationError::DuplicateAddressCandidate { symbol_name }
            if symbol_name == "aos_alloc_attrs"
    ));
}

#[test]
fn jit_runtime_symbol_registration_preflight_rejects_unknown_candidates() {
    let candidates = [synthetic_address_candidate(
        "aos_not_a_runtime_symbol",
        RuntimeSymbolKind::Builtin,
        1,
    )];
    let Err(error) = jit_runtime_symbol_registration_preflight_with_candidates(&candidates) else {
        panic!("unknown address candidates must be rejected");
    };

    assert!(matches!(
        error,
        JitRuntimeSymbolRegistrationError::UnknownAddressCandidate { symbol_name }
            if symbol_name == "aos_not_a_runtime_symbol"
    ));
}

#[test]
fn jit_runtime_symbol_registration_plan_refuses_current_address_gaps() {
    let Err(error) = jit_runtime_symbol_registration_plan() else {
        panic!("missing native addresses must block complete registration plans");
    };

    let JitRuntimeSymbolRegistrationPlanError::Incomplete {
        missing_count,
        preflight,
    } = error
    else {
        panic!("expected incomplete registration plan");
    };

    assert_eq!(missing_count, preflight.gaps().len());
    assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_some());
    assert!(
        preflight
            .gap_for_symbol("nix.builtin.derivationStrict")
            .is_some()
    );
}

#[test]
fn jit_runtime_symbol_registration_preflight_converts_synthetic_complete_report_to_plan() {
    let declaration_preflight = jit_runtime_symbol_declaration_preflight()
        .expect("JIT symbol declaration preflight builds");
    let declaration = declaration_preflight
        .declaration_for_symbol("aos_alloc_attrs")
        .expect("allocation helper declaration exists")
        .clone();
    let binding = JitRuntimeSymbolRegistrationBinding::new(declaration, synthetic_address(1));
    let preflight = JitRuntimeSymbolRegistrationPreflight::new(vec![binding.clone()], vec![]);
    let plan = preflight
        .into_registration_plan()
        .expect("synthetic complete registration preflight converts");

    assert_eq!(plan.bindings(), &[binding]);
    assert!(plan.binding_for_symbol("aos_alloc_attrs").is_some());
}
