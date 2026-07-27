use std::collections::BTreeSet;

use crate::compile::{
    RuntimeAbiParameterKind, RuntimeAbiReturnKind, RuntimeHelperRole, resolve,
    runtime_helper_call_signature, runtime_helper_symbols,
};
use crate::syntax::parse_str;

use super::*;

#[test]
fn runtime_forcing_symbol_is_safe_force_subset_of_core_inventory() {
    let helper_symbols = runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| symbol.role() == RuntimeHelperRole::ForcingControl)
        .map(|symbol| symbol.name())
        .collect::<BTreeSet<_>>();
    let entrypoint_symbols = runtime_forcing_entrypoints()
        .iter()
        .copied()
        .map(RuntimeForcingEntryPoint::symbol_name)
        .collect::<BTreeSet<_>>();
    let signature_symbols = runtime_forcing_abi_signatures()
        .iter()
        .copied()
        .map(RuntimeForcingAbiSignature::symbol_name)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        helper_symbols,
        BTreeSet::from(["aos_blackhole_check", "aos_force", "aos_force_deep"])
    );
    assert_eq!(
        entrypoint_symbols,
        BTreeSet::from(["aos_blackhole_check", "aos_force", "aos_force_deep"])
    );
    assert_eq!(signature_symbols, entrypoint_symbols);
}

#[test]
fn forcing_entrypoint_symbols_round_trip() {
    assert_eq!(
        runtime_forcing_entrypoints(),
        [
            RuntimeForcingEntryPoint::AosBlackholeCheck,
            RuntimeForcingEntryPoint::AosForce,
            RuntimeForcingEntryPoint::AosForceDeep,
        ]
    );

    for entrypoint in runtime_forcing_entrypoints() {
        assert_eq!(
            RuntimeForcingEntryPoint::from_symbol_name(entrypoint.symbol_name()),
            Some(*entrypoint)
        );
        assert_eq!(
            RuntimeForcingAbiSignature::from_symbol_name(entrypoint.symbol_name()),
            Some(entrypoint.abi_signature())
        );
    }
    for symbol in runtime_helper_symbols().iter().copied().filter(|symbol| {
        !matches!(
            symbol.name(),
            "aos_blackhole_check" | "aos_force" | "aos_force_deep"
        )
    }) {
        assert_eq!(
            RuntimeForcingEntryPoint::from_symbol_name(symbol.name()),
            None,
            "{} is not a forcing entry point with a Rust callable",
            symbol.name()
        );
        assert_eq!(
            RuntimeForcingAbiSignature::from_symbol_name(symbol.name()),
            None,
            "{} has no forcing ABI signature in this family",
            symbol.name()
        );
    }
}

#[test]
fn forcing_abi_signature_pins_runtime_return_boundaries() {
    assert_eq!(
        runtime_forcing_abi_signatures(),
        [
            RuntimeForcingAbiSignature::new(
                RuntimeForcingEntryPoint::AosBlackholeCheck,
                FORCE_VALUE_PARAMETERS,
                RuntimeForcingAbiReturnKind::Unit,
            ),
            RuntimeForcingAbiSignature::new(
                RuntimeForcingEntryPoint::AosForce,
                FORCE_VALUE_PARAMETERS,
                RuntimeForcingAbiReturnKind::Value,
            ),
            RuntimeForcingAbiSignature::new(
                RuntimeForcingEntryPoint::AosForceDeep,
                FORCE_VALUE_PARAMETERS,
                RuntimeForcingAbiReturnKind::Value,
            ),
        ]
    );
    for entrypoint in runtime_forcing_entrypoints() {
        let signature = entrypoint.abi_signature();

        assert_eq!(signature.entrypoint(), *entrypoint);
        assert_eq!(signature.symbol_name(), entrypoint.symbol_name());
        assert_eq!(
            signature.parameters(),
            [
                RuntimeForcingAbiParameter::new(
                    "rt",
                    RuntimeForcingAbiParameterKind::RuntimeContext,
                ),
                RuntimeForcingAbiParameter::new("value", RuntimeForcingAbiParameterKind::Value),
            ]
            .as_slice()
        );
        assert_eq!(
            signature.return_kind(),
            entrypoint.abi_signature().return_kind()
        );
    }
}

#[test]
fn forcing_abi_signature_matches_core_runtime_call_metadata() {
    for entrypoint in runtime_forcing_entrypoints() {
        let local_signature = entrypoint.abi_signature();
        let core_signature =
            runtime_helper_call_signature(local_signature.symbol_name()).expect("core force ABI");
        let core_parameters = core_signature
            .parameters()
            .iter()
            .map(|parameter| (parameter.name(), parameter.kind()))
            .collect::<Vec<_>>();

        assert_eq!(
            local_signature
                .parameters()
                .iter()
                .map(|parameter| (parameter.name(), parameter.kind()))
                .collect::<Vec<_>>(),
            vec![
                ("rt", RuntimeForcingAbiParameterKind::RuntimeContext),
                ("value", RuntimeForcingAbiParameterKind::Value),
            ],
            "{} local ABI parameters match the forcing family shape",
            entrypoint.symbol_name()
        );
        assert_eq!(
            core_parameters,
            vec![
                ("rt", RuntimeAbiParameterKind::RuntimeContext),
                ("value", RuntimeAbiParameterKind::Value),
            ],
            "{} core ABI parameters match the forcing family shape",
            entrypoint.symbol_name()
        );
        match local_signature.return_kind() {
            RuntimeForcingAbiReturnKind::Unit => {
                assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Unit);
            }
            RuntimeForcingAbiReturnKind::Value => {
                assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Value);
            }
        }
    }
}

#[test]
fn forcing_rust_callable_bindings_preserve_entrypoint_inventory() {
    let bindings = runtime_forcing_rust_callable_bindings();
    let expected = [
        (
            RuntimeForcingEntryPoint::AosBlackholeCheck,
            RuntimeForcingRustCallableShape::TreeWalkBlackholeCheck,
            rust_callable_aos_blackhole_check as RuntimeBlackholeCheckFn as *const (),
        ),
        (
            RuntimeForcingEntryPoint::AosForce,
            RuntimeForcingRustCallableShape::TreeWalkForceValue,
            rust_callable_aos_force as RuntimeForceValueFn as *const (),
        ),
        (
            RuntimeForcingEntryPoint::AosForceDeep,
            RuntimeForcingRustCallableShape::TreeWalkDeepForceValue,
            rust_callable_aos_force_deep as RuntimeForceValueFn as *const (),
        ),
    ];

    assert_eq!(bindings.len(), expected.len());
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(RuntimeForcingRustCallableBinding::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_forcing_entrypoints()
    );
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(|binding| (
                binding.entrypoint(),
                binding.shape(),
                binding.address().as_ptr(),
            ))
            .collect::<Vec<_>>()
            .as_slice(),
        expected.as_slice()
    );
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(|binding| binding.entrypoint().abi_signature())
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_forcing_abi_signatures()
    );

    for binding in bindings {
        assert_eq!(binding.symbol_name(), binding.entrypoint().symbol_name());
        assert_eq!(binding.entrypoint().rust_callable_binding(), binding);
        assert_eq!(binding.shape(), binding.entrypoint().rust_callable_shape());
        assert_eq!(
            binding.address(),
            binding.entrypoint().rust_callable_address()
        );
        assert!(
            binding.address().is_non_null(),
            "{} Rust-callable address is non-null",
            binding.symbol_name()
        );
    }
}

#[test]
fn forcing_native_export_preflight_preserves_frozen_abi_and_callable() {
    let preflight = runtime_forcing_native_export_preflight();

    assert!(!preflight.is_complete());
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeForcingNativeExportReadiness::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_forcing_entrypoints()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeForcingNativeExportReadiness::abi_signature)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_forcing_abi_signatures()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeForcingNativeExportReadiness::rust_callable_binding)
            .collect::<Vec<_>>(),
        runtime_forcing_rust_callable_bindings()
    );

    for entrypoint in runtime_forcing_entrypoints() {
        let record = preflight
            .readiness_for_symbol(entrypoint.symbol_name())
            .expect("force export readiness exists");

        assert_eq!(record.entrypoint(), *entrypoint);
        assert_eq!(record.symbol_name(), entrypoint.symbol_name());
        assert_eq!(record.blockers(), entrypoint.native_export_blockers());
        match entrypoint {
            RuntimeForcingEntryPoint::AosBlackholeCheck => assert_eq!(
                record.blockers(),
                [
                    RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
                    RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                    RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
                    RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
                ]
                .as_slice()
            ),
            RuntimeForcingEntryPoint::AosForce | RuntimeForcingEntryPoint::AosForceDeep => {
                assert_eq!(
                    record.blockers(),
                    [
                        RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
                        RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                        RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
                        RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
                        RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
                        RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
                    ]
                    .as_slice()
                );
            }
        }
        assert!(!record.is_export_ready());
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented)
        );
        assert!(
            record.blockers().contains(
                &RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented
            )
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented)
        );
        match entrypoint {
            RuntimeForcingEntryPoint::AosBlackholeCheck => {
                assert!(!record.blockers().contains(
                    &RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented
                ));
                assert!(!record.blockers().contains(
                    &RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented
                ));
                assert!(
                    !record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::NativeValueReturnUnmaterialized
                    )
                );
            }
            RuntimeForcingEntryPoint::AosForce | RuntimeForcingEntryPoint::AosForceDeep => {
                assert!(record.blockers().contains(
                    &RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented
                ));
                assert!(record.blockers().contains(
                    &RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented
                ));
                assert!(
                    !record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::NativeValueReturnUnmaterialized
                    )
                );
            }
        }
    }
}

#[test]
fn force_and_blackhole_check_rust_callables_preserve_non_thunk_values() {
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str("null").expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut eval = TreeWalk::new(&ir);
    let value = Value::int(42);
    rust_callable_aos_blackhole_check(&mut eval, IrId::new(0), Span::new(0, 4), value)
        .expect("non-thunk blackhole check succeeds");
    let forced = rust_callable_aos_force(&mut eval, IrId::new(0), Span::new(0, 4), value)
        .expect("non-thunk force succeeds");
    let deeply_forced =
        rust_callable_aos_force_deep(&mut eval, IrId::new(0), Span::new(0, 4), value)
            .expect("non-thunk deep force succeeds");

    assert_eq!(forced.as_int().expect("forced value is an int"), 42);
    assert_eq!(
        deeply_forced
            .as_int()
            .expect("deeply forced value is an int"),
        42
    );
}

#[test]
fn blackhole_check_rust_callable_traps_only_blackholed_thunks() {
    let source = "[ (1 + 2) (3 + 4) ]";
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut eval = TreeWalk::new(&ir);
    let root = eval.eval_root().expect("list evaluates");
    let (forced_candidate, blackhole_candidate) = {
        let list = eval.heap().get_list(root).expect("root list is heap-owned");
        (
            list.get(0).expect("first element exists"),
            list.get(1).expect("second element exists"),
        )
    };

    rust_callable_aos_blackhole_check(
        &mut eval,
        ir.root,
        Span::new(0, source.len() as u32),
        forced_candidate,
    )
    .expect("suspended thunk is not a blackhole");
    rust_callable_aos_force(
        &mut eval,
        ir.root,
        Span::new(0, source.len() as u32),
        forced_candidate,
    )
    .expect("first thunk forces");
    rust_callable_aos_blackhole_check(
        &mut eval,
        ir.root,
        Span::new(0, source.len() as u32),
        forced_candidate,
    )
    .expect("forced thunk is not a blackhole");

    let guard = {
        let thunk = eval
            .heap()
            .get_thunk(blackhole_candidate)
            .expect("second element is a thunk");
        let crate::eval::ForceClaim::Claimed(guard) = thunk
            .cell()
            .begin_force()
            .expect("suspended thunk is claimed")
        else {
            panic!("expected a claimed suspended thunk");
        };
        guard
    };
    std::mem::forget(guard);

    let error = rust_callable_aos_blackhole_check(
        &mut eval,
        ir.root,
        Span::new(0, source.len() as u32),
        blackhole_candidate,
    )
    .expect_err("blackholed thunk traps");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Force {
            id: ir.root,
            source: ForceError::InfiniteRecursion,
        }
    );
}

#[test]
fn deep_force_rust_callable_forces_nested_container_thunks() {
    let source = "[ [ (1 + 2) ] ]";
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut eval = TreeWalk::new(&ir);
    let root = eval.eval_root().expect("list evaluates");
    let outer_element = {
        let list = eval.heap().get_list(root).expect("root list is heap-owned");
        list.get(0).expect("outer element exists")
    };

    assert!(
        eval.heap()
            .get_thunk(outer_element)
            .expect("outer element is a suspended thunk")
            .cell()
            .cached_value()
            .expect("suspended outer thunk is readable")
            .is_none()
    );

    let deeply_forced =
        rust_callable_aos_force_deep(&mut eval, ir.root, Span::new(0, source.len() as u32), root)
            .expect("nested list deep force succeeds");
    let inner_list_value = eval
        .heap()
        .get_thunk(outer_element)
        .expect("outer element remains a thunk")
        .cell()
        .cached_value()
        .expect("outer thunk cache is readable")
        .expect("outer thunk caches the forced inner list");
    let inner_element = {
        let inner_list = eval
            .heap()
            .get_list(inner_list_value)
            .expect("inner list is heap-owned");
        inner_list.get(0).expect("inner element exists")
    };
    let inner_cached_value = eval
        .heap()
        .get_thunk(inner_element)
        .expect("inner element remains a thunk")
        .cell()
        .cached_value()
        .expect("inner thunk cache is readable")
        .expect("inner thunk caches its forced scalar");

    assert!(deeply_forced.raw_eq(root));
    assert_eq!(
        inner_cached_value
            .as_int()
            .expect("inner cached value is an int"),
        3
    );
}
