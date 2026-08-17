use std::collections::BTreeSet;

use crate::compile::{
    RuntimeAbiParameterKind, RuntimeAbiReturnKind, RuntimeHelperRole, resolve,
    runtime_helper_call_signature, runtime_helper_symbols,
};
use crate::eval::tree_walk::TreeWalkErrorKind;
use crate::syntax::parse_str;
use crate::value::ValueTag;
use ratchet_value::attrs::pic::ShapedSelectError;

use super::*;

#[test]
fn runtime_attr_access_symbols_are_safe_attr_subset_of_core_inventory() {
    let helper_symbols = runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| symbol.role() == RuntimeHelperRole::AttrsetAccess)
        .map(|symbol| symbol.name())
        .collect::<BTreeSet<_>>();
    let entrypoint_symbols = runtime_attr_access_entrypoints()
        .iter()
        .copied()
        .map(RuntimeAttrAccessEntryPoint::symbol_name)
        .collect::<BTreeSet<_>>();
    let signature_symbols = runtime_attr_access_abi_signatures()
        .iter()
        .copied()
        .map(RuntimeAttrAccessAbiSignature::symbol_name)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        helper_symbols,
        BTreeSet::from(["aos_has_attr", "aos_select_ic", "aos_update"])
    );
    assert_eq!(
        entrypoint_symbols,
        BTreeSet::from(["aos_has_attr", "aos_select_ic", "aos_update"])
    );
    assert_eq!(signature_symbols, entrypoint_symbols);
}

#[test]
fn attr_access_entrypoint_symbols_round_trip() {
    assert_eq!(
        runtime_attr_access_entrypoints(),
        [
            RuntimeAttrAccessEntryPoint::AosHasAttr,
            RuntimeAttrAccessEntryPoint::AosSelectIc,
            RuntimeAttrAccessEntryPoint::AosUpdate
        ]
    );

    for entrypoint in runtime_attr_access_entrypoints() {
        assert_eq!(
            RuntimeAttrAccessEntryPoint::from_symbol_name(entrypoint.symbol_name()),
            Some(*entrypoint)
        );
        assert_eq!(
            RuntimeAttrAccessAbiSignature::from_symbol_name(entrypoint.symbol_name()),
            Some(entrypoint.abi_signature())
        );
    }
    for symbol in runtime_helper_symbols().iter().copied().filter(|symbol| {
        !matches!(
            symbol.name(),
            "aos_has_attr" | "aos_select_ic" | "aos_update"
        )
    }) {
        assert_eq!(
            RuntimeAttrAccessEntryPoint::from_symbol_name(symbol.name()),
            None,
            "{} is not an attribute-access entry point with a Rust callable",
            symbol.name()
        );
        assert_eq!(
            RuntimeAttrAccessAbiSignature::from_symbol_name(symbol.name()),
            None,
            "{} has no attribute-access ABI signature in this family",
            symbol.name()
        );
    }
}

#[test]
fn attr_access_abi_signatures_pin_static_key_value_returns() {
    let has_attr = RuntimeAttrAccessEntryPoint::AosHasAttr.abi_signature();
    let select_ic = RuntimeAttrAccessEntryPoint::AosSelectIc.abi_signature();
    let update = RuntimeAttrAccessEntryPoint::AosUpdate.abi_signature();

    assert_eq!(
        runtime_attr_access_abi_signatures(),
        [
            RuntimeAttrAccessAbiSignature::new(
                RuntimeAttrAccessEntryPoint::AosHasAttr,
                HAS_ATTR_PARAMETERS,
                RuntimeAttrAccessAbiReturnKind::Value,
            ),
            RuntimeAttrAccessAbiSignature::new(
                RuntimeAttrAccessEntryPoint::AosSelectIc,
                SELECT_IC_PARAMETERS,
                RuntimeAttrAccessAbiReturnKind::Value,
            ),
            RuntimeAttrAccessAbiSignature::new(
                RuntimeAttrAccessEntryPoint::AosUpdate,
                UPDATE_PARAMETERS,
                RuntimeAttrAccessAbiReturnKind::Value,
            ),
        ]
    );

    for (entrypoint, signature) in [
        (RuntimeAttrAccessEntryPoint::AosHasAttr, has_attr),
        (RuntimeAttrAccessEntryPoint::AosSelectIc, select_ic),
    ] {
        assert_eq!(signature.entrypoint(), entrypoint);
        assert_eq!(signature.symbol_name(), entrypoint.symbol_name());
        assert_eq!(
            signature.parameters(),
            [
                RuntimeAttrAccessAbiParameter::new(
                    "rt",
                    RuntimeAttrAccessAbiParameterKind::RuntimeContext,
                ),
                RuntimeAttrAccessAbiParameter::new(
                    "attrs",
                    RuntimeAttrAccessAbiParameterKind::Value,
                ),
                RuntimeAttrAccessAbiParameter::new(
                    "symbol",
                    RuntimeAttrAccessAbiParameterKind::SymbolId,
                ),
                RuntimeAttrAccessAbiParameter::new(
                    "site",
                    RuntimeAttrAccessAbiParameterKind::InlineCacheSiteId,
                ),
            ]
            .as_slice()
        );
        assert_eq!(
            signature.return_kind(),
            RuntimeAttrAccessAbiReturnKind::Value
        );
    }

    assert_eq!(update.entrypoint(), RuntimeAttrAccessEntryPoint::AosUpdate);
    assert_eq!(update.symbol_name(), "aos_update");
    assert_eq!(
        update.parameters(),
        [
            RuntimeAttrAccessAbiParameter::new(
                "rt",
                RuntimeAttrAccessAbiParameterKind::RuntimeContext,
            ),
            RuntimeAttrAccessAbiParameter::new("left", RuntimeAttrAccessAbiParameterKind::Value,),
            RuntimeAttrAccessAbiParameter::new("right", RuntimeAttrAccessAbiParameterKind::Value,),
        ]
        .as_slice()
    );
    assert_eq!(update.return_kind(), RuntimeAttrAccessAbiReturnKind::Value);
}

#[test]
fn attr_access_abi_signature_matches_core_runtime_call_metadata() {
    for local_signature in runtime_attr_access_abi_signatures().iter().copied() {
        let core_signature = runtime_helper_call_signature(local_signature.symbol_name())
            .expect("core attr-access ABI");
        let core_parameters = core_signature
            .parameters()
            .iter()
            .map(|parameter| (parameter.name(), parameter.kind()))
            .collect::<Vec<_>>();

        let expected_local_parameters = match local_signature.entrypoint() {
            RuntimeAttrAccessEntryPoint::AosHasAttr | RuntimeAttrAccessEntryPoint::AosSelectIc => {
                vec![
                    ("rt", RuntimeAttrAccessAbiParameterKind::RuntimeContext),
                    ("attrs", RuntimeAttrAccessAbiParameterKind::Value),
                    ("symbol", RuntimeAttrAccessAbiParameterKind::SymbolId),
                    ("site", RuntimeAttrAccessAbiParameterKind::InlineCacheSiteId),
                ]
            }
            RuntimeAttrAccessEntryPoint::AosUpdate => vec![
                ("rt", RuntimeAttrAccessAbiParameterKind::RuntimeContext),
                ("left", RuntimeAttrAccessAbiParameterKind::Value),
                ("right", RuntimeAttrAccessAbiParameterKind::Value),
            ],
        };
        let expected_core_parameters = match local_signature.entrypoint() {
            RuntimeAttrAccessEntryPoint::AosHasAttr | RuntimeAttrAccessEntryPoint::AosSelectIc => {
                vec![
                    ("rt", RuntimeAbiParameterKind::RuntimeContext),
                    ("attrs", RuntimeAbiParameterKind::Value),
                    ("symbol", RuntimeAbiParameterKind::SymbolId),
                    ("site", RuntimeAbiParameterKind::InlineCacheSiteId),
                ]
            }
            RuntimeAttrAccessEntryPoint::AosUpdate => vec![
                ("rt", RuntimeAbiParameterKind::RuntimeContext),
                ("left", RuntimeAbiParameterKind::Value),
                ("right", RuntimeAbiParameterKind::Value),
            ],
        };

        assert_eq!(
            local_signature
                .parameters()
                .iter()
                .map(|parameter| (parameter.name(), parameter.kind()))
                .collect::<Vec<_>>(),
            expected_local_parameters
        );
        assert_eq!(core_parameters, expected_core_parameters);
        assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            local_signature.return_kind(),
            RuntimeAttrAccessAbiReturnKind::Value
        );
    }
}

#[test]
fn attr_access_rust_callable_bindings_preserve_entrypoint_inventory() {
    let bindings = runtime_attr_access_rust_callable_bindings();
    let expected = [
        (
            RuntimeAttrAccessEntryPoint::AosHasAttr,
            RuntimeAttrAccessRustCallableShape::TreeWalkHasAttrValue,
            rust_callable_aos_has_attr as RuntimeHasAttrFn as *const (),
        ),
        (
            RuntimeAttrAccessEntryPoint::AosSelectIc,
            RuntimeAttrAccessRustCallableShape::TreeWalkSelectAttrValue,
            rust_callable_aos_select_ic as RuntimeSelectIcFn as *const (),
        ),
        (
            RuntimeAttrAccessEntryPoint::AosUpdate,
            RuntimeAttrAccessRustCallableShape::TreeWalkUpdateAttrValues,
            rust_callable_aos_update as RuntimeUpdateFn as *const (),
        ),
    ];

    assert_eq!(bindings.len(), expected.len());
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(RuntimeAttrAccessRustCallableBinding::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_attr_access_entrypoints()
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
        runtime_attr_access_abi_signatures()
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
fn attr_access_native_export_preflight_preserves_frozen_abi_and_callable() {
    let preflight = runtime_attr_access_native_export_preflight();

    assert!(!preflight.is_complete());
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeAttrAccessNativeExportReadiness::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_attr_access_entrypoints()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeAttrAccessNativeExportReadiness::abi_signature)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_attr_access_abi_signatures()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeAttrAccessNativeExportReadiness::rust_callable_binding)
            .collect::<Vec<_>>(),
        runtime_attr_access_rust_callable_bindings()
    );

    for entrypoint in runtime_attr_access_entrypoints().iter().copied() {
        let record = preflight
            .readiness_for_symbol(entrypoint.symbol_name())
            .expect("attr-access export readiness exists");

        assert_eq!(record.entrypoint(), entrypoint);
        assert_eq!(record.symbol_name(), entrypoint.symbol_name());
        assert_eq!(record.blockers(), entrypoint.native_export_blockers());
        assert!(!record.is_export_ready());
        match entrypoint {
            RuntimeAttrAccessEntryPoint::AosHasAttr | RuntimeAttrAccessEntryPoint::AosSelectIc => {
                assert_eq!(
                    record.blockers(),
                    [
                        RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper,
                        RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
                    ]
                    .as_slice()
                );
                assert!(!record.blockers().contains(
                    &RuntimeAttrAccessNativeExportBlocker::NativeAttrUpdateMergeUnimplemented
                ));
            }
            RuntimeAttrAccessEntryPoint::AosUpdate => {
                assert_eq!(
                    record.blockers(),
                    [
                        RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper,
                        RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::NativeAttrUpdateMergeUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
                        RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
                    ]
                    .as_slice()
                );
                assert!(!record.blockers().contains(
                    &RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented
                ));
                assert!(!record.blockers().contains(
                    &RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented
                ));
                assert!(!record.blockers().contains(
                    &RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented
                ));
            }
        }
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented)
        );
        assert!(record.blockers().contains(
            &RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented
        ));
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized)
        );
    }
}

#[test]
fn attr_access_rust_callable_reports_static_key_presence() {
    let source = "{ a = 42; nested.z = 0; }";
    let span = Span::new(0, source.len() as u32);
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut symbols = ir.symbols.clone();
    let present_key = symbols.intern(b"a").expect("symbol exists");
    let missing_key = symbols.intern(b"z").expect("symbol exists");
    let mut eval = TreeWalk::new(&ir);
    let attrs = eval.eval_root().expect("attrset evaluates");

    let present = rust_callable_aos_has_attr(
        &mut eval,
        ir.root,
        span,
        attrs,
        present_key,
        IrInlineCacheSiteId::new(7),
    )
    .expect("has-attr presence check succeeds");
    let repeated_present = rust_callable_aos_has_attr(
        &mut eval,
        ir.root,
        span,
        attrs,
        present_key,
        IrInlineCacheSiteId::new(7),
    )
    .expect("repeated has-attr presence check succeeds");
    let missing = rust_callable_aos_has_attr(
        &mut eval,
        ir.root,
        span,
        attrs,
        missing_key,
        IrInlineCacheSiteId::new(8),
    )
    .expect("has-attr missing check succeeds");

    assert_eq!(present.as_bool().expect("present result is bool"), true);
    assert_eq!(
        repeated_present
            .as_bool()
            .expect("repeated present result is bool"),
        true
    );
    assert_eq!(missing.as_bool().expect("missing result is bool"), false);
    assert_eq!(eval.stats().inline_cache_hits(), 1);
    assert_eq!(eval.stats().inline_cache_misses(), 2);
}

#[test]
fn attr_access_rust_callable_selects_static_attr_values() {
    let source = "{ a = 42; nested.z = 0; }";
    let span = Span::new(0, source.len() as u32);
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut symbols = ir.symbols.clone();
    let key = symbols.intern(b"a").expect("symbol exists");
    let mut eval = TreeWalk::new(&ir);
    let attrs = eval.eval_root().expect("attrset evaluates");
    let selected = rust_callable_aos_select_ic(
        &mut eval,
        ir.root,
        span,
        attrs,
        key,
        IrInlineCacheSiteId::new(7),
    )
    .expect("static attr selection succeeds");
    let repeated = rust_callable_aos_select_ic(
        &mut eval,
        ir.root,
        span,
        attrs,
        key,
        IrInlineCacheSiteId::new(7),
    )
    .expect("repeated static attr selection succeeds");

    assert_eq!(selected.as_int().expect("selected value is int"), 42);
    assert_eq!(repeated.as_int().expect("repeated value is int"), 42);
    assert_eq!(eval.stats().inline_cache_hits(), 1);
    assert_eq!(eval.stats().inline_cache_misses(), 1);
}

#[test]
fn attr_access_rust_callable_rejects_same_site_different_key_reuse() {
    let source = "{ a = 42; b = 7; }";
    let span = Span::new(0, source.len() as u32);
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut symbols = ir.symbols.clone();
    let a = symbols.intern(b"a").expect("a symbol exists");
    let b = symbols.intern(b"b").expect("b symbol exists");
    let mut eval = TreeWalk::new(&ir);
    let attrs = eval.eval_root().expect("attrset evaluates");
    let site = IrInlineCacheSiteId::new(7);

    let selected = rust_callable_aos_select_ic(&mut eval, ir.root, span, attrs, a, site)
        .expect("initial static attr selection succeeds");
    let error = rust_callable_aos_select_ic(&mut eval, ir.root, span, attrs, b, site)
        .expect_err("same IC site rejects different static key");

    assert_eq!(selected.as_int(), Ok(42));
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::ShapedSelectCache {
            source: ShapedSelectError::KeyChanged {
                previous,
                attempted,
            },
            ..
        } if previous == a && attempted == b
    ));
}

#[test]
fn attr_access_rust_callable_updates_attrsets_shallowly() {
    let source = "{ left = { a = 1 / 0; b = 1; }; right = { b = 2; c = 3; }; }";
    let span = Span::new(0, source.len() as u32);
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut symbols = ir.symbols.clone();
    let a = symbols.intern(b"a").expect("a symbol exists");
    let b = symbols.intern(b"b").expect("b symbol exists");
    let c = symbols.intern(b"c").expect("c symbol exists");
    let left_key = symbols.intern(b"left").expect("left symbol exists");
    let right_key = symbols.intern(b"right").expect("right symbol exists");
    let mut eval = TreeWalk::new(&ir);
    let root = eval.eval_root().expect("root attrset evaluates");
    let (left, right) = {
        let attrs = eval
            .heap()
            .get_attrs(root)
            .expect("root is heap-owned attrs");
        (
            attrs.get(left_key).expect("left exists"),
            attrs.get(right_key).expect("right exists"),
        )
    };
    let left = eval
        .force_value(ir.root, span, left)
        .expect("left attrset thunk forces");
    let right = eval
        .force_value(ir.root, span, right)
        .expect("right attrset thunk forces");
    let result =
        rust_callable_aos_update(&mut eval, ir.root, span, left, right).expect("attrsets update");
    let attrs = eval
        .heap()
        .get_attrs(result)
        .expect("update result is heap-owned");

    assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(2));
    assert_eq!(attrs.get(c).expect("c exists").as_int(), Ok(3));
    assert_eq!(attrs.get(a).expect("a remains lazy").tag(), ValueTag::Thunk);
}

#[test]
fn attr_access_rust_callable_reports_missing_and_non_attrs() {
    let source = "{ a = 42; nested.z = 0; }";
    let span = Span::new(0, source.len() as u32);
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let mut symbols = ir.symbols.clone();
    let missing_key = symbols.intern(b"z").expect("symbol exists");
    let mut eval = TreeWalk::new(&ir);
    let attrs = eval.eval_root().expect("attrset evaluates");
    let missing = rust_callable_aos_select_ic(
        &mut eval,
        ir.root,
        span,
        attrs,
        missing_key,
        IrInlineCacheSiteId::new(7),
    )
    .expect_err("missing attr reports an error");

    assert!(matches!(
        missing.kind(),
        TreeWalkErrorKind::MissingAttribute { symbol, .. } if symbol == missing_key
    ));

    let non_attrs = rust_callable_aos_select_ic(
        &mut eval,
        ir.root,
        span,
        Value::int(42),
        missing_key,
        IrInlineCacheSiteId::new(7),
    )
    .expect_err("non-attrs receiver reports a type error");

    assert!(matches!(
        non_attrs.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let non_attrs_presence = rust_callable_aos_has_attr(
        &mut eval,
        ir.root,
        span,
        Value::int(42),
        missing_key,
        IrInlineCacheSiteId::new(7),
    )
    .expect("non-attrs receiver reports absence");

    assert_eq!(non_attrs_presence.as_bool(), Ok(false));
}
