//! Unit tests for the runtime ABI metadata (moved verbatim from `runtime_abi.rs`).

use super::signature_tables::{LAMBDA_CALL_PARAMETERS, THUNK_CALL_PARAMETERS};
use std::collections::BTreeSet;

use crate::builtins::BUILTINS;

use super::*;

#[test]
fn builtin_runtime_symbols_use_frozen_prefix_and_visible_names() {
    assert_eq!(
        BUILTINS
            .lookup(b"derivationStrict")
            .expect("derivationStrict is registered")
            .runtime_symbol()
            .to_symbol_string()
            .expect("builtin name is UTF-8"),
        "nix.builtin.derivationStrict"
    );
    assert_eq!(
        BUILTINS
            .lookup(b"foldl'")
            .expect("foldl' is registered")
            .runtime_symbol()
            .to_symbol_string()
            .expect("builtin name is UTF-8"),
        "nix.builtin.foldl'"
    );

    for builtin in BUILTINS.iter().copied() {
        let symbol = builtin
            .runtime_symbol()
            .to_symbol_string()
            .expect("declared builtin names are UTF-8");
        assert!(symbol.starts_with(BUILTIN_SYMBOL_PREFIX), "{symbol}");
        assert_eq!(
            &symbol.as_bytes()[BUILTIN_SYMBOL_PREFIX.len()..],
            builtin.name()
        );
    }
}

#[test]
fn builtin_runtime_symbol_rejects_non_utf8_suffixes() {
    let error = BuiltinRuntimeSymbol::new(b"\xff")
        .to_symbol_string()
        .expect_err("invalid UTF-8 is rejected");

    assert!(matches!(
        error,
        RuntimeSymbolNameError::NonUtf8BuiltinName { .. }
    ));
}

#[test]
fn runtime_helper_symbols_are_unique_sorted_and_prefixed() {
    let mut previous = None;
    let mut seen = BTreeSet::new();

    for symbol in runtime_helper_symbols() {
        assert!(symbol.name().starts_with(RUNTIME_HELPER_SYMBOL_PREFIX));
        assert!(
            seen.insert(symbol.name()),
            "{} appears twice",
            symbol.name()
        );
        if let Some(previous) = previous {
            assert!(
                previous < symbol.name(),
                "{previous} before {}",
                symbol.name()
            );
        }
        previous = Some(symbol.name());
    }
}

#[test]
fn runtime_helper_symbols_include_single_write_barrier_wall() {
    let write_barriers = runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| symbol.role() == RuntimeHelperRole::WriteBarrier)
        .map(RuntimeHelperSymbol::name)
        .collect::<BTreeSet<_>>();

    assert_eq!(write_barriers, BTreeSet::from(["aos_gc_write_barrier"]));
}

#[test]
fn runtime_call_metadata_pins_value_layout_and_convention() {
    let value_layout = runtime_abi_value_layout();

    // The by-value layout tracks the selected carrier (two-word on the
    // baseline, one-word under the `candidate_c_value` variant).
    #[cfg(not(feature = "candidate_c_value"))]
    {
        assert_eq!(value_layout.size_bytes(), 16);
        assert_eq!(value_layout.register_words(), 2);
    }
    #[cfg(feature = "candidate_c_value")]
    {
        assert_eq!(value_layout.size_bytes(), 8);
        assert_eq!(value_layout.register_words(), 1);
    }
    assert_eq!(value_layout.register_word_bytes(), 8);

    let mut signatures = vec![
        runtime_thunk_call_signature(),
        runtime_lambda_call_signature(),
    ];
    signatures.extend(runtime_primop_call_signatures().iter().copied());

    for signature in signatures {
        assert_eq!(signature.convention(), RuntimeAbiCallingConvention::ExternC);
        assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            signature.parameters()[0],
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext)
        );
        assert_eq!(
            signature.parameters()[1],
            RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer)
        );
    }
}

#[test]
fn thunk_and_lambda_call_signatures_share_runtime_prefix() {
    let thunk = runtime_thunk_call_signature();
    let lambda = runtime_lambda_call_signature();

    assert_eq!(thunk.callable(), RuntimeCallableKind::ThunkBody);
    assert_eq!(thunk.parameters(), THUNK_CALL_PARAMETERS);
    assert_eq!(thunk.parameters().len(), 2);

    assert_eq!(lambda.callable(), RuntimeCallableKind::LambdaBody);
    assert_eq!(lambda.parameters(), LAMBDA_CALL_PARAMETERS);
    assert_eq!(lambda.parameters().len(), 3);
    assert_eq!(
        lambda.parameters()[2],
        RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value)
    );
}

#[test]
fn primop_call_signatures_cover_declared_builtin_arities() {
    let max_declared_arity = BUILTINS
        .iter()
        .filter_map(|builtin| builtin.first_class_arity())
        .max()
        .expect("first-class builtins exist");

    assert_eq!(MAX_RUNTIME_PRIMOP_ABI_ARITY, 3);
    assert!(max_declared_arity <= MAX_RUNTIME_PRIMOP_ABI_ARITY);
    assert_eq!(
        runtime_primop_call_signatures().len(),
        MAX_RUNTIME_PRIMOP_ABI_ARITY + 1
    );

    for arity in 0..=MAX_RUNTIME_PRIMOP_ABI_ARITY {
        let signature = runtime_primop_call_signature(arity).expect("arity is covered");
        assert_eq!(signature.callable(), RuntimeCallableKind::Primop { arity });
        assert_eq!(signature.parameters().len(), arity + 2);
        for (index, parameter) in signature.parameters().iter().copied().enumerate() {
            match index {
                0 => assert_eq!(
                    parameter,
                    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext)
                ),
                1 => assert_eq!(
                    parameter,
                    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer)
                ),
                argument_index => {
                    let expected_name = format!("a{}", argument_index - 2);
                    assert_eq!(
                        parameter.name(),
                        expected_name.as_str(),
                        "primop argument names stay positional"
                    );
                    assert_eq!(parameter.kind(), RuntimeAbiParameterKind::Value);
                }
            }
        }
    }
}

#[test]
fn primop_call_signature_rejects_unfrozen_arities() {
    let error = runtime_primop_call_signature(MAX_RUNTIME_PRIMOP_ABI_ARITY + 1)
        .expect_err("unsupported arity rejects");

    assert_eq!(
        error,
        RuntimeCallAbiError::UnsupportedPrimopArity {
            arity: MAX_RUNTIME_PRIMOP_ABI_ARITY + 1,
            max: MAX_RUNTIME_PRIMOP_ABI_ARITY,
        }
    );
}

#[test]
fn allocation_helper_call_signatures_pin_scalars_and_pointer_results() {
    let attrs = runtime_helper_call_signature("aos_alloc_attrs")
        .expect("attrs allocation signature is core-owned");
    let thunk = runtime_helper_call_signature("aos_alloc_thunk")
        .expect("thunk allocation signature is core-owned");
    let raw = runtime_helper_call_signature("aos_alloc_raw")
        .expect("raw allocation signature is core-owned");

    assert_eq!(
        attrs.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_alloc_attrs", RuntimeHelperRole::Allocation),
        }
    );
    assert_eq!(
        attrs.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("shape", RuntimeAbiParameterKind::ShapeId),
            RuntimeAbiParameter::new("slots", RuntimeAbiParameterKind::U32),
        ]
    );
    assert_eq!(attrs.return_kind(), RuntimeAbiReturnKind::AttrsPointer);

    assert_eq!(
        thunk.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("code_ptr", RuntimeAbiParameterKind::CodePointer),
            RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
        ]
    );
    assert_eq!(thunk.return_kind(), RuntimeAbiReturnKind::ThunkPointer);

    assert_eq!(
        raw.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("size", RuntimeAbiParameterKind::Usize),
            RuntimeAbiParameter::new("align", RuntimeAbiParameterKind::Usize),
            RuntimeAbiParameter::new("type_tag", RuntimeAbiParameterKind::TypeTag),
        ]
    );
    assert_eq!(raw.return_kind(), RuntimeAbiReturnKind::RawPointer);
}

#[test]
fn call_control_helper_call_signature_pins_apply_value_boundary() {
    let apply = runtime_helper_call_signature("aos_apply").expect("apply signature is core-owned");

    assert_eq!(
        apply.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_apply", RuntimeHelperRole::CallControl),
        }
    );
    assert_eq!(
        apply.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("function", RuntimeAbiParameterKind::Value),
            RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value),
        ]
    );
    assert_eq!(apply.return_kind(), RuntimeAbiReturnKind::Value);
}

#[test]
fn deoptimization_helper_call_signature_pins_record_pointer_boundary() {
    let deopt = runtime_helper_call_signature("aos_deopt").expect("deopt signature is core-owned");

    assert_eq!(
        deopt.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_deopt", RuntimeHelperRole::Deoptimization),
        }
    );
    assert_eq!(
        deopt.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("deopt_record", RuntimeAbiParameterKind::DeoptRecordPointer,),
        ]
    );
    assert_eq!(deopt.return_kind(), RuntimeAbiReturnKind::Value);
}

#[test]
fn error_helper_call_signature_pins_throw_divergence() {
    let throw = runtime_helper_call_signature("aos_throw").expect("throw signature is core-owned");

    assert_eq!(
        throw.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_throw", RuntimeHelperRole::ErrorControl),
        }
    );
    assert_eq!(
        throw.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("err", RuntimeAbiParameterKind::ErrorPointer),
        ]
    );
    assert_eq!(throw.return_kind(), RuntimeAbiReturnKind::Diverges);
}

#[test]
fn forcing_helper_call_signatures_pin_whnf_value_boundary() {
    let force = runtime_helper_call_signature("aos_force").expect("force signature is core-owned");
    let force_deep = runtime_helper_call_signature("aos_force_deep")
        .expect("deep-force signature is core-owned");
    let blackhole_check = runtime_helper_call_signature("aos_blackhole_check")
        .expect("blackhole-check signature is core-owned");

    for (symbol_name, signature) in [("aos_force", force), ("aos_force_deep", force_deep)] {
        assert_eq!(
            signature.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new(symbol_name, RuntimeHelperRole::ForcingControl,),
            }
        );
        assert_eq!(
            signature.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
            ]
        );
        assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
    }

    assert_eq!(
        blackhole_check.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new(
                "aos_blackhole_check",
                RuntimeHelperRole::ForcingControl,
            ),
        }
    );
    assert_eq!(
        blackhole_check.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
        ]
    );
    assert_eq!(blackhole_check.return_kind(), RuntimeAbiReturnKind::Unit);
}

#[test]
fn attrset_helper_call_signatures_pin_static_key_value_boundaries() {
    let has_attr =
        runtime_helper_call_signature("aos_has_attr").expect("has-attr signature is core-owned");
    let select_ic =
        runtime_helper_call_signature("aos_select_ic").expect("select-IC signature is core-owned");

    for (symbol_name, signature) in [("aos_has_attr", has_attr), ("aos_select_ic", select_ic)] {
        assert_eq!(
            signature.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new(symbol_name, RuntimeHelperRole::AttrsetAccess,),
            }
        );
        assert_eq!(
            signature.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("attrs", RuntimeAbiParameterKind::Value),
                RuntimeAbiParameter::new("symbol", RuntimeAbiParameterKind::SymbolId),
                RuntimeAbiParameter::new("site", RuntimeAbiParameterKind::InlineCacheSiteId),
            ]
        );
        assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
    }

    let update =
        runtime_helper_call_signature("aos_update").expect("update signature is core-owned");
    assert_eq!(
        update.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_update", RuntimeHelperRole::AttrsetAccess,),
        }
    );
    assert_eq!(
        update.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("left", RuntimeAbiParameterKind::Value),
            RuntimeAbiParameter::new("right", RuntimeAbiParameterKind::Value),
        ]
    );
    assert_eq!(update.return_kind(), RuntimeAbiReturnKind::Value);
}

#[test]
fn write_barrier_helper_call_signature_pins_unit_return() {
    let signature = runtime_helper_call_signature("aos_gc_write_barrier")
        .expect("write-barrier signature is core-owned");

    assert_eq!(
        signature.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new(
                "aos_gc_write_barrier",
                RuntimeHelperRole::WriteBarrier,
            ),
        }
    );
    assert_eq!(
        signature.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("thunk", RuntimeAbiParameterKind::ThunkPointer),
            RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
        ]
    );
    assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Unit);
}

#[test]
fn env_get_helper_call_signature_pins_slot_lookup_value_return() {
    let signature =
        runtime_helper_call_signature("aos_env_get").expect("env-get signature is core-owned");

    assert_eq!(
        signature.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_env_get", RuntimeHelperRole::EnvironmentAccess,),
        }
    );
    assert_eq!(
        signature.parameters(),
        &[
            RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
            RuntimeAbiParameter::new("slot", RuntimeAbiParameterKind::U32),
        ]
    );
    assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
}

#[test]
fn upval_get_helper_call_signature_pins_depth_slot_lookup_value_return() {
    let signature =
        runtime_helper_call_signature("aos_upval_get").expect("upval-get signature is core-owned");

    assert_eq!(
        signature.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_upval_get", RuntimeHelperRole::EnvironmentAccess,),
        }
    );
    assert_eq!(
        signature.parameters(),
        &[
            RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
            RuntimeAbiParameter::new("depth", RuntimeAbiParameterKind::U32),
            RuntimeAbiParameter::new("slot", RuntimeAbiParameterKind::U32),
        ]
    );
    assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
}

#[test]
fn primop_call_helper_call_signature_pins_rt_env_module_node_value_return() {
    let signature = runtime_helper_call_signature("aos_primop_call")
        .expect("primop-call signature is core-owned");

    assert_eq!(
        signature.callable(),
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new("aos_primop_call", RuntimeHelperRole::PrimopDispatch,),
        }
    );
    assert_eq!(
        signature.parameters(),
        &[
            RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
            RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
            RuntimeAbiParameter::new("module_id", RuntimeAbiParameterKind::U32),
            RuntimeAbiParameter::new("node_id", RuntimeAbiParameterKind::U32),
        ]
    );
    assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
}

#[test]
fn builtin_call_manifest_preserves_runtime_builtin_symbol_order() {
    let runtime_builtin_symbols = runtime_symbol_manifest()
        .expect("runtime manifest builds")
        .into_iter()
        .filter(|entry| entry.kind() == RuntimeSymbolKind::Builtin)
        .map(|entry| entry.name().to_owned())
        .collect::<Vec<_>>();
    let call_manifest = runtime_builtin_call_manifest().expect("builtin call manifest builds");

    assert_eq!(
        call_manifest
            .iter()
            .map(RuntimeBuiltinCallManifestEntry::symbol_name)
            .collect::<Vec<_>>(),
        runtime_builtin_symbols
    );
}

#[test]
fn builtin_call_manifest_marks_callable_and_value_only_builtins() {
    let manifest = runtime_builtin_call_manifest().expect("builtin call manifest builds");

    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "nix.builtin.derivationStrict")
            .map(RuntimeBuiltinCallManifestEntry::status),
        Some(RuntimeBuiltinCallStatus::Callable {
            arity: 1,
            signature: runtime_primop_call_signature(1).expect("arity 1 is frozen"),
        })
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.symbol_name() == "nix.builtin.foldl'")
            .map(RuntimeBuiltinCallManifestEntry::status),
        Some(RuntimeBuiltinCallStatus::Callable {
            arity: 3,
            signature: runtime_primop_call_signature(3).expect("arity 3 is frozen"),
        })
    );
    for symbol_name in [
        "nix.builtin.builtins",
        "nix.builtin.false",
        "nix.builtin.null",
        "nix.builtin.true",
    ] {
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.symbol_name() == symbol_name)
                .map(RuntimeBuiltinCallManifestEntry::status),
            Some(RuntimeBuiltinCallStatus::ValueOnly),
            "{symbol_name} stays a value-only builtin symbol"
        );
    }
}

#[test]
fn builtin_call_preflight_reports_current_value_only_gaps() {
    let preflight = runtime_builtin_call_preflight().expect("builtin call preflight builds");
    let callable_count = BUILTINS
        .iter()
        .filter(|builtin| builtin.first_class_arity().is_some())
        .count();
    let value_only_count = BUILTINS
        .iter()
        .filter(|builtin| builtin.first_class_arity().is_none())
        .count();

    assert!(!preflight.is_complete());
    assert_eq!(preflight.call_bindings().len(), callable_count);
    assert_eq!(preflight.missing_bindings().len(), value_only_count);
    assert!(
        preflight
            .missing_bindings()
            .iter()
            .all(|missing| missing.unsupported_arity().is_none())
    );
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "nix.builtin.true" && missing.builtin_name() == b"true"
    }));

    for binding in preflight.call_bindings() {
        let builtin = BUILTINS
            .lookup(binding.builtin_name())
            .expect("call binding names a declared builtin");
        let expected_symbol = builtin
            .runtime_symbol()
            .to_symbol_string()
            .expect("builtin symbol is UTF-8");
        assert_eq!(binding.symbol_name(), expected_symbol);
        assert_eq!(Some(binding.arity()), builtin.first_class_arity());
        assert_eq!(
            binding.signature(),
            runtime_primop_call_signature(binding.arity()).expect("binding arity is frozen")
        );
    }
}

#[test]
fn builtin_call_status_reports_future_unsupported_arities() {
    assert_eq!(
        RuntimeBuiltinCallStatus::from_first_class_arity(Some(MAX_RUNTIME_PRIMOP_ABI_ARITY + 1)),
        RuntimeBuiltinCallStatus::UnsupportedArity {
            arity: MAX_RUNTIME_PRIMOP_ABI_ARITY + 1,
            max: MAX_RUNTIME_PRIMOP_ABI_ARITY,
        }
    );
}

#[test]
fn runtime_symbol_manifest_combines_helpers_and_builtins() {
    let manifest = runtime_symbol_manifest().expect("manifest builds");

    assert_eq!(
        manifest.len(),
        runtime_helper_symbols().len() + BUILTINS.len()
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.name() == "aos_gc_write_barrier")
            .map(RuntimeSymbolManifestEntry::kind),
        Some(RuntimeSymbolKind::Helper(RuntimeHelperRole::WriteBarrier))
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.name() == "nix.builtin.derivationStrict")
            .map(RuntimeSymbolManifestEntry::kind),
        Some(RuntimeSymbolKind::Builtin)
    );
    assert_eq!(
        manifest
            .iter()
            .find(|entry| entry.name() == "nix.builtin.foldl'")
            .map(RuntimeSymbolManifestEntry::kind),
        Some(RuntimeSymbolKind::Builtin)
    );

    for helper in runtime_helper_symbols().iter().copied() {
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == helper.name())
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Helper(helper.role())),
            "{} helper appears in the manifest",
            helper.name()
        );
    }

    for builtin in BUILTINS.iter().copied() {
        let symbol = builtin
            .runtime_symbol()
            .to_symbol_string()
            .expect("builtin symbol is UTF-8");
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == symbol)
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Builtin),
            "{symbol} builtin appears in the manifest"
        );
    }
}

#[test]
fn runtime_symbol_manifest_is_sorted_and_unique() {
    let manifest = runtime_symbol_manifest().expect("manifest builds");
    let mut previous = None;
    let mut seen = BTreeSet::new();

    for entry in &manifest {
        assert!(
            seen.insert(entry.name().to_owned()),
            "{} appears twice",
            entry.name()
        );
        if let Some(previous) = previous {
            assert!(
                previous < entry.name(),
                "{previous} before {}",
                entry.name()
            );
        }
        previous = Some(entry.name());
    }
}

#[test]
fn runtime_symbol_manifest_rejects_duplicates_before_registration() {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let duplicate = RuntimeSymbolManifestEntry::new(
        "aos_duplicate".to_owned(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
    );

    push_manifest_entry(&mut entries, &mut seen, duplicate.clone()).expect("first symbol records");
    let error = push_manifest_entry(&mut entries, &mut seen, duplicate)
        .expect_err("duplicate symbol rejects");

    assert!(matches!(
        error,
        RuntimeSymbolNameError::DuplicateRuntimeSymbol { .. }
    ));
    assert_eq!(entries.len(), 1);
}
