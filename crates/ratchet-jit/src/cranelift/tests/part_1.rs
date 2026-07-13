//! Cranelift finalize/execute tests (moved verbatim from `cranelift.rs`).

use super::*;

#[test]
fn registered_artifact_finalization_allows_constant_artifacts_with_registration_gaps() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::int(8)).expect("constant artifact lowers");

    let preflight =
        jit_cranelift_registered_artifact_finalization_preflight_with_candidates(artifact, &[])
            .expect("constant artifact does not need runtime imports");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.constant_smoke.thunk_body"
    );
    assert_ne!(
        preflight.finalized_function().code_ptr().as_ptr() as usize,
        0
    );
    assert!(preflight.artifact_runtime_imports().is_empty());
    assert!(preflight.registered_symbols().is_empty());
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(matches!(
        preflight.registration_gap_for_symbol("aos_env_get"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                ..
            }
        )
    ));
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_artifact_finalization_requires_candidates_for_artifact_imports() {
    let Err(error) = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        env_get_artifact(4),
        &[],
    ) else {
        panic!("env-get artifact finalization requires registered env helper candidate");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
        symbol_names,
    } = error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn registered_artifact_finalization_finalizes_forced_env_get_artifact_with_candidates() {
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            5,
        ),
    ]);

    let preflight = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        forced_env_get_artifact(4),
        &candidates,
    )
    .expect("forced env-get artifact finalization accepts registered helpers");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_ne!(
        preflight.finalized_function().code_ptr().as_ptr() as usize,
        0
    );
    assert_eq!(
        preflight
            .finalized_function()
            .compiled_code_ptr()
            .as_non_null(),
        preflight.finalized_function().code_ptr()
    );
    let stack_maps = preflight
        .finalized_function()
        .defined_function()
        .user_stack_maps();
    assert_eq!(stack_maps.len(), 1);
    assert!(stack_maps[0].identity_sp_offset().is_some());
    assert_eq!(stack_maps[0].entries().len(), 1);
    assert_eq!(
        stack_maps[0].entries()[0].value_type(),
        cranelift_codegen::ir::types::I64
    );
    let artifact_import_names = preflight
        .artifact_runtime_imports()
        .iter()
        .map(JitModuleArtifactRuntimeImport::symbol_name)
        .collect::<Vec<_>>();
    assert_eq!(
        artifact_import_names,
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit"]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert_eq!(
        preflight
            .registered_symbol_for("aos_env_get")
            .expect("env helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        3
    );
    assert_eq!(
        preflight
            .registered_symbol_for("aos_force")
            .expect("force helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        5
    );
    assert!(
        preflight
            .registration_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(preflight.registration_gap_for_symbol("aos_force").is_none());
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_artifact_finalization_finalizes_update_artifact_with_candidates() {
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            5,
        ),
        synthetic_address_candidate(
            "aos_update",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            7,
        ),
    ]);

    let preflight = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        update_artifact(4, 6),
        &candidates,
    )
    .expect("update artifact finalization accepts registered helpers");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.2.thunk_body"
    );
    assert_ne!(
        preflight.finalized_function().code_ptr().as_ptr() as usize,
        0
    );
    assert_eq!(
        preflight
            .finalized_function()
            .compiled_code_ptr()
            .as_non_null(),
        preflight.finalized_function().code_ptr()
    );
    assert_eq!(
        artifact_runtime_import_names(preflight.artifact_runtime_imports()),
        ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_update"]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_update").is_some());
    assert!(preflight.registered_symbol_for("aos_env_get").is_some());
    assert!(preflight.registered_symbol_for("aos_force").is_some());
    assert!(preflight.registered_symbol_for("aos_update").is_some());
    assert!(
        preflight
            .registration_gap_for_symbol("aos_update")
            .is_none()
    );
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_artifact_finalization_preserves_unresolved_artifact_import_readiness() {
    let Err(error) = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        artifact_with_unknown_runtime_helper_import(),
        &[],
    ) else {
        panic!("unresolved artifact import must stay a readiness error");
    };

    let JitCraneliftModuleSetupError::Readiness(
        JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
    ) = error
    else {
        panic!("expected unresolved artifact-import readiness error");
    };

    assert!(preflight.artifact_runtime_imports().is_empty());
    assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
    assert!(!preflight.is_complete());
}

#[test]
fn registered_artifact_finalization_rejects_wrong_kind_candidates_for_artifact_imports() {
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Builtin,
        3,
    )];

    let Err(error) = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        env_get_artifact(4),
        &candidates,
    ) else {
        panic!("wrong-kind env helper candidate must not satisfy artifact imports");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
        symbol_names,
    } = error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn module_declaration_preflight_builds_jit_module_imports() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::int(99)).expect("constant artifact lowers");
    let readiness = jit_module_readiness_preflight_for_artifact(&artifact)
        .expect("module readiness preflight builds");
    let preflight = jit_cranelift_module_declaration_preflight_for_artifact(&artifact)
        .expect("JIT module declaration preflight builds");

    assert_eq!(
        preflight.artifact().function_name(),
        &UserFuncName::default()
    );
    assert_eq!(
        preflight.imported_symbols().len(),
        readiness.symbol_declarations().len()
    );
    for declaration in readiness.symbol_declarations() {
        assert!(
            preflight
                .imported_symbol_for(declaration.symbol_name())
                .is_some(),
            "{} is declared as a JIT module import",
            declaration.symbol_name()
        );
    }
    assert!(
        preflight
            .imported_symbols()
            .iter()
            .all(|symbol| symbol.linkage() == Linkage::Import)
    );
    assert!(
        preflight
            .imported_symbol_for("nix.builtin.derivationStrict")
            .is_some()
    );
    assert!(preflight.imported_symbol_for("aos_apply").is_some());
    assert!(preflight.imported_symbol_for("aos_deopt").is_some());
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(
        preflight
            .imported_symbol_for("aos_blackhole_check")
            .is_some()
    );
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_has_attr").is_some());
    assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
    assert!(preflight.imported_symbol_for("aos_update").is_some());
    assert!(preflight.imported_symbol_for("aos_throw").is_some());
    assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn artifact_definition_preflight_defines_constant_artifact_in_encapsulated_module() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::int(7)).expect("constant artifact lowers");
    let preflight = jit_cranelift_artifact_definition_preflight_for_artifact(artifact)
        .expect("artifact definition preflight builds");

    assert_eq!(
        preflight.defined_function().symbol_name(),
        "aos.jit.constant_smoke.thunk_body"
    );
    assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
    assert!(
        preflight
            .imported_symbol_for("nix.builtin.derivationStrict")
            .is_some()
    );
    assert!(preflight.imported_symbol_for("aos_apply").is_some());
    assert!(preflight.imported_symbol_for("aos_deopt").is_some());
    assert!(
        preflight
            .imported_symbol_for("aos_blackhole_check")
            .is_some()
    );
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_has_attr").is_some());
    assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
    assert!(preflight.imported_symbol_for("aos_update").is_some());
    assert!(preflight.imported_symbol_for("aos_throw").is_some());
    assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn artifact_definition_preflight_uses_deterministic_ir_root_symbol() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(false),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(5, 6),
                EffectClass::pure(),
                IrData::Int(5),
            ),
        ],
        Vec::new(),
    );
    let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(1))
        .expect("IR root artifact lowers");
    let preflight = jit_cranelift_artifact_definition_preflight_for_artifact(artifact)
        .expect("artifact definition preflight builds");

    assert_eq!(
        preflight.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(
        preflight.defined_function().symbol_name(),
        "aos.jit.ir_root.1.thunk_body"
    );
    assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn artifact_definition_preflight_refuses_artifact_runtime_imports() {
    let Err(error) =
        jit_cranelift_artifact_definition_preflight_for_artifact(env_get_artifact(4))
    else {
        panic!("call-bearing artifact must wait for registered runtime symbols");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
        symbol_names,
    } = error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn artifact_definition_preflight_preserves_unresolved_artifact_import_readiness() {
    let Err(error) = jit_cranelift_artifact_definition_preflight_for_artifact(
        artifact_with_unknown_runtime_helper_import(),
    ) else {
        panic!("unresolved artifact import must stay a readiness error");
    };

    let JitCraneliftModuleSetupError::Readiness(
        JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
    ) = error
    else {
        panic!("expected unresolved artifact-import readiness error");
    };

    assert!(preflight.artifact_runtime_imports().is_empty());
    assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
    assert!(!preflight.is_complete());
}

#[test]
fn artifact_finalization_preflight_finalizes_constant_artifact_code_pointer() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::int(11)).expect("constant artifact lowers");
    let preflight = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)
        .expect("artifact finalization preflight builds");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.constant_smoke.thunk_body"
    );
    assert_eq!(
        preflight.finalized_function().defined_function().linkage(),
        Linkage::Export
    );
    assert_ne!(
        preflight.finalized_function().code_ptr().as_ptr() as usize,
        0
    );
    assert_eq!(
        preflight
            .finalized_function()
            .compiled_code_ptr()
            .as_non_null(),
        preflight.finalized_function().code_ptr()
    );
    assert!(
        preflight
            .imported_symbol_for("nix.builtin.derivationStrict")
            .is_some()
    );
    assert!(preflight.imported_symbol_for("aos_apply").is_some());
    assert!(preflight.imported_symbol_for("aos_deopt").is_some());
    assert!(
        preflight
            .imported_symbol_for("aos_blackhole_check")
            .is_some()
    );
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_has_attr").is_some());
    assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
    assert!(preflight.imported_symbol_for("aos_update").is_some());
    assert!(preflight.imported_symbol_for("aos_throw").is_some());
    assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn artifact_finalization_preflight_uses_deterministic_ir_root_symbol() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Null,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("IR root artifact lowers");
    let preflight = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)
        .expect("artifact finalization preflight builds");

    assert_eq!(
        preflight.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(0))
    );
    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_ne!(
        preflight.finalized_function().code_ptr().as_ptr() as usize,
        0
    );
    assert_eq!(
        preflight
            .finalized_function()
            .compiled_code_ptr()
            .as_non_null(),
        preflight.finalized_function().code_ptr()
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn artifact_finalization_preflight_refuses_artifact_runtime_imports() {
    let Err(error) =
        jit_cranelift_artifact_finalization_preflight_for_artifact(env_get_artifact(8))
    else {
        panic!("call-bearing artifact must wait for registered runtime symbols");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
        symbol_names,
    } = error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn native_thunk_call_executes_constant_smoke_artifact() {
    let expected = Value::int(23);
    let artifact =
        lower_constant_thunk_body_artifact(expected).expect("constant artifact lowers");
    let invocation = jit_cranelift_native_thunk_call_for_artifact(artifact)
        .expect("constant artifact can be called through native thunk ABI");

    assert!(invocation.value().raw_eq(expected));
    assert_eq!(
        invocation.finalized_function().symbol_name(),
        "aos.jit.constant_smoke.thunk_body"
    );
    assert_eq!(
        invocation
            .finalized_function()
            .compiled_code_ptr()
            .as_non_null(),
        invocation.finalized_function().code_ptr()
    );
    assert!(invocation.owns_encapsulated_module());
    assert!(!invocation.finalization().is_complete());
}

#[test]
fn module_context_finalizes_multiple_bodies_into_one_module() {
    // A shared context needs no registered candidates for constant bodies,
    // which import no runtime helpers.
    let context = JitModuleContext::with_candidates(&[]).expect("shared module builds");

    let first = context
        .define_and_finalize(
            lower_constant_thunk_body_artifact(Value::int(11)).expect("first constant lowers"),
        )
        .expect("first body finalizes into the shared module");
    let second = context
        .define_and_finalize(
            lower_constant_thunk_body_artifact(Value::int(22)).expect("second constant lowers"),
        )
        .expect("second body finalizes into the shared module");

    assert_eq!(first.artifact().kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(second.artifact().kind(), JitClifArtifactKind::ThunkBody);
    // Two bodies finalized into one module land at distinct code pointers, and
    // the earlier pointer stays valid across the later define-then-finalize.
    assert_ne!(
        first.finalized_function().code_ptr(),
        second.finalized_function().code_ptr(),
    );
    // The monotonic define counter disambiguates the export symbols even though
    // both derive from the same constant-smoke base name.
    assert_ne!(
        first.finalized_function().symbol_name(),
        second.finalized_function().symbol_name(),
    );
    assert!(
        first
            .finalized_function()
            .symbol_name()
            .starts_with("aos.jit.constant_smoke.thunk_body."),
    );
    assert!(
        second
            .finalized_function()
            .symbol_name()
            .starts_with("aos.jit.constant_smoke.thunk_body."),
    );

    // A keep-alive handle pins the module's code memory after the context drops.
    let _keep_alive = context.keep_alive();
    drop(context);
}

#[test]
fn native_thunk_call_executes_literal_ir_artifact() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );
    let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("literal IR artifact lowers");
    let invocation = jit_cranelift_native_thunk_call_for_artifact(artifact)
        .expect("literal IR artifact can be called through native thunk ABI");

    assert!(invocation.value().raw_eq(Value::bool(true)));
    assert_eq!(
        invocation.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert!(invocation.owns_encapsulated_module());
}

#[test]
fn native_thunk_call_rejects_artifact_runtime_imports() {
    let Err(error) = jit_cranelift_native_thunk_call_for_artifact(env_get_artifact(8)) else {
        panic!("call-bearing artifact must wait for registered runtime symbols");
    };

    let JitCraneliftNativeCallError::FinalizeArtifact {
        source:
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names },
    } = error
    else {
        panic!("expected native call to preserve runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn tier1_slot_preflight_refuses_artifact_runtime_imports() {
    let Err(error) = jit_cranelift_tier1_slot_preflight_for_artifact(env_get_artifact(12))
    else {
        panic!("call-bearing artifact must wait for registered runtime symbols");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
        symbol_names,
    } = error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn tier1_slot_preflight_installs_constant_artifact_metadata() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::int(17)).expect("constant artifact lowers");
    let preflight = jit_cranelift_tier1_slot_preflight_for_artifact(artifact)
        .expect("tier-1 slot preflight builds");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.constant_smoke.thunk_body"
    );
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().is_tier1_installed());
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(preflight.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        preflight
            .slot()
            .tier1_code_ptr()
            .map(JitCompiledCodePointer::as_non_null),
        Some(preflight.finalized_function().code_ptr())
    );
    assert!(!preflight.finalization().is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn tier1_slot_preflight_keeps_ir_root_module_owner_with_slot() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );
    let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("IR root artifact lowers");
    let preflight = jit_cranelift_tier1_slot_preflight_for_artifact(artifact)
        .expect("tier-1 slot preflight builds");

    assert_eq!(
        preflight.artifact().function_name(),
        &clif_name_for_ir_root(IrId::new(0))
    );
    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(preflight.finalized_function().compiled_code_ptr())
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_tier1_slot_preflight_installs_env_get_artifact_with_candidate() {
    let env_get_address = synthetic_runtime_import_address();
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
        env_get_address,
    )];

    let preflight = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
        env_get_artifact(7),
        &candidates,
    )
    .expect("registered tier-1 env-get slot preflight builds");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().is_tier1_installed());
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(preflight.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        preflight
            .slot()
            .tier1_code_ptr()
            .map(JitCompiledCodePointer::as_non_null),
        Some(preflight.finalized_function().code_ptr())
    );
    assert_eq!(preflight.finalization().artifact_runtime_imports().len(), 1);
    assert!(
        preflight
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert_eq!(
        preflight
            .finalization()
            .registered_symbol_for("aos_env_get")
            .expect("env helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        env_get_address
    );
    assert!(
        preflight
            .finalization()
            .registration_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(!preflight.finalization().is_complete());
    assert!(preflight.owns_encapsulated_module());
}
