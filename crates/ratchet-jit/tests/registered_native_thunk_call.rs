use std::{num::NonZeroUsize, ptr};

use ratchet_core::{
    EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    syntax::Span,
};
use ratchet_jit::{
    JitCraneliftModuleSetupError, JitCraneliftNativeCallError, JitEnvFramePtr,
    JitRuntimeContextPtr, JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate, JitTier,
    JitTieredCodeSlot, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates,
    jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates,
    lower_apply_local_slots_ir_thunk_body_artifact, lower_env_get_ir_thunk_body_artifact,
    lower_forced_env_get_ir_thunk_body_artifact,
};
use ratchet_value::value::Value;

extern "C" fn test_aos_env_get(_env: JitEnvFramePtr, slot: u32) -> Value {
    Value::int(i64::from(slot) + 10)
}

extern "C" fn test_aos_force(_rt: JitRuntimeContextPtr, value: Value) -> Value {
    if value.raw_eq(Value::int(19)) {
        Value::int(38)
    } else {
        value
    }
}

extern "C" fn test_aos_apply(_rt: JitRuntimeContextPtr, function: Value, argument: Value) -> Value {
    let Ok(function) = function.as_int() else {
        return Value::null();
    };
    let Ok(argument) = argument.as_int() else {
        return Value::null();
    };

    Value::int((function * 100) + argument)
}

fn local_var_arena(slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot },
        )],
        Vec::new(),
    )
}

fn apply_arena(function_slot: u32, argument_slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local {
                    slot: function_slot,
                },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local {
                    slot: argument_slot,
                },
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    )
}

fn native_address(raw: usize) -> JitRuntimeSymbolAddress {
    JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).expect("test address is non-zero"))
}

fn candidate(
    symbol_name: &str,
    role: RuntimeHelperRole,
    raw: usize,
) -> JitRuntimeSymbolAddressCandidate {
    JitRuntimeSymbolAddressCandidate::new(
        symbol_name.to_owned(),
        RuntimeSymbolKind::Helper(role),
        native_address(raw),
    )
}

fn env_get_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_env_get",
        RuntimeHelperRole::EnvironmentAccess,
        test_aos_env_get as *const () as usize,
    )
}

fn force_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_force",
        RuntimeHelperRole::ForcingControl,
        test_aos_force as *const () as usize,
    )
}

fn apply_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_apply",
        RuntimeHelperRole::CallControl,
        test_aos_apply as *const () as usize,
    )
}

#[test]
fn registered_native_thunk_call_executes_env_get_artifact_with_candidate() {
    let arena = local_var_arena(9);
    let artifact = lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("env-get artifact lowers");
    let candidates = [env_get_candidate()];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The only artifact import is `aos_env_get`, and the candidate is a live
    // `extern "C"` test function with the frozen `(env, slot) -> Value` ABI.
    // The test helper ignores the null environment pointer and returns a
    // valid-tag Value.
    let invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("registered env-get artifact can be called through native thunk ABI");

    assert!(invocation.value().raw_eq(Value::int(19)));
    assert!(invocation.owns_encapsulated_module());
    assert_eq!(
        invocation.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(
        invocation.finalization().artifact_runtime_imports().len(),
        1
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address() == candidates[0].address())
    );
}

#[test]
fn registered_native_thunk_call_executes_forced_env_get_artifact_with_candidates() {
    let arena = local_var_arena(9);
    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("forced env-get artifact lowers");
    let candidates = [env_get_candidate(), force_candidate()];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The artifact imports `aos_env_get` and `aos_force`, and both candidates
    // are live `extern "C"` test functions with the frozen helper ABIs. The
    // test helpers ignore the null runtime and environment pointers and return
    // valid-tag Values.
    let invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("registered forced env-get artifact can be called through native thunk ABI");

    assert!(invocation.value().raw_eq(Value::int(38)));
    assert!(invocation.owns_encapsulated_module());
    let import_names = invocation
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(import_names, ["aos_env_get", "aos_force"]);
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_force")
            .is_some()
    );
}

#[test]
fn registered_native_thunk_call_executes_apply_artifact_with_candidates() {
    let arena = apply_arena(4, 6);
    let artifact = lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("apply artifact lowers");
    let candidates = [env_get_candidate(), apply_candidate()];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The artifact imports `aos_env_get` and `aos_apply`, and both candidates
    // are live `extern "C"` test functions with the frozen helper ABIs. The
    // helpers tolerate the null runtime/environment pointers and return
    // valid-tag Values.
    let invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("registered apply artifact can be called through native thunk ABI");

    assert!(invocation.value().raw_eq(Value::int(1416)));
    assert!(invocation.owns_encapsulated_module());
    let import_names = invocation
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(import_names, ["aos_env_get", "aos_apply"]);
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address() == candidates[0].address())
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address() == candidates[1].address())
    );
}

#[test]
fn registered_native_thunk_call_requires_candidates_for_artifact_imports() {
    let arena = local_var_arena(9);
    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("forced env-get artifact lowers");
    let candidates = [env_get_candidate()];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The candidate that is supplied is host-ABI-matched, but the call should
    // fail during registered finalization because the artifact also imports
    // `aos_force`.
    let Err(error) = (unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }) else {
        panic!("missing force candidate must reject before native invocation");
    };

    let JitCraneliftNativeCallError::FinalizeArtifact {
        source:
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names },
    } = error
    else {
        panic!("expected missing artifact-import candidate error, got {error}");
    };
    assert_eq!(symbol_names, ["aos_force".to_owned()]);
}

#[test]
fn registered_native_thunk_call_requires_apply_candidate_for_apply_artifacts() {
    let arena = apply_arena(4, 6);
    let artifact = lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("apply artifact lowers");
    let candidates = [env_get_candidate()];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The supplied `aos_env_get` candidate is host-ABI-matched, but the call
    // should fail during registered finalization because the artifact also
    // imports `aos_apply`.
    let Err(error) = (unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }) else {
        panic!("missing apply candidate must reject before native invocation");
    };

    let JitCraneliftNativeCallError::FinalizeArtifact {
        source:
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names },
    } = error
    else {
        panic!("expected missing artifact-import candidate error, got {error}");
    };
    assert_eq!(symbol_names, ["aos_apply".to_owned()]);
}

#[test]
fn promotion_gated_registered_native_thunk_call_keeps_cold_slot_without_candidates() {
    let arena = local_var_arena(9);

    // SAFETY: Policy stays in tier 0, so this call must not lower, finalize,
    // register candidates, or enter native code.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &[],
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("cold promotion-gated native call preflight stays cold");

    assert!(!preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier0Oracle);
    assert_eq!(preflight.slot().invocation_counter().invocations(), 1);
    assert!(preflight.native_invocation().is_none());
    assert!(preflight.native_value().is_none());
    assert!(!preflight.owns_encapsulated_module());
}

#[test]
fn promotion_gated_registered_native_thunk_call_executes_forced_env_get_on_promotion() {
    let arena = local_var_arena(9);
    let candidates = [env_get_candidate(), force_candidate()];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The promoted artifact imports `aos_env_get` and `aos_force`, whose
    // candidates are live `extern "C"` test functions with the frozen helper
    // ABIs. The helpers tolerate the null runtime/environment pointers used by
    // this synthetic test and return valid-tag Values.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(0),
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("promotion-gated forced env-get native call succeeds");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert_eq!(preflight.slot().invocation_counter().invocations(), 1);
    assert!(
        preflight
            .native_value()
            .is_some_and(|value| value.raw_eq(Value::int(38)))
    );
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(invocation.finalized_function().compiled_code_ptr())
    );
    assert!(
        invocation
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .imported_symbol_for("aos_force")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_force")
            .is_some()
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn promotion_gated_registered_native_thunk_call_executes_apply_on_promotion() {
    let arena = apply_arena(4, 6);
    let candidates = [env_get_candidate(), apply_candidate()];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The promoted apply artifact imports `aos_env_get` and `aos_apply`, whose
    // candidates are live `extern "C"` test functions with the frozen helper
    // ABIs. The helpers tolerate the null runtime/environment pointers used by
    // this synthetic test and return valid-tag Values.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(2),
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("promotion-gated apply native call succeeds");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(
        preflight
            .native_value()
            .is_some_and(|value| value.raw_eq(Value::int(1416)))
    );
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(invocation.finalized_function().compiled_code_ptr())
    );
    assert!(
        invocation
            .finalization()
            .imported_symbol_for("aos_env_get")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .imported_symbol_for("aos_apply")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address() == candidates[0].address())
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address() == candidates[1].address())
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn promotion_gated_registered_native_thunk_call_reports_missing_apply_candidate() {
    let arena = apply_arena(4, 6);
    let candidates = [env_get_candidate()];

    // SAFETY: The supplied `aos_env_get` candidate is host-ABI-matched, but the
    // promoted apply artifact also imports `aos_apply`; finalization must fail
    // before native invocation.
    let Err(error) = (unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(2),
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }) else {
        panic!("missing apply candidate must reject before native invocation");
    };

    assert_eq!(error.slot().invocation_counter().invocations(), 1);
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    let JitCraneliftNativeCallError::FinalizeArtifact {
        source:
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names },
    } = error.native_call_error()
    else {
        panic!(
            "expected missing artifact-import candidate error, got {}",
            error.native_call_error()
        );
    };
    assert_eq!(symbol_names, &["aos_apply".to_owned()]);
}

#[test]
fn promotion_gated_registered_native_thunk_call_reports_missing_force_candidate() {
    let arena = local_var_arena(9);
    let candidates = [env_get_candidate()];

    // SAFETY: The supplied `aos_env_get` candidate is host-ABI-matched, but the
    // promoted forced artifact also imports `aos_force`; finalization must fail
    // before native invocation.
    let Err(error) = (unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(0),
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }) else {
        panic!("missing force candidate must reject before native invocation");
    };

    assert_eq!(error.slot().invocation_counter().invocations(), 1);
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    let JitCraneliftNativeCallError::FinalizeArtifact {
        source:
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names },
    } = error.native_call_error()
    else {
        panic!(
            "expected missing artifact-import candidate error, got {}",
            error.native_call_error()
        );
    };
    assert_eq!(symbol_names, &["aos_force".to_owned()]);
}
