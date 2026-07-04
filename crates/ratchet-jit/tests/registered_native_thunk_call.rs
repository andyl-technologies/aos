use std::{num::NonZeroUsize, ptr};

use ratchet_core::{
    EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    syntax::Span,
};
use ratchet_jit::{
    JitCraneliftModuleSetupError, JitCraneliftNativeCallError, JitEnvFramePtr,
    JitRuntimeContextPtr, JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate,
    jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates,
    lower_env_get_ir_thunk_body_artifact, lower_forced_env_get_ir_thunk_body_artifact,
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
