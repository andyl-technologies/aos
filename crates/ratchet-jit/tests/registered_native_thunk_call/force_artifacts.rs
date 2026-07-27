//! Direct native-call coverage for force-bearing artifacts.

use super::*;
use ratchet_jit::JitCraneliftRegisteredNativeThunkInvocation;

fn assert_invocation(
    invocation: &JitCraneliftRegisteredNativeThunkInvocation,
    expected: Value,
    helper: &str,
    candidate: &JitRuntimeSymbolAddressCandidate,
) {
    assert!(invocation.value().raw_eq(expected));
    assert_eq!(
        invocation
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>(),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            helper,
        ]
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for(helper)
            .is_some_and(|registered| registered.address() == candidate.address())
    );
}

#[test]
fn registered_native_thunk_call_executes_static_select_artifact_with_candidates() {
    let ir = static_select_ir(9);
    let artifact = lower_select_local_slot_ir_root_thunk_body_artifact(&ir)
        .expect("static select artifact lowers");
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        select_ic_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];
    let invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("registered static select artifact can be called through native thunk ABI");
    assert_invocation(
        &invocation,
        Value::int(811),
        "aos_select_ic",
        &candidates[2],
    );
}

#[test]
fn registered_native_thunk_call_executes_static_has_attr_artifact_with_candidates() {
    let ir = static_has_attr_ir(9);
    let artifact = lower_has_attr_local_slot_ir_root_thunk_body_artifact(&ir)
        .expect("static hasAttr artifact lowers");
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        has_attr_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];
    let invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("registered static hasAttr artifact can be called through native thunk ABI");
    assert_invocation(
        &invocation,
        Value::bool(true),
        "aos_has_attr",
        &candidates[2],
    );
}

#[test]
fn registered_native_thunk_call_executes_update_artifact_with_candidates() {
    let ir = update_ir(8, 9);
    let artifact =
        lower_update_local_slots_ir_root_thunk_body_artifact(&ir).expect("update artifact lowers");
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        update_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];
    let invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("registered update artifact can be called through native thunk ABI");
    assert_invocation(&invocation, Value::int(1838), "aos_update", &candidates[2]);
}
