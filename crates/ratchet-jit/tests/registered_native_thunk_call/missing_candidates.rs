//! Promotion failures caused by deliberately omitted runtime candidates.

use super::*;
use ratchet_jit::JitCraneliftRegisteredTier1NativeCallError;

fn assert_missing(error: &JitCraneliftRegisteredTier1NativeCallError, symbol_name: &str) {
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
    assert_eq!(symbol_names, &[symbol_name.to_owned()]);
}

#[test]
fn promotion_gated_registered_native_thunk_call_reports_missing_apply_candidate() {
    let arena = apply_arena(4, 6);
    let candidates = [env_get_candidate()];
    let Err(error) = (unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(), TierUpPolicy::default(), TierUpDemandHint::MultiUse,
            &arena, IrId::new(2), &candidates, ptr::null_mut(), ptr::null_mut(),
        )
    }) else {
        panic!("missing apply candidate must reject before native invocation");
    };
    assert_missing(&error, "aos_apply");
}

#[test]
fn promotion_gated_registered_native_thunk_call_reports_missing_select_candidate() {
    let ir = static_select_ir(9);
    let candidates = force_candidates_without_extra();
    let Err(error) = (unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::new(), TierUpPolicy::default(), TierUpDemandHint::MultiUse,
            &ir, ir.root, &candidates, ptr::null_mut(), ptr::null_mut(),
        )
    }) else {
        panic!("missing select candidate must reject before native invocation");
    };
    assert_missing(&error, "aos_select_ic");
}

#[test]
fn promotion_gated_registered_native_thunk_call_reports_missing_update_candidate() {
    let ir = update_ir(8, 9);
    let candidates = force_candidates_without_extra();
    let Err(error) = (unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(), TierUpPolicy::default(), TierUpDemandHint::MultiUse,
            &ir.arena, ir.root, &candidates, ptr::null_mut(), ptr::null_mut(),
        )
    }) else {
        panic!("missing update candidate must reject before native invocation");
    };
    assert_missing(&error, "aos_update");
}

#[test]
fn promotion_gated_registered_native_thunk_call_reports_missing_has_attr_candidate() {
    let ir = static_has_attr_ir(9);
    let candidates = force_candidates_without_extra();
    let Err(error) = (unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::new(), TierUpPolicy::default(), TierUpDemandHint::MultiUse,
            &ir, ir.root, &candidates, ptr::null_mut(), ptr::null_mut(),
        )
    }) else {
        panic!("missing hasAttr candidate must reject before native invocation");
    };
    assert_missing(&error, "aos_has_attr");
}

#[test]
fn promotion_gated_registered_native_thunk_call_reports_missing_force_candidate() {
    let arena = local_var_arena(9);
    let candidates = [
        env_get_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];
    let Err(error) = (unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(), TierUpPolicy::default(), TierUpDemandHint::MultiUse,
            &arena, IrId::new(0), &candidates, ptr::null_mut(), ptr::null_mut(),
        )
    }) else {
        panic!("missing force candidate must reject before native invocation");
    };
    assert_missing(&error, "aos_force");
}
