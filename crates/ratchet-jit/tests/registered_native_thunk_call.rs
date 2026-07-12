// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#![cfg(not(feature = "candidate_c_value"))]

use std::{ffi::c_void, num::NonZeroUsize, ptr};

use ratchet_core::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    syntax::{BinOpKind, Span, SymbolTable},
};
use ratchet_jit::{
    JitCraneliftModuleSetupError, JitCraneliftNativeCallError, JitEnvFramePtr,
    JitRuntimeContextPtr, JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate, JitTier,
    JitTieredCodeSlot, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates,
    jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates,
    jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates,
    lower_apply_local_slots_ir_thunk_body_artifact, lower_env_get_ir_thunk_body_artifact,
    lower_forced_env_get_ir_thunk_body_artifact,
    lower_has_attr_local_slot_ir_root_thunk_body_artifact,
    lower_select_local_slot_ir_root_thunk_body_artifact,
    lower_update_local_slots_ir_root_thunk_body_artifact,
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

extern "C" fn test_aos_select_ic(
    _rt: JitRuntimeContextPtr,
    attrs: Value,
    symbol: u32,
    site: u32,
) -> Value {
    if attrs.raw_eq(Value::int(38)) && symbol == 0 && site == 11 {
        Value::int(811)
    } else {
        Value::null()
    }
}

extern "C" fn test_aos_has_attr(
    _rt: JitRuntimeContextPtr,
    attrs: Value,
    symbol: u32,
    site: u32,
) -> Value {
    Value::bool(attrs.raw_eq(Value::int(38)) && symbol == 0 && site == 11)
}

extern "C" fn test_aos_update(_rt: JitRuntimeContextPtr, left: Value, right: Value) -> Value {
    let Ok(left) = left.as_int() else {
        return Value::null();
    };
    let Ok(right) = right.as_int() else {
        return Value::null();
    };

    Value::int((left * 100) + right)
}

extern "C" fn test_aos_jit_stack_map_enter(
    _rt: JitRuntimeContextPtr,
    _binding: *mut c_void,
    _identity: *mut c_void,
    _safepoint: u32,
    _values: u32,
) {
}

extern "C" fn test_aos_jit_stack_map_exit(
    _rt: JitRuntimeContextPtr,
    _binding: *mut c_void,
) {
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

fn update_ir(left_slot: u32, right_slot: u32) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: left_slot },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local { slot: right_slot },
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: BinOpKind::Update,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn static_select_ir(slot: u32) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            ),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
                    default: None,
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn static_has_attr_ir(slot: u32) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            ),
            IrNode::new(
                IrKind::HasAttr,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::HasAttr {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
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

fn select_ic_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_select_ic",
        RuntimeHelperRole::AttrsetAccess,
        test_aos_select_ic as *const () as usize,
    )
}

fn has_attr_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_has_attr",
        RuntimeHelperRole::AttrsetAccess,
        test_aos_has_attr as *const () as usize,
    )
}

fn update_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_update",
        RuntimeHelperRole::AttrsetAccess,
        test_aos_update as *const () as usize,
    )
}

fn stack_map_enter_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_jit_stack_map_enter",
        RuntimeHelperRole::SafepointControl,
        test_aos_jit_stack_map_enter as *const () as usize,
    )
}

fn stack_map_exit_candidate() -> JitRuntimeSymbolAddressCandidate {
    candidate(
        "aos_jit_stack_map_exit",
        RuntimeHelperRole::SafepointControl,
        test_aos_jit_stack_map_exit as *const () as usize,
    )
}

fn force_candidates_without_extra() -> [JitRuntimeSymbolAddressCandidate; 4] {
    [
        env_get_candidate(),
        force_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ]
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
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];

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
    assert_eq!(
        import_names,
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
        ]
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

#[path = "registered_native_thunk_call/force_artifacts.rs"]
mod force_artifacts;

#[test]
fn registered_native_thunk_call_requires_candidates_for_artifact_imports() {
    let arena = local_var_arena(9);
    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("forced env-get artifact lowers");
    let candidates = [
        env_get_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];

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
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];

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
fn promotion_gated_registered_native_thunk_call_executes_static_select_on_promotion() {
    let ir = static_select_ir(9);
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        select_ic_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The promoted artifact imports `aos_env_get`, `aos_force`, and
    // `aos_select_ic`; all candidates are live `extern "C"` test functions with
    // the frozen helper ABIs and valid returned-tag Values.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &ir,
            ir.root,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("promotion-gated static select native call succeeds");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(
        preflight
            .native_value()
            .is_some_and(|value| value.raw_eq(Value::int(811)))
    );
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(invocation.finalized_function().compiled_code_ptr())
    );
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
            "aos_select_ic",
        ]
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_apply")
            .is_none()
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn promotion_gated_registered_native_thunk_call_executes_static_has_attr_on_promotion() {
    let ir = static_has_attr_ir(9);
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        has_attr_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The promoted artifact imports `aos_env_get`, `aos_force`, and
    // `aos_has_attr`; all candidates are live `extern "C"` test functions with
    // the frozen helper ABIs and valid returned-tag Values.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &ir,
            ir.root,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("promotion-gated static hasAttr native call succeeds");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(
        preflight
            .native_value()
            .is_some_and(|value| value.raw_eq(Value::bool(true)))
    );
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(invocation.finalized_function().compiled_code_ptr())
    );
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
            "aos_has_attr",
        ]
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_has_attr")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_none()
    );
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn promotion_gated_registered_native_thunk_call_executes_update_on_promotion() {
    let ir = update_ir(8, 9);
    let candidates = [
        env_get_candidate(),
        force_candidate(),
        update_candidate(),
        stack_map_enter_candidate(),
        stack_map_exit_candidate(),
    ];

    // SAFETY: The current test host is accepted by the native Value ABI gate.
    // The promoted update artifact imports `aos_env_get`, `aos_force`, and
    // `aos_update`; all candidates are live `extern "C"` test functions with
    // the frozen helper ABIs and valid returned-tag Values.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &ir.arena,
            ir.root,
            &candidates,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .expect("promotion-gated update native call succeeds");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(
        preflight
            .native_value()
            .is_some_and(|value| value.raw_eq(Value::int(1838)))
    );
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        preflight.slot().tier1_code_ptr(),
        Some(invocation.finalized_function().compiled_code_ptr())
    );
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
            "aos_update",
        ]
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_update")
            .is_some()
    );
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_none()
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

#[path = "registered_native_thunk_call/missing_candidates.rs"]
mod missing_candidates;
