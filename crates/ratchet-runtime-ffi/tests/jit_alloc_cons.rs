//! End-to-end native allocation coverage for the semantic cons wrapper.

use std::{ffi::c_void, num::NonZeroUsize};

use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate,
    JitTier, JitTieredCodeSlot, TierUpCounter, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates,
};
use ratchet_oracle::{
    compile::{RuntimeHelperRole, RuntimeSymbolKind, resolve},
    eval::tree_walk::TreeWalk,
    syntax::parse_str,
    value::Value,
};
use ratchet_runtime_ffi::{
    RuntimeTrap, RuntimeTrapScope, alloc::aos_alloc_cons,
    aos_jit_stack_map_enter_native_wrapper_address, aos_jit_stack_map_exit_native_wrapper_address,
    context::RuntimeJitContext, wrappers::runtime_native_wrapper_bindings,
};

#[test]
fn semantic_cons_wrapper_transfers_invalid_tail_errors() {
    let source = r#""tail""#;
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut eval = TreeWalk::new(&ir);
    let tail = eval
        .eval_root()
        .expect("string evaluates")
        .as_string_ptr()
        .expect("string pointer")
        .cast::<c_void>()
        .as_ptr();
    let scope = RuntimeTrapScope::new();
    let mut context = std::pin::pin!(RuntimeJitContext::new(&mut eval, ir.root, span));
    let rt = context.as_mut().as_mut_ptr();

    // SAFETY: `rt` is a pinned live context and `head` is immediate. The tail
    // is a live evaluator-owned object but deliberately violates the required
    // list type, so the wrapper must transfer the safe evaluator error.
    let result = unsafe { aos_alloc_cons(rt, Value::int(1), tail) };

    assert!(result.is_null());
    assert!(matches!(
        scope.take_trap(),
        Some(RuntimeTrap::Allocation(_))
    ));
}

#[test]
fn finalized_native_singleton_list_calls_registered_semantic_cons_wrapper() {
    let source = "[ 41 ]";
    let ir = aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut eval = TreeWalk::new(&ir);
    let candidates = allocation_candidates();
    let mut context = std::pin::pin!(RuntimeJitContext::new(&mut eval, ir.root, span));
    let rt = context.as_mut().as_mut_ptr();

    // SAFETY: The runtime pointer comes from a pinned live RuntimeJitContext;
    // every candidate is the process-local wrapper for its frozen host ABI;
    // the lowered scalar head is a valid Value and the lowerer supplies a null
    // tail, so the semantic cons wrapper owns all list materialization.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &candidates,
            rt,
            rt,
        )
    }
    .expect("allocation-capable native body executes");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    let imports = invocation
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|import| import.symbol_name())
        .collect::<Vec<_>>();
    assert_eq!(
        imports,
        [
            "aos_alloc_cons",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
        ]
    );
    for symbol in imports {
        assert!(
            invocation
                .finalization()
                .registered_symbols()
                .iter()
                .any(|registered| registered.symbol_name() == symbol),
            "{symbol} must be registered"
        );
    }
    let value = preflight
        .native_value()
        .expect("native allocation returns a value");
    drop(context);
    let list = eval.heap().get_list(value).expect("native value is a list");

    assert_eq!(list.len(), 1);
    assert!(list.get(0).is_some_and(|item| item.raw_eq(Value::int(41))));
    assert_eq!(
        eval.heap().record_count(),
        0,
        "list stays in the flat store"
    );
}

fn allocation_candidates() -> Vec<JitRuntimeSymbolAddressCandidate> {
    let cons = runtime_native_wrapper_bindings()
        .expect("runtime wrapper manifest builds")
        .into_iter()
        .find(|binding| binding.symbol_name() == "aos_alloc_cons")
        .expect("semantic cons wrapper is present");
    let mut candidates = vec![candidate(
        cons.symbol_name(),
        RuntimeHelperRole::Allocation,
        cons.address().as_ptr() as usize,
    )];
    candidates.push(candidate(
        "aos_jit_stack_map_enter",
        RuntimeHelperRole::SafepointControl,
        aos_jit_stack_map_enter_native_wrapper_address() as usize,
    ));
    candidates.push(candidate(
        "aos_jit_stack_map_exit",
        RuntimeHelperRole::SafepointControl,
        aos_jit_stack_map_exit_native_wrapper_address() as usize,
    ));
    candidates
}

fn candidate(
    symbol: &str,
    role: RuntimeHelperRole,
    address: usize,
) -> JitRuntimeSymbolAddressCandidate {
    JitRuntimeSymbolAddressCandidate::new(
        symbol.to_owned(),
        RuntimeSymbolKind::Helper(role),
        JitRuntimeSymbolAddress::new(
            NonZeroUsize::new(address).expect("runtime wrapper address is non-null"),
        ),
    )
}
