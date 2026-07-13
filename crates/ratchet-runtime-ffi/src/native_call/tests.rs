//! Unit tests for the native-call FFI wrappers (split from native_call.rs, §2 cap).

use std::{ffi::c_void, num::NonZeroUsize};

use ratchet_jit::{
    JitModuleContext, JitRuntimeSymbolAddress, TIER2_NATIVE_DEPTH_BUDGET,
    lower_tier2_self_recursive_lambda,
};
use ratchet_oracle::{
    compile::{
        EffectClass, IrArena, IrData, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
        resolve,
    },
    eval::{heap::EvalGcMode, tree_walk::TreeWalkOptions},
    syntax::{Symbol, parse_str},
};

use super::*;

mod candidate_b;
mod candidate_c;

fn candidate(
    symbol_name: &str,
    role: RuntimeHelperRole,
    address: *mut c_void,
) -> JitRuntimeSymbolAddressCandidate {
    let address = NonZeroUsize::new(address as usize).expect("wrapper address is non-zero");
    JitRuntimeSymbolAddressCandidate::new(
        symbol_name.to_owned(),
        RuntimeSymbolKind::Helper(role),
        JitRuntimeSymbolAddress::new(address),
    )
}

#[test]
fn native_thunk_call_outcome_reports_value_and_trap() {
    let value_outcome = NativeThunkCallOutcome {
        value: Value::int(7),
        trap: None,
    };
    assert!(!value_outcome.is_trap());
    assert!(value_outcome.trap().is_none());
    assert_eq!(value_outcome.value().as_int(), Ok(7));
    assert!(value_outcome.into_trap().is_none());
}

#[test]
// Lowers a tier-2 force through the two-word stack-map geometry; tier-2
// emitters decline on the one-word carrier, so this runs baseline-only
// until the S4b phase-2 one-word emitters land.
#[cfg(not(feature = "candidate_c_value"))]
fn tier2_inner_force_dispatches_sweep_through_retained_stack_map() {
    let lowering_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Formal,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Formal {
                    name: Symbol::new(0),
                    default: None,
                },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 0 },
            ),
        ],
        Vec::new(),
    );
    let lowering = lower_tier2_self_recursive_lambda(
        &lowering_arena,
        IrId::new(0),
        IrId::new(1),
        TIER2_NATIVE_DEPTH_BUDGET,
    )
    .expect("tier-2 parameter force lowers");
    let force_address = crate::force::runtime_forcing_native_wrapper_bindings()
        .into_iter()
        .find(|binding| binding.symbol_name() == "aos_force")
        .expect("force wrapper binding exists")
        .address()
        .as_ptr();
    let candidates = [
        candidate(
            "aos_force",
            RuntimeHelperRole::ForcingControl,
            force_address,
        ),
        candidate(
            "aos_deopt",
            RuntimeHelperRole::Deoptimization,
            crate::deopt::aos_deopt_native_wrapper_address(),
        ),
        candidate(
            "aos_upval_get",
            RuntimeHelperRole::EnvironmentAccess,
            crate::env::aos_upval_get_native_wrapper_address(),
        ),
        candidate(
            "aos_jit_stack_map_enter",
            RuntimeHelperRole::SafepointControl,
            crate::stack_map::aos_jit_stack_map_enter_native_wrapper_address(),
        ),
        candidate(
            "aos_jit_stack_map_exit",
            RuntimeHelperRole::SafepointControl,
            crate::stack_map::aos_jit_stack_map_exit_native_wrapper_address(),
        ),
    ];
    let context = JitModuleContext::with_candidates(&candidates)
        .expect("tier-2 module context builds");
    let body = context
        .define_and_finalize_tier2_lambda(lowering)
        .expect("tier-2 pair finalizes");

    let parsed = parse_str("{ v = 1 + 1; }").expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
    let mut options = TreeWalkOptions::default();
    options.set_gc_mode(EvalGcMode::Sweep);
    options.set_gc_sweep_threshold(0);
    let mut eval = TreeWalk::with_options(&ir, options);
    let root = eval.eval_root().expect("attribute set evaluates");
    let symbol = ir
        .symbols
        .symbols()
        .iter()
        .position(|name| name.as_slice() == b"v")
        .map(|index| Symbol::new(index as u32))
        .expect("binding symbol exists");
    let argument = eval
        .heap()
        .get_attrs(root)
        .expect("root is attrs")
        .get(symbol)
        .expect("binding exists");

    let outcome = run_context_finalized_native_lambda_call(
        &mut eval,
        ir.root,
        Span::new(0, 14),
        &EvalEnv::default(),
        argument,
        &body,
    )
    .expect("tier-2 native call succeeds");

    assert!(outcome.trap().is_none());
    assert_eq!(outcome.value().as_int(), Ok(2));
    assert_eq!(eval.stats().gc_sweeps(), 1);
}
