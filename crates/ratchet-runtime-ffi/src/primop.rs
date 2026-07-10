//! Primop-dispatch C ABI wrapper.
//!
//! Native tier-1 code lowers an `IrKind::PrimOp` thunk body to a single call to
//! `aos_primop_call` with the frozen `(rt, env, module_id, node_id) -> Value`
//! signature. This wrapper decodes the runtime context and dispatched
//! environment, reconstructs the module-qualified primop node from the two baked
//! `u32` operands, and hands the node straight back to the tree-walk evaluator
//! through [`TreeWalk::run_lowered_primop_body`]. The builtin's real
//! implementation always runs on the tree walk: the wrapper is a pure
//! trampoline and never re-implements a builtin in native code, which is what
//! keeps the evaluator's impure-input trace (and therefore force-cache cutoff
//! soundness) identical to an ordinary tree-walk force.
//!
//! A tree-walk evaluator error is transferred through the active
//! [`crate::trap::RuntimeTrapScope`] as [`RuntimeTrap::Primop`] and the wrapper
//! returns [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A
//! null runtime or environment pointer always aborts as a safety-contract
//! violation.

use std::ffi::c_void;

use ratchet_oracle::{
    compile::IrId,
    eval::{EvalEnv, EvalModuleId, EvalNodeRef, tree_walk::TreeWalk},
    syntax::Span,
    value::Value,
};

use crate::context::with_native_runtime_env_context;
use crate::trap::{RuntimeTrap, record_runtime_trap, runtime_trap_sentinel_value};

/// Native C ABI function-pointer shape for `aos_primop_call`.
///
/// The function returns a by-value [`Value`] and never unwinds across the ABI
/// boundary. A tree-walk evaluator error is transferred through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// runtime or environment pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same pointer, lifetime, borrow,
/// and host-ABI obligations documented on [`aos_primop_call`].
pub type RuntimePrimopCallNativeFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u32) -> Value;

/// Forces a lowered primop body through the frozen native `aos_primop_call` ABI.
///
/// This wrapper is the success-path C ABI body for `aos_primop_call`. It decodes
/// `rt` as the shared runtime context and takes the dispatched [`EvalEnv`] from
/// that context, reconstructs the primop node from `module_id`/`node_id`, and
/// evaluates it through [`TreeWalk::run_lowered_primop_body`]. A tree-walk
/// evaluator error is recorded as [`RuntimeTrap::Primop`] through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// `rt` must be a non-null pointer produced from a pinned live runtime context
/// whose wrapped evaluator outlives the call, and the caller must uphold
/// exclusive mutable access to that evaluator. `env` must equal `rt`, carrying
/// the same pinned context and its live [`EvalEnv`]. The caller must also ensure
/// the host ABI matches the frozen `aos_primop_call` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_primop_call(
    rt: *mut c_void,
    env: *mut c_void,
    module_id: u32,
    node_id: u32,
) -> Value {
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and the
    // shared runtime-context pointer contract documented on this function.
    unsafe {
        with_native_runtime_env_context(rt, |eval, captured, _id, span| {
            if env != rt {
                std::process::abort();
            }
            primop_call_success_path(eval, captured, module_id, node_id, span)
        })
    }
}

/// Forces the reconstructed primop node against the context's captured environment.
fn primop_call_success_path(
    eval: &mut TreeWalk,
    env: &EvalEnv,
    module_id: u32,
    node_id: u32,
    span: Span,
) -> Value {
    let node = EvalNodeRef::new(EvalModuleId::new(module_id), IrId::new(node_id));
    match eval.run_lowered_primop_body(env, node, span) {
        Ok(value) => value,
        Err(error) => {
            record_runtime_trap(RuntimeTrap::Primop(error));
            runtime_trap_sentinel_value()
        }
    }
}

/// Returns the process-local address of the [`aos_primop_call`] native wrapper.
///
/// Tier-1 registration hands this address to the JIT as the `aos_primop_call`
/// symbol candidate so a compiled primop body resolves to this wrapper.
pub fn aos_primop_call_native_wrapper_address() -> *mut c_void {
    aos_primop_call as RuntimePrimopCallNativeFn as *mut c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aos_primop_call_wrapper_address_is_non_null() {
        assert!(!aos_primop_call_native_wrapper_address().is_null());
    }
}
