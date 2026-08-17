//! `builtins.stringLength` native leaf-helper C ABI wrapper.
//!
//! Native tier-1 code inlines `builtins.stringLength` by loading its argument
//! operand, forcing it, and guarding that the forced value is a string before
//! calling `aos_string_length` with the frozen `(rt, Value) -> Value` signature.
//! This wrapper decodes the runtime context and returns the argument's byte
//! length as an integer [`Value`] through the safe tree-walk helper
//! [`TreeWalk::rust_callable_aos_string_length`]. It is a leaf helper, not a
//! trampoline: it neither re-enters the interpreter's builtin dispatch nor forces
//! its argument (native code already forced it), so it performs only the same
//! heap length lookup an ordinary tree-walk `stringLength` does.
//!
//! A tree-walk evaluator error (for example, a value the string-tag guard let
//! through that is nonetheless not an owned string handle) is transferred through
//! the active [`crate::trap::RuntimeTrapScope`] as [`RuntimeTrap::Primop`] and the
//! wrapper returns [`runtime_trap_sentinel_value`]; outside a scope that error
//! aborts. A null runtime pointer or a malformed value payload always aborts as a
//! safety-contract violation.

use std::{ffi::c_void, process};

use ratchet_oracle::{compile::IrId, eval::tree_walk::TreeWalk, syntax::Span, value::Value};

use crate::context::with_native_runtime_context;
use crate::trap::{RuntimeTrap, record_runtime_trap, runtime_trap_sentinel_value};

/// Native C ABI function-pointer shape for `aos_string_length`.
///
/// The function returns a by-value [`Value`] and never unwinds across the ABI
/// boundary. A tree-walk evaluator error is transferred through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// runtime pointer or malformed value payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same pointer, lifetime, borrow,
/// and host-ABI obligations documented on [`aos_string_length`].
pub type RuntimeStringLengthNativeFn = unsafe extern "C" fn(*mut c_void, Value) -> Value;

/// Returns the byte length of a forced string through the frozen native ABI.
///
/// This wrapper is the success-path C ABI body for `aos_string_length`. It
/// validates the representation-level payload, decodes `rt` as the shared runtime
/// context, and returns the argument's byte length as an integer [`Value`] via
/// [`TreeWalk::rust_callable_aos_string_length`]. A tree-walk evaluator error is
/// recorded as [`RuntimeTrap::Primop`] through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer or malformed value payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. `rt` must be a non-null pointer produced from a
/// pinned live runtime context whose wrapped evaluator outlives the call and is
/// exclusively borrowed for its duration; any heap payload in `value` must be
/// reachable from that evaluator. The caller must also ensure the host ABI used
/// to call this function matches the frozen `aos_string_length` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_string_length(rt: *mut c_void, value: Value) -> Value {
    if value.validate_payload().is_err() {
        process::abort()
    }
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and the
    // runtime-context pointer contract documented on this function.
    unsafe {
        with_native_runtime_context(rt, |eval, id, span| {
            string_length_success_path(eval, id, span, value)
        })
    }
}

fn string_length_success_path(eval: &mut TreeWalk, id: IrId, span: Span, value: Value) -> Value {
    match eval.rust_callable_aos_string_length(id, span, value) {
        Ok(value) => value,
        Err(error) => {
            record_runtime_trap(RuntimeTrap::Primop(error));
            runtime_trap_sentinel_value()
        }
    }
}

/// Returns the process-local address of the [`aos_string_length`] native wrapper.
///
/// Tier-1 registration hands this address to the JIT as the `aos_string_length`
/// symbol candidate so a compiled `stringLength` inline body resolves to this
/// wrapper.
pub fn aos_string_length_native_wrapper_address() -> *mut c_void {
    aos_string_length as RuntimeStringLengthNativeFn as *mut c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aos_string_length_wrapper_address_is_non_null() {
        assert!(!aos_string_length_native_wrapper_address().is_null());
    }
}
