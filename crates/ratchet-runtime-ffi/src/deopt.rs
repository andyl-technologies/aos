//! Deoptimization C ABI wrapper.
//!
//! Native tier-1 code raises a deopt when an inline fast-path guard fails (a
//! non-integer arithmetic operand, a zero divisor, or another case a compiled
//! body cannot handle). Unlike the forcing, environment, apply, and attrset
//! wrappers, `aos_deopt` decodes nothing: it records a
//! [`RuntimeTrap::Deopt`](crate::trap::RuntimeTrap::Deopt) control signal in the
//! active [`RuntimeTrapScope`](crate::trap::RuntimeTrapScope) and returns the
//! trap sentinel. The engine observes the recorded trap as a silent deopt and
//! re-runs the body through the tree walk, which reproduces the exact value or
//! error the guard could not.
//!
//! Because the wrapper never dereferences its runtime-context or deopt-record
//! pointers, its body performs no unsafe operations and is an ordinary safe
//! `extern "C"` function. Compiled callers still cross the raw native-call
//! boundary through the reviewed `unsafe` sites in [`crate::native_call`].

use std::ffi::c_void;

use ratchet_oracle::value::Value;

use crate::trap::{RuntimeTrap, record_runtime_trap, runtime_trap_sentinel_value};

/// Native C ABI function-pointer shape for `aos_deopt`.
///
/// The function matches the frozen `(rt, deopt_record) -> Value` deopt ABI. It
/// never unwinds across the boundary. When a [`RuntimeTrapScope`] is installed
/// it records a [`RuntimeTrap::Deopt`] and returns the trap sentinel; outside a
/// scope [`record_runtime_trap`] aborts, matching the other wrappers.
///
/// [`RuntimeTrapScope`]: crate::trap::RuntimeTrapScope
pub type RuntimeDeoptNativeFn = extern "C" fn(*mut c_void, *mut c_void) -> Value;

/// Records a deoptimization request through the frozen native `aos_deopt` ABI.
///
/// This is the success-path C ABI body for `aos_deopt`. It ignores the runtime
/// context and deopt-record pointers, records a [`RuntimeTrap::Deopt`] in the
/// active [`RuntimeTrapScope`](crate::trap::RuntimeTrapScope), and returns
/// [`runtime_trap_sentinel_value`]. The sentinel is meaningless; the caller
/// treats the recorded trap as a deopt and re-runs the body on the tree walk.
///
/// Outside an armed trap scope, recording aborts the process, matching every
/// other runtime-FFI wrapper: a compiled body must only be entered under an
/// installed scope.
pub extern "C" fn aos_deopt(_rt: *mut c_void, _deopt_record: *mut c_void) -> Value {
    record_runtime_trap(RuntimeTrap::Deopt);
    runtime_trap_sentinel_value()
}

/// Returns the process-local address of the [`aos_deopt`] native wrapper.
///
/// Tier-1 registration hands this address to the JIT as the `aos_deopt` symbol
/// candidate so a compiled deopt call resolves to this wrapper. The pointer is a
/// process-local wrapper body address, not a final exported native ABI target.
pub fn aos_deopt_native_wrapper_address() -> *mut c_void {
    aos_deopt as RuntimeDeoptNativeFn as *mut c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::trap::RuntimeTrapScope;

    #[test]
    fn aos_deopt_records_deopt_trap_and_returns_sentinel() {
        let scope = RuntimeTrapScope::new();
        let value = aos_deopt(std::ptr::null_mut(), std::ptr::null_mut());

        assert!(value.raw_eq(runtime_trap_sentinel_value()));
        assert_eq!(scope.take_trap(), Some(RuntimeTrap::Deopt));
    }

    #[test]
    fn aos_deopt_wrapper_address_is_non_null() {
        assert!(!aos_deopt_native_wrapper_address().is_null());
    }
}
