//! Forcing C ABI wrappers.
//!
//! Native tier-1 code imports forcing helpers with frozen `(rt, Value)`
//! signatures. This module supplies the wrappers for that ABI:
//! `aos_blackhole_check`, `aos_force`, and `aos_force_deep` decode scoped
//! [`RuntimeForceContext`] pointers before dispatching through the safe
//! tree-walk forcing helpers. An evaluator error transfers back to the caller
//! through [`crate::trap::RuntimeTrapScope`]: the wrapper records the error and
//! returns [`runtime_trap_sentinel_value`], so a caller that installed a scope
//! can observe the failing force instead of the process aborting. Outside a
//! scope, [`record_runtime_trap`] falls back to aborting. Representation-level
//! faults still abort unconditionally: a null runtime pointer or a malformed
//! payload is a safety-contract violation, not a recoverable evaluator error.
//! Callers must still pass a Rust-valid [`Value`]; an invalid tag discriminant
//! is undefined behavior before these wrappers can inspect it.

use std::{ffi::c_void, process};

use ratchet_oracle::{
    compile::IrId,
    eval::tree_walk::TreeWalk,
    runtime::forcing::{
        RuntimeForcingAbiSignature, RuntimeForcingEntryPoint, RuntimeForcingNativeExportBlocker,
        rust_callable_aos_blackhole_check, rust_callable_aos_force, rust_callable_aos_force_deep,
    },
    syntax::Span,
    value::Value,
};

use crate::context::{
    RuntimeJitContext, with_native_jit_evaluator_context, with_native_runtime_context,
};
use crate::trap::{RuntimeTrap, record_runtime_trap};

mod compiled_safepoint;
use compiled_safepoint::run_force_at_compiled_safepoint;

/// Native C ABI function pointer shape for `aos_blackhole_check`.
///
/// The function never unwinds across the ABI boundary. A blackhole re-entry
/// error is transferred through the active [`crate::trap::RuntimeTrapScope`]
/// when one is installed, and otherwise aborts. A malformed payload or null
/// runtime pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_blackhole_check`]. The value argument must be a
/// Rust-valid [`Value`] with a valid tag discriminant. Calls must pass a valid
/// pinned [`RuntimeForceContext`] runtime pointer.
pub type RuntimeBlackholeCheckNativeFn = unsafe extern "C" fn(*mut c_void, Value);

/// Native C ABI function pointer shape for value-returning forcing helpers.
///
/// The function returns a by-value [`Value`] and never unwinds across the ABI
/// boundary. A forcing evaluator error is transferred through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope the error aborts. A
/// malformed payload or null runtime pointer always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on the wrapper being called. The value argument must be a
/// Rust-valid [`Value`] with a valid tag discriminant. Any returned heap value
/// must carry a live evaluator-owned heap payload for the value kind. Calls to
/// [`aos_force`] and [`aos_force_deep`] must pass a valid pinned
/// [`RuntimeForceContext`] runtime pointer.
pub type RuntimeForceNativeFn = unsafe extern "C" fn(*mut c_void, Value) -> Value;

// Trap transfer is implemented for the forcing wrappers, so no wrapper-local
// blocker remains. The oracle native-export gate still tracks
// `MissingFinalExportedWrapper` and the other final-admission blockers; those
// are cleared only when `aos-nix` formally admits the export, not here.
const BLACKHOLE_CHECK_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[];

const FORCE_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[];

const FORCE_DEEP_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[];

/// Checks a value for blackhole re-entry through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_blackhole_check`. It
/// accepts the frozen runtime-context pointer plus a by-value [`Value`],
/// validates the representation-level payload, decodes `rt` as a
/// [`RuntimeForceContext`], checks thunk blackhole state through the safe
/// tree-walk helper, and returns when no recursive re-entry was detected. A
/// blackhole re-entry error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns; outside a scope
/// that error aborts. A null pointer or malformed value payload always aborts
/// as a safety-contract violation.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. `rt` must be a non-null pointer produced from a
/// pinned live [`RuntimeForceContext`] whose wrapped evaluator and IR allocation
/// outlive the call. The context must not move while the pointer is used. The
/// caller must uphold exclusive mutable access to the wrapped evaluator for the
/// duration of the call. Any heap payload in `value` must be reachable from
/// that evaluator. The caller must also ensure the host ABI used to call this
/// function matches the frozen `aos_blackhole_check` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_blackhole_check(rt: *mut c_void, value: Value) {
    if value.validate_payload().is_err() {
        process::abort()
    }
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // RuntimeForceContext pointer contract documented on this function.
    let checked = unsafe {
        with_native_runtime_context(rt, |eval, id, span| {
            aos_blackhole_check_success_path(eval, id, span, value)
        })
    };
    checked
}

fn aos_blackhole_check_success_path(eval: &mut TreeWalk, id: IrId, span: Span, value: Value) {
    if let Err(error) = rust_callable_aos_blackhole_check(eval, id, span, value) {
        record_runtime_trap(RuntimeTrap::Force(error));
    }
}

/// Forces a value through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_force`. It accepts the
/// frozen runtime-context pointer plus a by-value [`Value`], validates the
/// representation-level payload, decodes `rt` as a [`RuntimeForceContext`],
/// forces thunks through the safe tree-walk force helper, and returns weak head
/// normal form. A forcing evaluator error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer or malformed value payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. `rt` must be a non-null pointer produced from a
/// pinned live [`RuntimeForceContext`] whose wrapped evaluator and IR allocation
/// outlive the call. The context must not move while the pointer is used. The
/// caller must uphold exclusive mutable access to the wrapped evaluator for the
/// duration of the call. Any heap payload in `value` must be reachable from
/// that evaluator. The caller must also ensure the host ABI used to call this
/// function matches the frozen `aos_force` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_force(rt: *mut c_void, value: Value) -> Value {
    if value.validate_payload().is_err() {
        process::abort()
    }
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // RuntimeForceContext pointer contract documented on this function.
    let forced = unsafe {
        with_native_jit_evaluator_context(rt, |context, eval, id, span| {
            run_force_at_compiled_safepoint(context, eval, id, span, |eval| {
                rust_callable_aos_force(eval, id, span, value)
            })
        })
    };
    forced
}

/// Deep-forces a value through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_force_deep`. It accepts
/// the frozen runtime-context pointer plus a by-value [`Value`], validates the
/// representation-level payload, decodes `rt` as a [`RuntimeForceContext`],
/// recursively forces list elements and attrset values through the safe
/// tree-walk deep-force helper, and returns the original container or leaf
/// [`Value`]. A deep-force evaluator error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer or malformed value payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. `rt` must be a non-null pointer produced from a
/// pinned live [`RuntimeForceContext`] whose wrapped evaluator and IR allocation
/// outlive the call. The context must not move while the pointer is used. The
/// caller must uphold exclusive mutable access to the wrapped evaluator for the
/// duration of the call. Any heap payload in `value` must be reachable from
/// that evaluator. The caller must also ensure the host ABI used to call this
/// function matches the frozen `aos_force_deep` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_force_deep(rt: *mut c_void, value: Value) -> Value {
    if value.validate_payload().is_err() {
        process::abort()
    }
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // RuntimeForceContext pointer contract documented on this function.
    let deeply_forced = unsafe {
        with_native_jit_evaluator_context(rt, |context, eval, id, span| {
            run_force_at_compiled_safepoint(context, eval, id, span, |eval| {
                rust_callable_aos_force_deep(eval, id, span, value)
            })
        })
    };
    deeply_forced
}

/// Returns metadata for exported forcing wrappers in symbol order.
pub fn runtime_forcing_native_wrapper_bindings() -> Vec<RuntimeForcingNativeWrapperBinding> {
    vec![
        RuntimeForcingNativeWrapperBinding::aos_blackhole_check(),
        RuntimeForcingNativeWrapperBinding::aos_force(),
        RuntimeForcingNativeWrapperBinding::aos_force_deep(),
    ]
}

/// Process-local address metadata for one forcing native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeForcingNativeWrapperAddress {
    ptr: *mut c_void,
}

impl RuntimeForcingNativeWrapperAddress {
    const fn new(ptr: *mut c_void) -> Self {
        Self { ptr }
    }

    /// Returns the process-local wrapper address.
    pub const fn as_ptr(self) -> *mut c_void {
        self.ptr
    }

    /// Returns true when the wrapper address is non-null.
    pub const fn is_non_null(self) -> bool {
        !self.ptr.is_null()
    }
}

/// Typed function pointer for one forcing native wrapper.
#[derive(Clone, Copy, Debug)]
pub enum RuntimeForcingNativeWrapperFunction {
    /// The `aos_blackhole_check` unit-returning wrapper.
    BlackholeCheck(RuntimeBlackholeCheckNativeFn),
    /// The `aos_force` value-returning wrapper.
    ForceValue(RuntimeForceNativeFn),
    /// The `aos_force_deep` value-returning wrapper.
    ForceDeepValue(RuntimeForceNativeFn),
}

/// Metadata for one success-path forcing native wrapper.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeForcingNativeWrapperBinding {
    entrypoint: RuntimeForcingEntryPoint,
    function: RuntimeForcingNativeWrapperFunction,
    address: RuntimeForcingNativeWrapperAddress,
    remaining_export_blockers: &'static [RuntimeForcingNativeExportBlocker],
}

impl RuntimeForcingNativeWrapperBinding {
    fn aos_blackhole_check() -> Self {
        Self {
            entrypoint: RuntimeForcingEntryPoint::AosBlackholeCheck,
            function: RuntimeForcingNativeWrapperFunction::BlackholeCheck(aos_blackhole_check),
            address: RuntimeForcingNativeWrapperAddress::new(
                aos_blackhole_check as RuntimeBlackholeCheckNativeFn as *mut c_void,
            ),
            remaining_export_blockers: BLACKHOLE_CHECK_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_force() -> Self {
        Self {
            entrypoint: RuntimeForcingEntryPoint::AosForce,
            function: RuntimeForcingNativeWrapperFunction::ForceValue(aos_force),
            address: RuntimeForcingNativeWrapperAddress::new(
                aos_force as RuntimeForceNativeFn as *mut c_void,
            ),
            remaining_export_blockers: FORCE_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_force_deep() -> Self {
        Self {
            entrypoint: RuntimeForcingEntryPoint::AosForceDeep,
            function: RuntimeForcingNativeWrapperFunction::ForceDeepValue(aos_force_deep),
            address: RuntimeForcingNativeWrapperAddress::new(
                aos_force_deep as RuntimeForceNativeFn as *mut c_void,
            ),
            remaining_export_blockers: FORCE_DEEP_REMAINING_EXPORT_BLOCKERS,
        }
    }

    /// Returns the forcing entry point served by this wrapper.
    pub const fn entrypoint(self) -> RuntimeForcingEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name served by this wrapper.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen ABI signature implemented on the success path.
    pub const fn abi_signature(self) -> RuntimeForcingAbiSignature {
        self.entrypoint.abi_signature()
    }

    /// Returns the typed native wrapper function pointer.
    pub const fn function(self) -> RuntimeForcingNativeWrapperFunction {
        self.function
    }

    /// Returns the process-local native wrapper address.
    pub const fn address(self) -> RuntimeForcingNativeWrapperAddress {
        self.address
    }

    /// Returns blockers that still prevent final native-export registration.
    pub const fn remaining_export_blockers(self) -> &'static [RuntimeForcingNativeExportBlocker] {
        self.remaining_export_blockers
    }

    /// Returns true when the wrapper has no remaining export blockers.
    pub const fn is_export_ready(self) -> bool {
        self.remaining_export_blockers.is_empty()
    }
}

/// Shared runtime context accepted by forcing native wrappers.
pub type RuntimeForceContext<'eval> = RuntimeJitContext<'eval>;

#[cfg(test)]
mod tests;
