//! Environment-access C ABI wrappers.
//!
//! The tree-walk evaluator stores lexical captures in [`EvalFrame`]. Native
//! tier-1 code imports `aos_env_get` with the frozen `(env, slot) -> Value`
//! signature, where `env` is an opaque pointer to that frame and `slot` is the
//! captured local index. This module supplies the first success-path wrapper for
//! that ABI and metadata describing what still prevents final native export
//! registration.

use std::{ffi::c_void, process, ptr::NonNull};

use ratchet_oracle::{
    eval::EvalFrame,
    runtime::env::{
        RuntimeEnvAccessAbiSignature, RuntimeEnvAccessEntryPoint,
        RuntimeEnvAccessNativeExportBlocker,
    },
    value::Value,
};

use crate::trap::{RuntimeTrap, record_runtime_trap, runtime_trap_sentinel_value};

/// Native C ABI function pointer shape for `aos_env_get`.
///
/// The function returns a by-value [`Value`] and never unwinds across the ABI
/// boundary. A frame-access evaluator error (an out-of-bounds slot or borrow
/// conflict) is transferred through the active [`crate::trap::RuntimeTrapScope`]
/// and the wrapper returns [`runtime_trap_sentinel_value`]; outside a scope that
/// error aborts. A null environment pointer always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same pointer, lifetime, borrow,
/// slot-bounds, and host-ABI obligations documented on [`aos_env_get`].
pub type RuntimeEnvGetNativeFn = unsafe extern "C" fn(*mut c_void, u32) -> Value;

// Trap transfer is implemented for the environment-access wrapper, so no
// wrapper-local blocker remains. The oracle native-export gate still tracks
// `MissingFinalExportedWrapper`; that is cleared only when `aos-nix` formally
// admits the export, not here.
const ENV_ACCESS_REMAINING_EXPORT_BLOCKERS: &[RuntimeEnvAccessNativeExportBlocker] = &[];

/// Reads one captured environment slot through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_env_get`. It decodes the
/// opaque environment pointer as an [`EvalFrame`], reads `slot` through the same
/// safe frame API used by the tree-walk oracle, and returns the copied [`Value`]
/// by value. A frame-access error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// environment pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// `env` must be a non-null pointer produced from a live [`EvalFrame`] whose
/// allocation outlives the call. The frame must not be mutably borrowed during
/// the call, and `slot` must be in bounds for that frame. The caller must also
/// ensure the host ABI used to call this function matches the frozen
/// `aos_env_get` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_env_get(env: *mut c_void, slot: u32) -> Value {
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // EvalFrame pointer contract documented on this function.
    unsafe {
        with_native_env_frame(env, |frame| match frame.get(slot) {
            Ok(value) => value,
            Err(error) => {
                record_runtime_trap(RuntimeTrap::Env(error));
                runtime_trap_sentinel_value()
            }
        })
    }
}

/// Returns metadata for exported environment-access wrappers in symbol order.
pub fn runtime_env_access_native_wrapper_bindings() -> Vec<RuntimeEnvAccessNativeWrapperBinding> {
    vec![RuntimeEnvAccessNativeWrapperBinding::aos_env_get()]
}

/// Process-local address metadata for one native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeEnvAccessNativeWrapperAddress {
    ptr: *mut c_void,
}

impl RuntimeEnvAccessNativeWrapperAddress {
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

/// Metadata for one success-path environment-access native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeEnvAccessNativeWrapperBinding {
    entrypoint: RuntimeEnvAccessEntryPoint,
    address: RuntimeEnvAccessNativeWrapperAddress,
    remaining_export_blockers: &'static [RuntimeEnvAccessNativeExportBlocker],
}

impl RuntimeEnvAccessNativeWrapperBinding {
    fn aos_env_get() -> Self {
        Self {
            entrypoint: RuntimeEnvAccessEntryPoint::AosEnvGet,
            address: RuntimeEnvAccessNativeWrapperAddress::new(
                aos_env_get as RuntimeEnvGetNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ENV_ACCESS_REMAINING_EXPORT_BLOCKERS,
        }
    }

    /// Returns the environment-access entry point served by this wrapper.
    pub const fn entrypoint(self) -> RuntimeEnvAccessEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name served by this wrapper.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen ABI signature implemented on the success path.
    pub const fn abi_signature(self) -> RuntimeEnvAccessAbiSignature {
        self.entrypoint.abi_signature()
    }

    /// Returns the typed native wrapper function pointer.
    pub const fn function(self) -> RuntimeEnvGetNativeFn {
        match self.entrypoint {
            RuntimeEnvAccessEntryPoint::AosEnvGet => aos_env_get,
        }
    }

    /// Returns the process-local native wrapper address.
    pub const fn address(self) -> RuntimeEnvAccessNativeWrapperAddress {
        self.address
    }

    /// Returns blockers that still prevent final native-export registration.
    pub const fn remaining_export_blockers(self) -> &'static [RuntimeEnvAccessNativeExportBlocker] {
        self.remaining_export_blockers
    }

    /// Returns true when the wrapper has no remaining export blockers.
    pub const fn is_export_ready(self) -> bool {
        self.remaining_export_blockers.is_empty()
    }
}

unsafe fn with_native_env_frame<R>(env: *mut c_void, call: impl FnOnce(&EvalFrame) -> R) -> R {
    let Some(env) = NonNull::new(env) else {
        process::abort();
    };
    // SAFETY: The caller must provide a live EvalFrame pointer with a lifetime
    // covering this call.
    call(unsafe { env.cast::<EvalFrame>().as_ref() })
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;

    #[test]
    fn env_native_wrapper_binding_preserves_symbol_abi_and_address() {
        let bindings = runtime_env_access_native_wrapper_bindings();

        assert_eq!(bindings.len(), 1);
        let binding = bindings[0];
        assert_eq!(binding.entrypoint(), RuntimeEnvAccessEntryPoint::AosEnvGet);
        assert_eq!(binding.symbol_name(), "aos_env_get");
        assert_eq!(
            binding.abi_signature(),
            RuntimeEnvAccessEntryPoint::AosEnvGet.abi_signature()
        );
        assert_eq!(
            binding.address().as_ptr(),
            aos_env_get as RuntimeEnvGetNativeFn as *mut c_void
        );
        assert!(binding.address().is_non_null());
        assert!(binding.remaining_export_blockers().is_empty());
        assert!(binding.is_export_ready());
    }

    #[test]
    fn env_native_wrapper_blockers_are_clear_while_oracle_gate_remains() {
        let binding = runtime_env_access_native_wrapper_bindings()
            .into_iter()
            .next()
            .expect("env wrapper binding exists");
        let oracle_blockers = RuntimeEnvAccessEntryPoint::AosEnvGet.native_export_blockers();
        let expected_oracle_blockers = [
            RuntimeEnvAccessNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeEnvAccessNativeExportBlocker::TrapTransferUnimplemented,
        ];

        // Trap transfer is implemented, so the wrapper carries no remaining
        // wrapper-local blocker, while the oracle native-export gate is
        // unchanged and remains authoritative for final admission.
        assert_eq!(oracle_blockers, expected_oracle_blockers.as_slice());
        assert!(binding.remaining_export_blockers().is_empty());
        assert!(binding.is_export_ready());
    }

    #[test]
    fn aos_env_get_native_wrapper_reads_frame_slots() {
        let frame = EvalFrame::new(2).expect("frame allocates");
        let expected = Value::int(42);
        frame.set(1, expected).expect("slot stores");

        let env = Rc::as_ptr(&frame) as *mut c_void;
        // SAFETY: The frame is live for the call, the slot is in bounds, and no
        // mutable borrow is active.
        let actual = unsafe { aos_env_get(env, 1) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn env_native_wrapper_binding_function_reads_frame_slots() {
        let binding = runtime_env_access_native_wrapper_bindings()
            .into_iter()
            .next()
            .expect("env wrapper binding exists");
        let frame = EvalFrame::new(1).expect("frame allocates");
        let expected = Value::bool(true);
        frame.set(0, expected).expect("slot stores");

        let env = Rc::as_ptr(&frame) as *mut c_void;
        // SAFETY: The frame is live for the call, the slot is in bounds, and no
        // mutable borrow is active.
        let actual = unsafe { (binding.function())(env, 0) };

        assert!(actual.raw_eq(expected));
    }
}
