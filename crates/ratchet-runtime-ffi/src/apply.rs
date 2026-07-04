//! Call-control C ABI wrappers.
//!
//! Native tier-1 code imports the generic apply helper with the frozen
//! `(rt, Value function, Value arg) -> Value` signature. This module supplies a
//! trap-only wrapper for that ABI: `aos_apply` aborts for every call until
//! runtime-context decoding, active call-root binding, call-depth accounting,
//! callable dispatch, trap transfer, and native value return materialization
//! exist. That is the only sound behavior today because the safe evaluator apply
//! path owns functor, lambda, and partial-application semantics.

use std::{ffi::c_void, process};

use ratchet_oracle::{
    runtime::apply::{
        RuntimeApplyAbiSignature, RuntimeApplyEntryPoint, RuntimeApplyNativeExportBlocker,
    },
    value::Value,
};

/// Native C ABI function pointer shape for `aos_apply`.
///
/// The function returns a by-value [`Value`] and transfers no error state. It
/// aborts instead of unwinding until the evaluator runtime context can expose
/// active call roots, call-depth accounting, callable dispatch, and native
/// value-return materialization to this ABI boundary.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_apply`]. The function and argument values must be
/// Rust-valid [`Value`] instances with valid tag discriminants. The current
/// trap-only wrapper aborts before decoding `_rt` or inspecting either value;
/// future callable dispatch will require all three arguments to be valid for
/// the active evaluator runtime.
pub type RuntimeApplyNativeFn = unsafe extern "C" fn(*mut c_void, Value, Value) -> Value;

const APPLY_REMAINING_EXPORT_BLOCKERS: &[RuntimeApplyNativeExportBlocker] = &[
    RuntimeApplyNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeApplyNativeExportBlocker::ActiveCallRootBindingUnimplemented,
    RuntimeApplyNativeExportBlocker::CallDepthAccountingUnimplemented,
    RuntimeApplyNativeExportBlocker::CallableDispatchBindingUnimplemented,
    RuntimeApplyNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeApplyNativeExportBlocker::NativeValueReturnUnmaterialized,
];

/// Aborts through the frozen apply native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_apply`. It accepts the
/// frozen runtime-context pointer plus by-value function and argument values,
/// then aborts until native wrappers can safely enter the evaluator's apply
/// machinery and return a materialized [`Value`]. Returning today would be
/// unsound because the wrapper cannot preserve call-depth accounting or
/// callable dispatch semantics without runtime context.
///
/// # Safety
///
/// `function` and `argument` must be Rust-valid [`Value`] instances with valid
/// tag discriminants before crossing this ABI boundary. The current wrapper
/// aborts before decoding `_rt` or inspecting either value. The caller must also
/// ensure the host ABI used to call this function matches the frozen `aos_apply`
/// runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_apply(_rt: *mut c_void, _function: Value, _argument: Value) -> Value {
    process::abort()
}

/// Returns metadata for exported apply wrappers in symbol order.
pub fn runtime_apply_native_wrapper_bindings() -> Vec<RuntimeApplyNativeWrapperBinding> {
    vec![RuntimeApplyNativeWrapperBinding::aos_apply()]
}

/// Process-local address metadata for one apply native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeApplyNativeWrapperAddress {
    ptr: *mut c_void,
}

impl RuntimeApplyNativeWrapperAddress {
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

/// Metadata for one trap-only apply native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeApplyNativeWrapperBinding {
    entrypoint: RuntimeApplyEntryPoint,
    address: RuntimeApplyNativeWrapperAddress,
    remaining_export_blockers: &'static [RuntimeApplyNativeExportBlocker],
}

impl RuntimeApplyNativeWrapperBinding {
    fn aos_apply() -> Self {
        Self {
            entrypoint: RuntimeApplyEntryPoint::AosApply,
            address: RuntimeApplyNativeWrapperAddress::new(
                aos_apply as RuntimeApplyNativeFn as *mut c_void,
            ),
            remaining_export_blockers: APPLY_REMAINING_EXPORT_BLOCKERS,
        }
    }

    /// Returns the apply entry point served by this wrapper.
    pub const fn entrypoint(self) -> RuntimeApplyEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name served by this wrapper.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen ABI signature served by this wrapper.
    pub const fn abi_signature(self) -> RuntimeApplyAbiSignature {
        self.entrypoint.abi_signature()
    }

    /// Returns the typed native wrapper function pointer.
    pub const fn function(self) -> RuntimeApplyNativeFn {
        match self.entrypoint {
            RuntimeApplyEntryPoint::AosApply => aos_apply,
        }
    }

    /// Returns the process-local native wrapper address.
    pub const fn address(self) -> RuntimeApplyNativeWrapperAddress {
        self.address
    }

    /// Returns blockers that still prevent final native-export registration.
    pub const fn remaining_export_blockers(self) -> &'static [RuntimeApplyNativeExportBlocker] {
        self.remaining_export_blockers
    }

    /// Returns true when the wrapper has no remaining export blockers.
    pub const fn is_export_ready(self) -> bool {
        self.remaining_export_blockers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, ExitStatus},
    };

    use super::*;

    const APPLY_ABORT_CHILD: &str = "apply::tests::aos_apply_native_wrapper_aborts_child";

    #[test]
    fn apply_native_wrapper_binding_preserves_symbol_abi_and_address() {
        let bindings = runtime_apply_native_wrapper_bindings();

        assert_eq!(bindings.len(), 1);
        let binding = bindings[0];
        assert_eq!(binding.entrypoint(), RuntimeApplyEntryPoint::AosApply);
        assert_eq!(binding.symbol_name(), "aos_apply");
        assert_eq!(
            binding.abi_signature(),
            RuntimeApplyEntryPoint::AosApply.abi_signature()
        );
        assert_eq!(
            binding.function() as RuntimeApplyNativeFn as *mut c_void,
            aos_apply as RuntimeApplyNativeFn as *mut c_void
        );
        assert_eq!(
            binding.address().as_ptr(),
            aos_apply as RuntimeApplyNativeFn as *mut c_void
        );
        assert!(binding.address().is_non_null());
        assert_eq!(
            binding.remaining_export_blockers(),
            [
                RuntimeApplyNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeApplyNativeExportBlocker::ActiveCallRootBindingUnimplemented,
                RuntimeApplyNativeExportBlocker::CallDepthAccountingUnimplemented,
                RuntimeApplyNativeExportBlocker::CallableDispatchBindingUnimplemented,
                RuntimeApplyNativeExportBlocker::TrapTransferUnimplemented,
                RuntimeApplyNativeExportBlocker::NativeValueReturnUnmaterialized,
            ]
            .as_slice()
        );
        assert!(!binding.is_export_ready());
    }

    #[test]
    fn aos_apply_native_wrapper_aborts() {
        assert_child_process_aborts(APPLY_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_apply_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let function = Value::int(1);
        let argument = Value::int(2);

        // SAFETY: `function` and `argument` have valid tag discriminants. The
        // current wrapper is trap-only and aborts before decoding `rt` or
        // inspecting either value.
        let _ = unsafe { aos_apply(rt, function, argument) };
    }

    fn assert_child_process_aborts(test_name: &str) {
        let status = Command::new(env::current_exe().expect("test binary path is available"))
            .args(["--exact", test_name, "--ignored"])
            .status()
            .expect("child test process runs");

        assert_abort_status(status, test_name);
    }

    #[cfg(unix)]
    fn assert_abort_status(status: ExitStatus, test_name: &str) {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(
            status.signal(),
            Some(libc::SIGABRT),
            "{test_name} should abort with SIGABRT, got {status:?}"
        );
    }

    #[cfg(not(unix))]
    fn assert_abort_status(status: ExitStatus, test_name: &str) {
        assert!(
            !status.success(),
            "{test_name} should abort with a non-success status"
        );
    }
}
