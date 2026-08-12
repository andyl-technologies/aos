//! Write-barrier C ABI wrappers.
//!
//! Native tier-1 code imports the GC write barrier with a frozen
//! `(rt, thunk, Value)` signature. This module supplies the first trap-only
//! wrapper for that ABI: `aos_gc_write_barrier` aborts for every call until
//! runtime-context decoding, GC-state extraction, thunk pointer decoding, value
//! decoding, trap transfer, and safe barrier dispatch exist. That is the only
//! sound behavior today because the active one-shot versus daemon-generational
//! barrier policy is stored in the runtime context.

use std::{ffi::c_void, process};

use ratchet_oracle::{
    runtime::barrier::{
        RuntimeWriteBarrierAbiSignature, RuntimeWriteBarrierEntryPoint,
        RuntimeWriteBarrierNativeExportBlocker,
    },
    value::Value,
};

/// Native C ABI function pointer shape for `aos_gc_write_barrier`.
///
/// The function returns no value and transfers no error state. It aborts instead
/// of unwinding until the evaluator runtime context can expose the active heap
/// strategy, remembered set, optional card table, source thunk, and published
/// value to the safe write-barrier dispatch path.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_gc_write_barrier`]. The value argument must be a
/// Rust-valid [`Value`] with a valid tag discriminant. The current trap-only
/// wrapper aborts before decoding `_rt`, dereferencing `_thunk`, or inspecting
/// `value`; future barrier dispatch will require all three arguments to be
/// valid for the active evaluator runtime.
pub type RuntimeWriteBarrierNativeFn = unsafe extern "C" fn(*mut c_void, *mut c_void, Value);

const WRITE_BARRIER_REMAINING_EXPORT_BLOCKERS: &[RuntimeWriteBarrierNativeExportBlocker] = &[
    RuntimeWriteBarrierNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::NativeThunkPointerDecodeUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::NativeValueDecodeUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented,
];

/// Aborts through the frozen write-barrier native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_gc_write_barrier`. It
/// accepts the frozen runtime-context pointer, source-thunk pointer, and
/// by-value [`Value`], then aborts until native wrappers can safely select and
/// dispatch the evaluator's active write barrier. Returning today would be
/// unsound because skipping the daemon-generational barrier can lose remembered
/// edges.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. The current wrapper aborts before decoding `_rt`,
/// dereferencing `_thunk`, or inspecting `value`. The caller must also ensure the
/// host ABI used to call this function matches the frozen `aos_gc_write_barrier`
/// runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_gc_write_barrier(
    _rt: *mut c_void,
    _thunk: *mut c_void,
    _value: Value,
) {
    process::abort()
}

/// Returns metadata for exported write-barrier wrappers in symbol order.
pub fn runtime_write_barrier_native_wrapper_bindings()
-> Vec<RuntimeWriteBarrierNativeWrapperBinding> {
    vec![RuntimeWriteBarrierNativeWrapperBinding::aos_gc_write_barrier()]
}

/// Process-local address metadata for one write-barrier native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierNativeWrapperAddress {
    ptr: *mut c_void,
}

impl RuntimeWriteBarrierNativeWrapperAddress {
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

/// Metadata for one trap-only write-barrier native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierNativeWrapperBinding {
    entrypoint: RuntimeWriteBarrierEntryPoint,
    address: RuntimeWriteBarrierNativeWrapperAddress,
    remaining_export_blockers: &'static [RuntimeWriteBarrierNativeExportBlocker],
}

impl RuntimeWriteBarrierNativeWrapperBinding {
    fn aos_gc_write_barrier() -> Self {
        Self {
            entrypoint: RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier,
            address: RuntimeWriteBarrierNativeWrapperAddress::new(
                aos_gc_write_barrier as RuntimeWriteBarrierNativeFn as *mut c_void,
            ),
            remaining_export_blockers: WRITE_BARRIER_REMAINING_EXPORT_BLOCKERS,
        }
    }

    /// Returns the write-barrier entry point served by this wrapper.
    pub const fn entrypoint(self) -> RuntimeWriteBarrierEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name served by this wrapper.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen ABI signature implemented by this wrapper.
    pub const fn abi_signature(self) -> RuntimeWriteBarrierAbiSignature {
        self.entrypoint.abi_signature()
    }

    /// Returns the typed native wrapper function pointer.
    pub const fn function(self) -> RuntimeWriteBarrierNativeFn {
        match self.entrypoint {
            RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier => aos_gc_write_barrier,
        }
    }

    /// Returns the process-local native wrapper address.
    pub const fn address(self) -> RuntimeWriteBarrierNativeWrapperAddress {
        self.address
    }

    /// Returns blockers that still prevent final native-export registration.
    pub const fn remaining_export_blockers(
        self,
    ) -> &'static [RuntimeWriteBarrierNativeExportBlocker] {
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

    const WRITE_BARRIER_ABORT_CHILD: &str =
        "barrier::tests::aos_gc_write_barrier_native_wrapper_aborts_child";

    #[test]
    fn write_barrier_native_wrapper_binding_preserves_symbol_abi_and_address() {
        let bindings = runtime_write_barrier_native_wrapper_bindings();

        assert_eq!(bindings.len(), 1);
        let binding = bindings[0];
        assert_eq!(
            binding.entrypoint(),
            RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier
        );
        assert_eq!(binding.symbol_name(), "aos_gc_write_barrier");
        assert_eq!(
            binding.abi_signature(),
            RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier.abi_signature()
        );
        assert_eq!(
            binding.function() as RuntimeWriteBarrierNativeFn as *mut c_void,
            aos_gc_write_barrier as RuntimeWriteBarrierNativeFn as *mut c_void
        );
        assert_eq!(
            binding.address().as_ptr(),
            aos_gc_write_barrier as RuntimeWriteBarrierNativeFn as *mut c_void
        );
        assert!(binding.address().is_non_null());
        assert_eq!(
            binding.remaining_export_blockers(),
            [
                RuntimeWriteBarrierNativeExportBlocker::RuntimeContextAbiUnimplemented,
                RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented,
                RuntimeWriteBarrierNativeExportBlocker::NativeThunkPointerDecodeUnimplemented,
                RuntimeWriteBarrierNativeExportBlocker::NativeValueDecodeUnimplemented,
                RuntimeWriteBarrierNativeExportBlocker::TrapTransferUnimplemented,
                RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented,
            ]
            .as_slice()
        );
        assert!(!binding.is_export_ready());
    }

    #[test]
    fn write_barrier_native_wrapper_remaining_blockers_extend_oracle_export_gate() {
        let binding = runtime_write_barrier_native_wrapper_bindings()
            .into_iter()
            .next()
            .expect("write-barrier wrapper binding exists");
        let oracle_blockers =
            RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier.native_export_blockers();
        let expected_oracle_blockers = [
            RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeWriteBarrierNativeExportBlocker::RuntimeContextAbiUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::NativeThunkPointerDecodeUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::NativeValueDecodeUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::TrapTransferUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented,
        ];

        assert_eq!(oracle_blockers, expected_oracle_blockers.as_slice());
        assert_eq!(binding.remaining_export_blockers(), &oracle_blockers[1..]);
    }

    #[test]
    fn aos_gc_write_barrier_native_wrapper_aborts() {
        assert_child_process_aborts(WRITE_BARRIER_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_gc_write_barrier_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let thunk = std::ptr::null_mut();
        let value = Value::int(1);

        // SAFETY: `value` has a valid tag discriminant. The current wrapper is
        // trap-only and aborts before decoding `rt`, dereferencing `thunk`, or
        // inspecting `value`.
        unsafe { aos_gc_write_barrier(rt, thunk, value) };
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

        assert!(
            status.signal().is_some(),
            "{test_name} should abort by signal, got {status:?}"
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
