//! Forcing C ABI wrappers.
//!
//! Native tier-1 code imports forcing helpers with frozen `(rt, Value)`
//! signatures. This module supplies the first success-path wrappers for that ABI:
//! `aos_blackhole_check` returns for representation-valid non-thunks, and
//! `aos_force` returns already-WHNF values by validated tag inspection.
//! Malformed payloads, thunk-protocol values, and blackhole-protocol values
//! abort until runtime-context decoding, force-root binding, blackhole handling,
//! force-cache integration, and trap transfer exist. Callers must still pass a
//! Rust-valid [`Value`]; an invalid tag discriminant is undefined behavior
//! before these wrappers can inspect it.

use std::{ffi::c_void, process};

use ratchet_oracle::{
    runtime::forcing::{
        RuntimeForcingAbiSignature, RuntimeForcingEntryPoint, RuntimeForcingNativeExportBlocker,
    },
    value::Value,
};

/// Native C ABI function pointer shape for `aos_blackhole_check`.
///
/// The function transfers no error state. It aborts instead of unwinding if a
/// valid [`Value`] carries a malformed payload or must enter the thunk
/// blackhole protocol; final evaluator runtime-context decoding and trap/error
/// transfer remain future work.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_blackhole_check`]. The value argument must be a
/// Rust-valid [`Value`] with a valid tag discriminant. Future blackhole-protocol
/// checks will require a valid runtime pointer, even though the current wrapper
/// aborts thunk values before dereferencing `_rt` or the thunk payload.
pub type RuntimeBlackholeCheckNativeFn = unsafe extern "C" fn(*mut c_void, Value);

/// Native C ABI function pointer shape for `aos_force`.
///
/// The function returns a by-value [`Value`] and transfers no error state. It
/// aborts instead of unwinding if a valid [`Value`] carries a malformed payload
/// or must enter the thunk protocol; final evaluator runtime-context decoding
/// and trap/error transfer remain future work.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_force`]. The value argument must be a Rust-valid
/// [`Value`] with a valid tag discriminant. Any returned heap value must carry a
/// live evaluator-owned heap payload for the value kind. Future thunk-protocol
/// forcing will require a valid runtime pointer, even though the current wrapper
/// aborts thunk values before dereferencing `_rt` or the thunk payload.
pub type RuntimeForceNativeFn = unsafe extern "C" fn(*mut c_void, Value) -> Value;

const BLACKHOLE_CHECK_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[
    RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
];

const FORCE_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[
    RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
    RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
];

/// Checks a representation-valid non-thunk through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_blackhole_check`. It
/// accepts the frozen runtime-context pointer plus a by-value [`Value`], returns
/// immediately when the value has a valid payload and is not a thunk, and aborts
/// for malformed payloads or thunk-tagged values until the evaluator blackhole
/// protocol is bound to native runtime contexts.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. This wrapper only validates representation-level
/// payload invariants and never dereferences heap payloads on its current
/// success path. The current thunk path aborts before decoding `_rt` or
/// dereferencing the thunk payload. The caller must also ensure the host ABI
/// used to call this function matches the frozen `aos_blackhole_check` runtime
/// signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_blackhole_check(_rt: *mut c_void, value: Value) {
    if value.validate_payload().is_ok() && !value.is_thunk() {
        return;
    }
    process::abort()
}

/// Forces an already-WHNF value through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_force`. It accepts the
/// frozen runtime-context pointer plus a by-value [`Value`], returns immediately
/// when the value has a valid payload and is already weak head normal form, and
/// aborts for malformed payloads or thunk-tagged values until the evaluator
/// force protocol is bound to native runtime contexts.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. Any heap payload returned from the WHNF fast path
/// must point at a live evaluator-owned heap object for the value kind; this
/// wrapper only validates representation-level payload invariants. The current
/// thunk path aborts before decoding `_rt` or dereferencing the thunk payload.
/// The caller must also ensure the host ABI used to call this function matches
/// the frozen `aos_force` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_force(_rt: *mut c_void, value: Value) -> Value {
    if value.validate_payload().is_ok() && value.is_whnf() {
        value
    } else {
        process::abort()
    }
}

/// Returns metadata for exported forcing wrappers in symbol order.
pub fn runtime_forcing_native_wrapper_bindings() -> Vec<RuntimeForcingNativeWrapperBinding> {
    vec![
        RuntimeForcingNativeWrapperBinding::aos_blackhole_check(),
        RuntimeForcingNativeWrapperBinding::aos_force(),
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

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, ExitStatus},
    };

    use super::*;
    use ratchet_oracle::{
        compile::IrId,
        eval::{EvalHeap, EvalThunk},
        value::ValueTag,
    };

    const MALFORMED_PAYLOAD_ABORT_CHILD: &str =
        "force::tests::aos_force_native_wrapper_aborts_malformed_payload_child";
    const THUNK_ABORT_CHILD: &str = "force::tests::aos_force_native_wrapper_aborts_thunk_child";
    const BLACKHOLE_MALFORMED_PAYLOAD_ABORT_CHILD: &str =
        "force::tests::aos_blackhole_check_native_wrapper_aborts_malformed_payload_child";
    const BLACKHOLE_THUNK_ABORT_CHILD: &str =
        "force::tests::aos_blackhole_check_native_wrapper_aborts_thunk_child";

    #[repr(C)]
    struct RawValueForTest {
        tag: ValueTag,
        payload: u64,
    }

    #[test]
    fn force_native_wrapper_binding_preserves_symbol_abi_and_address() {
        let bindings = runtime_forcing_native_wrapper_bindings();

        assert_eq!(bindings.len(), 2);
        let blackhole = bindings[0];
        assert_eq!(
            blackhole.entrypoint(),
            RuntimeForcingEntryPoint::AosBlackholeCheck
        );
        assert_eq!(blackhole.symbol_name(), "aos_blackhole_check");
        assert_eq!(
            blackhole.abi_signature(),
            RuntimeForcingEntryPoint::AosBlackholeCheck.abi_signature()
        );
        assert!(matches!(
            blackhole.function(),
            RuntimeForcingNativeWrapperFunction::BlackholeCheck(function)
                if function as RuntimeBlackholeCheckNativeFn as *mut c_void
                    == aos_blackhole_check as RuntimeBlackholeCheckNativeFn as *mut c_void
        ));
        assert_eq!(
            blackhole.address().as_ptr(),
            aos_blackhole_check as RuntimeBlackholeCheckNativeFn as *mut c_void
        );
        assert!(blackhole.address().is_non_null());
        assert_eq!(
            blackhole.remaining_export_blockers(),
            [
                RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
                RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
            ]
            .as_slice()
        );
        assert!(!blackhole.is_export_ready());

        let force = bindings[1];
        assert_eq!(force.entrypoint(), RuntimeForcingEntryPoint::AosForce);
        assert_eq!(force.symbol_name(), "aos_force");
        assert_eq!(
            force.abi_signature(),
            RuntimeForcingEntryPoint::AosForce.abi_signature()
        );
        assert!(matches!(
            force.function(),
            RuntimeForcingNativeWrapperFunction::ForceValue(function)
                if function as RuntimeForceNativeFn as *mut c_void
                    == aos_force as RuntimeForceNativeFn as *mut c_void
        ));
        assert_eq!(
            force.address().as_ptr(),
            aos_force as RuntimeForceNativeFn as *mut c_void
        );
        assert!(force.address().is_non_null());
        assert_eq!(
            force.remaining_export_blockers(),
            [
                RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
                RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
                RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
                RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
            ]
            .as_slice()
        );
        assert!(!force.is_export_ready());
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_returns_for_non_thunks() {
        let rt = std::ptr::null_mut();
        let value = Value::int(42);

        // SAFETY: The current wrapper success path does not dereference `rt`,
        // and the value is not a thunk.
        unsafe { aos_blackhole_check(rt, value) };
    }

    #[test]
    fn aos_force_native_wrapper_returns_whnf_values() {
        let rt = std::ptr::null_mut();
        let expected = Value::int(42);

        // SAFETY: The current wrapper fast path does not dereference `rt`, and
        // the value is already WHNF.
        let actual = unsafe { aos_force(rt, expected) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn force_native_wrapper_binding_function_returns_whnf_values() {
        let binding = runtime_forcing_native_wrapper_bindings()
            .into_iter()
            .find(|binding| binding.entrypoint() == RuntimeForcingEntryPoint::AosForce)
            .expect("force wrapper binding exists");
        let rt = std::ptr::null_mut();
        let expected = Value::bool(true);
        let RuntimeForcingNativeWrapperFunction::ForceValue(function) = binding.function() else {
            panic!("aos_force binding must carry a force-value function");
        };

        // SAFETY: The current wrapper fast path does not dereference `rt`, and
        // the value is already WHNF.
        let actual = unsafe { function(rt, expected) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn blackhole_native_wrapper_binding_function_returns_for_non_thunks() {
        let binding = runtime_forcing_native_wrapper_bindings()
            .into_iter()
            .find(|binding| binding.entrypoint() == RuntimeForcingEntryPoint::AosBlackholeCheck)
            .expect("blackhole-check wrapper binding exists");
        let rt = std::ptr::null_mut();
        let value = Value::bool(false);
        let RuntimeForcingNativeWrapperFunction::BlackholeCheck(function) = binding.function()
        else {
            panic!("aos_blackhole_check binding must carry a blackhole-check function");
        };

        // SAFETY: The current wrapper success path does not dereference `rt`,
        // and the value is not a thunk.
        unsafe { function(rt, value) };
    }

    #[test]
    fn aos_force_native_wrapper_aborts_malformed_payloads() {
        assert_child_process_aborts(MALFORMED_PAYLOAD_ABORT_CHILD);
    }

    #[test]
    fn aos_force_native_wrapper_aborts_thunks() {
        assert_child_process_aborts(THUNK_ABORT_CHILD);
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_aborts_malformed_payloads() {
        assert_child_process_aborts(BLACKHOLE_MALFORMED_PAYLOAD_ABORT_CHILD);
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_aborts_thunks() {
        assert_child_process_aborts(BLACKHOLE_THUNK_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_native_wrapper_aborts_malformed_payload_child() {
        let rt = std::ptr::null_mut();
        let malformed = malformed_bool_value();

        // SAFETY: `malformed` has a valid tag discriminant and no heap payload;
        // its invalid bool payload is the abort behavior under test.
        let _ = unsafe { aos_force(rt, malformed) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_native_wrapper_aborts_thunk_child() {
        let rt = std::ptr::null_mut();
        let (_heap, thunk) = allocated_thunk_value();

        // SAFETY: `thunk` is a valid evaluator-owned thunk value. The current
        // wrapper aborts thunk values before decoding `rt` or dereferencing the
        // thunk payload.
        let _ = unsafe { aos_force(rt, thunk) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_blackhole_check_native_wrapper_aborts_malformed_payload_child() {
        let rt = std::ptr::null_mut();
        let malformed = malformed_bool_value();

        // SAFETY: `malformed` has a valid tag discriminant and no heap payload;
        // its invalid bool payload is the abort behavior under test.
        unsafe { aos_blackhole_check(rt, malformed) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_blackhole_check_native_wrapper_aborts_thunk_child() {
        let rt = std::ptr::null_mut();
        let (_heap, thunk) = allocated_thunk_value();

        // SAFETY: `thunk` is a valid evaluator-owned thunk value. The current
        // wrapper aborts thunk values before decoding `rt` or dereferencing the
        // thunk payload.
        unsafe { aos_blackhole_check(rt, thunk) };
    }

    fn malformed_bool_value() -> Value {
        let raw = RawValueForTest {
            tag: ValueTag::Bool,
            payload: 2,
        };
        // SAFETY: `RawValueForTest` matches `Value`'s repr(C) tag/payload
        // layout, and the tag discriminant is valid. The malformed inline
        // payload is the abort behavior under test.
        unsafe { std::mem::transmute::<RawValueForTest, Value>(raw) }
    }

    fn allocated_thunk_value() -> (EvalHeap, Value) {
        let mut heap = EvalHeap::new();
        let thunk = heap
            .alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("test thunk allocates");
        (heap, thunk)
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
            "expected {test_name} to abort by signal, got {status:?}"
        );
    }

    #[cfg(not(unix))]
    fn assert_abort_status(status: ExitStatus, test_name: &str) {
        assert!(
            !status.success(),
            "expected {test_name} to abort, got {status:?}"
        );
    }
}
