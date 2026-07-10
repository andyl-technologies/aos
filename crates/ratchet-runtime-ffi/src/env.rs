//! Environment-access C ABI wrappers.
//!
//! The tree-walk evaluator stores lexical captures in linked
//! [`ratchet_oracle::eval::EvalFrame`]s or FV-5 flat closure tails. Native
//! tier-1 code imports `aos_env_get` with the frozen `(env, slot) -> Value`
//! signature, where `env` is an opaque pointer to that frame and `slot` is the
//! captured local index. This module supplies the first success-path wrapper for
//! that ABI and metadata describing what still prevents final native export
//! registration.

use std::ffi::c_void;

use ratchet_oracle::{
    eval::{EvalEnv, EvalEnvError, tree_walk::TreeWalk},
    runtime::env::{
        RuntimeEnvAccessAbiSignature, RuntimeEnvAccessEntryPoint,
        RuntimeEnvAccessNativeExportBlocker,
    },
    value::Value,
};

use crate::context::with_native_runtime_env_context;
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
/// opaque environment pointer as a pinned runtime context, resolves the
/// innermost conceptual frame through the same hybrid-environment API as the
/// tree-walk oracle, and returns the copied [`Value`] by value. An access error
/// is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// environment pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// `env` must be the opaque pointer produced from a pinned live runtime context
/// carrying the dispatched [`EvalEnv`]. The wrapped evaluator and environment
/// must outlive the call, and `slot` must be in bounds. The caller must also
/// ensure the host ABI matches the frozen `aos_env_get` signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_env_get(env: *mut c_void, slot: u32) -> Value {
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // pinned runtime-environment contract documented on this function.
    unsafe { // aos_env_get runtime-environment decode
        with_native_runtime_env_context(env, |eval, env, _, _| {
            innermost_frame_slot(eval, env, slot)
        })
    }
}

/// Native C ABI function-pointer shape for `aos_upval_get`.
///
/// The function returns a by-value [`Value`] and never unwinds. A bad upvalue
/// depth or a frame-access error is transferred through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope it aborts. A null
/// environment pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same pointer, lifetime, borrow,
/// slot-bounds, and host-ABI obligations documented on [`aos_upval_get`].
pub type RuntimeUpvalGetNativeFn = unsafe extern "C" fn(*mut c_void, u32, u32) -> Value;

/// Reads one captured upvalue slot through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_upval_get`. It decodes
/// the opaque environment pointer as a pinned runtime context, walks `depth`
/// conceptual frames up through its hybrid [`EvalEnv`], and reads `slot`. A
/// depth past the captured frame
/// stack is transferred as a deopt and a frame-access error as an environment
/// trap through the active [`crate::trap::RuntimeTrapScope`]; the wrapper then
/// returns [`runtime_trap_sentinel_value`]. A null pointer always aborts.
///
/// # Safety
///
/// `env` must be the opaque pointer produced from a pinned live runtime context
/// carrying the dispatched [`EvalEnv`]. The wrapped evaluator and environment
/// must outlive the call. The caller must also ensure the host ABI matches the
/// frozen `aos_upval_get` signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_upval_get(env: *mut c_void, depth: u32, slot: u32) -> Value {
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // pinned runtime-environment contract documented on this function.
    unsafe { // aos_upval_get runtime-environment decode
        with_native_runtime_env_context(env, |eval, env, _, _| {
            upval_frame_slot(eval, env, depth, slot)
        })
    }
}

/// Returns the process-local address of the [`aos_upval_get`] native wrapper.
///
/// Tier-1 registration hands this to the JIT as the `aos_upval_get` symbol
/// candidate so a compiled upvalue read resolves to this wrapper.
pub fn aos_upval_get_native_wrapper_address() -> *mut c_void {
    aos_upval_get as RuntimeUpvalGetNativeFn as *mut c_void
}

/// Reads `slot` from the innermost frame of `env`, trapping when there is none.
fn innermost_frame_slot(eval: &TreeWalk, env: &EvalEnv, slot: u32) -> Value {
    let value = env
        .frame_count()
        .checked_sub(1)
        .and_then(|frame| eval.tier2_captured_value_at_index(env, frame, slot));
    match value {
        Some(value) => value,
        None => env_access_trap(slot),
    }
}

/// Reads `slot` from the frame `depth` levels above the innermost frame.
///
/// A `depth` at or beyond the captured frame count is a control error the tree
/// walk raises as an invalid-upvalue-depth error, so it is transferred as a
/// deopt: the engine re-runs the body on the tree walk to reproduce the exact
/// error.
fn upval_frame_slot(eval: &TreeWalk, env: &EvalEnv, depth: u32, slot: u32) -> Value {
    let index = env
        .frame_count()
        .checked_sub(1)
        .and_then(|last| last.checked_sub(depth as usize));
    match index.and_then(|index| eval.tier2_captured_value_at_index(env, index, slot)) {
        Some(value) => value,
        None => {
            record_runtime_trap(RuntimeTrap::Deopt);
            runtime_trap_sentinel_value()
        }
    }
}

/// Reads `slot` from `frame`, transferring a frame-access error as a trap.
fn env_access_trap(slot: u32) -> Value {
    record_runtime_trap(RuntimeTrap::Env(EvalEnvError::SlotOutOfBounds { slot, slots: 0 }));
    runtime_trap_sentinel_value()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratchet_oracle::eval::EvalFrame;

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
        let env = EvalEnv::capture(&[frame]).expect("env captures");
        let ir = lower_source("null");
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(crate::context::RuntimeJitContext::new_with_env(
            &mut eval, ir.root, ratchet_oracle::syntax::Span::new(0, 4), &env,
        ));
        let env_ptr = context.as_mut().as_mut_ptr();
        // SAFETY: The env is live for the call, the slot is in bounds, and no
        // mutable borrow is active.
        let actual = unsafe { aos_env_get(env_ptr, 1) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn aos_upval_get_native_wrapper_reads_outer_frame_slots() {
        let outer = EvalFrame::new(1).expect("outer frame allocates");
        let inner = EvalFrame::new(1).expect("inner frame allocates");
        let outer_value = Value::int(7);
        let inner_value = Value::int(9);
        outer.set(0, outer_value).expect("outer slot stores");
        inner.set(0, inner_value).expect("inner slot stores");
        // Frames are ordered outermost to innermost.
        let env = EvalEnv::capture(&[outer, inner]).expect("env captures");
        let ir = lower_source("null");
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(crate::context::RuntimeJitContext::new_with_env(
            &mut eval, ir.root, ratchet_oracle::syntax::Span::new(0, 4), &env,
        ));
        let env_ptr = context.as_mut().as_mut_ptr();

        // SAFETY: The env is live, depths/slots are in bounds, no mutable borrow.
        let innermost = unsafe { aos_upval_get(env_ptr, 0, 0) };
        let parent = unsafe { aos_upval_get(env_ptr, 1, 0) };

        assert!(innermost.raw_eq(inner_value));
        assert!(parent.raw_eq(outer_value));
    }

    #[test]
    fn aos_upval_get_native_wrapper_traps_on_bad_depth() {
        let env = EvalEnv::capture(&[EvalFrame::new(1).expect("frame allocates")])
            .expect("env captures");
        let ir = lower_source("null");
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(crate::context::RuntimeJitContext::new_with_env(
            &mut eval, ir.root, ratchet_oracle::syntax::Span::new(0, 4), &env,
        ));
        let env_ptr = context.as_mut().as_mut_ptr();

        let scope = crate::trap::RuntimeTrapScope::new();
        // SAFETY: The env is live; depth 5 exceeds the single captured frame.
        let value = unsafe { aos_upval_get(env_ptr, 5, 0) };

        assert!(value.raw_eq(runtime_trap_sentinel_value()));
        assert_eq!(scope.take_trap(), Some(RuntimeTrap::Deopt));
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
        let env = EvalEnv::capture(&[frame]).expect("env captures");
        let ir = lower_source("null");
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(crate::context::RuntimeJitContext::new_with_env(
            &mut eval, ir.root, ratchet_oracle::syntax::Span::new(0, 4), &env,
        ));
        let env_ptr = context.as_mut().as_mut_ptr();
        // SAFETY: The env is live for the call, the slot is in bounds, and no
        // mutable borrow is active.
        let actual = unsafe { (binding.function())(env_ptr, 0) };

        assert!(actual.raw_eq(expected));
    }

    fn lower_source(source: &str) -> ratchet_oracle::compile::Ir {
        let parsed = ratchet_oracle::syntax::parse_str(source).expect("source parses");
        let resolved = ratchet_oracle::compile::resolve(parsed).expect("source resolves");
        aos_nix_dialect::nix_lower(resolved).expect("source lowers")
    }
}
