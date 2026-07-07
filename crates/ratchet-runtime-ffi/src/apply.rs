//! Call-control C ABI wrappers.
//!
//! Native tier-1 code imports the generic apply helper with the frozen
//! `(rt, Value function, Value arg) -> Value` signature. This module supplies a
//! success-path wrapper for that ABI: `aos_apply` decodes a scoped
//! [`RuntimeApplyContext`], roots imported function and argument values through
//! the safe tree-walk helper, and dispatches lambda, functor, and first-class
//! primop application. Failures still abort until native trap transfer exists.

use std::{ffi::c_void, process};

use ratchet_oracle::{
    compile::IrId,
    eval::tree_walk::TreeWalk,
    runtime::apply::{
        RuntimeApplyAbiSignature, RuntimeApplyEntryPoint, RuntimeApplyNativeExportBlocker,
        rust_callable_aos_apply,
    },
    syntax::Span,
    value::Value,
};

use crate::context::{RuntimeJitContext, with_native_runtime_context};
use crate::trap::{RuntimeTrap, record_runtime_trap, runtime_trap_sentinel_value};

/// Native C ABI function pointer shape for `aos_apply`.
///
/// The function returns a by-value [`Value`] and never unwinds across the ABI
/// boundary. A call-control evaluator error is transferred through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// runtime pointer or malformed payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_apply`]. The function and argument values must be
/// Rust-valid [`Value`] instances with valid tag discriminants and heap payloads
/// reachable from the evaluator encoded by the runtime pointer. Calls must pass
/// a valid pinned [`RuntimeApplyContext`] runtime pointer.
pub type RuntimeApplyNativeFn = unsafe extern "C" fn(*mut c_void, Value, Value) -> Value;

// Trap transfer is implemented for the apply wrapper, so no wrapper-local
// blocker remains. The oracle native-export gate stays authoritative for final
// admission (it still tracks `MissingFinalExportedWrapper` and the rest).
const APPLY_REMAINING_EXPORT_BLOCKERS: &[RuntimeApplyNativeExportBlocker] = &[];

/// Applies a callable value through the frozen apply native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_apply`. It accepts the
/// frozen runtime-context pointer plus by-value function and argument values,
/// validates their representation-level payloads, decodes `rt` as a
/// [`RuntimeApplyContext`], roots the imported values through the safe tree-walk
/// apply helper, and returns the application result [`Value`]. A call-control
/// evaluator error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer or malformed value payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// `function` and `argument` must be Rust-valid [`Value`] instances with valid
/// tag discriminants before crossing this ABI boundary. `rt` must be a non-null
/// pointer produced from a pinned live [`RuntimeApplyContext`] whose wrapped
/// evaluator and IR allocation outlive the call. The context must not move
/// while the pointer is used. The caller must uphold exclusive mutable access to
/// the wrapped evaluator for the duration of the call. Any heap payload in
/// `function` or `argument` must be reachable from that evaluator. The caller
/// must also ensure the host ABI used to call this function matches the frozen
/// `aos_apply` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_apply(rt: *mut c_void, function: Value, argument: Value) -> Value {
    if function.validate_payload().is_err() || argument.validate_payload().is_err() {
        process::abort()
    }
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // RuntimeApplyContext pointer contract documented on this function.
    let applied = unsafe {
        with_native_runtime_context(rt, |eval, id, span| {
            aos_apply_success_path(eval, id, span, function, argument)
        })
    };
    applied
}

fn aos_apply_success_path(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    function: Value,
    argument: Value,
) -> Value {
    match rust_callable_aos_apply(eval, id, span, function, argument) {
        Ok(value) => value,
        Err(error) => {
            record_runtime_trap(RuntimeTrap::Apply(error));
            runtime_trap_sentinel_value()
        }
    }
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

/// Metadata for one apply native wrapper.
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

    /// Returns wrapper-local blockers that still prevent this body from being
    /// export-ready.
    pub const fn remaining_export_blockers(self) -> &'static [RuntimeApplyNativeExportBlocker] {
        self.remaining_export_blockers
    }

    /// Returns true when the wrapper has no remaining export blockers.
    pub const fn is_export_ready(self) -> bool {
        self.remaining_export_blockers.is_empty()
    }
}

/// Shared runtime context accepted by apply native wrappers.
pub type RuntimeApplyContext<'eval> = RuntimeJitContext<'eval>;

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, ExitStatus},
    };

    use super::*;
    use ratchet_oracle::{
        compile::resolve, runtime::forcing::rust_callable_aos_force, syntax::parse_str,
        value::ValueTag,
    };

    const APPLY_MALFORMED_FUNCTION_ABORT_CHILD: &str =
        "apply::tests::aos_apply_native_wrapper_aborts_malformed_function_child";
    const APPLY_MALFORMED_ARGUMENT_ABORT_CHILD: &str =
        "apply::tests::aos_apply_native_wrapper_aborts_malformed_argument_child";
    const APPLY_NULL_CONTEXT_ABORT_CHILD: &str =
        "apply::tests::aos_apply_native_wrapper_aborts_on_null_context_child";
    const APPLY_TREE_WALK_ERROR_ABORT_CHILD: &str =
        "apply::tests::aos_apply_native_wrapper_aborts_on_tree_walk_error_child";

    #[repr(C)]
    struct RawValueForTest {
        tag: ValueTag,
        payload: u64,
    }

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
        assert!(binding.remaining_export_blockers().is_empty());
        assert!(binding.is_export_ready());
    }

    #[test]
    fn apply_native_wrapper_blockers_are_clear_while_oracle_gate_remains() {
        let binding = runtime_apply_native_wrapper_bindings()
            .into_iter()
            .next()
            .expect("apply wrapper binding exists");
        let oracle_blockers = RuntimeApplyEntryPoint::AosApply.native_export_blockers();

        // Trap transfer is implemented, so the wrapper carries no remaining
        // wrapper-local blocker, while the oracle native-export gate is
        // unchanged and remains authoritative for final admission.
        assert!(binding.remaining_export_blockers().is_empty());
        assert!(binding.is_export_ready());
        assert!(
            oracle_blockers.contains(&RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper)
        );
        assert!(
            oracle_blockers.contains(&RuntimeApplyNativeExportBlocker::TrapTransferUnimplemented)
        );
    }

    #[test]
    fn aos_apply_native_wrapper_applies_lambda_values() {
        let source = "x: x + 1";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let function = eval.eval_root().expect("lambda evaluates");
        let mut context = std::pin::pin!(RuntimeApplyContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and `function` belongs to that
        // evaluator.
        let actual = unsafe { aos_apply(rt, function, Value::int(41)) };

        drop(context);
        let forced = rust_callable_aos_force(&mut eval, ir.root, span, actual)
            .expect("application result forces");

        assert_eq!(forced.as_int(), Ok(42));
    }

    #[test]
    fn aos_apply_native_wrapper_applies_attrset_functor_values() {
        let source = "{ __functor = self: x: x + 2; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let functor = eval.eval_root().expect("functor attrset evaluates");
        let mut context = std::pin::pin!(RuntimeApplyContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and `functor` belongs to that
        // evaluator.
        let functor_actual = unsafe { aos_apply(rt, functor, Value::int(40)) };

        drop(context);
        let forced = rust_callable_aos_force(&mut eval, ir.root, span, functor_actual)
            .expect("functor application result forces");

        assert_eq!(forced.as_int(), Ok(42));
    }

    #[test]
    fn aos_apply_native_wrapper_applies_first_class_primop_values() {
        let source = "builtins.add";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let function = eval.eval_root().expect("primop evaluates");
        let mut context = std::pin::pin!(RuntimeApplyContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and `function` belongs to that
        // evaluator.
        let partial = unsafe { aos_apply(rt, function, Value::int(40)) };
        // SAFETY: The same pinned context remains live and `partial` is the
        // evaluator-owned result of the first application.
        let primop_actual = unsafe { aos_apply(rt, partial, Value::int(2)) };

        assert_eq!(primop_actual.as_int(), Ok(42));
    }

    #[test]
    fn apply_native_wrapper_binding_function_applies_lambda_values() {
        let binding = runtime_apply_native_wrapper_bindings()
            .into_iter()
            .next()
            .expect("apply wrapper binding exists");
        let source = "x: x + 1";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let function = eval.eval_root().expect("lambda evaluates");
        let mut context = std::pin::pin!(RuntimeApplyContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and `function` belongs to that
        // evaluator.
        let binding_actual = unsafe { binding.function()(rt, function, Value::int(41)) };

        drop(context);
        let forced = rust_callable_aos_force(&mut eval, ir.root, span, binding_actual)
            .expect("binding application result forces");

        assert_eq!(forced.as_int(), Ok(42));
    }

    #[test]
    fn aos_apply_native_wrapper_aborts_malformed_function() {
        assert_child_process_aborts(APPLY_MALFORMED_FUNCTION_ABORT_CHILD);
    }

    #[test]
    fn aos_apply_native_wrapper_aborts_malformed_argument() {
        assert_child_process_aborts(APPLY_MALFORMED_ARGUMENT_ABORT_CHILD);
    }

    #[test]
    fn aos_apply_native_wrapper_aborts_on_null_context() {
        assert_child_process_aborts(APPLY_NULL_CONTEXT_ABORT_CHILD);
    }

    #[test]
    fn aos_apply_native_wrapper_aborts_on_tree_walk_error() {
        assert_child_process_aborts(APPLY_TREE_WALK_ERROR_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_apply_native_wrapper_aborts_malformed_function_child() {
        let source = "x: x";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeApplyContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let malformed = malformed_bool_value();
        let argument = Value::int(1);

        // SAFETY: The pinned context and its evaluator are live for the call.
        // `malformed` has a valid tag discriminant and no heap payload; its
        // invalid bool payload is the abort behavior under test.
        let _ = unsafe { aos_apply(rt, malformed, argument) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_apply_native_wrapper_aborts_malformed_argument_child() {
        let source = "x: x";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let function = eval.eval_root().expect("lambda evaluates");
        let mut context = std::pin::pin!(RuntimeApplyContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let malformed = malformed_bool_value();

        // SAFETY: The pinned context and its evaluator are live for the call.
        // `malformed` has a valid tag discriminant and no heap payload; its
        // invalid bool payload is the abort behavior under test.
        let _ = unsafe { aos_apply(rt, function, malformed) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_apply_native_wrapper_aborts_on_null_context_child() {
        let rt = std::ptr::null_mut();
        let function = Value::int(1);
        let argument = Value::int(2);

        // SAFETY: `function` and `argument` have valid tag discriminants. The
        // test deliberately passes a null runtime context to verify abort
        // behavior before any apply operation can run.
        let _ = unsafe { aos_apply(rt, function, argument) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_apply_native_wrapper_aborts_on_tree_walk_error_child() {
        let source = "null";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeApplyContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let function = Value::int(1);

        // SAFETY: The pinned context is live, and the non-callable function
        // value is the tree-walk error behavior under test.
        let _ = unsafe { aos_apply(rt, function, Value::int(2)) };
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

    fn lower_source(source: &str) -> ratchet_oracle::compile::Ir {
        aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers")
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
