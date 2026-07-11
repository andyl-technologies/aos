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
mod tests {
    use std::{
        env,
        process::{Command, ExitStatus},
    };

    use super::*;
    use ratchet_oracle::{compile::resolve, eval::ForceClaim, syntax::parse_str, value::ValueTag};

    const MALFORMED_PAYLOAD_ABORT_CHILD: &str =
        "force::tests::aos_force_native_wrapper_aborts_malformed_payload_child";
    const FORCE_NULL_CONTEXT_ABORT_CHILD: &str =
        "force::tests::aos_force_native_wrapper_aborts_on_null_context_child";
    const FORCE_TREE_WALK_ERROR_ABORT_CHILD: &str =
        "force::tests::aos_force_native_wrapper_aborts_on_tree_walk_error_child";
    const FORCE_DEEP_MALFORMED_PAYLOAD_ABORT_CHILD: &str =
        "force::tests::aos_force_deep_native_wrapper_aborts_malformed_payload_child";
    const FORCE_DEEP_NULL_CONTEXT_ABORT_CHILD: &str =
        "force::tests::aos_force_deep_native_wrapper_aborts_on_null_context_child";
    const FORCE_DEEP_TREE_WALK_ERROR_ABORT_CHILD: &str =
        "force::tests::aos_force_deep_native_wrapper_aborts_on_tree_walk_error_child";
    const BLACKHOLE_MALFORMED_PAYLOAD_ABORT_CHILD: &str =
        "force::tests::aos_blackhole_check_native_wrapper_aborts_malformed_payload_child";
    const BLACKHOLE_NULL_CONTEXT_ABORT_CHILD: &str =
        "force::tests::aos_blackhole_check_native_wrapper_aborts_on_null_context_child";
    const BLACKHOLE_BLACKHOLED_THUNK_ABORT_CHILD: &str =
        "force::tests::aos_blackhole_check_native_wrapper_aborts_blackholed_thunk_child";

    #[repr(C)]
    struct RawValueForTest {
        tag: ValueTag,
        payload: u64,
    }

    #[test]
    fn force_native_wrapper_binding_preserves_symbol_abi_and_address() {
        let bindings = runtime_forcing_native_wrapper_bindings();

        assert_eq!(bindings.len(), 3);
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
        assert!(blackhole.remaining_export_blockers().is_empty());
        assert!(blackhole.is_export_ready());

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
        assert!(force.remaining_export_blockers().is_empty());
        assert!(force.is_export_ready());

        let force_deep = bindings[2];
        assert_eq!(
            force_deep.entrypoint(),
            RuntimeForcingEntryPoint::AosForceDeep
        );
        assert_eq!(force_deep.symbol_name(), "aos_force_deep");
        assert_eq!(
            force_deep.abi_signature(),
            RuntimeForcingEntryPoint::AosForceDeep.abi_signature()
        );
        assert!(matches!(
            force_deep.function(),
            RuntimeForcingNativeWrapperFunction::ForceDeepValue(function)
                if function as RuntimeForceNativeFn as *mut c_void
                    == aos_force_deep as RuntimeForceNativeFn as *mut c_void
        ));
        assert_eq!(
            force_deep.address().as_ptr(),
            aos_force_deep as RuntimeForceNativeFn as *mut c_void
        );
        assert!(force_deep.address().is_non_null());
        assert!(force_deep.remaining_export_blockers().is_empty());
        assert!(force_deep.is_export_ready());
    }

    #[test]
    fn force_native_wrapper_blockers_are_clear_while_oracle_gate_remains() {
        for binding in runtime_forcing_native_wrapper_bindings() {
            let oracle_blockers = binding.entrypoint().native_export_blockers();

            // Trap transfer is implemented, so the wrapper carries no remaining
            // wrapper-local blocker and reports as export-ready.
            assert!(
                binding.remaining_export_blockers().is_empty(),
                "{} runtime-FFI wrapper has no remaining wrapper-local blocker",
                binding.symbol_name()
            );
            assert!(binding.is_export_ready());

            // The oracle native-export gate is authoritative for final
            // admission and is unchanged by wrapper trap transfer: it still
            // tracks the missing final exported wrapper and the trap-transfer
            // obligation until `aos-nix` formally admits the export.
            assert!(
                oracle_blockers
                    .contains(&RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper),
                "{} oracle export gate still tracks final admission",
                binding.symbol_name()
            );
            assert!(
                oracle_blockers
                    .contains(&RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented),
                "{} oracle export gate is unchanged by wrapper trap transfer",
                binding.symbol_name()
            );
        }
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_returns_for_non_thunks() {
        let source = "42";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let value = Value::int(42);

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the value is not a thunk.
        unsafe { aos_blackhole_check(rt, value) };
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_returns_for_suspended_thunks() {
        let source = "[ (1 + 2) ]";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("list evaluates");
        let thunk = {
            let list = eval.heap().get_list(root).expect("root list is heap-owned");
            list.get(0).expect("element exists")
        };
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the suspended thunk belongs
        // to that evaluator.
        unsafe { aos_blackhole_check(rt, thunk) };
    }

    #[test]
    fn aos_force_native_wrapper_returns_whnf_values() {
        let source = "42";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let expected = Value::int(42);

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the value is already WHNF.
        let actual = unsafe { aos_force(rt, expected) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn aos_force_native_wrapper_forces_tree_walk_thunks() {
        let source = "{ value = 40 + 2; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut symbols = ir.symbols.clone();
        let key = symbols.intern(b"value").expect("value symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("attrset evaluates");
        let thunk = eval
            .heap()
            .get_attrs(root)
            .expect("root is heap-owned attrs")
            .get(key)
            .expect("value binding exists");
        assert_eq!(thunk.tag(), ValueTag::Thunk);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the thunk belongs to that
        // evaluator.
        let forced = unsafe { aos_force(rt, thunk) };

        assert_eq!(forced.as_int(), Ok(42));
    }

    #[test]
    fn aos_force_deep_native_wrapper_returns_deep_force_leaf_values() {
        let source = "null";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let expected = Value::null();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the value is already a
        // deep-forced WHNF leaf.
        let actual = unsafe { aos_force_deep(rt, expected) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn aos_force_deep_native_wrapper_returns_heap_leaf_values() {
        let source = "\"force-deep-leaf\"";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let heap_expected = eval.eval_root().expect("string evaluates");
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the value is an
        // evaluator-owned non-container WHNF heap leaf.
        let heap_actual = unsafe { aos_force_deep(rt, heap_expected) };

        assert!(heap_actual.raw_eq(heap_expected));
    }

    #[test]
    fn aos_force_deep_native_wrapper_forces_nested_container_thunks() {
        let source = "[ [ (1 + 2) ] ]";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("list evaluates");
        let outer_element = {
            let list = eval.heap().get_list(root).expect("root list is heap-owned");
            list.get(0).expect("outer element exists")
        };
        assert!(
            eval.heap()
                .get_thunk(outer_element)
                .expect("outer element is a suspended thunk")
                .cell()
                .cached_value()
                .expect("suspended outer thunk is readable")
                .is_none()
        );
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the root list belongs to that
        // evaluator.
        let deeply_forced = unsafe { aos_force_deep(rt, root) };

        drop(context);
        let inner_list_value = eval
            .heap()
            .get_thunk(outer_element)
            .expect("outer element remains a thunk")
            .cell()
            .cached_value()
            .expect("outer thunk cache is readable")
            .expect("outer thunk caches the forced inner list");
        let inner_element = {
            let inner_list = eval
                .heap()
                .get_list(inner_list_value)
                .expect("inner list is heap-owned");
            inner_list.get(0).expect("inner element exists")
        };
        let inner_cached_value = eval
            .heap()
            .get_thunk(inner_element)
            .expect("inner element remains a thunk")
            .cell()
            .cached_value()
            .expect("inner thunk cache is readable")
            .expect("inner thunk caches its forced scalar");

        assert!(deeply_forced.raw_eq(root));
        assert_eq!(inner_cached_value.as_int(), Ok(3));
    }

    #[test]
    fn aos_force_deep_native_wrapper_forces_nested_attrset_thunks() {
        let source = "{ a = { b = 1 + 2; }; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut symbols = ir.symbols.clone();
        let a = symbols.intern(b"a").expect("a symbol exists");
        let b = symbols.intern(b"b").expect("b symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("attrset evaluates");
        let a_thunk = {
            let attrs = eval
                .heap()
                .get_attrs(root)
                .expect("root attrset is heap-owned");
            attrs.get(a).expect("a binding exists")
        };
        assert!(
            eval.heap()
                .get_thunk(a_thunk)
                .expect("a binding is a suspended thunk")
                .cell()
                .cached_value()
                .expect("suspended a thunk is readable")
                .is_none()
        );
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the root attrset belongs to
        // that evaluator.
        let attrset_deeply_forced = unsafe { aos_force_deep(rt, root) };

        drop(context);
        let nested_attrs_value = eval
            .heap()
            .get_thunk(a_thunk)
            .expect("a binding remains a thunk")
            .cell()
            .cached_value()
            .expect("a thunk cache is readable")
            .expect("a thunk caches the forced nested attrset");
        let b_thunk = {
            let nested_attrs = eval
                .heap()
                .get_attrs(nested_attrs_value)
                .expect("nested attrset is heap-owned");
            nested_attrs.get(b).expect("b binding exists")
        };
        let b_cached_value = eval
            .heap()
            .get_thunk(b_thunk)
            .expect("b binding remains a thunk")
            .cell()
            .cached_value()
            .expect("b thunk cache is readable")
            .expect("b thunk caches its forced scalar");

        assert!(attrset_deeply_forced.raw_eq(root));
        assert_eq!(b_cached_value.as_int(), Ok(3));
    }

    #[test]
    fn force_native_wrapper_binding_function_returns_whnf_values() {
        let binding = runtime_forcing_native_wrapper_bindings()
            .into_iter()
            .find(|binding| binding.entrypoint() == RuntimeForcingEntryPoint::AosForce)
            .expect("force wrapper binding exists");
        let source = "true";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let expected = Value::bool(true);
        let RuntimeForcingNativeWrapperFunction::ForceValue(function) = binding.function() else {
            panic!("aos_force binding must carry a force-value function");
        };

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the value is already WHNF.
        let actual = unsafe { function(rt, expected) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn force_deep_native_wrapper_binding_function_returns_leaf_values() {
        let binding = runtime_forcing_native_wrapper_bindings()
            .into_iter()
            .find(|binding| binding.entrypoint() == RuntimeForcingEntryPoint::AosForceDeep)
            .expect("force-deep wrapper binding exists");
        let source = "true";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let deep_expected = Value::bool(true);
        let RuntimeForcingNativeWrapperFunction::ForceDeepValue(function) = binding.function()
        else {
            panic!("aos_force_deep binding must carry a force-deep-value function");
        };

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the value is already a
        // deep-forced WHNF leaf.
        let deep_actual = unsafe { function(rt, deep_expected) };

        assert!(deep_actual.raw_eq(deep_expected));
    }

    #[test]
    fn blackhole_native_wrapper_binding_function_returns_for_non_thunks() {
        let binding = runtime_forcing_native_wrapper_bindings()
            .into_iter()
            .find(|binding| binding.entrypoint() == RuntimeForcingEntryPoint::AosBlackholeCheck)
            .expect("blackhole-check wrapper binding exists");
        let source = "false";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let value = Value::bool(false);
        let RuntimeForcingNativeWrapperFunction::BlackholeCheck(function) = binding.function()
        else {
            panic!("aos_blackhole_check binding must carry a blackhole-check function");
        };

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and the value is not a thunk.
        unsafe { function(rt, value) };
    }

    #[test]
    fn aos_force_native_wrapper_aborts_malformed_payloads() {
        assert_child_process_aborts(MALFORMED_PAYLOAD_ABORT_CHILD);
    }

    #[test]
    fn aos_force_native_wrapper_aborts_on_null_context() {
        assert_child_process_aborts(FORCE_NULL_CONTEXT_ABORT_CHILD);
    }

    #[test]
    fn aos_force_native_wrapper_aborts_on_tree_walk_error() {
        assert_child_process_aborts(FORCE_TREE_WALK_ERROR_ABORT_CHILD);
    }

    #[test]
    fn aos_force_deep_native_wrapper_aborts_malformed_payloads() {
        assert_child_process_aborts(FORCE_DEEP_MALFORMED_PAYLOAD_ABORT_CHILD);
    }

    #[test]
    fn aos_force_deep_native_wrapper_aborts_on_null_context() {
        assert_child_process_aborts(FORCE_DEEP_NULL_CONTEXT_ABORT_CHILD);
    }

    #[test]
    fn aos_force_deep_native_wrapper_aborts_on_tree_walk_error() {
        assert_child_process_aborts(FORCE_DEEP_TREE_WALK_ERROR_ABORT_CHILD);
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_aborts_malformed_payloads() {
        assert_child_process_aborts(BLACKHOLE_MALFORMED_PAYLOAD_ABORT_CHILD);
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_aborts_on_null_context() {
        assert_child_process_aborts(BLACKHOLE_NULL_CONTEXT_ABORT_CHILD);
    }

    #[test]
    fn aos_blackhole_check_native_wrapper_aborts_blackholed_thunks() {
        assert_child_process_aborts(BLACKHOLE_BLACKHOLED_THUNK_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_native_wrapper_aborts_malformed_payload_child() {
        let source = "42";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let malformed = malformed_bool_value();

        // SAFETY: The pinned context and its evaluator are live for the call.
        // `malformed` has a valid tag discriminant and no heap payload; its
        // invalid bool payload is the abort behavior under test.
        let _ = unsafe { aos_force(rt, malformed) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_native_wrapper_aborts_on_null_context_child() {
        let rt = std::ptr::null_mut();
        let value = Value::int(42);

        // SAFETY: `value` has a valid tag discriminant. The test deliberately
        // passes a null runtime context to verify abort behavior before any
        // force operation can run.
        let _ = unsafe { aos_force(rt, value) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_native_wrapper_aborts_on_tree_walk_error_child() {
        let source = "{ value = 1 / 0; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut symbols = ir.symbols.clone();
        let key = symbols.intern(b"value").expect("value symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("attrset evaluates");
        let thunk = eval
            .heap()
            .get_attrs(root)
            .expect("root is heap-owned attrs")
            .get(key)
            .expect("value binding exists");
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: The pinned context is live, `thunk` belongs to that evaluator,
        // and the failing body is the abort behavior under test.
        let _ = unsafe { aos_force(rt, thunk) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_deep_native_wrapper_aborts_malformed_payload_child() {
        let source = "null";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let malformed = malformed_bool_value();

        // SAFETY: The pinned context and its evaluator are live for the call.
        // `malformed` has a valid tag discriminant and no heap payload; its
        // invalid bool payload is the abort behavior under test.
        let _ = unsafe { aos_force_deep(rt, malformed) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_deep_native_wrapper_aborts_on_null_context_child() {
        let rt = std::ptr::null_mut();
        let value = Value::null();

        // SAFETY: `value` has a valid tag discriminant. The test deliberately
        // passes a null runtime context to verify abort behavior before any
        // deep-force operation can run.
        let _ = unsafe { aos_force_deep(rt, value) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_deep_native_wrapper_aborts_on_tree_walk_error_child() {
        let source = "[ (1 / 0) ]";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("list evaluates");
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: The pinned context is live, `root` belongs to that evaluator,
        // and the failing child is the abort behavior under test.
        let _ = unsafe { aos_force_deep(rt, root) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_blackhole_check_native_wrapper_aborts_malformed_payload_child() {
        let source = "null";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();
        let malformed = malformed_bool_value();

        // SAFETY: The pinned context and its evaluator are live for the call.
        // `malformed` has a valid tag discriminant and no heap payload; its
        // invalid bool payload is the abort behavior under test.
        unsafe { aos_blackhole_check(rt, malformed) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_blackhole_check_native_wrapper_aborts_on_null_context_child() {
        let rt = std::ptr::null_mut();
        let bool_value = Value::bool(false);

        // SAFETY: `bool_value` has a valid tag discriminant. The test
        // deliberately passes a null runtime context to verify abort behavior
        // before any blackhole check can run.
        unsafe { aos_blackhole_check(rt, bool_value) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_blackhole_check_native_wrapper_aborts_blackholed_thunk_child() {
        let source = "[ (1 + 2) ]";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("list evaluates");
        let blackholed = {
            let list = eval.heap().get_list(root).expect("root list is heap-owned");
            list.get(0).expect("element exists")
        };
        let guard = {
            let thunk = eval
                .heap()
                .get_thunk(blackholed)
                .expect("element is a suspended thunk");
            let ForceClaim::Claimed(guard) = thunk
                .cell()
                .begin_force()
                .expect("suspended thunk is claimed")
            else {
                panic!("expected a claimed suspended thunk");
            };
            guard
        };
        std::mem::forget(guard);
        let mut context = std::pin::pin!(RuntimeForceContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: The pinned context is live, `blackholed` belongs to that
        // evaluator, and the blackhole state is the abort behavior under test.
        unsafe { aos_blackhole_check(rt, blackholed) };
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
            "expected {test_name} to abort, got {status:?}"
        );
    }
}
