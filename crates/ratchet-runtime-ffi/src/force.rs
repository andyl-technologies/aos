//! Forcing C ABI wrappers.
//!
//! Native tier-1 code imports forcing helpers with frozen `(rt, Value)`
//! signatures. This module supplies the first success-path wrappers for that
//! ABI: `aos_blackhole_check` returns for representation-valid non-thunks,
//! `aos_force` decodes a scoped [`RuntimeForceContext`] and dispatches through
//! the safe tree-walk forcing helper, and `aos_force_deep` returns only valid
//! WHNF leaves whose tags do not require recursive list or attrset traversal.
//! Malformed payloads, blackhole-protocol values outside ordinary force entry,
//! and deep-force container traversal paths abort until native trap transfer and
//! the remaining specialized protocols exist. Callers must still pass a
//! Rust-valid [`Value`]; an invalid tag discriminant is undefined behavior
//! before these wrappers can inspect it.

use std::{
    ffi::c_void,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    process,
    ptr::NonNull,
};

use ratchet_oracle::{
    compile::IrId,
    eval::tree_walk::TreeWalk,
    runtime::forcing::{
        RuntimeForcingAbiSignature, RuntimeForcingEntryPoint, RuntimeForcingNativeExportBlocker,
        rust_callable_aos_force,
    },
    syntax::Span,
    value::{Value, ValueTag},
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

/// Native C ABI function pointer shape for value-returning forcing helpers.
///
/// The function returns a by-value [`Value`] and transfers no error state. It
/// aborts instead of unwinding if a valid [`Value`] carries a malformed payload
/// or if the wrapper being called reaches a forcing/deep-force path that still
/// lacks runtime support. Final evaluator trap/error transfer remains future
/// work.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on the wrapper being called. The value argument must be a
/// Rust-valid [`Value`] with a valid tag discriminant. Any returned heap value
/// must carry a live evaluator-owned heap payload for the value kind. Calls to
/// [`aos_force`] must pass a valid pinned [`RuntimeForceContext`] runtime
/// pointer; deep-force traversal will require a valid runtime pointer once that
/// wrapper grows beyond its current WHNF-leaf fast path.
pub type RuntimeForceNativeFn = unsafe extern "C" fn(*mut c_void, Value) -> Value;

const BLACKHOLE_CHECK_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[
    RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
];

const FORCE_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] =
    &[RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented];

const FORCE_DEEP_REMAINING_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[
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

/// Forces a value through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_force`. It accepts the
/// frozen runtime-context pointer plus a by-value [`Value`], validates the
/// representation-level payload, decodes `rt` as a [`RuntimeForceContext`],
/// forces thunks through the safe tree-walk force helper, and returns weak head
/// normal form. It deliberately does not implement evaluator trap/error
/// transfer: the process aborts if the pointer is null, the value payload is
/// malformed, or the safe helper reports an error.
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
        with_native_force_context(rt, |eval, id, span| {
            aos_force_success_path(eval, id, span, value)
        })
    };
    forced
}

fn aos_force_success_path(eval: &mut TreeWalk, id: IrId, span: Span, value: Value) -> Value {
    match rust_callable_aos_force(eval, id, span, value) {
        Ok(value) => value,
        Err(_) => process::abort(),
    }
}

/// Deep-forces an already-deep WHNF leaf through an unmangled frozen native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_force_deep`. It accepts
/// the frozen runtime-context pointer plus a by-value [`Value`], returns
/// immediately when the value has a valid payload, is already weak head normal
/// form, and is not a list or attrset, and aborts for malformed payloads,
/// thunk-tagged values, lists, and attrsets until recursive evaluator
/// deep-force traversal is bound to native runtime contexts.
///
/// # Safety
///
/// `value` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. Any heap payload returned from the leaf fast path
/// must point at a live evaluator-owned heap object for the value kind; this
/// wrapper only validates representation-level payload invariants. The current
/// thunk, list, and attrset paths abort before decoding `_rt` or dereferencing
/// heap payloads. The caller must also ensure the host ABI used to call this
/// function matches the frozen `aos_force_deep` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_force_deep(_rt: *mut c_void, value: Value) -> Value {
    if value_is_deep_force_leaf(value) {
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
        RuntimeForcingNativeWrapperBinding::aos_force_deep(),
    ]
}

fn value_is_deep_force_leaf(value: Value) -> bool {
    value.validate_payload().is_ok()
        && value.is_whnf()
        && !matches!(value.tag(), ValueTag::List | ValueTag::Attrs)
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

/// Scoped tree-walk evaluator context decoded by `aos_force`.
///
/// Native force wrappers receive an opaque runtime pointer in their frozen C
/// ABI. This context is the current explicit Rust-side representation for that
/// pointer: it ties one live [`TreeWalk`] evaluator to the IR node id and source
/// span used when the safe oracle reports forcing failures.
pub struct RuntimeForceContext<'eval> {
    eval: NonNull<TreeWalk>,
    id: IrId,
    span: Span,
    _marker: PhantomData<&'eval mut TreeWalk>,
    _pinned: PhantomPinned,
}

impl<'eval> RuntimeForceContext<'eval> {
    /// Creates a scoped forcing context for native wrapper calls.
    pub fn new(eval: &'eval mut TreeWalk, id: IrId, span: Span) -> Self {
        Self {
            eval: NonNull::from(eval),
            id,
            span,
            _marker: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    /// Returns an opaque runtime pointer suitable for `aos_force` calls.
    ///
    /// The returned pointer is only valid while this pinned context value and
    /// its borrowed evaluator remain live. Callers must not move or drop the
    /// pinned context, and must uphold exclusive mutable access to the
    /// evaluator, while a native wrapper call uses the pointer.
    pub fn as_mut_ptr(self: Pin<&mut Self>) -> *mut c_void {
        self.as_ref().get_ref() as *const Self as *mut c_void
    }
}

// SAFETY: Callers must pass a live pinned RuntimeForceContext pointer and
// uphold exclusive evaluator access for the duration of the callback.
unsafe fn with_native_force_context<R>(
    rt: *mut c_void,
    call: impl FnOnce(&mut TreeWalk, IrId, Span) -> R,
) -> R {
    let Some(rt) = NonNull::new(rt) else {
        process::abort();
    };
    // SAFETY: The caller must provide a live RuntimeForceContext pointer with
    // exclusive evaluator access covering this call.
    let context = unsafe { rt.cast::<RuntimeForceContext<'static>>().as_mut() };
    let id = context.id;
    let span = context.span;
    // SAFETY: RuntimeForceContext::new stores a live TreeWalk pointer, and the
    // native wrapper contract requires exclusive evaluator access.
    call(unsafe { context.eval.as_mut() }, id, span)
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, ExitStatus},
    };

    use super::*;
    use ratchet_oracle::{
        attrs::FlatAttrs,
        compile::{IrId, resolve},
        eval::{EvalHeap, EvalThunk},
        list::NixList,
        string::NixString,
        syntax::parse_str,
        value::ValueTag,
    };

    const MALFORMED_PAYLOAD_ABORT_CHILD: &str =
        "force::tests::aos_force_native_wrapper_aborts_malformed_payload_child";
    const FORCE_NULL_CONTEXT_ABORT_CHILD: &str =
        "force::tests::aos_force_native_wrapper_aborts_on_null_context_child";
    const FORCE_TREE_WALK_ERROR_ABORT_CHILD: &str =
        "force::tests::aos_force_native_wrapper_aborts_on_tree_walk_error_child";
    const FORCE_DEEP_MALFORMED_PAYLOAD_ABORT_CHILD: &str =
        "force::tests::aos_force_deep_native_wrapper_aborts_malformed_payload_child";
    const FORCE_DEEP_THUNK_ABORT_CHILD: &str =
        "force::tests::aos_force_deep_native_wrapper_aborts_thunk_child";
    const FORCE_DEEP_LIST_ABORT_CHILD: &str =
        "force::tests::aos_force_deep_native_wrapper_aborts_lists_child";
    const FORCE_DEEP_ATTRS_ABORT_CHILD: &str =
        "force::tests::aos_force_deep_native_wrapper_aborts_attrs_child";
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
            [RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented].as_slice()
        );
        assert!(!force.is_export_ready());

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
        assert_eq!(
            force_deep.remaining_export_blockers(),
            [
                RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
                RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
                RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
                RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
            ]
            .as_slice()
        );
        assert!(!force_deep.is_export_ready());
    }

    #[test]
    fn force_native_wrapper_remaining_blockers_extend_oracle_export_gate() {
        for binding in runtime_forcing_native_wrapper_bindings() {
            let oracle_blockers = binding.entrypoint().native_export_blockers();
            if binding.entrypoint() == RuntimeForcingEntryPoint::AosForce {
                assert_eq!(
                    binding.remaining_export_blockers(),
                    [RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented].as_slice(),
                    "{} runtime-FFI wrapper has one remaining blocker",
                    binding.symbol_name()
                );
                for blocker in binding.remaining_export_blockers() {
                    assert!(
                        oracle_blockers.contains(blocker),
                        "{} runtime-FFI blocker {blocker:?} must remain tracked by oracle",
                        binding.symbol_name()
                    );
                }
            } else {
                assert_eq!(
                    binding.remaining_export_blockers(),
                    &oracle_blockers[1..],
                    "{} runtime-FFI blockers extend oracle gate after final admission",
                    binding.symbol_name()
                );
            }
        }
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
        let rt = std::ptr::null_mut();
        let expected = Value::null();

        // SAFETY: The current wrapper fast path does not dereference `rt`, and
        // the value is already a non-container WHNF leaf.
        let actual = unsafe { aos_force_deep(rt, expected) };

        assert!(actual.raw_eq(expected));
    }

    #[test]
    fn aos_force_deep_native_wrapper_returns_heap_leaf_values() {
        let rt = std::ptr::null_mut();
        let (_heap, heap_expected) = allocated_string_value();

        // SAFETY: The current wrapper fast path does not dereference `rt`, and
        // the value is already a non-container WHNF heap leaf. The heap remains
        // alive while the by-value wrapper result is compared.
        let heap_actual = unsafe { aos_force_deep(rt, heap_expected) };

        assert!(heap_actual.raw_eq(heap_expected));
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
        let rt = std::ptr::null_mut();
        let deep_expected = Value::bool(true);
        let RuntimeForcingNativeWrapperFunction::ForceDeepValue(function) = binding.function()
        else {
            panic!("aos_force_deep binding must carry a force-deep-value function");
        };

        // SAFETY: The current wrapper fast path does not dereference `rt`, and
        // the value is already a non-container WHNF leaf.
        let deep_actual = unsafe { function(rt, deep_expected) };

        assert!(deep_actual.raw_eq(deep_expected));
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
    fn aos_force_deep_native_wrapper_aborts_thunks() {
        assert_child_process_aborts(FORCE_DEEP_THUNK_ABORT_CHILD);
    }

    #[test]
    fn aos_force_deep_native_wrapper_aborts_lists() {
        assert_child_process_aborts(FORCE_DEEP_LIST_ABORT_CHILD);
    }

    #[test]
    fn aos_force_deep_native_wrapper_aborts_attrs() {
        assert_child_process_aborts(FORCE_DEEP_ATTRS_ABORT_CHILD);
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
        let rt = std::ptr::null_mut();
        let malformed = malformed_bool_value();

        // SAFETY: `malformed` has a valid tag discriminant and no heap payload;
        // its invalid bool payload is the abort behavior under test.
        let _ = unsafe { aos_force_deep(rt, malformed) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_deep_native_wrapper_aborts_thunk_child() {
        let rt = std::ptr::null_mut();
        let (_heap, thunk) = allocated_thunk_value();

        // SAFETY: `thunk` is a valid evaluator-owned thunk value. The current
        // wrapper aborts thunk values before decoding `rt` or dereferencing the
        // thunk payload.
        let _ = unsafe { aos_force_deep(rt, thunk) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_deep_native_wrapper_aborts_lists_child() {
        let rt = std::ptr::null_mut();
        let (_heap, list) = allocated_list_value();

        // SAFETY: `list` is a valid evaluator-owned list value. The current
        // wrapper aborts list values before decoding `rt` or dereferencing the
        // list payload for recursive deep-force traversal.
        let _ = unsafe { aos_force_deep(rt, list) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_force_deep_native_wrapper_aborts_attrs_child() {
        let rt = std::ptr::null_mut();
        let (_heap, attrs) = allocated_attrs_value();

        // SAFETY: `attrs` is a valid evaluator-owned attrset value. The current
        // wrapper aborts attrset values before decoding `rt` or dereferencing
        // the attrset payload for recursive deep-force traversal.
        let _ = unsafe { aos_force_deep(rt, attrs) };
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

    fn allocated_list_value() -> (EvalHeap, Value) {
        let mut heap = EvalHeap::new();
        let list = heap
            .alloc_list(NixList::empty())
            .expect("test list allocates");
        (heap, list)
    }

    fn allocated_attrs_value() -> (EvalHeap, Value) {
        let mut heap = EvalHeap::new();
        let attrs = heap
            .alloc_attrs(0, FlatAttrs::empty())
            .expect("test attrset allocates");
        (heap, attrs)
    }

    fn allocated_string_value() -> (EvalHeap, Value) {
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"force-deep-leaf".to_vec()))
            .expect("test string allocates");
        (heap, string)
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
