//! Allocation C ABI wrappers.
//!
//! Native tier-1 code imports allocation helpers through the frozen
//! `aos_alloc_*` pointer-returning ABI surface. `aos_alloc_cons` is the first
//! complete semantic wrapper: its arguments fully describe the result, so it
//! enters the evaluator, preserves roots across the allocation safepoint, and
//! returns an ordinary flat-list pointer. The storage-only and code/env wrappers
//! remain trap-only until their ABIs can initialize the active representation.

use std::{ffi::c_void, process, ptr::NonNull};

use ratchet_oracle::{
    runtime::alloc::{
        RuntimeAllocationAbiSignature, RuntimeAllocationEntryPoint,
        RuntimeAllocationNativeExportBlocker,
    },
    runtime::allocation_values::rust_callable_aos_alloc_cons,
    value::{HeapObject, Value},
};

use crate::context::with_native_runtime_context;
use crate::trap::{RuntimeTrap, record_runtime_trap};

/// Native C ABI function pointer shape for code-plus-environment allocations.
///
/// The function returns a typed heap-object pointer through the native ABI and
/// transfers no error state. It aborts instead of unwinding until the evaluator
/// runtime context can expose the active allocator, semantic payload
/// initialization for native code/environment pointers, trap transfer, and typed
/// pointer-return materialization to this ABI boundary.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_alloc_lambda`] and [`aos_alloc_thunk`]. The current
/// trap-only wrappers abort before decoding `_rt`, dereferencing `_code_ptr` or
/// `_env`, or materializing a typed heap pointer; future allocation dispatch
/// will require every pointer to be valid for the active evaluator runtime.
pub type RuntimeAllocationCodeEnvNativeFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;

/// Native C ABI function pointer shape for `aos_alloc_attrs`.
///
/// The function returns a typed attrset pointer through the native ABI and
/// transfers no error state. It aborts instead of unwinding until the evaluator
/// runtime context can expose the active allocator, allocation safepoint/trap
/// behavior, and typed pointer-return materialization to this ABI boundary.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_alloc_attrs`]. `shape` and `slots` must use the frozen
/// 32-bit ABI representation accepted by the runtime helper metadata. The
/// current trap-only wrapper aborts before decoding `_rt` or materializing a
/// typed heap pointer; future allocation dispatch will require all arguments to
/// be valid for the active evaluator runtime.
pub type RuntimeAllocationAttrsNativeFn =
    unsafe extern "C" fn(*mut c_void, u32, u32) -> *mut c_void;

/// Native C ABI function pointer shape for `aos_alloc_cons`.
///
/// The function returns a typed list pointer through the native ABI and
/// transfers allocation failures through the active runtime trap scope.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_alloc_cons`]. `head` must be a Rust-valid [`Value`] with
/// a valid tag discriminant, and `tail` must use the frozen list-pointer ABI
/// representation. All arguments must be valid for the active evaluator runtime.
pub type RuntimeAllocationConsNativeFn =
    unsafe extern "C" fn(*mut c_void, Value, *mut c_void) -> *mut c_void;

/// Native C ABI function pointer shape for length-bearing allocations.
///
/// The function returns a typed heap-object pointer through the native ABI and
/// transfers no error state. It aborts instead of unwinding until the evaluator
/// runtime context can expose the active allocator, allocation safepoint/trap
/// behavior, and typed pointer-return materialization to this ABI boundary.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_alloc_list`] and [`aos_alloc_string`]. The current
/// trap-only wrappers abort before decoding `_rt` or materializing a typed heap
/// pointer; future allocation dispatch will require every argument to be valid
/// for the active evaluator runtime.
pub type RuntimeAllocationLenNativeFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;

/// Native C ABI function pointer shape for `aos_alloc_raw`.
///
/// The function returns a typed raw-storage pointer through the native ABI and
/// transfers no error state. It aborts instead of unwinding until the evaluator
/// runtime context can expose the active allocator, raw-layout validation, trap
/// transfer, and typed pointer-return materialization to this ABI boundary.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_alloc_raw`]. The current trap-only wrapper aborts before
/// decoding `_rt`, validating layout payloads, or materializing a typed heap
/// pointer; future allocation dispatch will require every argument to be valid
/// for the active evaluator runtime.
pub type RuntimeAllocationRawNativeFn =
    unsafe extern "C" fn(*mut c_void, usize, usize, u32) -> *mut c_void;

const ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS: &[RuntimeAllocationNativeExportBlocker] = &[
    RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
];

const ALLOCATION_SEMANTIC_REMAINING_EXPORT_BLOCKERS: &[RuntimeAllocationNativeExportBlocker] = &[
    RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
    RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented,
];

const ALLOCATION_CONS_REMAINING_EXPORT_BLOCKERS: &[RuntimeAllocationNativeExportBlocker] = &[];

/// Aborts through the frozen attrset allocation native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_alloc_attrs`. It accepts
/// the frozen runtime-context pointer, hidden-class shape id, and slot count,
/// then aborts until native wrappers can safely enter the evaluator allocator
/// and return a materialized attrset pointer.
///
/// # Safety
///
/// `shape` and `slots` must use the frozen 32-bit ABI representation before
/// crossing this ABI boundary. The current wrapper aborts before decoding `_rt`
/// or materializing a typed attrset pointer. The caller must also ensure the
/// host ABI used to call this function matches the frozen `aos_alloc_attrs`
/// runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_alloc_attrs(
    _rt: *mut c_void,
    _shape: u32,
    _slots: u32,
) -> *mut c_void {
    process::abort()
}

/// Allocates and initializes through the frozen cons native ABI body.
///
/// The wrapper validates the by-value head, decodes the shared runtime context,
/// treats a null tail as the empty list, and delegates to the safe evaluator
/// allocation path. The resulting pointer identifies a registered, hash-consed
/// flat list. An evaluator allocation error is transferred through the active
/// trap scope and returns null; outside a scope, recording the error aborts.
///
/// # Safety
///
/// `head` must be a Rust-valid [`Value`] whose heap payload, if any, is owned by
/// the evaluator encoded by `rt`. A non-null `tail` must be a live list pointer
/// owned by the same evaluator. `rt` must point to a pinned live
/// [`crate::context::RuntimeJitContext`] with exclusive evaluator access. The
/// caller must ensure the host ABI matches the frozen `aos_alloc_cons`
/// signature and must stop consuming the null result when the trap scope records
/// an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_alloc_cons(
    rt: *mut c_void,
    head: Value,
    tail: *mut c_void,
) -> *mut c_void {
    if head.validate_payload().is_err() {
        process::abort()
    }
    let tail = NonNull::new(tail).map(NonNull::cast::<HeapObject>);
    // SAFETY: The caller supplies the pinned RuntimeJitContext and exclusive
    // evaluator access required by `with_native_runtime_context`.
    let allocated = unsafe { // aos_alloc_cons runtime-context decode
        with_native_runtime_context(rt, |eval, id, span| {
            rust_callable_aos_alloc_cons(eval, id, span, head, tail)
        })
    };
    match allocated {
        Ok(ptr) => ptr.cast::<c_void>().as_ptr(),
        Err(error) => {
            record_runtime_trap(RuntimeTrap::Allocation(error));
            std::ptr::null_mut()
        }
    }
}

/// Aborts through the frozen lambda allocation native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_alloc_lambda`. It accepts
/// the frozen runtime-context pointer, native code pointer, and environment
/// pointer, then aborts until native wrappers can safely enter the evaluator
/// allocator, initialize the lambda payload, and return a materialized lambda
/// pointer.
///
/// # Safety
///
/// `code_ptr` and `env` must use the frozen pointer ABI representation before
/// crossing this ABI boundary. The current wrapper aborts before decoding `_rt`,
/// dereferencing either pointer, or materializing a typed lambda pointer. The
/// caller must also ensure the host ABI used to call this function matches the
/// frozen `aos_alloc_lambda` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_alloc_lambda(
    _rt: *mut c_void,
    _code_ptr: *mut c_void,
    _env: *mut c_void,
) -> *mut c_void {
    process::abort()
}

/// Aborts through the frozen list allocation native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_alloc_list`. It accepts
/// the frozen runtime-context pointer and element count, then aborts until
/// native wrappers can safely enter the evaluator allocator and return a
/// materialized list pointer.
///
/// # Safety
///
/// The current wrapper aborts before decoding `_rt` or materializing a typed
/// list pointer. The caller must ensure the host ABI used to call this function
/// matches the frozen `aos_alloc_list` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_alloc_list(_rt: *mut c_void, _len: usize) -> *mut c_void {
    process::abort()
}

/// Aborts through the frozen raw allocation native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_alloc_raw`. It accepts the
/// frozen runtime-context pointer, raw size, alignment, and type tag, then
/// aborts until native wrappers can safely enter the evaluator allocator and
/// return a materialized raw storage pointer.
///
/// # Safety
///
/// The current wrapper aborts before decoding `_rt`, validating
/// `size`/`align`/`type_tag`, or materializing a typed raw pointer. The caller
/// must ensure the host ABI used to call this function matches the frozen
/// `aos_alloc_raw` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_alloc_raw(
    _rt: *mut c_void,
    _size: usize,
    _align: usize,
    _type_tag: u32,
) -> *mut c_void {
    process::abort()
}

/// Aborts through the frozen string allocation native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_alloc_string`. It accepts
/// the frozen runtime-context pointer and byte length, then aborts until native
/// wrappers can safely enter the evaluator allocator and return a materialized
/// string-header pointer.
///
/// # Safety
///
/// The current wrapper aborts before decoding `_rt` or materializing a typed
/// string-header pointer. The caller must ensure the host ABI used to call this
/// function matches the frozen `aos_alloc_string` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_alloc_string(_rt: *mut c_void, _len: usize) -> *mut c_void {
    process::abort()
}

/// Aborts through the frozen thunk allocation native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_alloc_thunk`. It accepts
/// the frozen runtime-context pointer, native code pointer, and environment
/// pointer, then aborts until native wrappers can safely enter the evaluator
/// allocator, initialize the thunk payload, and return a materialized thunk
/// pointer.
///
/// # Safety
///
/// `code_ptr` and `env` must use the frozen pointer ABI representation before
/// crossing this ABI boundary. The current wrapper aborts before decoding `_rt`,
/// dereferencing either pointer, or materializing a typed thunk pointer. The
/// caller must also ensure the host ABI used to call this function matches the
/// frozen `aos_alloc_thunk` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_alloc_thunk(
    _rt: *mut c_void,
    _code_ptr: *mut c_void,
    _env: *mut c_void,
) -> *mut c_void {
    process::abort()
}

/// Returns metadata for exported allocation wrappers in symbol order.
pub fn runtime_allocation_native_wrapper_bindings() -> Vec<RuntimeAllocationNativeWrapperBinding> {
    vec![
        RuntimeAllocationNativeWrapperBinding::aos_alloc_attrs(),
        RuntimeAllocationNativeWrapperBinding::aos_alloc_cons(),
        RuntimeAllocationNativeWrapperBinding::aos_alloc_lambda(),
        RuntimeAllocationNativeWrapperBinding::aos_alloc_list(),
        RuntimeAllocationNativeWrapperBinding::aos_alloc_raw(),
        RuntimeAllocationNativeWrapperBinding::aos_alloc_string(),
        RuntimeAllocationNativeWrapperBinding::aos_alloc_thunk(),
    ]
}

/// Process-local address metadata for one allocation native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationNativeWrapperAddress {
    ptr: *mut c_void,
}

impl RuntimeAllocationNativeWrapperAddress {
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

/// Typed function pointer for one allocation native wrapper.
#[derive(Clone, Copy, Debug)]
pub enum RuntimeAllocationNativeWrapperFunction {
    /// The `aos_alloc_attrs` wrapper.
    Attrs(RuntimeAllocationAttrsNativeFn),
    /// The `aos_alloc_cons` wrapper.
    Cons(RuntimeAllocationConsNativeFn),
    /// The `aos_alloc_lambda` wrapper.
    Lambda(RuntimeAllocationCodeEnvNativeFn),
    /// The `aos_alloc_list` wrapper.
    List(RuntimeAllocationLenNativeFn),
    /// The `aos_alloc_raw` wrapper.
    Raw(RuntimeAllocationRawNativeFn),
    /// The `aos_alloc_string` wrapper.
    String(RuntimeAllocationLenNativeFn),
    /// The `aos_alloc_thunk` wrapper.
    Thunk(RuntimeAllocationCodeEnvNativeFn),
}

/// Metadata for one trap-only allocation native wrapper.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeAllocationNativeWrapperBinding {
    entrypoint: RuntimeAllocationEntryPoint,
    function: RuntimeAllocationNativeWrapperFunction,
    address: RuntimeAllocationNativeWrapperAddress,
    remaining_export_blockers: &'static [RuntimeAllocationNativeExportBlocker],
}

impl RuntimeAllocationNativeWrapperBinding {
    fn aos_alloc_attrs() -> Self {
        Self {
            entrypoint: RuntimeAllocationEntryPoint::AosAllocAttrs,
            function: RuntimeAllocationNativeWrapperFunction::Attrs(aos_alloc_attrs),
            address: RuntimeAllocationNativeWrapperAddress::new(
                aos_alloc_attrs as RuntimeAllocationAttrsNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_alloc_cons() -> Self {
        Self {
            entrypoint: RuntimeAllocationEntryPoint::AosAllocCons,
            function: RuntimeAllocationNativeWrapperFunction::Cons(aos_alloc_cons),
            address: RuntimeAllocationNativeWrapperAddress::new(
                aos_alloc_cons as RuntimeAllocationConsNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ALLOCATION_CONS_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_alloc_lambda() -> Self {
        Self {
            entrypoint: RuntimeAllocationEntryPoint::AosAllocLambda,
            function: RuntimeAllocationNativeWrapperFunction::Lambda(aos_alloc_lambda),
            address: RuntimeAllocationNativeWrapperAddress::new(
                aos_alloc_lambda as RuntimeAllocationCodeEnvNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ALLOCATION_SEMANTIC_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_alloc_list() -> Self {
        Self {
            entrypoint: RuntimeAllocationEntryPoint::AosAllocList,
            function: RuntimeAllocationNativeWrapperFunction::List(aos_alloc_list),
            address: RuntimeAllocationNativeWrapperAddress::new(
                aos_alloc_list as RuntimeAllocationLenNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_alloc_raw() -> Self {
        Self {
            entrypoint: RuntimeAllocationEntryPoint::AosAllocRaw,
            function: RuntimeAllocationNativeWrapperFunction::Raw(aos_alloc_raw),
            address: RuntimeAllocationNativeWrapperAddress::new(
                aos_alloc_raw as RuntimeAllocationRawNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_alloc_string() -> Self {
        Self {
            entrypoint: RuntimeAllocationEntryPoint::AosAllocString,
            function: RuntimeAllocationNativeWrapperFunction::String(aos_alloc_string),
            address: RuntimeAllocationNativeWrapperAddress::new(
                aos_alloc_string as RuntimeAllocationLenNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_alloc_thunk() -> Self {
        Self {
            entrypoint: RuntimeAllocationEntryPoint::AosAllocThunk,
            function: RuntimeAllocationNativeWrapperFunction::Thunk(aos_alloc_thunk),
            address: RuntimeAllocationNativeWrapperAddress::new(
                aos_alloc_thunk as RuntimeAllocationCodeEnvNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ALLOCATION_SEMANTIC_REMAINING_EXPORT_BLOCKERS,
        }
    }

    /// Returns the allocation entry point served by this wrapper.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name served by this wrapper.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen ABI signature served by this wrapper.
    pub const fn abi_signature(self) -> RuntimeAllocationAbiSignature {
        self.entrypoint.abi_signature()
    }

    /// Returns the typed native wrapper function pointer.
    pub const fn function(self) -> RuntimeAllocationNativeWrapperFunction {
        self.function
    }

    /// Returns the process-local native wrapper address.
    pub const fn address(self) -> RuntimeAllocationNativeWrapperAddress {
        self.address
    }

    /// Returns blockers that still prevent final native-export registration.
    pub const fn remaining_export_blockers(
        self,
    ) -> &'static [RuntimeAllocationNativeExportBlocker] {
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

    const ALLOC_ATTRS_ABORT_CHILD: &str =
        "alloc::tests::aos_alloc_attrs_native_wrapper_aborts_child";
    const ALLOC_CONS_ABORT_CHILD: &str = "alloc::tests::aos_alloc_cons_native_wrapper_aborts_child";
    const ALLOC_LAMBDA_ABORT_CHILD: &str =
        "alloc::tests::aos_alloc_lambda_native_wrapper_aborts_child";
    const ALLOC_LIST_ABORT_CHILD: &str = "alloc::tests::aos_alloc_list_native_wrapper_aborts_child";
    const ALLOC_RAW_ABORT_CHILD: &str = "alloc::tests::aos_alloc_raw_native_wrapper_aborts_child";
    const ALLOC_STRING_ABORT_CHILD: &str =
        "alloc::tests::aos_alloc_string_native_wrapper_aborts_child";
    const ALLOC_THUNK_ABORT_CHILD: &str =
        "alloc::tests::aos_alloc_thunk_native_wrapper_aborts_child";

    #[test]
    fn allocation_native_wrapper_bindings_preserve_symbol_abi_and_address() {
        let bindings = runtime_allocation_native_wrapper_bindings();

        assert_eq!(bindings.len(), 7);
        assert_allocation_binding(
            bindings[0],
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            aos_alloc_attrs as RuntimeAllocationAttrsNativeFn as *mut c_void,
            ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        );
        assert!(matches!(
            bindings[0].function(),
            RuntimeAllocationNativeWrapperFunction::Attrs(function)
                if function as RuntimeAllocationAttrsNativeFn as *mut c_void
                    == aos_alloc_attrs as RuntimeAllocationAttrsNativeFn as *mut c_void
        ));
        assert_allocation_binding(
            bindings[1],
            RuntimeAllocationEntryPoint::AosAllocCons,
            aos_alloc_cons as RuntimeAllocationConsNativeFn as *mut c_void,
            ALLOCATION_CONS_REMAINING_EXPORT_BLOCKERS,
        );
        assert!(matches!(
            bindings[1].function(),
            RuntimeAllocationNativeWrapperFunction::Cons(function)
                if function as RuntimeAllocationConsNativeFn as *mut c_void
                    == aos_alloc_cons as RuntimeAllocationConsNativeFn as *mut c_void
        ));
        assert_allocation_binding(
            bindings[2],
            RuntimeAllocationEntryPoint::AosAllocLambda,
            aos_alloc_lambda as RuntimeAllocationCodeEnvNativeFn as *mut c_void,
            ALLOCATION_SEMANTIC_REMAINING_EXPORT_BLOCKERS,
        );
        assert!(matches!(
            bindings[2].function(),
            RuntimeAllocationNativeWrapperFunction::Lambda(function)
                if function as RuntimeAllocationCodeEnvNativeFn as *mut c_void
                    == aos_alloc_lambda as RuntimeAllocationCodeEnvNativeFn as *mut c_void
        ));
        assert_allocation_binding(
            bindings[3],
            RuntimeAllocationEntryPoint::AosAllocList,
            aos_alloc_list as RuntimeAllocationLenNativeFn as *mut c_void,
            ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        );
        assert!(matches!(
            bindings[3].function(),
            RuntimeAllocationNativeWrapperFunction::List(function)
                if function as RuntimeAllocationLenNativeFn as *mut c_void
                    == aos_alloc_list as RuntimeAllocationLenNativeFn as *mut c_void
        ));
        assert_allocation_binding(
            bindings[4],
            RuntimeAllocationEntryPoint::AosAllocRaw,
            aos_alloc_raw as RuntimeAllocationRawNativeFn as *mut c_void,
            ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        );
        assert!(matches!(
            bindings[4].function(),
            RuntimeAllocationNativeWrapperFunction::Raw(function)
                if function as RuntimeAllocationRawNativeFn as *mut c_void
                    == aos_alloc_raw as RuntimeAllocationRawNativeFn as *mut c_void
        ));
        assert_allocation_binding(
            bindings[5],
            RuntimeAllocationEntryPoint::AosAllocString,
            aos_alloc_string as RuntimeAllocationLenNativeFn as *mut c_void,
            ALLOCATION_STORAGE_REMAINING_EXPORT_BLOCKERS,
        );
        assert!(matches!(
            bindings[5].function(),
            RuntimeAllocationNativeWrapperFunction::String(function)
                if function as RuntimeAllocationLenNativeFn as *mut c_void
                    == aos_alloc_string as RuntimeAllocationLenNativeFn as *mut c_void
        ));
        assert_allocation_binding(
            bindings[6],
            RuntimeAllocationEntryPoint::AosAllocThunk,
            aos_alloc_thunk as RuntimeAllocationCodeEnvNativeFn as *mut c_void,
            ALLOCATION_SEMANTIC_REMAINING_EXPORT_BLOCKERS,
        );
        assert!(matches!(
            bindings[6].function(),
            RuntimeAllocationNativeWrapperFunction::Thunk(function)
                if function as RuntimeAllocationCodeEnvNativeFn as *mut c_void
                    == aos_alloc_thunk as RuntimeAllocationCodeEnvNativeFn as *mut c_void
        ));
    }

    #[test]
    fn allocation_native_wrapper_remaining_blockers_extend_oracle_export_gate() {
        for binding in runtime_allocation_native_wrapper_bindings() {
            let oracle_blockers = binding.entrypoint().native_export_blockers();
            if binding.entrypoint() == RuntimeAllocationEntryPoint::AosAllocCons {
                assert!(binding.remaining_export_blockers().is_empty());
                continue;
            }
            assert_eq!(
                binding.remaining_export_blockers(),
                &oracle_blockers[1..],
                "{} runtime-FFI blockers extend oracle gate after final admission",
                binding.symbol_name()
            );
        }
    }

    #[test]
    fn aos_alloc_attrs_native_wrapper_aborts() {
        assert_child_process_aborts(ALLOC_ATTRS_ABORT_CHILD);
    }

    #[test]
    fn aos_alloc_cons_native_wrapper_aborts() {
        assert_child_process_aborts(ALLOC_CONS_ABORT_CHILD);
    }

    #[test]
    fn aos_alloc_lambda_native_wrapper_aborts() {
        assert_child_process_aborts(ALLOC_LAMBDA_ABORT_CHILD);
    }

    #[test]
    fn aos_alloc_list_native_wrapper_aborts() {
        assert_child_process_aborts(ALLOC_LIST_ABORT_CHILD);
    }

    #[test]
    fn aos_alloc_raw_native_wrapper_aborts() {
        assert_child_process_aborts(ALLOC_RAW_ABORT_CHILD);
    }

    #[test]
    fn aos_alloc_string_native_wrapper_aborts() {
        assert_child_process_aborts(ALLOC_STRING_ABORT_CHILD);
    }

    #[test]
    fn aos_alloc_thunk_native_wrapper_aborts() {
        assert_child_process_aborts(ALLOC_THUNK_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_alloc_attrs_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let shape = 0;
        let slots = 0;

        // SAFETY: The current wrapper is trap-only and aborts before decoding
        // `rt`, interpreting `shape` or `slots`, or materializing a typed
        // attrset pointer.
        let _ = unsafe { aos_alloc_attrs(rt, shape, slots) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_alloc_cons_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let head = Value::null();
        let tail = std::ptr::null_mut();

        // SAFETY: `head` and the null tail are valid; the null runtime context
        // intentionally exercises the wrapper's safety-contract abort.
        let _ = unsafe { aos_alloc_cons(rt, head, tail) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_alloc_lambda_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let code_ptr = std::ptr::null_mut();
        let env = std::ptr::null_mut();

        // SAFETY: The current wrapper is trap-only and aborts before decoding
        // `rt`, dereferencing `code_ptr` or `env`, or materializing a typed
        // lambda pointer.
        let _ = unsafe { aos_alloc_lambda(rt, code_ptr, env) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_alloc_list_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let len = 0;

        // SAFETY: The current wrapper is trap-only and aborts before decoding
        // `rt`, interpreting `len`, or materializing a typed list pointer.
        let _ = unsafe { aos_alloc_list(rt, len) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_alloc_raw_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let size = 0;
        let align = 1;
        let type_tag = 0;

        // SAFETY: The current wrapper is trap-only and aborts before decoding
        // `rt`, validating the raw layout payload, or materializing a typed raw
        // pointer.
        let _ = unsafe { aos_alloc_raw(rt, size, align, type_tag) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_alloc_string_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let len = 0;

        // SAFETY: The current wrapper is trap-only and aborts before decoding
        // `rt`, interpreting `len`, or materializing a typed string pointer.
        let _ = unsafe { aos_alloc_string(rt, len) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_alloc_thunk_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let code_ptr = std::ptr::null_mut();
        let env = std::ptr::null_mut();

        // SAFETY: The current wrapper is trap-only and aborts before decoding
        // `rt`, dereferencing `code_ptr` or `env`, or materializing a typed
        // thunk pointer.
        let _ = unsafe { aos_alloc_thunk(rt, code_ptr, env) };
    }

    fn assert_allocation_binding(
        binding: RuntimeAllocationNativeWrapperBinding,
        entrypoint: RuntimeAllocationEntryPoint,
        address: *mut c_void,
        remaining_export_blockers: &'static [RuntimeAllocationNativeExportBlocker],
    ) {
        assert_eq!(binding.entrypoint(), entrypoint);
        assert_eq!(binding.symbol_name(), entrypoint.symbol_name());
        assert_eq!(binding.abi_signature(), entrypoint.abi_signature());
        assert_eq!(binding.address().as_ptr(), address);
        assert!(binding.address().is_non_null());
        assert_eq!(
            binding.remaining_export_blockers(),
            remaining_export_blockers
        );
        assert_eq!(binding.is_export_ready(), remaining_export_blockers.is_empty());
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
