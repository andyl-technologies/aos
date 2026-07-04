//! Attribute-access C ABI wrappers.
//!
//! Native tier-1 code imports attrset helpers with frozen keyed
//! `(rt, Value attrs, SymbolId, InlineCacheSiteId) -> Value` and update
//! `(rt, Value left, Value right) -> Value` signatures. This module supplies
//! trap-only wrappers for those ABIs: `aos_has_attr`, `aos_select_ic`, and
//! `aos_update` abort for every call until runtime-context decoding, active
//! attrset-root binding, symbol-table binding, inline-cache dispatch, update
//! merge, trap transfer, and native value return materialization exist. That is
//! the only sound behavior today because the safe evaluator paths own attrset
//! selection errors, boolean materialization, inline-cache state, and
//! right-biased merge semantics.

use std::{ffi::c_void, process};

use ratchet_oracle::{
    runtime::attr::{
        RuntimeAttrAccessAbiSignature, RuntimeAttrAccessEntryPoint,
        RuntimeAttrAccessNativeExportBlocker,
    },
    value::Value,
};

/// Native C ABI function pointer shape for keyed attrset-access helpers.
///
/// The function returns a by-value [`Value`] and transfers no error state. It
/// aborts instead of unwinding until the evaluator runtime context can expose
/// active attrset roots, symbol-table binding, inline-cache site binding,
/// inline-cache dispatch, trap transfer, and native value-return materialization
/// to this ABI boundary.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_has_attr`] and [`aos_select_ic`]. The attrset receiver
/// must be a Rust-valid [`Value`] with a valid tag discriminant, and `symbol`
/// plus `site` must use the frozen `u32` ABI representation for the evaluator's
/// symbol table and inline-cache site ids. The current trap-only wrappers abort
/// before decoding `_rt`, converting ids, or inspecting `attrs`; future lookup
/// dispatch will require every argument to be valid for the active evaluator
/// runtime.
pub type RuntimeAttrAccessKeyedNativeFn =
    unsafe extern "C" fn(*mut c_void, Value, u32, u32) -> Value;

/// Native C ABI function pointer shape for `aos_update`.
///
/// The function returns a by-value [`Value`] and transfers no error state. It
/// aborts instead of unwinding until the evaluator runtime context can expose
/// active attrset roots, native shallow-merge dispatch, trap transfer, and
/// native value-return materialization to this ABI boundary.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_update`]. `left` and `right` must be Rust-valid
/// [`Value`] instances with valid tag discriminants. The current trap-only
/// wrapper aborts before decoding `_rt` or inspecting either operand; future
/// update dispatch will require all three arguments to be valid for the active
/// evaluator runtime.
pub type RuntimeAttrUpdateNativeFn = unsafe extern "C" fn(*mut c_void, Value, Value) -> Value;

const ATTR_ACCESS_KEYED_REMAINING_EXPORT_BLOCKERS: &[RuntimeAttrAccessNativeExportBlocker] = &[
    RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
];

const ATTR_UPDATE_REMAINING_EXPORT_BLOCKERS: &[RuntimeAttrAccessNativeExportBlocker] = &[
    RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::NativeAttrUpdateMergeUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
];

/// Aborts through the frozen keyed attr-presence native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_has_attr`. It accepts the
/// frozen runtime-context pointer plus by-value attrset receiver, symbol id, and
/// inline-cache site id, then aborts until native wrappers can safely enter the
/// evaluator's attr-presence machinery and return a materialized Nix boolean.
/// Returning today would be unsound because the wrapper cannot preserve checked
/// attrset selection semantics, inline-cache state, or evaluator trap behavior
/// without runtime context.
///
/// # Safety
///
/// `attrs` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. `symbol` and `site` must use the frozen `u32`
/// ABI representation for the active evaluator's symbol table and inline-cache
/// site ids. The current wrapper aborts before decoding `_rt`, converting ids,
/// or inspecting `attrs`. The caller must also ensure the host ABI used to call
/// this function matches the frozen `aos_has_attr` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_has_attr(
    _rt: *mut c_void,
    _attrs: Value,
    _symbol: u32,
    _site: u32,
) -> Value {
    process::abort()
}

/// Aborts through the frozen keyed attr-select native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_select_ic`. It accepts the
/// frozen runtime-context pointer plus by-value attrset receiver, symbol id, and
/// inline-cache site id, then aborts until native wrappers can safely enter the
/// evaluator's checked select-cache machinery and return a materialized
/// [`Value`]. Returning today would be unsound because the wrapper cannot
/// preserve missing-attribute errors, non-attrset errors, inline-cache state, or
/// evaluator trap behavior without runtime context.
///
/// # Safety
///
/// `attrs` must be a Rust-valid [`Value`] with a valid tag discriminant before
/// crossing this ABI boundary. `symbol` and `site` must use the frozen `u32`
/// ABI representation for the active evaluator's symbol table and inline-cache
/// site ids. The current wrapper aborts before decoding `_rt`, converting ids,
/// or inspecting `attrs`. The caller must also ensure the host ABI used to call
/// this function matches the frozen `aos_select_ic` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_select_ic(
    _rt: *mut c_void,
    _attrs: Value,
    _symbol: u32,
    _site: u32,
) -> Value {
    process::abort()
}

/// Aborts through the frozen attrset-update native ABI body.
///
/// This wrapper is the trap-only C ABI body for `aos_update`. It accepts the
/// frozen runtime-context pointer plus by-value left and right operands, then
/// aborts until native wrappers can safely enter the evaluator's shallow
/// right-biased merge machinery and return a materialized [`Value`]. Returning
/// today would be unsound because the wrapper cannot preserve attrset update
/// semantics, operand error behavior, or evaluator trap behavior without runtime
/// context.
///
/// # Safety
///
/// `left` and `right` must be Rust-valid [`Value`] instances with valid tag
/// discriminants before crossing this ABI boundary. The current wrapper aborts
/// before decoding `_rt` or inspecting either operand. The caller must also
/// ensure the host ABI used to call this function matches the frozen
/// `aos_update` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_update(_rt: *mut c_void, _left: Value, _right: Value) -> Value {
    process::abort()
}

/// Returns metadata for exported attrset-access wrappers in symbol order.
pub fn runtime_attr_access_native_wrapper_bindings() -> Vec<RuntimeAttrAccessNativeWrapperBinding> {
    vec![
        RuntimeAttrAccessNativeWrapperBinding::aos_has_attr(),
        RuntimeAttrAccessNativeWrapperBinding::aos_select_ic(),
        RuntimeAttrAccessNativeWrapperBinding::aos_update(),
    ]
}

/// Process-local address metadata for one attrset-access native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAttrAccessNativeWrapperAddress {
    ptr: *mut c_void,
}

impl RuntimeAttrAccessNativeWrapperAddress {
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

/// Typed function pointer for one attrset-access native wrapper.
#[derive(Clone, Copy, Debug)]
pub enum RuntimeAttrAccessNativeWrapperFunction {
    /// The keyed `aos_has_attr` wrapper.
    HasAttr(RuntimeAttrAccessKeyedNativeFn),
    /// The keyed `aos_select_ic` wrapper.
    SelectIc(RuntimeAttrAccessKeyedNativeFn),
    /// The `aos_update` wrapper.
    Update(RuntimeAttrUpdateNativeFn),
}

/// Metadata for one trap-only attrset-access native wrapper.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeAttrAccessNativeWrapperBinding {
    entrypoint: RuntimeAttrAccessEntryPoint,
    function: RuntimeAttrAccessNativeWrapperFunction,
    address: RuntimeAttrAccessNativeWrapperAddress,
    remaining_export_blockers: &'static [RuntimeAttrAccessNativeExportBlocker],
}

impl RuntimeAttrAccessNativeWrapperBinding {
    fn aos_has_attr() -> Self {
        Self {
            entrypoint: RuntimeAttrAccessEntryPoint::AosHasAttr,
            function: RuntimeAttrAccessNativeWrapperFunction::HasAttr(aos_has_attr),
            address: RuntimeAttrAccessNativeWrapperAddress::new(
                aos_has_attr as RuntimeAttrAccessKeyedNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ATTR_ACCESS_KEYED_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_select_ic() -> Self {
        Self {
            entrypoint: RuntimeAttrAccessEntryPoint::AosSelectIc,
            function: RuntimeAttrAccessNativeWrapperFunction::SelectIc(aos_select_ic),
            address: RuntimeAttrAccessNativeWrapperAddress::new(
                aos_select_ic as RuntimeAttrAccessKeyedNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ATTR_ACCESS_KEYED_REMAINING_EXPORT_BLOCKERS,
        }
    }

    fn aos_update() -> Self {
        Self {
            entrypoint: RuntimeAttrAccessEntryPoint::AosUpdate,
            function: RuntimeAttrAccessNativeWrapperFunction::Update(aos_update),
            address: RuntimeAttrAccessNativeWrapperAddress::new(
                aos_update as RuntimeAttrUpdateNativeFn as *mut c_void,
            ),
            remaining_export_blockers: ATTR_UPDATE_REMAINING_EXPORT_BLOCKERS,
        }
    }

    /// Returns the attrset-access entry point served by this wrapper.
    pub const fn entrypoint(self) -> RuntimeAttrAccessEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name served by this wrapper.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen ABI signature served by this wrapper.
    pub const fn abi_signature(self) -> RuntimeAttrAccessAbiSignature {
        self.entrypoint.abi_signature()
    }

    /// Returns the typed native wrapper function pointer.
    pub const fn function(self) -> RuntimeAttrAccessNativeWrapperFunction {
        self.function
    }

    /// Returns the process-local native wrapper address.
    pub const fn address(self) -> RuntimeAttrAccessNativeWrapperAddress {
        self.address
    }

    /// Returns blockers that still prevent final native-export registration.
    pub const fn remaining_export_blockers(
        self,
    ) -> &'static [RuntimeAttrAccessNativeExportBlocker] {
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

    const HAS_ATTR_ABORT_CHILD: &str = "attr::tests::aos_has_attr_native_wrapper_aborts_child";
    const SELECT_IC_ABORT_CHILD: &str = "attr::tests::aos_select_ic_native_wrapper_aborts_child";
    const UPDATE_ABORT_CHILD: &str = "attr::tests::aos_update_native_wrapper_aborts_child";

    #[test]
    fn attr_access_native_wrapper_bindings_preserve_symbol_abi_and_address() {
        let bindings = runtime_attr_access_native_wrapper_bindings();

        assert_eq!(bindings.len(), 3);
        let has_attr = bindings[0];
        assert_eq!(
            has_attr.entrypoint(),
            RuntimeAttrAccessEntryPoint::AosHasAttr
        );
        assert_eq!(has_attr.symbol_name(), "aos_has_attr");
        assert_eq!(
            has_attr.abi_signature(),
            RuntimeAttrAccessEntryPoint::AosHasAttr.abi_signature()
        );
        assert!(matches!(
            has_attr.function(),
            RuntimeAttrAccessNativeWrapperFunction::HasAttr(function)
                if function as RuntimeAttrAccessKeyedNativeFn as *mut c_void
                    == aos_has_attr as RuntimeAttrAccessKeyedNativeFn as *mut c_void
        ));
        assert_eq!(
            has_attr.address().as_ptr(),
            aos_has_attr as RuntimeAttrAccessKeyedNativeFn as *mut c_void
        );
        assert!(has_attr.address().is_non_null());
        assert_eq!(
            has_attr.remaining_export_blockers(),
            [
                RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
            ]
            .as_slice()
        );
        assert!(!has_attr.is_export_ready());

        let select_ic = bindings[1];
        assert_eq!(
            select_ic.entrypoint(),
            RuntimeAttrAccessEntryPoint::AosSelectIc
        );
        assert_eq!(select_ic.symbol_name(), "aos_select_ic");
        assert_eq!(
            select_ic.abi_signature(),
            RuntimeAttrAccessEntryPoint::AosSelectIc.abi_signature()
        );
        assert!(matches!(
            select_ic.function(),
            RuntimeAttrAccessNativeWrapperFunction::SelectIc(function)
                if function as RuntimeAttrAccessKeyedNativeFn as *mut c_void
                    == aos_select_ic as RuntimeAttrAccessKeyedNativeFn as *mut c_void
        ));
        assert_eq!(
            select_ic.address().as_ptr(),
            aos_select_ic as RuntimeAttrAccessKeyedNativeFn as *mut c_void
        );
        assert!(select_ic.address().is_non_null());
        assert_eq!(
            select_ic.remaining_export_blockers(),
            [
                RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
            ]
            .as_slice()
        );
        assert!(!select_ic.is_export_ready());

        let update = bindings[2];
        assert_eq!(update.entrypoint(), RuntimeAttrAccessEntryPoint::AosUpdate);
        assert_eq!(update.symbol_name(), "aos_update");
        assert_eq!(
            update.abi_signature(),
            RuntimeAttrAccessEntryPoint::AosUpdate.abi_signature()
        );
        assert!(matches!(
            update.function(),
            RuntimeAttrAccessNativeWrapperFunction::Update(function)
                if function as RuntimeAttrUpdateNativeFn as *mut c_void
                    == aos_update as RuntimeAttrUpdateNativeFn as *mut c_void
        ));
        assert_eq!(
            update.address().as_ptr(),
            aos_update as RuntimeAttrUpdateNativeFn as *mut c_void
        );
        assert!(update.address().is_non_null());
        assert_eq!(
            update.remaining_export_blockers(),
            [
                RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::NativeAttrUpdateMergeUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
            ]
            .as_slice()
        );
        assert!(!update.is_export_ready());
    }

    #[test]
    fn aos_has_attr_native_wrapper_aborts() {
        assert_child_process_aborts(HAS_ATTR_ABORT_CHILD);
    }

    #[test]
    fn aos_select_ic_native_wrapper_aborts() {
        assert_child_process_aborts(SELECT_IC_ABORT_CHILD);
    }

    #[test]
    fn aos_update_native_wrapper_aborts() {
        assert_child_process_aborts(UPDATE_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_has_attr_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let attrs = Value::null();
        let symbol = 0;
        let site = 0;

        // SAFETY: `attrs` has a valid tag discriminant. The current wrapper is
        // trap-only and aborts before decoding `rt`, converting `symbol` or
        // `site`, or inspecting `attrs`.
        let _ = unsafe { aos_has_attr(rt, attrs, symbol, site) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_select_ic_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let attrs = Value::null();
        let symbol = 0;
        let site = 0;

        // SAFETY: `attrs` has a valid tag discriminant. The current wrapper is
        // trap-only and aborts before decoding `rt`, converting `symbol` or
        // `site`, or inspecting `attrs`.
        let _ = unsafe { aos_select_ic(rt, attrs, symbol, site) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_update_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let left = Value::null();
        let right = Value::int(1);

        // SAFETY: `left` and `right` have valid tag discriminants. The current
        // wrapper is trap-only and aborts before decoding `rt` or inspecting
        // either operand.
        let _ = unsafe { aos_update(rt, left, right) };
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
