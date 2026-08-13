//! Attribute-access C ABI wrappers.
//!
//! Native tier-1 code imports attrset helpers with frozen keyed
//! `(rt, Value attrs, SymbolId, InlineCacheSiteId) -> Value` and update
//! `(rt, Value left, Value right) -> Value` signatures. This module supplies
//! success-path wrappers for `aos_has_attr`, `aos_select_ic`, and `aos_update`
//! by decoding `rt` as a scoped [`RuntimeAttrAccessContext`] and dispatching
//! through the safe tree-walk oracle helpers. An evaluator error is transferred
//! through [`crate::trap::RuntimeTrapScope`] instead of aborting when a scope is
//! active; a null pointer or malformed payload still aborts.

use std::ffi::c_void;

use ratchet_oracle::{
    compile::{IrId, IrInlineCacheSiteId},
    eval::tree_walk::TreeWalk,
    runtime::attr::{
        RuntimeAttrAccessAbiSignature, RuntimeAttrAccessEntryPoint,
        RuntimeAttrAccessNativeExportBlocker, rust_callable_aos_has_attr,
        rust_callable_aos_select_ic, rust_callable_aos_update,
    },
    syntax::{Span, Symbol},
    value::Value,
};

use crate::context::{RuntimeJitContext, with_native_runtime_context};
use crate::trap::{RuntimeTrap, record_runtime_trap, runtime_trap_sentinel_value};

/// Native C ABI function pointer shape for keyed attrset-access helpers.
///
/// The function returns a by-value [`Value`] and never unwinds across the ABI
/// boundary. An attrset-access evaluator error is transferred through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// runtime pointer or malformed payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_has_attr`] and [`aos_select_ic`]. The receiver must be a
/// Rust-valid [`Value`] with a valid tag discriminant, and `symbol` plus `site`
/// must use the frozen `u32` ABI representation for the evaluator's symbol
/// table and inline-cache site ids. The runtime pointer must satisfy the
/// [`RuntimeAttrAccessContext`] obligations documented on [`aos_has_attr`] and
/// [`aos_select_ic`].
pub type RuntimeAttrAccessKeyedNativeFn =
    unsafe extern "C" fn(*mut c_void, Value, u32, u32) -> Value;

/// Native C ABI function pointer shape for `aos_update`.
///
/// The function returns a by-value [`Value`] and never unwinds across the ABI
/// boundary. An attrset-access evaluator error is transferred through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// runtime pointer or malformed payload always aborts as a safety-contract
/// violation.
///
/// # Safety
///
/// Calls through this pointer must satisfy the same host-ABI obligations
/// documented on [`aos_update`]. `left` and `right` must be Rust-valid
/// [`Value`] instances with valid tag discriminants and heap payloads reachable
/// from the evaluator encoded by the runtime pointer.
pub type RuntimeAttrUpdateNativeFn = unsafe extern "C" fn(*mut c_void, Value, Value) -> Value;

// Trap transfer is implemented for the attrset-access wrappers, so no
// wrapper-local blocker remains. The oracle native-export gate stays
// authoritative for final admission (it still tracks `MissingFinalExportedWrapper`).
const ATTR_ACCESS_KEYED_REMAINING_EXPORT_BLOCKERS: &[RuntimeAttrAccessNativeExportBlocker] = &[];

const ATTR_UPDATE_REMAINING_EXPORT_BLOCKERS: &[RuntimeAttrAccessNativeExportBlocker] = &[];

/// Reads the frozen keyed attr-presence native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_has_attr`. It decodes
/// `rt` as a [`RuntimeAttrAccessContext`], converts `symbol` and `site` through
/// their frozen `u32` ABI representation, probes `attrs` through the safe
/// tree-walk select-cache helper, and returns a materialized Nix boolean
/// [`Value`]. Non-attr receivers return false, matching single-key IR
/// `HasAttr` semantics. An evaluator error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// `rt` must be a non-null pointer produced from a pinned live
/// [`RuntimeAttrAccessContext`] whose wrapped evaluator and IR allocation
/// outlive the call. The context must not move while the pointer is used. The
/// caller must uphold exclusive mutable access to the wrapped evaluator for the
/// duration of the call. `attrs` must be a Rust-valid [`Value`] with a valid tag
/// discriminant and heap payloads reachable from that evaluator. `symbol` and
/// `site` must use the frozen `u32` ABI representation for the active
/// evaluator's symbol table and inline-cache site ids. The caller must also
/// ensure the host ABI used to call this function matches the frozen
/// `aos_has_attr` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_has_attr(
    rt: *mut c_void,
    attrs: Value,
    symbol: u32,
    site: u32,
) -> Value {
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // RuntimeAttrAccessContext pointer contract documented on this function.
    let probed = unsafe {
        with_native_runtime_context(rt, |eval, id, span| {
            aos_has_attr_success_path(eval, id, span, attrs, symbol, site)
        })
    };
    probed
}

/// Selects through the frozen keyed attr-select native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_select_ic`. It decodes
/// `rt` as a [`RuntimeAttrAccessContext`], converts `symbol` and `site` through
/// their frozen `u32` ABI representation, selects from `attrs` through the safe
/// tree-walk select-cache helper, and returns the selected [`Value`]. An
/// evaluator error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// `rt` must be a non-null pointer produced from a pinned live
/// [`RuntimeAttrAccessContext`] whose wrapped evaluator and IR allocation
/// outlive the call. The context must not move while the pointer is used. The
/// caller must uphold exclusive mutable access to the wrapped evaluator for the
/// duration of the call. `attrs` must be a Rust-valid [`Value`] with a valid tag
/// discriminant and heap payloads reachable from that evaluator. `symbol` and
/// `site` must use the frozen `u32` ABI representation for the active
/// evaluator's symbol table and inline-cache site ids. The caller must also
/// ensure the host ABI used to call this function matches the frozen
/// `aos_select_ic` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_select_ic(
    rt: *mut c_void,
    attrs: Value,
    symbol: u32,
    site: u32,
) -> Value {
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // RuntimeAttrAccessContext pointer contract documented on this function.
    let selected = unsafe {
        with_native_runtime_context(rt, |eval, id, span| {
            aos_select_ic_success_path(eval, id, span, attrs, symbol, site)
        })
    };
    selected
}

fn aos_has_attr_success_path(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    attrs: Value,
    symbol: u32,
    site: u32,
) -> Value {
    match rust_callable_aos_has_attr(
        eval,
        id,
        span,
        attrs,
        Symbol::new(symbol),
        IrInlineCacheSiteId::new(site),
    ) {
        Ok(value) => value,
        Err(error) => {
            record_runtime_trap(RuntimeTrap::Attr(error));
            runtime_trap_sentinel_value()
        }
    }
}

fn aos_select_ic_success_path(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    attrs: Value,
    symbol: u32,
    site: u32,
) -> Value {
    match rust_callable_aos_select_ic(
        eval,
        id,
        span,
        attrs,
        Symbol::new(symbol),
        IrInlineCacheSiteId::new(site),
    ) {
        Ok(value) => value,
        Err(error) => {
            record_runtime_trap(RuntimeTrap::Attr(error));
            runtime_trap_sentinel_value()
        }
    }
}

/// Updates through the frozen attrset-update native ABI body.
///
/// This wrapper is the success-path C ABI body for `aos_update`. It decodes
/// `rt` as a [`RuntimeAttrAccessContext`], shallowly merges `left` and `right`
/// through the safe tree-walk update helper, and returns the merged attrset
/// [`Value`]. An evaluator error is recorded through the active
/// [`crate::trap::RuntimeTrapScope`] and the wrapper returns
/// [`runtime_trap_sentinel_value`]; outside a scope that error aborts. A null
/// pointer always aborts as a safety-contract violation.
///
/// # Safety
///
/// `rt` must be a non-null pointer produced from a pinned live
/// [`RuntimeAttrAccessContext`] whose wrapped evaluator and IR allocation
/// outlive the call. The context must not move while the pointer is used. The
/// caller must uphold exclusive mutable access to the wrapped evaluator for the
/// duration of the call. `left` and `right` must be Rust-valid attrset
/// [`Value`] instances with valid tag discriminants and heap payloads reachable
/// from that evaluator. The caller must also ensure the host ABI used to call
/// this function matches the frozen `aos_update` runtime signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_update(rt: *mut c_void, left: Value, right: Value) -> Value {
    // SAFETY: The wrapper's caller must satisfy the frozen native ABI and
    // RuntimeAttrAccessContext pointer contract documented on this function.
    let updated = unsafe {
        with_native_runtime_context(rt, |eval, id, span| {
            aos_update_success_path(eval, id, span, left, right)
        })
    };
    updated
}

fn aos_update_success_path(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    left: Value,
    right: Value,
) -> Value {
    match rust_callable_aos_update(eval, id, span, left, right) {
        Ok(value) => value,
        Err(error) => {
            record_runtime_trap(RuntimeTrap::Attr(error));
            runtime_trap_sentinel_value()
        }
    }
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

/// Metadata for one attrset-access native wrapper.
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

    /// Returns wrapper-local blockers that still prevent export admission.
    ///
    /// This is not the full oracle native-export gate. The oracle gate remains
    /// authoritative for final registration blockers such as missing final
    /// exported-wrapper admission; this list tracks the blockers left after
    /// this process-local wrapper body has been materialized.
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

/// Shared runtime context accepted by attrset-access native wrappers.
pub type RuntimeAttrAccessContext<'eval> = RuntimeJitContext<'eval>;

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, ExitStatus},
    };

    use ratchet_oracle::{
        compile::resolve, runtime::forcing::rust_callable_aos_force, syntax::parse_str,
        value::ValueTag,
    };

    use super::*;

    const HAS_ATTR_ABORT_CHILD: &str = "attr::tests::aos_has_attr_native_wrapper_aborts_child";
    const SELECT_IC_ABORT_CHILD: &str = "attr::tests::aos_select_ic_native_wrapper_aborts_child";
    const SELECT_IC_ERROR_ABORT_CHILD: &str =
        "attr::tests::aos_select_ic_native_wrapper_aborts_on_tree_walk_error_child";
    const UPDATE_ABORT_CHILD: &str =
        "attr::tests::aos_update_native_wrapper_aborts_on_invalid_context_child";
    const UPDATE_ERROR_ABORT_CHILD: &str =
        "attr::tests::aos_update_native_wrapper_aborts_on_tree_walk_error_child";

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
        assert!(has_attr.remaining_export_blockers().is_empty());
        assert!(has_attr.is_export_ready());

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
        assert!(select_ic.remaining_export_blockers().is_empty());
        assert!(select_ic.is_export_ready());

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
        assert!(update.remaining_export_blockers().is_empty());
        assert!(update.is_export_ready());
    }

    #[test]
    fn attr_access_native_wrapper_blockers_are_clear_while_oracle_gate_remains() {
        for binding in runtime_attr_access_native_wrapper_bindings() {
            let oracle_blockers = binding.entrypoint().native_export_blockers();

            // Trap transfer is implemented, so the wrapper carries no remaining
            // wrapper-local blocker, while the oracle native-export gate is
            // unchanged and remains authoritative for final admission.
            assert!(
                binding.remaining_export_blockers().is_empty(),
                "{} runtime-FFI wrapper has no remaining wrapper-local blocker",
                binding.symbol_name()
            );
            assert!(binding.is_export_ready());
            assert!(
                oracle_blockers
                    .contains(&RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper),
                "{} oracle export gate still tracks final admission",
                binding.symbol_name()
            );
            assert!(
                oracle_blockers
                    .contains(&RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented),
                "{} oracle export gate is unchanged by wrapper trap transfer",
                binding.symbol_name()
            );
        }
    }

    #[test]
    fn aos_has_attr_native_wrapper_reports_static_key_presence() {
        let source = "{ a = 42; nested.z = 0; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut symbols = ir.symbols.clone();
        let present_key = symbols.intern(b"a").expect("a symbol exists");
        let missing_key = symbols.intern(b"z").expect("z symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let attrs = eval.eval_root().expect("attrset evaluates");
        let mut context = std::pin::pin!(RuntimeAttrAccessContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the calls, no other
        // mutable evaluator borrow is active, and `attrs` belongs to that
        // evaluator.
        let present = unsafe { aos_has_attr(rt, attrs, present_key.as_u32(), 7) };
        // SAFETY: The same context and attrs remain live for this repeated
        // select-cache probe.
        let repeated_present = unsafe { aos_has_attr(rt, attrs, present_key.as_u32(), 7) };
        // SAFETY: The same context and attrs remain live for this missing-key
        // presence probe.
        let missing = unsafe { aos_has_attr(rt, attrs, missing_key.as_u32(), 8) };
        // SAFETY: The same context remains live. A non-attr receiver is a valid
        // single-key has-attr probe and reports absence.
        let non_attrs = unsafe { aos_has_attr(rt, Value::int(42), present_key.as_u32(), 9) };

        assert_eq!(present.as_bool().expect("present result is bool"), true);
        assert_eq!(
            repeated_present
                .as_bool()
                .expect("repeated present result is bool"),
            true
        );
        assert_eq!(missing.as_bool().expect("missing result is bool"), false);
        assert_eq!(
            non_attrs.as_bool().expect("non-attrs result is bool"),
            false
        );
        drop(context);
        assert_eq!(eval.stats().inline_cache_hits(), 1);
        assert_eq!(eval.stats().inline_cache_misses(), 2);
    }

    #[test]
    fn aos_select_ic_native_wrapper_selects_static_attr_values() {
        let source = "{ a = 42; nested.z = 0; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut symbols = ir.symbols.clone();
        let key = symbols.intern(b"a").expect("a symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let attrs = eval.eval_root().expect("attrset evaluates");
        let mut context = std::pin::pin!(RuntimeAttrAccessContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and `attrs` belongs to that
        // evaluator.
        let selected = unsafe { aos_select_ic(rt, attrs, key.as_u32(), 7) };
        // SAFETY: The same context and attrs remain live for this repeated
        // select-cache lookup.
        let repeated = unsafe { aos_select_ic(rt, attrs, key.as_u32(), 7) };

        assert_eq!(selected.as_int().expect("selected value is int"), 42);
        assert_eq!(repeated.as_int().expect("repeated value is int"), 42);
        drop(context);
        assert_eq!(eval.stats().inline_cache_hits(), 1);
        assert_eq!(eval.stats().inline_cache_misses(), 1);
    }

    #[test]
    fn aos_update_native_wrapper_updates_attrsets_shallowly() {
        let source = "{ left = { a = 1 / 0; b = 1; }; right = { b = 2; c = 3; }; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut symbols = ir.symbols.clone();
        let a = symbols.intern(b"a").expect("a symbol exists");
        let b = symbols.intern(b"b").expect("b symbol exists");
        let c = symbols.intern(b"c").expect("c symbol exists");
        let left_key = symbols.intern(b"left").expect("left symbol exists");
        let right_key = symbols.intern(b"right").expect("right symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("root attrset evaluates");
        let (left, right) = {
            let attrs = eval
                .heap()
                .get_attrs(root)
                .expect("root is heap-owned attrs");
            (
                attrs.get(left_key).expect("left exists"),
                attrs.get(right_key).expect("right exists"),
            )
        };
        let left =
            rust_callable_aos_force(&mut eval, ir.root, span, left).expect("left attrset forces");
        let right =
            rust_callable_aos_force(&mut eval, ir.root, span, right).expect("right attrset forces");
        let mut context = std::pin::pin!(RuntimeAttrAccessContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: `context` and its evaluator are live for the call, no other
        // mutable evaluator borrow is active, and both attrset operands belong
        // to that evaluator.
        let result = unsafe { aos_update(rt, left, right) };

        drop(context);
        let attrs = eval
            .heap()
            .get_attrs(result)
            .expect("update result is heap-owned");

        assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(2));
        assert_eq!(attrs.get(c).expect("c exists").as_int(), Ok(3));
        assert_eq!(attrs.get(a).expect("a remains lazy").tag(), ValueTag::Thunk);
    }

    #[test]
    fn aos_has_attr_native_wrapper_aborts_on_invalid_context() {
        assert_child_process_aborts(HAS_ATTR_ABORT_CHILD);
    }

    #[test]
    fn aos_select_ic_native_wrapper_aborts_on_invalid_context() {
        assert_child_process_aborts(SELECT_IC_ABORT_CHILD);
    }

    #[test]
    fn aos_select_ic_native_wrapper_aborts_on_tree_walk_error() {
        assert_child_process_aborts(SELECT_IC_ERROR_ABORT_CHILD);
    }

    #[test]
    fn aos_update_native_wrapper_aborts_on_invalid_context() {
        assert_child_process_aborts(UPDATE_ABORT_CHILD);
    }

    #[test]
    fn aos_update_native_wrapper_aborts_on_tree_walk_error() {
        assert_child_process_aborts(UPDATE_ERROR_ABORT_CHILD);
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_has_attr_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let attrs = Value::null();
        let symbol = 0;
        let site = 0;

        // SAFETY: `attrs` has a valid tag discriminant. The test deliberately
        // passes a null runtime context to verify abort behavior before any
        // attrset lookup can run.
        let _ = unsafe { aos_has_attr(rt, attrs, symbol, site) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_select_ic_native_wrapper_aborts_child() {
        let rt = std::ptr::null_mut();
        let attrs = Value::null();
        let symbol = 0;
        let site = 0;

        // SAFETY: `attrs` has a valid tag discriminant. The test deliberately
        // passes a null runtime context to verify abort behavior before any
        // attrset lookup can run.
        let _ = unsafe { aos_select_ic(rt, attrs, symbol, site) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_select_ic_native_wrapper_aborts_on_tree_walk_error_child() {
        let source = "{ a = 42; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut symbols = ir.symbols.clone();
        let missing_key = symbols.intern(b"z").expect("z symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let attrs = eval.eval_root().expect("attrset evaluates");
        let mut context = std::pin::pin!(RuntimeAttrAccessContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: The pinned context and its evaluator are live for the call,
        // and `attrs` belongs to that evaluator. The missing key deliberately
        // forces a tree-walk error to verify FFI abort behavior.
        let _ = unsafe { aos_select_ic(rt, attrs, missing_key.as_u32(), 7) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_update_native_wrapper_aborts_on_invalid_context_child() {
        let source = "{ a = 42; }";
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let rt = std::ptr::null_mut();
        let left = eval.eval_root().expect("attrset evaluates");
        let right = left;

        // SAFETY: `left` and `right` are attrset values owned by `eval`. The
        // test deliberately violates only the runtime-context pointer contract
        // to verify abort behavior before any attrset update can run.
        let _ = unsafe { aos_update(rt, left, right) };
    }

    #[test]
    #[ignore = "subprocess target for abort behavior"]
    fn aos_update_native_wrapper_aborts_on_tree_walk_error_child() {
        let source = "{ a = 42; }";
        let span = Span::new(0, source.len() as u32);
        let ir = lower_source(source);
        let mut eval = TreeWalk::new(&ir);
        let attrs = eval.eval_root().expect("attrset evaluates");
        let mut context = std::pin::pin!(RuntimeAttrAccessContext::new(&mut eval, ir.root, span));
        let rt = context.as_mut().as_mut_ptr();

        // SAFETY: The pinned context and its evaluator are live for the call,
        // and `attrs` belongs to that evaluator. The non-attrs left operand
        // deliberately forces a tree-walk error to verify FFI abort behavior.
        let _ = unsafe { aos_update(rt, Value::int(42), attrs) };
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

    fn lower_source(source: &str) -> ratchet_oracle::compile::Ir {
        aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers")
    }
}
