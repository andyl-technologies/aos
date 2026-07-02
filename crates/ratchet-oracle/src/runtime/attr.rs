//! Runtime attribute-access helper metadata.
//!
//! The tree-walk oracle already performs checked attribute lookup through its
//! select evaluator path after callers have forced the receiver to WHNF. Future
//! native tiers reference the single-key inline cache boundary through the stable
//! `aos_select_ic` helper symbol. This module pins the helper's safe family
//! metadata and exposes a process-local Rust callable wrapper for registration
//! preflight only. It does not export a C ABI
//! function, install a polymorphic inline cache, decode a native runtime
//! context, or register a JIT symbol.

use crate::compile::{IrId, IrInlineCacheSiteId};
use crate::eval::tree_walk::{TreeWalk, TreeWalkError};
use crate::syntax::{Span, Symbol};
use crate::value::Value;

/// The attribute-access entry point owned by the runtime ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAttrAccessEntryPoint {
    /// The `aos_select_ic` helper that selects one static attr key from an attrset value.
    AosSelectIc,
}

/// Frozen attribute-access entry points registered by future native runtimes.
pub const RUNTIME_ATTR_ACCESS_ENTRYPOINTS: &[RuntimeAttrAccessEntryPoint] =
    &[RuntimeAttrAccessEntryPoint::AosSelectIc];

const SELECT_IC_PARAMETERS: &[RuntimeAttrAccessAbiParameter] = &[
    RuntimeAttrAccessAbiParameter::new("rt", RuntimeAttrAccessAbiParameterKind::RuntimeContext),
    RuntimeAttrAccessAbiParameter::new("attrs", RuntimeAttrAccessAbiParameterKind::Value),
    RuntimeAttrAccessAbiParameter::new("symbol", RuntimeAttrAccessAbiParameterKind::SymbolId),
    RuntimeAttrAccessAbiParameter::new(
        "site",
        RuntimeAttrAccessAbiParameterKind::InlineCacheSiteId,
    ),
];

/// Frozen attribute-access helper ABI signatures for future native runtimes.
pub const RUNTIME_ATTR_ACCESS_ABI_SIGNATURES: &[RuntimeAttrAccessAbiSignature] =
    &[RuntimeAttrAccessAbiSignature::new(
        RuntimeAttrAccessEntryPoint::AosSelectIc,
        SELECT_IC_PARAMETERS,
        RuntimeAttrAccessAbiReturnKind::Value,
    )];

type RuntimeSelectIcFn = fn(
    &mut TreeWalk,
    IrId,
    Span,
    Value,
    Symbol,
    IrInlineCacheSiteId,
) -> Result<Value, TreeWalkError>;

fn rust_callable_aos_select_ic(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    attrs: Value,
    symbol: Symbol,
    site: IrInlineCacheSiteId,
) -> Result<Value, TreeWalkError> {
    eval.select_attr_value(id, span, attrs, symbol, site)
}

/// Returns attribute-access helper bindings with callable Rust wrapper addresses.
///
/// The addresses are process-local Rust function addresses for registration
/// preflight metadata. They are not stable across builds or processes, are not
/// exported C symbols, and are not callable with
/// [`RuntimeAttrAccessAbiSignature`].
pub fn runtime_attr_access_rust_callable_bindings() -> Vec<RuntimeAttrAccessRustCallableBinding> {
    runtime_attr_access_entrypoints()
        .iter()
        .copied()
        .map(RuntimeAttrAccessEntryPoint::rust_callable_binding)
        .collect()
}

/// Builds native-export readiness metadata for frozen attribute-access helpers.
///
/// The returned report is intentionally negative today: the helper has frozen
/// ABI metadata and a safe evaluator-callable wrapper, but no exported C ABI
/// wrapper or inline-cache implementation. The blocker list is precise so
/// later unsafe wrapper work can clear individual obligations without treating
/// the Rust callable as a native ABI export.
pub fn runtime_attr_access_native_export_preflight() -> RuntimeAttrAccessNativeExportPreflight {
    RuntimeAttrAccessNativeExportPreflight::new(
        runtime_attr_access_entrypoints()
            .iter()
            .copied()
            .map(RuntimeAttrAccessNativeExportReadiness::for_entrypoint)
            .collect(),
    )
}

/// Returns the frozen attribute-access entry-point inventory.
pub const fn runtime_attr_access_entrypoints() -> &'static [RuntimeAttrAccessEntryPoint] {
    RUNTIME_ATTR_ACCESS_ENTRYPOINTS
}

/// Returns the frozen attribute-access helper ABI signature inventory.
pub const fn runtime_attr_access_abi_signatures() -> &'static [RuntimeAttrAccessAbiSignature] {
    RUNTIME_ATTR_ACCESS_ABI_SIGNATURES
}

impl RuntimeAttrAccessEntryPoint {
    /// Returns the stable runtime symbol name for this attribute-access entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosSelectIc => "aos_select_ic",
        }
    }

    /// Returns the attribute-access entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_select_ic" => Some(Self::AosSelectIc),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this attribute-access entry point.
    pub const fn abi_signature(self) -> RuntimeAttrAccessAbiSignature {
        match self {
            Self::AosSelectIc => RuntimeAttrAccessAbiSignature::new(
                self,
                SELECT_IC_PARAMETERS,
                RuntimeAttrAccessAbiReturnKind::Value,
            ),
        }
    }

    /// Returns the callable Rust evaluator-wrapper binding for this entry point.
    ///
    /// The callable's Rust shape is separate from the frozen native ABI
    /// signature because runtime-context decoding, symbol-table binding,
    /// inline-cache dispatch, trap transfer, and by-value return materialization
    /// are not implemented yet.
    pub fn rust_callable_binding(self) -> RuntimeAttrAccessRustCallableBinding {
        RuntimeAttrAccessRustCallableBinding::new(
            self,
            self.rust_callable_shape(),
            self.rust_callable_address(),
        )
    }

    /// Returns the Rust evaluator-wrapper call shape for this entry point.
    pub const fn rust_callable_shape(self) -> RuntimeAttrAccessRustCallableShape {
        match self {
            Self::AosSelectIc => RuntimeAttrAccessRustCallableShape::TreeWalkSelectAttrValue,
        }
    }

    /// Returns the process-local Rust evaluator-wrapper address for this entry point.
    ///
    /// The address is suitable for registration preflight metadata only. It is
    /// not an exported C ABI symbol, is not callable with the frozen native ABI
    /// signature, and must not be persisted.
    pub fn rust_callable_address(self) -> RuntimeAttrAccessRustCallableAddress {
        let ptr = match self {
            Self::AosSelectIc => rust_callable_aos_select_ic as RuntimeSelectIcFn as *const (),
        };
        RuntimeAttrAccessRustCallableAddress::new(ptr)
    }

    /// Returns the current native-export blockers for this attribute-access helper.
    pub const fn native_export_blockers(self) -> &'static [RuntimeAttrAccessNativeExportBlocker] {
        match self {
            Self::AosSelectIc => ATTR_ACCESS_NATIVE_EXPORT_BLOCKERS,
        }
    }
}

/// The Rust function shape behind a callable attribute-access wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAttrAccessRustCallableShape {
    /// `fn(&mut TreeWalk, IrId, Span, Value, Symbol, IrInlineCacheSiteId) -> Result<Value, TreeWalkError>`.
    TreeWalkSelectAttrValue,
}

/// A process-local callable Rust attribute-access wrapper address.
///
/// This pointer identifies a Rust function in the current process. It is used
/// as registration metadata for later native startup binding and is
/// intentionally not serialized or treated as stable ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAttrAccessRustCallableAddress {
    ptr: *const (),
}

impl RuntimeAttrAccessRustCallableAddress {
    const fn new(ptr: *const ()) -> Self {
        Self { ptr }
    }

    /// Returns the process-local function pointer.
    pub const fn as_ptr(self) -> *const () {
        self.ptr
    }

    /// Returns true when the address pointer is non-null.
    pub const fn is_non_null(self) -> bool {
        !self.ptr.is_null()
    }
}

/// A callable Rust wrapper binding for one attribute-access helper entry point.
///
/// This is not a native ABI binding. It deliberately omits
/// [`RuntimeAttrAccessAbiSignature`] because this Rust callable uses a mutable
/// [`TreeWalk`], typed oracle-only symbol/site ids, and returns [`TreeWalkError`]
/// through [`Result`], while the frozen native ABI will eventually decode a
/// runtime-context pointer and transfer failures through evaluator trap
/// machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAttrAccessRustCallableBinding {
    entrypoint: RuntimeAttrAccessEntryPoint,
    shape: RuntimeAttrAccessRustCallableShape,
    address: RuntimeAttrAccessRustCallableAddress,
}

impl RuntimeAttrAccessRustCallableBinding {
    const fn new(
        entrypoint: RuntimeAttrAccessEntryPoint,
        shape: RuntimeAttrAccessRustCallableShape,
        address: RuntimeAttrAccessRustCallableAddress,
    ) -> Self {
        Self {
            entrypoint,
            shape,
            address,
        }
    }

    /// Returns the attribute-access entry point served by this binding.
    pub const fn entrypoint(self) -> RuntimeAttrAccessEntryPoint {
        self.entrypoint
    }

    /// Returns the Rust function shape behind this binding.
    pub const fn shape(self) -> RuntimeAttrAccessRustCallableShape {
        self.shape
    }

    /// Returns the stable runtime symbol name served by this binding.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the process-local callable Rust address for this binding.
    pub const fn address(self) -> RuntimeAttrAccessRustCallableAddress {
        self.address
    }
}

/// A missing piece before an attribute-access helper can become a native ABI export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAttrAccessNativeExportBlocker {
    /// No `unsafe extern "C"` symbol body exists for the frozen helper name.
    MissingExternCWrapper,
    /// Native wrappers cannot yet decode the evaluator runtime context pointer.
    RuntimeContextDecodeUnimplemented,
    /// Native wrappers cannot yet bind the receiver value as an active root.
    ActiveAttrsetRootBindingUnimplemented,
    /// Native wrappers cannot yet bind native symbol ids to the evaluator symbol table.
    SymbolTableBindingUnimplemented,
    /// Native wrappers cannot yet bind inline-cache site ids to evaluator metadata.
    InlineCacheSiteBindingUnimplemented,
    /// The hidden-class/PIC dispatch path behind `aos_select_ic` is not implemented yet.
    InlineCacheDispatchUnimplemented,
    /// Helper failures cannot yet transfer into evaluator trap/error machinery.
    TrapTransferUnimplemented,
    /// The by-value [`Value`] return is not yet materialized through the native ABI.
    NativeValueReturnUnmaterialized,
}

const ATTR_ACCESS_NATIVE_EXPORT_BLOCKERS: &[RuntimeAttrAccessNativeExportBlocker] = &[
    RuntimeAttrAccessNativeExportBlocker::MissingExternCWrapper,
    RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
];

/// Native-export readiness for one frozen attribute-access helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAttrAccessNativeExportReadiness {
    entrypoint: RuntimeAttrAccessEntryPoint,
    abi_signature: RuntimeAttrAccessAbiSignature,
    rust_callable_binding: RuntimeAttrAccessRustCallableBinding,
    blockers: &'static [RuntimeAttrAccessNativeExportBlocker],
}

impl RuntimeAttrAccessNativeExportReadiness {
    fn for_entrypoint(entrypoint: RuntimeAttrAccessEntryPoint) -> Self {
        Self {
            entrypoint,
            abi_signature: entrypoint.abi_signature(),
            rust_callable_binding: entrypoint.rust_callable_binding(),
            blockers: entrypoint.native_export_blockers(),
        }
    }

    /// Returns the attribute-access entry point served by this readiness record.
    pub const fn entrypoint(&self) -> RuntimeAttrAccessEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this readiness record.
    pub const fn symbol_name(&self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen native ABI signature for this attribute-access helper.
    pub const fn abi_signature(&self) -> RuntimeAttrAccessAbiSignature {
        self.abi_signature
    }

    /// Returns the current Rust callable binding.
    pub const fn rust_callable_binding(&self) -> RuntimeAttrAccessRustCallableBinding {
        self.rust_callable_binding
    }

    /// Returns the current blockers before this helper can be a native ABI export.
    pub const fn blockers(&self) -> &'static [RuntimeAttrAccessNativeExportBlocker] {
        self.blockers
    }

    /// Returns true when this helper has exported native ABI metadata.
    pub const fn is_export_ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Native-export readiness report for frozen attribute-access helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAttrAccessNativeExportPreflight {
    readiness: Vec<RuntimeAttrAccessNativeExportReadiness>,
}

impl RuntimeAttrAccessNativeExportPreflight {
    fn new(readiness: Vec<RuntimeAttrAccessNativeExportReadiness>) -> Self {
        Self { readiness }
    }

    /// Returns attribute-access native-export readiness in entry-point order.
    pub fn readiness(&self) -> &[RuntimeAttrAccessNativeExportReadiness] {
        &self.readiness
    }

    /// Returns true when every attribute-access helper has native ABI export metadata.
    pub fn is_complete(&self) -> bool {
        self.readiness.iter().all(|record| record.is_export_ready())
    }

    /// Returns the readiness record for `symbol_name`, when present.
    pub fn readiness_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&RuntimeAttrAccessNativeExportReadiness> {
        self.readiness
            .iter()
            .find(|record| record.symbol_name() == symbol_name)
    }
}

/// A frozen attribute-access ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAttrAccessAbiSignature {
    entrypoint: RuntimeAttrAccessEntryPoint,
    parameters: &'static [RuntimeAttrAccessAbiParameter],
    return_kind: RuntimeAttrAccessAbiReturnKind,
}

impl RuntimeAttrAccessAbiSignature {
    const fn new(
        entrypoint: RuntimeAttrAccessEntryPoint,
        parameters: &'static [RuntimeAttrAccessAbiParameter],
        return_kind: RuntimeAttrAccessAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the attribute-access ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeAttrAccessEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeAttrAccessEntryPoint::abi_signature)
    }

    /// Returns the attribute-access entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeAttrAccessEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeAttrAccessAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeAttrAccessAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen attribute-access ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAttrAccessAbiParameter {
    name: &'static str,
    kind: RuntimeAttrAccessAbiParameterKind,
}

impl RuntimeAttrAccessAbiParameter {
    const fn new(name: &'static str, kind: RuntimeAttrAccessAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeAttrAccessAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by attribute-access symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAttrAccessAbiParameterKind {
    /// A pointer to the evaluator runtime context.
    RuntimeContext,
    /// A by-value runtime value word pair.
    Value,
    /// A dense interned-symbol table index.
    SymbolId,
    /// A stable per-lookup inline-cache site identifier.
    InlineCacheSiteId,
}

/// The success-path machine-level result kind returned by attribute-access helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAttrAccessAbiReturnKind {
    /// A by-value runtime value word pair.
    Value,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compile::{
        RuntimeAbiParameterKind, RuntimeAbiReturnKind, RuntimeHelperRole, resolve,
        runtime_helper_call_signature, runtime_helper_symbols,
    };
    use crate::eval::tree_walk::TreeWalkErrorKind;
    use crate::syntax::parse_str;
    use crate::value::ValueTag;

    use super::*;

    #[test]
    fn runtime_attr_access_symbol_is_safe_select_subset_of_core_inventory() {
        let helper_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::AttrsetAccess)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();
        let entrypoint_symbols = runtime_attr_access_entrypoints()
            .iter()
            .copied()
            .map(RuntimeAttrAccessEntryPoint::symbol_name)
            .collect::<BTreeSet<_>>();
        let signature_symbols = runtime_attr_access_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeAttrAccessAbiSignature::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            helper_symbols,
            BTreeSet::from(["aos_has_attr", "aos_select_ic", "aos_update"])
        );
        assert_eq!(entrypoint_symbols, BTreeSet::from(["aos_select_ic"]));
        assert_eq!(signature_symbols, entrypoint_symbols);
    }

    #[test]
    fn attr_access_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_attr_access_entrypoints(),
            [RuntimeAttrAccessEntryPoint::AosSelectIc]
        );

        for entrypoint in runtime_attr_access_entrypoints() {
            assert_eq!(
                RuntimeAttrAccessEntryPoint::from_symbol_name(entrypoint.symbol_name()),
                Some(*entrypoint)
            );
            assert_eq!(
                RuntimeAttrAccessAbiSignature::from_symbol_name(entrypoint.symbol_name()),
                Some(entrypoint.abi_signature())
            );
        }
        for symbol in runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.name() != "aos_select_ic")
        {
            assert_eq!(
                RuntimeAttrAccessEntryPoint::from_symbol_name(symbol.name()),
                None,
                "{} is not an attribute-access entry point with a Rust callable",
                symbol.name()
            );
            assert_eq!(
                RuntimeAttrAccessAbiSignature::from_symbol_name(symbol.name()),
                None,
                "{} has no attribute-access ABI signature in this family",
                symbol.name()
            );
        }
    }

    #[test]
    fn attr_access_abi_signature_pins_select_ic_value_return() {
        let signature = RuntimeAttrAccessEntryPoint::AosSelectIc.abi_signature();

        assert_eq!(
            runtime_attr_access_abi_signatures(),
            [RuntimeAttrAccessAbiSignature::new(
                RuntimeAttrAccessEntryPoint::AosSelectIc,
                SELECT_IC_PARAMETERS,
                RuntimeAttrAccessAbiReturnKind::Value,
            )]
        );
        assert_eq!(
            signature.entrypoint(),
            RuntimeAttrAccessEntryPoint::AosSelectIc
        );
        assert_eq!(signature.symbol_name(), "aos_select_ic");
        assert_eq!(
            signature.parameters(),
            [
                RuntimeAttrAccessAbiParameter::new(
                    "rt",
                    RuntimeAttrAccessAbiParameterKind::RuntimeContext,
                ),
                RuntimeAttrAccessAbiParameter::new(
                    "attrs",
                    RuntimeAttrAccessAbiParameterKind::Value,
                ),
                RuntimeAttrAccessAbiParameter::new(
                    "symbol",
                    RuntimeAttrAccessAbiParameterKind::SymbolId,
                ),
                RuntimeAttrAccessAbiParameter::new(
                    "site",
                    RuntimeAttrAccessAbiParameterKind::InlineCacheSiteId,
                ),
            ]
            .as_slice()
        );
        assert_eq!(
            signature.return_kind(),
            RuntimeAttrAccessAbiReturnKind::Value
        );
    }

    #[test]
    fn attr_access_abi_signature_matches_core_runtime_call_metadata() {
        let local_signature = RuntimeAttrAccessEntryPoint::AosSelectIc.abi_signature();
        let core_signature = runtime_helper_call_signature(local_signature.symbol_name())
            .expect("core select-ic ABI");
        let core_parameters = core_signature
            .parameters()
            .iter()
            .map(|parameter| (parameter.name(), parameter.kind()))
            .collect::<Vec<_>>();

        assert_eq!(
            local_signature
                .parameters()
                .iter()
                .map(|parameter| (parameter.name(), parameter.kind()))
                .collect::<Vec<_>>(),
            vec![
                ("rt", RuntimeAttrAccessAbiParameterKind::RuntimeContext),
                ("attrs", RuntimeAttrAccessAbiParameterKind::Value),
                ("symbol", RuntimeAttrAccessAbiParameterKind::SymbolId),
                ("site", RuntimeAttrAccessAbiParameterKind::InlineCacheSiteId,),
            ]
        );
        assert_eq!(
            core_parameters,
            vec![
                ("rt", RuntimeAbiParameterKind::RuntimeContext),
                ("attrs", RuntimeAbiParameterKind::Value),
                ("symbol", RuntimeAbiParameterKind::SymbolId),
                ("site", RuntimeAbiParameterKind::InlineCacheSiteId),
            ]
        );
        assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            local_signature.return_kind(),
            RuntimeAttrAccessAbiReturnKind::Value
        );
    }

    #[test]
    fn attr_access_rust_callable_bindings_preserve_entrypoint_inventory() {
        let bindings = runtime_attr_access_rust_callable_bindings();
        let expected = [(
            RuntimeAttrAccessEntryPoint::AosSelectIc,
            RuntimeAttrAccessRustCallableShape::TreeWalkSelectAttrValue,
            rust_callable_aos_select_ic as RuntimeSelectIcFn as *const (),
        )];

        assert_eq!(bindings.len(), expected.len());
        assert_eq!(
            bindings
                .iter()
                .copied()
                .map(RuntimeAttrAccessRustCallableBinding::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_attr_access_entrypoints()
        );
        assert_eq!(
            bindings
                .iter()
                .copied()
                .map(|binding| (
                    binding.entrypoint(),
                    binding.shape(),
                    binding.address().as_ptr(),
                ))
                .collect::<Vec<_>>()
                .as_slice(),
            expected.as_slice()
        );
        assert_eq!(
            bindings
                .iter()
                .copied()
                .map(|binding| binding.entrypoint().abi_signature())
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_attr_access_abi_signatures()
        );

        for binding in bindings {
            assert_eq!(binding.symbol_name(), binding.entrypoint().symbol_name());
            assert_eq!(binding.entrypoint().rust_callable_binding(), binding);
            assert_eq!(binding.shape(), binding.entrypoint().rust_callable_shape());
            assert_eq!(
                binding.address(),
                binding.entrypoint().rust_callable_address()
            );
            assert!(
                binding.address().is_non_null(),
                "{} Rust-callable address is non-null",
                binding.symbol_name()
            );
        }
    }

    #[test]
    fn attr_access_native_export_preflight_preserves_frozen_abi_and_callable() {
        let preflight = runtime_attr_access_native_export_preflight();

        assert!(!preflight.is_complete());
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeAttrAccessNativeExportReadiness::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_attr_access_entrypoints()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeAttrAccessNativeExportReadiness::abi_signature)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_attr_access_abi_signatures()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeAttrAccessNativeExportReadiness::rust_callable_binding)
                .collect::<Vec<_>>(),
            runtime_attr_access_rust_callable_bindings()
        );

        let record = preflight
            .readiness_for_symbol("aos_select_ic")
            .expect("select-ic export readiness exists");

        assert_eq!(
            record.entrypoint(),
            RuntimeAttrAccessEntryPoint::AosSelectIc
        );
        assert_eq!(record.symbol_name(), "aos_select_ic");
        assert_eq!(
            record.blockers(),
            RuntimeAttrAccessEntryPoint::AosSelectIc.native_export_blockers()
        );
        assert!(!record.is_export_ready());
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::MissingExternCWrapper)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented)
        );
        assert!(record.blockers().contains(
            &RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented
        ));
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented)
        );
        assert!(
            record.blockers().contains(
                &RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented
            )
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized)
        );
    }

    #[test]
    fn attr_access_rust_callable_selects_static_attr_values() {
        let source = "{ a = 42; nested.z = 0; }";
        let span = Span::new(0, source.len() as u32);
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut symbols = ir.symbols.clone();
        let key = symbols.intern(b"a").expect("symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let attrs = eval.eval_root().expect("attrset evaluates");
        let selected = rust_callable_aos_select_ic(
            &mut eval,
            ir.root,
            span,
            attrs,
            key,
            IrInlineCacheSiteId::new(7),
        )
        .expect("static attr selection succeeds");

        assert_eq!(selected.as_int().expect("selected value is int"), 42);
    }

    #[test]
    fn attr_access_rust_callable_reports_missing_and_non_attrs() {
        let source = "{ a = 42; nested.z = 0; }";
        let span = Span::new(0, source.len() as u32);
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut symbols = ir.symbols.clone();
        let missing_key = symbols.intern(b"z").expect("symbol exists");
        let mut eval = TreeWalk::new(&ir);
        let attrs = eval.eval_root().expect("attrset evaluates");
        let missing = rust_callable_aos_select_ic(
            &mut eval,
            ir.root,
            span,
            attrs,
            missing_key,
            IrInlineCacheSiteId::new(7),
        )
        .expect_err("missing attr reports an error");

        assert!(matches!(
            missing.kind(),
            TreeWalkErrorKind::MissingAttribute { symbol, .. } if symbol == missing_key
        ));

        let non_attrs = rust_callable_aos_select_ic(
            &mut eval,
            ir.root,
            span,
            Value::int(42),
            missing_key,
            IrInlineCacheSiteId::new(7),
        )
        .expect_err("non-attrs receiver reports a type error");

        assert!(matches!(
            non_attrs.kind(),
            TreeWalkErrorKind::Type {
                expected: "attrs",
                actual: ValueTag::Int,
                ..
            }
        ));
    }
}
