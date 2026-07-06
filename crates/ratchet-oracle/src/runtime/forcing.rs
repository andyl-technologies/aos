//! Runtime forcing helper metadata.
//!
//! The tree-walk oracle already owns thunk forcing through its internal
//! `TreeWalk::force_value` and `TreeWalk::deep_force_value` paths. Future
//! native tiers reference those operations through the stable `aos_force` and
//! `aos_force_deep` helper symbols. This module pins the helpers' safe family
//! metadata and exposes process-local Rust callable wrappers for registration
//! preflight only. It does not export a C ABI function, decode a native runtime
//! context, install a JIT symbol, or bypass the evaluator force path.

use crate::compile::IrId;
use crate::eval::{
    ForceError, ThunkState,
    tree_walk::{TreeWalk, TreeWalkError, TreeWalkErrorKind},
};
use crate::syntax::Span;
use crate::value::Value;

/// The forcing entry point owned by the runtime ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeForcingEntryPoint {
    /// The `aos_blackhole_check` helper that traps on recursive thunk re-entry.
    AosBlackholeCheck,
    /// The `aos_force` helper that forces a value to weak head normal form.
    AosForce,
    /// The `aos_force_deep` helper that recursively forces lists and attrsets.
    AosForceDeep,
}

/// Frozen forcing entry points registered by future native runtimes.
pub const RUNTIME_FORCING_ENTRYPOINTS: &[RuntimeForcingEntryPoint] = &[
    RuntimeForcingEntryPoint::AosBlackholeCheck,
    RuntimeForcingEntryPoint::AosForce,
    RuntimeForcingEntryPoint::AosForceDeep,
];

const FORCE_VALUE_PARAMETERS: &[RuntimeForcingAbiParameter] = &[
    RuntimeForcingAbiParameter::new("rt", RuntimeForcingAbiParameterKind::RuntimeContext),
    RuntimeForcingAbiParameter::new("value", RuntimeForcingAbiParameterKind::Value),
];

/// Frozen forcing helper ABI signatures for future native runtimes.
pub const RUNTIME_FORCING_ABI_SIGNATURES: &[RuntimeForcingAbiSignature] = &[
    RuntimeForcingAbiSignature::new(
        RuntimeForcingEntryPoint::AosBlackholeCheck,
        FORCE_VALUE_PARAMETERS,
        RuntimeForcingAbiReturnKind::Unit,
    ),
    RuntimeForcingAbiSignature::new(
        RuntimeForcingEntryPoint::AosForce,
        FORCE_VALUE_PARAMETERS,
        RuntimeForcingAbiReturnKind::Value,
    ),
    RuntimeForcingAbiSignature::new(
        RuntimeForcingEntryPoint::AosForceDeep,
        FORCE_VALUE_PARAMETERS,
        RuntimeForcingAbiReturnKind::Value,
    ),
];

type RuntimeForceValueFn = fn(&mut TreeWalk, IrId, Span, Value) -> Result<Value, TreeWalkError>;
type RuntimeBlackholeCheckFn = fn(&mut TreeWalk, IrId, Span, Value) -> Result<(), TreeWalkError>;

/// Runs the Rust-callable `aos_blackhole_check` helper through the tree-walk evaluator.
///
/// The helper returns for non-thunks and for evaluator-owned thunks whose state
/// is not [`ThunkState::Blackhole`]. A blackholed thunk is reported as the same
/// infinite-recursion force error used by ordinary tree-walk forcing.
///
/// # Errors
///
/// Returns [`TreeWalkError`] when a thunk payload is malformed, the thunk state
/// word is invalid, or the thunk is currently blackholed.
pub fn rust_callable_aos_blackhole_check(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    value: Value,
) -> Result<(), TreeWalkError> {
    if !value.is_thunk() {
        return Ok(());
    }
    let thunk = eval
        .heap()
        .get_thunk(value)
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
    let state = thunk
        .cell()
        .state()
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
    if state == ThunkState::Blackhole {
        return Err(TreeWalkError::new(
            TreeWalkErrorKind::Force {
                id,
                source: ForceError::InfiniteRecursion,
            },
            span,
        ));
    }
    Ok(())
}

/// Runs the Rust-callable `aos_force` helper through the tree-walk evaluator.
///
/// The helper forces `value` to weak head normal form with the same thunk
/// protocol used by ordinary tree-walk evaluation, then returns the forced
/// [`Value`].
///
/// # Errors
///
/// Returns [`TreeWalkError`] when forcing enters a blackhole, the thunk payload
/// is malformed, the forced expression fails, or the evaluator cannot preserve
/// required force roots during allocation.
pub fn rust_callable_aos_force(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    value: Value,
) -> Result<Value, TreeWalkError> {
    eval.force_value(id, span, value)
}

/// Runs the Rust-callable `aos_force_deep` helper through the tree-walk evaluator.
///
/// The helper forces `value` to weak head normal form, recursively forces list
/// elements and attrset values through the same tree-walk deep-force traversal
/// used by `builtins.deepSeq`, registers visited containers plus the current
/// container and cloned child values as transient safepoint roots across
/// recursive forcing, and returns the original container or leaf [`Value`].
///
/// # Errors
///
/// Returns [`TreeWalkError`] when ordinary forcing fails, a recursive
/// deep-force traversal cannot preserve its visited roots or transient root
/// storage, a traversed heap payload is malformed or foreign to the evaluator,
/// or any forced child expression fails.
pub fn rust_callable_aos_force_deep(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    value: Value,
) -> Result<Value, TreeWalkError> {
    let mut visited = Vec::new();
    eval.deep_force_value(id, span, value, &mut visited)
}

/// Returns forcing helper bindings with callable Rust wrapper addresses.
///
/// The addresses are process-local Rust function addresses for registration
/// preflight metadata. They are not stable across builds or processes, are not
/// exported C symbols, and are not callable with [`RuntimeForcingAbiSignature`].
pub fn runtime_forcing_rust_callable_bindings() -> Vec<RuntimeForcingRustCallableBinding> {
    runtime_forcing_entrypoints()
        .iter()
        .copied()
        .map(RuntimeForcingEntryPoint::rust_callable_binding)
        .collect()
}

/// Builds native-export readiness metadata for frozen forcing helpers.
///
/// The returned report is intentionally negative today: forcing helpers have
/// frozen ABI metadata and safe evaluator-callable wrappers, but no wrapper is
/// admitted as a final native export by this oracle gate. The blocker list is
/// precise so later unsafe wrapper work can clear individual obligations without
/// treating the Rust callable as a native ABI export.
pub fn runtime_forcing_native_export_preflight() -> RuntimeForcingNativeExportPreflight {
    RuntimeForcingNativeExportPreflight::new(
        runtime_forcing_entrypoints()
            .iter()
            .copied()
            .map(RuntimeForcingNativeExportReadiness::for_entrypoint)
            .collect(),
    )
}

/// Returns the frozen forcing entry-point inventory.
pub const fn runtime_forcing_entrypoints() -> &'static [RuntimeForcingEntryPoint] {
    RUNTIME_FORCING_ENTRYPOINTS
}

/// Returns the frozen forcing-helper ABI signature inventory.
pub const fn runtime_forcing_abi_signatures() -> &'static [RuntimeForcingAbiSignature] {
    RUNTIME_FORCING_ABI_SIGNATURES
}

impl RuntimeForcingEntryPoint {
    /// Returns the stable runtime symbol name for this forcing entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosBlackholeCheck => "aos_blackhole_check",
            Self::AosForce => "aos_force",
            Self::AosForceDeep => "aos_force_deep",
        }
    }

    /// Returns the forcing entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_blackhole_check" => Some(Self::AosBlackholeCheck),
            "aos_force" => Some(Self::AosForce),
            "aos_force_deep" => Some(Self::AosForceDeep),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this forcing entry point.
    pub const fn abi_signature(self) -> RuntimeForcingAbiSignature {
        match self {
            Self::AosBlackholeCheck => RuntimeForcingAbiSignature::new(
                self,
                FORCE_VALUE_PARAMETERS,
                RuntimeForcingAbiReturnKind::Unit,
            ),
            Self::AosForce | Self::AosForceDeep => RuntimeForcingAbiSignature::new(
                self,
                FORCE_VALUE_PARAMETERS,
                RuntimeForcingAbiReturnKind::Value,
            ),
        }
    }

    /// Returns the callable Rust evaluator-wrapper binding for this entry point.
    ///
    /// The callable's Rust shape is separate from the frozen native ABI
    /// signature because runtime-context decoding, active force-root binding,
    /// evaluator trap transfer, and complete forcing dispatch are not implemented
    /// yet.
    pub fn rust_callable_binding(self) -> RuntimeForcingRustCallableBinding {
        RuntimeForcingRustCallableBinding::new(
            self,
            self.rust_callable_shape(),
            self.rust_callable_address(),
        )
    }

    /// Returns the Rust evaluator-wrapper call shape for this entry point.
    pub const fn rust_callable_shape(self) -> RuntimeForcingRustCallableShape {
        match self {
            Self::AosBlackholeCheck => RuntimeForcingRustCallableShape::TreeWalkBlackholeCheck,
            Self::AosForce => RuntimeForcingRustCallableShape::TreeWalkForceValue,
            Self::AosForceDeep => RuntimeForcingRustCallableShape::TreeWalkDeepForceValue,
        }
    }

    /// Returns the process-local Rust evaluator-wrapper address for this entry point.
    ///
    /// The address is suitable for registration preflight metadata only. It is
    /// not an exported C ABI symbol, is not callable with the frozen native ABI
    /// signature, and must not be persisted.
    pub fn rust_callable_address(self) -> RuntimeForcingRustCallableAddress {
        let ptr = match self {
            Self::AosBlackholeCheck => {
                rust_callable_aos_blackhole_check as RuntimeBlackholeCheckFn as *const ()
            }
            Self::AosForce => rust_callable_aos_force as RuntimeForceValueFn as *const (),
            Self::AosForceDeep => rust_callable_aos_force_deep as RuntimeForceValueFn as *const (),
        };
        RuntimeForcingRustCallableAddress::new(ptr)
    }

    /// Returns the current native-export blockers for this forcing helper.
    pub const fn native_export_blockers(self) -> &'static [RuntimeForcingNativeExportBlocker] {
        match self {
            Self::AosBlackholeCheck => BLACKHOLE_CHECK_NATIVE_EXPORT_BLOCKERS,
            Self::AosForce | Self::AosForceDeep => FORCE_VALUE_NATIVE_EXPORT_BLOCKERS,
        }
    }
}

/// The Rust function shape behind a callable forcing wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeForcingRustCallableShape {
    /// `fn(&mut TreeWalk, IrId, Span, Value) -> Result<(), TreeWalkError>`.
    TreeWalkBlackholeCheck,
    /// `fn(&mut TreeWalk, IrId, Span, Value) -> Result<Value, TreeWalkError>`.
    TreeWalkForceValue,
    /// `fn(&mut TreeWalk, IrId, Span, Value) -> Result<Value, TreeWalkError>`.
    TreeWalkDeepForceValue,
}

/// A process-local callable Rust forcing wrapper address.
///
/// This pointer identifies a Rust function in the current process. It is used
/// as registration metadata for later native startup binding and is
/// intentionally not serialized or treated as stable ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeForcingRustCallableAddress {
    ptr: *const (),
}

impl RuntimeForcingRustCallableAddress {
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

/// A callable Rust wrapper binding for one forcing helper entry point.
///
/// This is not a native ABI binding. It deliberately omits
/// [`RuntimeForcingAbiSignature`] because this Rust callable uses a mutable
/// [`TreeWalk`] and returns [`TreeWalkError`] through [`Result`], while the
/// frozen native ABI will eventually decode a runtime-context pointer and
/// transfer failures through evaluator trap machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeForcingRustCallableBinding {
    entrypoint: RuntimeForcingEntryPoint,
    shape: RuntimeForcingRustCallableShape,
    address: RuntimeForcingRustCallableAddress,
}

impl RuntimeForcingRustCallableBinding {
    const fn new(
        entrypoint: RuntimeForcingEntryPoint,
        shape: RuntimeForcingRustCallableShape,
        address: RuntimeForcingRustCallableAddress,
    ) -> Self {
        Self {
            entrypoint,
            shape,
            address,
        }
    }

    /// Returns the forcing entry point served by this binding.
    pub const fn entrypoint(self) -> RuntimeForcingEntryPoint {
        self.entrypoint
    }

    /// Returns the Rust function shape behind this binding.
    pub const fn shape(self) -> RuntimeForcingRustCallableShape {
        self.shape
    }

    /// Returns the stable runtime symbol name served by this binding.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the process-local callable Rust address for this binding.
    pub const fn address(self) -> RuntimeForcingRustCallableAddress {
        self.address
    }
}

/// A missing piece before a forcing helper can become a native ABI export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeForcingNativeExportBlocker {
    /// No final exported C ABI wrapper is admitted for the frozen helper name.
    MissingFinalExportedWrapper,
    /// Native wrappers cannot yet decode the evaluator runtime context pointer.
    RuntimeContextDecodeUnimplemented,
    /// Native wrappers cannot yet bind an imported value to the evaluator force root.
    ActiveForceRootBindingUnimplemented,
    /// Native wrappers cannot yet preserve the evaluator's thunk blackhole protocol.
    BlackholeProtocolBindingUnimplemented,
    /// Native wrappers cannot yet route through force-cache admission and replay.
    ForceCacheIntegrationUnimplemented,
    /// Helper failures cannot yet transfer into evaluator trap/error machinery.
    TrapTransferUnimplemented,
    /// A candidate wrapper would not materialize the by-value [`Value`] native ABI return.
    NativeValueReturnUnmaterialized,
}

const BLACKHOLE_CHECK_NATIVE_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[
    RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
];

const FORCE_VALUE_NATIVE_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[
    RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
    RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
];

/// Native-export readiness for one frozen forcing helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeForcingNativeExportReadiness {
    entrypoint: RuntimeForcingEntryPoint,
    abi_signature: RuntimeForcingAbiSignature,
    rust_callable_binding: RuntimeForcingRustCallableBinding,
    blockers: &'static [RuntimeForcingNativeExportBlocker],
}

impl RuntimeForcingNativeExportReadiness {
    fn for_entrypoint(entrypoint: RuntimeForcingEntryPoint) -> Self {
        Self {
            entrypoint,
            abi_signature: entrypoint.abi_signature(),
            rust_callable_binding: entrypoint.rust_callable_binding(),
            blockers: entrypoint.native_export_blockers(),
        }
    }

    /// Returns the forcing entry point served by this readiness record.
    pub const fn entrypoint(&self) -> RuntimeForcingEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this readiness record.
    pub const fn symbol_name(&self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen native ABI signature for this forcing helper.
    pub const fn abi_signature(&self) -> RuntimeForcingAbiSignature {
        self.abi_signature
    }

    /// Returns the current Rust callable binding.
    pub const fn rust_callable_binding(&self) -> RuntimeForcingRustCallableBinding {
        self.rust_callable_binding
    }

    /// Returns the current blockers before this helper can be a native ABI export.
    pub const fn blockers(&self) -> &'static [RuntimeForcingNativeExportBlocker] {
        self.blockers
    }

    /// Returns true when this helper has exported native ABI metadata.
    pub const fn is_export_ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Native-export readiness report for frozen forcing helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeForcingNativeExportPreflight {
    readiness: Vec<RuntimeForcingNativeExportReadiness>,
}

impl RuntimeForcingNativeExportPreflight {
    fn new(readiness: Vec<RuntimeForcingNativeExportReadiness>) -> Self {
        Self { readiness }
    }

    /// Returns forcing native-export readiness in entry-point order.
    pub fn readiness(&self) -> &[RuntimeForcingNativeExportReadiness] {
        &self.readiness
    }

    /// Returns true when every forcing helper has native ABI export metadata.
    pub fn is_complete(&self) -> bool {
        self.readiness.iter().all(|record| record.is_export_ready())
    }

    /// Returns the readiness record for `symbol_name`, when present.
    pub fn readiness_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&RuntimeForcingNativeExportReadiness> {
        self.readiness
            .iter()
            .find(|record| record.symbol_name() == symbol_name)
    }
}

/// A frozen forcing ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeForcingAbiSignature {
    entrypoint: RuntimeForcingEntryPoint,
    parameters: &'static [RuntimeForcingAbiParameter],
    return_kind: RuntimeForcingAbiReturnKind,
}

impl RuntimeForcingAbiSignature {
    const fn new(
        entrypoint: RuntimeForcingEntryPoint,
        parameters: &'static [RuntimeForcingAbiParameter],
        return_kind: RuntimeForcingAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the forcing ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeForcingEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeForcingEntryPoint::abi_signature)
    }

    /// Returns the forcing entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeForcingEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeForcingAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeForcingAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen forcing ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeForcingAbiParameter {
    name: &'static str,
    kind: RuntimeForcingAbiParameterKind,
}

impl RuntimeForcingAbiParameter {
    const fn new(name: &'static str, kind: RuntimeForcingAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeForcingAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by forcing symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeForcingAbiParameterKind {
    /// A pointer to the evaluator runtime context.
    RuntimeContext,
    /// A by-value runtime value word pair.
    Value,
}

/// The success-path machine-level result kind returned by forcing helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeForcingAbiReturnKind {
    /// No success-path machine-level value is returned.
    Unit,
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
    use crate::syntax::parse_str;

    use super::*;

    #[test]
    fn runtime_forcing_symbol_is_safe_force_subset_of_core_inventory() {
        let helper_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::ForcingControl)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();
        let entrypoint_symbols = runtime_forcing_entrypoints()
            .iter()
            .copied()
            .map(RuntimeForcingEntryPoint::symbol_name)
            .collect::<BTreeSet<_>>();
        let signature_symbols = runtime_forcing_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeForcingAbiSignature::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            helper_symbols,
            BTreeSet::from(["aos_blackhole_check", "aos_force", "aos_force_deep"])
        );
        assert_eq!(
            entrypoint_symbols,
            BTreeSet::from(["aos_blackhole_check", "aos_force", "aos_force_deep"])
        );
        assert_eq!(signature_symbols, entrypoint_symbols);
    }

    #[test]
    fn forcing_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_forcing_entrypoints(),
            [
                RuntimeForcingEntryPoint::AosBlackholeCheck,
                RuntimeForcingEntryPoint::AosForce,
                RuntimeForcingEntryPoint::AosForceDeep,
            ]
        );

        for entrypoint in runtime_forcing_entrypoints() {
            assert_eq!(
                RuntimeForcingEntryPoint::from_symbol_name(entrypoint.symbol_name()),
                Some(*entrypoint)
            );
            assert_eq!(
                RuntimeForcingAbiSignature::from_symbol_name(entrypoint.symbol_name()),
                Some(entrypoint.abi_signature())
            );
        }
        for symbol in runtime_helper_symbols().iter().copied().filter(|symbol| {
            !matches!(
                symbol.name(),
                "aos_blackhole_check" | "aos_force" | "aos_force_deep"
            )
        }) {
            assert_eq!(
                RuntimeForcingEntryPoint::from_symbol_name(symbol.name()),
                None,
                "{} is not a forcing entry point with a Rust callable",
                symbol.name()
            );
            assert_eq!(
                RuntimeForcingAbiSignature::from_symbol_name(symbol.name()),
                None,
                "{} has no forcing ABI signature in this family",
                symbol.name()
            );
        }
    }

    #[test]
    fn forcing_abi_signature_pins_runtime_return_boundaries() {
        assert_eq!(
            runtime_forcing_abi_signatures(),
            [
                RuntimeForcingAbiSignature::new(
                    RuntimeForcingEntryPoint::AosBlackholeCheck,
                    FORCE_VALUE_PARAMETERS,
                    RuntimeForcingAbiReturnKind::Unit,
                ),
                RuntimeForcingAbiSignature::new(
                    RuntimeForcingEntryPoint::AosForce,
                    FORCE_VALUE_PARAMETERS,
                    RuntimeForcingAbiReturnKind::Value,
                ),
                RuntimeForcingAbiSignature::new(
                    RuntimeForcingEntryPoint::AosForceDeep,
                    FORCE_VALUE_PARAMETERS,
                    RuntimeForcingAbiReturnKind::Value,
                ),
            ]
        );
        for entrypoint in runtime_forcing_entrypoints() {
            let signature = entrypoint.abi_signature();

            assert_eq!(signature.entrypoint(), *entrypoint);
            assert_eq!(signature.symbol_name(), entrypoint.symbol_name());
            assert_eq!(
                signature.parameters(),
                [
                    RuntimeForcingAbiParameter::new(
                        "rt",
                        RuntimeForcingAbiParameterKind::RuntimeContext,
                    ),
                    RuntimeForcingAbiParameter::new("value", RuntimeForcingAbiParameterKind::Value),
                ]
                .as_slice()
            );
            assert_eq!(
                signature.return_kind(),
                entrypoint.abi_signature().return_kind()
            );
        }
    }

    #[test]
    fn forcing_abi_signature_matches_core_runtime_call_metadata() {
        for entrypoint in runtime_forcing_entrypoints() {
            let local_signature = entrypoint.abi_signature();
            let core_signature = runtime_helper_call_signature(local_signature.symbol_name())
                .expect("core force ABI");
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
                    ("rt", RuntimeForcingAbiParameterKind::RuntimeContext),
                    ("value", RuntimeForcingAbiParameterKind::Value),
                ],
                "{} local ABI parameters match the forcing family shape",
                entrypoint.symbol_name()
            );
            assert_eq!(
                core_parameters,
                vec![
                    ("rt", RuntimeAbiParameterKind::RuntimeContext),
                    ("value", RuntimeAbiParameterKind::Value),
                ],
                "{} core ABI parameters match the forcing family shape",
                entrypoint.symbol_name()
            );
            match local_signature.return_kind() {
                RuntimeForcingAbiReturnKind::Unit => {
                    assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Unit);
                }
                RuntimeForcingAbiReturnKind::Value => {
                    assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Value);
                }
            }
        }
    }

    #[test]
    fn forcing_rust_callable_bindings_preserve_entrypoint_inventory() {
        let bindings = runtime_forcing_rust_callable_bindings();
        let expected = [
            (
                RuntimeForcingEntryPoint::AosBlackholeCheck,
                RuntimeForcingRustCallableShape::TreeWalkBlackholeCheck,
                rust_callable_aos_blackhole_check as RuntimeBlackholeCheckFn as *const (),
            ),
            (
                RuntimeForcingEntryPoint::AosForce,
                RuntimeForcingRustCallableShape::TreeWalkForceValue,
                rust_callable_aos_force as RuntimeForceValueFn as *const (),
            ),
            (
                RuntimeForcingEntryPoint::AosForceDeep,
                RuntimeForcingRustCallableShape::TreeWalkDeepForceValue,
                rust_callable_aos_force_deep as RuntimeForceValueFn as *const (),
            ),
        ];

        assert_eq!(bindings.len(), expected.len());
        assert_eq!(
            bindings
                .iter()
                .copied()
                .map(RuntimeForcingRustCallableBinding::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_forcing_entrypoints()
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
            runtime_forcing_abi_signatures()
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
    fn forcing_native_export_preflight_preserves_frozen_abi_and_callable() {
        let preflight = runtime_forcing_native_export_preflight();

        assert!(!preflight.is_complete());
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeForcingNativeExportReadiness::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_forcing_entrypoints()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeForcingNativeExportReadiness::abi_signature)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_forcing_abi_signatures()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeForcingNativeExportReadiness::rust_callable_binding)
                .collect::<Vec<_>>(),
            runtime_forcing_rust_callable_bindings()
        );

        for entrypoint in runtime_forcing_entrypoints() {
            let record = preflight
                .readiness_for_symbol(entrypoint.symbol_name())
                .expect("force export readiness exists");

            assert_eq!(record.entrypoint(), *entrypoint);
            assert_eq!(record.symbol_name(), entrypoint.symbol_name());
            assert_eq!(record.blockers(), entrypoint.native_export_blockers());
            match entrypoint {
                RuntimeForcingEntryPoint::AosBlackholeCheck => assert_eq!(
                    record.blockers(),
                    [
                        RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
                        RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                        RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
                        RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
                    ]
                    .as_slice()
                ),
                RuntimeForcingEntryPoint::AosForce | RuntimeForcingEntryPoint::AosForceDeep => {
                    assert_eq!(
                        record.blockers(),
                        [
                            RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
                            RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                            RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
                            RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
                            RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
                            RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
                        ]
                        .as_slice()
                    );
                }
            }
            assert!(!record.is_export_ready());
            assert!(
                record
                    .blockers()
                    .contains(&RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper)
            );
            assert!(
                record.blockers().contains(
                    &RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented
                )
            );
            assert!(record.blockers().contains(
                &RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented
            ));
            assert!(
                record
                    .blockers()
                    .contains(&RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented)
            );
            match entrypoint {
                RuntimeForcingEntryPoint::AosBlackholeCheck => {
                    assert!(!record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented
                    ));
                    assert!(!record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented
                    ));
                    assert!(!record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::NativeValueReturnUnmaterialized
                    ));
                }
                RuntimeForcingEntryPoint::AosForce | RuntimeForcingEntryPoint::AosForceDeep => {
                    assert!(record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented
                    ));
                    assert!(record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented
                    ));
                    assert!(!record.blockers().contains(
                        &RuntimeForcingNativeExportBlocker::NativeValueReturnUnmaterialized
                    ));
                }
            }
        }
    }

    #[test]
    fn force_and_blackhole_check_rust_callables_preserve_non_thunk_values() {
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str("null").expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let value = Value::int(42);
        rust_callable_aos_blackhole_check(&mut eval, IrId::new(0), Span::new(0, 4), value)
            .expect("non-thunk blackhole check succeeds");
        let forced = rust_callable_aos_force(&mut eval, IrId::new(0), Span::new(0, 4), value)
            .expect("non-thunk force succeeds");
        let deeply_forced =
            rust_callable_aos_force_deep(&mut eval, IrId::new(0), Span::new(0, 4), value)
                .expect("non-thunk deep force succeeds");

        assert_eq!(forced.as_int().expect("forced value is an int"), 42);
        assert_eq!(
            deeply_forced
                .as_int()
                .expect("deeply forced value is an int"),
            42
        );
    }

    #[test]
    fn blackhole_check_rust_callable_traps_only_blackholed_thunks() {
        let source = "[ (1 + 2) (3 + 4) ]";
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let root = eval.eval_root().expect("list evaluates");
        let (forced_candidate, blackhole_candidate) = {
            let list = eval.heap().get_list(root).expect("root list is heap-owned");
            (
                list.get(0).expect("first element exists"),
                list.get(1).expect("second element exists"),
            )
        };

        rust_callable_aos_blackhole_check(
            &mut eval,
            ir.root,
            Span::new(0, source.len() as u32),
            forced_candidate,
        )
        .expect("suspended thunk is not a blackhole");
        rust_callable_aos_force(
            &mut eval,
            ir.root,
            Span::new(0, source.len() as u32),
            forced_candidate,
        )
        .expect("first thunk forces");
        rust_callable_aos_blackhole_check(
            &mut eval,
            ir.root,
            Span::new(0, source.len() as u32),
            forced_candidate,
        )
        .expect("forced thunk is not a blackhole");

        let guard = {
            let thunk = eval
                .heap()
                .get_thunk(blackhole_candidate)
                .expect("second element is a thunk");
            let crate::eval::ForceClaim::Claimed(guard) = thunk
                .cell()
                .begin_force()
                .expect("suspended thunk is claimed")
            else {
                panic!("expected a claimed suspended thunk");
            };
            guard
        };
        std::mem::forget(guard);

        let error = rust_callable_aos_blackhole_check(
            &mut eval,
            ir.root,
            Span::new(0, source.len() as u32),
            blackhole_candidate,
        )
        .expect_err("blackholed thunk traps");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Force {
                id: ir.root,
                source: ForceError::InfiniteRecursion,
            }
        );
    }

    #[test]
    fn deep_force_rust_callable_forces_nested_container_thunks() {
        let source = "[ [ (1 + 2) ] ]";
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
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

        let deeply_forced = rust_callable_aos_force_deep(
            &mut eval,
            ir.root,
            Span::new(0, source.len() as u32),
            root,
        )
        .expect("nested list deep force succeeds");
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
        assert_eq!(
            inner_cached_value
                .as_int()
                .expect("inner cached value is an int"),
            3
        );
    }
}
