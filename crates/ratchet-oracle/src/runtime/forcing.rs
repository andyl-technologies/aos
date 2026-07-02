//! Runtime forcing helper metadata.
//!
//! The tree-walk oracle already owns thunk forcing through its internal
//! `TreeWalk::force_value` path. Future native tiers reference that operation
//! through the stable `aos_force` helper symbol. This module pins the helper's
//! safe family metadata and exposes a process-local Rust callable wrapper for
//! registration preflight only. It does not export a C ABI function, decode a
//! native runtime context, install a JIT symbol, or bypass the evaluator force
//! path.

use crate::compile::IrId;
use crate::eval::tree_walk::{TreeWalk, TreeWalkError};
use crate::syntax::Span;
use crate::value::Value;

/// The forcing entry point owned by the runtime ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeForcingEntryPoint {
    /// The `aos_force` helper that forces a value to weak head normal form.
    AosForce,
}

/// Frozen forcing entry points registered by future native runtimes.
pub const RUNTIME_FORCING_ENTRYPOINTS: &[RuntimeForcingEntryPoint] =
    &[RuntimeForcingEntryPoint::AosForce];

const FORCE_VALUE_PARAMETERS: &[RuntimeForcingAbiParameter] = &[
    RuntimeForcingAbiParameter::new("rt", RuntimeForcingAbiParameterKind::RuntimeContext),
    RuntimeForcingAbiParameter::new("value", RuntimeForcingAbiParameterKind::Value),
];

/// Frozen forcing helper ABI signatures for future native runtimes.
pub const RUNTIME_FORCING_ABI_SIGNATURES: &[RuntimeForcingAbiSignature] =
    &[RuntimeForcingAbiSignature::new(
        RuntimeForcingEntryPoint::AosForce,
        FORCE_VALUE_PARAMETERS,
        RuntimeForcingAbiReturnKind::Value,
    )];

type RuntimeForceValueFn = fn(&mut TreeWalk, IrId, Span, Value) -> Result<Value, TreeWalkError>;

fn rust_callable_aos_force(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    value: Value,
) -> Result<Value, TreeWalkError> {
    eval.force_value(id, span, value)
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
/// The returned report is intentionally negative today: `aos_force` has frozen
/// ABI metadata and a safe evaluator-callable wrapper, but no exported C ABI
/// wrapper. The blocker list is precise so later unsafe wrapper work can clear
/// individual obligations without treating the Rust callable as a native ABI
/// export.
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
            Self::AosForce => "aos_force",
        }
    }

    /// Returns the forcing entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_force" => Some(Self::AosForce),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this forcing entry point.
    pub const fn abi_signature(self) -> RuntimeForcingAbiSignature {
        match self {
            Self::AosForce => RuntimeForcingAbiSignature::new(
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
    /// evaluator trap transfer, and by-value return materialization are not
    /// implemented yet.
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
            Self::AosForce => RuntimeForcingRustCallableShape::TreeWalkForceValue,
        }
    }

    /// Returns the process-local Rust evaluator-wrapper address for this entry point.
    ///
    /// The address is suitable for registration preflight metadata only. It is
    /// not an exported C ABI symbol, is not callable with the frozen native ABI
    /// signature, and must not be persisted.
    pub fn rust_callable_address(self) -> RuntimeForcingRustCallableAddress {
        let ptr = match self {
            Self::AosForce => rust_callable_aos_force as RuntimeForceValueFn as *const (),
        };
        RuntimeForcingRustCallableAddress::new(ptr)
    }

    /// Returns the current native-export blockers for this forcing helper.
    pub const fn native_export_blockers(self) -> &'static [RuntimeForcingNativeExportBlocker] {
        match self {
            Self::AosForce => FORCING_NATIVE_EXPORT_BLOCKERS,
        }
    }
}

/// The Rust function shape behind a callable forcing wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeForcingRustCallableShape {
    /// `fn(&mut TreeWalk, IrId, Span, Value) -> Result<Value, TreeWalkError>`.
    TreeWalkForceValue,
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
    /// No `unsafe extern "C"` symbol body exists for the frozen helper name.
    MissingExternCWrapper,
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
    /// The by-value [`Value`] return is not yet materialized through the native ABI.
    NativeValueReturnUnmaterialized,
}

const FORCING_NATIVE_EXPORT_BLOCKERS: &[RuntimeForcingNativeExportBlocker] = &[
    RuntimeForcingNativeExportBlocker::MissingExternCWrapper,
    RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
    RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
    RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeForcingNativeExportBlocker::NativeValueReturnUnmaterialized,
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
        assert_eq!(entrypoint_symbols, BTreeSet::from(["aos_force"]));
        assert_eq!(signature_symbols, entrypoint_symbols);
    }

    #[test]
    fn forcing_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_forcing_entrypoints(),
            [RuntimeForcingEntryPoint::AosForce]
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
        for symbol in runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.name() != "aos_force")
        {
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
    fn forcing_abi_signature_pins_runtime_value_return() {
        let signature = RuntimeForcingEntryPoint::AosForce.abi_signature();

        assert_eq!(
            runtime_forcing_abi_signatures(),
            [RuntimeForcingAbiSignature::new(
                RuntimeForcingEntryPoint::AosForce,
                FORCE_VALUE_PARAMETERS,
                RuntimeForcingAbiReturnKind::Value,
            )]
        );
        assert_eq!(signature.entrypoint(), RuntimeForcingEntryPoint::AosForce);
        assert_eq!(signature.symbol_name(), "aos_force");
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
        assert_eq!(signature.return_kind(), RuntimeForcingAbiReturnKind::Value);
    }

    #[test]
    fn forcing_abi_signature_matches_core_runtime_call_metadata() {
        let local_signature = RuntimeForcingEntryPoint::AosForce.abi_signature();
        let core_signature =
            runtime_helper_call_signature(local_signature.symbol_name()).expect("core force ABI");
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
            ]
        );
        assert_eq!(
            core_parameters,
            vec![
                ("rt", RuntimeAbiParameterKind::RuntimeContext),
                ("value", RuntimeAbiParameterKind::Value),
            ]
        );
        assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            local_signature.return_kind(),
            RuntimeForcingAbiReturnKind::Value
        );
    }

    #[test]
    fn forcing_rust_callable_bindings_preserve_entrypoint_inventory() {
        let bindings = runtime_forcing_rust_callable_bindings();
        let expected = [(
            RuntimeForcingEntryPoint::AosForce,
            RuntimeForcingRustCallableShape::TreeWalkForceValue,
            rust_callable_aos_force as RuntimeForceValueFn as *const (),
        )];

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

        let record = preflight
            .readiness_for_symbol("aos_force")
            .expect("force export readiness exists");
        assert_eq!(record.entrypoint(), RuntimeForcingEntryPoint::AosForce);
        assert_eq!(record.symbol_name(), "aos_force");
        assert_eq!(
            record.blockers(),
            RuntimeForcingEntryPoint::AosForce.native_export_blockers()
        );
        assert!(!record.is_export_ready());
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::MissingExternCWrapper)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented)
        );
        assert!(
            record.blockers().contains(
                &RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented
            )
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeForcingNativeExportBlocker::NativeValueReturnUnmaterialized)
        );
    }

    #[test]
    fn force_rust_callable_preserves_non_thunk_values() {
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str("null").expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let value = Value::int(42);
        let forced = rust_callable_aos_force(&mut eval, IrId::new(0), Span::new(0, 4), value)
            .expect("non-thunk force succeeds");

        assert_eq!(forced.as_int().expect("forced value is an int"), 42);
    }
}
