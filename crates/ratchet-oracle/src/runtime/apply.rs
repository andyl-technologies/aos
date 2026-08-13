//! Runtime apply helper metadata.
//!
//! The tree-walk oracle already owns generic function application through its
//! `TreeWalk::apply_value` path. Future native tiers reference that operation
//! through the stable `aos_apply` helper symbol. This module pins the helper's
//! safe family metadata and exposes a process-local Rust callable wrapper for
//! registration preflight only. It does not export a C ABI function, decode a
//! native runtime context, install a JIT symbol, or bypass the evaluator apply
//! path.

use crate::compile::IrId;
use crate::eval::tree_walk::{TreeWalk, TreeWalkError};
use crate::syntax::Span;
use crate::value::Value;

/// The call-control entry point owned by the runtime ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeApplyEntryPoint {
    /// The `aos_apply` helper that applies a function value to one argument.
    AosApply,
}

/// Frozen call-control entry points registered by future native runtimes.
pub const RUNTIME_APPLY_ENTRYPOINTS: &[RuntimeApplyEntryPoint] =
    &[RuntimeApplyEntryPoint::AosApply];

const APPLY_PARAMETERS: &[RuntimeApplyAbiParameter] = &[
    RuntimeApplyAbiParameter::new("rt", RuntimeApplyAbiParameterKind::RuntimeContext),
    RuntimeApplyAbiParameter::new("function", RuntimeApplyAbiParameterKind::Value),
    RuntimeApplyAbiParameter::new("arg", RuntimeApplyAbiParameterKind::Value),
];

/// Frozen apply helper ABI signatures for future native runtimes.
pub const RUNTIME_APPLY_ABI_SIGNATURES: &[RuntimeApplyAbiSignature] =
    &[RuntimeApplyAbiSignature::new(
        RuntimeApplyEntryPoint::AosApply,
        APPLY_PARAMETERS,
        RuntimeApplyAbiReturnKind::Value,
    )];

type RuntimeApplyValueFn =
    fn(&mut TreeWalk, IrId, Span, Value, Value) -> Result<Value, TreeWalkError>;

/// Runs the Rust-callable `aos_apply` helper through the tree-walk evaluator.
///
/// The helper keeps the imported function and argument values registered as
/// transient safepoint roots, forces the function when the evaluator's ordinary
/// apply path demands it, dispatches lambda, functor, and first-class primop
/// calls, and returns the application result [`Value`].
///
/// # Errors
///
/// Returns [`TreeWalkError`] when the function cannot be forced, the forced
/// value is not callable, argument binding fails, call-depth accounting rejects
/// the call, callable dispatch fails, or the evaluator cannot preserve imported
/// function/argument roots across allocation safepoints.
pub fn rust_callable_aos_apply(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    function: Value,
    argument: Value,
) -> Result<Value, TreeWalkError> {
    eval.apply_value_with_transient_roots(id, span, function, argument)
}

/// Returns call-control helper bindings with callable Rust wrapper addresses.
///
/// The addresses are process-local Rust function addresses for registration
/// preflight metadata. They are not stable across builds or processes, are not
/// exported C symbols, and are not callable with [`RuntimeApplyAbiSignature`].
pub fn runtime_apply_rust_callable_bindings() -> Vec<RuntimeApplyRustCallableBinding> {
    runtime_apply_entrypoints()
        .iter()
        .copied()
        .map(RuntimeApplyEntryPoint::rust_callable_binding)
        .collect()
}

/// Builds native-export readiness metadata for frozen apply helpers.
///
/// The returned report is intentionally negative today: the helper has frozen
/// ABI metadata and a safe evaluator-callable wrapper, but no wrapper is
/// admitted as a final native export by this oracle gate. The blocker list is
/// precise so later unsafe wrapper work can clear individual obligations without
/// treating the Rust callable as a native ABI export.
pub fn runtime_apply_native_export_preflight() -> RuntimeApplyNativeExportPreflight {
    RuntimeApplyNativeExportPreflight::new(
        runtime_apply_entrypoints()
            .iter()
            .copied()
            .map(RuntimeApplyNativeExportReadiness::for_entrypoint)
            .collect(),
    )
}

/// Returns the frozen apply entry-point inventory.
pub const fn runtime_apply_entrypoints() -> &'static [RuntimeApplyEntryPoint] {
    RUNTIME_APPLY_ENTRYPOINTS
}

/// Returns the frozen apply-helper ABI signature inventory.
pub const fn runtime_apply_abi_signatures() -> &'static [RuntimeApplyAbiSignature] {
    RUNTIME_APPLY_ABI_SIGNATURES
}

impl RuntimeApplyEntryPoint {
    /// Returns the stable runtime symbol name for this apply entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosApply => "aos_apply",
        }
    }

    /// Returns the apply entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_apply" => Some(Self::AosApply),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this apply entry point.
    pub const fn abi_signature(self) -> RuntimeApplyAbiSignature {
        match self {
            Self::AosApply => RuntimeApplyAbiSignature::new(
                self,
                APPLY_PARAMETERS,
                RuntimeApplyAbiReturnKind::Value,
            ),
        }
    }

    /// Returns the callable Rust evaluator-wrapper binding for this entry point.
    ///
    /// The callable's Rust shape is separate from the frozen native ABI
    /// signature because runtime-context decoding, active call-root binding,
    /// evaluator trap transfer, and by-value return materialization are not
    /// implemented yet.
    pub fn rust_callable_binding(self) -> RuntimeApplyRustCallableBinding {
        RuntimeApplyRustCallableBinding::new(
            self,
            self.rust_callable_shape(),
            self.rust_callable_address(),
        )
    }

    /// Returns the Rust evaluator-wrapper call shape for this entry point.
    pub const fn rust_callable_shape(self) -> RuntimeApplyRustCallableShape {
        match self {
            Self::AosApply => RuntimeApplyRustCallableShape::TreeWalkApplyValue,
        }
    }

    /// Returns the process-local Rust evaluator-wrapper address for this entry point.
    ///
    /// The address is suitable for registration preflight metadata only. It is
    /// not an exported C ABI symbol, is not callable with the frozen native ABI
    /// signature, and must not be persisted.
    pub fn rust_callable_address(self) -> RuntimeApplyRustCallableAddress {
        let ptr = match self {
            Self::AosApply => rust_callable_aos_apply as RuntimeApplyValueFn as *const (),
        };
        RuntimeApplyRustCallableAddress::new(ptr)
    }

    /// Returns the current native-export blockers for this apply helper.
    pub const fn native_export_blockers(self) -> &'static [RuntimeApplyNativeExportBlocker] {
        match self {
            Self::AosApply => APPLY_NATIVE_EXPORT_BLOCKERS,
        }
    }
}

/// The Rust function shape behind a callable apply wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeApplyRustCallableShape {
    /// `fn(&mut TreeWalk, IrId, Span, Value, Value) -> Result<Value, TreeWalkError>`.
    TreeWalkApplyValue,
}

/// A process-local callable Rust apply wrapper address.
///
/// This pointer identifies a Rust function in the current process. It is used
/// as registration metadata for later native startup binding and is
/// intentionally not serialized or treated as stable ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeApplyRustCallableAddress {
    ptr: *const (),
}

impl RuntimeApplyRustCallableAddress {
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

/// A callable Rust wrapper binding for one apply helper entry point.
///
/// This is not a native ABI binding. It deliberately omits
/// [`RuntimeApplyAbiSignature`] because this Rust callable uses a mutable
/// [`TreeWalk`] and returns [`TreeWalkError`] through [`Result`], while the
/// frozen native ABI will eventually decode a runtime-context pointer and
/// transfer failures through evaluator trap machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeApplyRustCallableBinding {
    entrypoint: RuntimeApplyEntryPoint,
    shape: RuntimeApplyRustCallableShape,
    address: RuntimeApplyRustCallableAddress,
}

impl RuntimeApplyRustCallableBinding {
    const fn new(
        entrypoint: RuntimeApplyEntryPoint,
        shape: RuntimeApplyRustCallableShape,
        address: RuntimeApplyRustCallableAddress,
    ) -> Self {
        Self {
            entrypoint,
            shape,
            address,
        }
    }

    /// Returns the apply entry point served by this binding.
    pub const fn entrypoint(self) -> RuntimeApplyEntryPoint {
        self.entrypoint
    }

    /// Returns the Rust function shape behind this binding.
    pub const fn shape(self) -> RuntimeApplyRustCallableShape {
        self.shape
    }

    /// Returns the stable runtime symbol name served by this binding.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the process-local callable Rust address for this binding.
    pub const fn address(self) -> RuntimeApplyRustCallableAddress {
        self.address
    }
}

/// A missing piece before an apply helper can become a native ABI export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeApplyNativeExportBlocker {
    /// No final exported C ABI wrapper is admitted for the frozen helper name.
    MissingFinalExportedWrapper,
    /// Native wrappers cannot yet decode the evaluator runtime context pointer.
    RuntimeContextDecodeUnimplemented,
    /// Native wrappers cannot yet bind imported function and argument values as roots.
    ActiveCallRootBindingUnimplemented,
    /// Native wrappers cannot yet preserve evaluator call-depth accounting.
    CallDepthAccountingUnimplemented,
    /// Native wrappers cannot yet preserve functor and partial-application dispatch.
    CallableDispatchBindingUnimplemented,
    /// Helper failures cannot yet transfer into evaluator trap/error machinery.
    TrapTransferUnimplemented,
    /// The by-value [`Value`] return is not yet materialized through the native ABI.
    NativeValueReturnUnmaterialized,
}

const APPLY_NATIVE_EXPORT_BLOCKERS: &[RuntimeApplyNativeExportBlocker] = &[
    RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeApplyNativeExportBlocker::RuntimeContextDecodeUnimplemented,
    RuntimeApplyNativeExportBlocker::ActiveCallRootBindingUnimplemented,
    RuntimeApplyNativeExportBlocker::CallDepthAccountingUnimplemented,
    RuntimeApplyNativeExportBlocker::CallableDispatchBindingUnimplemented,
    RuntimeApplyNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeApplyNativeExportBlocker::NativeValueReturnUnmaterialized,
];

/// Native-export readiness for one frozen apply helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeApplyNativeExportReadiness {
    entrypoint: RuntimeApplyEntryPoint,
    abi_signature: RuntimeApplyAbiSignature,
    rust_callable_binding: RuntimeApplyRustCallableBinding,
    blockers: &'static [RuntimeApplyNativeExportBlocker],
}

impl RuntimeApplyNativeExportReadiness {
    fn for_entrypoint(entrypoint: RuntimeApplyEntryPoint) -> Self {
        Self {
            entrypoint,
            abi_signature: entrypoint.abi_signature(),
            rust_callable_binding: entrypoint.rust_callable_binding(),
            blockers: entrypoint.native_export_blockers(),
        }
    }

    /// Returns the apply entry point served by this readiness record.
    pub const fn entrypoint(&self) -> RuntimeApplyEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this readiness record.
    pub const fn symbol_name(&self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen native ABI signature for this apply helper.
    pub const fn abi_signature(&self) -> RuntimeApplyAbiSignature {
        self.abi_signature
    }

    /// Returns the current Rust callable binding.
    pub const fn rust_callable_binding(&self) -> RuntimeApplyRustCallableBinding {
        self.rust_callable_binding
    }

    /// Returns the current blockers before this helper can be a native ABI export.
    pub const fn blockers(&self) -> &'static [RuntimeApplyNativeExportBlocker] {
        self.blockers
    }

    /// Returns true when this helper has exported native ABI metadata.
    pub const fn is_export_ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Native-export readiness report for frozen apply helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeApplyNativeExportPreflight {
    readiness: Vec<RuntimeApplyNativeExportReadiness>,
}

impl RuntimeApplyNativeExportPreflight {
    fn new(readiness: Vec<RuntimeApplyNativeExportReadiness>) -> Self {
        Self { readiness }
    }

    /// Returns apply native-export readiness in entry-point order.
    pub fn readiness(&self) -> &[RuntimeApplyNativeExportReadiness] {
        &self.readiness
    }

    /// Returns true when every apply helper has native ABI export metadata.
    pub fn is_complete(&self) -> bool {
        self.readiness.iter().all(|record| record.is_export_ready())
    }

    /// Returns the readiness record for `symbol_name`, when present.
    pub fn readiness_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&RuntimeApplyNativeExportReadiness> {
        self.readiness
            .iter()
            .find(|record| record.symbol_name() == symbol_name)
    }
}

/// A frozen apply ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeApplyAbiSignature {
    entrypoint: RuntimeApplyEntryPoint,
    parameters: &'static [RuntimeApplyAbiParameter],
    return_kind: RuntimeApplyAbiReturnKind,
}

impl RuntimeApplyAbiSignature {
    const fn new(
        entrypoint: RuntimeApplyEntryPoint,
        parameters: &'static [RuntimeApplyAbiParameter],
        return_kind: RuntimeApplyAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the apply ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeApplyEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeApplyEntryPoint::abi_signature)
    }

    /// Returns the apply entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeApplyEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeApplyAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeApplyAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen apply ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeApplyAbiParameter {
    name: &'static str,
    kind: RuntimeApplyAbiParameterKind,
}

impl RuntimeApplyAbiParameter {
    const fn new(name: &'static str, kind: RuntimeApplyAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeApplyAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by apply symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeApplyAbiParameterKind {
    /// A pointer to the evaluator runtime context.
    RuntimeContext,
    /// A by-value runtime value word pair.
    Value,
}

/// The success-path machine-level result kind returned by apply helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeApplyAbiReturnKind {
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
    use crate::eval::tree_walk::TreeWalkOptions;
    use crate::runtime::alloc::GcStressPolicy;
    use crate::syntax::parse_str;

    use super::*;

    #[test]
    fn runtime_apply_symbol_matches_core_call_control_inventory() {
        let helper_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::CallControl)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();
        let entrypoint_symbols = runtime_apply_entrypoints()
            .iter()
            .copied()
            .map(RuntimeApplyEntryPoint::symbol_name)
            .collect::<BTreeSet<_>>();
        let signature_symbols = runtime_apply_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeApplyAbiSignature::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(helper_symbols, BTreeSet::from(["aos_apply"]));
        assert_eq!(entrypoint_symbols, helper_symbols);
        assert_eq!(signature_symbols, helper_symbols);
    }

    #[test]
    fn apply_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_apply_entrypoints(),
            [RuntimeApplyEntryPoint::AosApply]
        );

        for entrypoint in runtime_apply_entrypoints() {
            assert_eq!(
                RuntimeApplyEntryPoint::from_symbol_name(entrypoint.symbol_name()),
                Some(*entrypoint)
            );
            assert_eq!(
                RuntimeApplyAbiSignature::from_symbol_name(entrypoint.symbol_name()),
                Some(entrypoint.abi_signature())
            );
        }
        for symbol in runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() != RuntimeHelperRole::CallControl)
        {
            assert_eq!(
                RuntimeApplyEntryPoint::from_symbol_name(symbol.name()),
                None,
                "{} is not an apply entry point",
                symbol.name()
            );
            assert_eq!(
                RuntimeApplyAbiSignature::from_symbol_name(symbol.name()),
                None,
                "{} has no apply ABI signature",
                symbol.name()
            );
        }
    }

    #[test]
    fn apply_abi_signature_pins_runtime_value_return() {
        let signature = RuntimeApplyEntryPoint::AosApply.abi_signature();

        assert_eq!(
            runtime_apply_abi_signatures(),
            [RuntimeApplyAbiSignature::new(
                RuntimeApplyEntryPoint::AosApply,
                APPLY_PARAMETERS,
                RuntimeApplyAbiReturnKind::Value,
            )]
        );
        assert_eq!(signature.entrypoint(), RuntimeApplyEntryPoint::AosApply);
        assert_eq!(signature.symbol_name(), "aos_apply");
        assert_eq!(
            signature.parameters(),
            [
                RuntimeApplyAbiParameter::new("rt", RuntimeApplyAbiParameterKind::RuntimeContext,),
                RuntimeApplyAbiParameter::new("function", RuntimeApplyAbiParameterKind::Value),
                RuntimeApplyAbiParameter::new("arg", RuntimeApplyAbiParameterKind::Value),
            ]
            .as_slice()
        );
        assert_eq!(signature.return_kind(), RuntimeApplyAbiReturnKind::Value);
    }

    #[test]
    fn apply_abi_signature_matches_core_runtime_call_metadata() {
        let local_signature = RuntimeApplyEntryPoint::AosApply.abi_signature();
        let core_signature =
            runtime_helper_call_signature(local_signature.symbol_name()).expect("core apply ABI");
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
                ("rt", RuntimeApplyAbiParameterKind::RuntimeContext),
                ("function", RuntimeApplyAbiParameterKind::Value),
                ("arg", RuntimeApplyAbiParameterKind::Value),
            ]
        );
        assert_eq!(
            core_parameters,
            vec![
                ("rt", RuntimeAbiParameterKind::RuntimeContext),
                ("function", RuntimeAbiParameterKind::Value),
                ("arg", RuntimeAbiParameterKind::Value),
            ]
        );
        assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            local_signature.return_kind(),
            RuntimeApplyAbiReturnKind::Value
        );
    }

    #[test]
    fn apply_rust_callable_bindings_preserve_entrypoint_inventory() {
        let bindings = runtime_apply_rust_callable_bindings();
        let expected = [(
            RuntimeApplyEntryPoint::AosApply,
            RuntimeApplyRustCallableShape::TreeWalkApplyValue,
            rust_callable_aos_apply as RuntimeApplyValueFn as *const (),
        )];

        assert_eq!(bindings.len(), expected.len());
        assert_eq!(
            bindings
                .iter()
                .copied()
                .map(RuntimeApplyRustCallableBinding::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_apply_entrypoints()
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
            runtime_apply_abi_signatures()
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
    fn apply_native_export_preflight_preserves_frozen_abi_and_callable() {
        let preflight = runtime_apply_native_export_preflight();

        assert!(!preflight.is_complete());
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeApplyNativeExportReadiness::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_apply_entrypoints()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeApplyNativeExportReadiness::abi_signature)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_apply_abi_signatures()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeApplyNativeExportReadiness::rust_callable_binding)
                .collect::<Vec<_>>(),
            runtime_apply_rust_callable_bindings()
        );

        let record = preflight
            .readiness_for_symbol("aos_apply")
            .expect("apply export readiness exists");

        assert_eq!(record.entrypoint(), RuntimeApplyEntryPoint::AosApply);
        assert_eq!(record.symbol_name(), "aos_apply");
        assert_eq!(
            record.blockers(),
            RuntimeApplyEntryPoint::AosApply.native_export_blockers()
        );
        assert_eq!(
            record.blockers(),
            [
                RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper,
                RuntimeApplyNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeApplyNativeExportBlocker::ActiveCallRootBindingUnimplemented,
                RuntimeApplyNativeExportBlocker::CallDepthAccountingUnimplemented,
                RuntimeApplyNativeExportBlocker::CallableDispatchBindingUnimplemented,
                RuntimeApplyNativeExportBlocker::TrapTransferUnimplemented,
                RuntimeApplyNativeExportBlocker::NativeValueReturnUnmaterialized,
            ]
            .as_slice()
        );
        assert!(!record.is_export_ready());
        assert!(
            record
                .blockers()
                .contains(&RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeApplyNativeExportBlocker::RuntimeContextDecodeUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeApplyNativeExportBlocker::ActiveCallRootBindingUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeApplyNativeExportBlocker::CallDepthAccountingUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeApplyNativeExportBlocker::CallableDispatchBindingUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeApplyNativeExportBlocker::TrapTransferUnimplemented)
        );
        assert!(
            record
                .blockers()
                .contains(&RuntimeApplyNativeExportBlocker::NativeValueReturnUnmaterialized)
        );
    }

    #[test]
    fn apply_rust_callable_applies_lambda_values() {
        let source = "x: x + 1";
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let function = eval.eval_root().expect("lambda evaluates");
        let applied = rust_callable_aos_apply(
            &mut eval,
            ir.root,
            Span::new(0, source.len() as u32),
            function,
            Value::int(41),
        )
        .expect("lambda application succeeds");
        let forced = eval
            .force_value(ir.root, Span::new(0, source.len() as u32), applied)
            .expect("application result forces");

        assert_eq!(forced.as_int().expect("application returns an int"), 42);
    }

    #[test]
    fn apply_rust_callable_applies_attrset_functor_values() {
        let source = "{ __functor = self: x: x + 2; }";
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let function = eval.eval_root().expect("functor attrset evaluates");
        let applied = rust_callable_aos_apply(
            &mut eval,
            ir.root,
            Span::new(0, source.len() as u32),
            function,
            Value::int(40),
        )
        .expect("functor application succeeds");
        let forced = eval
            .force_value(ir.root, Span::new(0, source.len() as u32), applied)
            .expect("functor result forces");

        assert_eq!(forced.as_int().expect("functor returns an int"), 42);
    }

    #[test]
    fn apply_rust_callable_applies_first_class_primop_values() {
        let source = "builtins.add";
        let span = Span::new(0, source.len() as u32);
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let function = eval.eval_root().expect("primop evaluates");
        let partial = rust_callable_aos_apply(&mut eval, ir.root, span, function, Value::int(40))
            .expect("first primop application succeeds");
        let applied = rust_callable_aos_apply(&mut eval, ir.root, span, partial, Value::int(2))
            .expect("second primop application succeeds");

        assert_eq!(applied.as_int().expect("primop returns an int"), 42);
    }

    // Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
    // reservation heap geometry (GC-stress record placement / chunked / fake
    // pointer) or reads a boxed wide scalar context-free — both unavailable under
    // the single-reservation Candidate-C carrier. Real eval is covered by the
    // byte-parity battery (cutover plan sections 2, 3.6).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn apply_rust_callable_preserves_imported_roots_under_gc_stress() {
        let source = "{ f = x: builtins.deepSeq x 42; arg = [ (y: y) ]; }";
        let span = Span::new(0, source.len() as u32);
        let ir = aos_nix_dialect::nix_lower(
            resolve(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let f = ir.symbols.lookup(b"f").expect("f symbol exists");
        let arg = ir.symbols.lookup(b"arg").expect("arg symbol exists");
        let mut eval = TreeWalk::with_options(
            &ir,
            TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
        );
        let root = eval.eval_root().expect("root attrset evaluates");
        let attrs = eval.heap().get_attrs(root).expect("root is an attrset");
        let function = attrs.get(f).expect("function attr exists");
        let argument = attrs.get(arg).expect("argument attr exists");

        let applied = rust_callable_aos_apply(&mut eval, ir.root, span, function, argument)
            .expect("GC-stress application succeeds");
        let forced = eval
            .force_value(ir.root, span, applied)
            .expect("application result forces");

        assert_eq!(forced.as_int().expect("application returns an int"), 42);
    }
}
