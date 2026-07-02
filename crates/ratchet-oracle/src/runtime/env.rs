//! Runtime environment-access helper metadata.
//!
//! The tree-walk oracle already reads lexical environment slots through
//! [`EvalFrame::get`]. Future native tiers need the same operation behind the
//! stable `aos_env_get` helper symbol. This module pins the helper's safe
//! family metadata and exposes a process-local Rust callable wrapper for
//! registration preflight only. It does not export a C ABI function, define an
//! environment object layout, or register a JIT symbol.

use crate::eval::env::{EvalEnvError, EvalFrame};
use crate::value::Value;

/// The environment-access entry point owned by the runtime ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEnvAccessEntryPoint {
    /// The `aos_env_get` helper that reads one captured lexical frame slot.
    AosEnvGet,
}

/// Frozen environment-access entry points registered by future native runtimes.
pub const RUNTIME_ENV_ACCESS_ENTRYPOINTS: &[RuntimeEnvAccessEntryPoint] =
    &[RuntimeEnvAccessEntryPoint::AosEnvGet];

const ENV_GET_PARAMETERS: &[RuntimeEnvAccessAbiParameter] = &[
    RuntimeEnvAccessAbiParameter::new("env", RuntimeEnvAccessAbiParameterKind::EnvPointer),
    RuntimeEnvAccessAbiParameter::new("slot", RuntimeEnvAccessAbiParameterKind::U32),
];

/// Frozen environment-access helper ABI signatures for future native runtimes.
pub const RUNTIME_ENV_ACCESS_ABI_SIGNATURES: &[RuntimeEnvAccessAbiSignature] =
    &[RuntimeEnvAccessAbiSignature::new(
        RuntimeEnvAccessEntryPoint::AosEnvGet,
        ENV_GET_PARAMETERS,
        RuntimeEnvAccessAbiReturnKind::Value,
    )];

/// Returns environment-access helper bindings with callable Rust wrapper addresses.
///
/// The addresses are process-local Rust function addresses for registration
/// preflight metadata. They are not stable across builds or processes, are not
/// exported C symbols, and are not callable with
/// [`RuntimeEnvAccessAbiSignature`].
pub fn runtime_env_access_rust_callable_bindings() -> Vec<RuntimeEnvAccessRustCallableBinding> {
    runtime_env_access_entrypoints()
        .iter()
        .copied()
        .map(RuntimeEnvAccessEntryPoint::rust_callable_binding)
        .collect()
}

/// Returns the frozen environment-access entry-point inventory.
pub const fn runtime_env_access_entrypoints() -> &'static [RuntimeEnvAccessEntryPoint] {
    RUNTIME_ENV_ACCESS_ENTRYPOINTS
}

/// Returns the frozen environment-access helper ABI signature inventory.
pub const fn runtime_env_access_abi_signatures() -> &'static [RuntimeEnvAccessAbiSignature] {
    RUNTIME_ENV_ACCESS_ABI_SIGNATURES
}

type RuntimeEnvGetFn = fn(&EvalFrame, u32) -> Result<Value, EvalEnvError>;

fn rust_callable_aos_env_get(frame: &EvalFrame, slot: u32) -> Result<Value, EvalEnvError> {
    frame.get(slot)
}

impl RuntimeEnvAccessEntryPoint {
    /// Returns the stable runtime symbol name for this environment-access entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosEnvGet => "aos_env_get",
        }
    }

    /// Returns the environment-access entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_env_get" => Some(Self::AosEnvGet),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this environment-access entry point.
    pub const fn abi_signature(self) -> RuntimeEnvAccessAbiSignature {
        match self {
            Self::AosEnvGet => RuntimeEnvAccessAbiSignature::new(
                self,
                ENV_GET_PARAMETERS,
                RuntimeEnvAccessAbiReturnKind::Value,
            ),
        }
    }

    /// Returns the callable Rust storage-wrapper binding for this entry point.
    ///
    /// The callable's Rust shape is separate from the frozen native ABI
    /// signature because environment-pointer decoding and trap transfer are not
    /// implemented yet.
    pub fn rust_callable_binding(self) -> RuntimeEnvAccessRustCallableBinding {
        RuntimeEnvAccessRustCallableBinding::new(
            self,
            self.rust_callable_shape(),
            self.rust_callable_address(),
        )
    }

    /// Returns the Rust storage-wrapper call shape for this entry point.
    pub const fn rust_callable_shape(self) -> RuntimeEnvAccessRustCallableShape {
        match self {
            Self::AosEnvGet => RuntimeEnvAccessRustCallableShape::FrameSlotLookup,
        }
    }

    /// Returns the process-local Rust storage-wrapper address for this entry point.
    ///
    /// The address is suitable for registration preflight metadata only. It is
    /// not an exported C ABI symbol, is not callable with the frozen native ABI
    /// signature, and must not be persisted.
    pub fn rust_callable_address(self) -> RuntimeEnvAccessRustCallableAddress {
        let ptr = match self {
            Self::AosEnvGet => rust_callable_aos_env_get as RuntimeEnvGetFn as *const (),
        };
        RuntimeEnvAccessRustCallableAddress::new(ptr)
    }
}

/// The Rust function shape behind a callable environment-access wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEnvAccessRustCallableShape {
    /// `fn(&EvalFrame, u32) -> Result<Value, EvalEnvError>`.
    FrameSlotLookup,
}

/// A process-local callable Rust environment-access wrapper address.
///
/// This pointer identifies a Rust function in the current process. It is used as
/// registration metadata for later native startup binding and is intentionally
/// not serialized or treated as stable ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeEnvAccessRustCallableAddress {
    ptr: *const (),
}

impl RuntimeEnvAccessRustCallableAddress {
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

/// A callable Rust wrapper binding for one environment-access helper entry point.
///
/// This is not a native ABI binding. It deliberately omits
/// [`RuntimeEnvAccessAbiSignature`] because this Rust callable uses a borrowed
/// [`EvalFrame`] and returns [`EvalEnvError`] through [`Result`], while the frozen
/// native ABI will eventually decode a raw environment pointer and transfer
/// failures through evaluator trap machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeEnvAccessRustCallableBinding {
    entrypoint: RuntimeEnvAccessEntryPoint,
    shape: RuntimeEnvAccessRustCallableShape,
    address: RuntimeEnvAccessRustCallableAddress,
}

impl RuntimeEnvAccessRustCallableBinding {
    const fn new(
        entrypoint: RuntimeEnvAccessEntryPoint,
        shape: RuntimeEnvAccessRustCallableShape,
        address: RuntimeEnvAccessRustCallableAddress,
    ) -> Self {
        Self {
            entrypoint,
            shape,
            address,
        }
    }

    /// Returns the environment-access entry point served by this binding.
    pub const fn entrypoint(self) -> RuntimeEnvAccessEntryPoint {
        self.entrypoint
    }

    /// Returns the Rust function shape behind this binding.
    pub const fn shape(self) -> RuntimeEnvAccessRustCallableShape {
        self.shape
    }

    /// Returns the stable runtime symbol name served by this binding.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the process-local callable Rust address for this binding.
    pub const fn address(self) -> RuntimeEnvAccessRustCallableAddress {
        self.address
    }
}

/// A frozen environment-access ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeEnvAccessAbiSignature {
    entrypoint: RuntimeEnvAccessEntryPoint,
    parameters: &'static [RuntimeEnvAccessAbiParameter],
    return_kind: RuntimeEnvAccessAbiReturnKind,
}

impl RuntimeEnvAccessAbiSignature {
    const fn new(
        entrypoint: RuntimeEnvAccessEntryPoint,
        parameters: &'static [RuntimeEnvAccessAbiParameter],
        return_kind: RuntimeEnvAccessAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the environment-access ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeEnvAccessEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeEnvAccessEntryPoint::abi_signature)
    }

    /// Returns the environment-access entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeEnvAccessEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeEnvAccessAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeEnvAccessAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen environment-access ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeEnvAccessAbiParameter {
    name: &'static str,
    kind: RuntimeEnvAccessAbiParameterKind,
}

impl RuntimeEnvAccessAbiParameter {
    const fn new(name: &'static str, kind: RuntimeEnvAccessAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeEnvAccessAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by environment-access symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEnvAccessAbiParameterKind {
    /// A pointer to a captured lexical environment frame.
    EnvPointer,
    /// A 32-bit environment slot index.
    U32,
}

/// The success-path machine-level result kind returned by environment helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEnvAccessAbiReturnKind {
    /// A by-value runtime value word pair.
    Value,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compile::{
        RuntimeAbiParameterKind, RuntimeAbiReturnKind, RuntimeHelperRole,
        runtime_helper_call_signature, runtime_helper_symbols,
    };
    use crate::eval::env::EvalFrame;
    use crate::value::Value;

    use super::*;

    #[test]
    fn runtime_env_access_symbol_matches_core_helper_inventory() {
        let helper_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::EnvironmentAccess)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();
        let entrypoint_symbols = runtime_env_access_entrypoints()
            .iter()
            .copied()
            .map(RuntimeEnvAccessEntryPoint::symbol_name)
            .collect::<BTreeSet<_>>();
        let signature_symbols = runtime_env_access_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeEnvAccessAbiSignature::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(helper_symbols, BTreeSet::from(["aos_env_get"]));
        assert_eq!(entrypoint_symbols, helper_symbols);
        assert_eq!(signature_symbols, helper_symbols);
    }

    #[test]
    fn env_access_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_env_access_entrypoints(),
            [RuntimeEnvAccessEntryPoint::AosEnvGet]
        );

        for entrypoint in runtime_env_access_entrypoints() {
            assert_eq!(
                RuntimeEnvAccessEntryPoint::from_symbol_name(entrypoint.symbol_name()),
                Some(*entrypoint)
            );
            assert_eq!(
                RuntimeEnvAccessAbiSignature::from_symbol_name(entrypoint.symbol_name()),
                Some(entrypoint.abi_signature())
            );
        }
        for symbol in runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() != RuntimeHelperRole::EnvironmentAccess)
        {
            assert_eq!(
                RuntimeEnvAccessEntryPoint::from_symbol_name(symbol.name()),
                None,
                "{} is not an environment-access entry point",
                symbol.name()
            );
            assert_eq!(
                RuntimeEnvAccessAbiSignature::from_symbol_name(symbol.name()),
                None,
                "{} has no environment-access ABI signature",
                symbol.name()
            );
        }
    }

    #[test]
    fn env_access_abi_signature_pins_frame_slot_value_return() {
        let signature = RuntimeEnvAccessEntryPoint::AosEnvGet.abi_signature();

        assert_eq!(
            runtime_env_access_abi_signatures(),
            [RuntimeEnvAccessAbiSignature::new(
                RuntimeEnvAccessEntryPoint::AosEnvGet,
                ENV_GET_PARAMETERS,
                RuntimeEnvAccessAbiReturnKind::Value,
            )]
        );
        assert_eq!(
            signature.entrypoint(),
            RuntimeEnvAccessEntryPoint::AosEnvGet
        );
        assert_eq!(signature.symbol_name(), "aos_env_get");
        assert_eq!(
            signature.parameters(),
            [
                RuntimeEnvAccessAbiParameter::new(
                    "env",
                    RuntimeEnvAccessAbiParameterKind::EnvPointer,
                ),
                RuntimeEnvAccessAbiParameter::new("slot", RuntimeEnvAccessAbiParameterKind::U32),
            ]
            .as_slice()
        );
        assert_eq!(
            signature.return_kind(),
            RuntimeEnvAccessAbiReturnKind::Value
        );
    }

    #[test]
    fn env_access_abi_signature_matches_core_runtime_call_metadata() {
        let local_signature = RuntimeEnvAccessEntryPoint::AosEnvGet.abi_signature();
        let core_signature =
            runtime_helper_call_signature(local_signature.symbol_name()).expect("core env-get ABI");
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
                ("env", RuntimeEnvAccessAbiParameterKind::EnvPointer),
                ("slot", RuntimeEnvAccessAbiParameterKind::U32),
            ]
        );
        assert_eq!(
            core_parameters,
            vec![
                ("env", RuntimeAbiParameterKind::EnvPointer),
                ("slot", RuntimeAbiParameterKind::U32),
            ]
        );
        assert_eq!(core_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            local_signature.return_kind(),
            RuntimeEnvAccessAbiReturnKind::Value
        );
    }

    #[test]
    fn env_access_rust_callable_bindings_preserve_entrypoint_inventory() {
        let bindings = runtime_env_access_rust_callable_bindings();
        let expected = [(
            RuntimeEnvAccessEntryPoint::AosEnvGet,
            RuntimeEnvAccessRustCallableShape::FrameSlotLookup,
            rust_callable_aos_env_get as RuntimeEnvGetFn as *const (),
        )];

        assert_eq!(bindings.len(), expected.len());
        assert_eq!(
            bindings
                .iter()
                .copied()
                .map(RuntimeEnvAccessRustCallableBinding::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_env_access_entrypoints()
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
            runtime_env_access_abi_signatures()
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
    fn env_get_rust_callable_reads_frame_slots() {
        let frame = EvalFrame::new(2).expect("frame allocates");
        let expected = Value::int(42);

        frame.set(1, expected).expect("slot stores");

        assert_eq!(
            rust_callable_aos_env_get(&frame, 1)
                .expect("slot reads")
                .as_int()
                .expect("slot stores int"),
            expected.as_int().expect("expected int")
        );
    }

    #[test]
    fn env_get_rust_callable_reports_slot_errors() {
        let frame = EvalFrame::new(1).expect("frame allocates");
        let error = rust_callable_aos_env_get(&frame, 2).expect_err("out-of-range slot rejects");

        assert_eq!(error, EvalEnvError::SlotOutOfBounds { slot: 2, slots: 1 });
    }
}
