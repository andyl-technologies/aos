//! Runtime write-barrier ABI metadata.
//!
//! The safe tree-walk evaluator routes thunk resolution through direct Rust
//! helpers today. Future native tiers still need one frozen helper symbol for
//! the GC-visible mutation wall: publishing a forced value into a thunk's state
//! slot. This module pins that symbol and its machine-level signature without
//! exporting FFI functions or performing barrier work itself.

/// The write-barrier entry point owned by the runtime ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierEntryPoint {
    /// The single GC write barrier used when publishing a forced thunk result.
    AosGcWriteBarrier,
}

/// Frozen write-barrier entry points registered by future native runtimes.
pub const RUNTIME_WRITE_BARRIER_ENTRYPOINTS: &[RuntimeWriteBarrierEntryPoint] =
    &[RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier];

const GC_WRITE_BARRIER_PARAMETERS: &[RuntimeWriteBarrierAbiParameter] = &[
    RuntimeWriteBarrierAbiParameter::new("rt", RuntimeWriteBarrierAbiParameterKind::RuntimeContext),
    RuntimeWriteBarrierAbiParameter::new(
        "thunk",
        RuntimeWriteBarrierAbiParameterKind::ThunkPointer,
    ),
    RuntimeWriteBarrierAbiParameter::new("value", RuntimeWriteBarrierAbiParameterKind::Value),
];

/// Frozen write-barrier ABI signatures for future native runtimes.
pub const RUNTIME_WRITE_BARRIER_ABI_SIGNATURES: &[RuntimeWriteBarrierAbiSignature] =
    &[RuntimeWriteBarrierAbiSignature::new(
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier,
        GC_WRITE_BARRIER_PARAMETERS,
        RuntimeWriteBarrierAbiReturnKind::Unit,
    )];

/// Returns the frozen write-barrier entry-point inventory.
pub const fn runtime_write_barrier_entrypoints() -> &'static [RuntimeWriteBarrierEntryPoint] {
    RUNTIME_WRITE_BARRIER_ENTRYPOINTS
}

/// Returns the frozen write-barrier ABI signature inventory.
pub const fn runtime_write_barrier_abi_signatures() -> &'static [RuntimeWriteBarrierAbiSignature] {
    RUNTIME_WRITE_BARRIER_ABI_SIGNATURES
}

impl RuntimeWriteBarrierEntryPoint {
    /// Returns the stable runtime symbol name for this write-barrier entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosGcWriteBarrier => "aos_gc_write_barrier",
        }
    }

    /// Returns the write-barrier entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_gc_write_barrier" => Some(Self::AosGcWriteBarrier),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this write-barrier entry point.
    pub const fn abi_signature(self) -> RuntimeWriteBarrierAbiSignature {
        match self {
            Self::AosGcWriteBarrier => RuntimeWriteBarrierAbiSignature::new(
                self,
                GC_WRITE_BARRIER_PARAMETERS,
                RuntimeWriteBarrierAbiReturnKind::Unit,
            ),
        }
    }
}

/// A frozen write-barrier ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierAbiSignature {
    entrypoint: RuntimeWriteBarrierEntryPoint,
    parameters: &'static [RuntimeWriteBarrierAbiParameter],
    return_kind: RuntimeWriteBarrierAbiReturnKind,
}

impl RuntimeWriteBarrierAbiSignature {
    const fn new(
        entrypoint: RuntimeWriteBarrierEntryPoint,
        parameters: &'static [RuntimeWriteBarrierAbiParameter],
        return_kind: RuntimeWriteBarrierAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the write-barrier ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeWriteBarrierEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeWriteBarrierEntryPoint::abi_signature)
    }

    /// Returns the write-barrier entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeWriteBarrierEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeWriteBarrierAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeWriteBarrierAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen write-barrier ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierAbiParameter {
    name: &'static str,
    kind: RuntimeWriteBarrierAbiParameterKind,
}

impl RuntimeWriteBarrierAbiParameter {
    const fn new(name: &'static str, kind: RuntimeWriteBarrierAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeWriteBarrierAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by write-barrier symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierAbiParameterKind {
    /// The evaluator runtime context that owns the installed heap strategy.
    RuntimeContext,
    /// A pointer to the claimed source thunk whose forced-result slot is updated.
    ThunkPointer,
    /// A by-value runtime value word pair being published.
    Value,
}

/// The success-path machine-level result kind returned by write-barrier symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierAbiReturnKind {
    /// The write barrier returns no value on success.
    Unit,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};

    use super::*;

    #[test]
    fn runtime_write_barrier_symbol_matches_core_helper_inventory() {
        let helper_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::WriteBarrier)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();
        let entrypoint_symbols = runtime_write_barrier_entrypoints()
            .iter()
            .copied()
            .map(RuntimeWriteBarrierEntryPoint::symbol_name)
            .collect::<BTreeSet<_>>();
        let signature_symbols = runtime_write_barrier_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeWriteBarrierAbiSignature::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(helper_symbols, BTreeSet::from(["aos_gc_write_barrier"]));
        assert_eq!(entrypoint_symbols, helper_symbols);
        assert_eq!(signature_symbols, helper_symbols);
    }

    #[test]
    fn write_barrier_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_write_barrier_entrypoints(),
            [RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier]
        );

        for entrypoint in runtime_write_barrier_entrypoints() {
            assert_eq!(
                RuntimeWriteBarrierEntryPoint::from_symbol_name(entrypoint.symbol_name()),
                Some(*entrypoint)
            );
            assert_eq!(
                RuntimeWriteBarrierAbiSignature::from_symbol_name(entrypoint.symbol_name()),
                Some(entrypoint.abi_signature())
            );
        }
        for symbol in runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() != RuntimeHelperRole::WriteBarrier)
        {
            assert_eq!(
                RuntimeWriteBarrierEntryPoint::from_symbol_name(symbol.name()),
                None,
                "{} is not a write-barrier entry point",
                symbol.name()
            );
            assert_eq!(
                RuntimeWriteBarrierAbiSignature::from_symbol_name(symbol.name()),
                None,
                "{} has no write-barrier ABI signature",
                symbol.name()
            );
        }
    }

    #[test]
    fn write_barrier_abi_signature_pins_runtime_parameters() {
        let signature = RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier.abi_signature();

        assert_eq!(
            runtime_write_barrier_abi_signatures(),
            [RuntimeWriteBarrierAbiSignature::new(
                RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier,
                GC_WRITE_BARRIER_PARAMETERS,
                RuntimeWriteBarrierAbiReturnKind::Unit,
            )]
        );
        assert_eq!(
            signature.entrypoint(),
            RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier
        );
        assert_eq!(signature.symbol_name(), "aos_gc_write_barrier");
        assert_eq!(
            signature.parameters(),
            [
                RuntimeWriteBarrierAbiParameter::new(
                    "rt",
                    RuntimeWriteBarrierAbiParameterKind::RuntimeContext,
                ),
                RuntimeWriteBarrierAbiParameter::new(
                    "thunk",
                    RuntimeWriteBarrierAbiParameterKind::ThunkPointer,
                ),
                RuntimeWriteBarrierAbiParameter::new(
                    "value",
                    RuntimeWriteBarrierAbiParameterKind::Value,
                ),
            ]
            .as_slice()
        );
        assert_eq!(
            signature.return_kind(),
            RuntimeWriteBarrierAbiReturnKind::Unit
        );
    }
}
