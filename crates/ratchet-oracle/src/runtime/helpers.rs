//! Safe runtime-helper binding inventory for future native registration.
//!
//! The allocation and write-barrier modules each own their frozen helper
//! symbols, ABI signatures, and safe Rust dispatch tables. This module combines
//! those helper families into one registration-oriented manifest so later
//! Cranelift or C-ABI glue can consume a single inventory without guessing from
//! symbol text. It does not export native functions or install symbols in a JIT
//! module.

use crate::compile::RuntimeHelperRole;

use super::alloc::{RuntimeAllocationAbiSignature, RuntimeAllocationEntryPoint};
use super::barrier::{RuntimeWriteBarrierAbiSignature, RuntimeWriteBarrierEntryPoint};

/// Runtime helpers that currently have a safe Rust ABI binding.
pub const RUNTIME_HELPER_BINDINGS: &[RuntimeHelperBinding] = &[
    RuntimeHelperBinding::Allocation(RuntimeAllocationEntryPoint::AosAllocAttrs.abi_signature()),
    RuntimeHelperBinding::Allocation(RuntimeAllocationEntryPoint::AosAllocCons.abi_signature()),
    RuntimeHelperBinding::Allocation(RuntimeAllocationEntryPoint::AosAllocLambda.abi_signature()),
    RuntimeHelperBinding::Allocation(RuntimeAllocationEntryPoint::AosAllocList.abi_signature()),
    RuntimeHelperBinding::Allocation(RuntimeAllocationEntryPoint::AosAllocRaw.abi_signature()),
    RuntimeHelperBinding::Allocation(RuntimeAllocationEntryPoint::AosAllocString.abi_signature()),
    RuntimeHelperBinding::Allocation(RuntimeAllocationEntryPoint::AosAllocThunk.abi_signature()),
    RuntimeHelperBinding::WriteBarrier(
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier.abi_signature(),
    ),
];

/// Returns the safe runtime-helper binding inventory.
pub const fn runtime_helper_bindings() -> &'static [RuntimeHelperBinding] {
    RUNTIME_HELPER_BINDINGS
}

/// The native failure behavior promised by a runtime helper binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperFailureConvention {
    /// The helper returns only on success and transfers failures to evaluator
    /// trap/error machinery instead of returning a null pointer or sentinel.
    TrapToEvaluator,
}

/// A safe ABI binding for one frozen runtime helper symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperBinding {
    /// A heap allocation helper routed through `runtime::alloc`.
    Allocation(RuntimeAllocationAbiSignature),
    /// A write-barrier helper routed through `runtime::barrier`.
    WriteBarrier(RuntimeWriteBarrierAbiSignature),
}

impl RuntimeHelperBinding {
    /// Returns the stable helper symbol name.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::Allocation(signature) => signature.symbol_name(),
            Self::WriteBarrier(signature) => signature.symbol_name(),
        }
    }

    /// Returns the core helper role served by this binding.
    pub const fn role(self) -> RuntimeHelperRole {
        match self {
            Self::Allocation(_) => RuntimeHelperRole::Allocation,
            Self::WriteBarrier(_) => RuntimeHelperRole::WriteBarrier,
        }
    }

    /// Returns the native failure convention for this helper binding.
    pub const fn failure_convention(self) -> RuntimeHelperFailureConvention {
        match self {
            Self::Allocation(_) | Self::WriteBarrier(_) => {
                RuntimeHelperFailureConvention::TrapToEvaluator
            }
        }
    }

    /// Returns the binding for a frozen runtime helper symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeAllocationAbiSignature::from_symbol_name(symbol_name)
            .map(Self::Allocation)
            .or_else(|| {
                RuntimeWriteBarrierAbiSignature::from_symbol_name(symbol_name)
                    .map(Self::WriteBarrier)
            })
    }

    /// Returns the allocation ABI signature when this binding serves allocation.
    pub const fn allocation_signature(self) -> Option<RuntimeAllocationAbiSignature> {
        match self {
            Self::Allocation(signature) => Some(signature),
            Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the write-barrier ABI signature when this binding serves a barrier.
    pub const fn write_barrier_signature(self) -> Option<RuntimeWriteBarrierAbiSignature> {
        match self {
            Self::Allocation(_) => None,
            Self::WriteBarrier(signature) => Some(signature),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};

    use super::*;
    use crate::runtime::alloc::runtime_allocation_abi_signatures;
    use crate::runtime::barrier::runtime_write_barrier_abi_signatures;

    #[test]
    fn runtime_helper_bindings_match_core_bound_helper_roles() {
        let bound_symbols = runtime_helper_bindings()
            .iter()
            .copied()
            .map(|binding| (binding.symbol_name(), binding.role()))
            .collect::<Vec<_>>();
        let core_bound_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| {
                matches!(
                    symbol.role(),
                    RuntimeHelperRole::Allocation | RuntimeHelperRole::WriteBarrier
                )
            })
            .map(|symbol| (symbol.name(), symbol.role()))
            .collect::<Vec<_>>();

        assert_eq!(bound_symbols, core_bound_symbols);
    }

    #[test]
    fn runtime_helper_bindings_preserve_family_abi_inventories() {
        let allocation_signatures = runtime_helper_bindings()
            .iter()
            .copied()
            .filter_map(RuntimeHelperBinding::allocation_signature)
            .collect::<Vec<_>>();
        let write_barrier_signatures = runtime_helper_bindings()
            .iter()
            .copied()
            .filter_map(RuntimeHelperBinding::write_barrier_signature)
            .collect::<Vec<_>>();

        assert_eq!(
            allocation_signatures.as_slice(),
            runtime_allocation_abi_signatures()
        );
        assert_eq!(
            write_barrier_signatures.as_slice(),
            runtime_write_barrier_abi_signatures()
        );
    }

    #[test]
    fn runtime_helper_bindings_pin_failure_conventions() {
        let helper_conventions = runtime_helper_bindings()
            .iter()
            .copied()
            .map(|binding| (binding.symbol_name(), binding.failure_convention()))
            .collect::<Vec<_>>();

        assert_eq!(
            helper_conventions,
            vec![
                (
                    "aos_alloc_attrs",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
                (
                    "aos_alloc_cons",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
                (
                    "aos_alloc_lambda",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
                (
                    "aos_alloc_list",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
                (
                    "aos_alloc_raw",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
                (
                    "aos_alloc_string",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
                (
                    "aos_alloc_thunk",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
                (
                    "aos_gc_write_barrier",
                    RuntimeHelperFailureConvention::TrapToEvaluator,
                ),
            ]
        );
    }

    #[test]
    fn runtime_helper_bindings_round_trip_only_bound_helper_symbols() {
        for binding in runtime_helper_bindings().iter().copied() {
            assert_eq!(
                RuntimeHelperBinding::from_symbol_name(binding.symbol_name()),
                Some(binding)
            );
        }

        for symbol in runtime_helper_symbols().iter().copied().filter(|symbol| {
            !matches!(
                symbol.role(),
                RuntimeHelperRole::Allocation | RuntimeHelperRole::WriteBarrier
            )
        }) {
            assert_eq!(
                RuntimeHelperBinding::from_symbol_name(symbol.name()),
                None,
                "{} is not bound by the safe runtime helper manifest",
                symbol.name()
            );
        }
        assert_eq!(
            RuntimeHelperBinding::from_symbol_name("nix.builtin.derivationStrict"),
            None
        );
    }
}
