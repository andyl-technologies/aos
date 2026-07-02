//! Address-free runtime ABI inventory consumed by future JIT tiers.
//!
//! The inventory in this module mirrors the safe runtime ABI metadata owned by
//! `ratchet-core`. It gives JIT-side code a local, documented entry point for the
//! thunk, lambda, and builtin primop call signatures without creating raw
//! function-pointer type aliases or executable wrappers.

use ratchet_core::{
    RuntimeCallSignature, runtime_lambda_call_signature, runtime_primop_call_signatures,
    runtime_thunk_call_signature,
};

/// Address-free runtime-call signatures required by JIT lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JitRuntimeAbiInventory {
    thunk_body: RuntimeCallSignature,
    lambda_body: RuntimeCallSignature,
    primop_wrappers: Vec<RuntimeCallSignature>,
}

impl JitRuntimeAbiInventory {
    /// Builds the JIT-side ABI inventory from the core metadata source of truth.
    pub fn from_core_metadata() -> Self {
        Self {
            thunk_body: runtime_thunk_call_signature(),
            lambda_body: runtime_lambda_call_signature(),
            primop_wrappers: runtime_primop_call_signatures().to_vec(),
        }
    }

    /// Returns the frozen runtime-call signature for compiled thunk bodies.
    pub const fn thunk_body_signature(&self) -> RuntimeCallSignature {
        self.thunk_body
    }

    /// Returns the frozen runtime-call signature for compiled lambda bodies.
    pub const fn lambda_body_signature(&self) -> RuntimeCallSignature {
        self.lambda_body
    }

    /// Returns frozen builtin primop wrapper signatures in arity order.
    pub fn primop_wrapper_signatures(&self) -> &[RuntimeCallSignature] {
        &self.primop_wrappers
    }
}

/// Returns the JIT-side view of the frozen runtime-call ABI metadata.
pub fn jit_runtime_abi_inventory() -> JitRuntimeAbiInventory {
    JitRuntimeAbiInventory::from_core_metadata()
}

#[cfg(test)]
mod tests {
    use ratchet_core::{
        RuntimeCallableKind, runtime_lambda_call_signature, runtime_primop_call_signatures,
        runtime_thunk_call_signature,
    };

    use super::*;

    #[test]
    fn jit_runtime_abi_inventory_mirrors_core_call_metadata() {
        let inventory = jit_runtime_abi_inventory();

        assert_eq!(
            inventory.thunk_body_signature(),
            runtime_thunk_call_signature()
        );
        assert_eq!(
            inventory.lambda_body_signature(),
            runtime_lambda_call_signature()
        );
        assert_eq!(
            inventory.primop_wrapper_signatures(),
            runtime_primop_call_signatures()
        );
    }

    #[test]
    fn jit_runtime_abi_inventory_preserves_callable_kinds() {
        let inventory = jit_runtime_abi_inventory();
        let primop_arities = inventory
            .primop_wrapper_signatures()
            .iter()
            .map(|signature| signature.callable())
            .collect::<Vec<_>>();

        assert_eq!(
            inventory.thunk_body_signature().callable(),
            RuntimeCallableKind::ThunkBody
        );
        assert_eq!(
            inventory.lambda_body_signature().callable(),
            RuntimeCallableKind::LambdaBody
        );
        assert_eq!(
            primop_arities,
            vec![
                RuntimeCallableKind::Primop { arity: 0 },
                RuntimeCallableKind::Primop { arity: 1 },
                RuntimeCallableKind::Primop { arity: 2 },
                RuntimeCallableKind::Primop { arity: 3 },
            ]
        );
    }
}
