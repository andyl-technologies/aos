//! Shared fixtures for the runtime-helper binding inventory tests.

use std::collections::BTreeSet;

use crate::compile::{
    RuntimeBuiltinCallPreflight, RuntimeCallableKind, RuntimeHelperRole,
    runtime_builtin_call_preflight, runtime_helper_call_signatures, runtime_helper_symbols,
    runtime_symbol_manifest,
};

use super::*;
use crate::runtime::alloc::{
    RuntimeAllocationNativeExportBlocker, runtime_allocation_abi_signatures,
    runtime_allocation_native_export_preflight,
};
use crate::runtime::apply::{
    RuntimeApplyNativeExportBlocker, runtime_apply_abi_signatures,
    runtime_apply_native_export_preflight,
};
use crate::runtime::attr::{
    RuntimeAttrAccessNativeExportBlocker, runtime_attr_access_abi_signatures,
    runtime_attr_access_native_export_preflight,
};
use crate::runtime::barrier::{
    RuntimeWriteBarrierNativeExportBlocker, runtime_write_barrier_abi_signatures,
    runtime_write_barrier_native_export_preflight,
};
use crate::runtime::env::{
    RuntimeEnvAccessNativeExportBlocker, runtime_env_access_abi_signatures,
    runtime_env_access_native_export_preflight,
};
use crate::runtime::forcing::{
    RuntimeForcingNativeExportBlocker, runtime_forcing_abi_signatures,
    runtime_forcing_native_export_preflight,
};

fn expected_runtime_symbol_abi_signature_projection(
    binding_manifest: &[RuntimeSymbolBindingManifestEntry],
    builtin_preflight: &RuntimeBuiltinCallPreflight,
) -> (
    Vec<RuntimeSymbolAbiSignatureBinding>,
    Vec<RuntimeSymbolAbiMissingBinding>,
) {
    let mut signature_bindings = Vec::new();
    let mut missing_bindings = Vec::new();

    for entry in binding_manifest {
        match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                if binding.core_call_signature().is_some() {
                    signature_bindings.push(RuntimeSymbolAbiSignatureBinding::Helper(binding));
                } else {
                    missing_bindings.push(RuntimeSymbolAbiMissingBinding::Helper {
                        symbol_name: entry.symbol_name().to_owned(),
                        role: binding.role(),
                    });
                }
            }
            RuntimeSymbolBindingStatus::UnboundHelper(role) => {
                missing_bindings.push(RuntimeSymbolAbiMissingBinding::Helper {
                    symbol_name: entry.symbol_name().to_owned(),
                    role,
                });
            }
            RuntimeSymbolBindingStatus::Builtin => {
                if let Some(binding) = builtin_preflight
                    .call_bindings()
                    .iter()
                    .find(|binding| binding.symbol_name() == entry.symbol_name())
                    .cloned()
                {
                    signature_bindings.push(RuntimeSymbolAbiSignatureBinding::Builtin(binding));
                } else if let Some(binding) = builtin_preflight
                    .missing_bindings()
                    .iter()
                    .find(|binding| binding.symbol_name() == entry.symbol_name())
                    .cloned()
                {
                    missing_bindings.push(RuntimeSymbolAbiMissingBinding::Builtin(binding));
                } else {
                    missing_bindings.push(RuntimeSymbolAbiMissingBinding::UnclassifiedBuiltin {
                        symbol_name: entry.symbol_name().to_owned(),
                    });
                }
            }
        }
    }

    (signature_bindings, missing_bindings)
}

mod part_1;
mod part_2;
mod part_3;
