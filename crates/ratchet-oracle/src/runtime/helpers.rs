//! Safe runtime-helper binding inventory for future native registration.
//!
//! The allocation and write-barrier modules each own their frozen helper
//! symbols, ABI signatures, and safe Rust dispatch tables. This module combines
//! those helper families into one registration-oriented manifest so later
//! Cranelift or C-ABI glue can consume a single inventory without guessing from
//! symbol text. It does not export native functions or install symbols in a JIT
//! module.

use crate::compile::{
    RuntimeHelperRole, RuntimeSymbolKind, RuntimeSymbolNameError, runtime_symbol_manifest,
};
use thiserror::Error;

use super::alloc::{
    RuntimeAllocationAbiSignature, RuntimeAllocationEntryPoint,
    RuntimeAllocationRustCallableBinding, runtime_allocation_rust_callable_bindings,
};
use super::barrier::{
    RuntimeWriteBarrierAbiSignature, RuntimeWriteBarrierEntryPoint,
    RuntimeWriteBarrierRustCallableBinding, runtime_write_barrier_rust_callable_bindings,
};

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

/// Returns helper bindings that currently have callable Rust storage wrappers.
///
/// These bindings are process-local Rust callables, not exported C ABI targets.
/// The inventory is separate from complete runtime-symbol registration, which
/// also has to bind future helper roles and builtin symbols.
pub fn runtime_helper_rust_callable_bindings() -> Vec<RuntimeHelperRustCallableBinding> {
    let mut bindings = runtime_allocation_rust_callable_bindings()
        .into_iter()
        .map(RuntimeHelperRustCallableBinding::Allocation)
        .collect::<Vec<_>>();
    bindings.extend(
        runtime_write_barrier_rust_callable_bindings()
            .into_iter()
            .map(RuntimeHelperRustCallableBinding::WriteBarrier),
    );
    bindings
}

/// Builds a helper-family preflight for callable Rust storage wrappers.
pub fn runtime_helper_rust_callable_preflight() -> RuntimeHelperRustCallablePreflight {
    let mut callable_bindings = Vec::new();
    let mut missing_bindings = Vec::new();

    for binding in runtime_helper_bindings().iter().copied() {
        match binding.rust_callable_binding() {
            Some(callable) => callable_bindings.push(callable),
            None => missing_bindings.push(binding),
        }
    }

    RuntimeHelperRustCallablePreflight::new(callable_bindings, missing_bindings)
}

/// One runtime symbol's current safe binding status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolBindingStatus {
    /// A helper symbol that already has a safe Rust binding.
    BoundHelper(RuntimeHelperBinding),
    /// A helper symbol reserved by the core ABI but not yet bound in this crate.
    UnboundHelper(RuntimeHelperRole),
    /// A builtin runtime symbol reserved by the core ABI.
    Builtin,
}

/// One runtime symbol and its current safe binding status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolBindingManifestEntry {
    symbol_name: String,
    status: RuntimeSymbolBindingStatus,
}

impl RuntimeSymbolBindingManifestEntry {
    fn new(symbol_name: String, status: RuntimeSymbolBindingStatus) -> Self {
        Self {
            symbol_name,
            status,
        }
    }

    /// Returns the stable runtime symbol name.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the symbol's current safe binding status.
    pub const fn status(&self) -> RuntimeSymbolBindingStatus {
        self.status
    }
}

/// Result returned when building the runtime symbol binding manifest.
pub type RuntimeSymbolBindingManifestResult =
    Result<Vec<RuntimeSymbolBindingManifestEntry>, RuntimeSymbolNameError>;

/// Builds the oracle-side safe runtime symbol binding manifest.
///
/// The manifest preserves [`runtime_symbol_manifest`] order while classifying
/// each frozen runtime symbol as a currently bound helper, an unbound future
/// helper, or a builtin. Later native registration can use this as a preflight
/// before attaching executable addresses.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be built.
pub fn runtime_symbol_binding_manifest() -> RuntimeSymbolBindingManifestResult {
    runtime_symbol_manifest()?
        .into_iter()
        .map(|entry| {
            let status = match entry.kind() {
                RuntimeSymbolKind::Helper(role) => {
                    RuntimeHelperBinding::from_symbol_name(entry.name())
                        .map(RuntimeSymbolBindingStatus::BoundHelper)
                        .unwrap_or(RuntimeSymbolBindingStatus::UnboundHelper(role))
                }
                RuntimeSymbolKind::Builtin => RuntimeSymbolBindingStatus::Builtin,
            };
            Ok(RuntimeSymbolBindingManifestEntry::new(
                entry.name().to_owned(),
                status,
            ))
        })
        .collect()
}

/// One runtime symbol that still lacks a native registration binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolMissingBinding {
    /// A helper symbol has no safe runtime helper binding yet.
    Helper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The helper role reserved by the core runtime ABI.
        role: RuntimeHelperRole,
    },
    /// A builtin symbol has no executable builtin binding yet.
    Builtin {
        /// The stable runtime symbol name.
        symbol_name: String,
    },
}

impl RuntimeSymbolMissingBinding {
    fn helper(symbol_name: String, role: RuntimeHelperRole) -> Self {
        Self::Helper { symbol_name, role }
    }

    fn builtin(symbol_name: String) -> Self {
        Self::Builtin { symbol_name }
    }

    /// Returns the stable runtime symbol name that is not yet bindable.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::Helper { symbol_name, .. } | Self::Builtin { symbol_name } => symbol_name,
        }
    }

    /// Returns the helper role when the missing binding is a helper symbol.
    pub const fn helper_role(&self) -> Option<RuntimeHelperRole> {
        match self {
            Self::Helper { role, .. } => Some(*role),
            Self::Builtin { .. } => None,
        }
    }
}

/// The complete set of safe helper bindings ready for registration metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolRegistrationPlan {
    helper_bindings: Vec<RuntimeHelperBinding>,
}

impl RuntimeSymbolRegistrationPlan {
    fn new(helper_bindings: Vec<RuntimeHelperBinding>) -> Self {
        Self { helper_bindings }
    }

    /// Returns safe helper bindings in runtime symbol-manifest order.
    pub fn helper_bindings(&self) -> &[RuntimeHelperBinding] {
        &self.helper_bindings
    }
}

/// A deterministic readiness report for future native symbol registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolRegistrationPreflight {
    helper_bindings: Vec<RuntimeHelperBinding>,
    missing_bindings: Vec<RuntimeSymbolMissingBinding>,
}

impl RuntimeSymbolRegistrationPreflight {
    fn new(
        helper_bindings: Vec<RuntimeHelperBinding>,
        missing_bindings: Vec<RuntimeSymbolMissingBinding>,
    ) -> Self {
        Self {
            helper_bindings,
            missing_bindings,
        }
    }

    /// Returns safe helper bindings in runtime symbol-manifest order.
    pub fn helper_bindings(&self) -> &[RuntimeHelperBinding] {
        &self.helper_bindings
    }

    /// Returns unbound helper and builtin symbols in runtime symbol-manifest order.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has a current safe binding.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Converts a complete preflight report into registration metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolRegistrationError::Incomplete`] when any runtime
    /// symbol still lacks a binding.
    pub fn into_registration_plan(
        self,
    ) -> Result<RuntimeSymbolRegistrationPlan, RuntimeSymbolRegistrationError> {
        let missing_count = self.missing_bindings.len();
        if missing_count == 0 {
            Ok(RuntimeSymbolRegistrationPlan::new(self.helper_bindings))
        } else {
            Err(RuntimeSymbolRegistrationError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

/// Result returned when building runtime symbol registration readiness metadata.
pub type RuntimeSymbolRegistrationPreflightResult =
    Result<RuntimeSymbolRegistrationPreflight, RuntimeSymbolNameError>;

/// A failure while preparing runtime symbol registration metadata.
#[derive(Debug, Error)]
pub enum RuntimeSymbolRegistrationError {
    /// The core runtime symbol manifest could not be built.
    #[error("failed to build runtime symbol binding manifest")]
    SymbolManifest {
        /// The underlying stable-symbol manifest error.
        #[from]
        source: RuntimeSymbolNameError,
    },
    /// Some runtime symbols have no current binding.
    #[error("runtime symbol registration is incomplete: {missing_count} symbol bindings missing")]
    Incomplete {
        /// The number of symbols still missing registration bindings.
        missing_count: usize,
        /// The full preflight report, including bindable and missing symbols.
        preflight: RuntimeSymbolRegistrationPreflight,
    },
}

/// Result returned when requiring complete runtime symbol registration metadata.
pub type RuntimeSymbolRegistrationPlanResult =
    Result<RuntimeSymbolRegistrationPlan, RuntimeSymbolRegistrationError>;

/// Builds a readiness report for future native symbol registration.
///
/// The report consumes [`runtime_symbol_binding_manifest`], preserves its order,
/// keeps currently bindable helper metadata, and records every unbound helper or
/// builtin symbol that prevents complete native registration today.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be built.
pub fn runtime_symbol_registration_preflight() -> RuntimeSymbolRegistrationPreflightResult {
    let mut helper_bindings = Vec::new();
    let mut missing_bindings = Vec::new();

    for entry in runtime_symbol_binding_manifest()? {
        match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                debug_assert_eq!(entry.symbol_name(), binding.symbol_name());
                helper_bindings.push(binding);
            }
            RuntimeSymbolBindingStatus::UnboundHelper(role) => {
                missing_bindings.push(RuntimeSymbolMissingBinding::helper(
                    entry.symbol_name().to_owned(),
                    role,
                ));
            }
            RuntimeSymbolBindingStatus::Builtin => {
                missing_bindings.push(RuntimeSymbolMissingBinding::builtin(
                    entry.symbol_name().to_owned(),
                ));
            }
        }
    }

    Ok(RuntimeSymbolRegistrationPreflight::new(
        helper_bindings,
        missing_bindings,
    ))
}

/// Builds complete safe runtime symbol registration metadata.
///
/// This function is intentionally stricter than
/// [`runtime_symbol_registration_preflight`]: it succeeds only after every
/// frozen runtime symbol has a safe binding.
///
/// # Errors
///
/// Returns [`RuntimeSymbolRegistrationError::SymbolManifest`] if the core
/// runtime symbol manifest cannot be built. Returns
/// [`RuntimeSymbolRegistrationError::Incomplete`] while any helper or builtin
/// symbol remains unbound.
pub fn runtime_symbol_registration_plan() -> RuntimeSymbolRegistrationPlanResult {
    runtime_symbol_registration_preflight()
        .map_err(RuntimeSymbolRegistrationError::from)?
        .into_registration_plan()
}

/// A callable Rust storage-wrapper binding for one runtime helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperRustCallableBinding {
    /// An allocation helper backed by `runtime::alloc` storage-wrapper dispatch.
    Allocation(RuntimeAllocationRustCallableBinding),
    /// A write-barrier helper backed by `runtime::barrier` storage-wrapper dispatch.
    WriteBarrier(RuntimeWriteBarrierRustCallableBinding),
}

impl RuntimeHelperRustCallableBinding {
    /// Returns the stable helper symbol name served by this callable binding.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::Allocation(binding) => binding.symbol_name(),
            Self::WriteBarrier(binding) => binding.symbol_name(),
        }
    }

    /// Returns the core helper role served by this callable binding.
    pub const fn role(self) -> RuntimeHelperRole {
        match self {
            Self::Allocation(_) => RuntimeHelperRole::Allocation,
            Self::WriteBarrier(_) => RuntimeHelperRole::WriteBarrier,
        }
    }

    /// Returns the safe helper binding metadata associated with this callable.
    pub const fn helper_binding(self) -> RuntimeHelperBinding {
        match self {
            Self::Allocation(binding) => {
                RuntimeHelperBinding::Allocation(binding.entrypoint().abi_signature())
            }
            Self::WriteBarrier(binding) => {
                RuntimeHelperBinding::WriteBarrier(binding.entrypoint().abi_signature())
            }
        }
    }

    /// Returns the allocation callable when this binding serves allocation.
    pub const fn allocation_callable(self) -> Option<RuntimeAllocationRustCallableBinding> {
        match self {
            Self::Allocation(binding) => Some(binding),
            Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the write-barrier callable when this binding serves a barrier.
    pub const fn write_barrier_callable(self) -> Option<RuntimeWriteBarrierRustCallableBinding> {
        match self {
            Self::Allocation(_) => None,
            Self::WriteBarrier(binding) => Some(binding),
        }
    }
}

/// A deterministic helper-family report for callable Rust storage wrappers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeHelperRustCallablePreflight {
    callable_bindings: Vec<RuntimeHelperRustCallableBinding>,
    missing_bindings: Vec<RuntimeHelperBinding>,
}

impl RuntimeHelperRustCallablePreflight {
    fn new(
        callable_bindings: Vec<RuntimeHelperRustCallableBinding>,
        missing_bindings: Vec<RuntimeHelperBinding>,
    ) -> Self {
        Self {
            callable_bindings,
            missing_bindings,
        }
    }

    /// Returns helper bindings that have callable Rust storage wrappers.
    pub fn callable_bindings(&self) -> &[RuntimeHelperRustCallableBinding] {
        &self.callable_bindings
    }

    /// Returns bound helper metadata that still lacks a callable Rust wrapper.
    pub fn missing_bindings(&self) -> &[RuntimeHelperBinding] {
        &self.missing_bindings
    }

    /// Returns true when every currently bound helper has a callable Rust wrapper.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }
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

    /// Returns the callable Rust storage-wrapper binding for this helper, if any.
    pub fn rust_callable_binding(self) -> Option<RuntimeHelperRustCallableBinding> {
        match self {
            Self::Allocation(signature) => Some(RuntimeHelperRustCallableBinding::Allocation(
                signature.entrypoint().rust_callable_binding(),
            )),
            Self::WriteBarrier(signature) => Some(RuntimeHelperRustCallableBinding::WriteBarrier(
                signature.entrypoint().rust_callable_binding(),
            )),
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
    use std::collections::BTreeSet;

    use crate::compile::{RuntimeHelperRole, runtime_helper_symbols, runtime_symbol_manifest};

    use super::*;
    use crate::runtime::alloc::{
        runtime_allocation_abi_signatures, runtime_allocation_rust_callable_bindings,
    };
    use crate::runtime::barrier::{
        runtime_write_barrier_abi_signatures, runtime_write_barrier_rust_callable_bindings,
    };

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
    fn runtime_helper_rust_callable_bindings_preserve_family_inventories() {
        let helper_callables = runtime_helper_rust_callable_bindings();
        let mut expected_callables = runtime_allocation_rust_callable_bindings()
            .into_iter()
            .map(RuntimeHelperRustCallableBinding::Allocation)
            .collect::<Vec<_>>();
        expected_callables.extend(
            runtime_write_barrier_rust_callable_bindings()
                .into_iter()
                .map(RuntimeHelperRustCallableBinding::WriteBarrier),
        );

        assert_eq!(helper_callables, expected_callables);
        assert_eq!(
            helper_callables
                .iter()
                .copied()
                .map(RuntimeHelperRustCallableBinding::helper_binding)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_helper_bindings()
        );

        for callable in helper_callables {
            assert_eq!(
                RuntimeHelperBinding::from_symbol_name(callable.symbol_name()),
                Some(callable.helper_binding())
            );
            assert_eq!(
                callable.helper_binding().rust_callable_binding(),
                Some(callable)
            );
            match callable.role() {
                RuntimeHelperRole::Allocation => {
                    assert!(callable.allocation_callable().is_some());
                    assert!(callable.write_barrier_callable().is_none());
                }
                RuntimeHelperRole::WriteBarrier => {
                    assert!(callable.allocation_callable().is_none());
                    assert!(callable.write_barrier_callable().is_some());
                }
                role => panic!("unexpected callable helper role: {role:?}"),
            }
        }
    }

    #[test]
    fn runtime_helper_rust_callable_preflight_covers_bound_helpers() {
        let preflight = runtime_helper_rust_callable_preflight();

        assert!(preflight.is_complete());
        assert_eq!(
            preflight.callable_bindings(),
            runtime_helper_rust_callable_bindings().as_slice()
        );
        assert!(preflight.missing_bindings().is_empty());
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

    #[test]
    fn runtime_symbol_binding_manifest_preserves_core_symbol_order() {
        let core_manifest = runtime_symbol_manifest().expect("core manifest builds");
        let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");

        let core_symbols = core_manifest
            .iter()
            .map(|entry| entry.name())
            .collect::<Vec<_>>();
        let binding_symbols = binding_manifest
            .iter()
            .map(RuntimeSymbolBindingManifestEntry::symbol_name)
            .collect::<Vec<_>>();

        assert_eq!(binding_symbols, core_symbols);
    }

    #[test]
    fn runtime_symbol_binding_manifest_marks_bound_helpers() {
        let manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
        let bound_helpers = manifest
            .iter()
            .filter_map(|entry| match entry.status() {
                RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                    Some((entry.symbol_name(), binding))
                }
                RuntimeSymbolBindingStatus::UnboundHelper(_)
                | RuntimeSymbolBindingStatus::Builtin => None,
            })
            .collect::<Vec<_>>();
        let expected_helpers = runtime_helper_bindings()
            .iter()
            .copied()
            .map(|binding| (binding.symbol_name(), binding))
            .collect::<Vec<_>>();

        assert_eq!(bound_helpers, expected_helpers);
    }

    #[test]
    fn runtime_symbol_binding_manifest_marks_unbound_helpers_and_builtins() {
        let manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");

        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.symbol_name() == "aos_force")
                .map(RuntimeSymbolBindingManifestEntry::status),
            Some(RuntimeSymbolBindingStatus::UnboundHelper(
                RuntimeHelperRole::ForcingControl
            ))
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.symbol_name() == "aos_apply")
                .map(RuntimeSymbolBindingManifestEntry::status),
            Some(RuntimeSymbolBindingStatus::UnboundHelper(
                RuntimeHelperRole::CallControl
            ))
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.symbol_name() == "nix.builtin.derivationStrict")
                .map(RuntimeSymbolBindingManifestEntry::status),
            Some(RuntimeSymbolBindingStatus::Builtin)
        );
    }

    #[test]
    fn runtime_symbol_binding_manifest_bound_symbols_match_safe_inventory() {
        let manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
        let bound_symbols = manifest
            .iter()
            .filter_map(|entry| match entry.status() {
                RuntimeSymbolBindingStatus::BoundHelper(_) => Some(entry.symbol_name()),
                RuntimeSymbolBindingStatus::UnboundHelper(_)
                | RuntimeSymbolBindingStatus::Builtin => None,
            })
            .collect::<BTreeSet<_>>();
        let helper_binding_symbols = runtime_helper_bindings()
            .iter()
            .copied()
            .map(RuntimeHelperBinding::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(bound_symbols, helper_binding_symbols);
    }

    #[test]
    fn runtime_symbol_registration_preflight_reports_current_gaps() {
        let preflight =
            runtime_symbol_registration_preflight().expect("registration preflight builds");
        let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");

        assert!(!preflight.is_complete());
        assert_eq!(preflight.helper_bindings(), runtime_helper_bindings());
        assert_eq!(
            preflight.helper_bindings().len() + preflight.missing_bindings().len(),
            binding_manifest.len()
        );
        assert!(
            preflight
                .missing_bindings()
                .windows(2)
                .all(|window| { window[0].symbol_name() < window[1].symbol_name() })
        );
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "aos_force"
                && missing.helper_role() == Some(RuntimeHelperRole::ForcingControl)
        }));
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "aos_apply"
                && missing.helper_role() == Some(RuntimeHelperRole::CallControl)
        }));
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "nix.builtin.derivationStrict"
                && missing.helper_role().is_none()
        }));
    }

    #[test]
    fn runtime_symbol_registration_plan_rejects_until_all_symbols_are_bound() {
        let error = runtime_symbol_registration_plan()
            .expect_err("complete registration is not available yet");

        let RuntimeSymbolRegistrationError::Incomplete {
            missing_count,
            preflight,
        } = error
        else {
            panic!("registration should fail because bindings are incomplete");
        };
        assert_eq!(missing_count, preflight.missing_bindings().len());
        assert!(!preflight.is_complete());
        assert_eq!(preflight.helper_bindings(), runtime_helper_bindings());
    }
}
