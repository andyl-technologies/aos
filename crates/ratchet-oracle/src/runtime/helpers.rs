//! Safe runtime-helper binding inventory for future native registration.
//!
//! The allocation, environment-access, and write-barrier modules each own their
//! frozen helper symbols, ABI signatures, and safe Rust dispatch tables. This
//! module combines those helper families into one registration-oriented manifest
//! so later Cranelift or C-ABI glue can consume a single inventory without
//! guessing from symbol text. It does not export native functions or install
//! symbols in a JIT module.

use std::collections::BTreeMap;

use crate::compile::{
    RuntimeBuiltinCallBinding, RuntimeBuiltinCallMissingBinding, RuntimeBuiltinCallPreflight,
    RuntimeCallSignature, RuntimeHelperRole, RuntimeSymbolKind, RuntimeSymbolNameError,
    runtime_builtin_call_preflight, runtime_helper_call_signature, runtime_symbol_manifest,
};
use thiserror::Error;

use super::alloc::{
    RuntimeAllocationAbiSignature, RuntimeAllocationEntryPoint,
    RuntimeAllocationNativeExportBlocker, RuntimeAllocationRustCallableBinding,
    runtime_allocation_rust_callable_bindings,
};
use super::barrier::{
    RuntimeWriteBarrierAbiSignature, RuntimeWriteBarrierEntryPoint,
    RuntimeWriteBarrierNativeExportBlocker, RuntimeWriteBarrierRustCallableBinding,
    runtime_write_barrier_rust_callable_bindings,
};
use super::env::{
    RuntimeEnvAccessAbiSignature, RuntimeEnvAccessEntryPoint, RuntimeEnvAccessRustCallableBinding,
    runtime_env_access_rust_callable_bindings,
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
    RuntimeHelperBinding::EnvironmentAccess(RuntimeEnvAccessEntryPoint::AosEnvGet.abi_signature()),
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
        runtime_env_access_rust_callable_bindings()
            .into_iter()
            .map(RuntimeHelperRustCallableBinding::EnvironmentAccess),
    );
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

/// Result returned when building runtime-symbol ABI-signature readiness metadata.
pub type RuntimeSymbolAbiSignaturePreflightResult =
    Result<RuntimeSymbolAbiSignaturePreflight, RuntimeSymbolNameError>;

/// Result returned when requiring complete runtime-symbol ABI-signature metadata.
pub type RuntimeSymbolAbiSignaturePlanResult =
    Result<RuntimeSymbolAbiSignaturePlan, RuntimeSymbolAbiSignaturePlanError>;

/// A failure while preparing complete runtime-symbol ABI-signature metadata.
#[derive(Debug, Error)]
pub enum RuntimeSymbolAbiSignaturePlanError {
    /// The core runtime symbol or builtin call manifest could not be built.
    #[error("failed to build runtime symbol ABI-signature metadata")]
    SymbolManifest {
        /// The underlying stable-symbol manifest error.
        #[from]
        source: RuntimeSymbolNameError,
    },
    /// Some runtime symbols have no ABI-signature metadata.
    #[error(
        "runtime symbol ABI-signature metadata is incomplete: {missing_count} symbol signatures missing"
    )]
    Incomplete {
        /// The number of symbols still missing ABI-signature metadata.
        missing_count: usize,
        /// The full preflight report, including bindable and missing symbols.
        preflight: RuntimeSymbolAbiSignaturePreflight,
    },
}

/// Builds a runtime-symbol report for helper and builtin ABI-signature metadata.
///
/// The report consumes [`runtime_symbol_binding_manifest`], preserves its order,
/// keeps helper metadata only when a matching core [`RuntimeCallSignature`]
/// exists, attaches builtin call-signature metadata for callable builtin
/// symbols, and records helper or builtin symbols that still prevent complete
/// ABI-signature coverage. This is signature metadata only: no executable
/// addresses are attached and no Cranelift symbols are registered.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest or the
/// builtin call manifest cannot be built.
pub fn runtime_symbol_abi_signature_preflight() -> RuntimeSymbolAbiSignaturePreflightResult {
    let builtin_preflight = runtime_builtin_call_preflight()?;
    let mut signature_bindings = Vec::new();
    let mut missing_bindings = Vec::new();

    for entry in runtime_symbol_binding_manifest()? {
        match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                debug_assert_eq!(entry.symbol_name(), binding.symbol_name());
                if binding.core_call_signature().is_some() {
                    signature_bindings.push(RuntimeSymbolAbiSignatureBinding::Helper(binding));
                } else {
                    missing_bindings.push(RuntimeSymbolAbiMissingBinding::helper(
                        entry.symbol_name().to_owned(),
                        binding.role(),
                    ));
                }
            }
            RuntimeSymbolBindingStatus::UnboundHelper(role) => {
                missing_bindings.push(RuntimeSymbolAbiMissingBinding::helper(
                    entry.symbol_name().to_owned(),
                    role,
                ));
            }
            RuntimeSymbolBindingStatus::Builtin => {
                match builtin_call_binding_for(&builtin_preflight, entry.symbol_name()) {
                    Some(binding) => {
                        signature_bindings.push(RuntimeSymbolAbiSignatureBinding::Builtin(binding));
                    }
                    None => {
                        missing_bindings.push(
                            builtin_call_missing_binding_for(
                                &builtin_preflight,
                                entry.symbol_name(),
                            )
                            .map(RuntimeSymbolAbiMissingBinding::Builtin)
                            .unwrap_or_else(|| {
                                RuntimeSymbolAbiMissingBinding::builtin_unclassified(
                                    entry.symbol_name().to_owned(),
                                )
                            }),
                        );
                    }
                }
            }
        }
    }

    Ok(RuntimeSymbolAbiSignaturePreflight::new(
        signature_bindings,
        missing_bindings,
    ))
}

/// Builds the complete runtime-symbol ABI-signature plan.
///
/// # Errors
///
/// Returns [`RuntimeSymbolAbiSignaturePlanError::SymbolManifest`] if the core
/// runtime symbol manifest or the builtin call manifest cannot be built. Returns
/// [`RuntimeSymbolAbiSignaturePlanError::Incomplete`] while any runtime symbol
/// still lacks ABI-signature metadata.
pub fn runtime_symbol_abi_signature_plan() -> RuntimeSymbolAbiSignaturePlanResult {
    runtime_symbol_abi_signature_preflight()?.into_abi_signature_plan()
}

/// Result returned when building native-target candidate readiness metadata.
pub type RuntimeSymbolNativeTargetCandidatePreflightResult =
    Result<RuntimeSymbolNativeTargetCandidatePreflight, RuntimeSymbolNameError>;

/// Result returned when requiring complete native-target candidate metadata.
pub type RuntimeSymbolNativeTargetCandidatePlanResult =
    Result<RuntimeSymbolNativeTargetCandidatePlan, RuntimeSymbolNativeTargetCandidatePlanError>;

/// A failure while preparing complete native-target candidate metadata.
#[derive(Debug, Error)]
pub enum RuntimeSymbolNativeTargetCandidatePlanError {
    /// The core runtime symbol or builtin call manifest could not be built.
    #[error("failed to build runtime symbol native-target candidate metadata")]
    SymbolManifest {
        /// The underlying stable-symbol manifest error.
        #[from]
        source: RuntimeSymbolNameError,
    },
    /// Some runtime symbols cannot yet become native-target candidates.
    #[error(
        "runtime symbol native-target candidate metadata is incomplete: {missing_count} symbol targets missing"
    )]
    Incomplete {
        /// The number of symbols still missing native-target candidate metadata.
        missing_count: usize,
        /// The full preflight report, including candidate and missing symbols.
        preflight: RuntimeSymbolNativeTargetCandidatePreflight,
    },
}

/// Builds a runtime-symbol report for native target candidate metadata.
///
/// The report consumes [`runtime_symbol_abi_signature_preflight`] and preserves
/// runtime-symbol order. It records address-free helper symbols that already
/// have core ABI metadata and a process-local Rust callable body available, and
/// reports why every other symbol cannot yet become a native-target candidate.
/// It does not export wrappers, attach addresses, return callable/signature
/// handles, or register Cranelift symbols.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest or the
/// builtin call manifest cannot be built.
pub fn runtime_symbol_native_target_candidate_preflight()
-> RuntimeSymbolNativeTargetCandidatePreflightResult {
    let abi_preflight = runtime_symbol_abi_signature_preflight()?;
    let binding_manifest = runtime_symbol_binding_manifest()?;

    Ok(project_native_target_candidate_preflight(
        &binding_manifest,
        &abi_preflight,
    ))
}

fn project_native_target_candidate_preflight(
    binding_manifest: &[RuntimeSymbolBindingManifestEntry],
    abi_preflight: &RuntimeSymbolAbiSignaturePreflight,
) -> RuntimeSymbolNativeTargetCandidatePreflight {
    let signature_bindings = abi_signature_bindings_by_symbol(abi_preflight.signature_bindings());
    let abi_missing_bindings = abi_missing_bindings_by_symbol(abi_preflight.missing_bindings());
    let mut candidate_bindings = Vec::new();
    let mut missing_bindings = Vec::new();

    for entry in binding_manifest {
        if let Some(binding) = signature_bindings.get(entry.symbol_name()) {
            match binding {
                RuntimeSymbolAbiSignatureBinding::Helper(helper) => {
                    debug_assert_eq!(entry.symbol_name(), helper.symbol_name());
                    if helper.rust_callable_binding().is_some() {
                        candidate_bindings
                            .push(RuntimeSymbolNativeTargetCandidateBinding::helper(*helper));
                    } else {
                        missing_bindings.push(
                            RuntimeSymbolNativeTargetCandidateMissingBinding::helper_callable(
                                *helper,
                            ),
                        );
                    }
                }
                RuntimeSymbolAbiSignatureBinding::Builtin(builtin) => {
                    missing_bindings.push(
                        RuntimeSymbolNativeTargetCandidateMissingBinding::builtin_wrapper(
                            (*builtin).clone(),
                        ),
                    );
                }
            }
        } else if let Some(missing) = abi_missing_bindings.get(entry.symbol_name()) {
            missing_bindings.push(
                RuntimeSymbolNativeTargetCandidateMissingBinding::abi_signature((*missing).clone()),
            );
        } else {
            missing_bindings.push(
                RuntimeSymbolNativeTargetCandidateMissingBinding::abi_signature(
                    RuntimeSymbolAbiMissingBinding::from_binding_manifest_entry(entry),
                ),
            );
        }
    }

    RuntimeSymbolNativeTargetCandidatePreflight::new(candidate_bindings, missing_bindings)
}

/// Builds the complete runtime-symbol native-target candidate plan.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNativeTargetCandidatePlanError::SymbolManifest`] if
/// the core runtime symbol manifest or the builtin call manifest cannot be
/// built. Returns [`RuntimeSymbolNativeTargetCandidatePlanError::Incomplete`]
/// while any runtime symbol still lacks native-target candidate metadata.
pub fn runtime_symbol_native_target_candidate_plan() -> RuntimeSymbolNativeTargetCandidatePlanResult
{
    runtime_symbol_native_target_candidate_preflight()?.into_native_target_candidate_plan()
}

/// Result returned when building native-export readiness metadata.
pub type RuntimeSymbolNativeExportPreflightResult =
    Result<RuntimeSymbolNativeExportPreflight, RuntimeSymbolNameError>;

/// Result returned when requiring complete native-export metadata.
pub type RuntimeSymbolNativeExportPlanResult =
    Result<RuntimeSymbolNativeExportPlan, RuntimeSymbolNativeExportPlanError>;

/// A failure while preparing complete native-export metadata.
#[derive(Debug, Error)]
pub enum RuntimeSymbolNativeExportPlanError {
    /// The core runtime symbol or builtin call manifest could not be built.
    #[error("failed to build runtime symbol native-export metadata")]
    SymbolManifest {
        /// The underlying stable-symbol manifest error.
        #[from]
        source: RuntimeSymbolNameError,
    },
    /// Some runtime symbols cannot yet be exported as native ABI targets.
    #[error(
        "runtime symbol native-export metadata is incomplete: {missing_count} symbol exports missing"
    )]
    Incomplete {
        /// The number of symbols still missing native-export metadata.
        missing_count: usize,
        /// The full preflight report, including exported and missing symbols.
        preflight: RuntimeSymbolNativeExportPreflight,
    },
}

/// Builds a runtime-symbol report for exported native ABI readiness.
///
/// The report consumes [`runtime_symbol_native_target_candidate_preflight`],
/// preserves runtime-symbol order, and records why every current native-target
/// candidate still lacks an exported C ABI wrapper. This is the final safe gate
/// before unsafe wrapper work: it does not export functions, attach addresses,
/// register Cranelift symbols, or treat process-local Rust callables as ABI
/// symbols.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest or the
/// builtin call manifest cannot be built.
pub fn runtime_symbol_native_export_preflight() -> RuntimeSymbolNativeExportPreflightResult {
    let binding_manifest = runtime_symbol_binding_manifest()?;
    let target_preflight = runtime_symbol_native_target_candidate_preflight()?;

    Ok(project_native_export_preflight(
        &binding_manifest,
        &target_preflight,
    ))
}

fn project_native_export_preflight(
    binding_manifest: &[RuntimeSymbolBindingManifestEntry],
    target_preflight: &RuntimeSymbolNativeTargetCandidatePreflight,
) -> RuntimeSymbolNativeExportPreflight {
    let target_candidates =
        native_target_candidates_by_symbol(target_preflight.candidate_bindings());
    let target_missing = native_target_missing_by_symbol(target_preflight.missing_bindings());
    let mut missing_bindings = Vec::new();

    for entry in binding_manifest {
        if let Some(candidate) = target_candidates.get(entry.symbol_name()) {
            if let Some(helper_binding) =
                RuntimeHelperBinding::from_symbol_name(candidate.symbol_name())
            {
                missing_bindings.push(
                    RuntimeSymbolNativeExportMissingBinding::exported_c_abi_wrapper(
                        candidate.symbol_name().to_owned(),
                        candidate.helper_role(),
                        helper_binding.failure_convention(),
                        helper_binding.allocation_native_export_blockers(),
                        helper_binding.write_barrier_native_export_blockers(),
                    ),
                );
            } else {
                missing_bindings.push(
                    RuntimeSymbolNativeExportMissingBinding::native_target_candidate(
                        RuntimeSymbolNativeTargetCandidateMissingBinding::abi_signature(
                            RuntimeSymbolAbiMissingBinding::from_binding_manifest_entry(entry),
                        ),
                    ),
                );
            }
        } else if let Some(missing) = target_missing.get(entry.symbol_name()) {
            missing_bindings.push(
                RuntimeSymbolNativeExportMissingBinding::native_target_candidate(
                    (*missing).clone(),
                ),
            );
        } else {
            missing_bindings.push(
                RuntimeSymbolNativeExportMissingBinding::native_target_candidate(
                    RuntimeSymbolNativeTargetCandidateMissingBinding::abi_signature(
                        RuntimeSymbolAbiMissingBinding::from_binding_manifest_entry(entry),
                    ),
                ),
            );
        }
    }

    RuntimeSymbolNativeExportPreflight::new(Vec::new(), missing_bindings)
}

/// Builds the complete runtime-symbol native-export plan.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNativeExportPlanError::SymbolManifest`] if the core
/// runtime symbol manifest or the builtin call manifest cannot be built.
/// Returns [`RuntimeSymbolNativeExportPlanError::Incomplete`] while any runtime
/// symbol still lacks exported native ABI metadata.
pub fn runtime_symbol_native_export_plan() -> RuntimeSymbolNativeExportPlanResult {
    runtime_symbol_native_export_preflight()?.into_native_export_plan()
}

/// Result returned when building runtime-symbol Rust-callable readiness metadata.
pub type RuntimeSymbolRustCallablePreflightResult =
    Result<RuntimeSymbolRustCallablePreflight, RuntimeSymbolNameError>;

/// Builds a runtime-symbol report for callable Rust storage wrappers.
///
/// The report consumes [`runtime_symbol_binding_manifest`], preserves its order,
/// keeps callable helper metadata for currently covered helper families, and
/// records every helper or builtin symbol that still prevents complete runtime
/// symbol registration. The helper callables are process-local Rust function
/// addresses; they are not exported C ABI targets and are not installable as
/// final JIT symbols.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be built.
pub fn runtime_symbol_rust_callable_preflight() -> RuntimeSymbolRustCallablePreflightResult {
    let mut helper_callables = Vec::new();
    let mut missing_bindings = Vec::new();

    for entry in runtime_symbol_binding_manifest()? {
        match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                match binding.rust_callable_binding() {
                    Some(callable) => {
                        debug_assert_eq!(entry.symbol_name(), callable.symbol_name());
                        helper_callables.push(callable);
                    }
                    None => missing_bindings.push(RuntimeSymbolMissingBinding::helper(
                        entry.symbol_name().to_owned(),
                        binding.role(),
                    )),
                }
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

    Ok(RuntimeSymbolRustCallablePreflight::new(
        helper_callables,
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

fn builtin_call_binding_for(
    preflight: &RuntimeBuiltinCallPreflight,
    symbol_name: &str,
) -> Option<RuntimeBuiltinCallBinding> {
    preflight
        .call_bindings()
        .iter()
        .find(|binding| binding.symbol_name() == symbol_name)
        .cloned()
}

fn builtin_call_missing_binding_for(
    preflight: &RuntimeBuiltinCallPreflight,
    symbol_name: &str,
) -> Option<RuntimeBuiltinCallMissingBinding> {
    preflight
        .missing_bindings()
        .iter()
        .find(|missing| missing.symbol_name() == symbol_name)
        .cloned()
}

fn abi_signature_bindings_by_symbol(
    bindings: &[RuntimeSymbolAbiSignatureBinding],
) -> BTreeMap<&str, &RuntimeSymbolAbiSignatureBinding> {
    bindings
        .iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect()
}

fn abi_missing_bindings_by_symbol(
    missing_bindings: &[RuntimeSymbolAbiMissingBinding],
) -> BTreeMap<&str, &RuntimeSymbolAbiMissingBinding> {
    missing_bindings
        .iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect()
}

fn native_target_candidates_by_symbol(
    candidates: &[RuntimeSymbolNativeTargetCandidateBinding],
) -> BTreeMap<&str, &RuntimeSymbolNativeTargetCandidateBinding> {
    candidates
        .iter()
        .map(|candidate| (candidate.symbol_name(), candidate))
        .collect()
}

fn native_target_missing_by_symbol(
    missing_bindings: &[RuntimeSymbolNativeTargetCandidateMissingBinding],
) -> BTreeMap<&str, &RuntimeSymbolNativeTargetCandidateMissingBinding> {
    missing_bindings
        .iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect()
}

/// A callable Rust storage-wrapper binding for one runtime helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperRustCallableBinding {
    /// An allocation helper backed by `runtime::alloc` storage-wrapper dispatch.
    Allocation(RuntimeAllocationRustCallableBinding),
    /// An environment-access helper backed by `runtime::env` storage-wrapper dispatch.
    EnvironmentAccess(RuntimeEnvAccessRustCallableBinding),
    /// A write-barrier helper backed by `runtime::barrier` storage-wrapper dispatch.
    WriteBarrier(RuntimeWriteBarrierRustCallableBinding),
}

impl RuntimeHelperRustCallableBinding {
    /// Returns the stable helper symbol name served by this callable binding.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::Allocation(binding) => binding.symbol_name(),
            Self::EnvironmentAccess(binding) => binding.symbol_name(),
            Self::WriteBarrier(binding) => binding.symbol_name(),
        }
    }

    /// Returns the core helper role served by this callable binding.
    pub const fn role(self) -> RuntimeHelperRole {
        match self {
            Self::Allocation(_) => RuntimeHelperRole::Allocation,
            Self::EnvironmentAccess(_) => RuntimeHelperRole::EnvironmentAccess,
            Self::WriteBarrier(_) => RuntimeHelperRole::WriteBarrier,
        }
    }

    /// Returns the safe helper binding metadata associated with this callable.
    pub const fn helper_binding(self) -> RuntimeHelperBinding {
        match self {
            Self::Allocation(binding) => {
                RuntimeHelperBinding::Allocation(binding.entrypoint().abi_signature())
            }
            Self::EnvironmentAccess(binding) => {
                RuntimeHelperBinding::EnvironmentAccess(binding.entrypoint().abi_signature())
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
            Self::EnvironmentAccess(_) | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the environment-access callable when this binding serves environment access.
    pub const fn env_access_callable(self) -> Option<RuntimeEnvAccessRustCallableBinding> {
        match self {
            Self::EnvironmentAccess(binding) => Some(binding),
            Self::Allocation(_) | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the write-barrier callable when this binding serves a barrier.
    pub const fn write_barrier_callable(self) -> Option<RuntimeWriteBarrierRustCallableBinding> {
        match self {
            Self::Allocation(_) | Self::EnvironmentAccess(_) => None,
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

/// ABI-signature metadata for one runtime symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolAbiSignatureBinding {
    /// A helper symbol backed by safe helper metadata and a core call signature.
    Helper(RuntimeHelperBinding),
    /// A builtin symbol backed by frozen primop call-signature metadata.
    Builtin(RuntimeBuiltinCallBinding),
}

impl RuntimeSymbolAbiSignatureBinding {
    /// Returns the stable runtime symbol name served by this binding.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::Helper(binding) => binding.symbol_name(),
            Self::Builtin(binding) => binding.symbol_name(),
        }
    }

    /// Returns helper metadata when this binding serves a helper symbol.
    pub const fn helper_binding(&self) -> Option<RuntimeHelperBinding> {
        match self {
            Self::Helper(binding) => Some(*binding),
            Self::Builtin(_) => None,
        }
    }

    /// Returns builtin call metadata when this binding serves a builtin symbol.
    pub const fn builtin_call_binding(&self) -> Option<&RuntimeBuiltinCallBinding> {
        match self {
            Self::Helper(_) => None,
            Self::Builtin(binding) => Some(binding),
        }
    }

    /// Returns the core runtime-call signature represented by this binding.
    pub fn core_call_signature(&self) -> Option<RuntimeCallSignature> {
        match self {
            Self::Helper(binding) => binding.core_call_signature(),
            Self::Builtin(binding) => Some(binding.signature()),
        }
    }
}

/// One runtime symbol that still lacks ABI-signature registration metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolAbiMissingBinding {
    /// A helper symbol has no complete ABI-signature metadata yet.
    Helper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The helper role reserved by the core runtime ABI.
        role: RuntimeHelperRole,
    },
    /// A builtin symbol is not currently a callable runtime wrapper.
    Builtin(RuntimeBuiltinCallMissingBinding),
    /// A builtin symbol was not classified by the builtin call manifest.
    UnclassifiedBuiltin {
        /// The stable runtime symbol name.
        symbol_name: String,
    },
}

impl RuntimeSymbolAbiMissingBinding {
    fn helper(symbol_name: String, role: RuntimeHelperRole) -> Self {
        Self::Helper { symbol_name, role }
    }

    fn builtin_unclassified(symbol_name: String) -> Self {
        Self::UnclassifiedBuiltin { symbol_name }
    }

    fn from_binding_manifest_entry(entry: &RuntimeSymbolBindingManifestEntry) -> Self {
        match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                Self::helper(entry.symbol_name().to_owned(), binding.role())
            }
            RuntimeSymbolBindingStatus::UnboundHelper(role) => {
                Self::helper(entry.symbol_name().to_owned(), role)
            }
            RuntimeSymbolBindingStatus::Builtin => {
                Self::builtin_unclassified(entry.symbol_name().to_owned())
            }
        }
    }

    /// Returns the stable runtime symbol name that is not yet bindable.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::Helper { symbol_name, .. } | Self::UnclassifiedBuiltin { symbol_name } => {
                symbol_name
            }
            Self::Builtin(binding) => binding.symbol_name(),
        }
    }

    /// Returns the helper role when the missing binding is a helper symbol.
    pub const fn helper_role(&self) -> Option<RuntimeHelperRole> {
        match self {
            Self::Helper { role, .. } => Some(*role),
            Self::Builtin(_) | Self::UnclassifiedBuiltin { .. } => None,
        }
    }

    /// Returns builtin missing-binding metadata when this gap is a builtin.
    pub const fn builtin_missing_binding(&self) -> Option<&RuntimeBuiltinCallMissingBinding> {
        match self {
            Self::Builtin(binding) => Some(binding),
            Self::Helper { .. } | Self::UnclassifiedBuiltin { .. } => None,
        }
    }
}

/// The complete set of runtime-symbol ABI signatures required before native binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolAbiSignaturePlan {
    signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>,
}

impl RuntimeSymbolAbiSignaturePlan {
    fn new(signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>) -> Self {
        Self { signature_bindings }
    }

    /// Returns ABI-signature metadata in runtime symbol-manifest projection order.
    pub fn signature_bindings(&self) -> &[RuntimeSymbolAbiSignatureBinding] {
        &self.signature_bindings
    }
}

/// A deterministic runtime-symbol report for ABI-signature metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolAbiSignaturePreflight {
    signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>,
    missing_bindings: Vec<RuntimeSymbolAbiMissingBinding>,
}

impl RuntimeSymbolAbiSignaturePreflight {
    fn new(
        signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>,
        missing_bindings: Vec<RuntimeSymbolAbiMissingBinding>,
    ) -> Self {
        Self {
            signature_bindings,
            missing_bindings,
        }
    }

    /// Returns ABI-signature metadata in runtime symbol-manifest projection order.
    pub fn signature_bindings(&self) -> &[RuntimeSymbolAbiSignatureBinding] {
        &self.signature_bindings
    }

    /// Returns runtime symbols that still lack complete ABI-signature metadata.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolAbiMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has ABI-signature metadata.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Converts a complete preflight report into ABI-signature metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolAbiSignaturePlanError::Incomplete`] when any
    /// runtime symbol still lacks ABI-signature metadata.
    pub fn into_abi_signature_plan(
        self,
    ) -> Result<RuntimeSymbolAbiSignaturePlan, RuntimeSymbolAbiSignaturePlanError> {
        let missing_count = self.missing_bindings.len();
        if missing_count == 0 {
            Ok(RuntimeSymbolAbiSignaturePlan::new(self.signature_bindings))
        } else {
            Err(RuntimeSymbolAbiSignaturePlanError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

/// An address-free helper runtime symbol ready for future wrapper generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeTargetCandidateBinding {
    symbol_name: String,
    role: RuntimeHelperRole,
}

impl RuntimeSymbolNativeTargetCandidateBinding {
    fn helper(helper_binding: RuntimeHelperBinding) -> Self {
        debug_assert!(helper_binding.rust_callable_binding().is_some());
        Self {
            symbol_name: helper_binding.symbol_name().to_owned(),
            role: helper_binding.role(),
        }
    }

    /// Returns the stable runtime symbol name served by this target candidate.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the helper role covered by this native-target candidate.
    pub const fn helper_role(&self) -> RuntimeHelperRole {
        self.role
    }
}

/// One runtime symbol that cannot yet become a native-target candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolNativeTargetCandidateMissingBinding {
    /// The symbol still lacks ABI-signature metadata.
    MissingAbiSignature(RuntimeSymbolAbiMissingBinding),
    /// A helper has ABI metadata but lacks a process-local Rust callable body.
    MissingHelperCallable {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The helper role reserved by the core runtime ABI.
        role: RuntimeHelperRole,
    },
    /// A callable builtin has ABI metadata but no native wrapper body yet.
    MissingBuiltinWrapper(RuntimeBuiltinCallBinding),
}

impl RuntimeSymbolNativeTargetCandidateMissingBinding {
    fn abi_signature(binding: RuntimeSymbolAbiMissingBinding) -> Self {
        Self::MissingAbiSignature(binding)
    }

    fn helper_callable(binding: RuntimeHelperBinding) -> Self {
        Self::MissingHelperCallable {
            symbol_name: binding.symbol_name().to_owned(),
            role: binding.role(),
        }
    }

    fn builtin_wrapper(binding: RuntimeBuiltinCallBinding) -> Self {
        Self::MissingBuiltinWrapper(binding)
    }

    /// Returns the stable runtime symbol name that is not yet candidate-ready.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::MissingAbiSignature(binding) => binding.symbol_name(),
            Self::MissingHelperCallable { symbol_name, .. } => symbol_name,
            Self::MissingBuiltinWrapper(binding) => binding.symbol_name(),
        }
    }

    /// Returns the ABI-signature gap when candidate readiness is blocked earlier.
    pub const fn missing_abi_signature(&self) -> Option<&RuntimeSymbolAbiMissingBinding> {
        match self {
            Self::MissingAbiSignature(binding) => Some(binding),
            Self::MissingHelperCallable { .. } | Self::MissingBuiltinWrapper(_) => None,
        }
    }

    /// Returns the helper role when a helper lacks a Rust callable body.
    pub const fn missing_helper_callable_role(&self) -> Option<RuntimeHelperRole> {
        match self {
            Self::MissingHelperCallable { role, .. } => Some(*role),
            Self::MissingAbiSignature(_) | Self::MissingBuiltinWrapper(_) => None,
        }
    }

    /// Returns builtin call metadata when a callable builtin lacks a wrapper.
    pub const fn missing_builtin_wrapper(&self) -> Option<&RuntimeBuiltinCallBinding> {
        match self {
            Self::MissingBuiltinWrapper(binding) => Some(binding),
            Self::MissingAbiSignature(_) | Self::MissingHelperCallable { .. } => None,
        }
    }
}

/// The complete set of address-free native-target candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeTargetCandidatePlan {
    candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>,
}

impl RuntimeSymbolNativeTargetCandidatePlan {
    fn new(candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>) -> Self {
        Self { candidate_bindings }
    }

    /// Returns native-target candidates in runtime symbol-manifest projection order.
    pub fn candidate_bindings(&self) -> &[RuntimeSymbolNativeTargetCandidateBinding] {
        &self.candidate_bindings
    }
}

/// A deterministic runtime-symbol report for native target candidate metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeTargetCandidatePreflight {
    candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>,
    missing_bindings: Vec<RuntimeSymbolNativeTargetCandidateMissingBinding>,
}

impl RuntimeSymbolNativeTargetCandidatePreflight {
    fn new(
        candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>,
        missing_bindings: Vec<RuntimeSymbolNativeTargetCandidateMissingBinding>,
    ) -> Self {
        Self {
            candidate_bindings,
            missing_bindings,
        }
    }

    /// Returns helper target candidates in runtime symbol-manifest projection order.
    pub fn candidate_bindings(&self) -> &[RuntimeSymbolNativeTargetCandidateBinding] {
        &self.candidate_bindings
    }

    /// Returns runtime symbols that still lack native-target candidate readiness.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolNativeTargetCandidateMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has native-target candidate metadata.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Converts a complete preflight report into native-target candidate metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolNativeTargetCandidatePlanError::Incomplete`] when
    /// any runtime symbol still lacks native-target candidate metadata.
    pub fn into_native_target_candidate_plan(
        self,
    ) -> Result<RuntimeSymbolNativeTargetCandidatePlan, RuntimeSymbolNativeTargetCandidatePlanError>
    {
        let missing_count = self.missing_bindings.len();
        if missing_count == 0 {
            Ok(RuntimeSymbolNativeTargetCandidatePlan::new(
                self.candidate_bindings,
            ))
        } else {
            Err(RuntimeSymbolNativeTargetCandidatePlanError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

/// A runtime symbol with native-export readiness metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeExportBinding {
    symbol_name: String,
    role: RuntimeHelperRole,
    failure_convention: RuntimeHelperFailureConvention,
}

impl RuntimeSymbolNativeExportBinding {
    #[cfg(test)]
    fn new(
        symbol_name: String,
        role: RuntimeHelperRole,
        failure_convention: RuntimeHelperFailureConvention,
    ) -> Self {
        Self {
            symbol_name,
            role,
            failure_convention,
        }
    }

    /// Returns the stable runtime symbol name served by this metadata record.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the helper role covered by this metadata record.
    pub const fn helper_role(&self) -> RuntimeHelperRole {
        self.role
    }

    /// Returns the failure convention required by this metadata record.
    pub const fn failure_convention(&self) -> RuntimeHelperFailureConvention {
        self.failure_convention
    }
}

/// One runtime symbol that cannot yet be exported as a native ABI target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolNativeExportMissingBinding {
    /// The symbol is blocked before native-target candidate readiness.
    MissingNativeTargetCandidate(RuntimeSymbolNativeTargetCandidateMissingBinding),
    /// A helper candidate still lacks an exported C ABI wrapper.
    MissingExportedCAbiWrapper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The helper role reserved by the core runtime ABI.
        role: RuntimeHelperRole,
        /// The native failure convention the wrapper must implement.
        failure_convention: RuntimeHelperFailureConvention,
        /// Allocation-specific blockers when this wrapper serves `aos_alloc_*`.
        allocation_blockers: &'static [RuntimeAllocationNativeExportBlocker],
        /// Write-barrier-specific blockers when this wrapper serves `aos_gc_write_barrier`.
        write_barrier_blockers: &'static [RuntimeWriteBarrierNativeExportBlocker],
    },
}

impl RuntimeSymbolNativeExportMissingBinding {
    fn native_target_candidate(binding: RuntimeSymbolNativeTargetCandidateMissingBinding) -> Self {
        Self::MissingNativeTargetCandidate(binding)
    }

    fn exported_c_abi_wrapper(
        symbol_name: String,
        role: RuntimeHelperRole,
        failure_convention: RuntimeHelperFailureConvention,
        allocation_blockers: &'static [RuntimeAllocationNativeExportBlocker],
        write_barrier_blockers: &'static [RuntimeWriteBarrierNativeExportBlocker],
    ) -> Self {
        Self::MissingExportedCAbiWrapper {
            symbol_name,
            role,
            failure_convention,
            allocation_blockers,
            write_barrier_blockers,
        }
    }

    /// Returns the stable runtime symbol name that is not yet export-ready.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::MissingNativeTargetCandidate(binding) => binding.symbol_name(),
            Self::MissingExportedCAbiWrapper { symbol_name, .. } => symbol_name,
        }
    }

    /// Returns the earlier native-target candidate gap, when present.
    pub const fn missing_native_target_candidate(
        &self,
    ) -> Option<&RuntimeSymbolNativeTargetCandidateMissingBinding> {
        match self {
            Self::MissingNativeTargetCandidate(binding) => Some(binding),
            Self::MissingExportedCAbiWrapper { .. } => None,
        }
    }

    /// Returns the helper role when the missing piece is an exported C ABI wrapper.
    pub const fn missing_exported_c_abi_wrapper_role(&self) -> Option<RuntimeHelperRole> {
        match self {
            Self::MissingExportedCAbiWrapper { role, .. } => Some(*role),
            Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns the failure convention required by the missing C ABI wrapper.
    pub const fn missing_exported_c_abi_failure_convention(
        &self,
    ) -> Option<RuntimeHelperFailureConvention> {
        match self {
            Self::MissingExportedCAbiWrapper {
                failure_convention, ..
            } => Some(*failure_convention),
            Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns allocation-specific blockers for a missing `aos_alloc_*` C ABI wrapper.
    pub fn missing_exported_allocation_blockers(
        &self,
    ) -> Option<&'static [RuntimeAllocationNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                allocation_blockers,
                ..
            } if !allocation_blockers.is_empty() => Some(*allocation_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns write-barrier-specific blockers for a missing `aos_gc_write_barrier` wrapper.
    pub fn missing_exported_write_barrier_blockers(
        &self,
    ) -> Option<&'static [RuntimeWriteBarrierNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                write_barrier_blockers,
                ..
            } if !write_barrier_blockers.is_empty() => Some(*write_barrier_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }
}

/// The complete set of runtime-symbol native-export metadata records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeExportPlan {
    export_bindings: Vec<RuntimeSymbolNativeExportBinding>,
}

impl RuntimeSymbolNativeExportPlan {
    fn new(export_bindings: Vec<RuntimeSymbolNativeExportBinding>) -> Self {
        Self { export_bindings }
    }

    /// Returns native-export metadata records in runtime symbol-manifest order.
    pub fn export_bindings(&self) -> &[RuntimeSymbolNativeExportBinding] {
        &self.export_bindings
    }
}

/// A deterministic runtime-symbol report for exported native ABI readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeExportPreflight {
    export_bindings: Vec<RuntimeSymbolNativeExportBinding>,
    missing_bindings: Vec<RuntimeSymbolNativeExportMissingBinding>,
}

impl RuntimeSymbolNativeExportPreflight {
    fn new(
        export_bindings: Vec<RuntimeSymbolNativeExportBinding>,
        missing_bindings: Vec<RuntimeSymbolNativeExportMissingBinding>,
    ) -> Self {
        Self {
            export_bindings,
            missing_bindings,
        }
    }

    /// Returns native-export metadata records in runtime symbol-manifest order.
    pub fn export_bindings(&self) -> &[RuntimeSymbolNativeExportBinding] {
        &self.export_bindings
    }

    /// Returns runtime symbols that still lack native-export readiness.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolNativeExportMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has exported native ABI metadata.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Converts a complete preflight report into native-export metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolNativeExportPlanError::Incomplete`] when any
    /// runtime symbol still lacks exported native ABI metadata.
    pub fn into_native_export_plan(
        self,
    ) -> Result<RuntimeSymbolNativeExportPlan, RuntimeSymbolNativeExportPlanError> {
        let missing_count = self.missing_bindings.len();
        if missing_count == 0 {
            Ok(RuntimeSymbolNativeExportPlan::new(self.export_bindings))
        } else {
            Err(RuntimeSymbolNativeExportPlanError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

/// A deterministic runtime-symbol report for callable Rust storage wrappers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolRustCallablePreflight {
    helper_callables: Vec<RuntimeHelperRustCallableBinding>,
    missing_bindings: Vec<RuntimeSymbolMissingBinding>,
}

impl RuntimeSymbolRustCallablePreflight {
    fn new(
        helper_callables: Vec<RuntimeHelperRustCallableBinding>,
        missing_bindings: Vec<RuntimeSymbolMissingBinding>,
    ) -> Self {
        Self {
            helper_callables,
            missing_bindings,
        }
    }

    /// Returns callable helper metadata in runtime symbol-manifest order.
    pub fn helper_callables(&self) -> &[RuntimeHelperRustCallableBinding] {
        &self.helper_callables
    }

    /// Returns runtime symbols that still lack a complete registration binding.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has a callable registration binding.
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
    /// An environment-access helper routed through `runtime::env`.
    EnvironmentAccess(RuntimeEnvAccessAbiSignature),
    /// A write-barrier helper routed through `runtime::barrier`.
    WriteBarrier(RuntimeWriteBarrierAbiSignature),
}

impl RuntimeHelperBinding {
    /// Returns the stable helper symbol name.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::Allocation(signature) => signature.symbol_name(),
            Self::EnvironmentAccess(signature) => signature.symbol_name(),
            Self::WriteBarrier(signature) => signature.symbol_name(),
        }
    }

    /// Returns the core helper role served by this binding.
    pub const fn role(self) -> RuntimeHelperRole {
        match self {
            Self::Allocation(_) => RuntimeHelperRole::Allocation,
            Self::EnvironmentAccess(_) => RuntimeHelperRole::EnvironmentAccess,
            Self::WriteBarrier(_) => RuntimeHelperRole::WriteBarrier,
        }
    }

    /// Returns the native failure convention for this helper binding.
    pub const fn failure_convention(self) -> RuntimeHelperFailureConvention {
        match self {
            Self::Allocation(_) | Self::EnvironmentAccess(_) | Self::WriteBarrier(_) => {
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
            Self::EnvironmentAccess(signature) => {
                Some(RuntimeHelperRustCallableBinding::EnvironmentAccess(
                    signature.entrypoint().rust_callable_binding(),
                ))
            }
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
                RuntimeEnvAccessAbiSignature::from_symbol_name(symbol_name)
                    .map(Self::EnvironmentAccess)
            })
            .or_else(|| {
                RuntimeWriteBarrierAbiSignature::from_symbol_name(symbol_name)
                    .map(Self::WriteBarrier)
            })
    }

    /// Returns the allocation ABI signature when this binding serves allocation.
    pub const fn allocation_signature(self) -> Option<RuntimeAllocationAbiSignature> {
        match self {
            Self::Allocation(signature) => Some(signature),
            Self::EnvironmentAccess(_) | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns allocation-native-export blockers for allocation helpers.
    pub const fn allocation_native_export_blockers(
        self,
    ) -> &'static [RuntimeAllocationNativeExportBlocker] {
        match self {
            Self::Allocation(signature) => signature.entrypoint().native_export_blockers(),
            Self::EnvironmentAccess(_) | Self::WriteBarrier(_) => &[],
        }
    }

    /// Returns the environment-access ABI signature when this binding serves environment access.
    pub const fn env_access_signature(self) -> Option<RuntimeEnvAccessAbiSignature> {
        match self {
            Self::EnvironmentAccess(signature) => Some(signature),
            Self::Allocation(_) | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the write-barrier ABI signature when this binding serves a barrier.
    pub const fn write_barrier_signature(self) -> Option<RuntimeWriteBarrierAbiSignature> {
        match self {
            Self::Allocation(_) | Self::EnvironmentAccess(_) => None,
            Self::WriteBarrier(signature) => Some(signature),
        }
    }

    /// Returns write-barrier-native-export blockers for write-barrier helpers.
    pub const fn write_barrier_native_export_blockers(
        self,
    ) -> &'static [RuntimeWriteBarrierNativeExportBlocker] {
        match self {
            Self::Allocation(_) | Self::EnvironmentAccess(_) => &[],
            Self::WriteBarrier(signature) => signature.entrypoint().native_export_blockers(),
        }
    }

    /// Returns the core runtime-call signature for this helper binding.
    pub fn core_call_signature(self) -> Option<RuntimeCallSignature> {
        runtime_helper_call_signature(self.symbol_name())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compile::{
        RuntimeBuiltinCallPreflight, RuntimeCallableKind, RuntimeHelperRole,
        runtime_builtin_call_preflight, runtime_helper_call_signatures, runtime_helper_symbols,
        runtime_symbol_manifest,
    };

    use super::*;
    use crate::runtime::alloc::{
        RuntimeAllocationNativeExportBlocker, runtime_allocation_abi_signatures,
        runtime_allocation_native_export_preflight, runtime_allocation_rust_callable_bindings,
    };
    use crate::runtime::barrier::{
        RuntimeWriteBarrierNativeExportBlocker, runtime_write_barrier_abi_signatures,
        runtime_write_barrier_native_export_preflight,
        runtime_write_barrier_rust_callable_bindings,
    };
    use crate::runtime::env::{
        runtime_env_access_abi_signatures, runtime_env_access_rust_callable_bindings,
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
                        missing_bindings.push(
                            RuntimeSymbolAbiMissingBinding::UnclassifiedBuiltin {
                                symbol_name: entry.symbol_name().to_owned(),
                            },
                        );
                    }
                }
            }
        }

        (signature_bindings, missing_bindings)
    }

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
                    RuntimeHelperRole::Allocation
                        | RuntimeHelperRole::EnvironmentAccess
                        | RuntimeHelperRole::WriteBarrier
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
        let env_access_signatures = runtime_helper_bindings()
            .iter()
            .copied()
            .filter_map(RuntimeHelperBinding::env_access_signature)
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
            env_access_signatures.as_slice(),
            runtime_env_access_abi_signatures()
        );
        assert_eq!(
            write_barrier_signatures.as_slice(),
            runtime_write_barrier_abi_signatures()
        );
    }

    #[test]
    fn runtime_helper_bindings_have_core_runtime_call_signatures() {
        let helper_core_signatures = runtime_helper_bindings()
            .iter()
            .copied()
            .map(|binding| {
                (
                    binding.symbol_name(),
                    binding
                        .core_call_signature()
                        .expect("bound helper has a core runtime call signature"),
                )
            })
            .collect::<Vec<_>>();
        let core_signatures = runtime_helper_call_signatures()
            .iter()
            .copied()
            .map(|signature| {
                let RuntimeCallableKind::Helper { symbol } = signature.callable() else {
                    panic!("helper call signature must carry helper callable metadata");
                };
                (symbol.name(), signature)
            })
            .collect::<Vec<_>>();

        for binding in helper_core_signatures {
            assert!(
                core_signatures.contains(&binding),
                "{} bound helper has matching core runtime-call metadata",
                binding.0
            );
        }
        assert_eq!(
            RuntimeHelperBinding::from_symbol_name("aos_env_get")
                .and_then(RuntimeHelperBinding::core_call_signature)
                .map(|signature| {
                    let RuntimeCallableKind::Helper { symbol } = signature.callable() else {
                        panic!("helper call signature must carry helper callable metadata");
                    };
                    (symbol.name(), signature)
                }),
            core_signatures
                .iter()
                .copied()
                .find(|(symbol_name, _)| *symbol_name == "aos_env_get")
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
                    "aos_env_get",
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
            runtime_env_access_rust_callable_bindings()
                .into_iter()
                .map(RuntimeHelperRustCallableBinding::EnvironmentAccess),
        );
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
                    assert!(callable.env_access_callable().is_none());
                    assert!(callable.write_barrier_callable().is_none());
                }
                RuntimeHelperRole::EnvironmentAccess => {
                    assert!(callable.allocation_callable().is_none());
                    assert!(callable.env_access_callable().is_some());
                    assert!(callable.write_barrier_callable().is_none());
                }
                RuntimeHelperRole::WriteBarrier => {
                    assert!(callable.allocation_callable().is_none());
                    assert!(callable.env_access_callable().is_none());
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
                RuntimeHelperRole::Allocation
                    | RuntimeHelperRole::EnvironmentAccess
                    | RuntimeHelperRole::WriteBarrier
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

        assert!(matches!(
            manifest
                .iter()
                .find(|entry| entry.symbol_name() == "aos_env_get")
                .map(RuntimeSymbolBindingManifestEntry::status),
            Some(RuntimeSymbolBindingStatus::BoundHelper(binding))
                if binding.role() == RuntimeHelperRole::EnvironmentAccess
        ));
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
    fn runtime_symbol_abi_signature_preflight_combines_helpers_and_builtins() {
        let signature_preflight =
            runtime_symbol_abi_signature_preflight().expect("signature preflight builds");
        let registration_preflight =
            runtime_symbol_registration_preflight().expect("registration preflight builds");
        let builtin_preflight =
            runtime_builtin_call_preflight().expect("builtin call preflight builds");
        let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
        let (expected_signature_bindings, expected_missing_bindings) =
            expected_runtime_symbol_abi_signature_projection(&binding_manifest, &builtin_preflight);
        let helper_symbols = signature_preflight
            .signature_bindings()
            .iter()
            .filter_map(RuntimeSymbolAbiSignatureBinding::helper_binding)
            .map(RuntimeHelperBinding::symbol_name)
            .collect::<Vec<_>>();
        let builtin_symbols = signature_preflight
            .signature_bindings()
            .iter()
            .filter_map(RuntimeSymbolAbiSignatureBinding::builtin_call_binding)
            .map(|binding| binding.symbol_name())
            .collect::<Vec<_>>();

        assert!(!signature_preflight.is_complete());
        assert_eq!(
            signature_preflight.signature_bindings().len()
                + signature_preflight.missing_bindings().len(),
            binding_manifest.len()
        );
        assert_eq!(
            helper_symbols,
            registration_preflight
                .helper_bindings()
                .iter()
                .copied()
                .map(RuntimeHelperBinding::symbol_name)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            signature_preflight.signature_bindings(),
            expected_signature_bindings.as_slice()
        );
        for binding in signature_preflight.signature_bindings() {
            assert!(
                binding.core_call_signature().is_some(),
                "{} has core runtime-call metadata",
                binding.symbol_name()
            );
        }
        assert_eq!(
            signature_preflight.missing_bindings(),
            expected_missing_bindings.as_slice()
        );
        assert_eq!(
            builtin_symbols,
            builtin_preflight
                .call_bindings()
                .iter()
                .map(|binding| binding.symbol_name())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn runtime_symbol_abi_signature_preflight_reports_current_gaps() {
        let signature_preflight =
            runtime_symbol_abi_signature_preflight().expect("signature preflight builds");

        assert!(
            signature_preflight
                .signature_bindings()
                .iter()
                .any(|binding| {
                    binding.helper_binding().is_some_and(|helper| {
                        helper.symbol_name() == "aos_env_get"
                            && helper.role() == RuntimeHelperRole::EnvironmentAccess
                    })
                })
        );
        assert!(
            signature_preflight
                .signature_bindings()
                .iter()
                .any(|binding| {
                    binding.builtin_call_binding().is_some_and(|builtin| {
                        builtin.symbol_name() == "nix.builtin.derivationStrict"
                            && builtin.arity() == 1
                    })
                })
        );
        assert!(
            signature_preflight
                .missing_bindings()
                .iter()
                .any(|missing| {
                    missing.symbol_name() == "aos_force"
                        && missing.helper_role() == Some(RuntimeHelperRole::ForcingControl)
                })
        );
        assert!(
            signature_preflight
                .missing_bindings()
                .iter()
                .any(|missing| {
                    missing.symbol_name() == "nix.builtin.true"
                        && missing.builtin_missing_binding().is_some_and(|builtin| {
                            builtin.symbol_name() == "nix.builtin.true"
                                && builtin.builtin_name() == b"true"
                                && builtin.unsupported_arity().is_none()
                        })
                })
        );
        assert!(
            signature_preflight
                .missing_bindings()
                .iter()
                .all(|missing| missing.symbol_name() != "nix.builtin.derivationStrict")
        );
    }

    #[test]
    fn runtime_symbol_abi_signature_preflight_converts_complete_report_to_plan() {
        let helper_binding = runtime_helper_bindings()
            .first()
            .copied()
            .expect("runtime helper inventory has at least one binding");
        let signature_bindings = vec![RuntimeSymbolAbiSignatureBinding::Helper(helper_binding)];
        let preflight =
            RuntimeSymbolAbiSignaturePreflight::new(signature_bindings.clone(), Vec::new());

        let plan = preflight
            .into_abi_signature_plan()
            .expect("complete ABI-signature preflight converts");

        assert_eq!(plan.signature_bindings(), signature_bindings.as_slice());
    }

    #[test]
    fn runtime_symbol_abi_signature_plan_rejects_until_all_symbols_have_metadata() {
        let error = runtime_symbol_abi_signature_plan()
            .expect_err("current ABI-signature plan rejects incomplete metadata");
        let RuntimeSymbolAbiSignaturePlanError::Incomplete {
            missing_count,
            preflight,
        } = error
        else {
            panic!("expected incomplete ABI-signature plan error");
        };

        assert_eq!(missing_count, preflight.missing_bindings().len());
        assert!(!preflight.is_complete());
        assert!(preflight.signature_bindings().iter().any(|binding| {
            binding.builtin_call_binding().is_some_and(|builtin| {
                builtin.symbol_name() == "nix.builtin.derivationStrict" && builtin.arity() == 1
            })
        }));
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "aos_force"
                && missing.helper_role() == Some(RuntimeHelperRole::ForcingControl)
        }));
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "nix.builtin.true"
                && missing
                    .builtin_missing_binding()
                    .is_some_and(|builtin| builtin.builtin_name() == b"true")
        }));
    }

    #[test]
    fn runtime_symbol_native_target_candidate_preflight_projects_helper_candidates_and_gaps() {
        let candidate_preflight = runtime_symbol_native_target_candidate_preflight()
            .expect("native target candidate preflight builds");
        let abi_preflight =
            runtime_symbol_abi_signature_preflight().expect("ABI-signature preflight builds");
        let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
        let abi_candidate_symbols = abi_preflight
            .signature_bindings()
            .iter()
            .filter_map(RuntimeSymbolAbiSignatureBinding::helper_binding)
            .filter(|binding| binding.rust_callable_binding().is_some())
            .map(|binding| binding.symbol_name())
            .collect::<BTreeSet<_>>();
        let expected_candidate_symbols = binding_manifest
            .iter()
            .map(RuntimeSymbolBindingManifestEntry::symbol_name)
            .filter(|symbol| abi_candidate_symbols.contains(symbol))
            .collect::<Vec<_>>();
        let expected_missing_symbols = binding_manifest
            .iter()
            .map(RuntimeSymbolBindingManifestEntry::symbol_name)
            .filter(|symbol| !abi_candidate_symbols.contains(symbol))
            .collect::<Vec<_>>();
        let candidate_symbols = candidate_preflight
            .candidate_bindings()
            .iter()
            .map(RuntimeSymbolNativeTargetCandidateBinding::symbol_name)
            .collect::<Vec<_>>();
        let missing_symbols = candidate_preflight
            .missing_bindings()
            .iter()
            .map(RuntimeSymbolNativeTargetCandidateMissingBinding::symbol_name)
            .collect::<Vec<_>>();

        assert!(!candidate_preflight.is_complete());
        assert_eq!(
            candidate_preflight.candidate_bindings().len()
                + candidate_preflight.missing_bindings().len(),
            binding_manifest.len()
        );
        assert_eq!(candidate_symbols, expected_candidate_symbols);
        assert_eq!(missing_symbols, expected_missing_symbols);

        for target in candidate_preflight.candidate_bindings() {
            match target.helper_role() {
                RuntimeHelperRole::Allocation => {
                    assert!(target.symbol_name().starts_with("aos_alloc_"))
                }
                RuntimeHelperRole::EnvironmentAccess => {
                    assert_eq!(target.symbol_name(), "aos_env_get")
                }
                RuntimeHelperRole::WriteBarrier => {
                    assert_eq!(target.symbol_name(), "aos_gc_write_barrier")
                }
                role => panic!("unexpected native-target candidate helper role: {role:?}"),
            }
        }
    }

    #[test]
    fn runtime_symbol_native_target_candidate_projection_requires_abi_signature_metadata() {
        let helper_binding = runtime_helper_bindings()
            .iter()
            .copied()
            .find(|binding| binding.rust_callable_binding().is_some())
            .expect("runtime helper inventory has at least one callable binding");
        let target_symbol = helper_binding.symbol_name().to_owned();
        let target_role = helper_binding.role();
        let abi_preflight =
            runtime_symbol_abi_signature_preflight().expect("ABI-signature preflight builds");
        let mut signature_bindings = abi_preflight.signature_bindings().to_vec();
        let target_index = signature_bindings
            .iter()
            .position(|binding| binding.symbol_name() == target_symbol)
            .expect("callable helper has ABI-signature metadata");
        let removed_binding = signature_bindings.remove(target_index);
        let RuntimeSymbolAbiSignatureBinding::Helper(_) = removed_binding else {
            panic!("removed callable helper ABI binding must be helper metadata");
        };
        let mut missing_bindings = abi_preflight.missing_bindings().to_vec();
        missing_bindings.push(RuntimeSymbolAbiMissingBinding::helper(
            target_symbol.clone(),
            target_role,
        ));
        let synthetic_abi_preflight =
            RuntimeSymbolAbiSignaturePreflight::new(signature_bindings, missing_bindings);
        let binding_manifest = runtime_symbol_binding_manifest().expect("binding manifest builds");
        let candidate_preflight =
            project_native_target_candidate_preflight(&binding_manifest, &synthetic_abi_preflight);
        let target_gap = candidate_preflight
            .missing_bindings()
            .iter()
            .find(|missing| missing.symbol_name() == target_symbol)
            .expect("callable helper without ABI metadata remains a candidate gap");

        assert!(
            candidate_preflight
                .candidate_bindings()
                .iter()
                .all(|candidate| candidate.symbol_name() != target_symbol)
        );
        assert_eq!(target_gap.missing_helper_callable_role(), None);
        assert!(target_gap.missing_abi_signature().is_some_and(|gap| {
            gap.symbol_name() == target_symbol && gap.helper_role() == Some(target_role)
        }));
    }

    #[test]
    fn runtime_symbol_native_target_candidate_preflight_reports_current_wrapper_gaps() {
        let candidate_preflight = runtime_symbol_native_target_candidate_preflight()
            .expect("native target candidate preflight builds");
        let builtin_preflight =
            runtime_builtin_call_preflight().expect("builtin call preflight builds");
        let missing_builtin_wrappers = candidate_preflight
            .missing_bindings()
            .iter()
            .filter_map(RuntimeSymbolNativeTargetCandidateMissingBinding::missing_builtin_wrapper)
            .map(|binding| binding.symbol_name())
            .collect::<Vec<_>>();

        assert_eq!(
            missing_builtin_wrappers,
            builtin_preflight
                .call_bindings()
                .iter()
                .map(|binding| binding.symbol_name())
                .collect::<Vec<_>>()
        );
        assert!(
            candidate_preflight
                .missing_bindings()
                .iter()
                .any(|missing| {
                    missing.missing_abi_signature().is_some_and(|gap| {
                        gap.symbol_name() == "aos_force"
                            && gap.helper_role() == Some(RuntimeHelperRole::ForcingControl)
                    })
                })
        );
        assert!(
            candidate_preflight
                .missing_bindings()
                .iter()
                .any(|missing| {
                    missing.missing_abi_signature().is_some_and(|gap| {
                        gap.symbol_name() == "nix.builtin.true"
                            && gap
                                .builtin_missing_binding()
                                .is_some_and(|builtin| builtin.builtin_name() == b"true")
                    })
                })
        );
        assert!(
            candidate_preflight
                .missing_bindings()
                .iter()
                .any(|missing| {
                    missing.missing_builtin_wrapper().is_some_and(|binding| {
                        binding.symbol_name() == "nix.builtin.derivationStrict"
                    })
                })
        );
        assert!(
            candidate_preflight
                .missing_bindings()
                .iter()
                .all(|missing| missing.missing_helper_callable_role().is_none())
        );
    }

    #[test]
    fn runtime_symbol_native_target_candidate_preflight_converts_complete_report_to_plan() {
        let helper_binding = runtime_helper_bindings()
            .iter()
            .copied()
            .find(|binding| binding.rust_callable_binding().is_some())
            .expect("runtime helper inventory has at least one callable binding");
        let candidate_bindings = vec![RuntimeSymbolNativeTargetCandidateBinding::helper(
            helper_binding,
        )];
        let preflight = RuntimeSymbolNativeTargetCandidatePreflight::new(
            candidate_bindings.clone(),
            Vec::new(),
        );

        let plan = preflight
            .into_native_target_candidate_plan()
            .expect("complete native-target candidate preflight converts");

        assert_eq!(plan.candidate_bindings(), candidate_bindings.as_slice());
    }

    #[test]
    fn runtime_symbol_native_target_candidate_plan_rejects_until_all_symbols_are_candidates() {
        let error = runtime_symbol_native_target_candidate_plan()
            .expect_err("current native-target candidate plan rejects incomplete metadata");
        let RuntimeSymbolNativeTargetCandidatePlanError::Incomplete {
            missing_count,
            preflight,
        } = error
        else {
            panic!("expected incomplete native-target candidate plan error");
        };

        assert_eq!(missing_count, preflight.missing_bindings().len());
        assert!(!preflight.is_complete());
        assert!(preflight.candidate_bindings().iter().any(|candidate| {
            candidate.symbol_name() == "aos_alloc_attrs"
                && candidate.helper_role() == RuntimeHelperRole::Allocation
        }));
        assert!(preflight.candidate_bindings().iter().any(|candidate| {
            candidate.symbol_name() == "aos_env_get"
                && candidate.helper_role() == RuntimeHelperRole::EnvironmentAccess
        }));
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.missing_abi_signature().is_some_and(|gap| {
                gap.symbol_name() == "aos_force"
                    && gap.helper_role() == Some(RuntimeHelperRole::ForcingControl)
            })
        }));
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing
                .missing_builtin_wrapper()
                .is_some_and(|binding| binding.symbol_name() == "nix.builtin.derivationStrict")
        }));
    }

    #[test]
    fn runtime_symbol_native_export_preflight_reports_exported_wrapper_gaps() {
        let export_preflight =
            runtime_symbol_native_export_preflight().expect("native export preflight builds");
        let target_preflight = runtime_symbol_native_target_candidate_preflight()
            .expect("native target candidate preflight builds");
        let exported_wrapper_gaps = export_preflight
            .missing_bindings()
            .iter()
            .filter(|missing| missing.missing_exported_c_abi_wrapper_role().is_some())
            .collect::<Vec<_>>();

        assert!(export_preflight.export_bindings().is_empty());
        assert!(!export_preflight.is_complete());
        assert_eq!(
            export_preflight.missing_bindings().len(),
            target_preflight.candidate_bindings().len() + target_preflight.missing_bindings().len()
        );
        assert_eq!(
            exported_wrapper_gaps.len(),
            target_preflight.candidate_bindings().len()
        );
        assert!(exported_wrapper_gaps.iter().any(|missing| {
            missing.symbol_name() == "aos_alloc_attrs"
                && missing.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::Allocation)
                && missing.missing_exported_c_abi_failure_convention()
                    == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
        }));
        assert!(exported_wrapper_gaps.iter().any(|missing| {
            missing.symbol_name() == "aos_gc_write_barrier"
                && missing.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::WriteBarrier)
                && missing.missing_exported_c_abi_failure_convention()
                    == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
        }));
        let allocation_preflight = runtime_allocation_native_export_preflight();
        let attrs_allocation_blockers = allocation_preflight
            .readiness_for_symbol("aos_alloc_attrs")
            .expect("attrs allocation export readiness exists")
            .blockers();
        let thunk_allocation_blockers = allocation_preflight
            .readiness_for_symbol("aos_alloc_thunk")
            .expect("thunk allocation export readiness exists")
            .blockers();
        let write_barrier_preflight = runtime_write_barrier_native_export_preflight();
        let write_barrier_blockers = write_barrier_preflight
            .readiness_for_symbol("aos_gc_write_barrier")
            .expect("write-barrier export readiness exists")
            .blockers();
        let attrs_export_gap = exported_wrapper_gaps
            .iter()
            .find(|missing| missing.symbol_name() == "aos_alloc_attrs")
            .expect("attrs export gap exists");
        let thunk_export_gap = exported_wrapper_gaps
            .iter()
            .find(|missing| missing.symbol_name() == "aos_alloc_thunk")
            .expect("thunk export gap exists");
        let write_barrier_export_gap = exported_wrapper_gaps
            .iter()
            .find(|missing| missing.symbol_name() == "aos_gc_write_barrier")
            .expect("write-barrier export gap exists");

        assert_eq!(
            attrs_export_gap.missing_exported_allocation_blockers(),
            Some(attrs_allocation_blockers)
        );
        assert!(
            !attrs_export_gap
                .missing_exported_allocation_blockers()
                .expect("attrs allocation blockers exist")
                .contains(
                    &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                )
        );
        assert_eq!(
            thunk_export_gap.missing_exported_allocation_blockers(),
            Some(thunk_allocation_blockers)
        );
        assert!(
            thunk_export_gap
                .missing_exported_allocation_blockers()
                .expect("thunk allocation blockers exist")
                .contains(
                    &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                )
        );
        assert_eq!(
            write_barrier_export_gap.missing_exported_write_barrier_blockers(),
            Some(write_barrier_blockers)
        );
        assert!(
            write_barrier_export_gap
                .missing_exported_write_barrier_blockers()
                .expect("write-barrier blockers exist")
                .contains(
                    &RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented
                )
        );
        assert!(
            write_barrier_export_gap
                .missing_exported_write_barrier_blockers()
                .expect("write-barrier blockers exist")
                .contains(&RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented)
        );
        assert_eq!(
            write_barrier_export_gap.missing_exported_allocation_blockers(),
            None
        );
        for gap in exported_wrapper_gaps.iter().filter(|missing| {
            missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::WriteBarrier)
        }) {
            assert!(
                gap.missing_exported_write_barrier_blockers()
                    .is_some_and(|blockers| !blockers.is_empty()),
                "{} write-barrier export gaps must retain family blockers",
                gap.symbol_name()
            );
        }
        assert!(exported_wrapper_gaps.iter().any(|missing| {
            missing.symbol_name() == "aos_env_get"
                && missing.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::EnvironmentAccess)
                && missing.missing_exported_c_abi_failure_convention()
                    == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
        }));
        assert!(export_preflight.missing_bindings().iter().any(|missing| {
            missing
                .missing_native_target_candidate()
                .is_some_and(|gap| {
                    gap.missing_abi_signature().is_some_and(|abi_gap| {
                        abi_gap.symbol_name() == "aos_force"
                            && abi_gap.helper_role() == Some(RuntimeHelperRole::ForcingControl)
                    })
                })
        }));
        assert!(export_preflight.missing_bindings().iter().any(|missing| {
            missing
                .missing_native_target_candidate()
                .is_some_and(|gap| {
                    gap.missing_builtin_wrapper().is_some_and(|binding| {
                        binding.symbol_name() == "nix.builtin.derivationStrict"
                    })
                })
        }));
    }

    #[test]
    fn runtime_symbol_native_export_preflight_preserves_runtime_symbol_order() {
        let export_preflight =
            runtime_symbol_native_export_preflight().expect("native export preflight builds");
        let manifest_symbols = runtime_symbol_binding_manifest()
            .expect("binding manifest builds")
            .into_iter()
            .map(|entry| entry.symbol_name().to_owned())
            .collect::<Vec<_>>();
        let export_symbols = export_preflight
            .missing_bindings()
            .iter()
            .map(RuntimeSymbolNativeExportMissingBinding::symbol_name)
            .collect::<Vec<_>>();

        assert_eq!(export_symbols, manifest_symbols);
    }

    #[test]
    fn runtime_symbol_native_export_preflight_converts_synthetic_report_to_plan() {
        let export_binding = RuntimeSymbolNativeExportBinding::new(
            "aos_alloc_attrs".to_owned(),
            RuntimeHelperRole::Allocation,
            RuntimeHelperFailureConvention::TrapToEvaluator,
        );
        let preflight =
            RuntimeSymbolNativeExportPreflight::new(vec![export_binding.clone()], Vec::new());

        let plan = preflight
            .into_native_export_plan()
            .expect("synthetic native-export metadata preflight converts");

        assert_eq!(plan.export_bindings(), &[export_binding]);
        assert_eq!(plan.export_bindings()[0].symbol_name(), "aos_alloc_attrs");
        assert_eq!(
            plan.export_bindings()[0].helper_role(),
            RuntimeHelperRole::Allocation
        );
        assert_eq!(
            plan.export_bindings()[0].failure_convention(),
            RuntimeHelperFailureConvention::TrapToEvaluator
        );
    }

    #[test]
    fn runtime_symbol_native_export_plan_rejects_until_all_symbols_are_exported() {
        let error = runtime_symbol_native_export_plan()
            .expect_err("current native-export plan rejects incomplete metadata");
        let RuntimeSymbolNativeExportPlanError::Incomplete {
            missing_count,
            preflight,
        } = error
        else {
            panic!("expected incomplete native-export plan error");
        };

        assert_eq!(missing_count, preflight.missing_bindings().len());
        assert!(!preflight.is_complete());
        assert!(preflight.export_bindings().is_empty());
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "aos_alloc_attrs"
                && missing.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::Allocation)
        }));
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing
                .missing_native_target_candidate()
                .is_some_and(|gap| {
                    gap.missing_abi_signature().is_some_and(|abi_gap| {
                        abi_gap.symbol_name() == "aos_force"
                            && abi_gap.helper_role() == Some(RuntimeHelperRole::ForcingControl)
                    })
                })
        }));
    }

    #[test]
    fn runtime_symbol_rust_callable_preflight_reports_current_gaps() {
        let callable_preflight =
            runtime_symbol_rust_callable_preflight().expect("callable preflight builds");
        let registration_preflight =
            runtime_symbol_registration_preflight().expect("registration preflight builds");
        let callable_helper_symbols = callable_preflight
            .helper_callables()
            .iter()
            .copied()
            .map(RuntimeHelperRustCallableBinding::symbol_name)
            .collect::<Vec<_>>();

        assert!(!callable_preflight.is_complete());
        assert_eq!(
            callable_preflight.helper_callables(),
            runtime_helper_rust_callable_bindings().as_slice()
        );
        assert_eq!(
            callable_helper_symbols,
            registration_preflight
                .helper_bindings()
                .iter()
                .copied()
                .map(RuntimeHelperBinding::symbol_name)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            callable_preflight.missing_bindings(),
            registration_preflight.missing_bindings()
        );
        assert!(callable_preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "aos_force"
                && missing.helper_role() == Some(RuntimeHelperRole::ForcingControl)
        }));
        assert!(callable_preflight.missing_bindings().iter().any(|missing| {
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
