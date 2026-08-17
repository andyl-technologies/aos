//! Safe runtime-helper binding inventory for future native registration.
//!
//! The allocation, apply, attrset-access, environment-access, forcing, and
//! write-barrier modules each own their frozen helper symbols, ABI signatures,
//! and safe Rust dispatch tables. This module combines those helper families into one
//! registration-oriented manifest so later Cranelift or C-ABI glue can consume a
//! single inventory without guessing from symbol text. It does not export native
//! functions or install symbols in a JIT module.

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
};
use super::apply::{
    RuntimeApplyAbiSignature, RuntimeApplyEntryPoint, RuntimeApplyNativeExportBlocker,
    RuntimeApplyRustCallableBinding,
};
use super::attr::{
    RuntimeAttrAccessAbiSignature, RuntimeAttrAccessEntryPoint,
    RuntimeAttrAccessNativeExportBlocker, RuntimeAttrAccessRustCallableBinding,
};
use super::barrier::{
    RuntimeWriteBarrierAbiSignature, RuntimeWriteBarrierEntryPoint,
    RuntimeWriteBarrierNativeExportBlocker, RuntimeWriteBarrierRustCallableBinding,
};
use super::env::{
    RuntimeEnvAccessAbiSignature, RuntimeEnvAccessEntryPoint, RuntimeEnvAccessNativeExportBlocker,
    RuntimeEnvAccessRustCallableBinding,
};
use super::forcing::{
    RuntimeForcingAbiSignature, RuntimeForcingEntryPoint, RuntimeForcingNativeExportBlocker,
    RuntimeForcingRustCallableBinding,
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
    RuntimeHelperBinding::CallControl(RuntimeApplyEntryPoint::AosApply.abi_signature()),
    RuntimeHelperBinding::Forcing(RuntimeForcingEntryPoint::AosBlackholeCheck.abi_signature()),
    RuntimeHelperBinding::EnvironmentAccess(RuntimeEnvAccessEntryPoint::AosEnvGet.abi_signature()),
    RuntimeHelperBinding::Forcing(RuntimeForcingEntryPoint::AosForce.abi_signature()),
    RuntimeHelperBinding::Forcing(RuntimeForcingEntryPoint::AosForceDeep.abi_signature()),
    RuntimeHelperBinding::WriteBarrier(
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier.abi_signature(),
    ),
    RuntimeHelperBinding::AttrsetAccess(RuntimeAttrAccessEntryPoint::AosHasAttr.abi_signature()),
    RuntimeHelperBinding::AttrsetAccess(RuntimeAttrAccessEntryPoint::AosSelectIc.abi_signature()),
    RuntimeHelperBinding::AttrsetAccess(RuntimeAttrAccessEntryPoint::AosUpdate.abi_signature()),
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
    runtime_helper_bindings()
        .iter()
        .copied()
        .filter_map(RuntimeHelperBinding::rust_callable_binding)
        .collect()
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
                        helper_binding.call_control_native_export_blockers(),
                        helper_binding.attrset_access_native_export_blockers(),
                        helper_binding.env_access_native_export_blockers(),
                        helper_binding.forcing_native_export_blockers(),
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

const RUNTIME_BUILTIN_NATIVE_WRAPPER_BLOCKERS: &[RuntimeBuiltinNativeWrapperBlocker] = &[
    RuntimeBuiltinNativeWrapperBlocker::MissingWrapperBody,
    RuntimeBuiltinNativeWrapperBlocker::RuntimeContextAbiDecodeUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::NativeEnvPointerDecodeUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::NativeValueArgumentDecodeUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::EvaluatorCallFrameBindingUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::ActiveArgumentRootRegistrationUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::BuiltinDispatchBindingUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::ArgumentForcingContractBindingUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::TrapTransferUnimplemented,
    RuntimeBuiltinNativeWrapperBlocker::NativeValueReturnMaterializationUnimplemented,
];

/// Returns blockers for callable builtin native-wrapper generation.
pub const fn runtime_builtin_native_wrapper_blockers()
-> &'static [RuntimeBuiltinNativeWrapperBlocker] {
    RUNTIME_BUILTIN_NATIVE_WRAPPER_BLOCKERS
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

mod bindings_a;
mod bindings_b;
pub use bindings_a::*;
pub use bindings_b::*;

#[cfg(test)]
mod tests;
