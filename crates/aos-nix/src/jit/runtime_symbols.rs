//! Runtime-symbol metadata bridged from runtime helper sources into JIT preflights.

use std::{collections::BTreeMap, ffi::c_void, num::NonZeroUsize};

use ratchet_core::{RuntimeHelperRole, RuntimeSymbolKind, RuntimeSymbolNameError};
use ratchet_jit::{
    JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate, JitRuntimeSymbolRegistrationBinding,
    JitRuntimeSymbolRegistrationError, JitRuntimeSymbolRegistrationGap,
    JitRuntimeSymbolRegistrationPlan, JitRuntimeSymbolRegistrationPlanError,
    JitRuntimeSymbolRegistrationPreflight,
    jit_runtime_symbol_registration_preflight_with_candidates,
};
use ratchet_oracle::runtime::helpers::{
    RuntimeHelperRustCallableBinding, RuntimeSymbolMissingBinding,
    RuntimeSymbolNativeExportMissingBinding, RuntimeSymbolNativeExportPreflight,
    runtime_symbol_native_export_preflight, runtime_symbol_rust_callable_preflight,
};
use ratchet_runtime_ffi::env::{
    RuntimeEnvAccessNativeWrapperBinding, runtime_env_access_native_wrapper_bindings,
};
use ratchet_runtime_ffi::force::{
    RuntimeForcingNativeWrapperBinding, runtime_forcing_native_wrapper_bindings,
};
use thiserror::Error;

const AOS_ENV_GET_SYMBOL: &str = "aos_env_get";
const AOS_FORCE_SYMBOL: &str = "aos_force";

/// A failure while building Nix JIT runtime-symbol address candidates.
#[derive(Debug, Error)]
pub enum NixJitRuntimeSymbolAddressCandidateError {
    /// The shared runtime symbol manifest could not be projected.
    #[error("runtime symbol manifest projection failed")]
    SymbolName(#[from] RuntimeSymbolNameError),

    /// A Rust-callable helper binding exposed a null process-local address.
    #[error("runtime helper {symbol_name} has a null Rust-callable address")]
    NullHelperAddress {
        /// The stable runtime symbol whose callable address was null.
        symbol_name: &'static str,
    },

    /// A runtime-FFI native wrapper binding exposed a null process-local address.
    #[error("runtime helper {symbol_name} has a null runtime-FFI native-wrapper address")]
    NullRuntimeFfiNativeWrapperAddress {
        /// The stable runtime symbol whose native-wrapper address was null.
        symbol_name: &'static str,
    },
}

/// Result returned by JIT runtime-symbol address-candidate preflights.
pub type NixJitPreflightResult =
    Result<NixJitRuntimeSymbolAddressCandidatePreflight, NixJitRuntimeSymbolAddressCandidateError>;

/// A failure while building Nix JIT runtime-symbol registration metadata.
#[derive(Debug, Error)]
pub enum NixJitRuntimeSymbolRegistrationError {
    /// Runtime helper addresses could not be projected into JIT metadata.
    #[error("JIT runtime-symbol address candidate projection failed")]
    AddressCandidates(#[from] NixJitRuntimeSymbolAddressCandidateError),

    /// Oracle native-export readiness metadata could not be built.
    #[error("JIT runtime-symbol native-export preflight failed")]
    NativeExport {
        /// The underlying native-export metadata failure.
        #[source]
        source: RuntimeSymbolNameError,
    },

    /// JIT runtime-symbol registration metadata could not be built.
    #[error("JIT runtime-symbol registration preflight failed")]
    Registration(#[from] JitRuntimeSymbolRegistrationError),
}

/// Result returned by JIT runtime-symbol registration preflights.
pub type NixJitRuntimeSymbolRegistrationResult =
    Result<NixJitRuntimeSymbolRegistrationPreflight, NixJitRuntimeSymbolRegistrationError>;

/// A failure while preparing complete Nix JIT runtime-symbol registration metadata.
#[derive(Debug, Error)]
pub enum NixJitRuntimeSymbolRegistrationPlanError {
    /// Runtime helper addresses could not be projected into JIT metadata.
    #[error("JIT runtime-symbol address candidate projection failed")]
    AddressCandidates(#[from] NixJitRuntimeSymbolAddressCandidateError),

    /// Oracle native-export readiness metadata could not be built.
    #[error("JIT runtime-symbol native-export preflight failed")]
    NativeExport {
        /// The underlying native-export metadata failure.
        #[source]
        source: RuntimeSymbolNameError,
    },

    /// JIT runtime-symbol registration metadata could not be built.
    #[error("JIT runtime-symbol registration preflight failed")]
    Registration(#[from] JitRuntimeSymbolRegistrationError),

    /// Some runtime-symbol registration gates are not yet complete.
    #[error(
        "Nix JIT runtime-symbol registration metadata is incomplete: {missing_count} gate(s) open"
    )]
    Incomplete {
        /// The number of incomplete registration, native-export, and address-provenance gates.
        missing_count: usize,
        /// The preserved Nix preflight report, including runtime address candidates.
        preflight: NixJitRuntimeSymbolRegistrationPreflight,
    },
}

impl From<NixJitRuntimeSymbolRegistrationError> for NixJitRuntimeSymbolRegistrationPlanError {
    fn from(error: NixJitRuntimeSymbolRegistrationError) -> Self {
        match error {
            NixJitRuntimeSymbolRegistrationError::AddressCandidates(source) => {
                Self::AddressCandidates(source)
            }
            NixJitRuntimeSymbolRegistrationError::NativeExport { source } => {
                Self::NativeExport { source }
            }
            NixJitRuntimeSymbolRegistrationError::Registration(source) => {
                Self::Registration(source)
            }
        }
    }
}

/// Result returned by complete JIT runtime-symbol registration plan gates.
pub type NixJitRuntimeSymbolRegistrationPlanResult =
    Result<NixJitRuntimeSymbolRegistrationPlan, NixJitRuntimeSymbolRegistrationPlanError>;

/// Source classification for one JIT runtime-symbol address candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NixJitRuntimeSymbolAddressProvenance {
    /// The candidate points at a process-local Rust helper wrapper.
    RustCallableHelper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The runtime symbol family served by the address candidate.
        kind: RuntimeSymbolKind,
    },
    /// The candidate points at a runtime-FFI native wrapper body.
    RuntimeFfiNativeWrapper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The runtime symbol family served by the address candidate.
        kind: RuntimeSymbolKind,
    },
}

impl NixJitRuntimeSymbolAddressProvenance {
    fn rust_callable_helper(candidate: &JitRuntimeSymbolAddressCandidate) -> Self {
        Self::RustCallableHelper {
            symbol_name: candidate.symbol_name().to_owned(),
            kind: candidate.kind(),
        }
    }

    fn runtime_ffi_native_wrapper(candidate: &JitRuntimeSymbolAddressCandidate) -> Self {
        Self::RuntimeFfiNativeWrapper {
            symbol_name: candidate.symbol_name().to_owned(),
            kind: candidate.kind(),
        }
    }

    /// Returns the stable runtime symbol name for this address provenance.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::RustCallableHelper { symbol_name, .. }
            | Self::RuntimeFfiNativeWrapper { symbol_name, .. } => symbol_name,
        }
    }

    /// Returns the runtime symbol family served by this address provenance.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        match self {
            Self::RustCallableHelper { kind, .. } | Self::RuntimeFfiNativeWrapper { kind, .. } => {
                *kind
            }
        }
    }

    /// Returns true when the candidate still uses Rust-callable helper provenance.
    pub const fn is_rust_callable_helper(&self) -> bool {
        matches!(self, Self::RustCallableHelper { .. })
    }

    /// Returns true when the candidate uses a runtime-FFI native wrapper address.
    pub const fn is_runtime_ffi_native_wrapper(&self) -> bool {
        matches!(self, Self::RuntimeFfiNativeWrapper { .. })
    }
}

/// An address candidate that is not yet a final exported native ABI address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NixJitRuntimeSymbolAddressProvenanceGap {
    /// The candidate points at a process-local Rust helper wrapper.
    RustCallableHelper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The runtime symbol family served by the address candidate.
        kind: RuntimeSymbolKind,
    },
}

impl NixJitRuntimeSymbolAddressProvenanceGap {
    fn from_provenance(provenance: &NixJitRuntimeSymbolAddressProvenance) -> Option<Self> {
        match provenance {
            NixJitRuntimeSymbolAddressProvenance::RustCallableHelper { symbol_name, kind } => {
                Some(Self::RustCallableHelper {
                    symbol_name: symbol_name.clone(),
                    kind: *kind,
                })
            }
            NixJitRuntimeSymbolAddressProvenance::RuntimeFfiNativeWrapper { .. } => None,
        }
    }

    /// Returns the stable runtime symbol name for this provenance gap.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::RustCallableHelper { symbol_name, .. } => symbol_name,
        }
    }

    /// Returns the runtime symbol family blocked by this provenance gap.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        match self {
            Self::RustCallableHelper { kind, .. } => *kind,
        }
    }
}

/// Nix runtime-symbol registration readiness assembled from runtime address metadata.
///
/// This report owns the address-candidate preflight that fed the JIT
/// registration preflight, plus the oracle native-export preflight and
/// address-provenance gaps that keep those candidates from being final exported
/// ABI targets. Callers can compare bound JIT addresses with the runtime-derived
/// source metadata while still inspecting native-export blockers and
/// address-provenance gaps. It still does not call `JITBuilder::symbol`, export
/// C ABI wrappers, dereference registered addresses, or call native code.
#[derive(Clone, Debug, PartialEq)]
pub struct NixJitRuntimeSymbolRegistrationPreflight {
    address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
    native_export_preflight: RuntimeSymbolNativeExportPreflight,
    address_provenance_gaps: Vec<NixJitRuntimeSymbolAddressProvenanceGap>,
    registration_preflight: JitRuntimeSymbolRegistrationPreflight,
}

impl NixJitRuntimeSymbolRegistrationPreflight {
    fn new(
        address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
        native_export_preflight: RuntimeSymbolNativeExportPreflight,
        address_provenance_gaps: Vec<NixJitRuntimeSymbolAddressProvenanceGap>,
        registration_preflight: JitRuntimeSymbolRegistrationPreflight,
    ) -> Self {
        Self {
            address_candidate_preflight,
            native_export_preflight,
            address_provenance_gaps,
            registration_preflight,
        }
    }

    /// Returns the address-candidate preflight used for registration metadata.
    pub const fn address_candidate_preflight(
        &self,
    ) -> &NixJitRuntimeSymbolAddressCandidatePreflight {
        &self.address_candidate_preflight
    }

    /// Returns the oracle native-export readiness preflight.
    pub const fn native_export_preflight(&self) -> &RuntimeSymbolNativeExportPreflight {
        &self.native_export_preflight
    }

    /// Returns the JIT runtime-symbol registration preflight.
    pub const fn registration_preflight(&self) -> &JitRuntimeSymbolRegistrationPreflight {
        &self.registration_preflight
    }

    /// Returns runtime symbols with declaration and address metadata.
    pub fn bindings(&self) -> &[JitRuntimeSymbolRegistrationBinding] {
        self.registration_preflight.bindings()
    }

    /// Returns stable runtime symbols not ready for native registration.
    pub fn gaps(&self) -> &[JitRuntimeSymbolRegistrationGap] {
        self.registration_preflight.gaps()
    }

    /// Returns native-export gaps in runtime symbol-manifest order.
    pub fn native_export_missing_bindings(&self) -> &[RuntimeSymbolNativeExportMissingBinding] {
        self.native_export_preflight.missing_bindings()
    }

    /// Returns address candidates that are not yet exported native ABI addresses.
    pub fn address_provenance_gaps(&self) -> &[NixJitRuntimeSymbolAddressProvenanceGap] {
        &self.address_provenance_gaps
    }

    /// Returns true when every runtime symbol has registration, export, and exported-address provenance.
    pub fn is_complete(&self) -> bool {
        self.registration_preflight.is_complete()
            && self.native_export_preflight.is_complete()
            && self.address_provenance_gaps.is_empty()
    }

    /// Returns the registration binding for `symbol_name`, when present.
    pub fn binding_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolRegistrationBinding> {
        self.registration_preflight.binding_for_symbol(symbol_name)
    }

    /// Returns the registration gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolRegistrationGap> {
        self.registration_preflight.gap_for_symbol(symbol_name)
    }

    /// Returns the native-export gap for `symbol_name`, when present.
    pub fn native_export_gap_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&RuntimeSymbolNativeExportMissingBinding> {
        self.native_export_preflight
            .missing_bindings()
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Returns the address-provenance gap for `symbol_name`, when present.
    pub fn address_provenance_gap_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&NixJitRuntimeSymbolAddressProvenanceGap> {
        self.address_provenance_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    fn missing_gate_count(&self) -> usize {
        self.registration_preflight.gaps().len()
            + self.native_export_preflight.missing_bindings().len()
            + self.address_provenance_gaps.len()
    }

    fn into_parts(
        self,
    ) -> (
        NixJitRuntimeSymbolAddressCandidatePreflight,
        RuntimeSymbolNativeExportPreflight,
        Vec<NixJitRuntimeSymbolAddressProvenanceGap>,
        JitRuntimeSymbolRegistrationPreflight,
    ) {
        (
            self.address_candidate_preflight,
            self.native_export_preflight,
            self.address_provenance_gaps,
            self.registration_preflight,
        )
    }
}

/// Complete Nix runtime-symbol registration metadata assembled from runtime addresses.
///
/// This plan owns the address-candidate preflight that fed the JIT registration
/// plan and the complete oracle native-export preflight required for a final
/// ABI handoff. It can only be built after address candidates have no remaining
/// non-final provenance gaps. It is still metadata for a future
/// `JITBuilder::symbol` pass: it does not export C ABI wrappers, finalize code,
/// dereference helper addresses, or call native code.
#[derive(Clone, Debug, PartialEq)]
pub struct NixJitRuntimeSymbolRegistrationPlan {
    address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
    native_export_preflight: RuntimeSymbolNativeExportPreflight,
    registration_plan: JitRuntimeSymbolRegistrationPlan,
}

impl NixJitRuntimeSymbolRegistrationPlan {
    fn new(
        address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
        native_export_preflight: RuntimeSymbolNativeExportPreflight,
        registration_plan: JitRuntimeSymbolRegistrationPlan,
    ) -> Self {
        Self {
            address_candidate_preflight,
            native_export_preflight,
            registration_plan,
        }
    }

    /// Returns the address-candidate preflight used for registration metadata.
    pub const fn address_candidate_preflight(
        &self,
    ) -> &NixJitRuntimeSymbolAddressCandidatePreflight {
        &self.address_candidate_preflight
    }

    /// Returns the complete oracle native-export readiness preflight.
    pub const fn native_export_preflight(&self) -> &RuntimeSymbolNativeExportPreflight {
        &self.native_export_preflight
    }

    /// Returns the complete JIT runtime-symbol registration plan.
    pub const fn registration_plan(&self) -> &JitRuntimeSymbolRegistrationPlan {
        &self.registration_plan
    }

    /// Returns runtime-symbol bindings in stable manifest order.
    pub fn bindings(&self) -> &[JitRuntimeSymbolRegistrationBinding] {
        self.registration_plan.bindings()
    }

    /// Returns the registration binding for `symbol_name`, when present.
    pub fn binding_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolRegistrationBinding> {
        self.registration_plan.binding_for_symbol(symbol_name)
    }
}

/// Process-local JIT address candidates derived from runtime wrapper metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NixJitRuntimeSymbolAddressCandidatePreflight {
    address_candidates: Vec<JitRuntimeSymbolAddressCandidate>,
    address_provenance: Vec<NixJitRuntimeSymbolAddressProvenance>,
    missing_bindings: Vec<RuntimeSymbolMissingBinding>,
}

impl NixJitRuntimeSymbolAddressCandidatePreflight {
    fn new(
        address_candidates: Vec<JitRuntimeSymbolAddressCandidate>,
        address_provenance: Vec<NixJitRuntimeSymbolAddressProvenance>,
        missing_bindings: Vec<RuntimeSymbolMissingBinding>,
    ) -> Self {
        debug_assert_eq!(address_candidates.len(), address_provenance.len());
        Self {
            address_candidates,
            address_provenance,
            missing_bindings,
        }
    }

    /// Returns JIT address candidates in runtime symbol-manifest order.
    pub fn address_candidates(&self) -> &[JitRuntimeSymbolAddressCandidate] {
        &self.address_candidates
    }

    /// Returns address provenance records in runtime symbol-manifest order.
    pub fn address_provenance(&self) -> &[NixJitRuntimeSymbolAddressProvenance] {
        &self.address_provenance
    }

    /// Returns allocation-helper address candidates in runtime symbol-manifest order.
    pub fn allocation_address_candidates(
        &self,
    ) -> impl Iterator<Item = &JitRuntimeSymbolAddressCandidate> {
        self.helper_role_address_candidates(RuntimeHelperRole::Allocation)
    }

    /// Returns helper address candidates for `role` in runtime symbol-manifest order.
    pub fn helper_role_address_candidates(
        &self,
        role: RuntimeHelperRole,
    ) -> impl Iterator<Item = &JitRuntimeSymbolAddressCandidate> {
        self.address_candidates
            .iter()
            .filter(move |candidate| candidate.kind() == RuntimeSymbolKind::Helper(role))
    }

    /// Returns runtime symbols that still lack address metadata.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has address metadata.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Returns the address candidate for `symbol_name`, when present.
    pub fn address_candidate_for(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolAddressCandidate> {
        self.address_candidates
            .iter()
            .find(|candidate| candidate.symbol_name() == symbol_name)
    }

    /// Returns address provenance for `symbol_name`, when present.
    pub fn address_provenance_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&NixJitRuntimeSymbolAddressProvenance> {
        self.address_provenance
            .iter()
            .find(|provenance| provenance.symbol_name() == symbol_name)
    }

    /// Returns the missing binding for `symbol_name`, when present.
    pub fn missing_binding_for(&self, symbol_name: &str) -> Option<&RuntimeSymbolMissingBinding> {
        self.missing_bindings
            .iter()
            .find(|missing| missing.symbol_name() == symbol_name)
    }
}

/// Builds process-local JIT address candidates from runtime wrapper metadata.
///
/// Most returned candidates intentionally use current-process Rust helper
/// callable addresses, not exported native ABI wrappers. `aos_env_get` is
/// sourced from the success-path `ratchet-runtime-ffi` native wrapper, and
/// `aos_force` is sourced from the runtime-FFI WHNF fast-path wrapper. This lets
/// the bridge distinguish native-wrapper address provenance from the remaining
/// native-export blockers. The candidates let integration code exercise JIT
/// registration and relocation plumbing while keeping the actual native call
/// boundary disabled.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be projected into oracle Rust-callable metadata. Returns
/// [`NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress`] if a helper
/// binding violates the non-null address invariant before it reaches the JIT
/// registration metadata. Returns
/// [`NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress`]
/// if an `aos_env_get` or `aos_force` runtime-FFI wrapper binding violates the
/// non-null address invariant before it reaches the JIT registration metadata.
pub fn nix_jit_runtime_symbol_address_candidate_preflight() -> NixJitPreflightResult {
    let oracle_preflight = runtime_symbol_rust_callable_preflight()?;
    let env_native_wrappers = runtime_env_native_wrappers_by_symbol();
    let forcing_native_wrappers = runtime_forcing_native_wrappers_by_symbol();
    let mut address_candidates = Vec::new();
    let mut address_provenance = Vec::new();

    for binding in oracle_preflight.helper_callables().iter().copied() {
        let (candidate, provenance) = jit_address_candidate_for_helper_binding(
            binding,
            &env_native_wrappers,
            &forcing_native_wrappers,
        )?;
        address_candidates.push(candidate);
        address_provenance.push(provenance);
    }

    Ok(NixJitRuntimeSymbolAddressCandidatePreflight::new(
        address_candidates,
        address_provenance,
        oracle_preflight.missing_bindings().to_vec(),
    ))
}

/// Builds JIT runtime-symbol registration readiness from runtime address metadata.
///
/// This top-level integration preflight derives process-local runtime address
/// candidates and feeds them into the JIT runtime-symbol registration preflight.
/// The returned report owns both sides of that handoff for tests and later
/// install planning. It still does not call `JITBuilder::symbol`, export C ABI
/// wrappers, finalize code, dereference helper addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolRegistrationError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT candidate metadata.
/// Returns [`NixJitRuntimeSymbolRegistrationError::NativeExport`] when oracle
/// native-export readiness metadata cannot be built.
/// Returns [`NixJitRuntimeSymbolRegistrationError::Registration`] when JIT
/// registration metadata cannot be built from the candidate set.
pub fn nix_jit_runtime_symbol_registration_preflight() -> NixJitRuntimeSymbolRegistrationResult {
    let address_candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()?;
    let native_export_preflight = runtime_symbol_native_export_preflight()
        .map_err(|source| NixJitRuntimeSymbolRegistrationError::NativeExport { source })?;
    let address_provenance_gaps =
        address_provenance_gaps(address_candidate_preflight.address_provenance());
    let registration_preflight = jit_runtime_symbol_registration_preflight_with_candidates(
        address_candidate_preflight.address_candidates(),
    )?;
    Ok(NixJitRuntimeSymbolRegistrationPreflight::new(
        address_candidate_preflight,
        native_export_preflight,
        address_provenance_gaps,
        registration_preflight,
    ))
}

/// Builds complete JIT runtime-symbol registration metadata from runtime address metadata.
///
/// This strict gate derives process-local runtime address candidates,
/// builds the JIT registration preflight, carries the oracle native-export
/// readiness preflight, and succeeds only once every stable runtime symbol has
/// declaration/address metadata, native-export metadata, and exported-address
/// provenance. While helper, builtin, native-export, or non-final address
/// provenance gaps remain, the incomplete error carries the owned Nix preflight
/// so callers can inspect the runtime address candidates, native-export
/// blockers, address-provenance gaps, and JIT registration gaps. It still does
/// not call `JITBuilder::symbol`, export C ABI wrappers, finalize code,
/// dereference helper addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT candidate metadata.
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::NativeExport`] when
/// oracle native-export readiness metadata cannot be built.
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::Registration`] when JIT
/// registration metadata cannot be built from the candidate set. Returns
/// [`NixJitRuntimeSymbolRegistrationPlanError::Incomplete`] while any stable
/// runtime-symbol registration, native-export, or address-provenance gate
/// remains incomplete.
pub fn nix_jit_runtime_symbol_registration_plan() -> NixJitRuntimeSymbolRegistrationPlanResult {
    let preflight = nix_jit_runtime_symbol_registration_preflight()?;
    let missing_count = preflight.missing_gate_count();
    if missing_count != 0 {
        return Err(NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
            missing_count,
            preflight,
        });
    }

    let (
        address_candidate_preflight,
        native_export_preflight,
        address_provenance_gaps,
        registration_preflight,
    ) = preflight.into_parts();
    let registration_plan = match registration_preflight.into_registration_plan() {
        Ok(registration_plan) => registration_plan,
        Err(JitRuntimeSymbolRegistrationPlanError::Registration(error)) => {
            return Err(NixJitRuntimeSymbolRegistrationPlanError::Registration(
                error,
            ));
        }
        Err(JitRuntimeSymbolRegistrationPlanError::Incomplete {
            missing_count,
            preflight,
        }) => {
            let missing_count = missing_count
                + native_export_preflight.missing_bindings().len()
                + address_provenance_gaps.len();
            return Err(NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
                missing_count,
                preflight: NixJitRuntimeSymbolRegistrationPreflight::new(
                    address_candidate_preflight,
                    native_export_preflight,
                    address_provenance_gaps,
                    preflight,
                ),
            });
        }
    };

    Ok(NixJitRuntimeSymbolRegistrationPlan::new(
        address_candidate_preflight,
        native_export_preflight,
        registration_plan,
    ))
}

fn address_provenance_gaps(
    provenance: &[NixJitRuntimeSymbolAddressProvenance],
) -> Vec<NixJitRuntimeSymbolAddressProvenanceGap> {
    provenance
        .iter()
        .filter_map(NixJitRuntimeSymbolAddressProvenanceGap::from_provenance)
        .collect()
}

fn jit_address_candidate_for_helper_binding(
    binding: RuntimeHelperRustCallableBinding,
    env_native_wrappers: &BTreeMap<&'static str, RuntimeEnvAccessNativeWrapperBinding>,
    forcing_native_wrappers: &BTreeMap<&'static str, RuntimeForcingNativeWrapperBinding>,
) -> Result<
    (
        JitRuntimeSymbolAddressCandidate,
        NixJitRuntimeSymbolAddressProvenance,
    ),
    NixJitRuntimeSymbolAddressCandidateError,
> {
    if let RuntimeHelperRustCallableBinding::EnvironmentAccess(env_binding) = binding
        && env_binding.symbol_name() == AOS_ENV_GET_SYMBOL
        && let Some(native_wrapper) = env_native_wrappers.get(AOS_ENV_GET_SYMBOL)
    {
        let candidate = jit_address_candidate_for_runtime_ffi_native_wrapper(
            native_wrapper.symbol_name(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            native_wrapper.address().as_ptr(),
        )?;
        let provenance =
            NixJitRuntimeSymbolAddressProvenance::runtime_ffi_native_wrapper(&candidate);
        return Ok((candidate, provenance));
    }

    if let RuntimeHelperRustCallableBinding::Forcing(forcing_binding) = binding
        && forcing_binding.symbol_name() == AOS_FORCE_SYMBOL
        && let Some(native_wrapper) = forcing_native_wrappers.get(AOS_FORCE_SYMBOL)
    {
        let candidate = jit_address_candidate_for_runtime_ffi_native_wrapper(
            native_wrapper.symbol_name(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            native_wrapper.address().as_ptr(),
        )?;
        let provenance =
            NixJitRuntimeSymbolAddressProvenance::runtime_ffi_native_wrapper(&candidate);
        return Ok((candidate, provenance));
    }

    let candidate = jit_address_candidate_for_helper_callable(binding)?;
    let provenance = NixJitRuntimeSymbolAddressProvenance::rust_callable_helper(&candidate);
    Ok((candidate, provenance))
}

fn jit_address_candidate_for_helper_callable(
    binding: RuntimeHelperRustCallableBinding,
) -> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let raw = helper_callable_address(binding) as usize;
    let address = JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
            symbol_name: binding.symbol_name(),
        },
    )?);

    Ok(JitRuntimeSymbolAddressCandidate::new(
        binding.symbol_name().to_owned(),
        RuntimeSymbolKind::Helper(binding.role()),
        address,
    ))
}

fn jit_address_candidate_for_runtime_ffi_native_wrapper(
    symbol_name: &'static str,
    kind: RuntimeSymbolKind,
    raw_pointer: *mut c_void,
) -> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let raw = raw_pointer as usize;
    let address = JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress {
            symbol_name,
        },
    )?);

    Ok(JitRuntimeSymbolAddressCandidate::new(
        symbol_name.to_owned(),
        kind,
        address,
    ))
}

fn helper_callable_address(binding: RuntimeHelperRustCallableBinding) -> *const () {
    match binding {
        RuntimeHelperRustCallableBinding::Allocation(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::CallControl(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::AttrsetAccess(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::EnvironmentAccess(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::WriteBarrier(binding) => binding.address().as_ptr(),
    }
}

fn runtime_env_native_wrappers_by_symbol()
-> BTreeMap<&'static str, RuntimeEnvAccessNativeWrapperBinding> {
    runtime_env_access_native_wrapper_bindings()
        .into_iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect()
}

fn runtime_forcing_native_wrappers_by_symbol()
-> BTreeMap<&'static str, RuntimeForcingNativeWrapperBinding> {
    runtime_forcing_native_wrapper_bindings()
        .into_iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect()
}

#[cfg(test)]
mod tests;
