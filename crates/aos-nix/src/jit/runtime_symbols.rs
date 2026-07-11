//! Runtime-symbol metadata bridged from runtime helper sources into JIT preflights.

use std::{collections::BTreeMap, num::NonZeroUsize};

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
use ratchet_runtime_ffi::wrappers::{
    RuntimeNativeWrapperBinding, RuntimeNativeWrapperBlockers, runtime_native_wrapper_bindings,
};
use thiserror::Error;

mod standalone;

pub use standalone::{
    nix_jit_deopt_address_candidate, nix_jit_primop_call_address_candidate,
    nix_jit_upval_get_address_candidate,
};

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
        /// Family-specific blockers that still prevent final native export.
        remaining_export_blockers: RuntimeNativeWrapperBlockers,
    },
    /// The candidate points at a standalone runtime-FFI wrapper with no oracle
    /// helper-family binding.
    StandaloneRuntimeFfiWrapper {
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

    fn runtime_ffi_native_wrapper(
        candidate: &JitRuntimeSymbolAddressCandidate,
        remaining_export_blockers: RuntimeNativeWrapperBlockers,
    ) -> Self {
        Self::RuntimeFfiNativeWrapper {
            symbol_name: candidate.symbol_name().to_owned(),
            kind: candidate.kind(),
            remaining_export_blockers,
        }
    }

    fn standalone_runtime_ffi_wrapper(candidate: &JitRuntimeSymbolAddressCandidate) -> Self {
        Self::StandaloneRuntimeFfiWrapper {
            symbol_name: candidate.symbol_name().to_owned(),
            kind: candidate.kind(),
        }
    }

    /// Returns the stable runtime symbol name for this address provenance.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::RustCallableHelper { symbol_name, .. }
            | Self::RuntimeFfiNativeWrapper { symbol_name, .. }
            | Self::StandaloneRuntimeFfiWrapper { symbol_name, .. } => symbol_name,
        }
    }

    /// Returns the runtime symbol family served by this address provenance.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        match self {
            Self::RustCallableHelper { kind, .. }
            | Self::RuntimeFfiNativeWrapper { kind, .. }
            | Self::StandaloneRuntimeFfiWrapper { kind, .. } => *kind,
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

    /// Returns true when the candidate uses a standalone runtime-FFI wrapper.
    pub const fn is_standalone_runtime_ffi_wrapper(&self) -> bool {
        matches!(self, Self::StandaloneRuntimeFfiWrapper { .. })
    }

    /// Returns runtime-FFI wrapper blockers that still prevent final native export.
    pub const fn runtime_ffi_remaining_export_blockers(
        &self,
    ) -> Option<RuntimeNativeWrapperBlockers> {
        match self {
            Self::RuntimeFfiNativeWrapper {
                remaining_export_blockers,
                ..
            } => Some(*remaining_export_blockers),
            Self::RustCallableHelper { .. } | Self::StandaloneRuntimeFfiWrapper { .. } => None,
        }
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
            NixJitRuntimeSymbolAddressProvenance::StandaloneRuntimeFfiWrapper { .. } => None,
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
/// Covered helper families intentionally use current-process runtime-FFI
/// trap-wrapper addresses, not final exported native ABI targets. Helpers
/// without runtime-FFI wrappers fall back to Rust-callable metadata. The
/// currently covered trap-only helper families are sourced from the unified
/// `ratchet-runtime-ffi` native-wrapper manifest, letting the bridge
/// distinguish native-wrapper address provenance from the remaining
/// native-export blockers. The candidates let integration code exercise JIT
/// registration and relocation plumbing while keeping the actual native call
/// boundary disabled.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be projected into oracle Rust-callable metadata or the unified
/// runtime-FFI native-wrapper manifest. Returns
/// [`NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress`] if a helper
/// binding violates the non-null address invariant before it reaches the JIT
/// registration metadata. Returns
/// [`NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress`]
/// if an `aos_alloc_*`, `aos_env_get`, `aos_apply`, `aos_has_attr`,
/// `aos_select_ic`, `aos_update`, `aos_blackhole_check`, `aos_force`,
/// `aos_force_deep`, or `aos_gc_write_barrier` runtime-FFI wrapper binding
/// violates the non-null address invariant before it reaches the JIT
/// registration metadata.
pub fn nix_jit_runtime_symbol_address_candidate_preflight() -> NixJitPreflightResult {
    let oracle_preflight = runtime_symbol_rust_callable_preflight()?;
    let native_wrappers = runtime_native_wrappers_by_symbol()?;
    let mut address_candidates = Vec::new();
    let mut address_provenance = Vec::new();

    for binding in oracle_preflight.helper_callables().iter().copied() {
        let (candidate, provenance) =
            jit_address_candidate_for_helper_binding(binding, &native_wrappers)?;
        address_candidates.push(candidate);
        address_provenance.push(provenance);
    }

    for candidate in [
        nix_jit_stack_map_enter_address_candidate()?,
        nix_jit_stack_map_exit_address_candidate()?,
    ] {
        address_provenance.push(
            NixJitRuntimeSymbolAddressProvenance::standalone_runtime_ffi_wrapper(&candidate),
        );
        address_candidates.push(candidate);
    }

    Ok(NixJitRuntimeSymbolAddressCandidatePreflight::new(
        address_candidates,
        address_provenance,
        oracle_preflight.missing_bindings().to_vec(),
    ))
}

/// Builds the JIT address candidate for the `aos_string_length` leaf helper.
///
/// `aos_string_length` returns the byte length of an already-forced string. Like
/// [`nix_jit_primop_call_address_candidate`], it is a standalone
/// `ratchet-runtime-ffi` wrapper rather than an oracle-modeled evaluator helper,
/// so it is registered directly from its process-local wrapper address so a
/// compiled `stringLength` inline body importing `aos_string_length` can be
/// finalized. Unlike the primop trampoline it never re-enters the interpreter's
/// builtin dispatch; it performs only the same heap length lookup an ordinary
/// tree-walk `stringLength` does.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress`]
/// if the `aos_string_length` wrapper reports a null process-local address.
pub fn nix_jit_string_length_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let address = ratchet_runtime_ffi::aos_string_length_native_wrapper_address();
    let raw = NonZeroUsize::new(address as usize).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress {
            symbol_name: "aos_string_length",
        },
    )?;
    Ok(JitRuntimeSymbolAddressCandidate::new(
        "aos_string_length".to_owned(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::PrimopDispatch),
        JitRuntimeSymbolAddress::new(raw),
    ))
}

/// Builds the JIT address candidate for compiled stack-map entry.
///
/// # Errors
///
/// Returns an error if the wrapper address is null.
pub fn nix_jit_stack_map_enter_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    standalone_runtime_ffi_candidate(
        "aos_jit_stack_map_enter",
        RuntimeHelperRole::SafepointControl,
        ratchet_runtime_ffi::aos_jit_stack_map_enter_native_wrapper_address(),
    )
}

/// Builds the JIT address candidate for compiled stack-map exit.
///
/// # Errors
///
/// Returns an error if the wrapper address is null.
pub fn nix_jit_stack_map_exit_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    standalone_runtime_ffi_candidate(
        "aos_jit_stack_map_exit",
        RuntimeHelperRole::SafepointControl,
        ratchet_runtime_ffi::aos_jit_stack_map_exit_native_wrapper_address(),
    )
}

fn standalone_runtime_ffi_candidate(
    symbol_name: &'static str,
    role: RuntimeHelperRole,
    address: *mut std::ffi::c_void,
) -> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let raw = NonZeroUsize::new(address as usize).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress {
            symbol_name,
        },
    )?;
    Ok(JitRuntimeSymbolAddressCandidate::new(
        symbol_name.to_owned(),
        RuntimeSymbolKind::Helper(role),
        JitRuntimeSymbolAddress::new(raw),
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
    native_wrappers: &BTreeMap<&'static str, RuntimeNativeWrapperBinding>,
) -> Result<
    (
        JitRuntimeSymbolAddressCandidate,
        NixJitRuntimeSymbolAddressProvenance,
    ),
    NixJitRuntimeSymbolAddressCandidateError,
> {
    if let Some(native_wrapper) = native_wrappers.get(binding.symbol_name()).copied() {
        let candidate = jit_address_candidate_for_runtime_ffi_native_wrapper(native_wrapper)?;
        let provenance = NixJitRuntimeSymbolAddressProvenance::runtime_ffi_native_wrapper(
            &candidate,
            native_wrapper.remaining_export_blockers(),
        );
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
    binding: RuntimeNativeWrapperBinding,
) -> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let raw = binding.address().as_ptr() as usize;
    let address = JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress {
            symbol_name: binding.symbol_name(),
        },
    )?);

    Ok(JitRuntimeSymbolAddressCandidate::new(
        binding.symbol_name().to_owned(),
        RuntimeSymbolKind::Helper(binding.role()),
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

fn runtime_native_wrappers_by_symbol()
-> Result<BTreeMap<&'static str, RuntimeNativeWrapperBinding>, RuntimeSymbolNameError> {
    Ok(runtime_native_wrapper_bindings()?
        .into_iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect())
}

#[cfg(test)]
mod provenance_tests {
    use ratchet_oracle::runtime::{
        alloc::RuntimeAllocationNativeExportBlocker, apply::RuntimeApplyNativeExportBlocker,
        attr::RuntimeAttrAccessNativeExportBlocker,
        barrier::RuntimeWriteBarrierNativeExportBlocker, env::RuntimeEnvAccessNativeExportBlocker,
        forcing::RuntimeForcingNativeExportBlocker,
        helpers::RuntimeSymbolNativeExportMissingBinding,
    };

    use super::*;

    #[test]
    fn jit_runtime_symbol_address_provenance_exposes_runtime_ffi_export_blockers() {
        let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let attrs = preflight
            .address_provenance_for_symbol("aos_alloc_attrs")
            .expect("attrs allocation provenance exists");
        let thunk = preflight
            .address_provenance_for_symbol("aos_alloc_thunk")
            .expect("thunk allocation provenance exists");

        assert!(attrs.is_runtime_ffi_native_wrapper());
        assert!(matches!(
            attrs.runtime_ffi_remaining_export_blockers(),
            Some(RuntimeNativeWrapperBlockers::Allocation(blockers))
                if blockers.contains(
                    &RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented
                )
                    && blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented
                    )
                    && blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized
                    )
                    && !blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper
                    )
                    && !blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                    )
        ));
        assert!(matches!(
            thunk.runtime_ffi_remaining_export_blockers(),
            Some(RuntimeNativeWrapperBlockers::Allocation(blockers))
                if blockers.contains(
                    &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                )
                    && !blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper
                    )
        ));

        let registration = nix_jit_runtime_symbol_registration_preflight()
            .expect("Nix JIT registration preflight builds");
        assert!(
            registration
                .native_export_gap_for_symbol("aos_alloc_attrs")
                .is_some_and(
                    |gap| gap
                        .missing_exported_allocation_blockers()
                        .is_some_and(|blockers| blockers.contains(
                            &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper
                        ))
                )
        );
        assert!(
            registration
                .address_provenance_gap_for_symbol("aos_alloc_attrs")
                .is_none()
        );

        let binding = runtime_symbol_rust_callable_preflight()
            .expect("oracle Rust-callable preflight builds")
            .helper_callables()
            .iter()
            .copied()
            .find(|binding| binding.symbol_name() == "aos_env_get")
            .expect("oracle env Rust callable exists");
        let (_, fallback_provenance) =
            jit_address_candidate_for_helper_binding(binding, &BTreeMap::new())
                .expect("fallback Rust-callable candidate builds");

        assert!(fallback_provenance.is_rust_callable_helper());
        assert!(
            fallback_provenance
                .runtime_ffi_remaining_export_blockers()
                .is_none()
        );
    }

    #[test]
    fn jit_runtime_symbol_address_provenance_preserves_family_export_gate_split() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let registration_preflight = nix_jit_runtime_symbol_registration_preflight()
            .expect("Nix JIT registration preflight builds");
        let native_wrappers =
            runtime_native_wrapper_bindings().expect("runtime FFI wrapper manifest builds");

        for binding in native_wrappers {
            let provenance = candidate_preflight
                .address_provenance_for_symbol(binding.symbol_name())
                .expect("runtime FFI wrapper provenance exists");
            let blockers = provenance
                .runtime_ffi_remaining_export_blockers()
                .expect("runtime FFI wrapper provenance carries blockers");

            assert_eq!(provenance.kind(), RuntimeSymbolKind::Helper(binding.role()));
            assert_eq!(blockers, binding.remaining_export_blockers());
            assert!(!blockers.contains_final_exported_wrapper_blocker());
            assert!(
                registration_preflight
                    .native_export_gap_for_symbol(binding.symbol_name())
                    .is_some_and(
                        |gap| native_export_gap_contains_final_exported_wrapper_blocker(
                            gap, blockers
                        )
                    )
            );
        }
    }

    fn native_export_gap_contains_final_exported_wrapper_blocker(
        gap: &RuntimeSymbolNativeExportMissingBinding,
        provenance_blockers: RuntimeNativeWrapperBlockers,
    ) -> bool {
        match provenance_blockers {
            RuntimeNativeWrapperBlockers::Allocation(_) => gap
                .missing_exported_allocation_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
                    )
                }),
            RuntimeNativeWrapperBlockers::CallControl(_) => gap
                .missing_exported_call_control_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(&RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper)
                }),
            RuntimeNativeWrapperBlockers::AttrsetAccess(_) => gap
                .missing_exported_attrset_access_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(
                        &RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper,
                    )
                }),
            RuntimeNativeWrapperBlockers::EnvironmentAccess(_) => gap
                .missing_exported_env_access_blockers()
                .is_some_and(|blockers| {
                    blockers
                        .contains(&RuntimeEnvAccessNativeExportBlocker::MissingFinalExportedWrapper)
                }),
            RuntimeNativeWrapperBlockers::Forcing(_) => gap
                .missing_exported_forcing_blockers()
                .is_some_and(|blockers| {
                    blockers
                        .contains(&RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper)
                }),
            RuntimeNativeWrapperBlockers::WriteBarrier(_) => gap
                .missing_exported_write_barrier_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(
                        &RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper,
                    )
                }),
        }
    }
}

#[cfg(test)]
mod tests;
