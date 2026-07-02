//! Runtime-symbol metadata bridged from oracle helpers into JIT preflights.

use std::num::NonZeroUsize;

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
    runtime_symbol_rust_callable_preflight,
};
use thiserror::Error;

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
}

/// Result returned by JIT runtime-symbol address-candidate preflights.
pub type NixJitPreflightResult =
    Result<NixJitRuntimeSymbolAddressCandidatePreflight, NixJitRuntimeSymbolAddressCandidateError>;

/// A failure while building Nix JIT runtime-symbol registration metadata.
#[derive(Debug, Error)]
pub enum NixJitRuntimeSymbolRegistrationError {
    /// Oracle runtime helper addresses could not be projected into JIT metadata.
    #[error("JIT runtime-symbol address candidate projection failed")]
    AddressCandidates(#[from] NixJitRuntimeSymbolAddressCandidateError),

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
    /// Oracle runtime helper addresses could not be projected into JIT metadata.
    #[error("JIT runtime-symbol address candidate projection failed")]
    AddressCandidates(#[from] NixJitRuntimeSymbolAddressCandidateError),

    /// JIT runtime-symbol registration metadata could not be built.
    #[error("JIT runtime-symbol registration preflight failed")]
    Registration(#[from] JitRuntimeSymbolRegistrationError),

    /// Some runtime symbols cannot yet be registered with native addresses.
    #[error(
        "Nix JIT runtime-symbol registration metadata is incomplete: {missing_count} symbol(s) missing"
    )]
    Incomplete {
        /// The number of runtime symbols still missing registration metadata.
        missing_count: usize,
        /// The preserved Nix preflight report, including oracle address candidates.
        preflight: NixJitRuntimeSymbolRegistrationPreflight,
    },
}

impl From<NixJitRuntimeSymbolRegistrationError> for NixJitRuntimeSymbolRegistrationPlanError {
    fn from(error: NixJitRuntimeSymbolRegistrationError) -> Self {
        match error {
            NixJitRuntimeSymbolRegistrationError::AddressCandidates(source) => {
                Self::AddressCandidates(source)
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

/// Nix runtime-symbol registration readiness assembled from oracle helper addresses.
///
/// This report owns the address-candidate preflight that fed the JIT
/// registration preflight, so callers can compare bound JIT addresses with the
/// oracle-derived source metadata. It still does not call `JITBuilder::symbol`,
/// export C ABI wrappers, dereference registered addresses, or call native code.
#[derive(Clone, Debug, PartialEq)]
pub struct NixJitRuntimeSymbolRegistrationPreflight {
    address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
    registration_preflight: JitRuntimeSymbolRegistrationPreflight,
}

impl NixJitRuntimeSymbolRegistrationPreflight {
    fn new(
        address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
        registration_preflight: JitRuntimeSymbolRegistrationPreflight,
    ) -> Self {
        Self {
            address_candidate_preflight,
            registration_preflight,
        }
    }

    /// Returns the address-candidate preflight used for registration metadata.
    pub const fn address_candidate_preflight(
        &self,
    ) -> &NixJitRuntimeSymbolAddressCandidatePreflight {
        &self.address_candidate_preflight
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

    /// Returns true when every stable runtime symbol has registration metadata.
    pub fn is_complete(&self) -> bool {
        self.registration_preflight.is_complete()
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

    fn into_parts(
        self,
    ) -> (
        NixJitRuntimeSymbolAddressCandidatePreflight,
        JitRuntimeSymbolRegistrationPreflight,
    ) {
        (
            self.address_candidate_preflight,
            self.registration_preflight,
        )
    }
}

/// Complete Nix runtime-symbol registration metadata assembled from oracle addresses.
///
/// This plan owns the address-candidate preflight that fed the JIT registration
/// plan. It is still metadata for a future `JITBuilder::symbol` pass: it does
/// not export C ABI wrappers, finalize code, dereference helper addresses, or
/// call native code.
#[derive(Clone, Debug, PartialEq)]
pub struct NixJitRuntimeSymbolRegistrationPlan {
    address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
    registration_plan: JitRuntimeSymbolRegistrationPlan,
}

impl NixJitRuntimeSymbolRegistrationPlan {
    fn new(
        address_candidate_preflight: NixJitRuntimeSymbolAddressCandidatePreflight,
        registration_plan: JitRuntimeSymbolRegistrationPlan,
    ) -> Self {
        Self {
            address_candidate_preflight,
            registration_plan,
        }
    }

    /// Returns the address-candidate preflight used for registration metadata.
    pub const fn address_candidate_preflight(
        &self,
    ) -> &NixJitRuntimeSymbolAddressCandidatePreflight {
        &self.address_candidate_preflight
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

/// Process-local JIT address candidates derived from oracle helper callables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NixJitRuntimeSymbolAddressCandidatePreflight {
    address_candidates: Vec<JitRuntimeSymbolAddressCandidate>,
    missing_bindings: Vec<RuntimeSymbolMissingBinding>,
}

impl NixJitRuntimeSymbolAddressCandidatePreflight {
    fn new(
        address_candidates: Vec<JitRuntimeSymbolAddressCandidate>,
        missing_bindings: Vec<RuntimeSymbolMissingBinding>,
    ) -> Self {
        Self {
            address_candidates,
            missing_bindings,
        }
    }

    /// Returns JIT address candidates in runtime symbol-manifest order.
    pub fn address_candidates(&self) -> &[JitRuntimeSymbolAddressCandidate] {
        &self.address_candidates
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

    /// Returns runtime symbols that still lack Rust-callable address metadata.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has Rust-callable address metadata.
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

    /// Returns the missing binding for `symbol_name`, when present.
    pub fn missing_binding_for(&self, symbol_name: &str) -> Option<&RuntimeSymbolMissingBinding> {
        self.missing_bindings
            .iter()
            .find(|missing| missing.symbol_name() == symbol_name)
    }
}

/// Builds process-local JIT address candidates from oracle Rust callables.
///
/// The returned candidates intentionally use current-process Rust helper
/// callable addresses, not exported native ABI wrappers. They let integration
/// code exercise JIT registration and relocation plumbing while keeping the
/// actual native call boundary disabled.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be projected into oracle Rust-callable metadata. Returns
/// [`NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress`] if a helper
/// binding violates the non-null address invariant before it reaches the JIT
/// registration metadata.
pub fn nix_jit_runtime_symbol_address_candidate_preflight() -> NixJitPreflightResult {
    let oracle_preflight = runtime_symbol_rust_callable_preflight()?;
    let address_candidates = oracle_preflight
        .helper_callables()
        .iter()
        .copied()
        .map(jit_address_candidate_for_helper_callable)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(NixJitRuntimeSymbolAddressCandidatePreflight::new(
        address_candidates,
        oracle_preflight.missing_bindings().to_vec(),
    ))
}

/// Builds JIT runtime-symbol registration readiness from oracle helper addresses.
///
/// This top-level integration preflight derives process-local oracle helper
/// address candidates and feeds them into the JIT runtime-symbol registration
/// preflight. The returned report owns both sides of that handoff for tests and
/// later install planning. It still does not call `JITBuilder::symbol`, export C
/// ABI wrappers, finalize code, dereference helper addresses, or call native
/// code.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolRegistrationError::AddressCandidates`] when
/// oracle helper addresses cannot be projected into JIT candidate metadata.
/// Returns [`NixJitRuntimeSymbolRegistrationError::Registration`] when JIT
/// registration metadata cannot be built from the candidate set.
pub fn nix_jit_runtime_symbol_registration_preflight() -> NixJitRuntimeSymbolRegistrationResult {
    let address_candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()?;
    let registration_preflight = jit_runtime_symbol_registration_preflight_with_candidates(
        address_candidate_preflight.address_candidates(),
    )?;
    Ok(NixJitRuntimeSymbolRegistrationPreflight::new(
        address_candidate_preflight,
        registration_preflight,
    ))
}

/// Builds complete JIT runtime-symbol registration metadata from oracle helper addresses.
///
/// This strict gate derives process-local oracle helper address candidates,
/// builds the JIT registration preflight, and succeeds only once every stable
/// runtime symbol has both declaration and address metadata. While helper and
/// builtin gaps remain, the incomplete error carries the owned Nix preflight so
/// callers can inspect both the oracle address candidates and JIT registration
/// gaps. It still does not call `JITBuilder::symbol`, export C ABI wrappers,
/// finalize code, dereference helper addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::AddressCandidates`] when
/// oracle helper addresses cannot be projected into JIT candidate metadata.
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::Registration`] when JIT
/// registration metadata cannot be built from the candidate set. Returns
/// [`NixJitRuntimeSymbolRegistrationPlanError::Incomplete`] while any stable
/// runtime symbol still lacks registration metadata.
pub fn nix_jit_runtime_symbol_registration_plan() -> NixJitRuntimeSymbolRegistrationPlanResult {
    let preflight = nix_jit_runtime_symbol_registration_preflight()?;
    let missing_count = preflight.gaps().len();
    if missing_count != 0 {
        return Err(NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
            missing_count,
            preflight,
        });
    }

    let (address_candidate_preflight, registration_preflight) = preflight.into_parts();
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
            return Err(NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
                missing_count,
                preflight: NixJitRuntimeSymbolRegistrationPreflight::new(
                    address_candidate_preflight,
                    preflight,
                ),
            });
        }
    };

    Ok(NixJitRuntimeSymbolRegistrationPlan::new(
        address_candidate_preflight,
        registration_plan,
    ))
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

fn helper_callable_address(binding: RuntimeHelperRustCallableBinding) -> *const () {
    match binding {
        RuntimeHelperRustCallableBinding::Allocation(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::EnvironmentAccess(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::WriteBarrier(binding) => binding.address().as_ptr(),
    }
}

#[cfg(test)]
mod tests;
