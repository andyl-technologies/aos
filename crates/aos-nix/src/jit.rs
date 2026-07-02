//! Integration adapters between the safe oracle runtime and JIT metadata.
//!
//! This module lives in `aos-nix` because it composes the safe
//! `ratchet-oracle` runtime metadata with the unsafe-capable `ratchet-jit`
//! crate. The addresses projected here are process-local Rust callable helper
//! addresses. They are useful for JIT registration preflights and relocation
//! plumbing tests, but they are not exported C ABI wrappers and must not be
//! called from finalized native code.

use std::num::NonZeroUsize;

use ratchet_core::{RuntimeSymbolKind, RuntimeSymbolNameError};
use ratchet_jit::{JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate};
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
mod tests {
    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, syntax::Span,
    };
    use ratchet_jit::{
        DEFAULT_TIER1_INVOCATION_THRESHOLD, JitTier, JitTieredCodeSlot, TierUpCounter,
        TierUpDemandHint, TierUpPolicy,
        jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
        jit_runtime_symbol_registration_preflight_with_candidates,
    };

    use super::*;

    #[test]
    fn jit_runtime_symbol_address_candidate_preflight_projects_oracle_helper_addresses() {
        let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");

        let env_get = preflight
            .address_candidate_for("aos_env_get")
            .expect("environment helper has a Rust-callable address candidate");

        assert_eq!(
            env_get.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess)
        );
        assert_ne!(env_get.address().as_nonzero_usize().get(), 0);
        assert!(preflight.missing_binding_for("aos_env_get").is_none());
        assert!(preflight.missing_binding_for("aos_force").is_some());
        assert!(!preflight.is_complete());
    }

    #[test]
    fn jit_runtime_symbol_address_candidates_feed_jit_registration_preflight() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");

        let registration = jit_runtime_symbol_registration_preflight_with_candidates(
            candidate_preflight.address_candidates(),
        )
        .expect("JIT registration preflight accepts oracle helper address candidates");

        assert!(
            registration
                .binding_for_symbol("aos_env_get")
                .is_some_and(|binding| binding.address()
                    == candidate_preflight
                        .address_candidate_for("aos_env_get")
                        .expect("env candidate exists")
                        .address())
        );
        assert!(registration.gap_for_symbol("aos_env_get").is_none());
        assert!(!registration.is_complete());
    }

    #[test]
    fn jit_runtime_symbol_address_candidates_feed_registered_env_promotion() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 1 },
            )],
            Vec::new(),
        );

        let promotion =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::with_counter(TierUpCounter::new(
                    DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
                )),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                candidate_preflight.address_candidates(),
            )
            .expect("registered env promotion accepts oracle helper address candidates");

        assert!(promotion.did_compile());
        assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
        let promoted = promotion
            .promoted_preflight()
            .expect("promotion owns registered preflight");
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_env_get")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_env_get")
                        .expect("env candidate exists")
                        .address())
        );
        assert!(promotion.owns_encapsulated_module());
    }
}
