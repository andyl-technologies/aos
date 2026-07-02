//! Integration adapters between the safe oracle runtime and JIT metadata.
//!
//! This module lives in `aos-nix` because it composes the safe
//! `ratchet-oracle` runtime metadata with the unsafe-capable `ratchet-jit`
//! crate. The addresses projected here are process-local Rust callable helper
//! addresses. They are useful for JIT registration preflights and relocation
//! plumbing tests, but they are not exported C ABI wrappers and must not be
//! called from finalized native code.

use std::num::NonZeroUsize;

use ratchet_core::{IrArena, IrId, RuntimeSymbolKind, RuntimeSymbolNameError};
use ratchet_jit::{
    JitCompiledCodePointer, JitCraneliftRegisteredTier1PromotionPreflight,
    JitCraneliftRegisteredTier1SlotPreflight, JitCraneliftTier1PromotionError,
    JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate, JitTieredCodeSlot, TierUpDecision,
    TierUpDemandHint, TierUpPolicy,
    jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
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

/// A failure while driving a Nix registered tier-1 promotion preflight.
#[derive(Debug, Error)]
pub enum NixJitRegisteredTier1PromotionError {
    /// Oracle runtime helper addresses could not be projected into JIT metadata.
    #[error(
        "JIT runtime-symbol address candidate projection failed after a tier-1 promotion decision"
    )]
    AddressCandidates {
        /// The invocation-updated slot observed before candidate projection.
        slot: JitTieredCodeSlot,
        /// The policy decision that requested tier-1 promotion.
        decision: TierUpDecision,
        /// The underlying address-candidate projection failure.
        source: NixJitRuntimeSymbolAddressCandidateError,
    },

    /// Cranelift registered-symbol promotion failed after policy requested tier 1.
    #[error(transparent)]
    Cranelift(#[from] JitCraneliftTier1PromotionError),
}

impl NixJitRegisteredTier1PromotionError {
    /// Returns the invocation-updated slot from the failed promotion attempt.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        match self {
            Self::AddressCandidates { slot, .. } => slot,
            Self::Cranelift(source) => source.slot(),
        }
    }

    /// Returns the policy decision that requested tier-1 promotion.
    pub const fn decision(&self) -> TierUpDecision {
        match self {
            Self::AddressCandidates { decision, .. } => *decision,
            Self::Cranelift(source) => source.decision(),
        }
    }
}

/// Result returned by registered tier-1 promotion preflights.
pub type NixJitRegisteredTier1PromotionResult =
    Result<JitCraneliftRegisteredTier1PromotionPreflight, NixJitRegisteredTier1PromotionError>;

/// Safe handoff for a registered tier-1 install attempt.
///
/// This value owns the registered promotion preflight so any promoted tier-1
/// code pointer metadata remains tied to the Cranelift module owner that
/// produced it. It is a future evaluator-thunk install handoff only: it does
/// not publish into heap state, perform an atomic compare-and-swap, cast the
/// code pointer to a function, dereference registered helper addresses, or call
/// native code.
pub struct NixJitRegisteredTier1InstallPlan {
    promotion_preflight: JitCraneliftRegisteredTier1PromotionPreflight,
}

impl NixJitRegisteredTier1InstallPlan {
    /// Wraps one registered promotion preflight as an evaluator install handoff.
    pub fn from_promotion_preflight(
        promotion_preflight: JitCraneliftRegisteredTier1PromotionPreflight,
    ) -> Self {
        Self {
            promotion_preflight,
        }
    }

    /// Returns the owned registered promotion preflight.
    pub const fn promotion_preflight(&self) -> &JitCraneliftRegisteredTier1PromotionPreflight {
        &self.promotion_preflight
    }

    /// Returns the policy decision made for this install attempt.
    pub const fn decision(&self) -> TierUpDecision {
        self.promotion_preflight.decision()
    }

    /// Returns true when this attempt produced tier-1 code metadata.
    pub const fn did_compile(&self) -> bool {
        self.promotion_preflight.did_compile()
    }

    /// Returns true when tier-1 pointer metadata is ready for future thunk install.
    pub fn is_ready_for_install(&self) -> bool {
        self.did_compile() && self.tier1_code_ptr().is_some() && self.owns_encapsulated_module()
    }

    /// Returns the updated safe tiered-code slot.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        self.promotion_preflight.slot()
    }

    /// Returns opaque tier-1 code pointer metadata, when promotion compiled.
    ///
    /// The returned pointer is not callable, and its validity remains bounded by
    /// the module owner kept inside this plan.
    pub const fn tier1_code_ptr(&self) -> Option<JitCompiledCodePointer> {
        self.slot().tier1_code_ptr()
    }

    /// Returns the promoted registered tier-1 preflight when compilation occurred.
    pub const fn promoted_preflight(&self) -> Option<&JitCraneliftRegisteredTier1SlotPreflight> {
        self.promotion_preflight.promoted_preflight()
    }

    /// Returns true when this plan owns the Cranelift module backing the pointer.
    pub fn owns_encapsulated_module(&self) -> bool {
        self.promotion_preflight.owns_encapsulated_module()
    }
}

/// Result returned by registered tier-1 install-plan preflights.
pub type NixJitRegisteredTier1InstallPlanResult =
    Result<NixJitRegisteredTier1InstallPlan, NixJitRegisteredTier1PromotionError>;

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

/// Drives registered tier-1 promotion using oracle-derived helper addresses.
///
/// This is the `aos-nix` integration handoff between the safe oracle runtime
/// metadata and the JIT crate. It derives process-local helper address
/// candidates, then delegates to the registered-symbol tier-1 promotion
/// preflight. The returned preflight owns only safe tier metadata and Cranelift
/// module ownership; it does not publish into evaluator thunk state, cast or
/// call compiled code pointers, or call registered runtime helper addresses.
/// Candidate projection runs only after the policy decision requests tier 1, so
/// a cold attempt can record its invocation and stay in tier 0 without requiring
/// helper-address metadata.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError::AddressCandidates`] when
/// oracle helper addresses cannot be projected into JIT registration metadata.
/// Returns [`NixJitRegisteredTier1PromotionError::Cranelift`] when policy
/// requests tier-1 promotion but lowering, registration, finalization, or slot
/// installation fails.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates`]
/// when policy requests promotion.
pub fn nix_jit_registered_tier1_promotion_preflight_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
) -> NixJitRegisteredTier1PromotionResult {
    nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
        slot,
        policy,
        demand_hint,
        arena,
        root,
        nix_jit_runtime_symbol_address_candidate_preflight,
    )
}

/// Builds a safe registered tier-1 install plan for an IR root.
///
/// This composes the `aos-nix` registered promotion bridge with a handoff object
/// that can later feed evaluator thunk-state integration. A cold result records
/// the invocation and carries the updated slot. A promoted result additionally
/// owns the registered Cranelift tier-1 preflight and its encapsulated module.
/// The plan still does not mutate evaluator heap state, cast or call the code
/// pointer, dereference registered helper addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError`] under the same conditions as
/// [`nix_jit_registered_tier1_promotion_preflight_for_ir_root`].
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_registered_tier1_promotion_preflight_for_ir_root`] when policy
/// requests promotion.
pub fn nix_jit_registered_tier1_install_plan_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
) -> NixJitRegisteredTier1InstallPlanResult {
    nix_jit_registered_tier1_promotion_preflight_for_ir_root(slot, policy, demand_hint, arena, root)
        .map(NixJitRegisteredTier1InstallPlan::from_promotion_preflight)
}

fn nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    candidate_source: impl FnOnce() -> NixJitPreflightResult,
) -> NixJitRegisteredTier1PromotionResult {
    let mut observed_slot = slot.clone();
    let decision = observed_slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(
            JitCraneliftRegisteredTier1PromotionPreflight::StayedInTier {
                slot: observed_slot,
                decision,
            },
        );
    }

    let candidates = candidate_source().map_err(|source| {
        NixJitRegisteredTier1PromotionError::AddressCandidates {
            slot: observed_slot,
            decision,
            source,
        }
    })?;

    Ok(
        jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            slot,
            policy,
            demand_hint,
            arena,
            root,
            candidates.address_candidates(),
        )?,
    )
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
