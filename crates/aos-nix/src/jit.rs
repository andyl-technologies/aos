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
    JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftTier1PromotionError,
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
mod tests {
    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, syntax::Span,
    };
    use ratchet_jit::{
        DEFAULT_TIER1_INVOCATION_THRESHOLD, JitTier, JitTieredCodeSlot, TierUpCounter,
        TierUpDemandHint, TierUpPolicy, jit_runtime_symbol_registration_preflight_with_candidates,
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

    #[test]
    fn nix_jit_registered_tier1_promotion_preflight_records_cold_invocation_without_lowering() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
        )
        .expect("cold unsupported root does not lower");

        assert!(!promotion.did_compile());
        assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
        assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
        assert!(promotion.promoted_preflight().is_none());
        assert!(!promotion.owns_encapsulated_module());
    }

    #[test]
    fn nix_jit_registered_tier1_promotion_preflight_keeps_cold_path_before_candidates() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let promotion =
            nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                || {
                    Err(
                        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                            symbol_name: "aos_env_get",
                        },
                    )
                },
            )
            .expect("cold attempt returns before address candidates are needed");

        assert!(!promotion.did_compile());
        assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
        assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
    }

    #[test]
    fn nix_jit_registered_tier1_promotion_preflight_reports_candidate_failure_after_promotion() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 2 },
            )],
            Vec::new(),
        );

        let result = nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            || {
                Err(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_env_get",
                    },
                )
            },
        );

        let Err(error) = result else {
            panic!("promotion should require address candidates");
        };
        assert!(error.decision().should_promote());
        assert_eq!(
            error.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
        let NixJitRegisteredTier1PromotionError::AddressCandidates { source, .. } = error else {
            panic!("expected address candidate failure");
        };
        assert!(matches!(
            source,
            NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                symbol_name: "aos_env_get"
            }
        ));
    }

    #[test]
    fn nix_jit_registered_tier1_promotion_preflight_uses_oracle_candidates() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 2 },
            )],
            Vec::new(),
        );

        let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
        )
        .expect("aos-nix wrapper promotes env slot with oracle candidates");

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
