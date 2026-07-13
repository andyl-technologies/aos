//! Integration adapters between the safe oracle runtime and JIT metadata.
//!
//! This module lives in `aos-nix` because it composes the safe
//! `ratchet-oracle` runtime metadata, the unsafe-capable `ratchet-jit` crate,
//! and the narrow `ratchet-runtime-ffi` native-wrapper crate. Covered
//! allocation, call-control, attrset-access, environment-access, forcing, and
//! write-barrier helpers come from trap-only runtime-FFI native wrappers and
//! keep their remaining native-export blockers in address provenance. The safe
//! registered native-call gate in this module still refuses to cross the unsafe
//! native-call boundary until the strict exported runtime-symbol registration
//! plan is complete. The separate literal conformance precursor uses
//! `ratchet-jit`'s reviewed no-import thunk-call path only, so it does not
//! dereference or call registered helper addresses.

use ratchet_core::{Ir, IrArena, IrId};
use ratchet_jit::{
    JitCompiledCodePointer, JitCraneliftRegisteredTier1PromotionPreflight,
    JitCraneliftRegisteredTier1SlotPreflight, JitCraneliftTier1PromotionError, JitTieredCodeSlot,
    TierUpDecision, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
    jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates,
    jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
    jit_cranelift_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates,
};
use thiserror::Error;

mod conformance;
mod engine;
mod runtime_symbols;
mod thunk_install;

pub use engine::{DEFAULT_TIER1_PROMOTION_THRESHOLD, NixJitTier1Engine};

pub use conformance::{
    BindingProjectionReason, NixJitForcedEnvSlotNativeDifferentialError,
    NixJitForcedEnvSlotNativeDifferentialResult, NixJitForcedEnvSlotNativeOutcome,
    NixJitLiteralNativeDifferential, NixJitLiteralNativeDifferentialError,
    NixJitLiteralNativeDifferentialResult, NixJitTier1ConformanceGap,
    NixJitTier1ConformanceReadiness, NixJitTier1ConformanceReadinessError,
    NixJitTier1ConformanceReadinessResult, NixJitTier1DispatchAgreement,
    NixJitTier1PublishDispatchConfig, NixJitTier1PublishDispatchError,
    NixJitTier1PublishDispatchOutcome, NixJitTier1PublishDispatchResult, ShapeDifferentialError,
    ShapeDifferentialOutcome, ShapeDifferentialResult, nix_jit_apply_native_differential,
    nix_jit_arith_native_differential, nix_jit_force_aware_tier1_conformance_readiness_for_ir_root,
    nix_jit_force_aware_tier1_conformance_readiness_for_lowered_ir_root,
    nix_jit_forced_env_slot_native_differential, nix_jit_forced_upval_slot_native_differential,
    nix_jit_literal_native_differential_for_ir_root,
    nix_jit_static_has_attr_native_differential, nix_jit_static_select_native_differential,
    nix_jit_tier1_conformance_readiness_for_ir_root,
    nix_jit_tier1_conformance_readiness_for_lowered_ir_root,
    nix_jit_tier1_forced_env_slot_publish_dispatch, nix_jit_update_native_differential,
};
pub use runtime_symbols::{
    NixJitPreflightResult, NixJitRuntimeSymbolAddressCandidateError,
    NixJitRuntimeSymbolAddressCandidatePreflight, NixJitRuntimeSymbolAddressProvenance,
    NixJitRuntimeSymbolAddressProvenanceGap, NixJitRuntimeSymbolRegistrationError,
    NixJitRuntimeSymbolRegistrationPlan, NixJitRuntimeSymbolRegistrationPlanError,
    NixJitRuntimeSymbolRegistrationPlanResult, NixJitRuntimeSymbolRegistrationPreflight,
    NixJitRuntimeSymbolRegistrationResult, nix_jit_deopt_address_candidate,
    nix_jit_primop_call_address_candidate, nix_jit_runtime_symbol_address_candidate_preflight,
    nix_jit_runtime_symbol_registration_plan, nix_jit_runtime_symbol_registration_preflight,
    nix_jit_stack_map_enter_address_candidate, nix_jit_stack_map_exit_address_candidate,
    nix_jit_string_length_address_candidate, nix_jit_upval_get_address_candidate,
};
pub use thunk_install::{
    NixJitThunkInstallGap, NixJitThunkInstallReadiness, NixJitThunkInstallReadinessError,
    NixJitThunkInstallReadinessResult, NixJitThunkInstallRequirement,
    nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root,
    nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_lowered_ir_root,
    nix_jit_registered_tier1_thunk_install_readiness_for_ir_root,
    nix_jit_registered_tier1_thunk_install_readiness_for_lowered_ir_root,
};

/// A failure while driving a Nix registered tier-1 promotion preflight.
#[derive(Debug, Error)]
pub enum NixJitRegisteredTier1PromotionError {
    /// Runtime helper addresses could not be projected into JIT metadata.
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

/// A failure while preparing a safe Nix registered native-call handoff.
#[derive(Debug, Error)]
pub enum NixJitRegisteredTier1NativeCallPreflightError {
    /// Complete exported runtime-symbol metadata is not available.
    #[error("Nix JIT runtime-symbol registration plan is not ready for native calls")]
    RuntimeSymbolRegistrationPlan {
        /// The invocation-updated slot observed before native-call gating.
        slot: JitTieredCodeSlot,
        /// The policy decision that requested a native tier-1 call.
        decision: TierUpDecision,
        /// The underlying strict runtime-symbol registration plan failure.
        source: NixJitRuntimeSymbolRegistrationPlanError,
    },
}

impl NixJitRegisteredTier1NativeCallPreflightError {
    /// Returns the invocation-updated slot from the failed native-call preflight.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        match self {
            Self::RuntimeSymbolRegistrationPlan { slot, .. } => slot,
        }
    }

    /// Returns the tier-up policy decision made by the failed preflight.
    pub const fn decision(&self) -> TierUpDecision {
        match self {
            Self::RuntimeSymbolRegistrationPlan { decision, .. } => *decision,
        }
    }

    /// Returns the strict runtime-symbol registration plan error.
    pub const fn runtime_symbol_registration_plan_error(
        &self,
    ) -> &NixJitRuntimeSymbolRegistrationPlanError {
        match self {
            Self::RuntimeSymbolRegistrationPlan { source, .. } => source,
        }
    }
}

/// Safe readiness state for a Nix registered native tier-1 call.
#[derive(Debug)]
pub enum NixJitRegisteredTier1NativeCallPreflight {
    /// Policy kept execution in the current tier before native-call planning.
    StayedInTier {
        /// The invocation-updated slot.
        slot: JitTieredCodeSlot,
        /// The policy decision that kept the slot cold.
        decision: TierUpDecision,
    },

    /// Complete exported runtime-symbol metadata is ready for a future handoff.
    RuntimeSymbolsReady {
        /// The invocation-updated slot.
        slot: JitTieredCodeSlot,
        /// The policy decision that requested native tier-1 execution.
        decision: TierUpDecision,
        /// The strict runtime-symbol registration plan required before native calls.
        registration_plan: NixJitRuntimeSymbolRegistrationPlan,
    },
}

impl NixJitRegisteredTier1NativeCallPreflight {
    /// Returns the tier-up policy decision made by this preflight.
    pub const fn decision(&self) -> TierUpDecision {
        match self {
            Self::StayedInTier { decision, .. } | Self::RuntimeSymbolsReady { decision, .. } => {
                *decision
            }
        }
    }

    /// Returns the invocation-updated tiered-code slot.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        match self {
            Self::StayedInTier { slot, .. } | Self::RuntimeSymbolsReady { slot, .. } => slot,
        }
    }

    /// Returns true when this preflight carries complete runtime-symbol metadata.
    pub const fn has_runtime_symbol_registration_plan(&self) -> bool {
        matches!(self, Self::RuntimeSymbolsReady { .. })
    }

    /// Returns false because `aos-nix` never calls native code from this safe gate.
    pub const fn did_call_native_code(&self) -> bool {
        false
    }

    /// Returns the strict runtime-symbol registration plan, when it is ready.
    pub const fn runtime_symbol_registration_plan(
        &self,
    ) -> Option<&NixJitRuntimeSymbolRegistrationPlan> {
        match self {
            Self::StayedInTier { .. } => None,
            Self::RuntimeSymbolsReady {
                registration_plan, ..
            } => Some(registration_plan),
        }
    }
}

/// Result returned by safe Nix registered native-call preflights.
pub type NixJitRegisteredTier1NativeCallPreflightResult =
    Result<NixJitRegisteredTier1NativeCallPreflight, NixJitRegisteredTier1NativeCallPreflightError>;

/// Drives registered tier-1 promotion using runtime address candidates.
///
/// This is the `aos-nix` integration handoff between the safe oracle runtime
/// metadata and the JIT crate. It derives process-local helper address
/// candidates, then delegates to the registered-symbol tier-1 promotion
/// preflight. Current bounded roots can include local environment slots and
/// direct local-slot applications, so promotion may register `aos_env_get` alone
/// or `aos_env_get` plus `aos_apply`. The returned preflight owns only safe tier
/// metadata and Cranelift module ownership; it does not publish into evaluator
/// thunk state, cast or call compiled code pointers, or call registered runtime
/// helper addresses.
/// Candidate projection runs only after the policy decision requests tier 1, so
/// a cold attempt can record its invocation and stay in tier 0 without requiring
/// helper-address metadata.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT registration metadata.
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

/// Drives registered tier-1 promotion for a full lowered IR root.
///
/// This is the full-IR counterpart to
/// [`nix_jit_registered_tier1_promotion_preflight_for_ir_root`]. It preserves
/// the arena-only bounded root set and additionally lets the JIT selector lower
/// bounded static attr selections using the lowered IR's attr-path side tables.
/// Candidate projection remains lazy and runs only after the tier-up policy
/// requests promotion.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT registration metadata.
/// Returns [`NixJitRegisteredTier1PromotionError::Cranelift`] when policy
/// requests tier-1 promotion but full-IR lowering, registration, finalization,
/// or slot installation fails.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates`]
/// when policy requests promotion.
pub fn nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
) -> NixJitRegisteredTier1PromotionResult {
    nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidate_source(
        slot,
        policy,
        demand_hint,
        ir,
        root,
        nix_jit_runtime_symbol_address_candidate_preflight,
    )
}

/// Drives force-aware registered tier-1 promotion using runtime address candidates.
///
/// This is the `aos-nix` bridge for the JIT crate's force-aware promotion
/// preflight. It keeps the existing literal promotion behavior, but local
/// environment-slot roots lower through a forced env-slot artifact that imports
/// `aos_env_get` and `aos_force`, while direct local-slot apply roots preserve
/// the `aos_apply` helper boundary and import `aos_env_get` plus `aos_apply`.
/// The current runtime address candidates include those imported helpers, so
/// hot bounded roots can finalize and install opaque tier-1 pointer metadata
/// while native calls remain gated by the strict aggregate readiness plan.
///
/// Candidate projection runs only after the policy decision requests tier 1, so
/// a cold attempt can record its invocation and stay in tier 0 without requiring
/// helper-address metadata.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT registration metadata.
/// Returns [`NixJitRegisteredTier1PromotionError::Cranelift`] when policy
/// requests tier-1 promotion but lowering, registration, finalization, or slot
/// installation fails.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates`]
/// when policy requests promotion for a finalizable artifact.
pub fn nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
) -> NixJitRegisteredTier1PromotionResult {
    nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
        slot,
        policy,
        demand_hint,
        arena,
        root,
        nix_jit_runtime_symbol_address_candidate_preflight,
    )
}

/// Drives force-aware registered tier-1 promotion for a full lowered IR root.
///
/// This is the full-IR counterpart to
/// [`nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root`].
/// It keeps the existing literal, forced local-slot, and direct local-slot
/// application behavior, and additionally allows bounded static attr selections
/// to finalize with runtime-derived attr-helper candidates. Static select
/// roots without defaults require `aos_env_get`, `aos_force`, and
/// `aos_select_ic`; static select roots with scalar defaults also require
/// `aos_has_attr` for the missing-attribute probe.
///
/// Candidate projection runs only after the policy decision requests tier 1, so
/// a cold attempt can record its invocation and stay in tier 0 without requiring
/// helper-address metadata.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT registration metadata.
/// Returns [`NixJitRegisteredTier1PromotionError::Cranelift`] when policy
/// requests tier-1 promotion but full-IR lowering, registration, finalization,
/// or slot installation fails.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates`]
/// when policy requests promotion for a finalizable artifact.
pub fn nix_jit_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
) -> NixJitRegisteredTier1PromotionResult {
    nix_jit_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidate_source(
        slot,
        policy,
        demand_hint,
        ir,
        root,
        nix_jit_runtime_symbol_address_candidate_preflight,
    )
}

/// Builds a safe registered tier-1 install plan for an IR root.
///
/// This composes the `aos-nix` registered promotion bridge with a handoff object
/// that can later feed evaluator thunk-state integration. A cold result records
/// the invocation and carries the updated slot. A promoted result additionally
/// owns the registered Cranelift tier-1 preflight and its encapsulated module;
/// bounded local-slot apply roots retain registered `aos_env_get` and
/// `aos_apply` metadata in that owned preflight. The plan still does not mutate
/// evaluator heap state, cast or call the code pointer, dereference registered
/// helper addresses, or call native code.
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

/// Builds a safe registered tier-1 install plan for a full lowered IR root.
///
/// This composes the full-IR `aos-nix` registered promotion bridge with the
/// safe install handoff object used by the arena-only path. Bounded static attr
/// selections can produce pointer/module-owner metadata when their runtime
/// helper candidates are available. The plan still does not mutate evaluator
/// heap state, cast or call the code pointer, dereference registered helper
/// addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError`] under the same conditions as
/// [`nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root`].
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root`] when
/// policy requests promotion.
pub fn nix_jit_registered_tier1_install_plan_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
) -> NixJitRegisteredTier1InstallPlanResult {
    nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root(
        slot,
        policy,
        demand_hint,
        ir,
        root,
    )
    .map(NixJitRegisteredTier1InstallPlan::from_promotion_preflight)
}

/// Builds a force-aware safe registered tier-1 install plan for an IR root.
///
/// This composes the force-aware registered promotion bridge with the same safe
/// handoff object used by the existing registered install-plan path. Literal
/// roots can produce a ready plan. Local environment-slot roots lower through
/// the forced env-slot artifact and can produce the same safe pointer/module
/// owner plan with registered `aos_env_get` and `aos_force` helper metadata.
/// Direct local-slot apply roots can produce the same safe plan with registered
/// `aos_env_get` and `aos_apply` helper metadata. The plan still does not mutate
/// evaluator heap state, cast or call the code pointer, dereference registered
/// helper addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError`] under the same conditions as
/// [`nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root`].
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root`] when
/// policy requests promotion for a finalizable artifact.
pub fn nix_jit_force_aware_registered_tier1_install_plan_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
) -> NixJitRegisteredTier1InstallPlanResult {
    nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        slot,
        policy,
        demand_hint,
        arena,
        root,
    )
    .map(NixJitRegisteredTier1InstallPlan::from_promotion_preflight)
}

/// Builds a force-aware safe registered tier-1 install plan for a full lowered IR root.
///
/// This composes the full-IR force-aware promotion bridge with the same safe
/// install handoff object used by the existing force-aware path. Bounded static
/// attr selections can produce a ready pointer/module-owner plan with registered
/// `aos_env_get`, `aos_force`, and attr-helper metadata. Default-bearing static
/// selects additionally carry `aos_has_attr` metadata before the plan reaches
/// future evaluator-thunk installation. The plan still does not mutate evaluator
/// heap state, cast or call the code pointer, dereference registered helper
/// addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRegisteredTier1PromotionError`] under the same conditions as
/// [`nix_jit_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root`].
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root`]
/// when policy requests promotion for a finalizable artifact.
pub fn nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
) -> NixJitRegisteredTier1InstallPlanResult {
    nix_jit_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root(
        slot,
        policy,
        demand_hint,
        ir,
        root,
    )
    .map(NixJitRegisteredTier1InstallPlan::from_promotion_preflight)
}

/// Safely preflights a force-aware registered tier-1 native call for a Nix IR root.
///
/// This is the `aos-nix` gate in front of the unsafe registered native-call
/// boundary owned by `ratchet-jit`. It records one tier-up invocation and
/// preserves cold behavior without deriving runtime-symbol metadata, lowering
/// IR, finalizing code, casting code pointers, or calling native code. Once
/// policy requests promotion, it requires the strict
/// [`NixJitRuntimeSymbolRegistrationPlan`] so the current mixed runtime helper
/// address candidates cannot reach finalized native code before native exports
/// and remaining non-final address provenance are complete.
///
/// # Errors
///
/// Returns
/// [`NixJitRegisteredTier1NativeCallPreflightError::RuntimeSymbolRegistrationPlan`]
/// when policy requests native tier-1 execution but complete exported
/// runtime-symbol registration metadata is not ready.
pub fn nix_jit_force_aware_registered_tier1_native_call_preflight_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
) -> NixJitRegisteredTier1NativeCallPreflightResult {
    nix_jit_force_aware_registered_tier1_native_call_preflight_for_ir_root_with_registration_plan_source(
        slot,
        policy,
        demand_hint,
        arena,
        root,
        nix_jit_runtime_symbol_registration_plan,
    )
}

/// Safely preflights a force-aware registered tier-1 native call for a full IR root.
///
/// This is the full-IR counterpart to
/// [`nix_jit_force_aware_registered_tier1_native_call_preflight_for_ir_root`].
/// It accepts lowered IR and root identity so full-IR callers, including
/// bounded static attr-access and local-slot update roots, can use the same safe
/// `aos-nix` gate that will eventually feed the unsafe registered native-call
/// boundary. The current implementation still stops before inspecting the IR,
/// lowering, finalization, code pointer casts, and native execution: once
/// policy requests promotion, it requires the strict
/// [`NixJitRuntimeSymbolRegistrationPlan`] first.
///
/// # Errors
///
/// Returns
/// [`NixJitRegisteredTier1NativeCallPreflightError::RuntimeSymbolRegistrationPlan`]
/// when policy requests native tier-1 execution but complete exported
/// runtime-symbol registration metadata is not ready.
pub fn nix_jit_force_aware_registered_tier1_native_call_preflight_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
) -> NixJitRegisteredTier1NativeCallPreflightResult {
    nix_jit_force_aware_registered_tier1_native_call_preflight_for_lowered_ir_root_with_registration_plan_source(
        slot,
        policy,
        demand_hint,
        ir,
        root,
        nix_jit_runtime_symbol_registration_plan,
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

fn nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidate_source(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
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
        jit_cranelift_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
            slot,
            policy,
            demand_hint,
            ir,
            root,
            candidates.address_candidates(),
        )?,
    )
}

fn nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
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
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            slot,
            policy,
            demand_hint,
            arena,
            root,
            candidates.address_candidates(),
        )?,
    )
}

fn nix_jit_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidate_source(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
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
        jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
            slot,
            policy,
            demand_hint,
            ir,
            root,
            candidates.address_candidates(),
        )?,
    )
}

fn nix_jit_force_aware_registered_tier1_native_call_preflight_for_ir_root_with_registration_plan_source(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    _arena: &IrArena,
    _root: IrId,
    registration_plan_source: impl FnOnce() -> NixJitRuntimeSymbolRegistrationPlanResult,
) -> NixJitRegisteredTier1NativeCallPreflightResult {
    let mut observed_slot = slot;
    let decision = observed_slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(NixJitRegisteredTier1NativeCallPreflight::StayedInTier {
            slot: observed_slot,
            decision,
        });
    }

    let registration_plan = match registration_plan_source() {
        Ok(registration_plan) => registration_plan,
        Err(source) => {
            return Err(
                NixJitRegisteredTier1NativeCallPreflightError::RuntimeSymbolRegistrationPlan {
                    slot: observed_slot,
                    decision,
                    source,
                },
            );
        }
    };

    Ok(
        NixJitRegisteredTier1NativeCallPreflight::RuntimeSymbolsReady {
            slot: observed_slot,
            decision,
            registration_plan,
        },
    )
}

fn nix_jit_force_aware_registered_tier1_native_call_preflight_for_lowered_ir_root_with_registration_plan_source(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    _ir: &Ir,
    _root: IrId,
    registration_plan_source: impl FnOnce() -> NixJitRuntimeSymbolRegistrationPlanResult,
) -> NixJitRegisteredTier1NativeCallPreflightResult {
    let mut observed_slot = slot;
    let decision = observed_slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(NixJitRegisteredTier1NativeCallPreflight::StayedInTier {
            slot: observed_slot,
            decision,
        });
    }

    let registration_plan = match registration_plan_source() {
        Ok(registration_plan) => registration_plan,
        Err(source) => {
            return Err(
                NixJitRegisteredTier1NativeCallPreflightError::RuntimeSymbolRegistrationPlan {
                    slot: observed_slot,
                    decision,
                    source,
                },
            );
        }
    };

    Ok(
        NixJitRegisteredTier1NativeCallPreflight::RuntimeSymbolsReady {
            slot: observed_slot,
            decision,
            registration_plan,
        },
    )
}

#[cfg(test)]
mod tests;
