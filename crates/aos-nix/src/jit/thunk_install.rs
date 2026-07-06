//! Safe evaluator-thunk install-readiness reports for JIT tier-1 handoff.

use ratchet_core::{Ir, IrArena, IrId};
use ratchet_jit::{JitTieredCodeSlot, TierUpDemandHint, TierUpPolicy};
use ratchet_oracle::eval::{EvalModuleId, EvalNodeRef, EvalThunk, ForceError, ThunkState};
use thiserror::Error;

use super::{
    NixJitRegisteredTier1InstallPlan, NixJitRegisteredTier1PromotionError,
    nix_jit_force_aware_registered_tier1_install_plan_for_ir_root,
    nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root,
    nix_jit_registered_tier1_install_plan_for_ir_root,
    nix_jit_registered_tier1_install_plan_for_lowered_ir_root,
};

/// One condition required before a tier-1 thunk install may publish to the evaluator heap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NixJitThunkInstallRequirement {
    /// The tier-up attempt must produce opaque tier-1 code pointer metadata.
    Tier1CodePointer,
    /// The Cranelift module owner backing the opaque pointer must be retained.
    CraneliftModuleOwner,
    /// The target evaluator thunk must represent a lowered IR body.
    TargetThunkIrBody,
    /// The target evaluator thunk body must match the compiled module-qualified IR root.
    TargetThunkRootMatch,
    /// The target evaluator thunk must still be suspended.
    TargetThunkSuspended,
    /// The evaluator heap must store tier-slot metadata beside the thunk.
    EvaluatorThunkTierSlotStorage,
    /// The evaluator must publish a slot update through an atomic thunk-state transition.
    AtomicThunkStatePublish,
    /// The evaluator must expose a native-entry dispatch trampoline.
    NativeThunkEntryDispatch,
}

impl NixJitThunkInstallRequirement {
    /// Returns true when the requirement is an unimplemented evaluator-publish action.
    pub const fn is_future_evaluator_publish_action(self) -> bool {
        matches!(
            self,
            Self::EvaluatorThunkTierSlotStorage
                | Self::AtomicThunkStatePublish
                | Self::NativeThunkEntryDispatch
        )
    }
}

/// One missing requirement for publishing a tier-1 install plan into a thunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NixJitThunkInstallGap {
    /// The tier-up attempt did not produce opaque tier-1 code pointer metadata.
    Tier1CodeNotCompiled,
    /// The plan does not retain the module owner backing the opaque code pointer.
    CraneliftModuleOwnerMissing,
    /// The target evaluator thunk does not point at a lowered IR body.
    TargetThunkHasNoIrBody,
    /// The target evaluator thunk points at a different module-qualified IR root.
    TargetThunkRootMismatch {
        /// The module-qualified IR root that was compiled for the install plan.
        expected: EvalNodeRef,
        /// The module-qualified IR root stored in the target thunk.
        actual: EvalNodeRef,
    },
    /// The target evaluator thunk is no longer suspended.
    TargetThunkNotSuspended {
        /// The observed thunk state.
        state: ThunkState,
    },
    /// Evaluator thunk records do not yet store tier-slot metadata.
    EvaluatorThunkTierSlotStorageUnavailable,
    /// Atomic thunk-state publication has not been implemented for tier installs.
    AtomicThunkStatePublishUnavailable,
    /// Native-entry dispatch from a thunk has not been implemented.
    NativeThunkEntryDispatchUnavailable,
}

impl NixJitThunkInstallGap {
    /// Returns the requirement represented by this gap.
    pub const fn requirement(self) -> NixJitThunkInstallRequirement {
        match self {
            Self::Tier1CodeNotCompiled => NixJitThunkInstallRequirement::Tier1CodePointer,
            Self::CraneliftModuleOwnerMissing => {
                NixJitThunkInstallRequirement::CraneliftModuleOwner
            }
            Self::TargetThunkHasNoIrBody => NixJitThunkInstallRequirement::TargetThunkIrBody,
            Self::TargetThunkRootMismatch { .. } => {
                NixJitThunkInstallRequirement::TargetThunkRootMatch
            }
            Self::TargetThunkNotSuspended { .. } => {
                NixJitThunkInstallRequirement::TargetThunkSuspended
            }
            Self::EvaluatorThunkTierSlotStorageUnavailable => {
                NixJitThunkInstallRequirement::EvaluatorThunkTierSlotStorage
            }
            Self::AtomicThunkStatePublishUnavailable => {
                NixJitThunkInstallRequirement::AtomicThunkStatePublish
            }
            Self::NativeThunkEntryDispatchUnavailable => {
                NixJitThunkInstallRequirement::NativeThunkEntryDispatch
            }
        }
    }
}

/// Readiness report for a future tier-1 publish into an evaluator thunk.
///
/// The report owns the safe install plan so compiled pointer metadata remains
/// tied to its Cranelift module owner. It inspects the target thunk body and
/// state, but it never mutates heap state, performs a compare-and-swap, casts or
/// calls the code pointer, dereferences helper addresses, or calls native code.
pub struct NixJitThunkInstallReadiness {
    install_plan: NixJitRegisteredTier1InstallPlan,
    expected_body: EvalNodeRef,
    target_body: Option<EvalNodeRef>,
    target_state: ThunkState,
    gaps: Vec<NixJitThunkInstallGap>,
}

impl NixJitThunkInstallReadiness {
    /// Builds a readiness report from an existing safe install plan.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError`] if the target thunk's state word cannot be decoded.
    fn from_install_plan(
        install_plan: NixJitRegisteredTier1InstallPlan,
        expected_body: EvalNodeRef,
        target_thunk: &EvalThunk,
    ) -> Result<Self, ForceError> {
        let target_body = target_thunk.body_ref();
        let target_state = target_thunk.cell().state()?;
        let mut gaps = Vec::new();

        if install_plan.tier1_code_ptr().is_none() {
            gaps.push(NixJitThunkInstallGap::Tier1CodeNotCompiled);
        } else if !install_plan.owns_encapsulated_module() {
            gaps.push(NixJitThunkInstallGap::CraneliftModuleOwnerMissing);
        }

        match target_body {
            Some(actual) if actual == expected_body => {}
            Some(actual) => gaps.push(NixJitThunkInstallGap::TargetThunkRootMismatch {
                expected: expected_body,
                actual,
            }),
            None => gaps.push(NixJitThunkInstallGap::TargetThunkHasNoIrBody),
        }

        if target_state != ThunkState::Suspended {
            gaps.push(NixJitThunkInstallGap::TargetThunkNotSuspended {
                state: target_state,
            });
        }

        if gaps.is_empty() {
            gaps.extend([
                NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
                NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
                NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
            ]);
        }

        Ok(Self {
            install_plan,
            expected_body,
            target_body,
            target_state,
            gaps,
        })
    }

    /// Returns the safe install plan owned by this readiness report.
    pub const fn install_plan(&self) -> &NixJitRegisteredTier1InstallPlan {
        &self.install_plan
    }

    /// Consumes this readiness report and returns its safe install plan.
    pub fn into_install_plan(self) -> NixJitRegisteredTier1InstallPlan {
        self.install_plan
    }

    /// Returns the module-qualified IR root that the install plan compiled.
    pub const fn expected_body(&self) -> EvalNodeRef {
        self.expected_body
    }

    /// Returns the module-qualified lowered IR body stored in the target thunk.
    pub const fn target_body_ref(&self) -> Option<EvalNodeRef> {
        self.target_body
    }

    /// Returns the target thunk state observed by this report.
    pub const fn target_state(&self) -> ThunkState {
        self.target_state
    }

    /// Returns missing requirements for publishing into the evaluator thunk.
    pub fn gaps(&self) -> &[NixJitThunkInstallGap] {
        &self.gaps
    }

    /// Returns true when `gap` is present in this report.
    pub fn has_gap(&self, gap: NixJitThunkInstallGap) -> bool {
        self.gaps.contains(&gap)
    }

    /// Returns true when all currently implemented safe prerequisites are satisfied.
    pub fn safe_preconditions_met(&self) -> bool {
        self.gaps
            .iter()
            .all(|gap| gap.requirement().is_future_evaluator_publish_action())
    }

    /// Returns true when this report can publish tier-1 code into the evaluator heap.
    ///
    /// This is currently false for successful compile reports because the heap
    /// tier-slot storage, atomic publication, and native-entry dispatch pieces
    /// intentionally remain future work.
    pub fn is_ready_for_evaluator_publish(&self) -> bool {
        self.gaps.is_empty()
    }
}

/// A failure while building a thunk-install readiness report.
#[derive(Debug, Error)]
pub enum NixJitThunkInstallReadinessError {
    /// Building the registered tier-1 install plan failed.
    #[error(transparent)]
    Promotion(#[from] NixJitRegisteredTier1PromotionError),

    /// Inspecting the target evaluator thunk state failed.
    #[error(transparent)]
    ThunkState(#[from] ForceError),
}

/// Result returned by thunk-install readiness preflights.
pub type NixJitThunkInstallReadinessResult =
    Result<NixJitThunkInstallReadiness, NixJitThunkInstallReadinessError>;

/// Builds a safe readiness report for publishing registered tier-1 code into a thunk.
///
/// This is the evaluator-facing preflight after
/// [`super::nix_jit_registered_tier1_install_plan_for_ir_root`]. It validates
/// that a target thunk still points at the compiled IR root and is suspended,
/// then reports the remaining heap-publication gaps. It never mutates evaluator
/// heap state, performs an atomic thunk-state compare-and-swap, casts or calls a
/// code pointer, dereferences registered helper addresses, or calls native code.
///
/// # Errors
///
/// Returns [`NixJitThunkInstallReadinessError::Promotion`] if the underlying
/// registered tier-1 install plan cannot be built. Returns
/// [`NixJitThunkInstallReadinessError::ThunkState`] if the target thunk state
/// word cannot be decoded.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`super::nix_jit_registered_tier1_install_plan_for_ir_root`] when policy
/// requests promotion.
pub fn nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitThunkInstallReadinessResult {
    let install_plan =
        nix_jit_registered_tier1_install_plan_for_ir_root(slot, policy, demand_hint, arena, root)?;
    let expected_body = EvalNodeRef::new(EvalModuleId::ROOT, root);
    Ok(NixJitThunkInstallReadiness::from_install_plan(
        install_plan,
        expected_body,
        target_thunk,
    )?)
}

/// Builds a safe readiness report for publishing full-IR registered tier-1 code into a thunk.
///
/// This is the evaluator-facing preflight after
/// [`super::nix_jit_registered_tier1_install_plan_for_lowered_ir_root`]. It
/// validates that a target thunk still points at the compiled IR root and is
/// suspended, then reports the remaining heap-publication gaps. Bounded static
/// attr selections can satisfy the implemented safe prerequisites through the
/// full-IR install-plan bridge. This function never mutates evaluator heap
/// state, performs an atomic thunk-state compare-and-swap, casts or calls a code
/// pointer, dereferences registered helper addresses, or calls native code.
///
/// # Errors
///
/// Returns [`NixJitThunkInstallReadinessError::Promotion`] if the underlying
/// full-IR registered tier-1 install plan cannot be built. Returns
/// [`NixJitThunkInstallReadinessError::ThunkState`] if the target thunk state
/// word cannot be decoded.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`super::nix_jit_registered_tier1_install_plan_for_lowered_ir_root`] when
/// policy requests promotion.
pub fn nix_jit_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitThunkInstallReadinessResult {
    let install_plan = nix_jit_registered_tier1_install_plan_for_lowered_ir_root(
        slot,
        policy,
        demand_hint,
        ir,
        root,
    )?;
    let expected_body = EvalNodeRef::new(EvalModuleId::ROOT, root);
    Ok(NixJitThunkInstallReadiness::from_install_plan(
        install_plan,
        expected_body,
        target_thunk,
    )?)
}

/// Builds a safe force-aware readiness report for publishing tier-1 code into a thunk.
///
/// This is the evaluator-facing preflight after
/// [`super::nix_jit_force_aware_registered_tier1_install_plan_for_ir_root`]. It
/// validates the same read-only target-thunk conditions as the existing
/// registered readiness bridge, while sourcing the install plan from the
/// force-aware promotion path. Literal, forced local-slot, and direct
/// local-slot apply roots can satisfy the implemented safe prerequisites before
/// the report exposes future evaluator-publish gaps. It never mutates evaluator
/// heap state, performs an atomic thunk-state compare-and-swap, casts or calls a
/// code pointer, dereferences registered helper addresses, or calls native code.
///
/// # Errors
///
/// Returns [`NixJitThunkInstallReadinessError::Promotion`] if the underlying
/// force-aware registered tier-1 install plan cannot be built. Returns
/// [`NixJitThunkInstallReadinessError::ThunkState`] if the target thunk state
/// word cannot be decoded.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`super::nix_jit_force_aware_registered_tier1_install_plan_for_ir_root`] when
/// policy requests promotion and Cranelift finalizes an artifact.
pub fn nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitThunkInstallReadinessResult {
    let install_plan = nix_jit_force_aware_registered_tier1_install_plan_for_ir_root(
        slot,
        policy,
        demand_hint,
        arena,
        root,
    )?;
    let expected_body = EvalNodeRef::new(EvalModuleId::ROOT, root);
    Ok(NixJitThunkInstallReadiness::from_install_plan(
        install_plan,
        expected_body,
        target_thunk,
    )?)
}

/// Builds a safe force-aware readiness report for publishing full-IR tier-1 code into a thunk.
///
/// This is the evaluator-facing preflight after
/// [`super::nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root`].
/// It validates the same read-only target-thunk conditions as the arena-only
/// force-aware bridge, while sourcing the install plan from the full-IR
/// force-aware promotion path. Literal, forced local-slot, direct local-slot
/// apply, and bounded static attr-selection roots can satisfy the implemented
/// safe prerequisites before the report exposes future evaluator-publish gaps.
/// It never mutates evaluator heap state, performs an atomic thunk-state
/// compare-and-swap, casts or calls a code pointer, dereferences registered
/// helper addresses, or calls native code.
///
/// # Errors
///
/// Returns [`NixJitThunkInstallReadinessError::Promotion`] if the underlying
/// full-IR force-aware registered tier-1 install plan cannot be built. Returns
/// [`NixJitThunkInstallReadinessError::ThunkState`] if the target thunk state
/// word cannot be decoded.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`super::nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub fn nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitThunkInstallReadinessResult {
    let install_plan = nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root(
        slot,
        policy,
        demand_hint,
        ir,
        root,
    )?;
    let expected_body = EvalNodeRef::new(EvalModuleId::ROOT, root);
    Ok(NixJitThunkInstallReadiness::from_install_plan(
        install_plan,
        expected_body,
        target_thunk,
    )?)
}

#[cfg(test)]
mod tests;
