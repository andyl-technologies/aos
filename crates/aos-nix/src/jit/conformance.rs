//! JIT-enabled conformance readiness for the future differential harness.
//!
//! The full Phase-6 gate is byte-for-byte equivalence between tier-1 execution
//! and the tier-0 oracle across a closure. This module records the current safe
//! prerequisite state for one candidate thunk before any native execution is
//! trusted by the harness.

use ratchet_core::{IrArena, IrId};
use ratchet_jit::{JitTieredCodeSlot, TierUpDemandHint, TierUpPolicy};
use thiserror::Error;

use super::{
    NixJitRuntimeSymbolRegistrationError, NixJitRuntimeSymbolRegistrationPreflight,
    NixJitThunkInstallGap, NixJitThunkInstallReadiness, NixJitThunkInstallReadinessError,
    nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root,
    nix_jit_registered_tier1_thunk_install_readiness_for_ir_root,
    nix_jit_runtime_symbol_registration_preflight,
};
use crate::eval::EvalThunk;

/// One condition preventing a JIT-enabled differential harness from running tier 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NixJitTier1ConformanceGap {
    /// Some runtime symbols still lack JIT registration metadata.
    RuntimeSymbolRegistration {
        /// Number of JIT runtime-symbol registration gaps.
        missing_count: usize,
    },
    /// Some runtime symbols still lack exported native ABI wrappers.
    RuntimeSymbolNativeExport {
        /// Number of native-export gaps.
        missing_count: usize,
    },
    /// Runtime symbol addresses still come from non-final Rust-callable provenance.
    RuntimeSymbolAddressProvenance {
        /// Number of address-provenance gaps.
        missing_count: usize,
    },
    /// The candidate thunk cannot yet publish or enter tier-1 code.
    ThunkInstall {
        /// The thunk-install readiness gap.
        gap: NixJitThunkInstallGap,
    },
}

impl NixJitTier1ConformanceGap {
    /// Returns true when the gap is one of the evaluator publish actions still unimplemented.
    pub const fn is_future_evaluator_publish_action(self) -> bool {
        match self {
            Self::ThunkInstall { gap } => gap.requirement().is_future_evaluator_publish_action(),
            Self::RuntimeSymbolRegistration { .. }
            | Self::RuntimeSymbolNativeExport { .. }
            | Self::RuntimeSymbolAddressProvenance { .. } => false,
        }
    }
}

/// Readiness report for enabling tier-1 execution in the differential harness.
///
/// The report owns the runtime-symbol registration preflight and one
/// evaluator-thunk install readiness report. It is a gate report only: it does
/// not mutate evaluator heap state, call into finalized code, dereference helper
/// addresses, or compare native output with the oracle.
pub struct NixJitTier1ConformanceReadiness {
    runtime_symbol_registration: NixJitRuntimeSymbolRegistrationPreflight,
    thunk_install_readiness: NixJitThunkInstallReadiness,
    gaps: Vec<NixJitTier1ConformanceGap>,
}

impl NixJitTier1ConformanceReadiness {
    fn new(
        runtime_symbol_registration: NixJitRuntimeSymbolRegistrationPreflight,
        thunk_install_readiness: NixJitThunkInstallReadiness,
    ) -> Self {
        let gaps = conformance_gaps_for(&runtime_symbol_registration, &thunk_install_readiness);
        Self {
            runtime_symbol_registration,
            thunk_install_readiness,
            gaps,
        }
    }

    /// Returns the runtime-symbol registration preflight used by this report.
    pub const fn runtime_symbol_registration(&self) -> &NixJitRuntimeSymbolRegistrationPreflight {
        &self.runtime_symbol_registration
    }

    /// Returns the per-thunk install readiness report used by this gate.
    pub const fn thunk_install_readiness(&self) -> &NixJitThunkInstallReadiness {
        &self.thunk_install_readiness
    }

    /// Returns all known gaps that keep the JIT-enabled harness disabled.
    pub fn gaps(&self) -> &[NixJitTier1ConformanceGap] {
        &self.gaps
    }

    /// Returns true when `gap` is present in this readiness report.
    pub fn has_gap(&self, gap: NixJitTier1ConformanceGap) -> bool {
        self.gaps.contains(&gap)
    }

    /// Returns true when every remaining gap is an evaluator publish action.
    ///
    /// This is weaker than full readiness: the JIT-enabled harness still
    /// cannot run until [`Self::is_ready_for_jit_enabled_harness`] is true.
    pub fn safe_preconditions_met(&self) -> bool {
        self.gaps
            .iter()
            .all(|gap| gap.is_future_evaluator_publish_action())
    }

    /// Returns true when tier-1 execution can be compared by the differential harness.
    pub fn is_ready_for_jit_enabled_harness(&self) -> bool {
        self.gaps.is_empty()
    }
}

/// A failure while building JIT-enabled conformance readiness.
#[derive(Debug, Error)]
pub enum NixJitTier1ConformanceReadinessError {
    /// Runtime-symbol registration metadata could not be built.
    #[error(transparent)]
    RuntimeSymbols(#[from] NixJitRuntimeSymbolRegistrationError),

    /// The per-thunk tier-1 install readiness report could not be built.
    #[error(transparent)]
    ThunkInstall(#[from] NixJitThunkInstallReadinessError),
}

/// Result returned by tier-1 conformance readiness preflights.
pub type NixJitTier1ConformanceReadinessResult =
    Result<NixJitTier1ConformanceReadiness, NixJitTier1ConformanceReadinessError>;

/// Builds a safe JIT-enabled conformance readiness report for one IR root.
///
/// This function composes the top-level runtime-symbol registration bridge with
/// the evaluator-thunk install-readiness report for `root`. It is the current
/// harness-facing gate before tier-1 output can be compared against the tier-0
/// oracle. The returned report can only become ready once runtime symbols have
/// final exported native addresses and the evaluator can publish and dispatch
/// compiled thunk entries.
///
/// # Errors
///
/// Returns [`NixJitTier1ConformanceReadinessError::RuntimeSymbols`] when
/// runtime-symbol registration metadata cannot be built. Returns
/// [`NixJitTier1ConformanceReadinessError::ThunkInstall`] when the per-thunk
/// install-readiness report cannot be built.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_registered_tier1_thunk_install_readiness_for_ir_root`] when policy
/// requests promotion.
pub fn nix_jit_tier1_conformance_readiness_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitTier1ConformanceReadinessResult {
    let runtime_symbol_registration = nix_jit_runtime_symbol_registration_preflight()?;
    let thunk_install_readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        slot,
        policy,
        demand_hint,
        arena,
        root,
        target_thunk,
    )?;

    Ok(NixJitTier1ConformanceReadiness::new(
        runtime_symbol_registration,
        thunk_install_readiness,
    ))
}

/// Builds a safe force-aware JIT-enabled conformance readiness report for one IR root.
///
/// This function composes the top-level runtime-symbol registration bridge with
/// the force-aware evaluator-thunk install-readiness report for `root`. It is a
/// harness-facing gate only: local environment-slot roots currently surface the
/// registered-module finalization guard for forced artifacts before the returned
/// readiness report can be built. Literal roots report the same runtime-symbol
/// and evaluator publication blockers as the non-force-aware gate, while cold
/// roots preserve the no-code gap.
///
/// # Errors
///
/// Returns [`NixJitTier1ConformanceReadinessError::RuntimeSymbols`] when
/// runtime-symbol registration metadata cannot be built. Returns
/// [`NixJitTier1ConformanceReadinessError::ThunkInstall`] when the force-aware
/// per-thunk install-readiness report cannot be built.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root`]
/// when policy requests promotion for a finalizable artifact.
pub fn nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitTier1ConformanceReadinessResult {
    let runtime_symbol_registration = nix_jit_runtime_symbol_registration_preflight()?;
    let thunk_install_readiness =
        nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root(
            slot,
            policy,
            demand_hint,
            arena,
            root,
            target_thunk,
        )?;

    Ok(NixJitTier1ConformanceReadiness::new(
        runtime_symbol_registration,
        thunk_install_readiness,
    ))
}

fn conformance_gaps_for(
    runtime_symbol_registration: &NixJitRuntimeSymbolRegistrationPreflight,
    thunk_install_readiness: &NixJitThunkInstallReadiness,
) -> Vec<NixJitTier1ConformanceGap> {
    let mut gaps = Vec::new();

    push_nonzero_gap(
        &mut gaps,
        runtime_symbol_registration.gaps().len(),
        |missing_count| NixJitTier1ConformanceGap::RuntimeSymbolRegistration { missing_count },
    );
    push_nonzero_gap(
        &mut gaps,
        runtime_symbol_registration
            .native_export_missing_bindings()
            .len(),
        |missing_count| NixJitTier1ConformanceGap::RuntimeSymbolNativeExport { missing_count },
    );
    push_nonzero_gap(
        &mut gaps,
        runtime_symbol_registration.address_provenance_gaps().len(),
        |missing_count| NixJitTier1ConformanceGap::RuntimeSymbolAddressProvenance { missing_count },
    );
    gaps.extend(
        thunk_install_readiness
            .gaps()
            .iter()
            .copied()
            .map(|gap| NixJitTier1ConformanceGap::ThunkInstall { gap }),
    );

    gaps
}

fn push_nonzero_gap(
    gaps: &mut Vec<NixJitTier1ConformanceGap>,
    missing_count: usize,
    gap: impl FnOnce(usize) -> NixJitTier1ConformanceGap,
) {
    if missing_count != 0 {
        gaps.push(gap(missing_count));
    }
}

#[cfg(test)]
mod tests {
    use crate::jit::NixJitRegisteredTier1PromotionError;

    use ratchet_core::{EffectClass, IrData, IrKind, IrNode, syntax::Span};
    use ratchet_jit::{
        DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCraneliftModuleSetupError, JitTier, TierUpCounter,
    };

    use super::*;

    fn local_var_arena(slot: u32) -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot },
            )],
            Vec::new(),
        )
    }

    fn string_arena() -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        )
    }

    fn bool_arena(value: bool) -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(value),
            )],
            Vec::new(),
        )
    }

    fn hot_slot() -> JitTieredCodeSlot {
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1))
    }

    #[test]
    fn tier1_conformance_readiness_reports_current_runtime_and_publish_gaps() {
        let arena = local_var_arena(3);
        let thunk = EvalThunk::new(IrId::new(0));

        let readiness = nix_jit_tier1_conformance_readiness_for_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &thunk,
        )
        .expect("JIT conformance readiness report builds");

        assert!(
            readiness
                .thunk_install_readiness()
                .install_plan()
                .did_compile()
        );
        assert_eq!(
            readiness
                .thunk_install_readiness()
                .install_plan()
                .slot()
                .current_tier(),
            JitTier::Tier1Baseline
        );
        assert!(!readiness.is_ready_for_jit_enabled_harness());
        assert!(!readiness.safe_preconditions_met());
        assert!(readiness.runtime_symbol_registration().gaps().len() > 0);
        assert!(
            readiness
                .runtime_symbol_registration()
                .native_export_missing_bindings()
                .len()
                > 0
        );
        assert!(
            readiness
                .runtime_symbol_registration()
                .address_provenance_gaps()
                .len()
                > 0
        );
        assert!(
            readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolRegistration {
                missing_count: readiness.runtime_symbol_registration().gaps().len(),
            })
        );
        assert!(
            readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolNativeExport {
                missing_count: readiness
                    .runtime_symbol_registration()
                    .native_export_missing_bindings()
                    .len(),
            })
        );
        assert!(
            readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolAddressProvenance {
                missing_count: readiness
                    .runtime_symbol_registration()
                    .address_provenance_gaps()
                    .len(),
            })
        );
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
        }));
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
        }));
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        }));
    }

    #[test]
    fn tier1_conformance_readiness_keeps_cold_no_compile_gap() {
        let arena = string_arena();
        let thunk = EvalThunk::new(IrId::new(0));

        let readiness = nix_jit_tier1_conformance_readiness_for_ir_root(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &thunk,
        )
        .expect("cold JIT conformance readiness report builds");

        assert!(
            !readiness
                .thunk_install_readiness()
                .install_plan()
                .did_compile()
        );
        assert!(!readiness.is_ready_for_jit_enabled_harness());
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::Tier1CodeNotCompiled,
        }));
        assert_eq!(
            readiness
                .thunk_install_readiness()
                .install_plan()
                .slot()
                .invocation_counter()
                .invocations(),
            1
        );
    }

    #[test]
    fn force_aware_tier1_conformance_readiness_reports_literal_publish_gaps() {
        let arena = bool_arena(true);
        let thunk = EvalThunk::new(IrId::new(0));

        let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(0),
            &thunk,
        )
        .expect("force-aware literal JIT conformance readiness report builds");

        assert!(
            readiness
                .thunk_install_readiness()
                .install_plan()
                .did_compile()
        );
        assert_eq!(
            readiness
                .thunk_install_readiness()
                .install_plan()
                .slot()
                .current_tier(),
            JitTier::Tier1Baseline
        );
        assert!(!readiness.is_ready_for_jit_enabled_harness());
        assert!(!readiness.safe_preconditions_met());
        assert!(
            readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolRegistration {
                missing_count: readiness.runtime_symbol_registration().gaps().len(),
            })
        );
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
        }));
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
        }));
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        }));
    }

    #[test]
    fn force_aware_tier1_conformance_readiness_keeps_cold_no_compile_gap() {
        let arena = string_arena();
        let thunk = EvalThunk::new(IrId::new(0));

        let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &thunk,
        )
        .expect("cold force-aware JIT conformance readiness report builds");

        assert!(
            !readiness
                .thunk_install_readiness()
                .install_plan()
                .did_compile()
        );
        assert!(!readiness.is_ready_for_jit_enabled_harness());
        assert!(readiness.has_gap(NixJitTier1ConformanceGap::ThunkInstall {
            gap: NixJitThunkInstallGap::Tier1CodeNotCompiled,
        }));
        assert_eq!(
            readiness
                .thunk_install_readiness()
                .install_plan()
                .slot()
                .invocation_counter()
                .invocations(),
            1
        );
    }

    #[test]
    fn force_aware_tier1_conformance_readiness_reports_force_finalization_guard() {
        let arena = local_var_arena(9);
        let thunk = EvalThunk::new(IrId::new(0));

        let result = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &thunk,
        );
        let Err(error) = result else {
            panic!("force-aware env-slot conformance is guarded before finalization");
        };

        let NixJitTier1ConformanceReadinessError::ThunkInstall(
            NixJitThunkInstallReadinessError::Promotion(
                NixJitRegisteredTier1PromotionError::Cranelift(source),
            ),
        ) = error
        else {
            panic!("expected force-aware promotion failure");
        };
        assert!(source.decision().should_promote());
        assert_eq!(
            source.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert!(source.slot().tier1_code_ptr().is_none());
        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsCannotFinalize { symbol_names } =
            source.setup_error()
        else {
            panic!("expected force helper finalization guard");
        };
        assert_eq!(symbol_names, &["aos_force".to_owned()]);
    }
}
