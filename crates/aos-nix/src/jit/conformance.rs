//! JIT-enabled conformance readiness for the future differential harness.
//!
//! The full Phase-6 gate is byte-for-byte equivalence between tier-1 execution
//! and the tier-0 oracle across a closure. This module records the current safe
//! prerequisite state for one candidate thunk, plus the first literal-only
//! native differential sample that keeps evaluator thunk publication disabled.

use ratchet_core::{Ir, IrArena, IrData, IrId, IrKind, IrNode};
use ratchet_jit::{
    JitCraneliftNativeCallError, JitCraneliftNativeThunkInvocation, JitLowerError,
    JitTieredCodeSlot, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_native_thunk_call_for_artifact, lower_constant_ir_thunk_body_artifact,
};
use ratchet_value::value::Value;
use thiserror::Error;

use super::{
    NixJitRuntimeSymbolRegistrationError, NixJitRuntimeSymbolRegistrationPreflight,
    NixJitThunkInstallGap, NixJitThunkInstallReadiness, NixJitThunkInstallReadinessError,
    nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root,
    nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_lowered_ir_root,
    nix_jit_registered_tier1_thunk_install_readiness_for_ir_root,
    nix_jit_registered_tier1_thunk_install_readiness_for_lowered_ir_root,
    nix_jit_runtime_symbol_registration_preflight,
};
use crate::eval::EvalThunk;

mod native_differential;
mod shape_differential;
mod tier1_publish_dispatch;

pub use native_differential::{
    BindingProjectionReason, NixJitForcedEnvSlotNativeDifferentialError,
    NixJitForcedEnvSlotNativeDifferentialResult, NixJitForcedEnvSlotNativeOutcome,
    nix_jit_forced_env_slot_native_differential, nix_jit_forced_upval_slot_native_differential,
};
pub use shape_differential::{
    ShapeDifferentialError, ShapeDifferentialOutcome, ShapeDifferentialResult,
    nix_jit_apply_native_differential, nix_jit_arith_native_differential,
    nix_jit_static_has_attr_native_differential, nix_jit_static_select_native_differential,
    nix_jit_update_native_differential,
};
pub use tier1_publish_dispatch::{
    NixJitTier1DispatchAgreement, NixJitTier1PublishDispatchConfig,
    NixJitTier1PublishDispatchError, NixJitTier1PublishDispatchOutcome,
    NixJitTier1PublishDispatchResult, nix_jit_tier1_forced_env_slot_publish_dispatch,
};

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
    /// Runtime symbol addresses still come from non-final provenance.
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

/// Result of comparing one literal native thunk result against the safe value projection.
///
/// This value owns the native invocation so the backing Cranelift module remains
/// alive. It is deliberately narrower than the future differential harness: it
/// accepts only literal Core-IR roots supported by the current no-import
/// lowerer, calls the reviewed native thunk path, and compares the returned
/// representation-level [`Value`] with the same literal value constructed by
/// the safe tier-0 side.
pub struct NixJitLiteralNativeDifferential {
    root: IrId,
    oracle_value: Value,
    native_invocation: JitCraneliftNativeThunkInvocation,
}

impl NixJitLiteralNativeDifferential {
    fn new(
        root: IrId,
        oracle_value: Value,
        native_invocation: JitCraneliftNativeThunkInvocation,
    ) -> Self {
        Self {
            root,
            oracle_value,
            native_invocation,
        }
    }

    /// Returns the Core IR root compared by this differential sample.
    pub const fn root(&self) -> IrId {
        self.root
    }

    /// Returns the safe literal value used as the oracle side of the comparison.
    pub const fn oracle_value(&self) -> Value {
        self.oracle_value
    }

    /// Returns the native thunk value returned by the no-import JIT call path.
    pub const fn native_value(&self) -> Value {
        self.native_invocation.value()
    }

    /// Returns the native invocation that owns the backing Cranelift module.
    pub const fn native_invocation(&self) -> &JitCraneliftNativeThunkInvocation {
        &self.native_invocation
    }

    /// Returns true when native and oracle values match at the representation level.
    pub const fn values_match(&self) -> bool {
        self.native_value().raw_eq(self.oracle_value)
    }

    /// Returns true because the invocation owns the module backing the call target.
    pub fn owns_encapsulated_module(&self) -> bool {
        self.native_invocation.owns_encapsulated_module()
    }
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

/// A failure while building a literal native differential sample.
#[derive(Debug, Error)]
pub enum NixJitLiteralNativeDifferentialError {
    /// The safe literal value could not be projected for the oracle side.
    #[error("literal oracle value projection failed for IR root {root:?}")]
    ProjectOracleLiteral {
        /// The requested IR root.
        root: IrId,
        /// The underlying literal-shape error.
        source: JitLowerError,
    },

    /// The literal IR root could not be lowered into a no-import thunk artifact.
    #[error("literal thunk lowering failed for IR root {root:?}")]
    LowerLiteral {
        /// The requested IR root.
        root: IrId,
        /// The underlying lowerer error.
        source: JitLowerError,
    },

    /// The no-import native thunk call failed.
    #[error("native literal thunk call failed for IR root {root:?}")]
    NativeCall {
        /// The requested IR root.
        root: IrId,
        /// The underlying native-call error.
        source: JitCraneliftNativeCallError,
    },

    /// The native result did not match the safe literal value projection.
    #[error("native literal result for IR root {root:?} was {actual:?}, expected {expected:?}")]
    ValueMismatch {
        /// The requested IR root.
        root: IrId,
        /// The value constructed by the safe literal projection.
        expected: Value,
        /// The value returned by native code.
        actual: Value,
    },
}

/// Result returned by literal native differential samples.
pub type NixJitLiteralNativeDifferentialResult =
    Result<NixJitLiteralNativeDifferential, NixJitLiteralNativeDifferentialError>;

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

/// Builds a safe JIT-enabled conformance readiness report for one full-IR root.
///
/// This function composes the top-level runtime-symbol registration bridge with
/// the full-IR evaluator-thunk install-readiness report for `root`. It is a
/// harness-facing gate only: bounded static attr-selection roots can now
/// finalize and install opaque tier-1 pointer metadata when their helper
/// candidates are present, but still report the same runtime-symbol and
/// evaluator publication blockers as other supported roots. Cold roots preserve
/// the no-code gap.
///
/// # Errors
///
/// Returns [`NixJitTier1ConformanceReadinessError::RuntimeSymbols`] when
/// runtime-symbol registration metadata cannot be built. Returns
/// [`NixJitTier1ConformanceReadinessError::ThunkInstall`] when the full-IR
/// per-thunk install-readiness report cannot be built.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_registered_tier1_thunk_install_readiness_for_lowered_ir_root`] when
/// policy requests promotion.
pub fn nix_jit_tier1_conformance_readiness_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitTier1ConformanceReadinessResult {
    let runtime_symbol_registration = nix_jit_runtime_symbol_registration_preflight()?;
    let thunk_install_readiness =
        nix_jit_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
            slot,
            policy,
            demand_hint,
            ir,
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
/// harness-facing gate only: local environment-slot roots and direct local-slot
/// apply roots can now finalize and install opaque tier-1 pointer metadata when
/// their helper candidates are present, but still report the same runtime-symbol
/// and evaluator publication blockers as literal roots. Cold roots preserve the
/// no-code gap.
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
/// when policy requests promotion and Cranelift finalizes an artifact.
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

/// Builds a safe force-aware JIT-enabled conformance readiness report for one full-IR root.
///
/// This function composes the top-level runtime-symbol registration bridge with
/// the full-IR force-aware evaluator-thunk install-readiness report for `root`.
/// It is a harness-facing gate only: bounded static attr-selection roots can
/// finalize and install opaque tier-1 pointer metadata through
/// `aos_env_get`/`aos_force`/`aos_select_ic`, but still report the same
/// runtime-symbol and evaluator publication blockers as other supported roots.
/// Cold roots preserve the no-code gap.
///
/// # Errors
///
/// Returns [`NixJitTier1ConformanceReadinessError::RuntimeSymbols`] when
/// runtime-symbol registration metadata cannot be built. Returns
/// [`NixJitTier1ConformanceReadinessError::ThunkInstall`] when the full-IR
/// force-aware per-thunk install-readiness report cannot be built.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_lowered_ir_root`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub fn nix_jit_force_aware_tier1_conformance_readiness_for_lowered_ir_root(
    slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
    target_thunk: &EvalThunk,
) -> NixJitTier1ConformanceReadinessResult {
    let runtime_symbol_registration = nix_jit_runtime_symbol_registration_preflight()?;
    let thunk_install_readiness =
        nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
            slot,
            policy,
            demand_hint,
            ir,
            root,
            target_thunk,
        )?;

    Ok(NixJitTier1ConformanceReadiness::new(
        runtime_symbol_registration,
        thunk_install_readiness,
    ))
}

/// Compares one no-import literal native thunk result against the safe literal value projection.
///
/// This is a bounded precursor for the future JIT-enabled differential harness.
/// It does not publish into evaluator thunk state, perform atomic thunk-state
/// transitions, call registered runtime helpers, or run a full closure oracle.
/// It only accepts literal Core-IR roots currently supported by
/// [`lower_constant_ir_thunk_body_artifact`], calls the reviewed no-import
/// native thunk path, and returns an owned comparison report when the raw
/// [`Value`] bits match.
///
/// # Errors
///
/// Returns [`NixJitLiteralNativeDifferentialError::ProjectOracleLiteral`] when
/// the root cannot be projected into a safe literal value. Returns
/// [`NixJitLiteralNativeDifferentialError::LowerLiteral`] when the root cannot
/// be lowered into a no-import thunk artifact. Returns
/// [`NixJitLiteralNativeDifferentialError::NativeCall`] when finalization or
/// native invocation fails. Returns
/// [`NixJitLiteralNativeDifferentialError::ValueMismatch`] when the native
/// result differs from the safe literal projection at the representation level.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as [`jit_cranelift_native_thunk_call_for_artifact`].
pub fn nix_jit_literal_native_differential_for_ir_root(
    arena: &IrArena,
    root: IrId,
) -> NixJitLiteralNativeDifferentialResult {
    let oracle_value = literal_oracle_value_for_ir_root(arena, root).map_err(|source| {
        NixJitLiteralNativeDifferentialError::ProjectOracleLiteral { root, source }
    })?;
    let artifact = lower_constant_ir_thunk_body_artifact(arena, root)
        .map_err(|source| NixJitLiteralNativeDifferentialError::LowerLiteral { root, source })?;
    let native_invocation = jit_cranelift_native_thunk_call_for_artifact(artifact)
        .map_err(|source| NixJitLiteralNativeDifferentialError::NativeCall { root, source })?;
    let actual = native_invocation.value();

    if !actual.raw_eq(oracle_value) {
        return Err(NixJitLiteralNativeDifferentialError::ValueMismatch {
            root,
            expected: oracle_value,
            actual,
        });
    }

    Ok(NixJitLiteralNativeDifferential::new(
        root,
        oracle_value,
        native_invocation,
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

fn literal_oracle_value_for_ir_root(arena: &IrArena, root: IrId) -> Result<Value, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            literal_oracle_value_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => literal_oracle_value_for_node(node),
    }
}

fn literal_oracle_value_for_body(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        // The one-word carrier can only construct inline-range integers
        // context-free; wide integers and floats box through the heap, so the
        // lowering declines them and the oracle mirrors that decline.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Int, IrData::Int(value)) => {
            if i32::try_from(value).is_ok() {
                Ok(Value::int(value))
            } else {
                Err(JitLowerError::UnsupportedIrBody { kind: IrKind::Int })
            }
        }
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Float, IrData::Float(_)) => Err(JitLowerError::UnsupportedIrBody {
            kind: IrKind::Float,
        }),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedBodyConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrBody { kind }),
    }
}

fn literal_oracle_value_for_node(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        // See literal_oracle_value_for_body: inline-range integers only on
        // the one-word carrier.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Int, IrData::Int(value)) => {
            if i32::try_from(value).is_ok() {
                Ok(Value::int(value))
            } else {
                Err(JitLowerError::UnsupportedIrRoot { kind: IrKind::Int })
            }
        }
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Float, IrData::Float(_)) => Err(JitLowerError::UnsupportedIrRoot {
            kind: IrKind::Float,
        }),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrRoot { kind }),
    }
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
mod tests;
