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
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
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
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
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
mod tests {
    use crate::jit::nix_jit_runtime_symbol_address_candidate_preflight;

    use ratchet_core::{
        EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts,
        IrInlineCacheSiteId, IrKind, IrNode,
        syntax::{BinOpKind, Span, SymbolTable},
    };
    use ratchet_jit::{
        DEFAULT_TIER1_INVOCATION_THRESHOLD, JitClifArtifactSource, JitTier, TierUpCounter,
    };

    use super::*;

    mod apply;

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

    fn static_select_ir(slot: u32) -> Ir {
        let mut symbols = SymbolTable::new();
        let symbol = symbols
            .intern(b"target")
            .expect("test symbol table accepts target");
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Local { slot },
                ),
                IrNode::new(
                    IrKind::Select,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::Select {
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        site: IrInlineCacheSiteId::new(11),
                        default: None,
                    },
                ),
            ],
            Vec::new(),
        );
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(1),
            arena,
            facts,
            symbols,
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn static_has_attr_ir(slot: u32) -> Ir {
        let mut symbols = SymbolTable::new();
        let symbol = symbols
            .intern(b"target")
            .expect("test symbol table accepts target");
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Local { slot },
                ),
                IrNode::new(
                    IrKind::HasAttr,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::HasAttr {
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        site: IrInlineCacheSiteId::new(11),
                    },
                ),
            ],
            Vec::new(),
        );
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(1),
            arena,
            facts,
            symbols,
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn update_ir(left_slot: u32, right_slot: u32) -> Ir {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Local { slot: left_slot },
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(2, 3),
                    EffectClass::pure(),
                    IrData::Local { slot: right_slot },
                ),
                IrNode::new(
                    IrKind::BinOp,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Binary {
                        op: BinOpKind::Update,
                        lhs: IrId::new(0),
                        rhs: IrId::new(1),
                    },
                ),
            ],
            Vec::new(),
        );
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(2),
            arena,
            facts,
            symbols: SymbolTable::new(),
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
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

    fn int_arena(value: i64) -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Int(value),
            )],
            Vec::new(),
        )
    }

    fn float_arena(value: f64) -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Float,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Float(value),
            )],
            Vec::new(),
        )
    }

    fn null_arena() -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Null,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        )
    }

    fn thunk_alloc_bool_arena(value: bool) -> IrArena {
        IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Bool(value),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        )
    }

    fn hot_slot() -> JitTieredCodeSlot {
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1))
    }

    #[test]
    fn literal_native_differential_matches_direct_scalar_values() {
        let cases = [
            (int_arena(-17), Value::int(-17)),
            (float_arena(-13.5), Value::float(-13.5)),
            (bool_arena(false), Value::bool(false)),
            (null_arena(), Value::null()),
        ];

        for (arena, expected) in cases {
            let differential =
                nix_jit_literal_native_differential_for_ir_root(&arena, IrId::new(0))
                    .expect("literal native differential succeeds");

            assert_eq!(differential.root(), IrId::new(0));
            assert!(differential.values_match());
            assert!(differential.owns_encapsulated_module());
            assert!(differential.oracle_value().raw_eq(expected));
            assert!(differential.native_value().raw_eq(expected));
            assert_eq!(
                differential
                    .native_invocation()
                    .finalization()
                    .artifact()
                    .source(),
                JitClifArtifactSource::IrRoot(IrId::new(0))
            );
            assert_eq!(
                differential
                    .native_invocation()
                    .finalized_function()
                    .symbol_name(),
                "aos.jit.ir_root.0.thunk_body"
            );
        }
    }

    #[test]
    fn literal_native_differential_matches_direct_thunk_bool_value() {
        let arena = thunk_alloc_bool_arena(true);

        let differential = nix_jit_literal_native_differential_for_ir_root(&arena, IrId::new(1))
            .expect("direct thunk literal native differential succeeds");

        assert_eq!(differential.root(), IrId::new(1));
        assert!(differential.values_match());
        assert!(differential.oracle_value().raw_eq(Value::bool(true)));
        assert!(differential.native_value().raw_eq(Value::bool(true)));
        assert_eq!(
            differential
                .native_invocation()
                .finalization()
                .artifact()
                .source(),
            JitClifArtifactSource::IrRoot(IrId::new(1))
        );
    }

    #[test]
    fn literal_native_differential_rejects_unsupported_root_before_native_call() {
        let arena = local_var_arena(2);

        let Err(error) = nix_jit_literal_native_differential_for_ir_root(&arena, IrId::new(0))
        else {
            panic!("local variables are not no-import literal differential inputs");
        };

        assert!(matches!(
            error,
            NixJitLiteralNativeDifferentialError::ProjectOracleLiteral {
                root,
                source: JitLowerError::UnsupportedIrRoot {
                    kind: IrKind::LocalVar
                }
            } if root == IrId::new(0)
        ));
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
                .is_empty()
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
            !readiness.has_gap(NixJitTier1ConformanceGap::RuntimeSymbolAddressProvenance {
                missing_count: 0,
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
    fn force_aware_tier1_conformance_readiness_reports_forced_env_slot_publish_gaps() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let arena = local_var_arena(9);
        let thunk = EvalThunk::new(IrId::new(0));

        let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &thunk,
        )
        .expect("force-aware env-slot JIT conformance readiness report builds");

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
                .invocation_counter()
                .invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
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
        let promoted = readiness
            .thunk_install_readiness()
            .install_plan()
            .promoted_preflight()
            .expect("readiness owns promoted preflight");
        assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 2);
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
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_force")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_force")
                        .expect("force candidate exists")
                        .address())
        );
    }

    #[test]
    fn force_aware_tier1_conformance_readiness_reports_update_publish_gaps() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let ir = update_ir(12, 13);
        let thunk = EvalThunk::new(ir.root);

        let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir.arena,
            ir.root,
            &thunk,
        )
        .expect("force-aware update conformance readiness report builds");

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
        let promoted = readiness
            .thunk_install_readiness()
            .install_plan()
            .promoted_preflight()
            .expect("readiness owns promoted preflight");
        let artifact_runtime_imports = promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>();
        assert_eq!(
            artifact_runtime_imports,
            ["aos_env_get", "aos_force", "aos_update"]
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_update")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_update")
                        .expect("update candidate exists")
                        .address())
        );
    }

    #[test]
    fn tier1_conformance_readiness_reports_update_publish_gaps() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let ir = update_ir(18, 19);
        let thunk = EvalThunk::new(ir.root);

        let readiness = nix_jit_tier1_conformance_readiness_for_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir.arena,
            ir.root,
            &thunk,
        )
        .expect("update conformance readiness report builds");

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
        let promoted = readiness
            .thunk_install_readiness()
            .install_plan()
            .promoted_preflight()
            .expect("readiness owns promoted preflight");
        let artifact_runtime_imports = promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>();
        assert_eq!(
            artifact_runtime_imports,
            ["aos_env_get", "aos_force", "aos_update"]
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_update")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_update")
                        .expect("update candidate exists")
                        .address())
        );
    }

    #[test]
    fn force_aware_tier1_conformance_readiness_reports_static_select_publish_gaps() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let ir = static_select_ir(14);
        let thunk = EvalThunk::new(ir.root);

        let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_lowered_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &thunk,
        )
        .expect("force-aware full-IR static-select conformance readiness report builds");

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
        let promoted = readiness
            .thunk_install_readiness()
            .install_plan()
            .promoted_preflight()
            .expect("readiness owns promoted preflight");
        let artifact_runtime_imports = promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>();
        assert_eq!(
            artifact_runtime_imports,
            ["aos_env_get", "aos_force", "aos_select_ic"]
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_select_ic")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_select_ic")
                        .expect("select candidate exists")
                        .address())
        );
    }

    #[test]
    fn force_aware_tier1_conformance_readiness_reports_static_has_attr_publish_gaps() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let ir = static_has_attr_ir(16);
        let thunk = EvalThunk::new(ir.root);

        let readiness = nix_jit_force_aware_tier1_conformance_readiness_for_lowered_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &thunk,
        )
        .expect("force-aware full-IR static-hasAttr conformance readiness report builds");

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
        let promoted = readiness
            .thunk_install_readiness()
            .install_plan()
            .promoted_preflight()
            .expect("readiness owns promoted preflight");
        let artifact_runtime_imports = promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>();
        assert_eq!(
            artifact_runtime_imports,
            ["aos_env_get", "aos_force", "aos_has_attr"]
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_has_attr")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_has_attr")
                        .expect("hasAttr candidate exists")
                        .address())
        );
    }

    #[test]
    fn tier1_conformance_readiness_reports_static_select_publish_gaps() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let ir = static_select_ir(15);
        let thunk = EvalThunk::new(ir.root);

        let readiness = nix_jit_tier1_conformance_readiness_for_lowered_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &thunk,
        )
        .expect("full-IR static-select conformance readiness report builds");

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
        let promoted = readiness
            .thunk_install_readiness()
            .install_plan()
            .promoted_preflight()
            .expect("readiness owns promoted preflight");
        let artifact_runtime_imports = promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>();
        assert_eq!(
            artifact_runtime_imports,
            ["aos_env_get", "aos_force", "aos_select_ic"]
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_select_ic")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_select_ic")
                        .expect("select candidate exists")
                        .address())
        );
    }

    #[test]
    fn tier1_conformance_readiness_reports_static_has_attr_publish_gaps() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let ir = static_has_attr_ir(17);
        let thunk = EvalThunk::new(ir.root);

        let readiness = nix_jit_tier1_conformance_readiness_for_lowered_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &thunk,
        )
        .expect("full-IR static-hasAttr conformance readiness report builds");

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
        let promoted = readiness
            .thunk_install_readiness()
            .install_plan()
            .promoted_preflight()
            .expect("readiness owns promoted preflight");
        let artifact_runtime_imports = promoted
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>();
        assert_eq!(
            artifact_runtime_imports,
            ["aos_env_get", "aos_force", "aos_has_attr"]
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_has_attr")
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for("aos_has_attr")
                        .expect("hasAttr candidate exists")
                        .address())
        );
    }
}
