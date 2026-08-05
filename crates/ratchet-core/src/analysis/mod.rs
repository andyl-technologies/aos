//! Whole-program and intraprocedural analysis passes over lowered IR.
//!
//! The passes in this module refine conservative [`crate::ir::ExprFacts`]
//! records after lowering. Each pass is required to prove facts positively:
//! uncertainty leaves the existing conservative fact unchanged.

pub mod capture;
pub mod cardinality;
pub mod dead_binding;
pub mod dynamic_scope;
pub mod escape;
pub mod escape_signature;
pub mod frame_identity;
pub mod full_laziness;
pub mod promise_region;
pub mod scalar_replacement;
pub mod semantic_slice;
pub mod strictness;
pub mod thunk_sharing;
pub mod worker_wrapper;

pub use capture::{
    CaptureAnalysisError, CaptureAnalysisReport, FLAT_CAPTURE_MAX_SLOTS,
    FREE_VAR_HISTOGRAM_BUCKETS, annotate_capture_plans,
};
pub use cardinality::{CardinalityAnalysisError, CardinalityAnalysisReport, annotate_cardinality};
pub use dead_binding::{
    DeadBindingElimination, DeadBindingEliminationError, DeadBindingEliminationPlan,
    DeadBindingReplacement, DeadBindingRetention, DeadBindingRetentionReason,
    dead_binding_elimination_plan,
};
pub use escape::{
    EscapeAnalysisError, EscapeAnalysisReport, annotate_escape, annotate_lambda_call_summary_escape,
};
pub use escape_signature::{
    PrimOpArgumentEscape, PrimOpEscapeSignature, primop_argument_escape_signature,
    primop_escape_signature,
};
pub use frame_identity::{IrFrameIdentity, IrFrameIdentityError, resolve_unique_ir_frame};
pub use full_laziness::{
    FullLazinessAnalysisError, FullLazinessAnalysisReport, FullLazinessCandidate,
    analyze_full_laziness,
};
pub use promise_region::{
    DEFAULT_PROMISE_REGION_SPECIALIZATION_CAP, PromiseNodeSpecializationCount,
    PromiseRegionDisposition, PromiseRegionError, PromiseRegionKey, PromiseRegionNode,
    PromiseRegionOptions, PromiseRegionPlan, PromiseRegionSymbolValidation, PromiseStatepoint,
    PromiseStatepointKind, PromiseVirtualAllocationSite, VirtualAllocationCounts,
    VirtualAllocationKind, plan_promise_region,
};
pub use scalar_replacement::{
    ScalarReplacement, ScalarReplacementError, ScalarReplacementKind, ScalarReplacementPlan,
    ScalarReplacementRetention, ScalarReplacementRetentionReason, scalar_replacement_plan,
};
pub use semantic_slice::{
    SemanticBinderId, SemanticBindingComponent, SemanticSlice, SemanticSliceError,
    analyze_semantic_slice, analyze_semantic_subslice, analyze_semantic_subslice_with_symbols,
    semantic_subslice_retains_all, semantic_subslice_retains_all_with_symbols,
};
pub(crate) use strictness::annotate_import_strictness;
pub use strictness::{
    CallTargetCandidates, ClosureFlowReport, KnownCallTarget, StrictnessAnalysisError,
    StrictnessAnalysisReport, analyze_call_target_candidates, analyze_known_call_targets,
    annotate_strictness,
};
pub use thunk_sharing::{
    FrameLocalSingleEntryThunk, FrameLocalThunkDowngrade, FrameLocalThunkDowngradeError,
    FrameLocalThunkUpdateReason, frame_local_single_entry_thunk_downgrade,
};
pub use worker_wrapper::{
    WorkerWrapperArgumentMode, WorkerWrapperPlan, WorkerWrapperPlanError, WorkerWrapperRetention,
    WorkerWrapperRetentionReason, WorkerWrapperSplit, worker_wrapper_plan,
};

#[cfg(test)]
mod tests;
