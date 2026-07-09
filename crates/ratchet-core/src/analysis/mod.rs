//! Whole-program and intraprocedural analysis passes over lowered IR.
//!
//! The passes in this module refine conservative [`crate::ir::ExprFacts`]
//! records after lowering. Each pass is required to prove facts positively:
//! uncertainty leaves the existing conservative fact unchanged.

pub mod capture;
pub mod cardinality;
pub mod dead_binding;
pub mod escape;
pub mod escape_signature;
pub mod full_laziness;
pub mod scalar_replacement;
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
pub use escape::{EscapeAnalysisError, EscapeAnalysisReport, annotate_escape};
pub use escape_signature::{
    PrimOpArgumentEscape, PrimOpEscapeSignature, primop_argument_escape_signature,
    primop_escape_signature,
};
pub use full_laziness::{
    FullLazinessAnalysisError, FullLazinessAnalysisReport, FullLazinessCandidate,
    analyze_full_laziness,
};
pub use scalar_replacement::{
    ScalarReplacement, ScalarReplacementError, ScalarReplacementKind, ScalarReplacementPlan,
    ScalarReplacementRetention, ScalarReplacementRetentionReason, scalar_replacement_plan,
};
pub use strictness::{StrictnessAnalysisError, StrictnessAnalysisReport, annotate_strictness};
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
