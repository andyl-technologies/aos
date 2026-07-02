//! Whole-program and intraprocedural analysis passes over lowered IR.
//!
//! The passes in this module refine conservative [`crate::ir::ExprFacts`]
//! records after lowering. Each pass is required to prove facts positively:
//! uncertainty leaves the existing conservative fact unchanged.

pub mod cardinality;
pub mod escape;
pub mod full_laziness;
pub mod strictness;
pub mod thunk_sharing;

pub use cardinality::{CardinalityAnalysisError, CardinalityAnalysisReport, annotate_cardinality};
pub use escape::{EscapeAnalysisError, EscapeAnalysisReport, annotate_escape};
pub use full_laziness::{
    FullLazinessAnalysisError, FullLazinessAnalysisReport, FullLazinessCandidate,
    analyze_full_laziness,
};
pub use strictness::{StrictnessAnalysisError, StrictnessAnalysisReport, annotate_strictness};
pub use thunk_sharing::{
    FrameLocalSingleEntryThunk, FrameLocalThunkDowngrade, FrameLocalThunkDowngradeError,
    FrameLocalThunkUpdateReason, frame_local_single_entry_thunk_downgrade,
};

#[cfg(test)]
mod tests;
