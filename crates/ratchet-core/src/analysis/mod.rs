//! Whole-program and intraprocedural analysis passes over lowered IR.
//!
//! The passes in this module refine conservative [`crate::ir::ExprFacts`]
//! records after lowering. Each pass is required to prove facts positively:
//! uncertainty leaves the existing conservative fact unchanged.

pub mod cardinality;
pub mod strictness;

pub use cardinality::{CardinalityAnalysisError, CardinalityAnalysisReport, annotate_cardinality};
pub use strictness::{StrictnessAnalysisError, StrictnessAnalysisReport, annotate_strictness};

#[cfg(test)]
mod tests;
