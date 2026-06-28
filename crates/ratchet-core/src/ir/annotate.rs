//! IR fact annotation orchestration.
//!
//! This module owns the current fact-refresh entry point for lowered IR. It
//! starts from conservative per-node facts, runs the available analysis
//! precursors, and leaves conservative facts behind if any pass rejects malformed
//! IR.

use thiserror::Error;

use crate::analysis::{
    CardinalityAnalysisError, CardinalityAnalysisReport, EscapeAnalysisError, EscapeAnalysisReport,
    StrictnessAnalysisError, StrictnessAnalysisReport, annotate_cardinality, annotate_escape,
    annotate_strictness,
};

use super::{Ir, IrFacts};

/// Summary of one complete IR fact annotation run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrAnalysisReport {
    /// Report returned by the strictness analysis pass.
    pub strictness: StrictnessAnalysisReport,
    /// Report returned by the cardinality analysis pass.
    pub cardinality: CardinalityAnalysisReport,
    /// Report returned by the escape analysis pass.
    pub escape: EscapeAnalysisReport,
}

/// Errors returned by the IR fact annotation pipeline.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IrAnalysisError {
    /// Strictness analysis rejected the IR.
    #[error(transparent)]
    Strictness(#[from] StrictnessAnalysisError),
    /// Cardinality analysis rejected the IR.
    #[error(transparent)]
    Cardinality(#[from] CardinalityAnalysisError),
    /// Escape analysis rejected the IR.
    #[error(transparent)]
    Escape(#[from] EscapeAnalysisError),
}

/// Refreshes all currently implemented per-node IR analysis facts.
///
/// The pipeline starts from conservative facts instead of refining whatever
/// facts the `Ir` happened to carry. If a pass fails, the IR is left with a
/// conservative fact table for every arena node, so callers cannot accidentally
/// consume partially refreshed facts.
///
/// # Errors
///
/// Returns [`IrAnalysisError`] when strictness, cardinality, or escape analysis
/// rejects malformed IR observed by the current producers, such as invalid
/// reachable side-table references, node payloads, symbols, or fact records.
pub fn annotate_ir(ir: &mut Ir) -> Result<IrAnalysisReport, IrAnalysisError> {
    let node_count = ir.arena.nodes().len();
    ir.facts = IrFacts::conservative(node_count);
    match run_analyses(ir) {
        Ok(report) => Ok(report),
        Err(error) => {
            ir.facts = IrFacts::conservative(node_count);
            Err(error)
        }
    }
}

fn run_analyses(ir: &mut Ir) -> Result<IrAnalysisReport, IrAnalysisError> {
    let strictness = annotate_strictness(ir)?;
    let cardinality = annotate_cardinality(ir)?;
    let escape = annotate_escape(ir)?;
    Ok(IrAnalysisReport {
        strictness,
        cardinality,
        escape,
    })
}
