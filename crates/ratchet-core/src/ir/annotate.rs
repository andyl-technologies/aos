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
use crate::scope::{FrameId, Upvalue};

use super::{Ir, IrFacts, IrId};

/// Version stamp of the fact-producing analysis pipeline.
///
/// Persisted fact sidecars record the analysis version that produced them. A
/// stored sidecar whose version differs from the current producer must be
/// treated as absent and re-analyzed; a sidecar carrying the current version
/// (with a matching lowered-IR fingerprint) can be consumed without
/// re-running [`annotate_ir`]. Bump this constant whenever any fact
/// producer's semantics change.
///
/// Version history:
///
/// - `0` — reserved for fact tables that were serialized without running the
///   analysis pipeline (conservative placeholder tables).
/// - `2` — the three-level demand lattice (`Unknown` / `Demanded` /
///   `DemandedBeforeEffect`), per-execution demand semantics, builtin demand
///   signatures, and the `tryEval` barrier bit. (`1` denotes the earlier
///   two-level lattice, which predates version stamping and can never appear
///   in a stamped sidecar.)
/// - `3` — derivation-boundary demand seeding: attrset literals flowing into
///   `derivationStrict` / `derivation` earn demand marks on their binding
///   values, `derivationStrict`'s argument demand is `Forced`, and the
///   per-node eager-assembly bit
///   ([`crate::ir::IrFacts::assembly_eager`]) is produced.
pub const IR_ANALYSIS_VERSION: u32 = 3;

/// Summary of one complete IR fact annotation run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IrAnalysisReport {
    /// Report returned by the strictness analysis pass.
    pub strictness: StrictnessAnalysisReport,
    /// Report returned by the cardinality analysis pass.
    pub cardinality: CardinalityAnalysisReport,
    /// Report returned by the escape analysis pass.
    pub escape: EscapeAnalysisReport,
    /// Deterministic dependency-footprint material derived from analyzed facts.
    pub dependency_footprint: IrDependencyFootprint,
}

/// Deterministic dependency material produced by IR annotation.
///
/// This footprint is a cache-key precursor. It exposes current strictness facts
/// and resolver capture sets in canonical storage order, but it does not compute
/// value hashes or decide which cache nodes are memoized.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IrDependencyFootprint {
    strict_nodes: Box<[IrId]>,
    frame_captures: Box<[IrFrameCaptureFootprint]>,
}

impl IrDependencyFootprint {
    fn from_ir(ir: &Ir) -> Self {
        let strict_nodes = ir
            .facts
            .as_slice()
            .iter()
            .enumerate()
            .filter_map(|(index, facts)| {
                facts.strictness.is_demanded().then(|| IrId::new(index as u32))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let frame_captures = ir
            .frames
            .iter()
            .enumerate()
            .filter_map(|(index, frame)| {
                let mut captures = frame.captures.to_vec();
                captures.sort_unstable();
                captures.dedup();
                if captures.is_empty() {
                    None
                } else {
                    Some(IrFrameCaptureFootprint {
                        frame: FrameId::new(index as u32),
                        captures: captures.into_boxed_slice(),
                    })
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            strict_nodes,
            frame_captures,
        }
    }

    /// Returns strict IR node ids in arena order.
    pub fn strict_nodes(&self) -> &[IrId] {
        &self.strict_nodes
    }

    /// Returns frame capture sets in resolver frame-table order.
    pub fn frame_captures(&self) -> &[IrFrameCaptureFootprint] {
        &self.frame_captures
    }

    /// Returns whether the footprint has no strict nodes or captured upvalues.
    pub fn is_empty(&self) -> bool {
        self.strict_nodes.is_empty() && self.frame_captures.is_empty()
    }
}

/// Captured upvalues for one resolver frame in the dependency footprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrFrameCaptureFootprint {
    frame: FrameId,
    captures: Box<[Upvalue]>,
}

impl IrFrameCaptureFootprint {
    /// Returns the frame that owns these captured upvalues.
    pub const fn frame(&self) -> FrameId {
        self.frame
    }

    /// Returns captured upvalues in canonical `(depth, slot)` order.
    pub fn captures(&self) -> &[Upvalue] {
        &self.captures
    }
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
    let dependency_footprint = IrDependencyFootprint::from_ir(ir);
    Ok(IrAnalysisReport {
        strictness,
        cardinality,
        escape,
        dependency_footprint,
    })
}
