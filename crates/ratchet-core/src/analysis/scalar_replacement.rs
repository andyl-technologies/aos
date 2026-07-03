//! Scalar replacement planning over strictness and escape facts.
//!
//! Scalar replacement is a representation optimization: optimized tiers may keep
//! proven-strict, proven-non-escaping immediate scalar values out of the heap.
//! This module does not rewrite IR. It is a conservative consumer boundary for
//! the current fact table so lowering code can ask which nodes are licensed for
//! scalar storage without re-deriving the proof predicate.

use thiserror::Error;

use crate::ir::{Escape, Ir, IrData, IrId, IrKind, Strictness};

/// Builds a scalar replacement plan for the current IR facts.
///
/// Immediate scalar nodes are admitted only when their facts prove both
/// [`Strictness::Strict`] and [`Escape::NoEscape`]. Scalar nodes with missing
/// proofs are retained with their current facts, while non-scalar nodes carrying
/// the same proof pair are retained as unsupported by this precursor.
///
/// # Errors
///
/// Returns [`ScalarReplacementError`] if the fact table is missing an arena
/// entry or if an immediate scalar node carries a payload that does not match
/// its kind.
pub fn scalar_replacement_plan(ir: &Ir) -> Result<ScalarReplacementPlan, ScalarReplacementError> {
    let mut plan = ScalarReplacementPlan {
        node_count: ir.arena.nodes().len(),
        ..ScalarReplacementPlan::default()
    };

    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        let id = IrId::new(index as u32);
        let facts = ir
            .facts
            .get(id)
            .ok_or(ScalarReplacementError::MissingFact { id })?;

        if let Some(kind) = scalar_kind(id, node.kind, node.data)? {
            plan.scalar_candidate_count += 1;
            if facts.strictness == Strictness::Strict && facts.escape == Escape::NoEscape {
                plan.replacements.push(ScalarReplacement { node: id, kind });
            } else {
                plan.retained.push(ScalarReplacementRetention {
                    node: id,
                    reason: ScalarReplacementRetentionReason::MissingProofs {
                        strictness: facts.strictness,
                        escape: facts.escape,
                    },
                });
            }
            continue;
        }

        if facts.strictness == Strictness::Strict && facts.escape == Escape::NoEscape {
            plan.retained.push(ScalarReplacementRetention {
                node: id,
                reason: ScalarReplacementRetentionReason::UnsupportedNodeKind { kind: node.kind },
            });
        }
    }

    Ok(plan)
}

fn scalar_kind(
    id: IrId,
    kind: IrKind,
    data: IrData,
) -> Result<Option<ScalarReplacementKind>, ScalarReplacementError> {
    match kind {
        IrKind::Int => match data {
            IrData::Int(_) => Ok(Some(ScalarReplacementKind::Int)),
            _ => Err(invalid_payload(id, kind, "integer payload")),
        },
        IrKind::Float => match data {
            IrData::Float(_) => Ok(Some(ScalarReplacementKind::Float)),
            _ => Err(invalid_payload(id, kind, "float payload")),
        },
        IrKind::Bool => match data {
            IrData::Bool(_) => Ok(Some(ScalarReplacementKind::Bool)),
            _ => Err(invalid_payload(id, kind, "boolean payload")),
        },
        IrKind::Null => match data {
            IrData::None => Ok(Some(ScalarReplacementKind::Null)),
            _ => Err(invalid_payload(id, kind, "empty payload")),
        },
        _ => Ok(None),
    }
}

fn invalid_payload(id: IrId, kind: IrKind, expected: &'static str) -> ScalarReplacementError {
    ScalarReplacementError::InvalidPayload { id, kind, expected }
}

/// A conservative scalar replacement plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScalarReplacementPlan {
    node_count: usize,
    scalar_candidate_count: usize,
    replacements: Vec<ScalarReplacement>,
    retained: Vec<ScalarReplacementRetention>,
}

impl ScalarReplacementPlan {
    /// Returns the number of IR nodes scanned.
    pub const fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns the number of immediate scalar nodes considered.
    pub const fn scalar_candidate_count(&self) -> usize {
        self.scalar_candidate_count
    }

    /// Returns scalar nodes licensed for non-heap representation.
    pub fn replacements(&self) -> &[ScalarReplacement] {
        &self.replacements
    }

    /// Returns nodes retained with the reason scalar replacement was withheld.
    pub fn retained(&self) -> &[ScalarReplacementRetention] {
        &self.retained
    }

    /// Returns whether no scalar node can be replaced.
    pub fn is_empty(&self) -> bool {
        self.replacements.is_empty()
    }
}

/// One immediate scalar node licensed for non-heap representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarReplacement {
    node: IrId,
    kind: ScalarReplacementKind,
}

impl ScalarReplacement {
    /// Returns the IR node covered by this replacement proof.
    pub const fn node(self) -> IrId {
        self.node
    }

    /// Returns the scalar representation class.
    pub const fn kind(self) -> ScalarReplacementKind {
        self.kind
    }
}

/// Immediate scalar value classes supported by this planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarReplacementKind {
    /// An integer scalar.
    Int,
    /// A floating-point scalar.
    Float,
    /// A boolean scalar.
    Bool,
    /// The null singleton.
    Null,
}

/// One node retained by the scalar replacement planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarReplacementRetention {
    node: IrId,
    reason: ScalarReplacementRetentionReason,
}

impl ScalarReplacementRetention {
    /// Returns the retained IR node.
    pub const fn node(self) -> IrId {
        self.node
    }

    /// Returns why scalar replacement was not licensed.
    pub const fn reason(self) -> ScalarReplacementRetentionReason {
        self.reason
    }
}

/// Why scalar replacement was withheld for a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarReplacementRetentionReason {
    /// The scalar node did not have both required facts.
    MissingProofs {
        /// The strictness fact that prevented replacement.
        strictness: Strictness,
        /// The escape fact that prevented replacement.
        escape: Escape,
    },
    /// The node is not an immediate scalar supported by this precursor.
    UnsupportedNodeKind {
        /// The unsupported node kind.
        kind: IrKind,
    },
}

/// A failure while building a scalar replacement plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ScalarReplacementError {
    /// A fact record was missing for an arena node.
    #[error("missing fact record for IR node {id:?}")]
    MissingFact {
        /// The node whose fact record was missing.
        id: IrId,
    },
    /// A scalar node's payload did not match its node kind.
    #[error("invalid payload for {kind:?} node {id:?}: expected {expected}")]
    InvalidPayload {
        /// The node with the invalid payload.
        id: IrId,
        /// The node kind whose payload was invalid.
        kind: IrKind,
        /// The expected payload shape.
        expected: &'static str,
    },
}
