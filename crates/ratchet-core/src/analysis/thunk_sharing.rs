//! Thunk-sharing downgrade preflight over lowered IR facts.
//!
//! Single-entry thunks are a representation optimization: they can skip normal
//! update and blackhole machinery only when analysis proves the thunk is entered
//! at most once and its allocation remains frame-local. This module names that
//! boundary so later evaluator tiers can consume it without re-deriving the
//! safety predicate at the allocation site.

use thiserror::Error;

use crate::ir::{Cardinality, Escape, Ir, IrData, IrId, IrKind, Strictness, ThunkSharing};

/// Returns the sharing downgrade licensed for one thunk allocation node.
///
/// The decision is derived only from the node's [`crate::ir::ExprFacts`]. A
/// missing cardinality or escape proof keeps full update/blackhole machinery.
/// Proven absence returns [`FrameLocalThunkDowngrade::Omit`] instead of a
/// single-entry downgrade.
///
/// # Errors
///
/// Returns [`FrameLocalThunkDowngradeError`] if `id` is missing, if its fact
/// record is missing, if it does not identify an [`IrKind::ThunkAlloc`] node, or
/// if the thunk allocation payload or body reference is malformed.
pub fn frame_local_single_entry_thunk_downgrade(
    ir: &Ir,
    id: IrId,
) -> Result<FrameLocalThunkDowngrade, FrameLocalThunkDowngradeError> {
    let node = ir
        .arena
        .node(id)
        .ok_or(FrameLocalThunkDowngradeError::MissingNode { id })?;
    let body = match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => body,
        (IrKind::ThunkAlloc, _) => {
            return Err(FrameLocalThunkDowngradeError::InvalidPayload {
                id,
                expected: "thunk body",
            });
        }
        (kind, _) => return Err(FrameLocalThunkDowngradeError::NotThunkAlloc { id, kind }),
    };
    ir.arena
        .node(body)
        .ok_or(FrameLocalThunkDowngradeError::MissingThunkBody { id, body })?;
    if body == id {
        return Err(FrameLocalThunkDowngradeError::SelfReferentialThunkBody { id });
    }
    let facts = ir
        .facts
        .get(id)
        .ok_or(FrameLocalThunkDowngradeError::MissingFact { id })?;

    Ok(match facts.thunk_sharing() {
        ThunkSharing::SingleEntry => {
            FrameLocalThunkDowngrade::SingleEntry(FrameLocalSingleEntryThunk { thunk: id, body })
        }
        ThunkSharing::Omit => FrameLocalThunkDowngrade::Omit,
        ThunkSharing::Update => FrameLocalThunkDowngrade::KeepUpdate(update_reason(
            facts.cardinality,
            facts.strictness,
            facts.escape,
        )),
    })
}

fn update_reason(
    cardinality: Cardinality,
    strictness: Strictness,
    escape: Escape,
) -> FrameLocalThunkUpdateReason {
    if cardinality == Cardinality::Absent && strictness.is_demanded() {
        return FrameLocalThunkUpdateReason::AbsentButStrict;
    }
    if cardinality != Cardinality::Once {
        return FrameLocalThunkUpdateReason::CardinalityNotOnce { cardinality };
    }
    if escape != Escape::NoEscape {
        return FrameLocalThunkUpdateReason::EscapesFrame;
    }
    FrameLocalThunkUpdateReason::ConservativeFallback
}

/// The representation decision for a thunk allocation node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameLocalThunkDowngrade {
    /// Keep ordinary update and blackhole machinery.
    KeepUpdate(FrameLocalThunkUpdateReason),
    /// Use the single-entry representation for a proven frame-local thunk.
    SingleEntry(FrameLocalSingleEntryThunk),
    /// Omit storage for a proven-absent lazy binding.
    Omit,
}

/// A thunk allocation proven safe for a single-entry representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameLocalSingleEntryThunk {
    thunk: IrId,
    body: IrId,
}

impl FrameLocalSingleEntryThunk {
    /// Returns the thunk allocation node covered by the proof.
    pub const fn thunk(self) -> IrId {
        self.thunk
    }

    /// Returns the deferred body node inside the thunk allocation.
    pub const fn body(self) -> IrId {
        self.body
    }
}

/// Why a thunk allocation must keep ordinary update/blackhole state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameLocalThunkUpdateReason {
    /// The cardinality proof is absent, many-entry, or absent-but-not-omitted.
    CardinalityNotOnce {
        /// The cardinality fact that prevented the downgrade.
        cardinality: Cardinality,
    },
    /// The thunk allocation is not proven frame-local.
    EscapesFrame,
    /// An absent binding also has a strictness proof, so omission is unsound.
    AbsentButStrict,
    /// The facts kept update state through a conservative fallback.
    ConservativeFallback,
}

/// A failure while preflighting a single-entry thunk downgrade.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameLocalThunkDowngradeError {
    /// The requested IR node is missing.
    #[error("missing IR node {id:?}")]
    MissingNode {
        /// The missing node id.
        id: IrId,
    },
    /// The requested IR node lacks a fact record.
    #[error("missing fact record for IR node {id:?}")]
    MissingFact {
        /// The node whose fact record was missing.
        id: IrId,
    },
    /// The requested IR node is not a thunk allocation.
    #[error("IR node {id:?} is {kind:?}, not a thunk allocation")]
    NotThunkAlloc {
        /// The non-thunk node id.
        id: IrId,
        /// The actual node kind.
        kind: IrKind,
    },
    /// The thunk allocation references a missing body node.
    #[error("thunk allocation {id:?} references missing body node {body:?}")]
    MissingThunkBody {
        /// The thunk allocation node.
        id: IrId,
        /// The missing thunk body node.
        body: IrId,
    },
    /// A thunk allocation referenced itself as its deferred body.
    #[error("thunk allocation {id:?} references itself as its body")]
    SelfReferentialThunkBody {
        /// The malformed thunk allocation node.
        id: IrId,
    },
    /// A thunk allocation node carried a non-body payload.
    #[error("invalid payload for thunk allocation {id:?}: expected {expected}")]
    InvalidPayload {
        /// The malformed thunk allocation node.
        id: IrId,
        /// The expected payload shape.
        expected: &'static str,
    },
}
