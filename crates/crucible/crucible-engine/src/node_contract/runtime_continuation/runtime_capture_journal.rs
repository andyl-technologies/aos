//! Defines explicit administrative capture history without altering Runtime7.
//!
//! Archive index three requires this separate typed closure. These serialized
//! rows are historical facts; only the actual runtime issues an original ticket
//! and installed source-specific codecs authenticate request/response custody.
//!
//! ```text
//! {"schema_version":1,"maximum_attempts":"64","attempts":[{"sequence":"1","capture_id":"capture/1","source_runtime":{},"source_activation":{},"cut":{},"ordinal":"0","owners":[]}]}
//! ```

use crucible_node_format::{ContentRef, Id, Position, U64};
use serde::{Deserialize, Serialize};

use crate::node_contract::{OwnerIdentity, SavedRuntimeActivation};

/// Retains each original administrative capture attempt across fresh restoration.
///
/// Attempt IDs and lifetime credit are never reset by a native or host restart.
/// An unsettled current attempt prevents archive signing and execution release.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOriginalCaptureJournal {
    /// Selects the distinct administrative journal, exactly edition one.
    pub schema_version: u16,
    /// Retains the source-selected lifetime attempt ceiling without renewal.
    pub maximum_attempts: U64,
    /// Preserves complete original attempts in strictly increasing sequence order.
    pub attempts: Vec<OriginalCaptureAttemptRecord>,
}

/// Retains the exact source scope and full original owner reservations for one attempt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalCaptureAttemptRecord {
    /// Retains the core-issued lifetime administrative sequence.
    pub sequence: U64,
    /// Names the actual capture without manufacturing a modeled grant.
    pub capture_id: Id,
    /// Binds the complete original Runtime7 object used by this same attempt.
    pub source_runtime: ContentRef,
    /// Preserves the actual capture-time owner incarnation and complete world.
    pub source_activation: SavedRuntimeActivation,
    /// Retains the unchanged superdense model cut.
    pub cut: Position,
    /// Retains the unchanged coordinator event ordinal.
    pub ordinal: U64,
    /// Preserves the full original owner roster, including the genuine host owner.
    pub owners: Vec<OriginalCaptureOwnerRecord>,
}

/// Retains one actual owner request reservation and its original settlement knowledge.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalCaptureOwnerRecord {
    /// Preserves actual source-time owner incarnation without rebinding history.
    pub owner: OwnerIdentity,
    /// Enumerates every original participant sharing this authoritative owner.
    pub participants: Vec<Id>,
    /// Retains the core-issued administrative operation namespace and identity.
    pub operation: Id,
    /// Preserves knowledge of this same original attempt, including uncertainty.
    pub state: OriginalCaptureOwnerState,
}

/// Preserves administrative effects separately from modeled execution history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OriginalCaptureOwnerState {
    /// Retains precharged original request custody before any callback effect.
    Reserved,
    /// Retains the same possibly effective original request before settled response.
    Submitted,
    /// Retains actual source-authenticated snapshot and exact settled response history.
    Settled {
        /// Binds the complete native or common host snapshot for this owner.
        snapshot: ContentRef,
        /// Binds the source-specific original request/response settlement journal.
        journal: Box<ContentRef>,
    },
    /// Retains sticky uncertain knowledge and forbids signing or new execution.
    Uncertain,
}
