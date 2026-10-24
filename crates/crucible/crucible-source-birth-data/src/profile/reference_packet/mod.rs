//! Defines immutable packet profile vocabulary without a native program owner.

use crucible_node_format::{Bytes, Id, Position};
use serde::{Deserialize, Serialize};

/// Binds the complete original source configuration independently of wire claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketProgramDefinition {
    /// Names the selected format, `source-owned.packet-program.v1`.
    pub schema: String,
    /// Lists every original native callback and its exact effect in FIFO order.
    pub events: Vec<PacketEvent>,
}

/// Defines one indivisible actual source callback and its native effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketEvent {
    /// Names the original native event independently of public fanout IDs.
    pub id: Id,
    /// Gives the first semantic transition within this callback.
    pub evaluation: Position,
    /// Gives its last semantic transition; the entire callback requires this below the cut.
    pub completion: Position,
    /// Carries output bytes, or null for an independently observable private mutation.
    pub payload: Option<Bytes>,
}

pub mod connected;
pub mod control;
pub mod coordinator;
pub mod service;

/// Shares the original continuation schema constructors.
pub mod continuation_contracts;
/// Shares the original static packet contract data.
pub mod contracts;
/// Names the original input contract feature.
pub mod input;

/// Reuses the original connected input feature identity.
pub mod input_features;
/// Reuses the original complete-preservation feature identity.
pub mod lineage_features;

pub(crate) use service::native5_policy::Native5PolicyData as Native5Policy;
