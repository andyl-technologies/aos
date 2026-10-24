//! Declares packet routes as DATA independently of their actual native actor.

use crucible_node_format::{ContentRef, Endpoint, Id, U64};
use serde::{Deserialize, Serialize};

/// Declares one exact original admitted connection independently of input frames.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketInputConnection {
    /// Names the immutable admitted connection.
    pub id: Id,
    /// Binds the complete source-installed connection policy bytes.
    pub policy: ContentRef,
    /// Names the declared original producer lane.
    pub producer: Endpoint,
    /// Names the declared original consumer lane.
    pub consumer: Endpoint,
    /// Gives the exact physical propagation delay in picoseconds.
    pub delay_ps: U64,
}

/// Installs a finite input-reactive source without selecting CPU or clock fidelity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedDefinition {
    /// Selects `source-owned.packet-connected-program/4`.
    pub schema: String,
    /// Declares all original input connections; frames cannot add another route.
    pub connections: Vec<PacketInputConnection>,
    /// Selects the local output lane, or null for a consuming sink.
    pub output: Option<Endpoint>,
}
