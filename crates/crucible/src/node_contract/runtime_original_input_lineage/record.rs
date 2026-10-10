//! Defines the closed reference-bearing Runtime7 envelope without changing old wire.
//!
//! Payload and provenance bytes are separate full-typed inventory objects. This
//! DTO never constructs local permissions; the selected coordinator and native
//! continuation policy must authenticate every body and original scope first.
//!
//! ```json
//! {"schema_version":7,"source_activation":{},"capture_cut":{},"capture_ordinal":"1","owners":[],"operations":[],"inputs":[]}
//! ```

use super::*;
use crate::node_scheduling::NativeInputAcknowledgement;
use serde::{Deserialize, Serialize};

/// Retains legacy provenance1 meaning using external exact body references.
///
/// This is a Runtime7 representation, not an extension of SavedInputProvenance1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalLineageProvenanceRecord {
    /// Selects the original provenance meaning, currently edition one.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Names the original logical consumer.
    pub node: Id,
    /// Preserves the original staging operation identity.
    pub stage_operation: Id,
    /// Preserves the original frozen batch identity.
    pub batch: Id,
    /// Binds the exact original ordered delivery inventory.
    pub inventory: ContentRef,
    /// Preserves authenticated roots in original full-reference order.
    pub roots: Vec<ContentRef>,
    /// Names original proof bytes as complete typed roles.
    pub objects: Vec<ContentRef>,
}

/// Retains complete original input facts with reference-only body custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalLineageInputRecord {
    /// Names the logical consumer whose current native state was captured.
    pub node: Id,
    /// Preserves the original native staging operation identity.
    pub stage_operation: Id,
    /// Preserves the original frozen input batch identity.
    pub batch: Id,
    /// Preserves source-capture owner identities independently of the first seal.
    pub owners: Vec<OwnerIdentity>,
    /// Preserves the original exclusive input cut.
    pub cutoff: Position,
    /// Binds the exact ordered original deliveries.
    pub inventory: ContentRef,
    /// Retains every original Event ID, native FIFO and full Position unchanged.
    pub deliveries: Vec<crate::node_scheduling::event::Delivery>,
    /// Names original payload bytes as separate authenticated typed objects.
    pub payloads: Vec<ContentRef>,
    /// Retains original provenance without embedding large JSON byte arrays.
    #[serde(deserialize_with = "required_nullable")]
    pub provenance: Option<OriginalLineageProvenanceRecord>,
    /// Retains the immutable first-sealed producer/consumer input ancestry.
    #[serde(deserialize_with = "required_nullable")]
    pub lineage: Option<SavedOriginalInputLineage>,
    /// Retains original native input ACK knowledge; it does not authorize replay.
    #[serde(deserialize_with = "required_nullable")]
    pub acknowledgement: Option<NativeInputAcknowledgement>,
    /// Retains original failure and effect knowledge without asserting rollback.
    #[serde(deserialize_with = "required_nullable")]
    pub failure: Option<OperationFailure>,
    /// Retains original completed transfer to the coordinator.
    pub committed: bool,
    /// Retains the original canonical staging commitment.
    pub coordinator_committed: bool,
}

/// Encodes complete Runtime7 historical ledgers and exact lineage references.
///
/// Terminal, fault, condition and other selected runtime editions cannot be
/// combined implicitly. Legacy native/coordinator decoders remain unsupported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalLineageRuntimeRecord {
    /// Selects the explicit closed Runtime7 envelope.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Retains actual source-capture activation separately from first-sealed lineage.
    pub source_activation: SavedRuntimeActivation,
    /// Preserves the exact original complete-world cut.
    pub capture_cut: Position,
    /// Preserves the original coordinator event ordinal.
    pub capture_ordinal: U64,
    /// Enumerates original complete owner custody in canonical order.
    pub owners: Vec<SavedRuntimeOwner>,
    /// Retains original native permission, output, pending and ACK facts as data.
    pub operations: Vec<SavedRuntimeOperation>,
    /// Retains the entire input roster, including original immutable lineage.
    pub inputs: Vec<OriginalLineageInputRecord>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
