//! Preserves closed common semantic and first-ancestry data for archive checks.
//!
//! Decoding creates historical data only. Installed source, full native model,
//! complete protocol, backend, signed index and fresh target checks are separate
//! conjunctions; this module cannot construct a runtime permission.

use super::*;
use crate::node_contract::NodeRuntime;
use serde::Deserialize;

#[path = "archive_semantics/construction_storage.rs"]
pub(super) mod construction_storage;
#[path = "archive_semantics/data.rs"]
pub(super) mod data;
#[path = "archive_semantics/protocol.rs"]
mod protocol;
#[path = "archive_semantics/validate.rs"]
mod validate;

#[cfg(test)]
#[path = "archive_semantics/tests.rs"]
mod tests;

/// Retains every original common custody and immutable ancestry field as data.
///
/// The source factory keeps this owner beside the authenticated archive and the
/// full host/native protocol owners through validation and fresh installation.
/// It has no deserializer for WorldActivation, OperationAdmission or input seals.
pub struct PacketCompleteArchivedSemantics {
    semantic: data::ArchivedSemanticCustody,
    ancestry: data::ArchivedAncestry,
    reserved_decoder_bytes: usize,
}

impl PacketCompleteArchivedSemantics {
    pub(in crate::node_adapters::cnp::semantic) fn source_common_data(
        &self,
    ) -> &data::ArchivedSemanticCustody {
        &self.semantic
    }

    pub(in crate::node_adapters::cnp::semantic) fn source_ancestry_data(
        &self,
    ) -> &data::ArchivedAncestry {
        &self.ancestry
    }

    pub(in crate::node_adapters::cnp::semantic) fn source_reference_ancestry_data(
        &self,
    ) -> Result<&data::ArchivedAncestryRecord<crucible_node_contract::ContentRef>, OperationFailure>
    {
        match &self.ancestry {
            data::ArchivedAncestry::References(record) => Ok(record),
            data::ArchivedAncestry::Inline(_) => {
                Err(refused("source requires reference-only ancestry/12"))
            }
        }
    }

    /// Counts closed decoder storage before either historical tree is allocated.
    ///
    /// The result is requested decoder storage, not a native physical peak. The
    /// caller includes both original byte buffers and all other retained owners
    /// independently in its aggregate budget.
    ///
    /// # Errors
    /// Refuses oversized records, invalid decoder geometry or arithmetic excess.
    pub fn decode_demand_data(
        semantic: &[u8],
        ancestry: &[u8],
        maximum_record_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<usize, OperationFailure> {
        if semantic.len() > maximum_record_bytes || ancestry.len() > maximum_record_bytes {
            return Err(refused("archived semantic record exceeds selected ceiling"));
        }
        decode_storage(semantic, maximum_total_bytes)
            .map_err(unknown)?
            .checked_add(decode_storage(ancestry, maximum_total_bytes).map_err(unknown)?)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
            .filter(|n| *n <= maximum_total_bytes)
            .ok_or_else(|| refused("archived semantic decoder storage exhausted"))
    }

    /// Decodes complete historical records under a caller's aggregate budget.
    ///
    /// No native callback or permission construction occurs. Unknown fields,
    /// missing nullable fields and duplicate keys refuse instead of projecting
    /// away state that another complete archive would have retained.
    ///
    /// # Errors
    /// Refuses malformed records, unsupported schemas or exhausted named storage.
    pub fn decode_data(
        semantic: &[u8],
        ancestry: &[u8],
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<Self, OperationFailure> {
        let demand = Self::decode_demand_data(
            semantic,
            ancestry,
            maximum_record_bytes,
            maximum_total_bytes,
        )?;
        additional_retained_bytes
            .checked_add(demand)
            .filter(|n| *n <= maximum_total_bytes)
            .ok_or_else(|| refused("archived semantic aggregate storage exhausted"))?;
        let semantic = canonical::parse_json(semantic, maximum_record_bytes).map_err(unknown)?;
        let ancestry = canonical::parse_json(ancestry, maximum_record_bytes).map_err(unknown)?;
        // Keep both original DOMs while constructing the typed owner. The
        // second decoder credit covers the simultaneous roundtrip DOM and
        // serde enum-content temporaries. Whole-tree equality also requires
        // explicit nulls and forbids silently dropped fields in nested types.
        let owner = Self {
            semantic: data::ArchivedSemanticCustody::deserialize(&semantic).map_err(unknown)?,
            ancestry: data::ArchivedAncestry::decode(&ancestry)?,
            reserved_decoder_bytes: demand,
        };
        if serde_json::to_value(&owner.semantic).map_err(unknown)? != semantic
            || serde_json::to_value(&owner.ancestry).map_err(unknown)? != ancestry
        {
            return Err(refused("archived semantic grammar loses original fields"));
        }
        if owner.semantic.schema != "source-owned.packet-semantic-custody/5" {
            return Err(refused("archived semantic or ancestry schema differs"));
        }
        Ok(owner)
    }
}

fn decode_storage(
    bytes: &[u8],
    maximum: usize,
) -> Result<usize, crate::node_contract::RuntimeError> {
    use data::*;
    use std::mem::size_of;

    let slot = [
        size_of::<ArchivedSemanticCustody>(),
        size_of::<ArchivedAncestry>(),
        size_of::<ArchivedReady>(),
        size_of::<ArchivedBatch>(),
        size_of::<ArchivedCommit>(),
        size_of::<ArchivedCommitment>(),
        size_of::<ArchivedInput>(),
        size_of::<ArchivedOperation>(),
        size_of::<ArchivedPublication<crate::node_scheduling::InputPayload>>(),
        size_of::<ArchivedLineage<crate::node_scheduling::InputPayload>>(),
        size_of::<ArchivedPublication<crucible_node_contract::ContentRef>>(),
        size_of::<ArchivedLineage<crucible_node_contract::ContentRef>>(),
        size_of::<serde_json::Value>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let map = NodeRuntime::capture_map_node_storage::<crucible_node_contract::Id, ArchivedInput>()
        .max(NodeRuntime::capture_map_node_storage::<
            crucible_node_contract::Id,
            ArchivedOperation,
        >())
        .max(NodeRuntime::capture_map_node_storage::<
            String,
            serde_json::Value,
        >());
    NodeRuntime::capture_selected_json_decode_storage(bytes, slot, map, maximum)
}

#[path = "archive_semantics/decoded_storage.rs"]
pub(super) mod decoded_storage;

#[path = "archive_semantics/initial15.rs"]
pub(super) mod initial15;

#[path = "archive_semantics/terminal_quote.rs"]
mod terminal_quote;
