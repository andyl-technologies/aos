//! Retains exact original input inventory bodies before native model capture.
//!
//! This closed codec covers the canonical ordered `Delivery` array already
//! committed by each original input batch. It authenticates no source authority;
//! the owning runtime and installed factory independently validate those inputs.

use crucible_node_contract::{ContentRef, Validate, canonical};

use crate::{
    node_contract::OriginalLineageInputRecord,
    node_scheduling::InputPayload,
    node_state::{StateError, StateLimits, schema},
};

use super::super::closure::bounded_record;
use super::refused;

const INVENTORY_MEDIA: &str = "application/vnd.crucible.input-inventory+json";

pub(super) struct InventoryCredit {
    pub(super) objects: usize,
    pub(super) bytes: usize,
}

pub(super) struct PreparedInventory {
    pub(super) body: InputPayload,
    pub(super) dependencies: Vec<ContentRef>,
}

/// Charges every original occurrence before any body or adjacency copy.
pub(super) fn credit(
    inputs: &[OriginalLineageInputRecord],
    limits: StateLimits,
) -> Result<InventoryCredit, StateError> {
    if inputs.len() > limits.maximum_content_objects {
        return Err(refused("original input inventory object credit exhausted"));
    }
    let mut bytes = 0usize;
    let mut edges = 0usize;
    for input in inputs {
        input.inventory.validate().map_err(schema)?;
        let length = usize::try_from(input.inventory.length.get()).map_err(schema)?;
        if input.inventory.media_type != INVENTORY_MEDIA
            || length
                > limits
                    .maximum_content_bytes
                    .min(limits.maximum_record_bytes)
        {
            return Err(refused("original input inventory role or extent changed"));
        }
        bytes = bytes
            .checked_add(length)
            .filter(|total| *total <= limits.maximum_total_content_bytes)
            .ok_or_else(|| refused("original input inventory byte credit exhausted"))?;
        let row_edges = input
            .deliveries
            .len()
            .checked_mul(3)
            .filter(|count| *count <= limits.maximum_content_objects)
            .ok_or_else(|| refused("original input inventory row credit exhausted"))?;
        edges = edges
            .checked_add(row_edges)
            .filter(|total| *total <= limits.maximum_dependency_edges)
            .ok_or_else(|| refused("original input inventory edge credit exhausted"))?;
        if input
            .deliveries
            .iter()
            .any(|delivery| delivery.connection_policy_ref.is_none())
        {
            return Err(refused("original input inventory connection policy absent"));
        }
        // The committed extent is the copy reservation, even when a corrupt
        // record claims a shorter body than its borrowed Delivery array.
        bounded_record(&input.deliveries, length)?;
    }
    Ok(InventoryCredit {
        objects: inputs.len(),
        bytes,
    })
}

/// Reconstructs the exact committed codec bytes and positive direct edges.
pub(super) fn prepare(
    inputs: &[OriginalLineageInputRecord],
    credit: &InventoryCredit,
) -> Result<Vec<PreparedInventory>, StateError> {
    let mut inventories = Vec::new();
    inventories
        .try_reserve_exact(credit.objects)
        .map_err(|_| refused("original input inventory reservation failed"))?;
    let mut remaining_bytes = credit.bytes;
    for input in inputs {
        let bytes =
            canonical::canonical_json(&serde_json::to_value(&input.deliveries).map_err(schema)?)
                .map_err(schema)?;
        let reference = canonical::content_ref(&bytes, INVENTORY_MEDIA).map_err(schema)?;
        if reference != input.inventory {
            return Err(refused(
                "original input inventory bytes or full reference changed",
            ));
        }
        remaining_bytes = remaining_bytes
            .checked_sub(bytes.len())
            .ok_or_else(|| refused("original input inventory exceeded reserved bytes"))?;
        let mut dependencies = Vec::new();
        let edges = input
            .deliveries
            .len()
            .checked_mul(3)
            .ok_or_else(|| refused("original input inventory edge count overflow"))?;
        dependencies
            .try_reserve_exact(edges)
            .map_err(|_| refused("original input inventory edge reservation failed"))?;
        for delivery in &input.deliveries {
            dependencies.push(delivery.payload.clone());
            dependencies.push(delivery.provenance_ref.clone());
            dependencies.push(
                delivery
                    .connection_policy_ref
                    .as_ref()
                    .ok_or_else(|| refused("original input inventory connection policy absent"))?
                    .clone(),
            );
        }
        dependencies.sort();
        dependencies.dedup();
        inventories.push(PreparedInventory {
            body: InputPayload { reference, bytes },
            dependencies,
        });
    }
    Ok(inventories)
}

#[cfg(test)]
#[path = "lineage_inventory_models.rs"]
mod models;
