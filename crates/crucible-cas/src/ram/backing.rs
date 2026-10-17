//! Checked canonical byte bounds for independently retained RAM graph versions.
//!
//! Bounds assume no deduplication between pages or versions. Backend physical
//! allocation, indexes and replication are separate admission obligations.

use std::collections::BTreeSet;

use crucible_ram::{Limits, Topology};

use crate::content_envelope::{ContentChild, ContentEnvelope};
use crate::content_store::{ContentId, ObjectKind};

use super::RamStoreError;
use super::codec::{PAGE_SCHEMA, ROOT_SCHEMA, SCHEMA_VERSION, TREE_SCHEMA};

/// Bounds canonical CAS bytes for complete simultaneously retained RAM versions.
///
/// Every region retains its complete padded binary catalog and every position
/// may have unique page contents. Envelope sizes use the actual CAS encoder;
/// the root reserves its format's maximum encoded record. This is a canonical
/// storage bound, not a certificate for a backend's physical allocation peak.
///
/// # Errors
/// Rejects an empty topology, zero versions, arithmetic overflow or an invalid
/// canonical envelope contract.
pub fn maximum_encoded_ram_graph_bytes(
    topology: &Topology,
    live_versions: u64,
) -> Result<u64, RamStoreError> {
    if topology.total_logical_bytes() == 0 || live_versions == 0 {
        return Err(RamStoreError::Invalid("RAM graph backing geometry"));
    }
    let page_id = ContentId::for_bytes(ObjectKind::RamExtent, SCHEMA_VERSION, b"size-page");
    let tree_id = ContentId::for_bytes(ObjectKind::RamTree, SCHEMA_VERSION, b"size-tree");
    let page_bytes = envelope_bytes(PAGE_SCHEMA, BTreeSet::new(), 32 + 4 + 4096)?;
    let tree_children = BTreeSet::from([
        ContentChild::new("left", tree_id)?,
        ContentChild::new("right", tree_id)?,
    ]);
    let branch_bytes = envelope_bytes(TREE_SCHEMA, tree_children, 1 + 32 + 4 + 8 + 2 * 44)?;
    let leaf_bytes = envelope_bytes(
        TREE_SCHEMA,
        BTreeSet::from([ContentChild::new("page", page_id)?]),
        1 + 32 + 4 + 8 + 32,
    )?;
    let maximum_tree_bytes = branch_bytes.max(leaf_bytes);

    let mut total = 0_u64;
    let mut root_children = BTreeSet::new();
    for (index, region) in topology.regions().iter().enumerate() {
        let pages = region.geometry().page_count();
        let padded_pages = pages
            .checked_next_power_of_two()
            .ok_or(RamStoreError::Limit("RAM graph backing bytes"))?;
        let tree_nodes = padded_pages
            .checked_mul(2)
            .and_then(|nodes| nodes.checked_sub(1))
            .ok_or(RamStoreError::Limit("RAM graph backing bytes"))?;
        let bytes = pages
            .checked_mul(page_bytes)
            .and_then(|bytes| {
                tree_nodes
                    .checked_mul(maximum_tree_bytes)
                    .and_then(|catalog| bytes.checked_add(catalog))
            })
            .ok_or(RamStoreError::Limit("RAM graph backing bytes"))?;
        total = total
            .checked_add(bytes)
            .ok_or(RamStoreError::Limit("RAM graph backing bytes"))?;
        root_children.insert(ContentChild::new(format!("region-{index:08x}"), tree_id)?);
    }
    let references = topology
        .regions()
        .len()
        .checked_mul(44)
        .and_then(|bytes| bytes.checked_add(4))
        .and_then(|bytes| bytes.checked_add(Limits::default().max_record_bytes))
        .ok_or(RamStoreError::Limit("RAM root backing bytes"))?;
    let root_bytes = envelope_bytes(ROOT_SCHEMA, root_children, references)?;
    total
        .checked_add(root_bytes)
        .and_then(|bytes| bytes.checked_mul(live_versions))
        .ok_or(RamStoreError::Limit("RAM graph backing bytes"))
}

fn envelope_bytes(
    schema: &str,
    children: BTreeSet<ContentChild>,
    body_bytes: usize,
) -> Result<u64, RamStoreError> {
    let envelope = ContentEnvelope::new(schema, SCHEMA_VERSION, children, vec![0; body_bytes])?;
    u64::try_from(envelope.canonical_bytes().len())
        .map_err(|_| RamStoreError::Limit("RAM envelope backing bytes"))
}
