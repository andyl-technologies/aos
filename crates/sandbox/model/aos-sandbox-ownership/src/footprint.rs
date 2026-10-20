//! Sizes the dominant requested buffers and carriers of historical replay.
//!
//! These are passive checked layout bounds. They neither authenticate supplied
//! rows nor construct an issuer, native writer or paid receiving original.

use std::mem::{align_of, size_of};

use super::*;

impl OwnershipHistoryBounds {
    /// Bounds additional replay memory from a caller's complete native row shape.
    ///
    /// The actual protected owner must derive these counts and encoded bytes
    /// from its held Journal before allocating decoded history. The result
    /// excludes the original native/materialized Journal, trust bootstrap and
    /// caller's resident owner; those are independently retained and paid.
    ///
    /// Returns `None` for an impossible v1 extent or checked arithmetic overflow.
    /// A successful calculation is DATA and supplies no provenance or grant.
    #[must_use]
    pub fn replay_requested_memory_bytes_v1(
        entries: usize,
        entry_bytes: usize,
        currents: usize,
    ) -> Option<usize> {
        if entries > MAXIMUM_DURABLE_ENTRIES || currents > entries
            || entry_bytes > entries.checked_mul(MAXIMUM_DURABLE_ENTRY_BYTES)?
        {
            return None;
        }
        let entry_maps = tree_node_bytes::<[u8; 16], DurableOwnershipEntry>()?
            .checked_add(tree_node_bytes::<SandboxId, Vec<(&[u8; 16], &DurableOwnershipEntry)>>()?)?
            .checked_add(tree_node_bytes::<(u64, [u8; 32]), [u8; 16]>()?)?
            .checked_add(tree_node_bytes::<[u8; 16], [u8; 16]>()?)?
            .checked_add(tree_node_bytes::<[u8; 16], ()>()?)?;
        let current_maps = tree_node_bytes::<SandboxId, ([u8; 16], u64, ObjectDigest)>()?
            .checked_add(tree_node_bytes::<SandboxId, RecoveredOwnershipLease>()?)?;
        // Entries retain boxed decoded leases; current heads clone their
        // canonical artifacts. A pending-successor check also owns one clone.
        let models = entries.checked_mul(size_of::<RecoveredOwnershipLease>()
            .checked_add(3 * 255)?)?;
        // The grouped/pending/completed/root vectors coexist. Four slots per
        // logical input cover their ordinary Vec minimum/growth capacities.
        let references = entries.checked_mul(4)?.checked_mul(
            size_of::<(&[u8; 16], &DurableOwnershipEntry)>()
                .checked_add(size_of::<&(&[u8; 16], &DurableOwnershipEntry)>())?
                .checked_add(size_of::<(&[u8; 16], &DurableOwnershipEntry, &Box<RecoveredOwnershipLease>)>())?
                .checked_add(size_of::<&(&[u8; 16], &DurableOwnershipEntry, &Box<RecoveredOwnershipLease>)>())?,
        )?;
        let temporary_current = if entries == 0 { 0 } else {
            tree_node_bytes::<SandboxId, RecoveredOwnershipLease>()?
        };
        // The historical verifier can hold the response, its nonauthorizing
        // proof copy, receipt/model strings and canonical signing-message
        // encodings beside previously decoded entries. Eight encoded extents
        // cover those requested buffers including ordinary encoder Vec growth;
        // the separately paid trust-policy scratch is not multiplied by rows.
        entry_bytes.checked_mul(8)?
            .checked_add(entries.checked_mul(entry_maps)?)?
            .checked_add(currents.checked_mul(current_maps)?)?
            .checked_add(models)?
            .checked_add(references)?
            .checked_add(temporary_current)
    }
}

// Pinned Rust1.98 liballoc btree/node.rs uses B=6: eleven key/value slots and
// twelve child edges. Charge a complete internal node per logical map entry;
// every nonempty node owns at least one key. Extra aligned header words cover
// parent/index/length and array padding without depending on private offsets.
fn tree_node_bytes<K, V>() -> Option<usize> {
    size_of::<K>().checked_add(size_of::<V>())?.checked_mul(11)?
        .checked_add(16 * size_of::<usize>())?
        .checked_add(align_of::<K>())?
        .checked_add(align_of::<V>())
}
