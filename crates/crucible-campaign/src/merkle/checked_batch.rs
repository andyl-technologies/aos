//! Bounded checked Merkle updates that visit each affected trie node once.
//!
//! One sorted page of upserts shares traversal and publishes only final nodes.
//! Ordinary pages retain at most 64 upserts. A prepaid first-nibble partition
//! may coalesce 1024 upserts while durable publication remains bounded to 64
//! objects; neither the incoming collection nor intermediate roots accumulate.

use crucible_cas::content_store::StoreError;
use crucible_cas::owned_decode::{DecodeBudget, DecodeScratch};

use super::*;

impl MerkleMap {
    /// Maximum upserts retained by one checked Merkle batch.
    pub const MAX_CHECKED_BATCH_UPSERTS: usize = MAX_NODE_PUBLICATION_BATCH;

    /// Applies one bounded, strictly sorted page under the caller's original account.
    ///
    /// Each affected old node is authenticated once. Final children are published
    /// before their parents in bounded checked storage batches. A failed call
    /// never returns a replacement root; immutable orphan nodes are harmless.
    /// The caller retains its previous root until this operation succeeds.
    /// Referenced values must already be available before the map is treated as
    /// an authenticated storage closure, just as with ordinary point insertion.
    ///
    /// # Errors
    /// Refuses oversized, duplicate or unordered input, original admission or
    /// boundary failure, corrupt old nodes, and checked storage publication failure.
    pub fn insert_batch_with_boundary(
        &self,
        prior: ContentId,
        entries: &[(CampaignHash, ContentId)],
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        check(original, boundary)?;
        if entries.len() > Self::MAX_CHECKED_BATCH_UPSERTS
            || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(invalid("checked-batch-keys-not-bounded-and-ascending"));
        }
        let _scope = original.enter();
        let credit = original
            .reserve_scratch_array::<(ContentId, BlobHandle)>(MAX_NODE_PUBLICATION_BATCH)
            .map_err(CampaignCodecError::from)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(MAX_NODE_PUBLICATION_BATCH)
            .map_err(|error| {
                CampaignCodecError::DecodeAdmission(
                    crucible_cas::owned_decode::DecodeAdmissionError::new(error),
                )
            })?;
        let mut writer = BatchWriter {
            map: self,
            original,
            boundary,
            pending,
            pending_bytes: 0,
            _credit: credit,
        };
        let node = writer.read_node(prior, 0)?;
        let root = writer.update(node, Some(prior), entries)?;
        writer.publish()?;
        check(writer.original, writer.boundary)?;
        Ok(root)
    }

    /// Maximum sorted upserts coalesced within one first-nibble partition.
    ///
    /// Sixteen neighboring 64-entry pages share the same first trie branch.
    /// Immutable node publication still retains at most 64 objects per batch.
    pub const MAX_CHECKED_PREFIX_UPSERTS: usize = 16 * MAX_NODE_PUBLICATION_BATCH;

    /// Coalesces one bounded first-nibble partition under the original account.
    ///
    /// Final nodes share the existing checked writer and 64-object durable
    /// publication batches. No replacement root escapes until the final partial
    /// batch and the original boundary succeed. The borrowed input must remain
    /// prepaid by its caller; referenced values have the same availability
    /// requirement as [`Self::insert_batch_with_boundary`].
    ///
    /// # Errors
    /// Refuses oversized, duplicate, unordered or mixed-partition input,
    /// original admission or boundary failure, corrupt old nodes, and checked
    /// storage publication failure.
    pub fn insert_prefix_batch_with_boundary(
        &self,
        prior: ContentId,
        entries: &[(CampaignHash, ContentId)],
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        check(original, boundary)?;
        if entries.len() > Self::MAX_CHECKED_PREFIX_UPSERTS
            || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || entries.first().is_some_and(|(first, _)| {
                entries
                    .iter()
                    .any(|(key, _)| digest_nibble(*key, 0) != digest_nibble(*first, 0))
            })
        {
            return Err(invalid(
                "checked-prefix-keys-not-bounded-ascending-and-shared",
            ));
        }
        let _scope = original.enter();
        let credit = original
            .reserve_scratch_array::<(ContentId, BlobHandle)>(MAX_NODE_PUBLICATION_BATCH)
            .map_err(CampaignCodecError::from)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(MAX_NODE_PUBLICATION_BATCH)
            .map_err(|error| {
                CampaignCodecError::DecodeAdmission(
                    crucible_cas::owned_decode::DecodeAdmissionError::new(error),
                )
            })?;
        let mut writer = BatchWriter {
            map: self,
            original,
            boundary,
            pending,
            pending_bytes: 0,
            _credit: credit,
        };
        let node = writer.read_node(prior, 0)?;
        let root = writer.update(node, Some(prior), entries)?;
        writer.publish()?;
        check(writer.original, writer.boundary)?;
        Ok(root)
    }
}

struct BatchWriter<'a> {
    map: &'a MerkleMap,
    original: &'a DecodeBudget,
    boundary: &'a mut dyn FnMut() -> Result<(), StoreError>,
    pending: Vec<(ContentId, BlobHandle)>,
    pending_bytes: u64,
    // Prepared sources and the Vec allocation close before their original credit.
    _credit: DecodeScratch,
}

impl BatchWriter<'_> {
    fn read_node(&mut self, id: ContentId, depth: u8) -> Result<MerkleNode, CampaignStoreError> {
        self.map
            .read_checked_node(id, depth, self.original, self.boundary)
    }

    fn update(
        &mut self,
        mut node: MerkleNode,
        prior: Option<ContentId>,
        entries: &[(CampaignHash, ContentId)],
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        let mut remaining = entries;
        while let Some((key, _)) = remaining.first() {
            check(self.original, self.boundary)?;
            let slot = digest_nibble(*key, node.depth);
            let count =
                remaining.partition_point(|(key, _)| digest_nibble(*key, node.depth) == slot);
            let (group, tail) = remaining.split_at(count);
            let existing = node.entries.get(&slot).cloned();
            let replacement = self.update_slot(node.depth, existing, group)?;
            if !node.entries.contains_key(&slot) {
                self.original
                    .charge_btree_entry::<u8, MerkleEntry>()
                    .map_err(CampaignCodecError::from)?;
            }
            node.entries.insert(slot, replacement);
            remaining = tail;
        }
        node.recompute_count()?;
        if entries.is_empty() {
            return Ok(MerkleMapRoot {
                content_id: prior.ok_or(invalid("empty-new-checked-batch-node"))?,
                entry_count: node.entry_count,
            });
        }
        let (id, source) = MerkleMap::prepare_node(&node)?;
        check(self.original, self.boundary)?;
        if Some(id) != prior {
            let length = source.logical_length();
            if self.pending.len() == MAX_NODE_PUBLICATION_BATCH
                || self.pending_bytes + length > MAX_NODE_PUBLICATION_BYTES
            {
                self.publish()?;
            }
            self.pending_bytes += length;
            self.pending.push((id, source));
        }
        Ok(MerkleMapRoot {
            content_id: id,
            entry_count: node.entry_count,
        })
    }

    fn update_slot(
        &mut self,
        depth: u8,
        existing: Option<MerkleEntry>,
        entries: &[(CampaignHash, ContentId)],
    ) -> Result<MerkleEntry, CampaignStoreError> {
        if entries.len() == 1 {
            let (key, value) = entries[0];
            if existing.as_ref().is_none_or(|old| {
                matches!(old,
                MerkleEntry::Leaf { key: old_key, .. } if *old_key == key)
            }) {
                return Ok(MerkleEntry::Leaf { key, value });
            }
        }
        let next = depth
            .checked_add(1)
            .filter(|depth| *depth < DIGEST_NIBBLES)
            .ok_or(invalid("distinct-keys-exhausted-digest"))?;
        let (node, prior) = match existing {
            Some(MerkleEntry::Node {
                content_id,
                entry_count,
            }) => {
                let node = self.read_node(content_id, next)?;
                if node.entry_count != entry_count {
                    return Err(invalid("child-entry-count-mismatch"));
                }
                (node, Some(content_id))
            }
            leaf => {
                let mut node = MerkleNode {
                    schema_version: MERKLE_NODE_SCHEMA_VERSION,
                    depth: next,
                    entry_count: 0,
                    entries: BTreeMap::new(),
                };
                if let Some(old @ MerkleEntry::Leaf { key, .. }) = leaf {
                    self.original
                        .charge_btree_entry::<u8, MerkleEntry>()
                        .map_err(CampaignCodecError::from)?;
                    node.entries.insert(digest_nibble(key, next), old);
                }
                (node, None)
            }
        };
        let root = self.update(node, prior, entries)?;
        Ok(MerkleEntry::Node {
            content_id: root.content_id,
            entry_count: root.entry_count,
        })
    }

    fn publish(&mut self) -> Result<(), CampaignStoreError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let _receipts = publish_nodes(self.map, self.original, self.boundary, &self.pending)?;
        self.pending.clear();
        self.pending_bytes = 0;
        Ok(())
    }
}

pub(super) fn publish_nodes(
    map: &MerkleMap,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    pending: &[(ContentId, BlobHandle)],
) -> Result<crucible_cas::content_store::PutBatchReceipt, CampaignStoreError> {
    check(original, boundary)?;
    let receipts = map
        .backend
        .put_many_if_absent_with_boundary(original, pending, boundary)?;
    if receipts.len() != pending.len()
        || receipts
            .iter()
            .zip(pending)
            .any(|(receipt, (id, _))| receipt.id != *id)
    {
        return Err(invalid("store-batch-receipt-mismatch"));
    }
    check(original, boundary)?;
    Ok(receipts)
}

pub(super) fn check(
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), CampaignStoreError> {
    original.verify_live().map_err(CampaignCodecError::from)?;
    boundary()?;
    original.verify_live().map_err(CampaignCodecError::from)?;
    Ok(())
}
