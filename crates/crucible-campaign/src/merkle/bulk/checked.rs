//! Original-account emission for the shared canonical sorted traversal.
// SPDX-License-Identifier: Apache-2.0

use crucible_cas::content_store::StoreError;
use crucible_cas::owned_decode::DecodeScratch;

use super::*;
use crate::merkle::checked_batch::{check, publish_nodes};

impl MerkleMap {
    /// Builds one canonical map from a fallible, strictly sorted stream.
    ///
    /// Final nodes share the ordinary traversal and wire encoding. Publication
    /// retains at most 64 objects/4 MiB. The caller owns the incoming stream's
    /// buffers; input failures, including an authenticated tail failure, prevent
    /// a replacement root from escaping.
    ///
    /// # Errors
    /// Returns input/order/schema, original admission, boundary or publication
    /// failures. Referenced values retain the ordinary availability contract.
    pub fn build_from_sorted_with_boundary<I>(
        &self,
        entries: I,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleMapRoot, CampaignStoreError>
    where
        I: IntoIterator<Item = Result<(CampaignHash, ContentId), StoreError>>,
    {
        check(original, boundary)?;
        let _entries_credit = original
            .reserve_scratch_array::<SortedEntries<I::IntoIter>>(1)
            .map_err(CampaignCodecError::from)?;
        let mut entries = SortedEntries::new(entries.into_iter());
        let mut sink = CheckedSink::new(self, original, boundary)?;
        let root = match entries.next()? {
            Some(first) => build_node(0, first, &mut entries, &mut sink)?,
            None => {
                let account = sink
                    .begin_node()?
                    .ok_or(invalid("checked-builder-missing-account"))?;
                let _scope = account.enter();
                sink.emit(
                    &MerkleNode {
                        schema_version: MERKLE_NODE_SCHEMA_VERSION,
                        depth: 0,
                        entry_count: 0,
                        entries: BTreeMap::new(),
                    },
                    Some(&account),
                )?
            }
        };
        if entries.peek()?.is_some() {
            return Err(invalid("sorted-builder-left-unconsumed-entry"));
        }
        sink.publish()?;
        check(sink.original, sink.boundary)?;
        Ok(root)
    }
}

struct CheckedSink<'a> {
    map: &'a MerkleMap,
    original: &'a DecodeBudget,
    boundary: &'a mut dyn FnMut() -> Result<(), StoreError>,
    pending: Vec<(ContentId, BlobHandle)>,
    bytes: u64,
    _credit: DecodeScratch,
}

impl<'a> CheckedSink<'a> {
    fn new(
        map: &'a MerkleMap,
        original: &'a DecodeBudget,
        boundary: &'a mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, CampaignStoreError> {
        let extent = MAX_NODE_PUBLICATION_BATCH
            .checked_mul(std::mem::size_of::<(ContentId, BlobHandle)>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(StoreError::Quota)?;
        let credit = original
            .reserve_scratch_bytes(extent as u64)
            .map_err(CampaignCodecError::from)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(MAX_NODE_PUBLICATION_BATCH)
            .map_err(|error| {
                CampaignStoreError::Store(StoreError::Allocation {
                    source: error,
                    custody: Some(original.custody()),
                })
            })?;
        Ok(Self {
            map,
            original,
            boundary,
            pending,
            bytes: 0,
            _credit: credit,
        })
    }

    fn publish(&mut self) -> Result<(), CampaignStoreError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let receipts = publish_nodes(self.map, self.original, self.boundary, &self.pending)?;
        let _receipts = receipts.accept_with_boundary(self.boundary)?;
        self.pending.clear();
        self.bytes = 0;
        Ok(())
    }
}

impl NodeSink for CheckedSink<'_> {
    fn begin_node(&mut self) -> Result<Option<DecodeBudget>, CampaignStoreError> {
        check(self.original, self.boundary)?;
        let account = self.original.child().map_err(CampaignCodecError::from)?;
        account
            .charge_array::<MerkleNode>(1)
            .map_err(CampaignCodecError::from)?;
        Ok(Some(account))
    }

    fn emit(
        &mut self,
        node: &MerkleNode,
        account: Option<&DecodeBudget>,
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        check(self.original, self.boundary)?;
        let account = account.ok_or(invalid("checked-builder-missing-node-account"))?;
        let _scope = account.enter();
        node.validate()?;
        let body = codec::encode(node);
        let envelope = ObjectEnvelope::for_record(
            CampaignRecordKind::MerkleNode,
            node.child_references()?,
            body,
        )?;
        // Canonical temporaries belong to the currently entered node child.
        // Source bytes get their own linear original loan before that child ends.
        account.check().map_err(CampaignCodecError::from)?;
        let bytes = envelope.canonical_bytes_with_boundary(self.original, self.boundary)?;
        if bytes.len() > MAX_MERKLE_NODE_ENVELOPE_BYTES {
            return Err(StoreError::Quota.into());
        }
        let id = envelope.content_id();
        let length = bytes.len() as u64;
        if self.pending.len() == MAX_NODE_PUBLICATION_BATCH
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|bytes| bytes > MAX_NODE_PUBLICATION_BYTES)
        {
            self.publish()?;
        }
        let source = BlobHandle::from_owned_bytes(bytes)?;
        self.bytes = self.bytes.checked_add(length).ok_or(StoreError::Quota)?;
        self.pending.push((id, source));
        check(self.original, self.boundary)?;
        Ok(MerkleMapRoot {
            content_id: id,
            entry_count: node.entry_count,
        })
    }
}
