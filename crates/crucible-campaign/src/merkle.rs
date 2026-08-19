//! Persistent canonical Merkle maps for authoritative campaign roots.
//!
//! Maps use a fixed-depth hexadecimal trie over a [`CampaignHash`]. Each
//! immutable node is stored in a [`crate::ObjectEnvelope`] whose declared child
//! table exactly covers its child nodes and values. The shape therefore depends
//! only on the final key/value set, not insertion order. Updating one key
//! rewrites at most one node per digest nibble and shares all unaffected nodes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible_cas::content_store::{BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind};
use thiserror::Error;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{CampaignCodecError, CampaignHash, CampaignRecordKind, ChildReference, ObjectEnvelope};

const MERKLE_NODE_SCHEMA_VERSION: u32 = 1;
const MAX_ENVELOPE_BYTES: u64 = codec::MAX_CANONICAL_BYTES as u64;
const MAX_PAGE_ITEMS: usize = 10_000;
const DIGEST_NIBBLES: u8 = 64;
const MAX_VERIFIED_NODES: usize = 1_000_000;

/// Failure while reading or updating an authenticated campaign collection.
#[derive(Debug, Error)]
pub enum CampaignStoreError {
    /// An immutable store operation failed.
    #[error(transparent)]
    Store(#[from] crucible_cas::content_store::StoreError),
    /// Canonical campaign bytes failed validation.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A Merkle node violated a structural invariant.
    #[error("campaign Merkle map is invalid: {reason}")]
    InvalidMerkle {
        /// Stable structural failure category.
        reason: &'static str,
    },
    /// A requested page size was zero or exceeded the public bound.
    #[error("campaign Merkle page size must be between 1 and {MAX_PAGE_ITEMS}")]
    InvalidPageSize,
}

/// Immutable identity and exact entry count of one Merkle map root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleMapRoot {
    content_id: ContentId,
    entry_count: u64,
}

impl MerkleMapRoot {
    /// Returns the immutable root-node content identity.
    #[must_use]
    pub const fn content_id(self) -> ContentId {
        self.content_id
    }

    /// Returns the exact number of key/value entries.
    #[must_use]
    pub const fn entry_count(self) -> u64 {
        self.entry_count
    }
}

/// One stable, bounded page from a snapshot-bound Merkle map scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleMapPage {
    entries: Vec<(CampaignHash, ContentId)>,
    next_after: Option<CampaignHash>,
}

impl MerkleMapPage {
    /// Returns entries in ascending key order.
    #[must_use]
    pub fn entries(&self) -> &[(CampaignHash, ContentId)] {
        &self.entries
    }

    /// Returns the exclusive cursor for the next page, or `None` at EOF.
    #[must_use]
    pub const fn next_after(&self) -> Option<CampaignHash> {
        self.next_after
    }
}

/// Persistent insertion-order-independent map backed by immutable blobs.
pub struct MerkleMap {
    backend: Arc<dyn ImmutableBlobBackend>,
}

impl MerkleMap {
    /// Creates a map repository over one admitted immutable store graph.
    #[must_use]
    pub fn new(backend: Arc<dyn ImmutableBlobBackend>) -> Self {
        Self { backend }
    }

    /// Publishes or reuses the canonical empty root.
    ///
    /// # Errors
    ///
    /// Returns a store or canonical-encoding error when the root cannot be
    /// authenticated and placed.
    pub fn empty(&self) -> Result<MerkleMapRoot, CampaignStoreError> {
        let node = MerkleNode::empty();
        let content_id = self.persist_node(&node)?;
        Ok(MerkleMapRoot {
            content_id,
            entry_count: 0,
        })
    }

    /// Authenticates an existing root and returns its exact entry count.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, corrupt, wrongly typed, or structurally
    /// invalid root object.
    pub fn inspect_shallow(&self, root: ContentId) -> Result<MerkleMapRoot, CampaignStoreError> {
        let node = self.read_node(root, 0)?;
        Ok(MerkleMapRoot {
            content_id: root,
            entry_count: node.entry_count,
        })
    }

    /// Authenticates every node and leaf value reachable from a root.
    ///
    /// This is the publication/transfer integrity operation. It validates
    /// ancestor prefixes, advertised subtree counts, repeated-node misuse, and
    /// the presence and digest of every referenced value object.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/corrupt value or node, malformed trie
    /// shape, count disagreement, or a closure above one million unique nodes.
    pub fn verify_closure(&self, root: ContentId) -> Result<MerkleMapRoot, CampaignStoreError> {
        self.verify_closure_objects(root)
            .map(|verified| verified.root)
    }

    /// Authenticates a complete root with memory bounded by trie depth.
    ///
    /// Unlike [`Self::verify_closure`], this variant does not retain the set of
    /// leaf values for an enclosing object-graph walk. It still validates every
    /// node, ancestor prefix, advertised count, value presence, and the final
    /// root count, making it suitable for independently rebuildable projection
    /// caches.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/corrupt value or node, malformed trie
    /// shape, count disagreement, or traversal above one million nodes.
    pub fn verify_closure_streaming(
        &self,
        root: ContentId,
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        let root_node = self.read_node(root, 0)?;
        let expected_entries = root_node.entry_count;
        // Depth increases on every child and non-root nodes cannot be empty, so
        // cycles are impossible. Reusing a node at another trie position makes
        // its eventual nonempty leaf fail the full ancestor-prefix check.
        let mut stack = vec![(root_node, Vec::<u8>::new())];
        let mut traversed_nodes = 0_usize;
        let mut observed_entries = 0_u64;

        while let Some((node, prefix)) = stack.pop() {
            traversed_nodes = traversed_nodes
                .checked_add(1)
                .ok_or(invalid("closure-node-limit"))?;
            if traversed_nodes > MAX_VERIFIED_NODES {
                return Err(invalid("closure-node-limit"));
            }
            for (slot, entry) in node.entries.iter().rev() {
                let mut child_prefix = prefix.clone();
                child_prefix.push(*slot);
                match entry {
                    MerkleEntry::Leaf { key, value } => {
                        if !key_has_prefix(*key, &child_prefix) {
                            return Err(invalid("leaf-ancestor-prefix-mismatch"));
                        }
                        if !self.backend.contains(*value)? {
                            return Err(crucible_cas::content_store::StoreError::NotFound {
                                id: *value,
                            }
                            .into());
                        }
                        observed_entries = observed_entries
                            .checked_add(1)
                            .ok_or(invalid("entry-count-overflow"))?;
                    }
                    MerkleEntry::Node {
                        content_id,
                        entry_count,
                    } => {
                        let child = self.read_node(*content_id, node.depth + 1)?;
                        if child.entry_count != *entry_count {
                            return Err(invalid("child-entry-count-mismatch"));
                        }
                        stack.push((child, child_prefix));
                    }
                }
            }
        }
        if observed_entries != expected_entries {
            return Err(invalid("root-entry-count-mismatch"));
        }
        Ok(MerkleMapRoot {
            content_id: root,
            entry_count: observed_entries,
        })
    }

    pub(crate) fn verify_closure_objects(
        &self,
        root: ContentId,
    ) -> Result<VerifiedMerkleClosure, CampaignStoreError> {
        let root_node = self.read_node(root, 0)?;
        let expected_entries = root_node.entry_count;
        let mut stack = vec![(root, root_node, Vec::<u8>::new())];
        let mut visited = BTreeSet::new();
        let mut values = BTreeSet::new();
        let mut observed_entries = 0_u64;

        while let Some((node_id, node, prefix)) = stack.pop() {
            if !visited.insert(node_id) {
                return Err(invalid("node-reused-at-multiple-prefixes"));
            }
            if visited.len() > MAX_VERIFIED_NODES {
                return Err(invalid("closure-node-limit"));
            }
            for (slot, entry) in node.entries.iter().rev() {
                let mut child_prefix = prefix.clone();
                child_prefix.push(*slot);
                match entry {
                    MerkleEntry::Leaf { key, value } => {
                        if !key_has_prefix(*key, &child_prefix) {
                            return Err(invalid("leaf-ancestor-prefix-mismatch"));
                        }
                        if !self.backend.contains(*value)? {
                            return Err(crucible_cas::content_store::StoreError::NotFound {
                                id: *value,
                            }
                            .into());
                        }
                        values.insert(*value);
                        observed_entries = observed_entries
                            .checked_add(1)
                            .ok_or(invalid("entry-count-overflow"))?;
                    }
                    MerkleEntry::Node {
                        content_id,
                        entry_count,
                    } => {
                        let child = self.read_node(*content_id, node.depth + 1)?;
                        if child.entry_count != *entry_count {
                            return Err(invalid("child-entry-count-mismatch"));
                        }
                        stack.push((*content_id, child, child_prefix));
                    }
                }
            }
        }
        if observed_entries != expected_entries {
            return Err(invalid("root-entry-count-mismatch"));
        }
        Ok(VerifiedMerkleClosure {
            root: MerkleMapRoot {
                content_id: root,
                entry_count: observed_entries,
            },
            values,
        })
    }

    /// Returns the value associated with `key` in the immutable root.
    ///
    /// # Errors
    ///
    /// Returns an error for an incomplete, corrupt, or structurally invalid
    /// path. Absence is returned as `Ok(None)`.
    pub fn get(
        &self,
        root: ContentId,
        key: CampaignHash,
    ) -> Result<Option<ContentId>, CampaignStoreError> {
        let mut depth = 0;
        let mut node = self.read_node(root, depth)?;
        loop {
            let slot = digest_nibble(key, depth);
            match node.entries.get(&slot).cloned() {
                None => return Ok(None),
                Some(MerkleEntry::Leaf {
                    key: stored_key,
                    value,
                }) => return Ok((stored_key == key).then_some(value)),
                Some(MerkleEntry::Node {
                    content_id,
                    entry_count,
                }) => {
                    let next_depth = depth.checked_add(1).ok_or(invalid("depth-overflow"))?;
                    let child = self.read_node(content_id, next_depth)?;
                    if child.entry_count != entry_count {
                        return Err(invalid("child-entry-count-mismatch"));
                    }
                    node = child;
                    depth = next_depth;
                }
            }
        }
    }

    /// Inserts or replaces one key and returns the new canonical root.
    ///
    /// The input root remains valid. Inserting the same key/value pair is an
    /// identity operation and returns the original root without publishing new
    /// nodes.
    ///
    /// # Errors
    ///
    /// Returns an error when the old root is invalid, counts overflow, or a new
    /// immutable node cannot be placed.
    pub fn insert(
        &self,
        root: ContentId,
        key: CampaignHash,
        value: ContentId,
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        let node = self.read_node(root, 0)?;
        let update = self.insert_node(root, node, key, value)?;
        Ok(MerkleMapRoot {
            content_id: update.content_id,
            entry_count: update.entry_count,
        })
    }

    /// Reads a bounded ascending page after an exclusive key cursor.
    ///
    /// The cursor is meaningful only with the same immutable `root`; callers
    /// bind the root in portable planner state. Changing `limit` changes page
    /// boundaries but never the concatenated entry order.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignStoreError::InvalidPageSize`] for a zero or oversized
    /// page, or an integrity error while traversing the root.
    pub fn scan(
        &self,
        root: ContentId,
        after: Option<CampaignHash>,
        limit: usize,
    ) -> Result<MerkleMapPage, CampaignStoreError> {
        if limit == 0 || limit > MAX_PAGE_ITEMS {
            return Err(CampaignStoreError::InvalidPageSize);
        }
        let node = self.read_node(root, 0)?;
        let target = limit
            .checked_add(1)
            .ok_or(CampaignStoreError::InvalidPageSize)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(target)
            .map_err(|_| CampaignStoreError::InvalidPageSize)?;
        self.scan_node(node, after, target, &mut entries)?;

        let has_more = entries.len() > limit;
        if has_more {
            entries.truncate(limit);
        }
        let next_after = has_more.then(|| entries[entries.len() - 1].0);
        Ok(MerkleMapPage {
            entries,
            next_after,
        })
    }

    pub(crate) fn equals_after_upserts(
        &self,
        prior: ContentId,
        next: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
    ) -> Result<bool, CampaignStoreError> {
        let mut prior_entries = MerkleScanCursor::new(self, prior);
        let mut next_entries = MerkleScanCursor::new(self, next);
        let mut prior_entry = prior_entries.next_entry()?;
        let mut upsert_entries = upserts.iter().map(|(key, value)| (*key, *value));
        let mut upsert_entry = upsert_entries.next();

        loop {
            let expected = match (prior_entry, upsert_entry) {
                (None, None) => None,
                (Some(entry), None) => {
                    prior_entry = prior_entries.next_entry()?;
                    Some(entry)
                }
                (None, Some(entry)) => {
                    upsert_entry = upsert_entries.next();
                    Some(entry)
                }
                (Some(prior_value), Some(upsert_value)) => {
                    match prior_value.0.cmp(&upsert_value.0) {
                        std::cmp::Ordering::Less => {
                            prior_entry = prior_entries.next_entry()?;
                            Some(prior_value)
                        }
                        std::cmp::Ordering::Equal => {
                            prior_entry = prior_entries.next_entry()?;
                            upsert_entry = upsert_entries.next();
                            Some(upsert_value)
                        }
                        std::cmp::Ordering::Greater => {
                            upsert_entry = upsert_entries.next();
                            Some(upsert_value)
                        }
                    }
                }
            };

            let Some(expected) = expected else {
                return Ok(next_entries.next_entry()?.is_none());
            };
            if next_entries.next_entry()? != Some(expected) {
                return Ok(false);
            }
        }
    }

    fn insert_node(
        &self,
        original_id: ContentId,
        mut node: MerkleNode,
        key: CampaignHash,
        value: ContentId,
    ) -> Result<NodeUpdate, CampaignStoreError> {
        let slot = digest_nibble(key, node.depth);
        let existing = node.entries.get(&slot).cloned();
        let (entry, changed) = match existing {
            None => (MerkleEntry::Leaf { key, value }, true),
            Some(MerkleEntry::Leaf {
                key: stored_key,
                value: stored_value,
            }) if stored_key == key => (MerkleEntry::Leaf { key, value }, stored_value != value),
            Some(MerkleEntry::Leaf {
                key: stored_key,
                value: stored_value,
            }) => {
                let next_depth = node
                    .depth
                    .checked_add(1)
                    .ok_or(invalid("distinct-keys-exhausted-digest"))?;
                let child =
                    self.split_leaves(next_depth, (stored_key, stored_value), (key, value))?;
                (
                    MerkleEntry::Node {
                        content_id: child.content_id,
                        entry_count: child.entry_count,
                    },
                    true,
                )
            }
            Some(MerkleEntry::Node {
                content_id,
                entry_count,
            }) => {
                let next_depth = node.depth.checked_add(1).ok_or(invalid("depth-overflow"))?;
                let child = self.read_node(content_id, next_depth)?;
                if child.entry_count != entry_count {
                    return Err(invalid("child-entry-count-mismatch"));
                }
                let update = self.insert_node(content_id, child, key, value)?;
                (
                    MerkleEntry::Node {
                        content_id: update.content_id,
                        entry_count: update.entry_count,
                    },
                    update.changed,
                )
            }
        };

        if !changed {
            return Ok(NodeUpdate {
                content_id: original_id,
                entry_count: node.entry_count,
                changed: false,
            });
        }
        node.entries.insert(slot, entry);
        node.recompute_count()?;
        let content_id = self.persist_node(&node)?;
        Ok(NodeUpdate {
            content_id,
            entry_count: node.entry_count,
            changed: true,
        })
    }

    fn split_leaves(
        &self,
        depth: u8,
        first: (CampaignHash, ContentId),
        second: (CampaignHash, ContentId),
    ) -> Result<NodeUpdate, CampaignStoreError> {
        if depth >= DIGEST_NIBBLES {
            return Err(invalid("distinct-keys-exhausted-digest"));
        }
        let first_slot = digest_nibble(first.0, depth);
        let second_slot = digest_nibble(second.0, depth);
        let mut node = MerkleNode {
            schema_version: MERKLE_NODE_SCHEMA_VERSION,
            depth,
            entry_count: 2,
            entries: BTreeMap::new(),
        };
        if first_slot != second_slot {
            node.entries.insert(
                first_slot,
                MerkleEntry::Leaf {
                    key: first.0,
                    value: first.1,
                },
            );
            node.entries.insert(
                second_slot,
                MerkleEntry::Leaf {
                    key: second.0,
                    value: second.1,
                },
            );
        } else {
            let next_depth = depth
                .checked_add(1)
                .ok_or(invalid("distinct-keys-exhausted-digest"))?;
            let child = self.split_leaves(next_depth, first, second)?;
            node.entries.insert(
                first_slot,
                MerkleEntry::Node {
                    content_id: child.content_id,
                    entry_count: child.entry_count,
                },
            );
        }
        let content_id = self.persist_node(&node)?;
        Ok(NodeUpdate {
            content_id,
            entry_count: 2,
            changed: true,
        })
    }

    fn scan_node(
        &self,
        node: MerkleNode,
        after: Option<CampaignHash>,
        target: usize,
        output: &mut Vec<(CampaignHash, ContentId)>,
    ) -> Result<(), CampaignStoreError> {
        let after_slot = after.map(|key| digest_nibble(key, node.depth));
        for (slot, entry) in node.entries {
            if output.len() >= target {
                break;
            }
            if after_slot.is_some_and(|after_slot| slot < after_slot) {
                continue;
            }
            let child_after = match after_slot {
                Some(after_slot) if slot == after_slot => after,
                _ => None,
            };
            match entry {
                MerkleEntry::Leaf { key, value } => {
                    if child_after.is_none_or(|after| key > after) {
                        output.push((key, value));
                    }
                }
                MerkleEntry::Node {
                    content_id,
                    entry_count,
                } => {
                    let child_depth = node.depth.checked_add(1).ok_or(invalid("depth-overflow"))?;
                    let child = self.read_node(content_id, child_depth)?;
                    if child.entry_count != entry_count {
                        return Err(invalid("child-entry-count-mismatch"));
                    }
                    self.scan_node(child, child_after, target, output)?;
                }
            }
        }
        Ok(())
    }

    fn persist_node(&self, node: &MerkleNode) -> Result<ContentId, CampaignStoreError> {
        node.validate()?;
        let body = codec::encode(node);
        let envelope = ObjectEnvelope::for_record(
            CampaignRecordKind::MerkleNode,
            node.child_references()?,
            body,
        )?;
        let bytes = envelope.canonical_bytes();
        let content_id = envelope.content_id();
        let source = BlobHandle::from_bytes(bytes);
        let receipt = self.backend.put_if_absent(content_id, &source)?;
        if receipt.id != content_id {
            return Err(invalid("store-receipt-id-mismatch"));
        }
        Ok(content_id)
    }

    fn read_node(
        &self,
        content_id: ContentId,
        expected_depth: u8,
    ) -> Result<MerkleNode, CampaignStoreError> {
        if content_id.kind() != ObjectKind::MerkleNode {
            return Err(invalid("root-or-child-kind"));
        }
        let bytes = self
            .backend
            .read(content_id, None)?
            .read_all(MAX_ENVELOPE_BYTES)?;
        let envelope = ObjectEnvelope::from_canonical_bytes_for_owner(&bytes)?;
        if envelope.record_kind() != CampaignRecordKind::MerkleNode
            || envelope.content_id() != content_id
        {
            return Err(invalid("node-envelope-kind-or-identity"));
        }
        let node = codec::decode::<MerkleNode>(envelope.body())?;
        node.validate()?;
        if node.depth != expected_depth {
            return Err(invalid("node-depth-mismatch"));
        }
        if node.child_references()? != *envelope.children() {
            return Err(invalid("node-child-table-mismatch"));
        }
        Ok(node)
    }
}

/// Authenticated leaf values discovered while validating one complete map.
pub(crate) struct VerifiedMerkleClosure {
    /// Authenticated root identity and entry count.
    pub(crate) root: MerkleMapRoot,
    /// Leaf values that the enclosing campaign closure must also validate.
    pub(crate) values: BTreeSet<ContentId>,
}

struct MerkleScanCursor<'a> {
    map: &'a MerkleMap,
    root: ContentId,
    after: Option<CampaignHash>,
    buffered: std::vec::IntoIter<(CampaignHash, ContentId)>,
    exhausted: bool,
}

impl<'a> MerkleScanCursor<'a> {
    fn new(map: &'a MerkleMap, root: ContentId) -> Self {
        Self {
            map,
            root,
            after: None,
            buffered: Vec::new().into_iter(),
            exhausted: false,
        }
    }

    fn next_entry(&mut self) -> Result<Option<(CampaignHash, ContentId)>, CampaignStoreError> {
        loop {
            if let Some(entry) = self.buffered.next() {
                return Ok(Some(entry));
            }
            if self.exhausted {
                return Ok(None);
            }

            let page = self.map.scan(self.root, self.after, MAX_PAGE_ITEMS)?;
            self.after = page.next_after;
            self.exhausted = page.next_after.is_none();
            self.buffered = page.entries.into_iter();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeUpdate {
    content_id: ContentId,
    entry_count: u64,
    changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MerkleNode {
    schema_version: u32,
    depth: u8,
    entry_count: u64,
    entries: BTreeMap<u8, MerkleEntry>,
}

impl MerkleNode {
    fn empty() -> Self {
        Self {
            schema_version: MERKLE_NODE_SCHEMA_VERSION,
            depth: 0,
            entry_count: 0,
            entries: BTreeMap::new(),
        }
    }

    fn recompute_count(&mut self) -> Result<(), CampaignStoreError> {
        self.entry_count = self.entries.values().try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.entry_count())
                .ok_or(invalid("entry-count-overflow"))
        })?;
        Ok(())
    }

    fn validate(&self) -> Result<(), CampaignStoreError> {
        if self.schema_version != MERKLE_NODE_SCHEMA_VERSION {
            return Err(invalid("unsupported-node-schema"));
        }
        if self.depth >= DIGEST_NIBBLES {
            return Err(invalid("node-depth-out-of-range"));
        }
        if self.depth != 0 && self.entries.is_empty() {
            return Err(invalid("empty-nonroot-node"));
        }
        let mut count = 0_u64;
        for (slot, entry) in &self.entries {
            if *slot >= 16 {
                return Err(invalid("slot-out-of-range"));
            }
            match entry {
                MerkleEntry::Leaf { key, .. } if digest_nibble(*key, self.depth) != *slot => {
                    return Err(invalid("leaf-slot-mismatch"));
                }
                MerkleEntry::Node {
                    content_id,
                    entry_count,
                } => {
                    if self.depth == DIGEST_NIBBLES - 1 {
                        return Err(invalid("node-below-final-depth"));
                    }
                    if content_id.kind() != ObjectKind::MerkleNode || *entry_count == 0 {
                        return Err(invalid("invalid-node-child"));
                    }
                }
                MerkleEntry::Leaf { .. } => {}
            }
            count = count
                .checked_add(entry.entry_count())
                .ok_or(invalid("entry-count-overflow"))?;
        }
        if count != self.entry_count {
            return Err(invalid("node-entry-count-mismatch"));
        }
        Ok(())
    }

    fn child_references(&self) -> Result<BTreeSet<ChildReference>, CampaignStoreError> {
        self.entries
            .iter()
            .map(|(slot, entry)| {
                let (suffix, id) = match entry {
                    MerkleEntry::Leaf { value, .. } => ("value", *value),
                    MerkleEntry::Node { content_id, .. } => ("node", *content_id),
                };
                ChildReference::new(format!("slot.{slot:02x}.{suffix}"), id)
                    .map_err(CampaignCodecError::from)
                    .map_err(CampaignStoreError::from)
            })
            .collect()
    }
}

impl Canonical for MerkleNode {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.depth.encode(encoder);
        self.entry_count.encode(encoder);
        self.entries.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            schema_version: u32::decode(decoder)?,
            depth: u8::decode(decoder)?,
            entry_count: u64::decode(decoder)?,
            entries: decoder.map_bounded(16, "merkle-node-slot-count")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MerkleEntry {
    Leaf {
        key: CampaignHash,
        value: ContentId,
    },
    Node {
        content_id: ContentId,
        entry_count: u64,
    },
}

impl MerkleEntry {
    const fn entry_count(&self) -> u64 {
        match self {
            Self::Leaf { .. } => 1,
            Self::Node { entry_count, .. } => *entry_count,
        }
    }
}

impl Canonical for MerkleEntry {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Leaf { key, value } => {
                encoder.u8(0);
                key.encode(encoder);
                Canonical::encode(value, encoder);
            }
            Self::Node {
                content_id,
                entry_count,
            } => {
                encoder.u8(1);
                Canonical::encode(content_id, encoder);
                entry_count.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Leaf {
                key: CampaignHash::decode(decoder)?,
                value: ContentId::decode(decoder)?,
            }),
            1 => Ok(Self::Node {
                content_id: ContentId::decode(decoder)?,
                entry_count: u64::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "merkle-entry",
                tag,
            }),
        }
    }
}

fn digest_nibble(key: CampaignHash, depth: u8) -> u8 {
    let bytes = key.as_bytes();
    let byte = bytes[usize::from(depth / 2)];
    if depth.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn key_has_prefix(key: CampaignHash, prefix: &[u8]) -> bool {
    prefix
        .iter()
        .enumerate()
        .all(|(depth, slot)| digest_nibble(key, depth as u8) == *slot)
}

const fn invalid(reason: &'static str) -> CampaignStoreError {
    CampaignStoreError::InvalidMerkle { reason }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crucible_cas::content_store::MemoryBlobBackend;

    fn hash(byte: u8) -> CampaignHash {
        let mut bytes = [0_u8; 32];
        bytes[0] = byte;
        CampaignHash::from_bytes(bytes)
    }

    fn value(name: &str) -> ContentId {
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, name.as_bytes())
    }

    fn map() -> (Arc<MemoryBlobBackend>, MerkleMap) {
        let backend = Arc::new(MemoryBlobBackend::new("campaign-test", 16 * 1024 * 1024));
        let map = MerkleMap::new(backend.clone());
        (backend, map)
    }

    #[test]
    fn insertion_order_does_not_change_root() {
        let (_, first_map) = map();
        let mut first = first_map.empty().expect("empty root");
        for key in [0x12, 0x1f, 0xa0, 0x11, 0xff] {
            first = first_map
                .insert(
                    first.content_id(),
                    hash(key),
                    value(&format!("value-{key}")),
                )
                .expect("insert first order");
        }

        let (_, second_map) = map();
        let mut second = second_map.empty().expect("empty root");
        for key in [0xff, 0x11, 0xa0, 0x1f, 0x12] {
            second = second_map
                .insert(
                    second.content_id(),
                    hash(key),
                    value(&format!("value-{key}")),
                )
                .expect("insert second order");
        }

        assert_eq!(first, second);
        assert_eq!(first.entry_count(), 5);
    }

    #[test]
    fn many_deterministic_permutations_produce_one_root_and_valid_closure() {
        fn shuffled(mut values: Vec<u8>, mut state: u64) -> Vec<u8> {
            for index in (1..values.len()).rev() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                values.swap(index, (state as usize) % (index + 1));
            }
            values
        }

        let keys = (0_u8..24).collect::<Vec<_>>();
        let mut expected = None;
        for seed in 0..32 {
            let (backend, map) = map();
            let mut root = map.empty().expect("empty root");
            for key in shuffled(keys.clone(), seed) {
                let body = format!("value-{key}").into_bytes();
                let value_id = value(std::str::from_utf8(&body).expect("ASCII value"));
                backend
                    .put_if_absent(value_id, &BlobHandle::from_bytes(body))
                    .expect("store value");
                root = map
                    .insert(root.content_id(), hash(key), value_id)
                    .expect("insert permutation");
            }
            assert_eq!(
                map.verify_closure(root.content_id()).expect("closure"),
                root
            );
            assert_eq!(
                map.verify_closure_streaming(root.content_id())
                    .expect("streaming closure"),
                root
            );
            match expected {
                None => expected = Some(root),
                Some(expected) => assert_eq!(root, expected),
            }
        }
    }

    #[test]
    fn lookup_replacement_and_identity_insert_are_exact() {
        let (backend, map) = map();
        let empty = map.empty().expect("empty root");
        let first = map
            .insert(empty.content_id(), hash(0x42), value("old"))
            .expect("insert");
        assert_eq!(
            map.get(first.content_id(), hash(0x42)).expect("lookup"),
            Some(value("old"))
        );
        assert_eq!(
            map.get(first.content_id(), hash(0x43)).expect("absence"),
            None
        );

        let count_before = backend.object_count().expect("object count");
        let same = map
            .insert(first.content_id(), hash(0x42), value("old"))
            .expect("identity insert");
        assert_eq!(same, first);
        assert_eq!(backend.object_count().expect("object count"), count_before);

        let replaced = map
            .insert(first.content_id(), hash(0x42), value("new"))
            .expect("replace");
        assert_ne!(replaced.content_id(), first.content_id());
        assert_eq!(replaced.entry_count(), 1);
        assert_eq!(
            map.get(replaced.content_id(), hash(0x42))
                .expect("replacement lookup"),
            Some(value("new"))
        );
    }

    #[test]
    fn paged_scans_are_page_size_independent() {
        let (_, map) = map();
        let mut root = map.empty().expect("empty root");
        for key in [0xfe, 0x01, 0x20, 0x1f, 0x00, 0xa0, 0x11] {
            root = map
                .insert(root.content_id(), hash(key), value(&format!("value-{key}")))
                .expect("insert");
        }

        fn collect(map: &MerkleMap, root: ContentId, page_size: usize) -> Vec<CampaignHash> {
            let mut cursor = None;
            let mut keys = Vec::new();
            loop {
                let page = map.scan(root, cursor, page_size).expect("scan page");
                keys.extend(page.entries().iter().map(|(key, _)| *key));
                let Some(next) = page.next_after() else {
                    return keys;
                };
                cursor = Some(next);
            }
        }

        let one = collect(&map, root.content_id(), 1);
        assert_eq!(one, collect(&map, root.content_id(), 3));
        assert_eq!(one, collect(&map, root.content_id(), 10));
        assert!(one.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn invalid_page_sizes_fail_closed() {
        let (_, map) = map();
        let root = map.empty().expect("empty root");
        assert!(matches!(
            map.scan(root.content_id(), None, 0),
            Err(CampaignStoreError::InvalidPageSize)
        ));
        assert!(matches!(
            map.scan(root.content_id(), None, MAX_PAGE_ITEMS + 1),
            Err(CampaignStoreError::InvalidPageSize)
        ));
    }

    #[test]
    fn maximum_depth_collisions_remain_canonical() {
        let (_, first_map) = map();
        let first_key = CampaignHash::from_bytes([0_u8; 32]);
        let mut second_bytes = [0_u8; 32];
        second_bytes[31] = 1;
        let second_key = CampaignHash::from_bytes(second_bytes);
        let empty = first_map.empty().expect("empty root");
        let first = first_map
            .insert(empty.content_id(), first_key, value("first"))
            .expect("first insert");
        let first = first_map
            .insert(first.content_id(), second_key, value("second"))
            .expect("deep collision insert");

        let (_, second_map) = map();
        let empty = second_map.empty().expect("empty root");
        let second = second_map
            .insert(empty.content_id(), second_key, value("second"))
            .expect("second-first insert");
        let second = second_map
            .insert(second.content_id(), first_key, value("first"))
            .expect("deep collision reverse insert");

        assert_eq!(first, second);
        assert_eq!(
            first_map
                .get(first.content_id(), first_key)
                .expect("first lookup"),
            Some(value("first"))
        );
        assert_eq!(
            first_map
                .get(first.content_id(), second_key)
                .expect("second lookup"),
            Some(value("second"))
        );
    }

    #[test]
    fn updates_share_untouched_nodes_and_preserve_old_roots() {
        let (backend, map) = map();
        let mut root = map.empty().expect("empty root");
        for key in [0x10, 0x1f, 0xa0] {
            root = map
                .insert(root.content_id(), hash(key), value(&format!("value-{key}")))
                .expect("insert");
        }
        let old_root = root;
        let count_before = backend.object_count().expect("object count");
        let changed = map
            .insert(old_root.content_id(), hash(0x10), value("replacement"))
            .expect("replace nested leaf");
        let count_after = backend.object_count().expect("object count");

        assert_eq!(count_after - count_before, 2);
        assert_eq!(
            map.get(old_root.content_id(), hash(0x10))
                .expect("old root lookup"),
            Some(value("value-16"))
        );
        assert_eq!(
            map.get(changed.content_id(), hash(0x10))
                .expect("new root lookup"),
            Some(value("replacement"))
        );
        assert_eq!(
            map.get(changed.content_id(), hash(0xa0))
                .expect("untouched lookup"),
            Some(value("value-160"))
        );
    }

    #[test]
    fn incomplete_and_inconsistent_nodes_fail_closed() {
        let (backend, map) = map();
        let empty = map.empty().expect("empty root");
        let missing_value = value("missing-value");
        let incomplete_leaf = map
            .insert(empty.content_id(), hash(0x20), missing_value)
            .expect("insert missing value reference");
        assert!(matches!(
            map.verify_closure(incomplete_leaf.content_id()),
            Err(CampaignStoreError::Store(
                crucible_cas::content_store::StoreError::NotFound { id }
            )) if id == missing_value
        ));
        assert!(matches!(
            map.verify_closure_streaming(incomplete_leaf.content_id()),
            Err(CampaignStoreError::Store(
                crucible_cas::content_store::StoreError::NotFound { id }
            )) if id == missing_value
        ));

        let missing_child = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"missing");
        let parent = MerkleNode {
            schema_version: MERKLE_NODE_SCHEMA_VERSION,
            depth: 0,
            entry_count: 1,
            entries: BTreeMap::from([(
                0,
                MerkleEntry::Node {
                    content_id: missing_child,
                    entry_count: 1,
                },
            )]),
        };
        let parent_id = map
            .persist_node(&parent)
            .expect("persist incomplete parent");
        assert!(matches!(
            map.scan(parent_id, None, 1),
            Err(CampaignStoreError::Store(
                crucible_cas::content_store::StoreError::NotFound { id }
            )) if id == missing_child
        ));
        assert!(matches!(
            map.verify_closure(parent_id),
            Err(CampaignStoreError::Store(
                crucible_cas::content_store::StoreError::NotFound { id }
            )) if id == missing_child
        ));
        assert!(matches!(
            map.verify_closure_streaming(parent_id),
            Err(CampaignStoreError::Store(
                crucible_cas::content_store::StoreError::NotFound { id }
            )) if id == missing_child
        ));

        let body = codec::encode(&MerkleNode {
            schema_version: MERKLE_NODE_SCHEMA_VERSION,
            depth: 0,
            entry_count: 1,
            entries: BTreeMap::from([(
                1,
                MerkleEntry::Leaf {
                    key: hash(0x10),
                    value: value("leaf"),
                },
            )]),
        });
        let envelope =
            ObjectEnvelope::for_record(CampaignRecordKind::MerkleNode, BTreeSet::new(), body)
                .expect("generic envelope permits incomplete child table");
        let bad_id = envelope.content_id();
        backend
            .put_if_absent(bad_id, &BlobHandle::from_bytes(envelope.canonical_bytes()))
            .expect("store inconsistent envelope");
        assert!(matches!(
            map.inspect_shallow(bad_id),
            Err(CampaignStoreError::InvalidMerkle {
                reason: "node-child-table-mismatch"
            })
        ));
    }
}
