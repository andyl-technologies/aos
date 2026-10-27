//! Current-storage Merkle membership under one existing original boundary.
//!
//! Every selected node is reread and authenticated. Checked metadata and body
//! access retain the caller's account instead of creating new read operations;
//! no cached presence, absence or old root can substitute for current storage.

use crucible_store::content_store::StoreError;
use crucible_store::owned_decode::DecodeBudget;

use super::*;

impl MerkleMap {
    /// Authenticates a current root and returns its exact entry count.
    ///
    /// # Errors
    /// Returns original admission or boundary refusal, missing or corrupt root
    /// bytes, or an invalid root node.
    pub(crate) fn inspect_shallow_with_boundary(
        &self,
        root: ContentId,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        check(original, boundary)?;
        let _scope = original.enter();
        let node = self.read_checked_node(root, 0, original, boundary)?;
        check(original, boundary)?;
        Ok(MerkleMapRoot {
            content_id: root,
            entry_count: node.entry_count,
        })
    }

    /// Authenticates one current membership path under the saved caller account.
    ///
    /// Each selected node uses checked metadata and complete body/EOF access,
    /// followed by the ordinary canonical and structural validators. The final
    /// boundary runs after traversal temporaries close. No read cache or new
    /// supervision operation is introduced, and unsupported checked backends
    /// refuse instead of falling back to ordinary reads.
    ///
    /// # Errors
    /// Returns original admission or boundary refusal, missing or corrupt nodes,
    /// invalid trie structure, or a checked storage/reader cleanup failure.
    pub fn get_with_boundary(
        &self,
        root: ContentId,
        key: CampaignHash,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Option<ContentId>, CampaignStoreError> {
        check(original, boundary)?;
        let _scope = original.enter();
        // The unchanged traversal's prefix Vec grows to at most 64 u8 slots.
        // Its last growth can overlap the old 32 slots with the new 64 slots.
        let prefix_bytes = usize::from(DIGEST_NIBBLES)
            + usize::from(DIGEST_NIBBLES) / 2
            + std::mem::size_of::<Vec<u8>>();
        let _prefix_credit = original
            .reserve_scratch_bytes(prefix_bytes as u64)
            .map_err(CampaignCodecError::from)?;

        let node = self.read_checked_node(root, 0, original, boundary)?;
        let value = Self::get_from_node(node, key, &mut |id, depth| {
            self.read_checked_node(id, depth, original, boundary)
        })?;
        // get_from_node consumes its last node and closes its prefix before
        // this cut. A prior read or structural failure returns without a later
        // success-only callback replacing the primary cause.
        check(original, boundary)?;
        Ok(value)
    }

    /// Reads one bounded ascending page under the saved caller account.
    ///
    /// The traversal authenticates every selected node through checked storage
    /// reads. The cursor remains exclusive and meaningful only for `root`, as
    /// in [`Self::scan`].
    ///
    /// # Errors
    /// Returns original admission or boundary refusal, an invalid page size,
    /// missing or corrupt nodes, or invalid trie structure.
    pub(crate) fn scan_with_boundary(
        &self,
        root: ContentId,
        after: Option<CampaignHash>,
        limit: usize,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleMapPage, CampaignStoreError> {
        if limit == 0 || limit > MAX_PAGE_ITEMS {
            return Err(CampaignStoreError::InvalidPageSize);
        }
        check(original, boundary)?;
        let _scope = original.enter();
        let target = limit
            .checked_add(1)
            .ok_or(CampaignStoreError::InvalidPageSize)?;

        // scan_node_with_reader retains one prefix per recursive frame and
        // clones at most one 64-nibble child alongside its parent. The charge
        // covers every Vec header plus both maximal prefix bodies.
        let prefix_bytes = (usize::from(DIGEST_NIBBLES) + 1)
            .checked_mul(std::mem::size_of::<Vec<u8>>())
            .and_then(|headers| headers.checked_add(2 * usize::from(DIGEST_NIBBLES)))
            .ok_or(CampaignStoreError::InvalidPageSize)?;
        let _prefix_credit = original
            .reserve_scratch_bytes(prefix_bytes as u64)
            .map_err(CampaignCodecError::from)?;
        let mut entries = Vec::new();
        crucible_store::owned_decode::reserve_vec(&mut entries, target)
            .map_err(CampaignCodecError::from)?;

        let node = self.read_checked_node(root, 0, original, boundary)?;
        Self::scan_node_with_reader(
            node,
            Vec::new(),
            after,
            target,
            &mut entries,
            &mut |id, depth| self.read_checked_node(id, depth, original, boundary),
        )?;
        check(original, boundary)?;
        Ok(finish_scan_page(entries, limit))
    }

    /// Computes the canonical root after exact upserts under checked node reads.
    ///
    /// The update uses the same trie construction as ordinary publication, but
    /// authenticates every prior node through the caller's saved operation.
    /// Newly constructed overlay nodes remain private and are never published.
    ///
    /// # Errors
    /// Returns original admission or boundary refusal, invalid prior trie
    /// structure, allocation refusal, or canonical encoding failure.
    pub(crate) fn root_after_upserts_with_boundary(
        &self,
        prior: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<ContentId, CampaignStoreError> {
        check(original, boundary)?;
        let _scope = original.enter();
        let mut overlay = BTreeMap::new();
        let mut current = prior;
        for (key, value) in upserts {
            let node = self.read_checked_overlay_node(current, 0, &overlay, original, boundary)?;
            current = self
                .insert_checked_overlay_node(
                    current,
                    node,
                    *key,
                    *value,
                    &mut overlay,
                    (original, &mut *boundary),
                )?
                .content_id;
        }
        check(original, boundary)?;
        Ok(current)
    }

    pub(super) fn insert_checked_overlay_node(
        &self,
        original_id: ContentId,
        mut node: MerkleNode,
        key: CampaignHash,
        value: ContentId,
        overlay: &mut BTreeMap<ContentId, MerkleNode>,
        checked: (&DecodeBudget, &mut dyn FnMut() -> Result<(), StoreError>),
    ) -> Result<NodeUpdate, CampaignStoreError> {
        let (operation, boundary) = checked;
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
                let child = self.split_checked_overlay_leaves(
                    next_depth,
                    (stored_key, stored_value),
                    (key, value),
                    overlay,
                    operation,
                )?;
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
                let child = self.read_checked_overlay_node(
                    content_id, next_depth, overlay, operation, boundary,
                )?;
                if child.entry_count != entry_count {
                    return Err(invalid("child-entry-count-mismatch"));
                }
                let update = self.insert_checked_overlay_node(
                    content_id,
                    child,
                    key,
                    value,
                    overlay,
                    (operation, &mut *boundary),
                )?;
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
        operation
            .charge_btree_entry::<u8, MerkleEntry>()
            .map_err(CampaignCodecError::from)?;
        node.entries.insert(slot, entry);
        node.recompute_count()?;
        let content_id = calculate_node_id(&node)?;
        Self::insert_checked_overlay(overlay, content_id, node, operation)?;
        Ok(NodeUpdate {
            content_id,
            entry_count: overlay
                .get(&content_id)
                .ok_or_else(|| invalid("checked-overlay-node-is-missing"))?
                .entry_count,
            changed: true,
        })
    }

    fn split_checked_overlay_leaves(
        &self,
        depth: u8,
        first: (CampaignHash, ContentId),
        second: (CampaignHash, ContentId),
        overlay: &mut BTreeMap<ContentId, MerkleNode>,
        operation: &DecodeBudget,
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
            operation
                .charge_btree_entries::<u8, MerkleEntry>(2)
                .map_err(CampaignCodecError::from)?;
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
            let child =
                self.split_checked_overlay_leaves(next_depth, first, second, overlay, operation)?;
            operation
                .charge_btree_entry::<u8, MerkleEntry>()
                .map_err(CampaignCodecError::from)?;
            node.entries.insert(
                first_slot,
                MerkleEntry::Node {
                    content_id: child.content_id,
                    entry_count: child.entry_count,
                },
            );
        }
        let content_id = calculate_node_id(&node)?;
        Self::insert_checked_overlay(overlay, content_id, node, operation)?;
        Ok(NodeUpdate {
            content_id,
            entry_count: 2,
            changed: true,
        })
    }

    pub(super) fn read_checked_overlay_node(
        &self,
        content_id: ContentId,
        expected_depth: u8,
        overlay: &BTreeMap<ContentId, MerkleNode>,
        operation: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleNode, CampaignStoreError> {
        if let Some(node) = overlay.get(&content_id) {
            if node.depth != expected_depth {
                return Err(invalid("node-depth-mismatch"));
            }
            operation
                .charge_btree_entries::<u8, MerkleEntry>(node.entries.len())
                .map_err(CampaignCodecError::from)?;
            return Ok(node.clone());
        }
        self.read_checked_node(content_id, expected_depth, operation, boundary)
    }

    pub(super) fn insert_checked_overlay(
        overlay: &mut BTreeMap<ContentId, MerkleNode>,
        content_id: ContentId,
        node: MerkleNode,
        operation: &DecodeBudget,
    ) -> Result<(), CampaignStoreError> {
        if !overlay.contains_key(&content_id) {
            operation
                .charge_btree_entry::<ContentId, MerkleNode>()
                .map_err(CampaignCodecError::from)?;
        }
        overlay.insert(content_id, node);
        Ok(())
    }

    pub(super) fn read_checked_node(
        &self,
        id: ContentId,
        depth: u8,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleNode, CampaignStoreError> {
        check(original, boundary)?;
        if id.kind() != ObjectKind::MerkleNode {
            return Err(invalid("root-or-child-kind"));
        }
        let node = {
            let bytes = self
                .backend
                .read_merkle_node_with_boundary(original, id, boundary)?;
            decode_node_bytes(id, depth, &bytes)?
        };
        // Reader, source and full encoded body have closed; decoded entries
        // remain paid by the caller's unchanged outer allocation scope.
        check(original, boundary)?;
        Ok(node)
    }
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
