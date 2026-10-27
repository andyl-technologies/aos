//! Canonical mixed Merkle edits over authenticated checked node reads.

use super::checked_lookup::check;
use super::*;
use crucible_store::content_store::StoreError;
use crucible_store::owned_decode::DecodeBudget;

impl MerkleMap {
    /// Computes the exact root after checked upserts and removals without writes.
    ///
    /// # Errors
    /// Returns admission or boundary refusal, invalid trie structure, or
    /// canonical encoding failure.
    pub(crate) fn root_after_edits_with_boundary(
        &self,
        prior: ContentId,
        edits: &BTreeMap<CampaignHash, Option<ContentId>>,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<ContentId, CampaignStoreError> {
        check(original, boundary)?;
        let _scope = original.enter();
        let mut overlay = BTreeMap::new();
        let mut current = prior;

        for (key, value) in edits {
            check(original, boundary)?;
            let node = self.read_checked_overlay_node(current, 0, &overlay, original, boundary)?;
            let update = match value {
                Some(value) => self.insert_checked_overlay_node(
                    current,
                    node,
                    *key,
                    *value,
                    &mut overlay,
                    (original, &mut *boundary),
                )?,
                None => self.remove_checked_overlay_node(
                    current,
                    node,
                    *key,
                    &mut overlay,
                    (original, &mut *boundary),
                )?,
            };
            current = update.content_id;
        }

        check(original, boundary)?;
        Ok(current)
    }

    fn remove_checked_overlay_node(
        &self,
        original_id: ContentId,
        mut node: MerkleNode,
        key: CampaignHash,
        overlay: &mut BTreeMap<ContentId, MerkleNode>,
        checked: (&DecodeBudget, &mut dyn FnMut() -> Result<(), StoreError>),
    ) -> Result<NodeUpdate, CampaignStoreError> {
        let (operation, boundary) = checked;
        check(operation, boundary)?;
        let slot = digest_nibble(key, node.depth);
        let replacement = match node.entries.get(&slot).cloned() {
            Some(MerkleEntry::Leaf { key: stored, .. }) if stored == key => None,
            Some(MerkleEntry::Node {
                content_id,
                entry_count,
            }) => {
                let depth = node.depth.checked_add(1).ok_or(invalid("depth-overflow"))?;
                let child = self
                    .read_checked_overlay_node(content_id, depth, overlay, operation, boundary)?;
                if child.entry_count != entry_count {
                    return Err(invalid("child-entry-count-mismatch"));
                }
                let update = self.remove_checked_overlay_node(
                    content_id,
                    child,
                    key,
                    overlay,
                    (operation, &mut *boundary),
                )?;
                if !update.changed {
                    return Ok(NodeUpdate {
                        content_id: original_id,
                        entry_count: node.entry_count,
                        changed: false,
                    });
                }
                match update.entry_count {
                    0 => None,
                    1 => Some(self.only_checked_overlay_leaf(
                        update.content_id,
                        depth,
                        overlay,
                        operation,
                        boundary,
                    )?),
                    _ => Some(MerkleEntry::Node {
                        content_id: update.content_id,
                        entry_count: update.entry_count,
                    }),
                }
            }
            _ => {
                return Ok(NodeUpdate {
                    content_id: original_id,
                    entry_count: node.entry_count,
                    changed: false,
                });
            }
        };

        if let Some(entry) = replacement {
            // Replacement occupies the existing, already paid map slot.
            node.entries.insert(slot, entry);
        } else {
            node.entries.remove(&slot);
        }
        node.recompute_count()?;
        let content_id = calculate_node_id(&node)?;
        let entry_count = node.entry_count;
        Self::insert_checked_overlay(overlay, content_id, node, operation)?;
        Ok(NodeUpdate {
            content_id,
            entry_count,
            changed: true,
        })
    }

    fn only_checked_overlay_leaf(
        &self,
        id: ContentId,
        depth: u8,
        overlay: &BTreeMap<ContentId, MerkleNode>,
        operation: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MerkleEntry, CampaignStoreError> {
        check(operation, boundary)?;
        let node = self.read_checked_overlay_node(id, depth, overlay, operation, boundary)?;
        if node.entry_count != 1 || node.entries.len() != 1 {
            return Err(invalid("single-leaf-node-count-mismatch"));
        }
        match node.entries.into_values().next() {
            Some(leaf @ MerkleEntry::Leaf { .. }) => Ok(leaf),
            Some(MerkleEntry::Node { content_id, .. }) => {
                let child_depth = depth.checked_add(1).ok_or(invalid("depth-overflow"))?;
                self.only_checked_overlay_leaf(
                    content_id,
                    child_depth,
                    overlay,
                    operation,
                    boundary,
                )
            }
            None => Err(invalid("single-leaf-node-is-empty")),
        }
    }
}
