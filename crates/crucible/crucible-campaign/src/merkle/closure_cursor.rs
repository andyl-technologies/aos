//! Lazily advanced authentication of one complete Merkle root.
//!
//! A cursor validates one node per step: its exact identity and depth, every
//! leaf's full ancestor prefix, and every child's advertised subtree count.
//! It retains only the not-yet-visited siblings along the current path, so its
//! memory is bounded by trie depth rather than by the number of entries. The
//! enclosing walk receives each node's leaf values as they are authenticated
//! and stays responsible for those value objects.
//!
//! Depth increases on every child and non-root nodes cannot be empty, so a
//! cursor cannot cycle. A node reused at another trie position eventually
//! yields a leaf whose full ancestor-prefix check fails, so no visited-node set
//! is needed to reject reuse.

use super::*;

/// Resumable complete-root authentication state.
pub(crate) struct MerkleClosureCursor {
    expected_entries: u64,
    observed_entries: u64,
    pending: Vec<(ContentId, MerkleNode, Vec<u8>)>,
}

impl MerkleClosureCursor {
    /// Returns the leaf entries authenticated so far.
    pub(crate) const fn observed_entries(&self) -> u64 {
        self.observed_entries
    }
}

/// One authenticated node and the leaf values it binds.
pub(crate) struct MerkleClosureStep {
    /// Exact node identity authenticated by this step.
    pub(crate) node: ContentId,
    /// Leaf values bound by this node, in ascending slot order.
    pub(crate) values: Vec<ContentId>,
}

impl MerkleMap {
    /// Starts authenticating a complete root by reading and validating it.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, corrupt, wrongly typed, or structurally
    /// invalid root node.
    pub(crate) fn closure_cursor(
        &self,
        root: ContentId,
    ) -> Result<MerkleClosureCursor, CampaignStoreError> {
        let node = self.read_node(root, 0)?;
        Ok(MerkleClosureCursor {
            expected_entries: node.entry_count,
            observed_entries: 0,
            pending: vec![(root, node, Vec::new())],
        })
    }

    /// Authenticates the next node, or proves the complete root count.
    ///
    /// Returns `Ok(None)` exactly once every node has been authenticated and
    /// the observed leaf count equals the root's advertised count. The caller
    /// must keep advancing until then before trusting any yielded value.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or corrupt child node, a leaf outside
    /// its ancestor prefix, a child count disagreement, or a root count
    /// disagreement.
    pub(crate) fn advance_closure_cursor(
        &self,
        cursor: &mut MerkleClosureCursor,
    ) -> Result<Option<MerkleClosureStep>, CampaignStoreError> {
        let Some((node_id, node, prefix)) = cursor.pending.pop() else {
            if cursor.observed_entries != cursor.expected_entries {
                return Err(invalid("root-entry-count-mismatch"));
            }
            return Ok(None);
        };

        let mut values = Vec::new();
        // Children are pushed in reverse so the lowest slot is visited next.
        for (slot, entry) in node.entries.iter().rev() {
            let mut child_prefix = prefix.clone();
            child_prefix.push(*slot);
            match entry {
                MerkleEntry::Leaf { key, value } => {
                    if !key_has_prefix(*key, &child_prefix) {
                        return Err(invalid("leaf-ancestor-prefix-mismatch"));
                    }
                    values.push(*value);
                    cursor.observed_entries = cursor
                        .observed_entries
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
                    cursor.pending.push((*content_id, child, child_prefix));
                }
            }
        }
        values.reverse();

        Ok(Some(MerkleClosureStep {
            node: node_id,
            values,
        }))
    }
}

#[cfg(test)]
mod tests;
