//! Authenticated subtree counts retained during one complete closure walk.
//!
//! A position binds the exact immutable node ID and its full trie prefix. The
//! ledger replaces the enclosing walk's position set; it does not borrow
//! ancestry results or retain node bytes between closure walks.

use super::*;

/// Retains counts only after their complete root walk succeeds.
pub(crate) struct VerifiedMerklePositions {
    counts: BTreeMap<(ContentId, Vec<u8>), u64>,
    check_leaf_presence: bool,
}

impl VerifiedMerklePositions {
    pub(crate) fn objects() -> Self {
        Self {
            counts: BTreeMap::new(),
            check_leaf_presence: true,
        }
    }

    pub(crate) fn structure() -> Self {
        Self {
            counts: BTreeMap::new(),
            check_leaf_presence: false,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.counts.len()
    }

    pub(crate) fn ids(&self) -> impl Iterator<Item = ContentId> + '_ {
        self.counts.keys().map(|(node, _prefix)| *node)
    }

    fn count(&self, id: ContentId, prefix: &[u8]) -> Option<u64> {
        self.counts.get(&(id, prefix.to_vec())).copied()
    }
}

impl MerkleMap {
    /// Authenticates every new position and seals its count after root validation.
    ///
    /// # Errors
    ///
    /// Returns the original store, codec, prefix, depth, count, and work-limit
    /// errors. A ledger cannot mix structure-only and leaf-presence validation.
    pub(super) fn verify_closure_objects_cached_with_leaf_presence(
        &self,
        root: ContentId,
        verified_positions: &mut VerifiedMerklePositions,
        check_leaf_presence: bool,
    ) -> Result<VerifiedMerkleClosure, CampaignStoreError> {
        if verified_positions.check_leaf_presence != check_leaf_presence {
            return Err(invalid("closure-verification-mode-mismatch"));
        }
        if let Some(entry_count) = verified_positions.count(root, &[]) {
            return Ok(VerifiedMerkleClosure {
                root: MerkleMapRoot {
                    content_id: root,
                    entry_count,
                },
                values: BTreeSet::new(),
            });
        }

        let root_node = self.read_node(root, 0)?;
        let expected_entries = root_node.entry_count;
        let mut stack = vec![(root, root_node, Vec::<u8>::new())];
        let mut visited = BTreeSet::new();
        let mut completed_positions = BTreeMap::new();
        let mut values = BTreeSet::new();
        let mut observed_entries = 0_u64;

        while let Some((node_id, node, prefix)) = stack.pop() {
            if !visited.insert(node_id) {
                return Err(invalid("node-reused-at-multiple-prefixes"));
            }
            if visited.len() > MAX_VERIFIED_NODES {
                return Err(invalid("closure-node-limit"));
            }
            completed_positions.insert((node_id, prefix.clone()), node.entry_count);

            for (slot, entry) in node.entries.iter().rev() {
                let mut child_prefix = prefix.clone();
                child_prefix.push(*slot);
                match entry {
                    MerkleEntry::Leaf { key, value } => {
                        if !key_has_prefix(*key, &child_prefix) {
                            return Err(invalid("leaf-ancestor-prefix-mismatch"));
                        }
                        if check_leaf_presence && !self.backend.contains(*value)? {
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
                        if let Some(verified_count) =
                            verified_positions.count(*content_id, &child_prefix)
                        {
                            // The complete prior walk checked this exact depth
                            // and full prefix. The new parent must still bind
                            // its original authenticated subtree count.
                            if verified_count != *entry_count {
                                return Err(invalid("child-entry-count-mismatch"));
                            }
                            observed_entries = observed_entries
                                .checked_add(verified_count)
                                .ok_or(invalid("entry-count-overflow"))?;
                            continue;
                        }

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

        // No partial or failed walk can lend counts to another root. The
        // enclosing closure owns and drops this ledger before returning.
        verified_positions.counts.extend(completed_positions);
        Ok(VerifiedMerkleClosure {
            root: MerkleMapRoot {
                content_id: root,
                entry_count: observed_entries,
            },
            values,
        })
    }
}

#[cfg(test)]
mod tests;
