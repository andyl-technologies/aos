//! Complete Merkle closure authentication under one saved operation account.

use std::collections::BTreeSet;

use crucible_store::content_store::{ContentId, StoreError};
use crucible_store::owned_decode::DecodeBudget;

use super::checked_lookup::check;
use super::*;

// A depth-first walk retains at most the unvisited siblings at every trie
// depth. Each node has sixteen slots and the root contributes one entry.
const MAX_CLOSURE_STACK_NODES: usize = 1 + ((16 - 1) * DIGEST_NIBBLES as usize);

type ClosureStackEntry = (ContentId, MerkleNode, Vec<u8>);

impl MerkleMap {
    /// Verifies a trie while its enclosing checked walk reads every leaf value.
    ///
    /// Already verified node positions remain reusable within the same caller
    /// operation. Every newly visited node uses checked metadata and body I/O.
    ///
    /// # Errors
    /// Returns original admission or boundary refusal, missing or corrupt
    /// nodes, invalid trie structure, or exhausted traversal bounds.
    pub(crate) fn verify_closure_structure_cached_with_boundary(
        &self,
        root: ContentId,
        verified_positions: &mut BTreeSet<(ContentId, Vec<u8>)>,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<VerifiedMerkleClosure, CampaignStoreError> {
        self.verify_closure_objects_cached_with_boundary_under(
            root,
            verified_positions,
            false,
            original,
            boundary,
        )
    }

    /// Verifies a trie and authenticates every referenced leaf value.
    ///
    /// This form supports anchored graph walks that may skip a leaf later. It
    /// therefore streams each referenced value to authenticated EOF before the
    /// position can contribute to the verified closure.
    ///
    /// # Errors
    /// Returns original admission or boundary refusal, missing or corrupt
    /// nodes or values, invalid trie structure, or exhausted traversal bounds.
    pub(crate) fn verify_closure_objects_cached_with_boundary(
        &self,
        root: ContentId,
        verified_positions: &mut BTreeSet<(ContentId, Vec<u8>)>,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<VerifiedMerkleClosure, CampaignStoreError> {
        self.verify_closure_objects_cached_with_boundary_under(
            root,
            verified_positions,
            true,
            original,
            boundary,
        )
    }

    fn verify_closure_objects_cached_with_boundary_under(
        &self,
        root: ContentId,
        verified_positions: &mut BTreeSet<(ContentId, Vec<u8>)>,
        check_leaf_presence: bool,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<VerifiedMerkleClosure, CampaignStoreError> {
        check(original, boundary)?;
        let _scope = original.enter();
        let root_node = self.read_checked_node(root, 0, original, boundary)?;
        let expected_entries = root_node.entry_count;
        let mut stack = prepaid_stack(original)?;
        stack.push((root, root_node, Vec::new()));
        let mut visited = BTreeSet::new();
        let mut newly_verified = BTreeSet::new();
        let mut values = BTreeSet::new();
        let mut observed_entries = 0_u64;

        while let Some((node_id, node, prefix)) = stack.pop() {
            check(original, boundary)?;
            original
                .charge_array::<u8>(prefix.len())
                .map_err(CampaignCodecError::from)?;
            let position = (node_id, prefix.clone());
            if verified_positions.contains(&position) {
                observed_entries = observed_entries
                    .checked_add(node.entry_count)
                    .ok_or(invalid("entry-count-overflow"))?;
                continue;
            }
            if !visited.contains(&node_id) {
                original
                    .charge_btree_entry::<ContentId, ()>()
                    .map_err(CampaignCodecError::from)?;
            }
            if !visited.insert(node_id) {
                return Err(invalid("node-reused-at-multiple-prefixes"));
            }
            if visited.len() > MAX_VERIFIED_NODES {
                return Err(invalid("closure-node-limit"));
            }
            original
                .charge_btree_entry::<(ContentId, Vec<u8>), ()>()
                .map_err(CampaignCodecError::from)?;
            newly_verified.insert(position);

            for (slot, entry) in node.entries.iter().rev() {
                let child_prefix = extend_prefix(original, &prefix, *slot)?;
                match entry {
                    MerkleEntry::Leaf { key, value } => {
                        if !key_has_prefix(*key, &child_prefix) {
                            return Err(invalid("leaf-ancestor-prefix-mismatch"));
                        }
                        if check_leaf_presence {
                            authenticate_leaf(self, *value, original, boundary)?;
                        }
                        if !values.contains(value) {
                            original
                                .charge_btree_entry::<ContentId, ()>()
                                .map_err(CampaignCodecError::from)?;
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
                        let child = self.read_checked_node(
                            *content_id,
                            node.depth
                                .checked_add(1)
                                .ok_or(invalid("closure-node-limit"))?,
                            original,
                            boundary,
                        )?;
                        if child.entry_count != *entry_count {
                            return Err(invalid("child-entry-count-mismatch"));
                        }
                        if stack.len() == MAX_CLOSURE_STACK_NODES {
                            return Err(invalid("closure-node-limit"));
                        }
                        stack.push((*content_id, child, child_prefix));
                    }
                }
            }
        }
        if observed_entries != expected_entries {
            return Err(invalid("root-entry-count-mismatch"));
        }
        check(original, boundary)?;
        // Do not expose a position until every descendant, leaf EOF and the
        // aggregate count have authenticated. Admit all destination nodes
        // before the first insertion so a refusal cannot publish a partial
        // reusable cache after returning an error.
        original
            .charge_btree_entries::<(ContentId, Vec<u8>), ()>(newly_verified.len())
            .map_err(CampaignCodecError::from)?;
        check(original, boundary)?;
        verified_positions.extend(newly_verified);
        Ok(VerifiedMerkleClosure {
            root: MerkleMapRoot {
                content_id: root,
                entry_count: observed_entries,
            },
            values,
        })
    }
}

fn prepaid_stack(original: &DecodeBudget) -> Result<Vec<ClosureStackEntry>, CampaignStoreError> {
    original
        .charge_array::<ClosureStackEntry>(MAX_CLOSURE_STACK_NODES)
        .map_err(CampaignCodecError::from)?;
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(MAX_CLOSURE_STACK_NODES)
        .map_err(|source| StoreError::Allocation {
            source,
            custody: Some(original.custody()),
        })?;
    if stack.capacity() > MAX_CLOSURE_STACK_NODES {
        return Err(StoreError::Quota.into());
    }
    Ok(stack)
}

fn extend_prefix(
    original: &DecodeBudget,
    prefix: &[u8],
    slot: u8,
) -> Result<Vec<u8>, CampaignStoreError> {
    let length = prefix
        .len()
        .checked_add(1)
        .ok_or(invalid("closure-node-limit"))?;
    original
        .charge_array::<u8>(length)
        .map_err(CampaignCodecError::from)?;
    let mut child = Vec::new();
    child
        .try_reserve_exact(length)
        .map_err(|source| StoreError::Allocation {
            source,
            custody: Some(original.custody()),
        })?;
    if child.capacity() > length {
        return Err(StoreError::Quota.into());
    }
    child.extend_from_slice(prefix);
    child.push(slot);
    Ok(child)
}

fn authenticate_leaf(
    map: &MerkleMap,
    id: ContentId,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), CampaignStoreError> {
    check(original, boundary)?;
    let source = map
        .backend
        .read_with_boundary(original, id, None, boundary)?;
    source.authenticate_with_boundary(original, id, boundary)?;
    drop(source);
    check(original, boundary)
}
