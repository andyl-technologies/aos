//! Bounded authenticated node bytes retained for one explicit validation pass.

use std::collections::{BTreeMap, VecDeque};

use super::{CampaignStoreError, ContentId, MerkleMap, MerkleNode, decode_node_bytes};

const MAX_RETAINED_NODES: usize = 128;
const MAX_RETAINED_BYTES: usize = 1024 * 1024;

#[cfg(test)]
mod tests;

/// Retains at most 128 authenticated nodes and 1 MiB of canonical payload.
///
/// Each Issue preflight and publication owns separate custody. Complete-head
/// ancestry custody ends before the mandatory fresh closure pass. No context
/// crosses an operation or survives its success or failure.
pub(crate) struct MerkleValidationReads {
    nodes: BTreeMap<ContentId, Vec<u8>>,
    order: VecDeque<ContentId>,
    bytes: usize,
    maximum_nodes: usize,
    maximum_bytes: usize,
}

impl Default for MerkleValidationReads {
    fn default() -> Self {
        Self::with_limits(MAX_RETAINED_NODES, MAX_RETAINED_BYTES)
    }
}

impl MerkleValidationReads {
    fn with_limits(maximum_nodes: usize, maximum_bytes: usize) -> Self {
        Self {
            nodes: BTreeMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            maximum_nodes,
            maximum_bytes,
        }
    }

    /// Releases all authenticated node custody before a fresh pass or return.
    pub(crate) fn clear(&mut self) {
        self.nodes.clear();
        self.order.clear();
        self.bytes = 0;
    }

    #[cfg(test)]
    pub(crate) fn retained_usage(&self) -> (usize, usize) {
        (self.nodes.len(), self.bytes)
    }

    #[cfg(test)]
    pub(crate) fn retained_id(&self) -> Option<ContentId> {
        self.order.front().copied()
    }

    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self::with_limits(0, 0)
    }

    /// Revalidates the original node contract before retaining canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns the original backend, envelope, identity, shape, or depth error.
    pub(super) fn read_node(
        &mut self,
        map: &MerkleMap,
        content_id: ContentId,
        expected_depth: u8,
    ) -> Result<MerkleNode, CampaignStoreError> {
        if let Some(bytes) = self.nodes.get(&content_id) {
            // Depth and canonical shape are caller invariants, even on a hit.
            return decode_node_bytes(content_id, expected_depth, bytes);
        }

        // A failed or incomplete authenticating read never enters custody.
        let (node, bytes) = map.read_node_with_bytes(content_id, expected_depth)?;
        if self.maximum_nodes == 0 || bytes.len() > self.maximum_bytes {
            return Ok(node);
        }

        while self.nodes.len() >= self.maximum_nodes
            || self.bytes > self.maximum_bytes - bytes.len()
        {
            let Some(oldest) = self.order.pop_front() else {
                return Ok(node);
            };
            if let Some(removed) = self.nodes.remove(&oldest) {
                self.bytes -= removed.len();
            }
        }

        self.bytes += bytes.len();
        self.nodes.insert(content_id, bytes);
        self.order.push_back(content_id);
        Ok(node)
    }
}

/// Selects explicit bounded custody without changing ordinary map methods.
pub(crate) struct MerkleReadSession<'a> {
    map: &'a MerkleMap,
    retained: Option<&'a mut MerkleValidationReads>,
}

impl<'a> MerkleReadSession<'a> {
    /// Selects either explicit attempt-local custody or ordinary scalar reads.
    pub(crate) fn new(map: &'a MerkleMap, retained: Option<&'a mut MerkleValidationReads>) -> Self {
        Self { map, retained }
    }

    /// Resolves one exact path with the original traversal invariants.
    ///
    /// # Errors
    ///
    /// Returns the original store, canonical-envelope, depth, or path error.
    pub(crate) fn get(
        &mut self,
        root: ContentId,
        key: super::CampaignHash,
    ) -> Result<Option<ContentId>, CampaignStoreError> {
        match self.retained.as_deref_mut() {
            Some(retained) => self.map.get_with_validation_reads(root, key, retained),
            None => self.map.get(root, key),
        }
    }

    /// Recomputes the canonical expected root without publishing any nodes.
    ///
    /// # Errors
    ///
    /// Returns the original store, node, count, depth, or overlay error.
    pub(crate) fn equals_after_upserts(
        &mut self,
        prior: ContentId,
        next: ContentId,
        upserts: &BTreeMap<super::CampaignHash, ContentId>,
    ) -> Result<bool, CampaignStoreError> {
        match self.retained.as_deref_mut() {
            Some(retained) => Ok(self
                .map
                .overlay_after_upserts_with_validation_reads(prior, upserts, Some(retained))?
                .0
                == next),
            None => self.map.equals_after_upserts(prior, next, upserts),
        }
    }
}
