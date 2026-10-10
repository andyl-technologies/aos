//! Current-storage Merkle membership under one existing original boundary.
//!
//! Every selected node is reread and authenticated. Checked metadata and body
//! access retain the caller's account instead of creating new read operations;
//! no cached presence, absence or old root can substitute for current storage.

use crucible_cas::content_store::StoreError;
use crucible_cas::owned_decode::DecodeBudget;

use super::*;

impl MerkleMap {
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

fn check(
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), CampaignStoreError> {
    original.verify_live().map_err(CampaignCodecError::from)?;
    boundary()?;
    original.verify_live().map_err(CampaignCodecError::from)?;
    Ok(())
}
