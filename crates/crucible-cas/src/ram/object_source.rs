//! Root-bound object discovery for bounded offline transfer transports.
//!
//! Requests use logical region coordinates, never arbitrary backend object IDs.
//! Every response is authenticated through the leased root's catalog path before
//! its canonical bytes are exposed to an object-chunk sender.

use crate::content_store::ContentId;
use crate::owned_decode::DecodeCustody;
use std::sync::Arc;

use super::codec::{TreeNode, TreeRef};
use super::{LeasedRamRoot, RamStore, RamStoreError, Work, valid_length};

/// One object selected through an admitted immutable RAM root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RamObjectCoordinate {
    /// The complete logical root record and its selected catalog references.
    Root,
    /// A canonical catalog subtree at an aligned logical position.
    Catalog {
        /// Stable inventory region identity.
        region_id: String,
        /// First logical page position covered by the subtree.
        first_page: u64,
        /// Binary subtree height, where zero selects a leaf catalog.
        height: u32,
    },
    /// The actual page content object at a real logical page position.
    Page {
        /// Stable inventory region identity.
        region_id: String,
        /// Zero-based page position, excluding canonical padding.
        page_index: u64,
    },
}

/// Canonical authenticated bytes for one root-bound transfer response.
///
/// Clones share the immutable body and its original metadata credit. The credit
/// remains live after the supplying store closes, until the final clone drops.
#[derive(Clone, Debug)]
pub struct RamObjectRecord {
    id: ContentId,
    canonical: Arc<CanonicalObject>,
}

#[derive(Debug)]
struct CanonicalObject {
    bytes: Vec<u8>,
    _custody: DecodeCustody,
}

impl RamObjectRecord {
    /// Returns the independently authenticated storage identity.
    pub const fn id(&self) -> ContentId {
        self.id
    }

    /// Returns the bounded canonical plaintext object bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical.bytes
    }
}

impl RamStore {
    /// Resolves one transfer request through a live immutable root capability.
    ///
    /// Catalog requests must name aligned canonical subtrees. Conceptual nodes
    /// below a compressed padding object do not exist and are rejected. Page
    /// requests independently validate the actual bytes and final valid length.
    /// The returned record remains bounded by the store's per-object ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error for an excluded region, invalid coordinate, inaccessible
    /// object, corrupt path or bytes, cancellation, or exhausted operation limits.
    pub fn read_transfer_object(
        &self,
        root: &LeasedRamRoot,
        coordinate: &RamObjectCoordinate,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamObjectRecord, RamStoreError> {
        self.admit_topology(root.record.topology())?;
        let mut work = Work::new(self.limits, original, boundary)?;
        self.read_transfer_object_with_work(root, coordinate, &mut work)
    }

    pub(super) fn read_transfer_object_with_work(
        &self,
        root: &LeasedRamRoot,
        coordinate: &RamObjectCoordinate,
        work: &mut Work<'_>,
    ) -> Result<RamObjectRecord, RamStoreError> {
        let account = work
            .original()
            .child()
            .map_err(super::codec_ownership::admission)?;
        let _scope = account.enter();
        let id = match coordinate {
            RamObjectCoordinate::Root => {
                let (record, catalogs) = self.read_root(root.object_id(), work)?;
                if &record != root.record.as_ref() || catalogs.as_slice() != root.regions.as_ref() {
                    return Err(RamStoreError::Invalid(
                        "transfer source root metadata changed",
                    ));
                }
                root.object_id()
            }
            RamObjectCoordinate::Catalog {
                region_id,
                first_page,
                height,
            } => {
                let reference =
                    self.transfer_catalog(root, region_id, *first_page, *height, work)?;
                self.read_tree(reference, work)?;
                reference.id
            }
            RamObjectCoordinate::Page {
                region_id,
                page_index,
            } => {
                let region = root
                    .record
                    .topology()
                    .region(region_id)
                    .ok_or(RamStoreError::Invalid("transfer page region"))?;
                let length = valid_length(region, *page_index)?;
                let reference = self.transfer_catalog(root, region_id, *page_index, 0, work)?;
                let TreeNode::Leaf { page, digest } = self.read_tree(reference, work)? else {
                    return Err(RamStoreError::Invalid("transfer page resolves to padding"));
                };
                if self.read_page_object(page, digest, work)?.len() != length {
                    return Err(RamStoreError::Invalid("transfer page valid length"));
                }
                page
            }
        };
        let canonical = self.read_envelope(id, work)?.canonical_bytes();
        account.check().map_err(super::codec_ownership::admission)?;
        crate::owned_decode::charge_bytes(
            (std::mem::size_of::<CanonicalObject>() + 2 * std::mem::size_of::<usize>()) as u64,
        )
        .map_err(super::codec_ownership::admission)?;
        Ok(RamObjectRecord {
            id,
            canonical: Arc::new(CanonicalObject {
                bytes: canonical,
                _custody: account.custody(),
            }),
        })
    }

    fn transfer_catalog(
        &self,
        root: &LeasedRamRoot,
        region_id: &str,
        first_page: u64,
        height: u32,
        work: &mut Work<'_>,
    ) -> Result<TreeRef, RamStoreError> {
        let (index, region) = root
            .record
            .topology()
            .regions()
            .iter()
            .filter(|region| root.record.scope().includes(region.class()))
            .enumerate()
            .find(|(_, region)| region.id() == region_id)
            .ok_or(RamStoreError::Invalid("transfer catalog region"))?;
        let geometry = region.geometry();
        if height > geometry.height()
            || first_page >= geometry.padded_leaf_count()
            || !first_page.is_multiple_of(1_u64 << height)
        {
            return Err(RamStoreError::Invalid("transfer catalog coordinate"));
        }
        let mut reference = root.regions[index];
        let mut position = first_page;
        while reference.height > height {
            let TreeNode::Branch { left, right } = self.read_tree(reference, work)? else {
                return Err(RamStoreError::Invalid(
                    "coordinate below canonical padding subtree",
                ));
            };
            let width = 1_u64 << (reference.height - 1);
            if position < width {
                reference = left;
            } else {
                position -= width;
                reference = right;
            }
        }
        Ok(reference)
    }
}
