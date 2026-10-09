//! Root-bound object discovery for bounded offline transfer transports.
//!
//! Requests use logical region coordinates, never arbitrary backend object IDs.
//! Every response is authenticated through the leased root's catalog path before
//! its canonical bytes are exposed to an object-chunk sender.

use crate::content_store::{ContentId, ObjectKind};
use crate::owned_decode::DecodeCustody;
use std::sync::Arc;

use super::codec::{
    TreeNode, TreeRef, decode_root_envelope, validate_page_envelope, validate_tree,
};
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
    canonical: CanonicalOwner,
}

#[derive(Debug)]
struct CanonicalObject {
    bytes: Vec<u8>,
    _custody: DecodeCustody,
}

// No raw strong or weak alias escapes this owner. The final Arc allocation
// closes before the moved value drops its bytes and original child custody.
#[derive(Debug)]
struct CanonicalOwner(Option<Arc<CanonicalObject>>);

impl CanonicalOwner {
    fn allocation_bytes() -> Result<u64, RamStoreError> {
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<CanonicalObject>())
            .map_err(|_| RamStoreError::Limit("transfer canonical owner layout"))?;
        u64::try_from(layout.pad_to_align().size())
            .map_err(|_| RamStoreError::Limit("transfer canonical owner layout"))
    }

    fn value(&self) -> &CanonicalObject {
        match &self.0 {
            Some(value) => value,
            None => unreachable!("only the terminal owner destructor consumes its value"),
        }
    }
}

impl Clone for CanonicalOwner {
    fn clone(&self) -> Self {
        match &self.0 {
            Some(value) => Self(Some(Arc::clone(value))),
            None => unreachable!("a live canonical owner retains its strong reference"),
        }
    }
}

impl Drop for CanonicalOwner {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            drop(Arc::into_inner(value));
        }
    }
}

impl RamObjectRecord {
    /// Returns the independently authenticated storage identity.
    pub const fn id(&self) -> ContentId {
        self.id
    }

    /// Returns a scalar field address for original allocation-custody tests.
    ///
    /// The address grants no ownership, dereferenceable alias, or execution
    /// authority. The retained immutable owner keeps the field alive.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn canonical_field_address_for_test(&self) -> usize {
        std::ptr::from_ref(self.canonical.value()).addr()
    }

    /// Returns the bounded canonical plaintext object bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical.value().bytes
    }
}

impl RamStore {
    pub(super) fn read_canonical_record(
        &self,
        id: ContentId,
        work: &mut Work<'_>,
    ) -> Result<(RamObjectRecord, super::codec_ownership::OwnedEnvelope), RamStoreError> {
        self.read_canonical_record_expected(id, None, work)
    }

    pub(super) fn read_canonical_tree_record(
        &self,
        expected: TreeRef,
        work: &mut Work<'_>,
    ) -> Result<(RamObjectRecord, super::codec_ownership::OwnedEnvelope), RamStoreError> {
        self.read_canonical_record_expected(expected.id, Some(expected), work)
    }

    fn read_canonical_record_expected(
        &self,
        id: ContentId,
        expected: Option<TreeRef>,
        work: &mut Work<'_>,
    ) -> Result<(RamObjectRecord, super::codec_ownership::OwnedEnvelope), RamStoreError> {
        let account = work
            .original()
            .child()
            .map_err(super::codec_ownership::admission)?;
        let _scope = account.enter();
        let bytes = match expected {
            Some(expected) => super::bounded_read::read_canonical_tree(
                self.backend.as_ref(),
                expected,
                &account,
                work,
            ),
            None => super::bounded_read::read_canonical(self.backend.as_ref(), id, &account, work),
        }?
        .ok_or(crate::content_store::StoreError::NotFound { id })?;
        let (_, maximum_children) = super::codec::object_limits(id)?;
        let envelope = super::codec::decode_envelope(id, &bytes, maximum_children, &account)?;
        account
            .charge_bytes(CanonicalOwner::allocation_bytes()?)
            .map_err(super::codec_ownership::admission)?;
        account
            .verify_live()
            .map_err(super::codec_ownership::admission)?;
        let record = RamObjectRecord {
            id,
            canonical: CanonicalOwner(Some(Arc::new(CanonicalObject {
                bytes,
                _custody: account.custody(),
            }))),
        };
        Ok((record, envelope))
    }

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
        let result = self.read_coordinate(root, coordinate, work);
        match result {
            Err(error) if work.account.read_failure().is_none() => {
                Err(work.account.fail_read(error).into())
            }
            result => result,
        }
    }

    fn read_coordinate(
        &self,
        root: &LeasedRamRoot,
        coordinate: &RamObjectCoordinate,
        work: &mut Work<'_>,
    ) -> Result<RamObjectRecord, RamStoreError> {
        match coordinate {
            RamObjectCoordinate::Root => {
                if root.object_id().kind() != ObjectKind::ExactManifest {
                    return Err(RamStoreError::Invalid("root object kind"));
                }
                let (record, envelope) = self.read_canonical_record(root.object_id(), work)?;
                validate_root(&envelope, root)?;
                Ok(record)
            }
            RamObjectCoordinate::Catalog {
                region_id,
                first_page,
                height,
            } => self
                .read_catalog_record(root, region_id, *first_page, *height, work)
                .map(|(_, _, record)| record),
            RamObjectCoordinate::Page {
                region_id,
                page_index,
            } => {
                let length = page_length(root, region_id, *page_index)?;
                let (_, node, _) =
                    self.read_catalog_record(root, region_id, *page_index, 0, work)?;
                let TreeNode::Leaf { page, digest } = node else {
                    return Err(RamStoreError::Invalid("transfer page resolves to padding"));
                };
                if page.kind() != ObjectKind::RamExtent {
                    return Err(RamStoreError::Invalid("page object kind"));
                }
                let (record, envelope) = self.read_canonical_record(page, work)?;
                if validate_page_envelope(&envelope, digest)? != length {
                    return Err(RamStoreError::Invalid("transfer page valid length"));
                }
                Ok(record)
            }
        }
    }

    fn read_catalog_record(
        &self,
        root: &LeasedRamRoot,
        region_id: &str,
        first_page: u64,
        height: u32,
        work: &mut Work<'_>,
    ) -> Result<(TreeRef, TreeNode, RamObjectRecord), RamStoreError> {
        let (mut reference, mut position) = catalog_start(root, region_id, first_page, height)?;
        loop {
            let (record, envelope) = self.read_canonical_tree_record(reference, work)?;
            let node = validate_tree(&envelope, reference)?;
            if reference.height == height {
                return Ok((reference, node, record));
            }
            reference = next_catalog(reference, node, &mut position)?;
        }
    }
}

pub(super) fn validate_root(
    envelope: &crate::content_envelope::ContentEnvelope,
    root: &LeasedRamRoot,
) -> Result<(), RamStoreError> {
    let (record, catalogs) = decode_root_envelope(envelope)?;
    if &record != root.record.as_ref() || catalogs.as_slice() != root.regions.as_ref() {
        return Err(RamStoreError::Invalid(
            "transfer source root metadata changed",
        ));
    }
    Ok(())
}

pub(super) fn page_length(
    root: &LeasedRamRoot,
    region_id: &str,
    page_index: u64,
) -> Result<usize, RamStoreError> {
    let region = root
        .record
        .topology()
        .region(region_id)
        .ok_or(RamStoreError::Invalid("transfer page region"))?;
    valid_length(region, page_index)
}

pub(super) fn catalog_start(
    root: &LeasedRamRoot,
    region_id: &str,
    first_page: u64,
    height: u32,
) -> Result<(TreeRef, u64), RamStoreError> {
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
    Ok((root.regions[index], first_page))
}

fn next_catalog(
    reference: TreeRef,
    node: TreeNode,
    position: &mut u64,
) -> Result<TreeRef, RamStoreError> {
    let TreeNode::Branch { left, right } = node else {
        return Err(RamStoreError::Invalid(
            "coordinate below canonical padding subtree",
        ));
    };
    let width = 1_u64 << (reference.height - 1);
    if *position < width {
        Ok(left)
    } else {
        *position -= width;
        Ok(right)
    }
}
