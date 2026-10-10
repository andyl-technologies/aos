//! Streams authenticated RAM reachability while the collector owns exclusion.

use crucible_ram::RegionDescriptor;

use crate::content_store::{ContentId, RefInventoryFence};

use super::codec::{TreeNode, TreeRef};
use super::{RamStore, RamStoreError, Work, valid_length};

impl RamStore {
    /// Visits the complete authenticated graph under a collector's GC fence.
    ///
    /// The exclusive inventory authority stays borrowed for the entire walk.
    /// This does not acquire a shared publication fence or manufacture a runtime
    /// root lease. Visitors may stream IDs into a disk-backed marking table;
    /// repeated contents are visited by position without an in-memory seen set.
    /// Every actual page is read and validated before collection can proceed.
    /// The caller's real supervision boundary runs before root metadata work
    /// and through every checked backend access; no replacement scope is made.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable or corrupt objects, invalid geometry,
    /// resource limits, or any visitor failure. A failed walk cannot authorize
    /// deletion; the caller must discard its incomplete collection candidate.
    pub fn visit_inventory_graph(
        &self,
        root: ContentId,
        _authority: &dyn RefInventoryFence,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
        visitor: &mut dyn FnMut(ContentId) -> Result<(), RamStoreError>,
    ) -> Result<(), RamStoreError> {
        // Borrow the existing exclusive fence; resource admission obtains no
        // publication fence and covers the root throughout this bounded walk.
        let mut work = Work::new(self.limits, original, boundary)?;
        work.original()
            .verify_live()
            .map_err(|error| RamStoreError::from_admission(original, error))?;
        (work.boundary)()?;
        work.original()
            .verify_live()
            .map_err(|error| RamStoreError::from_admission(original, error))?;
        let _metadata = self.reserve_root_metadata(1)?;
        let (record, regions) = self.read_root(root, &mut work)?;
        self.admit_topology(record.topology())?;
        self.validate_root_catalogs(&record, &regions)?;
        super::bounded_read::read_inventory(self, root, &record, &regions, visitor, &mut work)
    }
}

pub(super) trait InventoryAccess {
    fn tree(&mut self, reference: TreeRef) -> Result<TreeNode, RamStoreError>;
    fn page(
        &mut self,
        id: ContentId,
        digest: crucible_ram::PageDigest,
    ) -> Result<usize, RamStoreError>;
    fn visit(&mut self, id: ContentId) -> Result<(), RamStoreError>;
}

pub(super) struct ExistingInventory<'read, 'operation> {
    pub(super) store: &'read RamStore,
    pub(super) work: &'read mut Work<'operation>,
    pub(super) visitor: &'read mut dyn FnMut(ContentId) -> Result<(), RamStoreError>,
}

impl InventoryAccess for ExistingInventory<'_, '_> {
    fn tree(&mut self, reference: TreeRef) -> Result<TreeNode, RamStoreError> {
        self.store.read_tree(reference, self.work)
    }

    fn page(
        &mut self,
        id: ContentId,
        digest: crucible_ram::PageDigest,
    ) -> Result<usize, RamStoreError> {
        self.store
            .read_page_object(id, digest, self.work)
            .map(|page| page.len())
    }

    fn visit(&mut self, id: ContentId) -> Result<(), RamStoreError> {
        (self.visitor)(id)
    }
}

pub(super) fn walk(
    record: &crucible_ram::RootRecord,
    regions: &[TreeRef],
    root: ContentId,
    access: &mut impl InventoryAccess,
) -> Result<(), RamStoreError> {
    for (region, reference) in record
        .topology()
        .regions()
        .iter()
        .filter(|region| record.scope().includes(region.class()))
        .zip(regions.iter().copied())
    {
        visit_region(region, reference, 0, access)?;
    }
    access.visit(root)
}

fn visit_region(
    region: &RegionDescriptor,
    reference: TreeRef,
    first: u64,
    access: &mut impl InventoryAccess,
) -> Result<(), RamStoreError> {
    match access.tree(reference)? {
        TreeNode::Padding => {}
        TreeNode::Leaf { page, digest } => {
            if access.page(page, digest)? != valid_length(region, first)? {
                return Err(RamStoreError::Invalid("inventory page valid length"));
            }
            access.visit(page)?;
        }
        TreeNode::Branch { left, right } => {
            visit_region(region, left, first, access)?;
            visit_region(
                region,
                right,
                first + (1_u64 << (reference.height - 1)),
                access,
            )?;
        }
    }
    access.visit(reference.id)
}

pub(super) struct CheckedInventory<'read, 'operation, F, V> {
    pub(super) work: &'read mut Work<'operation>,
    pub(super) visitor: &'read mut dyn FnMut(ContentId) -> Result<(), RamStoreError>,
    pub(super) source: &'read mut F,
    pub(super) verify: &'read mut V,
}

impl<F, V> InventoryAccess for CheckedInventory<'_, '_, F, V>
where
    V: FnMut(&crate::owned_decode::DecodeBudget) -> Result<(), crate::content_store::StoreError>,
    F: FnMut(
        &crate::owned_decode::DecodeBudget,
        ContentId,
        &mut dyn FnMut() -> Result<(), crate::content_store::StoreError>,
    ) -> Result<crate::content_store::BlobHandle, crate::content_store::StoreError>,
{
    fn tree(&mut self, reference: TreeRef) -> Result<TreeNode, RamStoreError> {
        if reference.id.kind() != crate::content_store::ObjectKind::RamTree {
            return Err(RamStoreError::Invalid("tree object kind"));
        }
        let envelope = super::codec::read_envelope_using(
            reference.id,
            self.work,
            true,
            self.source,
            self.verify,
        )?;
        super::codec::validate_tree(&envelope, reference)
    }

    fn page(
        &mut self,
        id: ContentId,
        digest: crucible_ram::PageDigest,
    ) -> Result<usize, RamStoreError> {
        if id.kind() != crate::content_store::ObjectKind::RamExtent {
            return Err(RamStoreError::Invalid("page object kind"));
        }
        let envelope =
            super::codec::read_envelope_using(id, self.work, false, self.source, self.verify)?;
        super::codec::validate_page_envelope(&envelope, digest)?;
        Ok(super::RamPageBytes::new(envelope).len())
    }

    fn visit(&mut self, id: ContentId) -> Result<(), RamStoreError> {
        (self.visitor)(id)
    }
}
