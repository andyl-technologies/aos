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
        visitor: &mut dyn FnMut(ContentId) -> Result<(), RamStoreError>,
    ) -> Result<(), RamStoreError> {
        // Borrow the existing exclusive fence; resource admission obtains no
        // publication fence and covers the root throughout this bounded walk.
        let _metadata = self.reserve_root_metadata(1)?;
        let mut boundary = || Ok(());
        let mut work = Work::new(self.limits, &mut boundary);
        let (record, regions) = self.read_root(root, &mut work)?;
        self.admit_topology(record.topology())?;
        self.validate_root_catalogs(&record, &regions)?;
        for (region, reference) in record
            .topology()
            .regions()
            .iter()
            .filter(|region| record.scope().includes(region.class()))
            .zip(regions)
        {
            self.visit_inventory_region(region, reference, 0, visitor, &mut work)?;
        }
        visitor(root)
    }

    fn visit_inventory_region(
        &self,
        region: &RegionDescriptor,
        reference: TreeRef,
        first: u64,
        visitor: &mut dyn FnMut(ContentId) -> Result<(), RamStoreError>,
        work: &mut Work<'_>,
    ) -> Result<(), RamStoreError> {
        match self.read_tree(reference, work)? {
            TreeNode::Padding => {}
            TreeNode::Leaf { page, digest } => {
                if self.read_page_object(page, digest, work)?.len() != valid_length(region, first)?
                {
                    return Err(RamStoreError::Invalid("inventory page valid length"));
                }
                visitor(page)?;
            }
            TreeNode::Branch { left, right } => {
                self.visit_inventory_region(region, left, first, visitor, work)?;
                self.visit_inventory_region(
                    region,
                    right,
                    first + (1_u64 << (reference.height - 1)),
                    visitor,
                    work,
                )?;
            }
        }
        visitor(reference.id)
    }
}
