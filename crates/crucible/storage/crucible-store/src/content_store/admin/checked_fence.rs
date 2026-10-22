//! Linear inventory ownership through physical fence allocation destruction.
//!
//! The existing boxed backend fence and its original loan move together. The
//! box closes before external descriptor/resident resources and metadata credit
//! return; borrowing its methods cannot detach the allocation from that loan.

use super::*;
use crate::owned_decode::{DecodeScratch, ResourceLoan, ResourceLoanSlot};

/// Owns a checked inventory fence through its allocation's physical release.
///
/// Acquisition prepays the backend's existing fence allocation. This owner
/// retains that same credit outside the box, including when destruction unwinds.
/// It exposes the existing borrowed operations without an owning extraction.
pub struct CheckedInventoryFence<'a> {
    fence: Option<Box<dyn BlobInventoryFence + 'a>>,
    _resources: ResourceLoanSlot,
    _credit: Option<DecodeScratch>,
}

impl<'a> CheckedInventoryFence<'a> {
    pub(in crate::content_store) fn new(
        fence: Box<dyn BlobInventoryFence + 'a>,
        credit: DecodeScratch,
    ) -> Self {
        Self {
            fence: Some(fence),
            _resources: Default::default(),
            _credit: Some(credit),
        }
    }

    pub(in crate::content_store) fn new_with_resources(
        fence: Box<dyn BlobInventoryFence + 'a>,
        credit: DecodeScratch,
        resources: ResourceLoan,
    ) -> Self {
        Self {
            fence: Some(fence),
            _resources: resources.into(),
            _credit: Some(credit),
        }
    }

    // Ordinary physical facades retain the same child representation without
    // gaining a checked origin or substituting it after checked refusal.
    pub(in crate::content_store) fn ordinary(fence: Box<dyn BlobInventoryFence + 'a>) -> Self {
        Self {
            fence: Some(fence),
            _resources: Default::default(),
            _credit: None,
        }
    }

    fn borrow(&mut self) -> Result<&mut (dyn BlobInventoryFence + 'a), StoreError> {
        self.fence.as_deref_mut().ok_or(StoreError::Unsupported {
            capability: "closed-inventory-fence",
        })
    }
}

impl Drop for CheckedInventoryFence<'_> {
    fn drop(&mut self) {
        // Box destruction precedes the ordinary field drops, including if the
        // contained fence panics while closing its own resources.
        drop(self.fence.take());
    }
}

impl BlobInventoryFence for CheckedInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.borrow()?.visit_inventory(visitor)
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        self.borrow()?.delete_candidate(id)
    }

    fn visit_inventory_with_boundary(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        self.borrow()?
            .visit_inventory_with_boundary(visitor, boundary)
    }

    fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        self.borrow()?
            .delete_candidates_with_boundary(ids, boundary)
    }

    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        match self.fence.as_deref_mut() {
            Some(fence) => fence.retain_checked_failure(error),
            None => error,
        }
    }

    fn repair_put_if_absent(
        &mut self,
        authority: &PhysicalRepairAuthority,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        self.borrow()?.repair_put_if_absent(authority, id, source)
    }
}

#[cfg(test)]
mod tests;
