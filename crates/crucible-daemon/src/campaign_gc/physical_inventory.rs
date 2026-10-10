//! Same-original physical fence and receipt custody for daemon maintenance.
//!
//! Production always acquires the nominal checked backend owner. The explicit
//! scripted component adapter retains ordinary inventory only under cfg(test);
//! unsupported checked administration never falls back to that adapter.

#[cfg(test)]
use crucible_cas::content_store::BlobInventorySummary;
use crucible_cas::content_store::{
    BlobInventoryFence, BlobInventoryRecord, BlobStoreAdmin, CheckedInventoryFence, ContentId,
    InventoryGeneration, InventorySummaryReceipt, PhysicalStorageIdentity,
    PlannedDeleteDisposition, StoreError,
};

use super::{CampaignGcBlobInventoryBasis, CampaignGcOperationContext, CampaignGcPlanError};

pub(super) struct PhysicalFence<'backend, 'operation, 'boundary> {
    owner: FenceOwner<'backend>,
    operation: &'operation CampaignGcOperationContext<'boundary>,
}

enum FenceOwner<'backend> {
    Checked(CheckedInventoryFence<'backend>),
    #[cfg(test)]
    Scripted(Box<dyn BlobInventoryFence + 'backend>),
}

impl<'backend, 'operation, 'boundary> PhysicalFence<'backend, 'operation, 'boundary> {
    pub(super) fn checked(
        admin: &'backend dyn BlobStoreAdmin,
        operation: &'operation CampaignGcOperationContext<'boundary>,
    ) -> Result<Self, StoreError> {
        operation.check()?;
        let _scope = operation.original().enter();
        let owner = admin.acquire_inventory_fence_with_boundary(&mut || operation.check())?;
        Ok(Self {
            owner: FenceOwner::Checked(owner),
            operation,
        })
    }

    #[cfg(test)]
    pub(super) fn scripted(
        admin: &'backend dyn BlobStoreAdmin,
        operation: &'operation CampaignGcOperationContext<'boundary>,
    ) -> Result<Self, StoreError> {
        operation.check()?;
        Ok(Self {
            owner: FenceOwner::Scripted(admin.acquire_inventory_fence()?),
            operation,
        })
    }

    pub(super) fn as_mut(&mut self) -> &mut Self {
        self
    }

    pub(super) fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<PhysicalInventory, StoreError> {
        let _scope = self.operation.original().enter();
        match &mut self.owner {
            FenceOwner::Checked(owner) => owner
                .visit_inventory_with_boundary(visitor, &mut || self.operation.check())
                .map(PhysicalInventory::Checked),
            #[cfg(test)]
            FenceOwner::Scripted(owner) => owner
                .visit_inventory(visitor)
                .map(PhysicalInventory::Scripted),
        }
    }

    pub(super) fn delete_candidate(
        &mut self,
        id: ContentId,
    ) -> Result<PlannedDeleteDisposition, StoreError> {
        let _scope = self.operation.original().enter();
        match &mut self.owner {
            FenceOwner::Checked(owner) => {
                let receipt =
                    owner.delete_candidates_with_boundary(&[id], &mut || self.operation.check())?;
                match receipt.as_ref() {
                    [disposition] => Ok(*disposition),
                    _ => Err(StoreError::InvalidComposition {
                        reason: "GC checked deletion returned an invalid disposition count",
                    }),
                }
            }
            #[cfg(test)]
            FenceOwner::Scripted(owner) => owner.delete_candidate(id),
        }
    }
}

// The owning checked receipt retains its backend label and original credits
// through every comparison and the caller's bounded plan-basis construction.
pub(super) enum PhysicalInventory {
    Checked(InventorySummaryReceipt),
    #[cfg(test)]
    Scripted(BlobInventorySummary),
}

impl PhysicalInventory {
    pub(super) fn backend(&self) -> &str {
        match self {
            Self::Checked(summary) => summary.backend(),
            #[cfg(test)]
            Self::Scripted(summary) => summary.backend(),
        }
    }

    pub(super) fn storage_identity(&self) -> PhysicalStorageIdentity {
        match self {
            Self::Checked(summary) => summary.storage_identity(),
            #[cfg(test)]
            Self::Scripted(summary) => summary.storage_identity(),
        }
    }

    fn generation(&self) -> InventoryGeneration {
        match self {
            Self::Checked(summary) => summary.generation(),
            #[cfg(test)]
            Self::Scripted(summary) => summary.generation(),
        }
    }

    fn objects(&self) -> u64 {
        match self {
            Self::Checked(summary) => summary.objects(),
            #[cfg(test)]
            Self::Scripted(summary) => summary.objects(),
        }
    }

    fn logical_bytes(&self) -> u64 {
        match self {
            Self::Checked(summary) => summary.logical_bytes(),
            #[cfg(test)]
            Self::Scripted(summary) => summary.logical_bytes(),
        }
    }

    pub(super) fn basis(&self) -> Result<CampaignGcBlobInventoryBasis, CampaignGcPlanError> {
        CampaignGcBlobInventoryBasis::new(
            self.backend(),
            self.storage_identity(),
            self.generation(),
            self.objects(),
            self.logical_bytes(),
        )
    }
}

impl PartialEq for PhysicalInventory {
    fn eq(&self, other: &Self) -> bool {
        self.backend() == other.backend()
            && self.storage_identity() == other.storage_identity()
            && self.generation() == other.generation()
            && self.objects() == other.objects()
            && self.logical_bytes() == other.logical_bytes()
    }
}
