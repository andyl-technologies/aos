//! Owning checked outputs and their final acceptance custody.

use crate::content_store::batch::admission_under;

use std::ops::Deref;

use crate::owned_decode::{DecodeBudget, DecodeScratch};

use super::*;
use crate::content_store::sqlite::Accepted;

// Payload and resource owners close before their corresponding linear credits.
pub(in crate::content_store) struct CheckedReceipt<T> {
    accepted: Accepted<T>,
    resources: Option<Box<Resources>>,
    credit: DecodeScratch,
}

struct Resources {
    _previous: Option<Box<Resources>>,
    _resources: crate::owned_decode::ResourceLoan,
    _previous_credit: Option<DecodeScratch>,
}

pub(in crate::content_store) struct PreparedResources {
    node: Box<Resources>,
    credit: DecodeScratch,
}

impl PreparedResources {
    pub(in crate::content_store) fn new(
        account: &DecodeBudget,
        resources: crate::owned_decode::ResourceLoan,
        additional_bytes: u64,
    ) -> Result<Self, StoreError> {
        let bytes = additional_bytes
            .checked_add(std::mem::size_of::<Resources>() as u64)
            .ok_or(StoreError::Quota)?;
        let credit = account
            .reserve_scratch_bytes(bytes)
            .map_err(|error| admission_under(account, error))?;
        Ok(Self {
            node: Box::new(Resources {
                _previous: None,
                _resources: resources,
                _previous_credit: None,
            }),
            credit,
        })
    }
}

impl<T> CheckedReceipt<T> {
    pub(in crate::content_store) fn new(accepted: Accepted<T>, credit: DecodeScratch) -> Self {
        Self {
            accepted,
            resources: None,
            credit,
        }
    }

    pub(in crate::content_store) fn value(&self) -> &T {
        self.accepted.value()
    }

    pub(in crate::content_store) fn release_diagnostic(&mut self) {
        self.accepted.release_diagnostic();
    }

    pub(in crate::content_store) fn retain_resources(&mut self, mut prepared: PreparedResources) {
        let previous_credit = std::mem::replace(&mut self.credit, prepared.credit);
        prepared.node._previous = self.resources.take();
        prepared.node._previous_credit = Some(previous_credit);
        self.resources = Some(prepared.node);
    }

    pub(in crate::content_store) fn check(
        self,
        check: impl FnOnce(&mut T) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let Self {
            accepted,
            resources,
            credit,
        } = self;
        // Keep this field-ordered owner intact across error and unwind. Separate
        // locals would refund the latest credit before the resource chain drops.
        let remaining = (resources, credit);
        let accepted = accepted.check(check)?;
        let (resources, credit) = remaining;
        Ok(Self {
            accepted,
            resources,
            credit,
        })
    }
}

/// Retains ordered durable deletion dispositions and their original credits.
///
/// Borrowing this slice does not detach any disposition from its allocation or
/// final commit-outcome owner. This output cannot be cloned or converted into
/// an uncredited vector.
pub struct DeleteBatchReceipt(CheckedReceipt<Vec<PlannedDeleteDisposition>>);

impl DeleteBatchReceipt {
    pub(in crate::content_store) fn new(
        accepted: Accepted<Vec<PlannedDeleteDisposition>>,
        credit: DecodeScratch,
    ) -> Self {
        Self(CheckedReceipt::new(accepted, credit))
    }

    pub(in crate::content_store) fn check(
        self,
        check: impl FnOnce(&mut Vec<PlannedDeleteDisposition>) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        self.0.check(check).map(Self)
    }

    pub(in crate::content_store) fn retain_resources(&mut self, prepared: PreparedResources) {
        self.0.retain_resources(prepared);
    }
}

impl Deref for DeleteBatchReceipt {
    type Target = [PlannedDeleteDisposition];

    fn deref(&self) -> &Self::Target {
        self.0.accepted.value()
    }
}

impl std::fmt::Debug for DeleteBatchReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.deref().fmt(formatter)
    }
}

/// Retains authenticated inventory completion with its owned backend label.
///
/// Its original payload and physical resource credits remain live through the
/// last output owner, even after the inventory fence is released.
pub struct InventorySummaryReceipt(CheckedReceipt<BlobInventorySummary>);

impl InventorySummaryReceipt {
    pub(in crate::content_store) fn new(
        accepted: Accepted<BlobInventorySummary>,
        credit: DecodeScratch,
    ) -> Self {
        Self(CheckedReceipt::new(accepted, credit))
    }

    pub(in crate::content_store) fn check(
        self,
        check: impl FnOnce(&mut BlobInventorySummary) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        self.0.check(check).map(Self)
    }

    pub(in crate::content_store) fn retain_resources(&mut self, prepared: PreparedResources) {
        self.0.retain_resources(prepared);
    }
}

impl InventorySummaryReceipt {
    /// Returns the retained backend name without detaching its allocation.
    #[must_use]
    pub fn backend(&self) -> &str {
        self.0.accepted.value().backend()
    }

    /// Returns the physical namespace bound into this completed inventory.
    #[must_use]
    pub fn storage_identity(&self) -> PhysicalStorageIdentity {
        self.0.accepted.value().storage_identity()
    }

    /// Returns the exact completed physical-inventory generation.
    #[must_use]
    pub fn generation(&self) -> InventoryGeneration {
        self.0.accepted.value().generation()
    }

    /// Returns the number of exact logical placements visited.
    #[must_use]
    pub fn objects(&self) -> u64 {
        self.0.accepted.value().objects()
    }

    /// Returns the authenticated sum of logical placement lengths.
    #[must_use]
    pub fn logical_bytes(&self) -> u64 {
        self.0.accepted.value().logical_bytes()
    }
}

impl std::fmt::Debug for InventorySummaryReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.accepted.value().fmt(formatter)
    }
}
