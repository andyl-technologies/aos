//! Original-funded Memory inventory and ordered deletion without a roster copy.

use super::*;
use crate::content_store::{admin::outcome::Progress, batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

pub(super) fn acquire<'a>(
    backend: &'a MemoryBlobBackend,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedInventoryFence<'a>, StoreError> {
    let original = batch::account()?;
    checked_reader::check(&original, boundary)?;
    let credit = original
        .reserve_scratch_array::<Fence<'_>>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let progress = Progress::reserve(&original)?;
    let state = checked::lock(backend, &original, boundary)?;
    checked_reader::check(&original, boundary)?;
    Ok(CheckedInventoryFence::new(
        Box::new(Fence {
            inner: MemoryBlobInventoryFence {
                backend: &backend.name,
                instance: backend.inventory_instance,
                max_logical_bytes: backend.max_logical_bytes,
                max_objects: backend.max_objects,
                namespace: backend.namespace.as_ref(),
                state,
            },
            original,
            progress: Some(progress),
        }),
        credit,
    ))
}

struct Fence<'a> {
    inner: MemoryBlobInventoryFence<'a>,
    original: DecodeBudget,
    progress: Option<Progress>,
}

impl Fence<'_> {
    fn account(&self) -> Result<(), StoreError> {
        if !self.original.same_account(&batch::account()?) {
            return Err(StoreError::InvalidComposition {
                reason: "Memory admin belongs to another original",
            });
        }
        if self.progress.is_none() {
            return Err(StoreError::Unsupported {
                capability: "failed-Memory-admin",
            });
        }
        Ok(())
    }

    fn refuse(&mut self, error: StoreError) -> StoreError {
        match self.progress.take() {
            Some(progress) => progress.refuse(error),
            None => error,
        }
    }

    fn failure_credit(&self) -> Result<Progress, StoreError> {
        Progress::reserve(&self.original)
    }

    fn output_credit(&self, bytes: u64) -> Result<DecodeScratch, StoreError> {
        self.original
            .reserve_scratch_bytes(bytes)
            .map_err(|error| batch::admission_under(&self.original, error))
    }
}

impl BlobInventoryFence for Fence<'_> {
    fn visit_inventory(
        &mut self,
        _visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        Err(StoreError::Unsupported {
            capability: "checked-Memory-summary-requires-owning-receipt",
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let original = self.original.clone();
        let _entered = original.enter();
        self.delete_candidates_with_boundary(&[id], &mut || Ok(()))?
            .first()
            .copied()
            .ok_or(StoreError::InvalidComposition {
                reason: "Memory deletion returned no disposition",
            })
    }

    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        self.refuse(error)
    }

    fn visit_inventory_with_boundary(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        // A foreign caller has not entered this fence's operation. Rejecting
        // it does not mutate the genuine original's retained authority.
        self.account()?;
        // Terminal by default across public callbacks, including unwind.
        // Success alone restores this same pre-admitted fence owner.
        let progress = self.progress.take();
        let result = self.visit_checked(visitor, boundary);
        if result.is_ok() {
            self.progress = progress;
        }
        result
    }

    fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        // A foreign caller has not entered this fence's operation. Rejecting
        // it does not mutate the genuine original's retained authority.
        self.account()?;
        // Terminal by default across public callbacks, including unwind.
        // Success alone restores this same pre-admitted fence owner.
        let progress = self.progress.take();
        let result = self.delete_checked(ids, boundary);
        if result.is_ok() {
            self.progress = progress;
        }
        result
    }
}

#[cfg(test)]
mod tests;

impl Fence<'_> {
    fn visit_checked(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        checked_reader::check(&self.original, boundary)?;
        let credit = self.output_credit(self.inner.backend.len() as u64)?;
        let progress = self.failure_credit()?;
        let result = (|| {
            let generation = persistent_inventory_generation(
                self.inner.backend,
                self.inner.instance,
                self.inner.state.generation,
            )?;
            let mut counter =
                InventoryCounter::new(physical_storage_identity(self.inner.instance), generation);
            for (id, body) in &self.inner.state.objects {
                checked_reader::check(&self.original, boundary)?;
                let record = BlobInventoryRecord::new(*id, body.bytes()?.len() as u64);
                counter.push(record)?;
                visitor(record)?;
                checked_reader::check(&self.original, boundary)?;
            }
            checked_reader::check(&self.original, boundary)?;
            Ok(counter.finish(self.inner.backend.to_owned()))
        })();
        match result {
            Ok(value) => Ok(InventorySummaryReceipt::new_administrative(
                progress.accept(value),
                credit,
            )),
            Err(error) => Err(progress.refuse(error)),
        }
    }

    fn delete_checked(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        checked_reader::check(&self.original, boundary)?;
        if ids.len() > 64 {
            return Err(StoreError::Quota);
        }
        let credit = self
            .output_credit((ids.len() * std::mem::size_of::<PlannedDeleteDisposition>()) as u64)?;
        let mut progress = self.failure_credit()?;
        let result = (|| {
            let mut values = Vec::new();
            values
                .try_reserve_exact(ids.len())
                .map_err(|error| batch::allocation_under(&self.original, error))?;
            for id in ids {
                checked_reader::check(&self.original, boundary)?;
                progress.begin_mutation();
                let disposition = self.inner.remove(*id)?;
                progress.complete(disposition);
                values.push(disposition);
                checked_reader::check(&self.original, boundary)?;
            }
            Ok(values)
        })();
        match result {
            Ok(value) => Ok(DeleteBatchReceipt::new_administrative(
                progress.accept(value),
                credit,
            )),
            Err(error) => Err(progress.refuse(error)),
        }
    }
}
