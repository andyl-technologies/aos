//! Original-bound S3 pagination and conditional deletion under held namespace locks.

use super::*;
use crate::content_store::{admin::outcome::Progress, batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeDescriptorLoan, DecodeScratch};
use std::sync::TryLockError;

pub(super) fn acquire<'a>(
    backend: &'a S3BlobBackend,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedInventoryFence<'a>, StoreError> {
    let original = batch::account()?;
    let mut check = || checked_reader::check(&original, boundary);
    check()?;
    let administration = backend
        .administration
        .as_ref()
        .ok_or(StoreError::InvalidComposition {
            reason: "S3 blob backend has no committed-object administration capability",
        })?;
    let credit = original
        .reserve_scratch_array::<Fence<'_>>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let progress = Progress::reserve_diagnostic(&original, 6 * 4096)?;
    // Public client contracts bound each page to 1,000 1-KiB keys and each
    // cursor, version and small state body to 4 KiB. This is decoded output
    // custody; opaque transport internals retain their separately admitted owner.
    let page_bytes = u64::from(MAX_S3_OBJECT_LIST_ITEMS)
        * (1024 + std::mem::size_of::<String>() as u64)
        + 6 * 4096;
    let scratch = original
        .reserve_scratch_bytes(page_bytes)
        .map_err(|error| batch::admission_under(&original, error))?;
    let descriptors = original
        .reserve_descriptors(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let result = (|| {
        let publication = loop {
            check()?;
            match backend.lifecycle.publication.try_write() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => std::hint::spin_loop(),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(StoreError::Poisoned {
                        operation: "acquire-S3-blob-inventory-publication-fence",
                    });
                }
            }
        };
        let state = loop {
            check()?;
            match backend.lifecycle.state.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => std::hint::spin_loop(),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(StoreError::Poisoned {
                        operation: "acquire-S3-blob-inventory-state-fence",
                    });
                }
            }
        };
        let inventory = administration.load_or_create_state_checked(backend, &mut check)?;
        check()?;
        Ok(S3BlobInventoryFence {
            backend,
            administration,
            _publication: publication,
            _state: state,
            inventory,
        })
    })();
    match result {
        Ok(inner) => Ok(CheckedInventoryFence::new(
            Box::new(Fence {
                inner,
                original,
                progress: Some(progress),
                _scratch: scratch,
                _descriptors: descriptors,
            }),
            credit,
        )),
        Err(error) => Err(progress.refuse(error)),
    }
}

struct Fence<'a> {
    inner: S3BlobInventoryFence<'a>,
    original: DecodeBudget,
    progress: Option<Progress>,
    _scratch: DecodeScratch,
    _descriptors: DecodeDescriptorLoan,
}

impl Fence<'_> {
    fn account(&self) -> Result<(), StoreError> {
        if !self.original.same_account(&batch::account()?) {
            return Err(StoreError::InvalidComposition {
                reason: "S3 admin belongs to another original",
            });
        }
        if self.progress.is_none() {
            return Err(StoreError::Unsupported {
                capability: "failed-S3-admin",
            });
        }
        Ok(())
    }
}

impl BlobInventoryFence for Fence<'_> {
    fn visit_inventory(
        &mut self,
        _visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        Err(StoreError::Unsupported {
            capability: "checked-S3-summary-requires-owning-receipt",
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let original = self.original.clone();
        let _entered = original.enter();
        self.delete_candidates_with_boundary(&[id], &mut || Ok(()))?
            .first()
            .copied()
            .ok_or(StoreError::InvalidComposition {
                reason: "S3 deletion returned no disposition",
            })
    }

    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        match self.progress.take() {
            Some(progress) => progress.refuse(error),
            None => error,
        }
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

impl Fence<'_> {
    fn visit_checked(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        let original = &self.original;
        let mut check = || checked_reader::check(original, boundary);
        check()?;
        let credit = original
            .reserve_scratch_bytes(self.inner.backend.name.len() as u64)
            .map_err(|error| batch::admission_under(original, error))?;
        let progress = Progress::reserve_diagnostic(original, 6 * 4096)?;
        match self.inner.visit_objects(visitor, &mut check) {
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
        let original = &self.original;
        let mut check = || checked_reader::check(original, boundary);
        check()?;
        if ids.len() > 64 {
            return Err(StoreError::Quota);
        }
        let credit = original
            .reserve_scratch_array::<PlannedDeleteDisposition>(ids.len())
            .map_err(|error| batch::admission_under(original, error))?;
        let mut progress = Progress::reserve_diagnostic(original, 6 * 4096)?;
        let result = (|| {
            let mut values = Vec::new();
            values
                .try_reserve_exact(ids.len())
                .map_err(|error| batch::allocation_under(original, error))?;
            for id in ids {
                check()?;
                let key = self.inner.backend.key(*id);
                check()?;
                let metadata = self
                    .inner
                    .administration
                    .client
                    .head_versioned_object(&self.inner.backend.bucket, &key)?;
                check()?;
                let Some(metadata) = metadata else {
                    values.push(PlannedDeleteDisposition::AlreadyAbsent);
                    continue;
                };
                if metadata.logical_length() > self.inner.backend.maximum_logical_object_bytes {
                    return Err(StoreError::Corrupt { id: *id });
                }
                self.inner.inventory = self
                    .inner
                    .administration
                    .advance_state_checked(self.inner.backend, &mut check)?;
                check()?;
                progress.begin_mutation();
                let outcome = self.inner.administration.client.delete_object_if_version(
                    &self.inner.backend.bucket,
                    &key,
                    metadata.version(),
                )?;
                match outcome {
                    StoreS3ConditionalDeleteOutcome::PreconditionFailed => {
                        progress.complete(PlannedDeleteDisposition::AlreadyAbsent);
                        return Err(StoreError::Incompatible);
                    }
                    StoreS3ConditionalDeleteOutcome::Deleted => {
                        // The conditional API has already confirmed this exact
                        // deletion. A later readback failure must retain it.
                        progress.complete(PlannedDeleteDisposition::Deleted);
                        check()?;
                        if self
                            .inner
                            .administration
                            .client
                            .head_versioned_object(&self.inner.backend.bucket, &key)?
                            .is_some()
                        {
                            return Err(StoreError::Incompatible);
                        }
                        values.push(PlannedDeleteDisposition::Deleted);
                        check()?;
                    }
                }
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
