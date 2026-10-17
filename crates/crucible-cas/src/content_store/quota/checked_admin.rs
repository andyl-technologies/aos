//! Paid quota-state fencing and checked child administration across restart.

use super::*;
use crate::content_store::{
    CheckedInventoryFence, DeleteBatchReceipt, InventorySummaryReceipt,
    admin::{PreparedResources, outcome::Progress},
    batch, checked_reader,
};
use crate::owned_decode::{DecodeBudget, DecodeDescriptorLoan, DecodeScratch};

fn diagnostic_bytes(store: &LogicalQuotaStore) -> Result<u64, StoreError> {
    let path = store.state_root.as_os_str().len() as u64;
    path.checked_add(QUOTA_STATE_STAGING_FILE.len() as u64 + 1)
        .and_then(|bytes| bytes.checked_mul(4))
        .and_then(|bytes| bytes.checked_add(2 * QUOTA_STATE_BYTES))
        .ok_or(StoreError::Quota)
}

pub(super) fn acquire<'a>(
    store: &'a LogicalQuotaStore,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedInventoryFence<'a>, StoreError> {
    let original = batch::account()?;
    let mut check = || checked_reader::check(&original, boundary);
    check()?;
    let credit = original
        .reserve_scratch_array::<Fence<'_>>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let bytes = diagnostic_bytes(store)?;
    let scratch = original
        .reserve_scratch_bytes(bytes)
        .map_err(|error| batch::admission_under(&original, error))?;
    let progress = Progress::reserve_diagnostic(&original, bytes)?;
    // Quota lock plus state/staging and directory sync. Child descriptors
    // are separately admitted by the same original checked leaf.
    let descriptors = original
        .reserve_descriptors(3)
        .map_err(|error| batch::admission_under(&original, error))?;
    let result = (|| {
        check()?;
        create_dir_all_durable(&store.state_root)?;
        check()?;
        let path = store.state_root.join(QUOTA_LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "open-logical-quota-lock",
                path: path.clone(),
                source,
            })?;
        loop {
            check()?;
            match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(source) if source == rustix::io::Errno::WOULDBLOCK => std::hint::spin_loop(),
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "lock-logical-quota",
                        path,
                        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
                    });
                }
            }
        }
        let path = store.state_root.join(QUOTA_STATE_FILE);
        check()?;
        let state = match open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => {
                check()?;
                let state = read_quota_state(File::from(fd), &path)?;
                check()?;
                if state.binding != store.binding {
                    return Err(StoreError::InvalidComposition {
                        reason: "logical quota state belongs to another graph configuration",
                    });
                }
                store.validate_usage(state.objects, state.logical_bytes)?;
                Some(state)
            }
            Err(source) if source == rustix::io::Errno::NOENT => None,
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "open-logical-quota-state",
                    path,
                    source: std::io::Error::from_raw_os_error(source.raw_os_error()),
                });
            }
        };
        check()?;
        // Acquire the child once. Dirty recovery uses this exact held checked
        // capability; it never reacquires an ordinary fence.
        let mut child = {
            // Public boundaries may change the ambient account. The child
            // still receives this operation's saved original authority.
            let _entered = original.enter();
            store
                .child_admin
                .acquire_inventory_fence_with_boundary(&mut check)?
        };
        let state = match state {
            Some(state) if !state.dirty => state,
            _ => recover(store, &mut child, &original, &mut check)?,
        };
        check()?;
        Ok((lock, child, state))
    })();
    match result {
        Ok((lock, child, state)) => Ok(CheckedInventoryFence::new(
            Box::new(Fence {
                child,
                _lock: lock,
                store,
                state,
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

fn recover(
    store: &LogicalQuotaStore,
    child: &mut CheckedInventoryFence<'_>,
    original: &DecodeBudget,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<QuotaState, StoreError> {
    let summary = {
        let _entered = original.enter();
        child.visit_inventory_with_boundary(
            &mut |record| store.validate_usage(1, record.logical_length()),
            check,
        )?
    };
    if summary.backend() != store.child.name() {
        return Err(StoreError::InvalidComposition {
            reason: "logical quota child inventory name differs",
        });
    }
    store.validate_usage(summary.objects(), summary.logical_bytes())?;
    let state = QuotaState {
        binding: store.binding,
        objects: summary.objects(),
        logical_bytes: summary.logical_bytes(),
        dirty: false,
    };
    store.persist_state_checked(state, check)?;
    Ok(state)
}

struct Fence<'a> {
    child: CheckedInventoryFence<'a>,
    _lock: File,
    store: &'a LogicalQuotaStore,
    state: QuotaState,
    original: DecodeBudget,
    progress: Option<Progress>,
    _scratch: DecodeScratch,
    _descriptors: DecodeDescriptorLoan,
}

impl Fence<'_> {
    fn account(&self) -> Result<(), StoreError> {
        if !self.original.same_account(&batch::account()?) {
            return Err(StoreError::InvalidComposition {
                reason: "logical quota admin belongs to another original",
            });
        }
        if self.progress.is_none() {
            return Err(StoreError::Unsupported {
                capability: "failed-logical-quota-admin",
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
            capability: "checked-quota-summary-requires-owning-receipt",
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let original = self.original.clone();
        let _entered = original.enter();
        self.delete_candidates_with_boundary(&[id], &mut || Ok(()))?
            .first()
            .copied()
            .ok_or(StoreError::InvalidComposition {
                reason: "quota deletion returned no disposition",
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

#[cfg(test)]
mod tests;

impl Fence<'_> {
    fn visit_checked(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        let original = &self.original;
        let mut check = || checked_reader::check(original, boundary);
        check()?;
        let prepared = PreparedResources::metadata(original, self.store.name.len() as u64)?;
        let mut summary = {
            let _entered = original.enter();
            self.child
                .visit_inventory_with_boundary(visitor, &mut check)?
        };
        summary.retain_resources(prepared);
        summary.check(|summary| {
            check()?;
            if summary.backend() != self.store.child.name()
                || summary.objects() != self.state.objects
                || summary.logical_bytes() != self.state.logical_bytes
            {
                return Err(StoreError::InvalidComposition {
                    reason: "logical quota accounting differs from child inventory",
                });
            }
            *summary = BlobInventorySummary::new(
                self.store.name.clone(),
                summary.storage_identity(),
                summary.generation(),
                summary.objects(),
                summary.logical_bytes(),
            );
            check()
        })
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
        let mut progress = Progress::reserve_diagnostic(original, diagnostic_bytes(self.store)?)?;
        let result = (|| {
            progress.begin_mutation();
            self.store.persist_state_checked(
                QuotaState {
                    dirty: true,
                    ..self.state
                },
                &mut check,
            )?;
            let receipt = {
                let _entered = original.enter();
                self.child
                    .delete_candidates_with_boundary(ids, &mut check)?
            };
            // The actual child outcome stays owned through recovery, state
            // durability and the final boundary. Failure cannot detach it.
            receipt.check(|values| {
                for value in values.iter() {
                    progress.complete(*value);
                }
                progress.begin_mutation();
                self.state = recover(self.store, &mut self.child, original, &mut check)?;
                progress.complete(PlannedDeleteDisposition::AlreadyAbsent);
                check()
            })
        })();
        result.map_err(|error| progress.refuse(error))
    }
}
