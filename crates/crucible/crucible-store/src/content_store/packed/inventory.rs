//! Exclusive placement cursors and generation-bound logical deletion.
//!
//! The retained root authenticates the cursor. Deletion updates its object and
//! pack counters atomically, then removes a physical pack only when no live
//! object still names it. There is no retained process-wide inventory map.

use super::index_format::Key;
use super::index_io::IndexFile;
use super::index_io::Operation;
use super::*;
use crate::content_store::{DeleteBatchReceipt, InventorySummaryReceipt, batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

impl BlobStoreAdmin for PackedBlobBackend {
    fn acquire_inventory_fence_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedInventoryFence<'_>, StoreError> {
        let original = batch::account()?;
        checked_reader::check(&original, boundary)?;
        let credit = original
            .reserve_scratch_array::<Fence<'_>>(1)
            .map_err(|error| batch::admission_under(&original, error))?;
        let diagnostic = original
            .reserve_scratch_array::<checked_publication::Failure>(1)
            .map_err(|error| batch::admission_under(&original, error))?;
        let work = (|| {
            let lifecycle =
                checked_io::lock(self, LIFECYCLE_LOCK_FILE, false, &original, boundary)?;
            let state = checked_io::lock(self, STATE_LOCK_FILE, false, &original, boundary)?;
            let index = index_snapshot::IndexSnapshot::load(self, &original, boundary)?;
            maintenance::validate(
                self,
                &index,
                &mut Operation {
                    original: Some(&original),
                    boundary,
                },
            )?;
            checked_reader::check(&original, boundary)?;
            Ok((lifecycle, state, index))
        })();
        match work {
            Ok((lifecycle, state, index)) => Ok(CheckedInventoryFence::new(
                Box::new(Fence {
                    backend: self,
                    _lifecycle: IndexFile::Checked(lifecycle),
                    _state_lock: IndexFile::Checked(state),
                    index,
                    original: Some(original),
                    diagnostic: Some(diagnostic),
                }),
                credit,
            )),
            Err(error) => Err(checked_publication::scope_error(
                None,
                Some(error),
                [None, None],
                Default::default(),
                diagnostic,
            )),
        }
    }

    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let state_lock = self.lock_state()?;
        let index = self.load_index()?;
        self.validate_index_packs(&index)?;
        self.cleanup_material(&index)?;
        Ok(Box::new(Fence {
            backend: self,
            _lifecycle: IndexFile::Ordinary(lifecycle),
            _state_lock: IndexFile::Ordinary(state_lock),
            index,
            original: None,
            diagnostic: None,
        }))
    }
}

struct Fence<'a> {
    backend: &'a PackedBlobBackend,
    _lifecycle: IndexFile,
    _state_lock: IndexFile,
    index: index_snapshot::IndexSnapshot,
    original: Option<DecodeBudget>,
    diagnostic: Option<DecodeScratch>,
}

impl Fence<'_> {
    fn enumerate(
        &self,
        original: Option<&DecodeBudget>,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let mut operation = Operation { original, boundary };
        let generation = persistent_inventory_generation(
            &self.backend.name,
            self.index.header.instance,
            self.index.header.generation,
        )?;
        let mut inventory = InventoryCounter::new(
            physical_storage_identity(self.index.header.instance),
            generation,
        );
        let reader = self.index.reader(self.backend, &mut operation)?;
        let mut cursor = reader.cursor(&mut operation)?;
        while let Some((key, value)) = cursor.next(&mut operation)? {
            if key.0[0] != 0 {
                break;
            }
            let record = BlobInventoryRecord::new(key.id()?, value.entry()?.length);
            operation.check()?;
            visitor(record)?;
            operation.check()?;
            inventory.push(record)?;
        }
        operation.check()?;
        Ok(inventory.finish(self.backend.name.clone()))
    }

    fn refuse(&mut self, error: StoreError, progress: checked_publication::Progress) -> StoreError {
        match self.diagnostic.take() {
            Some(credit) => checked_publication::scope_error(
                None,
                Some(error),
                progress.cleanup,
                progress.outcome,
                credit,
            ),
            None => error,
        }
    }
}

impl BlobInventoryFence for Fence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.enumerate(None, visitor, &mut || Ok(()))
    }

    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        self.refuse(error, Default::default())
    }

    fn visit_inventory_with_boundary(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        if self.diagnostic.is_none() {
            return Err(StoreError::Unsupported {
                capability: "failed-packed-inventory-fence",
            });
        }
        let original = self
            .original
            .as_ref()
            .ok_or(StoreError::Unsupported {
                capability: "ordinary-fence-has-no-checked-origin",
            })?
            .clone();
        checked_reader::check(&original, boundary)?;
        let credit = original
            .reserve_scratch_bytes(
                std::mem::size_of::<BlobInventorySummary>() as u64 + self.backend.name.len() as u64,
            )
            .map_err(|error| batch::admission_under(&original, error))?;
        let diagnostic = original
            .reserve_scratch_array::<checked_publication::Failure>(1)
            .map_err(|error| batch::admission_under(&original, error))?;
        match self.enumerate(Some(&original), visitor, boundary) {
            Ok(value) => Ok(InventorySummaryReceipt::new_packed(
                Accepted {
                    value,
                    outcome: Default::default(),
                    credit: diagnostic,
                },
                credit,
            )),
            Err(error) => Err(self.refuse(error, Default::default())),
        }
    }

    fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        if self.diagnostic.is_none() {
            return Err(StoreError::Unsupported {
                capability: "failed-packed-inventory-fence",
            });
        }
        let original = self
            .original
            .as_ref()
            .ok_or(StoreError::Unsupported {
                capability: "ordinary-fence-has-no-checked-origin",
            })?
            .clone();
        checked_reader::check(&original, boundary)?;
        if ids.len() > 64 {
            return Err(StoreError::Quota);
        }
        let credit = original
            .reserve_scratch_array::<PlannedDeleteDisposition>(ids.len())
            .map_err(|error| batch::admission_under(&original, error))?;
        let diagnostic = original
            .reserve_scratch_array::<checked_publication::Failure>(1)
            .map_err(|error| batch::admission_under(&original, error))?;
        let mut progress = checked_publication::Progress::default();
        let result = (|| {
            let mut dispositions = Vec::new();
            dispositions
                .try_reserve_exact(ids.len())
                .map_err(|error| batch::allocation_under(&original, error))?;
            for id in ids {
                let replacement = maintenance::removed(
                    self.backend,
                    &self.index,
                    *id,
                    &mut Operation {
                        original: Some(&original),
                        boundary,
                    },
                    &mut progress,
                )?;
                let disposition = match replacement {
                    None => {
                        checked_io::sync_directory(&self.backend.admin, &original, boundary)?;
                        progress.outcome.durable_objects += 1;
                        PlannedDeleteDisposition::AlreadyAbsent
                    }
                    Some((replacement, pack, empty)) => {
                        checked_publication::publish_index(
                            self.backend,
                            &original,
                            &replacement,
                            &mut progress,
                            boundary,
                            1,
                        )?;
                        self.index = replacement.snapshot();
                        if empty {
                            let path =
                                checked_publication::io::pack_path(self.backend, pack, &original)?;
                            checked_reader::check(&original, boundary)?;
                            path.with_native("remove-packed-checked-final-pack", |path| {
                                rustix::fs::unlinkat(
                                    rustix::fs::CWD,
                                    path,
                                    rustix::fs::AtFlags::empty(),
                                )
                                .map_err(|source| {
                                    StoreError::StreamIo {
                                        operation: "remove-packed-checked-final-pack",
                                        source: source.into(),
                                    }
                                })
                            })?;
                            checked_reader::check(&original, boundary)?;
                            checked_io::sync_directory(&self.backend.packs, &original, boundary)?;
                        }
                        PlannedDeleteDisposition::Deleted
                    }
                };
                dispositions.push(disposition);
                checked_reader::check(&original, boundary)?;
            }
            Ok(dispositions)
        })();
        match result {
            Ok(value) => Ok(DeleteBatchReceipt::new_packed(
                Accepted {
                    value,
                    outcome: progress.outcome,
                    credit: diagnostic,
                },
                credit,
            )),
            Err(error) => Err(self.refuse(error, progress)),
        }
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let mut operation = Operation {
            original: None,
            boundary: &mut || Ok(()),
        };
        let mut progress = checked_publication::Progress::default();
        let removal =
            maintenance::removed(self.backend, &self.index, id, &mut operation, &mut progress);
        let Some((replacement, pack, empty)) = (match removal {
            Ok(value) => value,
            Err(error) => {
                return maintenance::ordinary_completion(self.backend, Err(error), &mut progress);
            }
        }) else {
            self.backend.cleanup_material(&self.index)?;
            return Ok(PlannedDeleteDisposition::AlreadyAbsent);
        };
        self.backend.publish_index_reconciled(&replacement)?;
        self.index = replacement.snapshot();
        if empty {
            self.backend.remove_pack(pack)?;
        }
        maintenance::ordinary_completion(
            self.backend,
            Ok(PlannedDeleteDisposition::Deleted),
            &mut progress,
        )
    }

    fn repair_put_if_absent(
        &mut self,
        _authority: &PhysicalRepairAuthority,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        let mut operation = Operation {
            original: None,
            boundary: &mut || Ok(()),
        };
        if let Some(existing) = self
            .index
            .reader(self.backend, &mut operation)?
            .find(Key::object(id), &mut operation)?
        {
            self.backend
                .open_entry(id, &existing.entry()?)?
                .copy_to(&mut io::sink())?;
            source.verified_as(id)?;
            sync_directory(&self.backend.admin)?;
            return Ok(packed_receipt(
                &self.backend.name,
                id,
                source.logical_length(),
            ));
        }
        let pack_bytes = id.with_encoded_text(|text| {
            pack_fixed_header_length()
                .checked_add(text.len() as u64 + 18)
                .and_then(|bytes| bytes.checked_add(source.logical_length()))
                .ok_or(StoreError::Quota)
        })?;
        maintenance::publication_headroom(
            self.backend,
            &self.index,
            1,
            pack_bytes,
            &mut operation,
        )?;
        let candidate = self.backend.build_single_pack(id, source)?;
        let mut progress = checked_publication::Progress::default();
        let result = (|| {
            let entry = candidate
                .entries
                .first()
                .ok_or(StoreError::Incompatible)?
                .to_index_entry(candidate.id);
            let replacement = maintenance::replacement(
                self.backend,
                &self.index,
                &[(id, entry)],
                entry
                    .offset
                    .checked_add(entry.length)
                    .ok_or(StoreError::Quota)?,
                &mut operation,
                &mut progress,
            )?;
            self.backend.publish_pack(&candidate)?;
            self.backend.publish_index_reconciled(&replacement)?;
            self.index = replacement.snapshot();
            Ok(packed_receipt(
                &self.backend.name,
                id,
                source.logical_length(),
            ))
        })();
        let cleanup = remove_temporary(&candidate.temporary, result.is_ok());
        let result = match result {
            Ok(value) => {
                checked_publication::record_cleanup(Ok(()), cleanup, &mut progress).map(|()| value)
            }
            Err(error) => checked_publication::record_cleanup(Err(error), cleanup, &mut progress)
                .and(Err(StoreError::Unavailable)),
        };
        maintenance::ordinary_completion(self.backend, result, &mut progress)
    }
}
