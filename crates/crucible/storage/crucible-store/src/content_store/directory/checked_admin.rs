//! Original-account directory cursors and durable ordered logical deletion.
//!
//! Three fixed-depth getdents cursors share the fence's original descriptor
//! envelope. Their fixed buffers and transient paths never retain a roster.
//! The fence Box's credit is external; each operation's output and failure
//! owners independently retain their original scratch through physical free.

use super::checked_publication::{self as publication, Progress};
use super::*;
use crate::content_store::{DeleteBatchReceipt, InventorySummaryReceipt, batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeDescriptorLoan, DecodeScratch};
use rustix::fs::{Mode, OFlags, RawDir};
use std::mem::MaybeUninit;

const CURSOR_BYTES: usize = 2048;

type Boundary<'a> = dyn FnMut() -> Result<(), StoreError> + 'a;

pub(super) type Initializer<'a> = dyn FnMut(&mut Boundary<'_>) -> Result<(), StoreError> + 'a;
type EntryVisitor<'a> = dyn FnMut(&str, &mut Boundary<'_>) -> Result<(), StoreError> + 'a;

pub(super) fn acquire<'a>(
    backend: &'a DirectoryBlobBackend,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedInventoryFence<'a>, StoreError> {
    let original = batch::account()?;
    acquire_initialized(backend, original, boundary, &mut |_| Ok(()))
}

pub(super) fn acquire_initialized<'a>(
    backend: &'a DirectoryBlobBackend,
    original: DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    initialize: &mut Initializer<'_>,
) -> Result<CheckedInventoryFence<'a>, StoreError> {
    // Wrappers pass the original captured before their first callback. A
    // callback's TLS change cannot introduce a second resource account here.
    checked_reader::check(&original, boundary)?;
    let credit = original
        .reserve_scratch_array::<Fence<'_>>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let failure_credit = original
        .reserve_scratch_array::<publication::Failure>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let diagnostic = original
        .reserve_scratch_bytes(
            DirectoryBlobBackend::quota_resource_costs(&backend.root)?.operation_bytes,
        )
        .map_err(|error| batch::admission_under(&original, error))?;
    // Lock + root/objects/prefix cursors is the peak. State creation needs
    // lock + staging + sync, and never overlaps the three traversal cursors.
    let descriptors = original
        .reserve_descriptors(4)
        .map_err(|error| batch::admission_under(&original, error))?;
    let mut progress = Progress::default();
    let result = (|| {
        let mut check = || checked_reader::check(&original, boundary);
        let lock = publication::lock_inventory(backend, &original, &mut check)?;
        // Encoded leaves authenticate their key generation under this same
        // lock before inventory state may be created or traversed.
        initialize(&mut check)?;
        check()?;
        let state = publication::load_state(backend, &mut check, &mut progress)?;
        walk(backend, &original, &mut check, &mut |_, _| Ok(()))?;
        check()?;
        Ok((lock, state))
    })();
    match result {
        Ok((lock, state)) => Ok(CheckedInventoryFence::new(
            Box::new(Fence {
                backend,
                _lock: lock,
                state,
                _descriptors: descriptors,
                original,
                diagnostic: Some(diagnostic),
                failure_credit: Some(failure_credit),
            }),
            credit,
        )),
        Err(error) => {
            let post_boundary = checked_reader::check(&original, boundary).err();
            let mut error = publication::scope_error_with_maintenance(
                (!progress.cleanup_only).then_some(error),
                progress.cleanup,
                Default::default(),
                Some(DirectoryMaintenanceOutcome {
                    durability_uncertain: progress.state_durability_uncertain,
                    ..Default::default()
                }),
                Some(diagnostic),
                failure_credit,
            );
            if let StoreError::DirectoryScope { source } = &mut error {
                source.retain_post_boundary(post_boundary);
            }
            Err(error)
        }
    }
}

struct Fence<'a> {
    backend: &'a DirectoryBlobBackend,
    _lock: File,
    state: DirectoryInventoryState,
    // All actual files close before this same prepaid descriptor envelope.
    _descriptors: DecodeDescriptorLoan,
    original: DecodeBudget,
    diagnostic: Option<DecodeScratch>,
    failure_credit: Option<DecodeScratch>,
}

impl Fence<'_> {
    fn account(&self) -> Result<DecodeBudget, StoreError> {
        let caller = batch::account()?;
        if !self.original.same_account(&caller) {
            return Err(StoreError::InvalidComposition {
                reason: "directory inventory fence belongs to another original account",
            });
        }
        if self.failure_credit.is_none() {
            return Err(StoreError::Unsupported {
                capability: "failed-directory-inventory-fence",
            });
        }
        Ok(caller)
    }

    fn refuse(
        &mut self,
        error: StoreError,
        cleanup: Option<StoreError>,
        outcome: DirectoryMaintenanceOutcome,
        cleanup_only: bool,
    ) -> StoreError {
        match self.failure_credit.take() {
            Some(credit) => publication::scope_error_with_maintenance(
                (!cleanup_only).then_some(error),
                cleanup,
                Default::default(),
                Some(outcome),
                self.diagnostic.take(),
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
        let _ = visitor;
        Err(StoreError::Unsupported {
            capability: "checked-directory-summary-requires-owning-receipt",
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let _entered = self.original.enter();
        let receipt = self.delete_candidates_with_boundary(&[id], &mut || Ok(()))?;
        receipt
            .first()
            .copied()
            .ok_or(StoreError::InvalidComposition {
                reason: "directory delete returned no disposition",
            })
    }

    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        self.refuse(error, None, Default::default(), false)
    }

    fn visit_inventory_with_boundary(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        let original = self.account()?;
        // Removing the existing credit seals the fence during work. A caught
        // visitor or boundary panic cannot reenter it after partial traversal.
        let retained_failure_credit = self.failure_credit.take();
        let result = (|| {
            checked_reader::check(&original, boundary)?;
            let credit = original
                .reserve_scratch_bytes(
                    std::mem::size_of::<BlobInventorySummary>() as u64
                        + self.backend.name.len() as u64,
                )
                .map_err(|error| batch::admission_under(&original, error))?;
            let failure_credit = original
                .reserve_scratch_array::<publication::Failure>(1)
                .map_err(|error| batch::admission_under(&original, error))?;
            let generation = persistent_inventory_generation(
                &self.backend.name,
                self.state.instance,
                self.state.generation,
            )?;
            let mut inventory =
                InventoryCounter::new(physical_storage_identity(self.state.instance), generation);
            let mut check = || checked_reader::check(&original, boundary);
            walk(self.backend, &original, &mut check, &mut |path, id| {
                let metadata = fs::symlink_metadata(path)
                    .map_err(|source| io_error("inspect-inventory-object", source))?;
                if !metadata.file_type().is_file() {
                    return Err(StoreError::InvalidComposition {
                        reason: "inventory object is not a regular file",
                    });
                }
                let record = BlobInventoryRecord::new(id, metadata.len());
                inventory.push(record)?;
                visitor(record)
            })?;
            check()?;
            Ok(InventorySummaryReceipt::new_directory(
                Accepted {
                    value: inventory.finish(self.backend.name.clone()),
                    outcome: Default::default(),
                    maintenance: None,
                    diagnostic: None,
                    credit: failure_credit,
                },
                credit,
            ))
        })();
        self.failure_credit = retained_failure_credit;
        result.map_err(|error| {
            let mut error = self.refuse(error, None, Default::default(), false);
            retain_post_boundary(&mut error, &original, boundary);
            error
        })
    }

    fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        let original = self.account()?;
        let retained_failure_credit = self.failure_credit.take();
        let mut outcome = DirectoryMaintenanceOutcome::default();
        let mut progress = Progress::default();
        let result = (|| {
            checked_reader::check(&original, boundary)?;
            if ids.len() > 64 {
                return Err(StoreError::Quota);
            }
            let credit = original
                .reserve_scratch_array::<PlannedDeleteDisposition>(ids.len())
                .map_err(|error| batch::admission_under(&original, error))?;
            let failure_credit = original
                .reserve_scratch_array::<publication::Failure>(1)
                .map_err(|error| batch::admission_under(&original, error))?;
            let mut dispositions = Vec::new();
            dispositions
                .try_reserve_exact(ids.len())
                .map_err(|error| batch::allocation_under(&original, error))?;
            let mut check = || checked_reader::check(&original, boundary);
            for id in ids {
                check()?;
                self.state.generation = self
                    .state
                    .generation
                    .checked_add(1)
                    .ok_or(StoreError::Quota)?;
                publication::persist_state(self.backend, self.state, &mut check, &mut progress)?;
                let path = checked::object_path(self.backend, &original, *id)?;
                check()?;
                let disposition = match fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        if !metadata.file_type().is_file() {
                            return Err(StoreError::InvalidComposition {
                                reason: "delete candidate is not a regular file",
                            });
                        }
                        check()?;
                        fs::remove_file(&path)
                            .map_err(|source| io_error("remove-planned-object", source))?;
                        outcome.removed_objects += 1;
                        outcome.durability_uncertain = true;
                        PlannedDeleteDisposition::Deleted
                    }
                    Err(source) if source.kind() == io::ErrorKind::NotFound => {
                        PlannedDeleteDisposition::AlreadyAbsent
                    }
                    Err(source) => return Err(io_error("inspect-delete-candidate", source)),
                };
                check()?;
                let parent = path.parent().ok_or(StoreError::InvalidComposition {
                    reason: "delete candidate has no parent",
                })?;
                // A nonexistent shard already has durable absence established
                // by its closest existing ancestor; never create it for GC.
                sync_absence(parent, &mut check)?;
                outcome.durable_candidates += 1;
                outcome.durability_uncertain = false;
                dispositions.push(disposition);
                check()?;
            }
            Ok(DeleteBatchReceipt::new_directory(
                Accepted {
                    value: dispositions,
                    outcome: Default::default(),
                    maintenance: Some(outcome),
                    diagnostic: None,
                    credit: failure_credit,
                },
                credit,
            ))
        })();
        self.failure_credit = retained_failure_credit;
        result.map_err(|error| {
            outcome.durability_uncertain |= progress.state_durability_uncertain;
            let mut error = self.refuse(error, progress.cleanup, outcome, progress.cleanup_only);
            retain_post_boundary(&mut error, &original, boundary);
            error
        })
    }
}

fn retain_post_boundary(
    error: &mut StoreError,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) {
    let post_boundary = checked_reader::check(original, boundary).err();
    if let StoreError::DirectoryScope { source } = error {
        source.retain_post_boundary(post_boundary);
    }
}

fn io_error(operation: &'static str, source: io::Error) -> StoreError {
    StoreError::StreamIo { operation, source }
}

fn sync_absence(
    mut path: &Path,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    loop {
        check()?;
        match File::open(path) {
            Ok(file) => {
                check()?;
                file.sync_all()
                    .map_err(|source| io_error("sync-directory-delete", source))?;
                return Ok(());
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                path = path.parent().ok_or(StoreError::InvalidComposition {
                    reason: "no existing inventory ancestor",
                })?;
            }
            Err(source) => return Err(io_error("open-directory-delete-sync", source)),
        }
    }
}

fn walk(
    backend: &DirectoryBlobBackend,
    original: &DecodeBudget,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
    visitor: &mut dyn FnMut(&Path, ContentId) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    entries(&backend.root, original, check, &mut |name, check| {
        let root_path = backend.root.join(name);
        require_directory(&root_path)?;
        match name {
            INVENTORY_ADMIN_DIRECTORY => Ok(()),
            OBJECT_DIRECTORY => entries(&root_path, original, check, &mut |prefix, check| {
                if prefix.len() != 2 || !prefix.bytes().all(is_lower_hex) {
                    return Err(StoreError::InvalidComposition {
                        reason: "inventory contains a noncanonical digest-prefix directory",
                    });
                }
                let prefix_path = root_path.join(prefix);
                require_directory(&prefix_path)?;
                entries(&prefix_path, original, check, &mut |name, check| {
                    let id = ContentId::parse(name)?;
                    if id.digest()[0]
                        != u8::from_str_radix(prefix, 16).map_err(|_| StoreError::InvalidId)?
                    {
                        return Err(StoreError::InvalidComposition {
                            reason: "inventory object is in the wrong digest-prefix directory",
                        });
                    }
                    let path = prefix_path.join(name);
                    check()?;
                    visitor(&path, id)?;
                    check()
                })
            }),
            _ => Err(StoreError::InvalidComposition {
                reason: "inventory contains an unknown root directory",
            }),
        }
    })
}

fn entries(
    path: &Path,
    original: &DecodeBudget,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
    visitor: &mut EntryVisitor<'_>,
) -> Result<(), StoreError> {
    check()?;
    let _buffer_credit = original
        .reserve_scratch_bytes(CURSOR_BYTES as u64)
        .map_err(|error| batch::admission_under(original, error))?;
    let file = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| io_error("open-inventory-directory", source.into()))?;
    let mut buffer = [MaybeUninit::uninit(); CURSOR_BYTES];
    let mut cursor = RawDir::new(&file, &mut buffer);
    loop {
        check()?;
        let Some(entry) = cursor.next() else {
            return check();
        };
        let entry = entry.map_err(|source| io_error("read-inventory-directory", source.into()))?;
        check()?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| StoreError::InvalidComposition {
                reason: "inventory path component is not canonical UTF-8",
            })?;
        if matches!(name, "." | "..") {
            continue;
        }
        visitor(name, check)?;
        check()?;
    }
}

#[cfg(test)]
mod tests;
