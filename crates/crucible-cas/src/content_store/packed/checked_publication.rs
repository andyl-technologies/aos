//! Checked one-object packs, durable index transitions, and retained outcomes.

use super::*;
use crate::content_store::{PutBatchReceipt, batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

mod io;

/// Reports actual physical pack visibility and logical index durability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackedPublicationOutcome {
    /// Number of newly linked complete physical packs in this batch.
    pub published_packs: u8,
    /// Number of ordered inputs covered by a successful durable index result.
    pub durable_objects: u8,
    /// Indicates an unconfirmed conditional pack link or packs-directory sync.
    pub pack_visibility_uncertain: bool,
    /// Indicates an unconfirmed index rename or admin-directory sync.
    pub index_visibility_uncertain: bool,
    /// Indicates that a temporary name could not be synchronously removed.
    pub staging_cleanup_pending: bool,
}

/// Retains checked Packed work, cleanup, and actual publication evidence.
pub struct PackedScopeError {
    body: Option<Box<Failure>>,
    _credit: DecodeScratch,
}

struct Failure {
    first_boundary: Option<StoreError>,
    work: Option<StoreError>,
    cleanup: [Option<StoreError>; 2],
    outcome: PackedPublicationOutcome,
}

impl PackedScopeError {
    /// Borrows the first caller boundary refusal retained by this scope.
    #[must_use]
    pub fn first_boundary(&self) -> Option<&StoreError> {
        self.body
            .as_deref()
            .and_then(|body| body.first_boundary.as_ref())
    }

    /// Borrows the original work refusal while the complete scope stays owned.
    #[must_use]
    pub fn work_failure(&self) -> Option<&StoreError> {
        self.body.as_deref().and_then(|body| body.work.as_ref())
    }

    /// Borrows an independently failed synchronous staging cleanup.
    #[must_use]
    pub fn cleanup_failure(&self) -> Option<&StoreError> {
        self.body
            .as_deref()
            .and_then(|body| body.cleanup.iter().find_map(Option::as_ref))
    }

    /// Borrows both independently failed staging cleanup sites in effect order.
    pub fn cleanup_failures(&self) -> impl Iterator<Item = &StoreError> {
        self.body
            .iter()
            .flat_map(|body| body.cleanup.iter().filter_map(Option::as_ref))
    }

    /// Returns the observed physical and logical publication outcome.
    #[must_use]
    pub fn outcome(&self) -> PackedPublicationOutcome {
        self.body
            .as_deref()
            .map_or_else(PackedPublicationOutcome::default, |body| body.outcome)
    }
}

impl std::fmt::Debug for PackedScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackedScopeError")
            .field("first_boundary", &self.first_boundary())
            .field("work", &self.work_failure())
            .field("cleanup", &self.cleanup_failure())
            .field("outcome", &self.outcome())
            .finish()
    }
}

impl std::fmt::Display for PackedScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "checked Packed scope failed ({:?})",
            self.outcome()
        )
    }
}

impl std::error::Error for PackedScopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first_boundary()
            .or_else(|| self.work_failure())
            .or_else(|| self.cleanup_failure())
            .map(|error| error as _)
    }
}

impl Drop for PackedScopeError {
    fn drop(&mut self) {
        if let Some(boxed) = self.body.take() {
            // Move the payload out and free this prepaid Box before releasing
            // any nested cause's credits or the enclosing original credit.
            let body = *boxed;
            drop(body);
        }
    }
}

pub(in crate::content_store) struct Accepted<T> {
    value: T,
    outcome: PackedPublicationOutcome,
    credit: DecodeScratch,
}

impl<T> Accepted<T> {
    pub(in crate::content_store) fn value(&self) -> &T {
        &self.value
    }

    pub(in crate::content_store) fn release_diagnostic(&mut self) {
        // The fixed error reserve remains available for any later outer check.
        // No provider diagnostic allocation is retained on this healthy leaf.
    }

    pub(in crate::content_store) fn check(
        mut self,
        check: impl FnOnce(&mut T) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        match check(&mut self.value) {
            Ok(()) => Ok(self),
            Err(work) => {
                let Self {
                    value,
                    outcome,
                    credit,
                } = self;
                drop(value);
                Err(scope_error(None, Some(work), [None, None], outcome, credit))
            }
        }
    }
}

fn scope_error(
    first_boundary: Option<StoreError>,
    work: Option<StoreError>,
    cleanup: [Option<StoreError>; 2],
    outcome: PackedPublicationOutcome,
    credit: DecodeScratch,
) -> StoreError {
    StoreError::PackedScope {
        source: PackedScopeError {
            body: Some(Box::new(Failure {
                first_boundary,
                work,
                cleanup,
                outcome,
            })),
            _credit: credit,
        },
    }
}

#[derive(Default)]
struct Progress {
    cleanup_only: bool,
    outcome: PackedPublicationOutcome,
    cleanup: [Option<StoreError>; 2],
}

pub(super) fn publish(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    objects: &[(ContentId, BlobHandle)],
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<PutBatchReceipt, StoreError> {
    checked_reader::check(original, boundary)?;
    if objects.len() > 64 {
        return Err(StoreError::Quota);
    }
    let receipt_credit = batch::admit_receipts(original, objects.len(), backend.name.len())?;
    let credit = original
        .reserve_scratch_array::<Failure>(1)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut progress = Progress::default();
    let mut first_boundary = None;
    let mut retained_boundary = || {
        if first_boundary.is_some() {
            return Err(crate::content_store::composite_publication::refusal_marker());
        }
        match boundary() {
            Ok(()) => Ok(()),
            Err(error) => {
                first_boundary = Some(error);
                Err(crate::content_store::composite_publication::refusal_marker())
            }
        }
    };
    let boundary = &mut retained_boundary as &mut dyn FnMut() -> Result<(), StoreError>;
    let result = (|| {
        let _lifecycle = checked_io::lock(backend, LIFECYCLE_LOCK_FILE, true, original, boundary)?;
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(objects.len())
            .map_err(|error| batch::allocation_under(original, error))?;
        for (id, source) in objects {
            publish_one(backend, original, *id, source, &mut progress, boundary)?;
            let mut name = String::new();
            name.try_reserve_exact(backend.name.len())
                .map_err(|error| batch::allocation_under(original, error))?;
            name.push_str(&backend.name);
            let mut placements = Vec::new();
            placements
                .try_reserve_exact(1)
                .map_err(|error| batch::allocation_under(original, error))?;
            placements.push(PlacementReceipt {
                backend: name,
                durable: true,
                logical_length: source.logical_length(),
            });
            receipts.push(PutReceipt {
                id: *id,
                placements,
            });
            checked_reader::check(original, boundary)?;
        }
        Ok(receipts)
    })();
    match (first_boundary, result) {
        (None, Ok(receipts)) => Ok(PutBatchReceipt::new_packed(
            Accepted {
                value: receipts,
                outcome: progress.outcome,
                credit,
            },
            receipt_credit,
            original.clone(),
        )),
        (first_boundary, result) => {
            let work = match result {
                Ok(receipts) => {
                    drop(receipts);
                    None
                }
                Err(StoreError::CompositeBoundary { .. }) if first_boundary.is_some() => None,
                Err(_) if progress.cleanup_only => None,
                Err(work) => Some(work),
            };
            Err(scope_error(
                first_boundary,
                work,
                progress.cleanup,
                progress.outcome,
                credit,
            ))
        }
    }
}

fn publish_one(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    source: &BlobHandle,
    progress: &mut Progress,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    checked_reader::check(original, boundary)?;
    let _state = checked_io::lock(backend, STATE_LOCK_FILE, false, original, boundary)?;
    let index = index_snapshot::IndexSnapshot::load(backend, original, boundary)?;
    if let Some(entry) = index.find(backend, id, original, boundary)? {
        let existing = checked::open_entry(backend, original, id, entry, None, boundary)?;
        io::copy(original, id, &existing, None, boundary)?;
        io::copy(original, id, source, None, boundary)?;
        checked_io::sync_directory(&backend.admin, original, boundary)?;
        progress.outcome.durable_objects += 1;
        return checked_reader::check(original, boundary);
    }
    if index.header.count >= MAX_LOGICAL_OBJECTS {
        return Err(StoreError::Quota);
    }

    let manifest = io::Manifest::one(backend.configuration, id, source.logical_length(), original)?;
    let mut staging = io::Staging::new(&backend.packs, "pack", original, boundary)?;
    let work = (|| {
        io::write_all(staging.file(), manifest.bytes(), 0, original, boundary)?;
        io::copy(
            original,
            id,
            source,
            Some((staging.file(), manifest.entry.offset)),
            boundary,
        )?;
        io::sync(staging.file(), original, boundary)?;
        // Admit the complete replacement buffer while the authenticated old
        // snapshot remains owned, before any irreversible physical link.
        let replacement = index.inserted(
            backend,
            id,
            manifest.entry.to_index_entry(manifest.pack),
            original,
            boundary,
        )?;
        let target = io::pack_path(backend, manifest.pack, original)?;
        checked_reader::check(original, boundary)?;
        match fs::hard_link(staging.path(), target.as_path()) {
            Ok(()) => {
                progress.outcome.published_packs += 1;
                progress.outcome.pack_visibility_uncertain = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                io::compare(staging.file(), target.as_path(), original, boundary)?;
            }
            Err(source) => {
                progress.outcome.pack_visibility_uncertain = true;
                return Err(StoreError::StreamIo {
                    operation: "publish-packed-checked-pack",
                    source,
                });
            }
        }
        checked_reader::check(original, boundary)?;
        checked_io::sync_directory(&backend.packs, original, boundary)?;
        progress.outcome.pack_visibility_uncertain = false;
        publish_index(backend, original, &replacement, progress, boundary)?;
        progress.outcome.durable_objects += 1;
        checked_reader::check(original, boundary)
    })();
    let cleanup = staging.cleanup();
    record_cleanup(work, cleanup, progress)
}

fn publish_index(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    replacement: &index_snapshot::EncodedIndex,
    progress: &mut Progress,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut staging = io::Staging::new(&backend.admin, "index", original, boundary)?;
    let work = (|| {
        io::write_all(staging.file(), replacement.bytes(), 0, original, boundary)?;
        io::sync(staging.file(), original, boundary)?;
        let target = checked_io::path(&backend.admin, INDEX_FILE, original)?;
        checked_reader::check(original, boundary)?;
        progress.outcome.index_visibility_uncertain = true;
        fs::rename(staging.path(), target.as_path()).map_err(|source| StoreError::StreamIo {
            operation: "publish-packed-checked-index",
            source,
        })?;
        checked_reader::check(original, boundary)?;
        checked_io::sync_directory(&backend.admin, original, boundary)?;
        progress.outcome.index_visibility_uncertain = false;
        Ok(())
    })();
    // This checked entry returns the complete uncertain result immediately.
    // A caller can retry under its same still-live original; a callback refusal
    // never becomes success through a second host read or synchronization.
    let cleanup = staging.cleanup();
    record_cleanup(work, cleanup, progress)
}

fn record_cleanup(
    work: Result<(), StoreError>,
    cleanup: Result<(), StoreError>,
    progress: &mut Progress,
) -> Result<(), StoreError> {
    match (work, cleanup) {
        (work, Ok(())) => work,
        (work, Err(cleanup)) => {
            progress.outcome.staging_cleanup_pending = true;
            // One failing object has at most two staging names: its index
            // candidate then its pack candidate. Any refusal stops the batch
            // before the next object's staging, so both complete causes fit.
            let slot = if progress.cleanup[0].is_none() { 0 } else { 1 };
            progress.cleanup[slot] = Some(cleanup);
            if work.is_ok() {
                // This internal stop marker carries no cause. The scope selects
                // the retained cleanup itself when the work completed cleanly.
                progress.cleanup_only = true;
            }
            work.and(Err(StoreError::Unavailable))
        }
    }
}
