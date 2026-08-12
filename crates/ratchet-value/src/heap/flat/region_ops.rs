//! Lexical-region operations for flat worker-domain object stores.
//!
//! Production closures use the downward-growing lane of the serial
//! Candidate-C reservation, while explicit-geometry and unsupported-platform
//! stores retain the owned chunked arena. Both backings preserve the same
//! drop-before-rewind and fail-loud stale-handle contract.

use super::*;

impl<T> FlatObjectStore<T> {
    /// Captures the current registry and rewindable backing position.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::SharedArenaRegionUnsupported`] for a
    /// permanent shared store whose low lane cannot be rewound.
    pub fn region_mark(&self) -> Result<FlatStoreRegionMark, FlatObjectError> {
        let backing = match &self.backing {
            FlatStoreBacking::Owned(arena) => FlatStoreBackingMark::Owned(arena.region_mark()),
            FlatStoreBacking::Rewindable { arena, .. } => FlatStoreBackingMark::Rewindable(
                arena.rewindable_mark().map_err(FlatObjectError::Arena)?,
            ),
            FlatStoreBacking::Shared(_) => {
                return Err(FlatObjectError::SharedArenaRegionUnsupported);
            }
        };
        Ok(FlatStoreRegionMark {
            entries: self.entries.len(),
            backing,
        })
    }

    /// Drops objects allocated after `mark` and rewinds their allocation lane.
    ///
    /// Payloads are dropped exactly once and their kind words are wiped before
    /// the backing cursor moves, so stale handles fail the flat-header check.
    /// The evaluator validates suffix reachability, marker ownership, epoch,
    /// and LIFO order before entering this store-level operation.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::SharedArenaRegionUnsupported`] for permanent
    /// shared stores, [`FlatObjectError::InvalidRegionMark`] for an impossible
    /// registry suffix, or [`FlatObjectError::Arena`] for a mismatched/stale
    /// backing marker. Every error is detected before payload destruction.
    pub fn pop_region(
        &mut self,
        mark: FlatStoreRegionMark,
    ) -> Result<FlatStorePopReport, FlatObjectError> {
        if mark.entries > self.entries.len() {
            return Err(FlatObjectError::InvalidRegionMark {
                marked_entries: mark.entries,
                current_entries: self.entries.len(),
            });
        }
        self.validate_backing_mark(mark.backing)?;
        let mut popped_entries = 0;
        for entry in self.entries[mark.entries..]
            .iter()
            .filter(|entry| entry.is_live())
        {
            // SAFETY: each registry entry names one live placement-written
            // `FlatObject<T>`. Truncation below prevents a second drop, and the
            // backing remains mapped until after this loop.
            unsafe { std::ptr::drop_in_place(entry.ptr.as_ptr() as *mut FlatObject<T>) };
            // SAFETY: the same exclusive live allocation remains writable;
            // zeroing its kind word makes a stale resolution fail loudly.
            unsafe { (entry.ptr.as_ptr() as *mut u64).write(0) };
            popped_entries += 1;
        }
        self.entries.truncate(mark.entries);
        let arena = self.pop_backing_to_mark(mark.backing)?;
        self.regions.clear();
        self.refresh_regions();
        Ok(FlatStorePopReport {
            popped_entries,
            arena,
        })
    }

    fn validate_backing_mark(&self, mark: FlatStoreBackingMark) -> Result<(), FlatObjectError> {
        match (&self.backing, mark) {
            (FlatStoreBacking::Owned(arena), FlatStoreBackingMark::Owned(mark)) => arena
                .validate_region_mark(mark)
                .map_err(FlatObjectError::Arena),
            (
                FlatStoreBacking::Rewindable { arena, .. },
                FlatStoreBackingMark::Rewindable(mark),
            ) => arena
                .validate_rewindable_mark(mark)
                .map_err(FlatObjectError::Arena),
            (FlatStoreBacking::Shared(_), _) => Err(FlatObjectError::SharedArenaRegionUnsupported),
            _ => Err(FlatObjectError::Arena(ArenaError::InvalidRegionMark)),
        }
    }

    fn pop_backing_to_mark(
        &mut self,
        mark: FlatStoreBackingMark,
    ) -> Result<ArenaRegionPopReport, FlatObjectError> {
        match (&mut self.backing, mark) {
            (FlatStoreBacking::Owned(arena), FlatStoreBackingMark::Owned(mark)) => {
                // SAFETY: validation succeeded before all suffix entries were
                // dropped and unregistered; the evaluator owns the reachability
                // proof for every address above the marker.
                unsafe { arena.pop_region_to_mark(mark) }.map_err(FlatObjectError::Arena)
            }
            (
                FlatStoreBacking::Rewindable { arena, .. },
                FlatStoreBackingMark::Rewindable(mark),
            ) => arena
                .pop_rewindable_to_mark(mark)
                .map_err(FlatObjectError::Arena),
            (FlatStoreBacking::Shared(_), _) => Err(FlatObjectError::SharedArenaRegionUnsupported),
            _ => Err(FlatObjectError::Arena(ArenaError::InvalidRegionMark)),
        }
    }
}
