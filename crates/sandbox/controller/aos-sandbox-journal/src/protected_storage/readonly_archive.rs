//! Shares finite readonly-name observation custody without role admission.
//!
//! The enclosing role selects and prepays its fixed path and roster. This
//! adapter invokes the existing physical name engine once per reached slot;
//! an indexed refusal identifies the same retained native failure. It cannot
//! authenticate a role, create a ledger, reset debt or retire a failed sample.

use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{ReadOnlyJournalNamesOriginalsV1, ProtectedFailure,
    MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES};

/// Describes checked native roster storage without a financial dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadonlyNameArchiveGeometryV1 {
    /// Bounds the actual archive and rooted observation byte representations.
    pub memory_bytes: u64,
    /// Bounds simultaneously retained rooted ancestors and opened names.
    pub open_files: u64,
    /// Bounds the same retained path and name namespace entries.
    pub namespace_entries: u64,
}

/// Retains the existing six-slot native roster and monotone cursor.
pub struct ReadonlyNameArchiveV1<E> {
    observations: [ReadOnlyJournalNamesOriginalsV1<E>; 6],
    limit: usize,
    next: AtomicUsize,
    observing: AtomicBool,
}

impl<E> ReadonlyNameArchiveV1<E> {
    /// Creates at most six empty native slots without IO or financial authority.
    pub fn new(limit: usize) -> Self {
        Self {
            observations: std::array::from_fn(|_| ReadOnlyJournalNamesOriginalsV1::new()),
            limit,
            next: AtomicUsize::new(0),
            observing: AtomicBool::new(false),
        }
    }

    /// Reports how many actual slots were entered, including failed samples.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.next.load(Ordering::Acquire)
    }

}

impl<E: ProtectedFailure> ReadonlyNameArchiveV1<E> {
    /// Runs the next actual name sample and returns its indexed refusal.
    ///
    /// # Errors
    /// Returns the failed native slot, or255 on overlap/exhaustion; every
    /// reached native file/error stays owned in that exact slot.
    pub fn observe(
        &self,
        witness: &super::ReadOnlyJournalNameWitness,
        held_file: &File,
    ) -> Result<(), u8> {
        // Reserve the fixed slot before any native observation. Concurrent or
        // recursive entry cannot start another name walker or replace debt.
        if self.observing.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(u8::MAX);
        }
        let index = self.next.load(Ordering::Acquire);
        if index >= self.limit || index >= self.observations.len() {
            self.observing.store(false, Ordering::Release);
            return Err(u8::MAX);
        }
        self.next.store(index + 1, Ordering::Release);
        let observation = &self.observations[index];
        observation.capture_once(witness, held_file);
        let result = if observation.is_complete() {
            Ok(())
        } else {
            Err(index as u8)
        };
        self.observing.store(false, Ordering::Release);
        result
    }

    /// Borrows the actual selected native failure without resampling.
    pub fn failure_at(&self, index: u8) -> Option<&E> {
        self.observations.get(usize::from(index))?.failure()
    }

    /// Reports the same bounded rooted roster's dominant bytes and names.
    ///
    /// The path and count are comparison DATA, never a receiving allowance.
    /// Returns None on checked geometry overflow.
    pub fn receiving_geometry_v1(observations: usize, path: &str) -> Option<ReadonlyNameArchiveGeometryV1> {
        let anchors = std::path::Path::new(path).components()
            .filter(|component| matches!(component, std::path::Component::Normal(_))).count()
            .checked_add(1)?;
        // The rooted resolver keeps all reached ancestors, its final directory,
        // and both fresh names. Three backing widths cover Vec growth/realloc;
        // bounded basename/error controls coexist with every whole result slot.
        let files = anchors.checked_add(2)?.checked_mul(observations)?;
        let per_observation = anchors.checked_mul(3 * std::mem::size_of::<File>())
            .and_then(|n| n.checked_add(3 * (MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES + 5)))
            .and_then(|n| n.checked_add(16 * 256))?;
        let memory = per_observation.checked_mul(observations)
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))?;
        let metadata = anchors.checked_mul(4).and_then(|n| n.checked_add(11))
            .and_then(|n| n.checked_mul(observations))?;
        Some(ReadonlyNameArchiveGeometryV1 {
            memory_bytes: u64::try_from(memory).ok()?,
            open_files: u64::try_from(files).ok()?,
            namespace_entries: u64::try_from(metadata).ok()?,
        })
    }
}
