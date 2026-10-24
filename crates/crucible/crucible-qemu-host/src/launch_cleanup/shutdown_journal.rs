//! Retains shutdown outputs in the launch's prepaid immutable cells.
//!
//! Actual errors move into their one-shot cells. Reports borrow selected cells
//! through frozen masks, so later progress cannot alter an earlier receipt.
//! The canonical shutdown owner takes the journal out of the launch before
//! effects; final observers free the shared header before accounting closes.

use std::alloc::Layout;
use std::fmt;
use std::ops::{Deref, Index};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};

use super::RetainedCleanupFinalizer;
use crate::shutdown::{
    QemuShutdownAttempt, QemuShutdownFailure, QemuShutdownReport, QemuShutdownTargetError,
};

const ATTEMPTS: usize = 4;
const FAILURES: usize = 6;

#[derive(Debug)]
struct JournalAllocation {
    attempts: [OnceLock<QemuShutdownAttempt>; ATTEMPTS],
    failures: [OnceLock<QemuShutdownFailure>; FAILURES],
    // Every retained output and its physical allocation closes before this loan.
    _finalizer: Option<RetainedCleanupFinalizer>,
}

#[derive(Clone, Debug)]
pub(crate) struct ShutdownJournal {
    shared: Option<Arc<JournalAllocation>>,
}

impl ShutdownJournal {
    pub(crate) const fn empty() -> Self {
        Self { shared: None }
    }

    pub(super) fn new(finalizer: RetainedCleanupFinalizer) -> Self {
        Self::allocate(Some(finalizer))
    }

    /// Creates only standalone, unissued component storage before its effects.
    pub(crate) fn component() -> Self {
        Self::allocate(None)
    }

    fn allocate(finalizer: Option<RetainedCleanupFinalizer>) -> Self {
        Self {
            shared: Some(Arc::new(JournalAllocation {
                attempts: std::array::from_fn(|_| OnceLock::new()),
                failures: std::array::from_fn(|_| OnceLock::new()),
                _finalizer: finalizer,
            })),
        }
    }

    fn allocation_layout() -> Option<Layout> {
        let (allocation, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<JournalAllocation>())
            .ok()?;
        Some(allocation.pad_to_align())
    }

    pub(super) fn peak_bytes() -> Option<u64> {
        Self::allocation_layout()?
            .size()
            .checked_add(std::mem::size_of::<JournalAllocation>())?
            .checked_add(std::mem::size_of::<QemuShutdownFailure>())?
            .checked_add(std::mem::size_of::<QemuShutdownReport>())?
            .checked_add(std::mem::size_of::<Self>())?
            .try_into()
            .ok()
    }

    pub(crate) fn available(&self) -> bool {
        self.shared.is_some()
    }

    fn attempts(&self) -> &[OnceLock<QemuShutdownAttempt>; ATTEMPTS] {
        static EMPTY: [OnceLock<QemuShutdownAttempt>; ATTEMPTS] =
            [const { OnceLock::new() }; ATTEMPTS];
        self.shared.as_ref().map_or(&EMPTY, |body| &body.attempts)
    }

    fn failures(&self) -> &[OnceLock<QemuShutdownFailure>; FAILURES] {
        static EMPTY: [OnceLock<QemuShutdownFailure>; FAILURES] =
            [const { OnceLock::new() }; FAILURES];
        self.shared.as_ref().map_or(&EMPTY, |body| &body.failures)
    }

    pub(crate) fn attempt(&self, index: usize) -> Option<&QemuShutdownAttempt> {
        self.attempts().get(index).and_then(OnceLock::get)
    }

    pub(crate) fn failure(&self, index: usize) -> Option<&QemuShutdownFailure> {
        self.failures().get(index).and_then(OnceLock::get)
    }

    pub(crate) fn record_attempt(&self, index: usize, output: QemuShutdownAttempt) {
        assert!(
            self.available(),
            "shutdown outputs require admitted storage"
        );
        assert!(
            self.attempts()[index].set(output).is_ok(),
            "each shutdown rung publishes its actual output once"
        );
    }

    pub(crate) fn record_failure(&self, index: usize, output: QemuShutdownFailure) {
        assert!(
            self.available(),
            "shutdown failures require admitted storage"
        );
        assert!(
            self.failures()[index].set(output).is_ok(),
            "each shutdown refusal retains its actual error once"
        );
    }

    pub(crate) fn refusal(&self, index: usize) -> Option<QemuShutdownRefusal> {
        self.failure(index)?;
        Some(QemuShutdownRefusal {
            journal: self.clone(),
            index,
        })
    }

    pub(crate) fn report(&self, reaped: bool, leaked: bool) -> QemuShutdownReport {
        let attempts = self
            .attempts()
            .iter()
            .enumerate()
            .fold(0, |mask, (index, cell)| {
                mask | (u8::from(cell.get().is_some()) << index)
            });
        let failures = self
            .failures()
            .iter()
            .enumerate()
            .fold(0, |mask, (index, cell)| {
                mask | (u8::from(cell.get().is_some()) << index)
            });

        QemuShutdownReport {
            attempts: QemuShutdownAttempts {
                journal: self.clone(),
                mask: attempts,
            },
            failures: QemuShutdownFailures {
                journal: self.clone(),
                mask: failures,
            },
            reaped,
            leaked,
        }
    }
}

impl Drop for ShutdownJournal {
    fn drop(&mut self) {
        if let Some(journal) = self.shared.take() {
            // No Weak or raw aliases escape. This actual header closes before
            // moved errors and the independent finalizer discharge accounting.
            drop(Arc::into_inner(journal));
        }
    }
}

/// Borrows the actual attempted rungs visible when a report was published.
///
/// Clones retain the same prepaid cells without allocating. Later progress
/// cannot add entries to an already published collection.
#[derive(Clone)]
pub struct QemuShutdownAttempts {
    journal: ShutdownJournal,
    mask: u8,
}

impl QemuShutdownAttempts {
    pub(crate) const fn empty() -> Self {
        Self {
            journal: ShutdownJournal::empty(),
            mask: 0,
        }
    }

    /// Returns the number of recorded rungs in this receipt.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mask.count_ones() as usize
    }

    /// Returns whether this receipt contains no recorded rungs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mask == 0
    }

    /// Iterates over the actual recorded rungs in escalation order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &QemuShutdownAttempt> {
        self.journal
            .attempts()
            .iter()
            .enumerate()
            .filter_map(|(index, cell)| {
                (self.mask & (1 << index) != 0)
                    .then(|| cell.get())
                    .flatten()
            })
    }
}

impl Index<usize> for QemuShutdownAttempts {
    type Output = QemuShutdownAttempt;

    fn index(&self, index: usize) -> &Self::Output {
        match self.iter().nth(index) {
            Some(output) => output,
            None => panic!("shutdown attempt index out of bounds"),
        }
    }
}

impl fmt::Debug for QemuShutdownAttempts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl PartialEq for QemuShutdownAttempts {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for QemuShutdownAttempts {}

/// Borrows the actual failures visible when a shutdown report was published.
///
/// The immutable selection preserves original errors and their string storage;
/// reporting and cloning never copy an owned diagnostic.
#[derive(Clone)]
pub struct QemuShutdownFailures {
    journal: ShutdownJournal,
    mask: u8,
}

impl QemuShutdownFailures {
    pub(crate) const fn empty() -> Self {
        Self {
            journal: ShutdownJournal::empty(),
            mask: 0,
        }
    }

    /// Returns the number of retained failures in this receipt.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mask.count_ones() as usize
    }

    /// Returns whether this receipt contains no retained failures.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mask == 0
    }

    /// Iterates over actual refusals in their original rung order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &QemuShutdownFailure> {
        self.journal
            .failures()
            .iter()
            .enumerate()
            .filter_map(|(index, cell)| {
                (self.mask & (1 << index) != 0)
                    .then(|| cell.get())
                    .flatten()
            })
    }
}

impl Index<usize> for QemuShutdownFailures {
    type Output = QemuShutdownFailure;

    fn index(&self, index: usize) -> &Self::Output {
        match self.iter().nth(index) {
            Some(output) => output,
            None => panic!("shutdown failure index out of bounds"),
        }
    }
}

impl fmt::Debug for QemuShutdownFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl PartialEq for QemuShutdownFailures {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for QemuShutdownFailures {}

/// Retains the original typed target refusal in its launch's prepaid cell.
///
/// Cloning shares the existing allocation. Field access borrows the actual
/// [`QemuShutdownTargetError`] through [`Deref`].
#[derive(Clone)]
pub struct QemuShutdownRefusal {
    journal: ShutdownJournal,
    index: usize,
}

impl Deref for QemuShutdownRefusal {
    type Target = QemuShutdownTargetError;

    fn deref(&self) -> &Self::Target {
        match self.journal.failure(self.index) {
            Some(output) => &output.source,
            None => unreachable!("a shutdown refusal borrows its initialized original cell"),
        }
    }
}

impl fmt::Debug for QemuShutdownRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(formatter)
    }
}

impl fmt::Display for QemuShutdownRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.deref(), formatter)
    }
}

impl std::error::Error for QemuShutdownRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.deref())
    }
}

impl PartialEq for QemuShutdownRefusal {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for QemuShutdownRefusal {}

#[cfg(test)]
mod tests;
