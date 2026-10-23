//! Retains controller-return snapshots in the launch's prepaid journal.
//!
//! The canonical progress owner takes this journal out of the launch before
//! observing publication or entering a provider. Receipts and erased causes
//! retain the independent finalizer, without a journal-to-launch ownership cycle.

use std::alloc::Layout;
use std::fmt;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};

use crucible_engine::BackendOperationalCause;
use crucible_host_resources::host_supervision::HostSupervisionError;

use super::RetainedCleanupFinalizer;

/// Preserves the immutable provider and boundary observations of a return.
#[derive(Clone, PartialEq, Eq)]
pub struct RamControlRetirementRecord {
    /// Exact first provider error, retained through later physical closure.
    pub first: Option<BackendOperationalCause>,
    /// First saved-original boundary refusal before the return.
    pub before: Option<HostSupervisionError>,
    /// Independent saved-original refusal after the returned disposition.
    pub after: Option<HostSupervisionError>,
    /// Whether an entered return lacks a physical disposition.
    pub uncertain: bool,
}

impl fmt::Debug for RamControlRetirementRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RamControlRetirementHistory")
            .field("first", &self.first)
            .field("before", &self.before)
            .field("after", &self.after)
            .field("uncertain", &self.uncertain)
            .finish()
    }
}

/// Retains one immutable controller-return snapshot and its original funding.
///
/// Field access borrows the saved observations through [`Deref`]. Cloning a
/// receipt allocates nothing and issues no operation or physical-return grant.
#[derive(Clone)]
pub struct RamControlRetirementHistory {
    journal: ControllerReturnJournal,
    index: NonZeroUsize,
}

impl RamControlRetirementHistory {
    pub(crate) const fn unavailable() -> Self {
        Self {
            journal: ControllerReturnJournal::empty(),
            index: NonZeroUsize::MIN,
        }
    }
}

impl Deref for RamControlRetirementHistory {
    type Target = RamControlRetirementRecord;

    fn deref(&self) -> &Self::Target {
        let Some(journal) = &self.journal.shared else {
            return &UNAVAILABLE;
        };
        match journal.records[self.index.get() - 1].get() {
            Some(record) => record,
            None => unreachable!("a controller receipt borrows its initialized prepaid record"),
        }
    }
}

impl fmt::Debug for RamControlRetirementHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(formatter)
    }
}

impl fmt::Display for RamControlRetirementHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RAM controller return refused: {self:?}")
    }
}

impl std::error::Error for RamControlRetirementHistory {}

impl PartialEq for RamControlRetirementHistory {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for RamControlRetirementHistory {}

static UNAVAILABLE: RamControlRetirementRecord = RamControlRetirementRecord {
    first: None,
    before: Some(HostSupervisionError::Unavailable),
    after: None,
    uncertain: false,
};

// First provider failure, pre, post and uncertainty each latch once. Including
// the initial record, five snapshots cover every monotonic state; eight slots
// leave bounded headroom. Only the exclusively claimed progress publishes.
const RETURN_SNAPSHOTS: usize = 8;

#[derive(Debug)]
struct JournalAllocation {
    records: [OnceLock<RamControlRetirementRecord>; RETURN_SNAPSHOTS],
    // Every record and error payload closes before this accounting observer.
    _finalizer: RetainedCleanupFinalizer,
}

#[derive(Clone, Debug)]
pub(crate) struct ControllerReturnJournal {
    shared: Option<Arc<JournalAllocation>>,
}

impl ControllerReturnJournal {
    pub(crate) const fn empty() -> Self {
        Self { shared: None }
    }

    pub(super) fn new(finalizer: RetainedCleanupFinalizer) -> Self {
        Self {
            shared: Some(Arc::new(JournalAllocation {
                records: std::array::from_fn(|_| OnceLock::new()),
                _finalizer: finalizer,
            })),
        }
    }

    pub(super) fn allocation_layout() -> Option<Layout> {
        let (allocation, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<JournalAllocation>())
            .ok()?;
        Some(allocation.pad_to_align())
    }

    pub(super) fn peak_bytes() -> Option<u64> {
        Self::allocation_layout()?
            .size()
            .checked_add(std::mem::size_of::<JournalAllocation>())?
            .checked_add(std::mem::size_of::<RamControlRetirementRecord>())?
            .checked_add(std::mem::size_of::<RamControlRetirementHistory>())?
            .checked_add(std::mem::size_of::<Self>())?
            .try_into()
            .ok()
    }

    pub(crate) fn snapshot(
        &self,
        record: &RamControlRetirementRecord,
    ) -> RamControlRetirementHistory {
        let Some(journal) = &self.shared else {
            unreachable!("only a launch's prepaid journal publishes controller observations");
        };
        for (index, slot) in journal.records.iter().enumerate() {
            if slot.get_or_init(|| record.clone()) == record {
                let Some(index) = NonZeroUsize::new(index + 1) else {
                    unreachable!("a bounded controller slot has a nonzero one-based index");
                };
                return RamControlRetirementHistory {
                    journal: self.clone(),
                    index,
                };
            }
        }
        unreachable!("the prepaid journal covers every monotonic return observation")
    }
}

impl Drop for ControllerReturnJournal {
    fn drop(&mut self) {
        if let Some(journal) = self.shared.take() {
            // No raw or Weak alias escapes. Free this actual header before the
            // moved records and independent finalizer can discharge accounting.
            drop(Arc::into_inner(journal));
        }
    }
}
