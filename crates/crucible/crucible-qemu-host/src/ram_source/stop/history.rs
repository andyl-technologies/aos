//! Retains immutable Source return snapshots in prepaid storage.
//!
//! Every receipt borrows an initialized record in the same finite journal. The
//! last alias frees the journal header before closing records and the original
//! worker loan; cloning and publishing a receipt allocate nothing.

use super::*;
use crucible_engine::SharedOperationalCause;
use crucible_host_resources::host_services::HostServiceLease;
use std::fmt;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::OnceLock;

/// Preserves one immutable snapshot of a Source's actual return observations.
#[derive(Clone, PartialEq, Eq)]
pub struct QemuRamSourceStopRecord {
    /// Same actual creation Original's independent pre/post observations.
    pub birth: (Option<HostSupervisionError>, Option<HostSupervisionError>),
    /// First actual cancellation transport failure.
    pub cancellation: Option<BackendOperationalCause>,
    /// First same-original failures around cancellation, waiting, and joining.
    pub observations: [(Option<HostSupervisionError>, Option<HostSupervisionError>); 3],
    /// The original failure returned by the actual joined worker.
    pub worker: Option<QemuRamWorkerFailure>,
    /// Actual caught panic payload and original loan, retained after body removal.
    pub panic: Option<QemuRamWorkerPanic>,
    /// First unexpected actual native join result, independent of Original status.
    pub native: Option<NativeJoinError>,
    /// Latest attempted libc status, including known busy or physical zero.
    pub native_status: Option<i32>,
    /// Whether an entered cancellation or join has no returned disposition.
    pub uncertain: bool,
}

impl fmt::Debug for QemuRamSourceStopRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuRamSourceStopHistory")
            .field("birth", &self.birth)
            .field("cancellation", &self.cancellation)
            .field("observations", &self.observations)
            .field("worker", &self.worker)
            .field("panic", &self.panic)
            .field("native", &self.native)
            .field("native_status", &self.native_status)
            .field("uncertain", &self.uncertain)
            .finish()
    }
}

/// Retains one immutable Source return snapshot and its original storage charge.
///
/// Field access borrows the recorded observations through [`Deref`]. Sharing a
/// receipt creates no new snapshot, native join, operation or execution grant.
#[derive(Clone)]
pub struct QemuRamSourceStopHistory {
    journal: StopJournal,
    // One-based slots keep optional receipts within the same prepaid extent.
    index: NonZeroUsize,
}

impl Deref for QemuRamSourceStopHistory {
    type Target = QemuRamSourceStopRecord;

    fn deref(&self) -> &Self::Target {
        match self
            .journal
            .shared
            .as_ref()
            .and_then(|journal| journal.records[self.index.get() - 1].get())
        {
            Some(record) => record,
            None => unreachable!("a stop receipt borrows only its initialized prepaid record"),
        }
    }
}

impl fmt::Debug for QemuRamSourceStopHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(formatter)
    }
}

impl fmt::Display for QemuRamSourceStopHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RAM source return refused: {self:?}")
    }
}

impl std::error::Error for QemuRamSourceStopHistory {}

impl PartialEq for QemuRamSourceStopHistory {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for QemuRamSourceStopHistory {}

// Birth changes once; six Original observations and cancellation, worker,
// panic, native refusal and uncertainty each fill once. The latched native
// owner adds at most busy followed by zero or one unexpected status. Including
// the initial snapshot, this admits at most fifteen distinct records. Only the
// exclusively borrowed Source publishes; receipt aliases cannot change records.
const STOP_SNAPSHOTS: usize = 16;

// The same prebirth loan funds this separate shared cause. An erased observer
// may outlive the stop journal, so the cause retains its own alias of that loan.
#[derive(Debug)]
struct CancellationCause {
    first: OnceLock<std::io::Error>,
    _lease: HostServiceLease,
}

impl fmt::Display for CancellationCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.first.get() {
            Some(first) => first.fmt(formatter),
            None => formatter.write_str("Source cancellation has no returned failure"),
        }
    }
}

impl std::error::Error for CancellationCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first
            .get()
            .map(|first| first as &dyn std::error::Error)
    }
}

#[derive(Debug)]
struct StopJournalAllocation {
    records: [OnceLock<QemuRamSourceStopRecord>; STOP_SNAPSHOTS],
    cancellation: SharedOperationalCause<CancellationCause>,
    // Snapshot payloads close before the original charge is returned.
    _lease: HostServiceLease,
}

#[derive(Clone, Debug)]
pub(super) struct StopJournal {
    shared: Option<Arc<StopJournalAllocation>>,
}

impl StopJournal {
    pub(super) const fn empty() -> Self {
        Self { shared: None }
    }

    pub(super) fn new(lease: HostServiceLease) -> Self {
        let cancellation = SharedOperationalCause::new(CancellationCause {
            first: OnceLock::new(),
            _lease: lease.clone(),
        });
        Self {
            shared: Some(Arc::new(StopJournalAllocation {
                records: std::array::from_fn(|_| OnceLock::new()),
                cancellation,
                _lease: lease,
            })),
        }
    }

    pub(super) fn peak_bytes() -> Option<u64> {
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<StopJournalAllocation>())
            .ok()?;
        u64::try_from(layout.pad_to_align().size())
            .ok()?
            .checked_add(std::mem::size_of::<StopJournalAllocation>() as u64)?
            .checked_add(std::mem::size_of::<QemuRamSourceStopRecord>() as u64)?
            .checked_add(std::mem::size_of::<QemuRamSourceStopHistory>() as u64)?
            .checked_add(std::mem::size_of::<Self>() as u64)?
            .checked_add(
                u64::try_from(
                    SharedOperationalCause::<CancellationCause>::allocation_bytes().ok()?,
                )
                .ok()?,
            )?
            .checked_add(std::mem::size_of::<CancellationCause>() as u64)?
            .checked_add(std::mem::size_of::<SharedOperationalCause<CancellationCause>>() as u64)
    }

    /// Publishes the original syscall failure from its prepaid shared body.
    pub(super) fn cancellation_failure(&self, first: std::io::Error) -> BackendOperationalCause {
        let Some(journal) = self.shared.as_ref() else {
            unreachable!("only a funded Source can publish cancellation failure");
        };
        journal
            .cancellation
            .source_ref()
            .first
            .get_or_init(|| first);
        journal.cancellation.backend_cause()
    }

    pub(super) fn snapshot(&self, record: &QemuRamSourceStopRecord) -> QemuRamSourceStopHistory {
        let Some(journal) = self.shared.as_ref() else {
            unreachable!("only a funded Source can publish stop observations");
        };
        for (index, slot) in journal.records.iter().enumerate() {
            if slot.get_or_init(|| record.clone()) == record {
                // The finite journal has sixteen slots, so this addition is
                // bounded and every published receipt has a nonzero index.
                let Some(index) = NonZeroUsize::new(index + 1) else {
                    unreachable!("a prepaid stop slot has a nonzero one-based index");
                };
                return QemuRamSourceStopHistory {
                    journal: self.clone(),
                    index,
                };
            }
        }
        unreachable!("the prepaid stop journal covers every monotonic observation")
    }
}

impl Drop for StopJournal {
    fn drop(&mut self) {
        if let Some(journal) = self.shared.take() {
            // No Weak alias escapes. The actual header closes before the moved
            // records, their payload aliases and this same original loan.
            drop(Arc::into_inner(journal));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceError};
    use crucible_host_resources::host_supervision::{
        HostOperationBudget, HostOperationBudgets, HostOperationSupervisor,
    };
    use crucible_host_resources::test_support::TestAllocationObserver;

    #[test]
    fn optional_stop_receipts_fit_their_existing_prepaid_extent() {
        assert_eq!(
            std::mem::size_of::<Option<QemuRamSourceStopHistory>>(),
            std::mem::size_of::<QemuRamSourceStopHistory>(),
        );
        #[cfg(target_pointer_width = "64")]
        assert_eq!(std::mem::size_of::<QemuRamSourceStopHistory>(), 16);
    }

    #[test]
    fn every_prepaid_slot_borrows_its_own_immutable_record_without_allocating() {
        let bytes = StopJournal::peak_bytes().unwrap();
        let account = HostServiceAllocator::new(1, 1, bytes).unwrap();
        let loan = account.reserve_resources(0, 0, bytes).unwrap();
        let journal = StopJournal::new(loan);
        let mut record = StopState::new().history;

        // These are component observations, not native status or return grants.
        // Exercise the first and final one-based offsets in the actual journal.
        for slot in 0..STOP_SNAPSHOTS {
            record.native_status = Some(i32::try_from(slot).unwrap());
            let ((receipt, repeated), counts) = TestAllocationObserver::count(|| {
                (journal.snapshot(&record), journal.snapshot(&record))
            });

            assert_eq!(counts.allocations, 0);
            assert_eq!(counts.reallocations, 0);
            assert!(!counts.overflow);
            assert_eq!(*receipt, record);
            assert!(std::ptr::eq(&*receipt, &*repeated));
        }
    }

    #[test]
    fn immutable_stop_receipts_keep_original_credit_through_actual_header_free() {
        let bytes = StopJournal::peak_bytes().unwrap();
        let account = HostServiceAllocator::new(1, 1, bytes).unwrap();
        let loan = account.reserve_resources(0, 0, bytes).unwrap();
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<StopJournalAllocation>())
            .unwrap();
        let (journal, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout.pad_to_align(), || {
                StopJournal::new(loan)
            });
        assert_eq!(counts.allocations, 2);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);

        // This component records an actual expired Cleanup. It supplies no
        // Main purpose, worker birth, native join or physical-return receipt.
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Cleanup).unwrap();
        let (revision, mut budgets) = supervisor.budgets().unwrap();
        budgets.classes[HostOperationClass::Cleanup as usize] =
            HostOperationBudget::finite(Duration::from_nanos(1));
        supervisor.update_budgets(revision, budgets).unwrap();
        thread::sleep(Duration::from_millis(1));
        let mut record = StopState::new().history;
        record.observations[0].0 = Some(original.wait_slice().unwrap_err());
        let ((first, alias), counts) = TestAllocationObserver::count(|| {
            let first = journal.snapshot(&record);
            let alias = first.clone();
            (first, alias)
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(std::ptr::eq(&*first, &*alias));

        record.observations[0].1 = Some(original.wait_slice().unwrap_err());
        let ((later, repeated), counts) = TestAllocationObserver::count(|| {
            (journal.snapshot(&record), journal.snapshot(&record))
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(std::ptr::eq(&*later, &*repeated));
        assert!(first.observations[0].1.is_none());
        assert!(later.observations[0].1.is_some());
        drop(journal);
        drop(first);
        drop(later);
        drop(repeated);
        assert!(matches!(
            account.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));

        // Both observer channels inspect this same component account.
        let (_, observations) = TestAllocationObserver::observe_controls(
            [&account, &account],
            None,
            [identity, None, None],
            || drop(alias),
        );
        let observed = observations[0].unwrap();
        assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
        let _whole = account.reserve_resources(0, 0, bytes).unwrap();
    }

    #[test]
    fn cancellation_observers_keep_prepaid_cause_through_actual_header_free() {
        use std::error::Error;

        let bytes = StopJournal::peak_bytes().unwrap();
        let account = HostServiceAllocator::new(1, 1, bytes).unwrap();
        let loan = account.reserve_resources(0, 0, bytes).unwrap();
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<CancellationCause>())
            .unwrap();
        let (journal, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout.pad_to_align(), || {
                StopJournal::new(loan)
            });
        assert_eq!(counts.allocations, 2);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);

        let first = std::io::Error::from_raw_os_error(libc::EPIPE);
        let ((cause, alias, receipt), counts) = TestAllocationObserver::count(|| {
            let cause = journal.cancellation_failure(first);
            let alias = cause.clone();
            let mut record = StopState::new().history;
            record.cancellation = Some(cause.clone());
            (cause, alias, journal.snapshot(&record))
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(cause, alias);
        assert_eq!(receipt.cancellation.as_ref(), Some(&cause));
        let original = cause
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(original.raw_os_error(), Some(libc::EPIPE));
        let original_identity = std::ptr::from_ref(original);

        // A repeated observation retains the first actual returned error. It
        // creates neither another error body nor another service reservation.
        let (repeated, counts) = TestAllocationObserver::count(|| {
            journal.cancellation_failure(std::io::Error::from_raw_os_error(libc::EINVAL))
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(repeated, cause);
        assert_eq!(
            std::ptr::from_ref(
                repeated
                    .source()
                    .unwrap()
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
            ),
            original_identity,
        );

        drop(receipt);
        drop(journal);
        drop(cause);
        drop(repeated);
        assert!(matches!(
            account.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));

        let (_, observations) = TestAllocationObserver::observe_controls(
            [&account, &account],
            None,
            [identity, None, None],
            || drop(alias),
        );
        let observed = observations[0].unwrap();
        assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
        let _whole = account.reserve_resources(0, 0, bytes).unwrap();
    }
}
