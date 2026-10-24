//! Checks prepaid return causes and final accounting through actual frees.
//!
//! The paired accounts fund component metadata; these checks issue no Main,
//! native Source, process-disposition receipt or execution permission.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use std::alloc::Layout;
use std::error::Error;

fn shared_layout<T>() -> Layout {
    Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<T>())
        .unwrap_or_else(|cause| panic!("component control layout must be representable: {cause}"))
        .0
        .pad_to_align()
}

#[test]
fn erased_controller_cause_keeps_paired_credit_through_every_control_free() {
    for layout in [
        shared_layout::<CleanupRecord>(),
        shared_layout::<ControllerReturnCause>(),
        shared_layout::<CleanupFinalizer>(),
        ControllerReturnJournal::allocation_layout().unwrap(),
    ] {
        let allocation::Fixture {
            cleanup,
            accounts,
            bytes,
            allocation,
        } = allocation::fixture_observing(layout);
        let mut progress = crate::ram_control::RamControlRetirementProgress::new();
        assert!(progress.bind(&cleanup));
        let ((returned, status), counts) = TestAllocationObserver::count(|| {
            progress.refuse_publication(RamControlError::AuthorityMismatch)
        });
        assert!(!returned);
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let history = status.unwrap_err();
        let cause = history.first.as_ref().unwrap().clone();
        drop(history);

        let (_, observations) = TestAllocationObserver::observe_controls(
            [&accounts[0], &accounts[1]],
            None,
            [Some(allocation), None, None],
            || {
                drop(progress);
                drop(cleanup);
                for account in &accounts {
                    assert!(account.reserve_resources(0, 0, 1).is_err());
                }
                drop(cause);
            },
        );

        let observed = observations[0].unwrap();
        assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
        for account in &accounts {
            drop(account.reserve_resources(0, 0, bytes).unwrap());
        }
    }
}

#[test]
fn publication_refusal_keeps_the_same_first_typed_provider_error_without_allocation() {
    let allocation::Fixture { cleanup, .. } = allocation::fixture();
    let mut progress = crate::ram_control::RamControlRetirementProgress::new();
    assert!(progress.bind(&cleanup));
    let (_, status) = progress.refuse_publication(RamControlError::Io(
        std::io::Error::from_raw_os_error(libc::EPIPE),
    ));
    let first = status.unwrap_err();
    let cause = first.first.as_ref().unwrap();
    let provider = cause
        .source()
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<RamControlError>())
        .unwrap();
    let RamControlError::Io(native) = provider else {
        panic!("typed provider error is retained");
    };
    assert_eq!(native.raw_os_error(), Some(libc::EPIPE));
    let pointer = provider as *const RamControlError;

    let ((returned, status), counts) = TestAllocationObserver::count(|| {
        progress.refuse_publication(RamControlError::AuthorityMismatch)
    });

    assert!(!returned);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let repeated = status.unwrap_err();
    assert_eq!(repeated, first);
    let provider = repeated
        .first
        .as_ref()
        .unwrap()
        .source()
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<RamControlError>())
        .unwrap();
    assert_eq!(provider as *const RamControlError, pointer);
}

#[derive(Debug)]
struct RetainedLaunchError {
    _cleanup: LaunchCleanup,
    dropped: Arc<AtomicBool>,
}

impl std::fmt::Display for RetainedLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("component provider retains its existing launch")
    }
}

impl Error for RetainedLaunchError {}

impl Drop for RetainedLaunchError {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[test]
fn returned_error_may_retain_the_actual_launch_without_forming_a_custody_cycle() {
    let allocation::Fixture {
        cleanup,
        accounts,
        bytes,
        ..
    } = allocation::fixture();
    let mut progress = crate::ram_control::RamControlRetirementProgress::new();
    assert!(progress.bind(&cleanup));
    // This distinct, existing component loan covers the custom io payload.
    // Keep it outside that payload until its complete enclosing error is freed.
    let payload_account = HostServiceAllocator::new(1, 1, 1024).unwrap();
    let payload_loan = payload_account.reserve_resources(0, 0, 1024).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let provider = RamControlError::Io(std::io::Error::other(RetainedLaunchError {
        _cleanup: cleanup.clone(),
        dropped: dropped.clone(),
    }));

    let ((_, status), counts) =
        TestAllocationObserver::count(|| progress.refuse_publication(provider));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let history = status.unwrap_err();
    let first = history.first.clone().unwrap();
    drop(progress);
    drop(cleanup);
    assert!(!dropped.load(Ordering::Acquire));
    for account in &accounts {
        assert!(account.reserve_resources(0, 0, 1).is_err());
    }

    drop(history);
    assert!(!dropped.load(Ordering::Acquire));
    drop(first);

    assert!(dropped.load(Ordering::Acquire));
    for account in &accounts {
        drop(account.reserve_resources(0, 0, bytes).unwrap());
    }
    drop(payload_loan);
}

#[test]
fn optional_controller_receipts_fit_their_prepaid_extent() {
    use crate::ram_control::RamControlRetirementHistory;

    assert_eq!(
        std::mem::size_of::<Option<RamControlRetirementHistory>>(),
        std::mem::size_of::<RamControlRetirementHistory>(),
    );
    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(std::mem::size_of::<RamControlRetirementHistory>(), 16);
        assert_eq!(
            std::mem::size_of::<[Option<RamControlRetirementHistory>; 2]>(),
            32
        );
    }
}

#[test]
fn every_prepaid_controller_slot_is_immutable_and_keeps_its_original_funding() {
    use crate::ram_control::{RamControlRetirementHistory, RamControlRetirementRecord};
    use crucible_host_resources::host_supervision::HostSupervisionError;

    let allocation::Fixture {
        cleanup,
        accounts,
        bytes,
        allocation,
    } = allocation::fixture_observing(ControllerReturnJournal::allocation_layout().unwrap());
    let storage = cleanup.claim_controller_return().unwrap();
    let journal = storage.journal;
    drop(storage.cause);

    // Exercise each finite storage offset with component observations only.
    // These bit patterns issue no operation or physical-return receipt.
    let receipts: [RamControlRetirementHistory; 8] = std::array::from_fn(|slot| {
        let record = RamControlRetirementRecord {
            first: None,
            before: (slot & 1 != 0).then_some(HostSupervisionError::Unavailable),
            after: (slot & 2 != 0).then_some(HostSupervisionError::Unavailable),
            uncertain: slot & 4 != 0,
        };
        let ((receipt, repeated), counts) = TestAllocationObserver::count(|| {
            (journal.snapshot(&record), journal.snapshot(&record))
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(*receipt, record);
        assert_eq!(receipt, repeated);
        receipt
    });

    drop(journal);
    drop(cleanup);
    for (slot, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.before.is_some(), slot & 1 != 0);
        assert_eq!(receipt.after.is_some(), slot & 2 != 0);
        assert_eq!(receipt.uncertain, slot & 4 != 0);
    }
    for account in &accounts {
        assert!(account.reserve_resources(0, 0, 1).is_err());
    }

    let (_, observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        [Some(allocation), None, None],
        || drop(receipts),
    );

    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    for account in &accounts {
        drop(account.reserve_resources(0, 0, bytes).unwrap());
    }
}
