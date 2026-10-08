//! Exercises fixed global allocation capture and original before-free markers.

#![cfg(feature = "test-support")]
// crucible-lint: allow panic-shortcut -- fixtures isolate physical allocation-close and original marker-order failures.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_linux_resource::test_support::{
    AllocationRosterOutcome, AllocationRosterSetupError, BeforeFreeMarkerOutcome,
    CloseMarkerSetupError, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static ORIGINAL_CLOSED: AtomicBool = AtomicBool::new(false);

struct OriginalCredit;

impl Drop for OriginalCredit {
    fn drop(&mut self) {
        ORIGINAL_CLOSED.store(true, Ordering::SeqCst);
    }
}

struct OrdinaryPayload([u8; 64]);

impl Drop for OrdinaryPayload {
    fn drop(&mut self) {
        ORIGINAL_CLOSED.store(true, Ordering::SeqCst);
    }
}

#[test]
fn fixed_global_roster_and_original_before_free_controls() {
    fixed_roster_retains_all64_original_extents_and_refuses65_as_overflow();
    global_roster_records_actual_worker_allocations_and_original_join();
    roster_observes_zeroed_allocation_and_separately_reports_reallocation();
    roster_preserves_outer_arm_and_resets_after_action_unwind();
    before_free_samples_separately_retained_original_credit_before_its_drop();
    before_free_detects_original_marker_already_closed_by_ordinary_payload_drop();
    before_free_rejects_overlapping_modes_and_preserves_original_flag();
    before_free_missing_target_and_action_unwind_clear_original_watch();
}

fn fixed_roster_retains_all64_original_extents_and_refuses65_as_overflow() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (owners, roster) = TestAllocationObserver::capture_allocation_roster(|| {
        std::array::from_fn::<_, 64, _>(|index| Box::new([index as u8; 32]))
    })
    .unwrap();

    assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(roster.allocations, 64);
    assert_eq!(roster.reallocations, 0);
    assert!(!roster.overflow);
    assert_eq!(roster.entries().count(), 64);
    for owner in &owners {
        let address = std::ptr::from_ref(owner.as_ref()).addr();
        let matches: Vec<_> = roster
            .entries()
            .filter(|entry| entry.contains_address(address))
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].bytes(), 32);
        assert_eq!(matches[0].alignment(), 1);
        assert!(!matches[0].contains_address(address - 1));
        assert!(!matches[0].contains_address(address + 32));
    }
    drop(owners);

    let (owners, overflow) = TestAllocationObserver::capture_allocation_roster(|| {
        std::array::from_fn::<_, 65, _>(|index| Box::new([index as u8; 32]))
    })
    .unwrap();

    assert_eq!(overflow.allocations, 65);
    assert_eq!(overflow.entries().count(), 64);
    assert!(overflow.overflow);
    drop(owners);
}

fn global_roster_records_actual_worker_allocations_and_original_join() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (start, receive) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        receive.recv().unwrap();
        Box::new([7u8; 64])
    });
    let (owner, roster) = TestAllocationObserver::capture_allocation_roster(|| {
        start.send(()).unwrap();
        worker.join().unwrap()
    })
    .unwrap();

    assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
    assert!(!roster.overflow);
    assert_eq!(roster.reallocations, 0);
    let address = std::ptr::from_ref(owner.as_ref()).addr();
    let entries: Vec<_> = roster
        .entries()
        .filter(|entry| entry.contains_address(address))
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].bytes(), 64);
    drop(owner);
}

fn roster_observes_zeroed_allocation_and_separately_reports_reallocation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (owner, roster) = TestAllocationObserver::capture_allocation_roster(|| {
        let mut owner = vec![0u8; 64];
        owner.reserve_exact(64);
        owner
    })
    .unwrap();

    assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(roster.allocations, 1);
    assert_eq!(roster.reallocations, 1);
    assert!(!roster.overflow);
    assert_eq!(owner.len(), 64);
    drop(owner);
}

fn roster_preserves_outer_arm_and_resets_after_action_unwind() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (_, roster) = TestAllocationObserver::capture_allocation_roster(|| {
        let nested = TestAllocationObserver::capture_allocation_roster(|| {
            panic!("nested action must not run")
        });
        assert!(matches!(
            nested,
            Err(AllocationRosterSetupError::AlreadyArmed)
        ));
    })
    .unwrap();
    assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(roster.allocations, 0);

    let panic = std::panic::catch_unwind(|| {
        TestAllocationObserver::capture_allocation_roster(|| {
            panic!("intentional roster action unwind")
        })
    });
    assert!(panic.is_err());

    let (owner, roster) =
        TestAllocationObserver::capture_allocation_roster(|| Box::new([1u8; 32])).unwrap();
    assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(roster.allocations, 1);
    assert!(!roster.overflow);
    drop(owner);
}

fn before_free_samples_separately_retained_original_credit_before_its_drop() {
    let _serial = TEST_LOCK.lock().unwrap();
    ORIGINAL_CLOSED.store(false, Ordering::SeqCst);
    let layout = Layout::new::<[u8; 64]>();
    let (owner, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || Box::new([9u8; 64]));
    let credit = OriginalCredit;
    assert_eq!(counts.allocations, 1);
    let (_, outcome) = TestAllocationObserver::observe_close_marker_before_free(
        &ORIGINAL_CLOSED,
        identity.unwrap(),
        || {
            drop(owner);
            drop(credit);
        },
    )
    .unwrap();

    assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
    assert!(ORIGINAL_CLOSED.load(Ordering::SeqCst));
}

fn before_free_detects_original_marker_already_closed_by_ordinary_payload_drop() {
    let _serial = TEST_LOCK.lock().unwrap();
    ORIGINAL_CLOSED.store(false, Ordering::SeqCst);
    let (owner, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<OrdinaryPayload>(), || {
            Box::new(OrdinaryPayload([9; 64]))
        });
    assert_eq!(owner.0, [9; 64]);
    assert_eq!(counts.allocations, 1);
    let (_, outcome) = TestAllocationObserver::observe_close_marker_before_free(
        &ORIGINAL_CLOSED,
        identity.unwrap(),
        || drop(owner),
    )
    .unwrap();

    assert_eq!(outcome, BeforeFreeMarkerOutcome::Closed);
    assert!(ORIGINAL_CLOSED.load(Ordering::SeqCst));
}

fn before_free_rejects_overlapping_modes_and_preserves_original_flag() {
    let _serial = TEST_LOCK.lock().unwrap();
    ORIGINAL_CLOSED.store(false, Ordering::SeqCst);
    let (owner, identity, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 64]>(), || {
            Box::new([9u8; 64])
        });
    let identity = identity.unwrap();
    let (_, outcome) = TestAllocationObserver::observe_close_marker_before_free(
        &ORIGINAL_CLOSED,
        identity,
        || {
            let nested = TestAllocationObserver::observe_close_marker_after_free(
                &ORIGINAL_CLOSED,
                identity,
                || panic!("overlapping publication must not run"),
            );
            assert!(matches!(nested, Err(CloseMarkerSetupError::AlreadyArmed)));
            drop(owner);
        },
    )
    .unwrap();

    assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
    assert!(!ORIGINAL_CLOSED.load(Ordering::SeqCst));
}

fn before_free_missing_target_and_action_unwind_clear_original_watch() {
    let _serial = TEST_LOCK.lock().unwrap();
    ORIGINAL_CLOSED.store(false, Ordering::SeqCst);
    let (owner, identity, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 64]>(), || {
            Box::new([9u8; 64])
        });
    let identity = identity.unwrap();
    let (_, outcome) = TestAllocationObserver::observe_close_marker_before_free(
        &ORIGINAL_CLOSED,
        identity,
        || drop(Box::new([8u8; 32])),
    )
    .unwrap();
    assert_eq!(outcome, BeforeFreeMarkerOutcome::Missing);

    let result = std::panic::catch_unwind(|| {
        TestAllocationObserver::observe_close_marker_before_free(&ORIGINAL_CLOSED, identity, || {
            panic!("intentional before-free action unwind")
        })
    });
    assert!(result.is_err());
    let (_, outcome) = TestAllocationObserver::observe_close_marker_before_free(
        &ORIGINAL_CLOSED,
        identity,
        || drop(owner),
    )
    .unwrap();
    assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
    assert!(!ORIGINAL_CLOSED.load(Ordering::SeqCst));
}
