//! Compares a fixed nonblocking probe with original control custody.
//!
//! The historical blocking allocator fixture remains separate and unchanged.
//! This binary reuses the sole lower observer and joins actual workers before
//! releasing its same-account watch. Grants remain charged until outer teardown.

#![cfg(feature = "test-support")]
// crucible-lint: allow panic-shortcut -- test fixtures panic to localize original-account and control-lifetime failures.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceError};
use crucible_linux_resource::test_support::{
    AllocationIdentity, CloseMarkerOutcome, CloseMarkerSetupError, ResidentProbeOutcome,
    ResidentProbeSetupError, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static TEST_LOCK: Mutex<()> = Mutex::new(());

static ORIGINAL_CLOSE: AtomicBool = AtomicBool::new(false);
static PAYLOAD_SAW_CLOSE: AtomicBool = AtomicBool::new(false);

struct OriginalPayloadMarker;

impl Drop for OriginalPayloadMarker {
    fn drop(&mut self) {
        PAYLOAD_SAW_CLOSE.store(ORIGINAL_CLOSE.load(Ordering::SeqCst), Ordering::SeqCst);
    }
}

fn reset_close_marker() {
    ORIGINAL_CLOSE.store(false, Ordering::SeqCst);
    PAYLOAD_SAW_CLOSE.store(false, Ordering::SeqCst);
}

#[test]
fn original_static_marker_publishes_after_free_before_separate_payload_drop() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset_close_marker();
    let (allocation, identity) = capture(64, || Box::new([9u8; 64]));
    let payload = OriginalPayloadMarker;

    let ((), outcome) =
        TestAllocationObserver::observe_close_marker_after_free(&ORIGINAL_CLOSE, identity, || {
            drop(allocation);
            drop(payload);
        })
        .unwrap();

    assert_eq!(outcome, CloseMarkerOutcome::Published);
    assert!(ORIGINAL_CLOSE.load(Ordering::SeqCst));
    assert!(PAYLOAD_SAW_CLOSE.load(Ordering::SeqCst));
}

#[test]
fn ordinary_payload_drop_precedes_actual_control_close_marker() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset_close_marker();
    let layout = Layout::new::<[std::sync::atomic::AtomicUsize; 2]>();
    let (allocation, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            Arc::new(OriginalPayloadMarker)
        });
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    let ((), outcome) = TestAllocationObserver::observe_close_marker_after_free(
        &ORIGINAL_CLOSE,
        identity.unwrap(),
        || drop(allocation),
    )
    .unwrap();

    assert_eq!(outcome, CloseMarkerOutcome::Published);
    assert!(ORIGINAL_CLOSE.load(Ordering::SeqCst));
    assert!(!PAYLOAD_SAW_CLOSE.load(Ordering::SeqCst));
}

#[test]
fn original_close_marker_preserves_outer_arm_and_clears_unwind_and_missing_state() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset_close_marker();
    let (allocation, identity) = capture(64, || Box::new([9u8; 64]));

    let ((), missing) =
        TestAllocationObserver::observe_close_marker_after_free(&ORIGINAL_CLOSE, identity, || {
            drop(Box::new([8u8; 32]))
        })
        .unwrap();
    assert_eq!(missing, CloseMarkerOutcome::Missing);
    assert!(!ORIGINAL_CLOSE.load(Ordering::SeqCst));

    let unwind = std::panic::catch_unwind(|| {
        TestAllocationObserver::observe_close_marker_after_free(&ORIGINAL_CLOSE, identity, || {
            panic!("intentional original static-marker action unwind")
        })
    });
    assert!(unwind.is_err());
    assert!(!ORIGINAL_CLOSE.load(Ordering::SeqCst));

    let ((), outcome) =
        TestAllocationObserver::observe_close_marker_after_free(&ORIGINAL_CLOSE, identity, || {
            let nested = TestAllocationObserver::observe_close_marker_after_free(
                &ORIGINAL_CLOSE,
                identity,
                || (),
            );
            assert_eq!(nested, Err(CloseMarkerSetupError::AlreadyArmed));
            drop(allocation);
        })
        .unwrap();
    assert_eq!(outcome, CloseMarkerOutcome::Published);
    assert!(ORIGINAL_CLOSE.load(Ordering::SeqCst));
}

struct OriginalCreditMarker<'a>(&'a AtomicU64);

impl Drop for OriginalCreditMarker<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::SeqCst);
    }
}

#[test]
fn atomic_after_free_retains_the_original_counter_until_separate_marker_drop() {
    let _serial = TEST_LOCK.lock().unwrap();
    let original = AtomicU64::new(7);
    let (allocation, identity) = capture(64, || Box::new([9u8; 64]));
    let marker = OriginalCreditMarker(&original);

    let (_, sample) =
        TestAllocationObserver::observe_atomic_after_free(&original, identity, || {
            drop(allocation);
            drop(marker);
        });

    assert_eq!(sample, Some(7));
    assert_eq!(original.load(Ordering::SeqCst), 0);
}

#[test]
fn ordinary_payload_credit_is_already_closed_at_its_control_deallocation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let original = AtomicU64::new(7);
    let layout = Layout::new::<OriginalCreditMarker<'_>>();
    let (allocation, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            Box::new(OriginalCreditMarker(&original))
        });
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    let (_, sample) =
        TestAllocationObserver::observe_atomic_after_free(&original, identity.unwrap(), || {
            drop(allocation)
        });

    assert_eq!(sample, Some(0));
    assert_eq!(original.load(Ordering::SeqCst), 0);
}

#[test]
fn missing_atomic_target_and_action_unwind_reset_before_the_actual_close() {
    let _serial = TEST_LOCK.lock().unwrap();
    let original = AtomicU64::new(7);
    let (allocation, identity) = capture(64, || Box::new([9u8; 64]));

    let (_, sample) =
        TestAllocationObserver::observe_atomic_after_free(&original, identity, || {
            drop(Box::new([11u8; 32]));
        });
    assert_eq!(sample, None);

    let result = std::panic::catch_unwind(|| {
        TestAllocationObserver::observe_atomic_after_free(&original, identity, || {
            panic!("intentional original counter action unwind");
        })
    });
    assert!(result.is_err());

    let (_, sample) =
        TestAllocationObserver::observe_atomic_after_free(&original, identity, || drop(allocation));
    assert_eq!(sample, Some(7));
}

#[test]
fn exact_layout_capture_requires_both_original_extent_and_alignment() {
    let _serial = TEST_LOCK.lock().unwrap();
    for (bytes, alignment, matches) in [(64, 1, true), (65, 1, false), (64, 64, false)] {
        let layout = Layout::from_size_align(bytes, alignment).unwrap();

        let (allocation, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout, || Box::new([7u8; 64]));

        assert_eq!(allocation[0], 7);
        assert_eq!(identity.is_some(), matches);
        assert_eq!(counts.allocations, 1);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
    }
}

#[test]
fn exact_layout_capture_reports_additional_constructor_allocations() {
    let _serial = TEST_LOCK.lock().unwrap();
    let layout = Layout::new::<[u8; 64]>();

    let (allocations, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            (Box::new([7u8; 64]), Box::new([9u8; 32]))
        });

    assert_eq!(allocations.0[0], 7);
    assert_eq!(allocations.1[0], 9);
    assert!(identity.is_some());
    assert_eq!(counts.allocations, 2);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
}

fn capture<T>(bytes: usize, action: impl FnOnce() -> T) -> (T, AllocationIdentity) {
    let (value, identity) = TestAllocationObserver::capture(bytes, action);
    (value, identity.unwrap())
}

fn assert_available(account: &HostServiceAllocator) {
    let replacement = account.reserve_resources(1, 1, 48).unwrap();
    assert_eq!(replacement.resident_bytes(), 48);
}

#[test]
fn original_paid_control_refuses_without_a_nested_allocation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, identity) = capture(48, || account.reserve_resources(1, 1, 48).unwrap());

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, identity, || {
            drop(lease);
        })
        .unwrap();

    assert_eq!(
        report.outcome,
        ResidentProbeOutcome::Refused(HostServiceError::CapacityExhausted)
    );
    assert_eq!(report.counts.allocations, 0);
    assert_eq!(report.counts.reallocations, 0);
    assert!(!report.counts.overflow);
    assert_eq!(report.first_allocation, None);
    assert_available(&account);
}

#[test]
fn ordinary_arc_predecessor_grants_and_retains_the_real_byte_until_outer_teardown() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (ordinary, identity) = capture(24, || {
        Arc::new(account.reserve_resources(1, 1, 48).unwrap())
    });

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, identity, || {
            drop(ordinary);
            // The ordinary Arc drops its paid payload before its own control closes.
            // The actual accepted probe now holds one original byte until teardown.
            assert_eq!(
                account.reserve_resources(0, 0, 48).unwrap_err(),
                HostServiceError::CapacityExhausted
            );
        })
        .unwrap();

    assert_eq!(report.outcome, ResidentProbeOutcome::Granted);
    assert_eq!(report.counts.allocations, 1);
    assert_eq!(report.counts.reallocations, 0);
    assert!(!report.counts.overflow);
    let layout = report.first_allocation.unwrap();
    assert_eq!(layout.bytes, 48);
    assert_eq!(layout.alignment, 8);
    assert_available(&account);
}

#[test]
fn detached_worker_and_panicking_worker_join_before_owned_observation_teardown() {
    let _serial = TEST_LOCK.lock().unwrap();
    for panic_worker in [false, true] {
        let account = HostServiceAllocator::new(1, 1, 48).unwrap();
        let (lease, identity) = capture(48, || account.reserve_resources(1, 1, 48).unwrap());

        let (_, report) =
            TestAllocationObserver::observe_resident_after_free(&account, identity, || {
                let worker = std::thread::spawn(move || {
                    let _original_borrower = lease;
                    if panic_worker {
                        panic!("intentional original borrower unwind");
                    }
                });
                assert_eq!(worker.join().is_err(), panic_worker);
            })
            .unwrap();

        assert_eq!(
            report.outcome,
            ResidentProbeOutcome::Refused(HostServiceError::CapacityExhausted)
        );
        assert_eq!(report.counts.allocations, 0);
        assert_available(&account);
    }
}

#[test]
fn missing_target_nested_setup_and_action_unwind_cannot_donate_a_witness() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, identity) = capture(48, || account.reserve_resources(1, 1, 48).unwrap());

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, identity, || {
            let nested =
                TestAllocationObserver::observe_resident_after_free(&account, identity, || ());
            assert_eq!(nested.unwrap_err(), ResidentProbeSetupError::AlreadyArmed);
        })
        .unwrap();
    assert_eq!(report.outcome, ResidentProbeOutcome::Missing);
    assert_eq!(report.counts.allocations, 0);

    let result = std::panic::catch_unwind(|| {
        let _ = TestAllocationObserver::observe_resident_after_free(&account, identity, || {
            panic!("intentional observer action unwind");
        });
    });
    assert!(result.is_err());

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, identity, || drop(lease))
            .unwrap();
    assert_eq!(
        report.outcome,
        ResidentProbeOutcome::Refused(HostServiceError::CapacityExhausted)
    );
    assert_available(&account);
}

#[test]
fn action_unwind_releases_an_accepted_original_grant_outside_the_hook() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (ordinary, identity) = capture(24, || {
        Arc::new(account.reserve_resources(1, 1, 48).unwrap())
    });

    let result = std::panic::catch_unwind(|| {
        let _ = TestAllocationObserver::observe_resident_after_free(&account, identity, || {
            drop(ordinary);
            assert_eq!(
                account.reserve_resources(0, 0, 48).unwrap_err(),
                HostServiceError::CapacityExhausted
            );
            panic!("intentional action unwind after the original byte grant");
        });
    });

    assert!(result.is_err());
    assert_available(&account);
    let (lease, identity) = capture(48, || account.reserve_resources(1, 1, 48).unwrap());
    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, identity, || drop(lease))
            .unwrap();
    assert_eq!(
        report.outcome,
        ResidentProbeOutcome::Refused(HostServiceError::CapacityExhausted)
    );
    assert_available(&account);
}
