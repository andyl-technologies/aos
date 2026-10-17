//! Exercises original finite scalar traces and original credit through free.

// crucible-lint: allow panic-shortcut -- tests retain real allocation owners through intentional close-order and unwind failures.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_linux_resource::test_support::{
    AllocationTrace, AllocationTraceSetupError, CloseMarkerSetupError, TestAllocationObserver,
    ThroughFreeMarkerOutcome,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static TRACE: AllocationTrace<512> = AllocationTrace::new();
static TRACE16: AllocationTrace<16> = AllocationTrace::new();
static TRACE32: AllocationTrace<32> = AllocationTrace::new();
static TRACE64: AllocationTrace<64> = AllocationTrace::new();
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
fn original512_trace_and_original_flag_through_free_controls() {
    smaller_original_capacities_have_distinct_boundaries_and_preserve_outer_arm();
    trace_keeps512_actual_extents_and_refuses513_as_overflow();
    trace_observes_live_constructor_count_and_exact_alignment();
    trace_rejects_nested_capture_and_resets_after_unwind();
    trace_separately_reports_native_reallocation();
    trace_excludes_real_worker_allocations_from_original_thread_scope();
    through_free_retains_separate_original_credit_and_detects_ordinary_early_drop();
    through_free_preserves_mode_exclusion_missing_target_and_unwind_reset();
}

fn trace_keeps512_actual_extents_and_refuses513_as_overflow() {
    let owners = TRACE
        .capture(|| std::array::from_fn::<_, 512, _>(|index| Box::new([index as u8; 32])))
        .unwrap();

    assert_eq!(TRACE.allocation_count(), 512);
    assert_eq!(TRACE.reallocations(), 0);
    assert!(!TRACE.overflowed());
    assert_eq!(TRACE.entries().count(), 512);
    for (owner, entry) in owners.iter().zip(TRACE.entries()) {
        let address = std::ptr::from_ref(owner.as_ref()).addr();
        assert!(entry.contains_address(address));
        assert_eq!(entry.bytes(), 32);
        assert_eq!(entry.alignment(), 1);
        assert!(!entry.contains_address(address - 1));
        assert!(!entry.contains_address(address + 32));
    }
    drop(owners);

    let owners = TRACE
        .capture(|| std::array::from_fn::<_, 513, _>(|index| Box::new([index as u8; 32])))
        .unwrap();

    assert_eq!(TRACE.allocation_count(), 513);
    assert_eq!(TRACE.entries().count(), 512);
    assert!(TRACE.overflowed());
    drop(owners);
}

fn trace_observes_live_constructor_count_and_exact_alignment() {
    #[repr(align(64))]
    struct Aligned([u8; 128]);

    let owners = TRACE
        .capture(|| {
            assert_eq!(TRACE.allocation_count(), 0);
            let first = Box::new(Aligned([7; 128]));
            assert_eq!(TRACE.allocation_count(), 1);
            let second = Box::new([9u8; 37]);
            assert_eq!(TRACE.allocation_count(), 2);
            (first, second)
        })
        .unwrap();

    let entries: Vec<_> = TRACE.entries().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].bytes(), 128);
    assert_eq!(entries[0].alignment(), 64);
    assert_eq!(entries[1].bytes(), 37);
    assert_eq!(entries[1].alignment(), 1);
    assert_eq!(owners.0.0[0], 7);
    drop(owners);
}

fn trace_rejects_nested_capture_and_resets_after_unwind() {
    let owners = TRACE
        .capture(|| {
            let first = Box::new([1u8; 41]);
            let nested = TRACE.capture(|| panic!("nested action must not run"));
            assert!(matches!(
                nested,
                Err(AllocationTraceSetupError::AlreadyArmed)
            ));
            let second = Box::new([2u8; 43]);
            (first, second)
        })
        .unwrap();
    assert_eq!(TRACE.allocation_count(), 2);
    drop(owners);

    let unwind = std::panic::catch_unwind(|| {
        let _ = TRACE.capture(|| {
            let _owner = Box::new([5u8; 71]);
            panic!("actual trace action unwind");
        });
    });
    assert!(unwind.is_err());

    let owner = TRACE.capture(|| Box::new([8u8; 79])).unwrap();
    assert_eq!(TRACE.allocation_count(), 1);
    assert_eq!(TRACE.reallocations(), 0);
    assert!(!TRACE.overflowed());
    drop(owner);
}

fn trace_separately_reports_native_reallocation() {
    let owner = TRACE
        .capture(|| {
            let mut owner = vec![0u8; 64];
            owner.reserve_exact(64);
            owner
        })
        .unwrap();

    assert_eq!(TRACE.allocation_count(), 1);
    assert_eq!(TRACE.reallocations(), 1);
    assert!(!TRACE.overflowed());
    assert_eq!(TRACE.entries().next().unwrap().bytes(), 64);
    assert_eq!(owner.capacity(), 128);
    drop(owner);
}

fn trace_excludes_real_worker_allocations_from_original_thread_scope() {
    let (start, receive) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        receive.recv().unwrap();
        Box::new([3u8; 113])
    });
    let owners = TRACE
        .capture(|| {
            let parent = Box::new([2u8; 37]);
            start.send(()).unwrap();
            (parent, worker.join().unwrap())
        })
        .unwrap();

    assert_eq!(owners.1.len(), 113);
    assert!(TRACE.entries().any(|entry| entry.bytes() == 37));
    assert!(TRACE.entries().all(|entry| entry.bytes() != 113));
    assert!(!TRACE.overflowed());
    drop(owners);
}

fn through_free_retains_separate_original_credit_and_detects_ordinary_early_drop() {
    ORIGINAL_CLOSED.store(false, Ordering::SeqCst);
    let credit = OriginalCredit;
    let (owner, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 64]>(), || {
            Box::new([1u8; 64])
        });
    assert_eq!(counts.allocations, 1);
    let (_, observation) = TestAllocationObserver::observe_close_marker_through_free(
        &ORIGINAL_CLOSED,
        identity.unwrap(),
        || {
            drop(owner);
            drop(credit);
        },
    )
    .unwrap();

    assert_eq!(
        observation,
        ThroughFreeMarkerOutcome::Sampled {
            before: false,
            after: false
        }
    );
    assert!(ORIGINAL_CLOSED.load(Ordering::SeqCst));

    ORIGINAL_CLOSED.store(false, Ordering::SeqCst);
    let (owner, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<OrdinaryPayload>(), || {
            Box::new(OrdinaryPayload([2; 64]))
        });
    assert_eq!(owner.0[0], 2);
    assert_eq!(counts.allocations, 1);
    let (_, observation) = TestAllocationObserver::observe_close_marker_through_free(
        &ORIGINAL_CLOSED,
        identity.unwrap(),
        || drop(owner),
    )
    .unwrap();

    assert_eq!(
        observation,
        ThroughFreeMarkerOutcome::Sampled {
            before: true,
            after: true
        }
    );
}

fn through_free_preserves_mode_exclusion_missing_target_and_unwind_reset() {
    ORIGINAL_CLOSED.store(false, Ordering::SeqCst);
    let (owner, identity, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 64]>(), || {
            Box::new([6u8; 64])
        });
    let identity = identity.unwrap();
    let (_, observation) = TestAllocationObserver::observe_close_marker_through_free(
        &ORIGINAL_CLOSED,
        identity,
        || {
            let nested = TestAllocationObserver::observe_close_marker_before_free(
                &ORIGINAL_CLOSED,
                identity,
                || panic!("nested action must not run"),
            );
            assert_eq!(nested, Err(CloseMarkerSetupError::AlreadyArmed));
        },
    )
    .unwrap();
    assert_eq!(observation, ThroughFreeMarkerOutcome::Missing);
    assert!(!ORIGINAL_CLOSED.load(Ordering::SeqCst));

    let unwind = std::panic::catch_unwind(|| {
        let _ = TestAllocationObserver::observe_close_marker_through_free(
            &ORIGINAL_CLOSED,
            identity,
            || panic!("original marker action unwind"),
        );
    });
    assert!(unwind.is_err());
    let (_, observation) = TestAllocationObserver::observe_close_marker_through_free(
        &ORIGINAL_CLOSED,
        identity,
        || drop(owner),
    )
    .unwrap();
    assert_eq!(
        observation,
        ThroughFreeMarkerOutcome::Sampled {
            before: false,
            after: false
        }
    );
}

fn smaller_original_capacities_have_distinct_boundaries_and_preserve_outer_arm() {
    let owners = TRACE16
        .capture(|| std::array::from_fn::<_, 16, _>(|_| Box::new([1u8; 31])))
        .unwrap();
    assert_eq!(TRACE16.allocation_count(), 16);
    assert_eq!(TRACE16.entries().count(), 16);
    assert_eq!(TRACE16.reallocations(), 0);
    assert!(!TRACE16.overflowed());
    drop(owners);
    let owners = TRACE16
        .capture(|| std::array::from_fn::<_, 17, _>(|_| Box::new([2u8; 31])))
        .unwrap();
    assert_eq!(TRACE16.allocation_count(), 17);
    assert_eq!(TRACE16.entries().count(), 16);
    assert!(TRACE16.overflowed());
    drop(owners);

    let owners = TRACE32
        .capture(|| std::array::from_fn::<_, 32, _>(|_| Box::new([1u8; 33])))
        .unwrap();
    assert_eq!(TRACE32.allocation_count(), 32);
    assert_eq!(TRACE32.entries().count(), 32);
    assert_eq!(TRACE32.reallocations(), 0);
    assert!(!TRACE32.overflowed());
    drop(owners);
    let owners = TRACE32
        .capture(|| std::array::from_fn::<_, 33, _>(|_| Box::new([2u8; 33])))
        .unwrap();
    assert_eq!(TRACE32.allocation_count(), 33);
    assert_eq!(TRACE32.entries().count(), 32);
    assert!(TRACE32.overflowed());
    drop(owners);

    let owners = TRACE64
        .capture(|| std::array::from_fn::<_, 64, _>(|_| Box::new([1u8; 35])))
        .unwrap();
    assert_eq!(TRACE64.allocation_count(), 64);
    assert_eq!(TRACE64.entries().count(), 64);
    assert_eq!(TRACE64.reallocations(), 0);
    assert!(!TRACE64.overflowed());
    drop(owners);
    let owners = TRACE64
        .capture(|| std::array::from_fn::<_, 65, _>(|_| Box::new([2u8; 35])))
        .unwrap();
    assert_eq!(TRACE64.allocation_count(), 65);
    assert_eq!(TRACE64.entries().count(), 64);
    assert!(TRACE64.overflowed());
    drop(owners);

    let owner = TRACE16
        .capture(|| {
            let nested =
                TRACE64.capture(|| panic!("a different-capacity nested action must not run"));
            assert!(matches!(
                nested,
                Err(AllocationTraceSetupError::AlreadyArmed)
            ));
            Box::new([4u8; 29])
        })
        .unwrap();
    assert_eq!(TRACE16.allocation_count(), 1);
    assert_eq!(TRACE16.entries().next().unwrap().bytes(), 29);
    drop(owner);

    let owner = TRACE64.capture(|| Box::new([5u8; 27])).unwrap();
    assert_eq!(TRACE64.allocation_count(), 1);
    assert_eq!(TRACE64.entries().next().unwrap().bytes(), 27);
    assert!(!TRACE64.overflowed());
    drop(owner);
}
