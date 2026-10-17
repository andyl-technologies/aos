//! Exercises original fixed native event order and thread-local capture scope.

#![cfg(feature = "test-support")]
// crucible-lint: allow panic-shortcut -- fixtures isolate native trace order and reset failures.
#![allow(clippy::unwrap_used)]

use crucible_linux_resource::test_support::{AllocationEventsSetupError, TestAllocationObserver};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

#[repr(align(64))]
struct Aligned([u8; 64]);

#[test]
fn native_allocation_and_actual_close_keep_original_order_and_layout() {
    let (_, report) = TestAllocationObserver::capture_allocation_events(|| {
        let first = std::hint::black_box(Box::new([9u8; 32]));
        drop(first);
        let second = std::hint::black_box(Box::new([7u8; 64]));
        drop(second);
    })
    .unwrap();

    let actual: Vec<_> = report
        .entries()
        .map(|event| (event.allocated, event.bytes, event.alignment))
        .collect();
    assert_eq!(
        actual,
        [(true, 32, 1), (false, 32, 1), (true, 64, 1), (false, 64, 1)]
    );
    assert_eq!(report.count, 4);
    assert_eq!(report.reallocations, 0);
    assert!(!report.overflow);
}

#[test]
fn original_no_allocation_action_has_zero_native_events() {
    let (value, report) = TestAllocationObserver::capture_allocation_events(|| 17).unwrap();
    assert_eq!(value, 17);
    assert_eq!(report.count, 0);
    assert_eq!(report.reallocations, 0);
    assert!(!report.overflow);
}

#[test]
fn fixed64_events_reject_additional_physical_closes_as_overflow() {
    let (_, report) = TestAllocationObserver::capture_allocation_events(|| {
        let owners = std::array::from_fn::<_, 33, _>(|index| {
            std::hint::black_box(Box::new([index as u8; 32]))
        });
        drop(owners);
    })
    .unwrap();

    assert_eq!(report.count, 64);
    assert_eq!(report.entries().count(), 64);
    assert!(report.overflow);
    assert_eq!(report.reallocations, 0);
}

#[test]
fn native_reallocation_cannot_pass_as_original_fixed_trace() {
    let (_, report) = TestAllocationObserver::capture_allocation_events(|| {
        let mut owner = vec![0u8; 64];
        owner.reserve_exact(64);
        std::hint::black_box(&owner);
        drop(owner);
    })
    .unwrap();

    assert_eq!(report.reallocations, 1);
    assert!(!report.overflow);
    let events: Vec<_> = report
        .entries()
        .map(|event| (event.allocated, event.bytes))
        .collect();
    assert_eq!(events, [(true, 64), (false, 128)]);
}

#[test]
fn nested_capture_refuses_without_replacing_original_trace() {
    let (_, report) = TestAllocationObserver::capture_allocation_events(|| {
        let nested = TestAllocationObserver::capture_allocation_events(|| {
            panic!("nested event action must not run")
        });
        assert!(matches!(
            nested,
            Err(AllocationEventsSetupError::AlreadyArmed)
        ));
        drop(std::hint::black_box(Box::new([7u8; 32])));
    })
    .unwrap();

    assert_eq!(report.count, 2);
    assert_eq!(report.reallocations, 0);
    assert!(!report.overflow);
}

#[test]
fn action_unwind_resets_original_trace_before_successor_capture() {
    let panic = std::panic::catch_unwind(|| {
        TestAllocationObserver::capture_allocation_events(|| {
            let _owner = std::hint::black_box(Box::new([7u8; 32]));
            panic!("intentional native event action unwind");
        })
    });
    assert!(panic.is_err());

    let (_, report) = TestAllocationObserver::capture_allocation_events(|| {
        drop(std::hint::black_box(Box::new([9u8; 64])))
    })
    .unwrap();
    let events: Vec<_> = report
        .entries()
        .map(|event| (event.allocated, event.bytes))
        .collect();
    assert_eq!(events, [(true, 64), (false, 64)]);
    assert!(!report.overflow);
}

#[test]
fn original_trace_scope_excludes_other_threads_real_allocations() {
    let (start, receive) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        receive.recv().unwrap();
        TestAllocationObserver::capture_allocation_events(|| {
            std::hint::black_box(Box::new([7u8; 113]))
        })
        .unwrap()
    });
    let ((owner, child_report), report) = TestAllocationObserver::capture_allocation_events(|| {
        start.send(()).unwrap();
        worker.join().unwrap()
    })
    .unwrap();

    assert_eq!(owner.len(), 113);
    assert_eq!(child_report.count, 1);
    let child_event = child_report.entries().next().unwrap();
    assert!(child_event.allocated);
    assert_eq!(child_event.bytes, 113);
    assert_eq!(child_event.alignment, 1);
    assert_eq!(child_report.reallocations, 0);
    assert!(!child_report.overflow);

    // The original parent trace retains all of its real runtime events;
    // its distinct thread-local arm excludes the child's actual allocation.
    assert!(!report.entries().any(|event| event.bytes == 113));
    assert_eq!(report.reallocations, 0);
    assert!(!report.overflow);
    drop(owner);
}

#[test]
fn exact_original_native_alignment_is_retained_through_actual_free() {
    let (_, report) = TestAllocationObserver::capture_allocation_events(|| {
        let owner = std::hint::black_box(Box::new(Aligned([7; 64])));
        assert_eq!(owner.0, [7; 64]);
        drop(owner);
    })
    .unwrap();

    let events: Vec<_> = report
        .entries()
        .map(|event| (event.allocated, event.bytes, event.alignment))
        .collect();
    assert_eq!(events, [(true, 64, 64), (false, 64, 64)]);
    assert_eq!(report.reallocations, 0);
    assert!(!report.overflow);
}
