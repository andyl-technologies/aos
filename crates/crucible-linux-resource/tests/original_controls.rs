//! Exercises fixed original static counters at actual allocation closes.

// crucible-lint: allow panic-shortcut -- controls retain real owners through deliberate constructor and borrower unwind.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crucible_linux_resource::test_support::{
    CloseMarkerSetupError, OriginalControlSelection, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static FIRST: AtomicU64 = AtomicU64::new(0);
static SECOND: AtomicU64 = AtomicU64::new(0);
static REQUESTED: AtomicU64 = AtomicU64::new(0);
static CLOSED: AtomicBool = AtomicBool::new(false);
static OTHER_CLOSED: AtomicBool = AtomicBool::new(false);
static USED: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);
static EXTENT: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);

struct EarlyDrop([u8; 64]);

impl Drop for EarlyDrop {
    fn drop(&mut self) {
        CLOSED.store(true, Ordering::SeqCst);
    }
}

#[test]
fn exact_original_static_control_and_constructor_selection_controls() {
    original_grants_and_actual_two_control_close_ordinals();
    independently_concurrent_controls_keep_original_samples();
    original_both_flags_detect_real_early_payload_drop();
    original_usage_and_drop_snapshots_keep_raw_source_values();
    first_constructor_extent_survives_actual_callback_unwind();
    original_requested_extent_selects_once_and_rejects_wrong_requests();
    constructor_selection_excludes_actual_other_thread_requests();
    occupied_and_duplicate_slots_and_legacy_overlap_refuse();
    empty_and_unwound_sessions_cannot_establish_completion();
}

fn original_grants_and_actual_two_control_close_ordinals() {
    FIRST.store(191, Ordering::SeqCst);
    SECOND.store(273, Ordering::SeqCst);
    let (first, first_id, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 33]>(), || {
            Box::new([1u8; 33])
        });
    let (second, second_id, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 37]>(), || {
            Box::new([2u8; 37])
        });
    let first_id = first_id.unwrap();
    let second_id = second_id.unwrap();
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::Explicit(first_id),
                OriginalStaticCounters::U64(&FIRST),
                true,
            )
            .unwrap();
        session
            .arm(
                OriginalControlSlot::Second,
                OriginalControlSelection::Explicit(second_id),
                OriginalStaticCounters::U64(&SECOND),
                false,
            )
            .unwrap();
        drop(first);
        let intermediate = session.report().unwrap();
        assert_eq!(intermediate.outcome, OriginalControlsOutcome::Missing);
        assert!(intermediate.controls[0].is_some());
        assert!(intermediate.controls[1].is_none());
        FIRST.store(0, Ordering::SeqCst);
        drop(second);
        SECOND.store(0, Ordering::SeqCst);
    })
    .unwrap();

    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let first = report.controls[0].unwrap();
    let second = report.controls[1].unwrap();
    assert_eq!(first.before, OriginalControlSnapshot::U64(191));
    assert_eq!(first.after, Some(OriginalControlSnapshot::U64(191)));
    assert_eq!(second.before, OriginalControlSnapshot::U64(273));
    assert_eq!(second.after, None);
    assert_eq!((first.ordinal, second.ordinal), (1, 2));
}

fn independently_concurrent_controls_keep_original_samples() {
    FIRST.store(191, Ordering::SeqCst);
    SECOND.store(273, Ordering::SeqCst);
    let (first, first_id, first_counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 33]>(), || {
            Box::new([1u8; 33])
        });
    let (second, second_id, second_counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 37]>(), || {
            Box::new([2u8; 37])
        });
    assert_eq!(first_counts.allocations, 1);
    assert_eq!(second_counts.allocations, 1);
    let start = std::sync::Barrier::new(2);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::Explicit(first_id.unwrap()),
                OriginalStaticCounters::U64(&FIRST),
                true,
            )
            .unwrap();
        session
            .arm(
                OriginalControlSlot::Second,
                OriginalControlSelection::Explicit(second_id.unwrap()),
                OriginalStaticCounters::U64(&SECOND),
                true,
            )
            .unwrap();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                start.wait();
                drop(first);
            });
            let second = scope.spawn(|| {
                start.wait();
                drop(second);
            });
            first.join().unwrap();
            second.join().unwrap();
        });
        assert_eq!(FIRST.load(Ordering::SeqCst), 191);
        assert_eq!(SECOND.load(Ordering::SeqCst), 273);
    })
    .unwrap();

    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let first = report.controls[0].unwrap();
    let second = report.controls[1].unwrap();
    assert_eq!(first.before, OriginalControlSnapshot::U64(191));
    assert_eq!(first.after, Some(OriginalControlSnapshot::U64(191)));
    assert_eq!(second.before, OriginalControlSnapshot::U64(273));
    assert_eq!(second.after, Some(OriginalControlSnapshot::U64(273)));
    // Both frees are real, but concurrent System calls have no inferred total order.
    let mut publications = [first.ordinal, second.ordinal];
    publications.sort();
    assert_eq!(publications, [1, 2]);
    FIRST.store(0, Ordering::SeqCst);
    SECOND.store(0, Ordering::SeqCst);
}

fn original_both_flags_detect_real_early_payload_drop() {
    CLOSED.store(false, Ordering::SeqCst);
    OTHER_CLOSED.store(false, Ordering::SeqCst);
    let (owner, id, counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<EarlyDrop>(), || {
            Box::new(EarlyDrop([4; 64]))
        });
    assert_eq!(owner.0[0], 4);
    assert_eq!(counts.allocations, 1);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::Explicit(id.unwrap()),
                OriginalStaticCounters::BothFlags {
                    first: &CLOSED,
                    second: &OTHER_CLOSED,
                },
                true,
            )
            .unwrap();
        drop(owner);
    })
    .unwrap();

    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let observation = report.controls[0].unwrap();
    let expected = OriginalControlSnapshot::BothFlags {
        first: true,
        second: false,
    };
    assert_eq!(observation.before, expected);
    assert_eq!(observation.after, Some(expected));
}

fn original_usage_and_drop_snapshots_keep_raw_source_values() {
    USED.store(209, Ordering::SeqCst);
    BASELINE.store(17, Ordering::SeqCst);
    EXTENT.store(64, Ordering::SeqCst);
    DROPS.store(0, Ordering::SeqCst);
    let (owner, id, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 64]>(), || {
            Box::new([7u8; 64])
        });
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::Explicit(id.unwrap()),
                OriginalStaticCounters::UsageAndDrops {
                    used: &USED,
                    baseline: &BASELINE,
                    extent: &EXTENT,
                    drops: &DROPS,
                },
                false,
            )
            .unwrap();
        drop(owner);
        USED.store(17, Ordering::SeqCst);
        DROPS.store(1, Ordering::SeqCst);
    })
    .unwrap();

    assert_eq!(
        report.controls[0].unwrap().before,
        OriginalControlSnapshot::UsageAndDrops {
            used: 209,
            baseline: 17,
            extent: 64,
            drops: 0
        }
    );
    assert_eq!(USED.load(Ordering::SeqCst), 17);
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
}

fn first_constructor_extent_survives_actual_callback_unwind() {
    CLOSED.store(false, Ordering::SeqCst);
    let (unwind, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(NonZeroUsize::new(63).unwrap()),
                OriginalStaticCounters::Bool(&CLOSED),
                true,
            )
            .unwrap();
        std::panic::catch_unwind(|| {
            let owner = Box::new([9u8; 63]);
            std::hint::black_box(&owner);
            panic!("actual constructor callback unwind");
        })
    })
    .unwrap();

    assert!(unwind.is_err());
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let observation = report.controls[0].unwrap();
    assert_eq!(observation.before, OriginalControlSnapshot::Bool(false));
    assert_eq!(
        observation.after,
        Some(OriginalControlSnapshot::Bool(false))
    );
}

fn original_requested_extent_selects_once_and_rejects_wrong_requests() {
    FIRST.store(487, Ordering::SeqCst);
    REQUESTED.store(0, Ordering::SeqCst);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadRequestedExtent(&REQUESTED),
                OriginalStaticCounters::U64(&FIRST),
                false,
            )
            .unwrap();
        REQUESTED.store(75, Ordering::SeqCst);
        let wrong = Box::new([8u8; 74]);
        std::hint::black_box(&wrong);
        drop(wrong);
        assert_eq!(
            session.report().unwrap().outcome,
            OriginalControlsOutcome::Missing
        );
        let original = Box::new([6u8; 75]);
        std::hint::black_box(&original);
        let replacement = Box::new([2u8; 75]);
        std::hint::black_box(&replacement);
        drop(replacement);
        assert_eq!(
            session.report().unwrap().outcome,
            OriginalControlsOutcome::Missing
        );
        drop(original);
        FIRST.store(0, Ordering::SeqCst);
    })
    .unwrap();

    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    assert_eq!(
        report.controls[0].unwrap().before,
        OriginalControlSnapshot::U64(487)
    );
}

fn constructor_selection_excludes_actual_other_thread_requests() {
    REQUESTED.store(93, Ordering::SeqCst);
    let (start, receive) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        receive.recv().unwrap();
        Box::new([3u8; 93])
    });
    let (owner, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadRequestedExtent(&REQUESTED),
                OriginalStaticCounters::U64(&FIRST),
                false,
            )
            .unwrap();
        start.send(()).unwrap();
        worker.join().unwrap()
    })
    .unwrap();

    assert_eq!(owner.len(), 93);
    assert_eq!(report.outcome, OriginalControlsOutcome::Missing);
    assert!(report.controls[0].is_none());
    drop(owner);
}

fn occupied_and_duplicate_slots_and_legacy_overlap_refuse() {
    let (owner, id, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 64]>(), || {
            Box::new([2u8; 64])
        });
    let id = id.unwrap();
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::Explicit(id),
                OriginalStaticCounters::Bool(&CLOSED),
                false,
            )
            .unwrap();
        assert_eq!(
            session.arm(
                OriginalControlSlot::First,
                OriginalControlSelection::Explicit(id),
                OriginalStaticCounters::U64(&FIRST),
                false,
            ),
            Err(CloseMarkerSetupError::AlreadyArmed)
        );
        assert_eq!(
            session.arm(
                OriginalControlSlot::Second,
                OriginalControlSelection::Explicit(id),
                OriginalStaticCounters::U64(&SECOND),
                false,
            ),
            Err(CloseMarkerSetupError::AlreadyArmed)
        );
        let nested = TestAllocationObserver::observe_close_marker_before_free(&CLOSED, id, || ());
        assert_eq!(nested, Err(CloseMarkerSetupError::AlreadyArmed));
        drop(owner);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}

fn empty_and_unwound_sessions_cannot_establish_completion() {
    let (value, report) = TestAllocationObserver::observe_original_controls(|_| 17).unwrap();
    assert_eq!(value, 17);
    assert_eq!(report.outcome, OriginalControlsOutcome::Missing);
    assert!(report.controls.iter().all(Option::is_none));

    let (owner, id, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 64]>(), || {
            Box::new([5u8; 64])
        });
    let unwind = std::panic::catch_unwind(|| {
        let _ = TestAllocationObserver::observe_original_controls(|session| {
            session
                .arm(
                    OriginalControlSlot::First,
                    OriginalControlSelection::Explicit(id.unwrap()),
                    OriginalStaticCounters::U64(&FIRST),
                    false,
                )
                .unwrap();
            let _owner = owner;
            panic!("actual borrower action unwind");
        });
    });
    assert!(unwind.is_err());

    CLOSED.store(false, Ordering::SeqCst);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(NonZeroUsize::new(67).unwrap()),
                OriginalStaticCounters::Bool(&CLOSED),
                false,
            )
            .unwrap();
        let owner = Box::new([1u8; 67]);
        std::hint::black_box(&owner);
        drop(owner);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}
