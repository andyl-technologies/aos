//! Exercises finite process-wide32 capture under original source-live samples.

use std::sync::atomic::{AtomicBool, Ordering};

use crucible_linux_resource::test_support::{
    AllocationRosterOutcome, AllocationRosterSetupError, AllocationTrace,
    AllocationTraceSetupError, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static TRACE: AllocationTrace<32> = AllocationTrace::new();
static LIVE: AtomicBool = AtomicBool::new(false);
static FUNDED: [AtomicBool; 32] = [const { AtomicBool::new(false) }; 32];

#[test]
fn global32_scope_boundary_original_samples_pause_and_reset_controls() {
    another_thread_request_uses_same_global_trace_and_original_sample();
    exact32_capacity_and33_overflow_retain_original_storage();
    global_and_same_storage_tls_overlaps_refuse_without_replacement();
    actual_reallocation_invalidates_the_extent_witness();
    original_callback_pause_and_action_unwind_reset_the_same_registry();
}

fn another_thread_request_uses_same_global_trace_and_original_sample() {
    let (start, ready) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        ready
            .recv()
            .unwrap_or_else(|error| panic!("original global capture control: {error}"));
        Box::new([3u8; 239])
    });
    LIVE.store(true, Ordering::SeqCst);
    let ((worker_owner, local_owner), outcome) =
        TestAllocationObserver::capture_global_allocation_trace32(
            &TRACE,
            &LIVE,
            &FUNDED,
            |session| {
                start
                    .send(())
                    .unwrap_or_else(|error| panic!("original global capture control: {error}"));
                let worker_owner = worker
                    .join()
                    .unwrap_or_else(|cause| std::panic::resume_unwind(cause));
                LIVE.store(false, Ordering::SeqCst);
                let local_owner = Box::new([4u8; 251]);
                std::hint::black_box(&local_owner);
                assert_eq!(
                    session
                        .pause()
                        .unwrap_or_else(|error| panic!("original global capture control: {error}")),
                    AllocationRosterOutcome::Complete
                );
                (worker_owner, local_owner)
            },
        )
        .unwrap_or_else(|error| panic!("original global capture control: {error}"));
    assert_eq!(outcome, AllocationRosterOutcome::Complete);
    assert!(!TRACE.overflowed());
    assert_eq!(TRACE.reallocations(), 0);
    let worker_index = TRACE
        .entries()
        .position(|entry| entry.bytes() == 239)
        .unwrap_or_else(|| panic!("actual worker/local extent must be recorded"));
    let local_index = TRACE
        .entries()
        .position(|entry| entry.bytes() == 251)
        .unwrap_or_else(|| panic!("actual worker/local extent must be recorded"));
    assert!(worker_index < local_index);
    assert!(FUNDED[worker_index].load(Ordering::SeqCst));
    assert!(!FUNDED[local_index].load(Ordering::SeqCst));
    assert_eq!(worker_owner.len(), 239);
    assert_eq!(local_owner.len(), 251);
}

fn exact32_capacity_and33_overflow_retain_original_storage() {
    LIVE.store(true, Ordering::SeqCst);
    for extra in [false, true] {
        let (owners, outcome) = TestAllocationObserver::capture_global_allocation_trace32(
            &TRACE,
            &LIVE,
            &FUNDED,
            |session| {
                let owners: [Box<[u8; 83]>; 32] = std::array::from_fn(|_| Box::new([5u8; 83]));
                std::hint::black_box(&owners);
                if extra {
                    let extra_owner = Box::new([7u8; 89]);
                    std::hint::black_box(&extra_owner);
                    drop(extra_owner);
                }
                assert_eq!(
                    session
                        .pause()
                        .unwrap_or_else(|error| panic!("original global capture control: {error}")),
                    AllocationRosterOutcome::Complete
                );
                owners
            },
        )
        .unwrap_or_else(|error| panic!("original global capture control: {error}"));
        assert_eq!(outcome, AllocationRosterOutcome::Complete);
        assert_eq!(TRACE.allocation_count(), if extra { 33 } else { 32 });
        assert_eq!(TRACE.entries().count(), 32);
        assert_eq!(TRACE.overflowed(), extra);
        assert_eq!(TRACE.reallocations(), 0);
        assert!(FUNDED.iter().all(|flag| flag.load(Ordering::SeqCst)));
        assert!(TRACE.entries().all(|entry| entry.bytes() == 83));
        drop(owners);
    }
}

fn global_and_same_storage_tls_overlaps_refuse_without_replacement() {
    let (owner, outcome) = TestAllocationObserver::capture_global_allocation_trace32(
        &TRACE,
        &LIVE,
        &FUNDED,
        |session| {
            let nested = TestAllocationObserver::capture_allocation_roster(|| ());
            assert!(matches!(
                nested,
                Err(AllocationRosterSetupError::AlreadyArmed)
            ));
            assert_eq!(
                TRACE.capture(|| ()),
                Err(AllocationTraceSetupError::AlreadyArmed)
            );
            let owner = Box::new([9u8; 97]);
            std::hint::black_box(&owner);
            assert_eq!(
                session
                    .pause()
                    .unwrap_or_else(|error| panic!("original global capture control: {error}")),
                AllocationRosterOutcome::Complete
            );
            owner
        },
    )
    .unwrap_or_else(|error| panic!("original global capture control: {error}"));
    assert_eq!(outcome, AllocationRosterOutcome::Complete);
    assert_eq!(TRACE.allocation_count(), 1);
    assert_eq!(
        TRACE
            .entries()
            .next()
            .unwrap_or_else(|| panic!("actual original extent must be recorded"))
            .bytes(),
        97
    );
    drop(owner);

    TRACE
        .capture(|| {
            let nested = TestAllocationObserver::capture_global_allocation_trace32(
                &TRACE,
                &LIVE,
                &FUNDED,
                |_| (),
            );
            assert!(matches!(
                nested,
                Err(AllocationRosterSetupError::AlreadyArmed)
            ));
        })
        .unwrap_or_else(|error| panic!("original global capture control: {error}"));
}

fn actual_reallocation_invalidates_the_extent_witness() {
    let (owner, outcome) = TestAllocationObserver::capture_global_allocation_trace32(
        &TRACE,
        &LIVE,
        &FUNDED,
        |session| {
            let mut owner = Vec::with_capacity(3);
            owner.resize(std::hint::black_box(257), 4u8);
            assert_eq!(
                session
                    .pause()
                    .unwrap_or_else(|error| panic!("original global capture control: {error}")),
                AllocationRosterOutcome::Complete
            );
            owner
        },
    )
    .unwrap_or_else(|error| panic!("original global capture control: {error}"));
    assert_eq!(outcome, AllocationRosterOutcome::Complete);
    assert!(TRACE.reallocations() > 0);
    assert_eq!(owner.len(), 257);
}

fn original_callback_pause_and_action_unwind_reset_the_same_registry() {
    let (unwind, outcome) = TestAllocationObserver::capture_global_allocation_trace32(
        &TRACE,
        &LIVE,
        &FUNDED,
        |session| {
            std::panic::catch_unwind(|| {
                let owner = Box::new([6u8; 101]);
                std::hint::black_box(&owner);
                assert_eq!(
                    session
                        .pause()
                        .unwrap_or_else(|error| panic!("original global capture control: {error}")),
                    AllocationRosterOutcome::Complete
                );
                panic!("actual constructor callback after original global count paused");
            })
        },
    )
    .unwrap_or_else(|error| panic!("original global capture control: {error}"));
    assert!(unwind.is_err());
    assert_eq!(outcome, AllocationRosterOutcome::Complete);
    assert_eq!(TRACE.allocation_count(), 1);
    assert_eq!(
        TRACE
            .entries()
            .next()
            .unwrap_or_else(|| panic!("actual original extent must be recorded"))
            .bytes(),
        101
    );
    assert!(!TRACE.overflowed());
    let unwind = std::panic::catch_unwind(|| {
        let _ = TestAllocationObserver::capture_global_allocation_trace32(
            &TRACE,
            &LIVE,
            &FUNDED,
            |_| panic!("actual original action unwind"),
        );
    });
    assert!(unwind.is_err());
    let (owner, outcome) = TestAllocationObserver::capture_global_allocation_trace32(
        &TRACE,
        &LIVE,
        &FUNDED,
        |session| {
            let owner = Box::new([2u8; 103]);
            assert_eq!(
                session
                    .pause()
                    .unwrap_or_else(|error| panic!("original global capture control: {error}")),
                AllocationRosterOutcome::Complete
            );
            owner
        },
    )
    .unwrap_or_else(|error| panic!("original global capture control: {error}"));
    assert_eq!(outcome, AllocationRosterOutcome::Complete);
    assert_eq!(TRACE.allocation_count(), 1);
    assert_eq!(owner.len(), 103);
}
