//! Exercises finite namespace-node lifetime tracking with original static counters.

use crucible_linux_resource::test_support::{
    AllocationRosterOutcome, AllocationRosterSetupError, AllocationTrace, MemoryNodeCounters,
    TestAllocationObserver,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static ADDRESSES: [AtomicUsize; 64] = [const { AtomicUsize::new(0) }; 64];
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static OVERFLOW: AtomicBool = AtomicBool::new(false);
static FUNDED: AtomicBool = AtomicBool::new(true);
static CLOSED: AtomicBool = AtomicBool::new(false);
static COUNTERS: MemoryNodeCounters = MemoryNodeCounters {
    addresses: &ADDRESSES,
    allocations: &ALLOCATIONS,
    deallocations: &DEALLOCATIONS,
    overflow: &OVERFLOW,
    funded: &FUNDED,
    namespace_closed: &CLOSED,
};
static TRACE: AllocationTrace<64> = AllocationTrace::new();
static OTHER_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static OTHER_COUNTERS: MemoryNodeCounters = MemoryNodeCounters {
    addresses: &ADDRESSES,
    allocations: &OTHER_ALLOCATIONS,
    deallocations: &DEALLOCATIONS,
    overflow: &OVERFLOW,
    funded: &FUNDED,
    namespace_closed: &CLOSED,
};

fn reset() {
    for address in &ADDRESSES {
        address.store(0, Ordering::SeqCst);
    }
    ALLOCATIONS.store(0, Ordering::SeqCst);
    DEALLOCATIONS.store(0, Ordering::SeqCst);
    OVERFLOW.store(false, Ordering::SeqCst);
    FUNDED.store(true, Ordering::SeqCst);
    CLOSED.store(false, Ordering::SeqCst);
}

#[test]
fn original_node_slots_reuse_and_before_free_samples_remain_complete_or_explicitly_refused() {
    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |session| {
        TRACE
            .capture(|| drop(std::hint::black_box(Box::new([1u64; 68]))))
            .unwrap();
        assert_eq!(TRACE.allocation_count(), 1);
        assert!(!TRACE.overflowed());
        for _ in 0..128 {
            drop(std::hint::black_box(Box::new([2u64; 80])));
        }
        session.pause_allocations().unwrap();
        CLOSED.store(true, Ordering::SeqCst);
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(report.allocations, 129);
    assert_eq!(report.allocations, report.deallocations);
    assert_eq!(report.live, 0);
    assert!(!report.overflow);
    assert!(
        report.funded,
        "a later original N close cannot alter earlier free samples"
    );

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| {
        let owner = std::hint::black_box(Box::new([3u64; 68]));
        CLOSED.store(true, Ordering::SeqCst);
        drop(owner);
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(report.allocations, 1);
    assert!(
        !report.funded,
        "actual physical free sees the original early N close"
    );

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| {
        let owners: [Box<[u64; 68]>; 65] = std::array::from_fn(|_| Box::new([4; 68]));
        std::hint::black_box(&owners);
        drop(owners);
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Unavailable);
    assert!(report.overflow);
    assert_eq!(report.allocations, 65);
    assert_eq!(report.deallocations, 64);

    reset();
    let (owner, report) =
        TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| Box::new([5u64; 68]))
            .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Unavailable);
    assert_eq!(report.live, 1);
    assert!(matches!(
        TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| ()),
        Err(AllocationRosterSetupError::Unavailable)
    ));
    drop(owner);

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| {
        drop(std::hint::black_box(Box::new([6u64; 67])));
        drop(std::hint::black_box(Box::new([7u128; 34])));
        let nested = TestAllocationObserver::capture_allocation_roster(|| ());
        assert!(matches!(
            nested,
            Err(AllocationRosterSetupError::AlreadyArmed)
        ));
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(report.allocations, 0);

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |session| {
        let owner = std::hint::black_box(Box::new([8u64; 68]));
        session.pause_allocations().unwrap();
        let worker = std::thread::spawn(move || {
            drop(std::hint::black_box(Box::new([9u64; 80])));
            drop(owner);
        });
        worker.join().unwrap();
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(
        report.allocations, 1,
        "worker requests and paused owner requests are excluded"
    );
    assert_eq!(
        report.deallocations, 1,
        "physical closes remain global through actual join"
    );

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| {
        let mut owner = Vec::<u64>::with_capacity(68);
        owner.extend_from_slice(&[10; 68]);
        owner.reserve(1);
        std::hint::black_box(&owner);
        drop(owner);
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Unavailable);

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |session| {
        let mut owner = Vec::<u64>::with_capacity(68);
        owner.extend_from_slice(&[10; 68]);
        session.pause_allocations().unwrap();
        owner.reserve(1);
        std::hint::black_box(&owner);
        drop(owner);
    })
    .unwrap();
    assert_eq!(
        report.outcome,
        AllocationRosterOutcome::Unavailable,
        "paused owner realloc of a selected original node remains refused"
    );

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |session| {
        let mut owner = Vec::<u64>::with_capacity(68);
        owner.extend_from_slice(&[10; 68]);
        session.pause_allocations().unwrap();
        let worker = std::thread::spawn(move || {
            owner.reserve(1);
            std::hint::black_box(&owner);
            drop(owner);
        });
        worker.join().unwrap();
    })
    .unwrap();
    assert_eq!(
        report.outcome,
        AllocationRosterOutcome::Unavailable,
        "selected worker realloc is refused before System moves original storage"
    );

    reset();
    assert!(matches!(
        TestAllocationObserver::observe_memory_nodes64(&OTHER_COUNTERS, |_| ()),
        Err(AllocationRosterSetupError::Unavailable)
    ));

    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |session| {
        let refused =
            std::thread::scope(|scope| scope.spawn(|| session.pause_allocations()).join().unwrap());
        assert_eq!(
            refused,
            Err(AllocationRosterSetupError::Unavailable),
            "a worker cannot silently clear its own TLS instead of the original owner's capture"
        );
        drop(std::hint::black_box(Box::new([13u64; 68])));
        session.pause_allocations().unwrap();
        assert_eq!(
            session.pause_allocations(),
            Err(AllocationRosterSetupError::Unavailable)
        );
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(
        report.allocations, 1,
        "worker refusal leaves owner request tracking intact"
    );
    assert_eq!(report.deallocations, 1);

    reset();
    let panic = std::panic::catch_unwind(|| {
        TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| {
            let _owner = std::hint::black_box(Box::new([11u64; 68]));
            panic!("original node action unwind");
        })
        .unwrap();
    });
    assert!(panic.is_err());
    assert_eq!(
        ALLOCATIONS.load(Ordering::SeqCst),
        DEALLOCATIONS.load(Ordering::SeqCst)
    );
    reset();
    let (_, report) = TestAllocationObserver::observe_memory_nodes64(&COUNTERS, |_| {
        drop(std::hint::black_box(Box::new([12u64; 80])));
    })
    .unwrap();
    assert_eq!(report.outcome, AllocationRosterOutcome::Complete);
    assert_eq!(report.allocations, 1);
}
