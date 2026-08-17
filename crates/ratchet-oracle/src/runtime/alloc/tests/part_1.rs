//! Runtime allocator tests (part 1), split from `super`.

use super::super::*;
use super::*;

#[test]
fn tier_a_allocator_routes_every_entrypoint() {
    let mut allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");

    assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
    assert!(allocator.gc_stress_policy().is_disabled());
    assert_eq!(
        allocator.allocation_safepoints(),
        AllocationSafepointState::default()
    );
    let allocation = allocator.aos_alloc_thunk().expect("thunk allocates");
    assert_eq!(allocation.kind, HeapObjectKind::Thunk);
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        1,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocThunk,
        allocation,
        allocator.stats(),
    );

    let allocation = allocator.aos_alloc_lambda().expect("lambda allocates");
    assert_eq!(allocation.kind, HeapObjectKind::Lambda);
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        2,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocLambda,
        allocation,
        allocator.stats(),
    );

    let allocation = allocator.aos_alloc_attrs(7, 2).expect("attrs allocates");
    assert_eq!(
        allocation.kind,
        HeapObjectKind::Attrs { shape: 7, slots: 2 }
    );
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        3,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocAttrs,
        allocation,
        allocator.stats(),
    );

    let allocation = allocator.aos_alloc_cons().expect("cons allocates");
    assert_eq!(allocation.kind, HeapObjectKind::Cons);
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        4,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocCons,
        allocation,
        allocator.stats(),
    );

    let allocation = allocator.aos_alloc_list(3).expect("list allocates");
    assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        5,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocList,
        allocation,
        allocator.stats(),
    );

    let allocation = allocator.aos_alloc_string(5).expect("string allocates");
    assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        6,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocString,
        allocation,
        allocator.stats(),
    );

    let allocation = allocator
        .aos_alloc_raw(8, 8, 0x7261_7770)
        .expect("raw allocates");
    assert_eq!(
        allocation.kind,
        HeapObjectKind::Raw {
            type_tag: 0x7261_7770,
        }
    );
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        7,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocRaw,
        allocation,
        allocator.stats(),
    );

    let stats = allocator.stats();
    assert_eq!(stats.chunks, 1);
    assert!(stats.used_bytes > 0);
}

#[test]
fn tier_a_allocator_dispatches_typed_allocation_requests() {
    let mut allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");
    let requests = [
        (
            RuntimeAllocationRequest::Attrs { shape: 7, slots: 2 },
            HeapObjectKind::Attrs { shape: 7, slots: 2 },
        ),
        (RuntimeAllocationRequest::Cons, HeapObjectKind::Cons),
        (RuntimeAllocationRequest::Lambda, HeapObjectKind::Lambda),
        (
            RuntimeAllocationRequest::List { len: 3 },
            HeapObjectKind::List { len: 3 },
        ),
        (
            RuntimeAllocationRequest::Raw {
                size: 8,
                align: 8,
                type_tag: 0x7261_7770,
            },
            HeapObjectKind::Raw {
                type_tag: 0x7261_7770,
            },
        ),
        (
            RuntimeAllocationRequest::String { len: 5 },
            HeapObjectKind::String { len: 5 },
        ),
        (RuntimeAllocationRequest::Thunk, HeapObjectKind::Thunk),
    ];

    assert_eq!(
        requests
            .iter()
            .map(|(request, _)| request.entrypoint())
            .collect::<Vec<_>>(),
        runtime_allocation_entrypoints()
    );

    for (index, (request, expected_kind)) in requests.into_iter().enumerate() {
        assert_eq!(request.symbol_name(), request.entrypoint().symbol_name());
        let allocation = allocator
            .allocate(request)
            .expect("typed request allocates");
        assert_eq!(allocation.kind, expected_kind);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            u64::try_from(index + 1).expect("request index fits in u64"),
            RuntimeAllocatorTier::TierAOneShot,
            request.entrypoint(),
            allocation,
            allocator.stats(),
        );
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last()
                .expect("safepoint records")
                .request(),
            request
        );
    }
}

#[test]
fn allocation_safepoint_classifies_high_water_memory_budget() {
    let mut allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
    let request = RuntimeAllocationRequest::Raw {
        size: 16,
        align: 8,
        type_tag: 0x7261_7770,
    };
    allocator
        .allocate(request)
        .expect("raw allocation succeeds");
    let state = allocator.allocation_safepoints();
    let safepoint = state.last().expect("safepoint records");
    let mapped_bytes = safepoint.heap_mapped_bytes_after();
    assert!(mapped_bytes > 1);

    let loose_budget = memory_budget(mapped_bytes.checked_mul(2).expect("budget doubles"));
    let continue_decision = safepoint.classify_memory_budget(loose_budget, 0, 0);
    assert_eq!(continue_decision.sequence(), safepoint.sequence());
    assert_eq!(continue_decision.tier(), RuntimeAllocatorTier::TierAOneShot);
    assert_eq!(
        continue_decision.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocRaw
    );
    assert_eq!(safepoint.request(), request);
    assert_eq!(continue_decision.request(), request);
    assert_eq!(continue_decision.budget(), loose_budget);
    assert_eq!(
        continue_decision.sample(),
        HeapMemorySample::new(mapped_bytes, 0, 0)
    );
    assert_eq!(continue_decision.stats_after(), safepoint.stats_after());
    assert_eq!(
        continue_decision.response(),
        HeapMemoryBudgetResponse::ContinueTierA {
            headroom_bytes: loose_budget.soft_limit_bytes() - mapped_bytes,
            projected_resident_bytes: mapped_bytes,
        }
    );
    assert!(!continue_decision.requires_runtime_action());
    assert!(!continue_decision.requests_tier_b());

    let spill_budget = memory_budget(mapped_bytes);
    let spill_reclaim_bytes = mapped_bytes - spill_budget.soft_limit_bytes();
    let spill_decision = state
        .last_memory_budget_decision(spill_budget, spill_reclaim_bytes, 0)
        .expect("last safepoint classifies");
    assert_eq!(spill_decision.request(), request);
    assert_eq!(
        spill_decision.sample(),
        HeapMemorySample::new(mapped_bytes, spill_reclaim_bytes, 0)
    );
    assert_eq!(
        spill_decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes: spill_reclaim_bytes,
            available_reclaim_bytes: spill_reclaim_bytes,
            projected_resident_bytes: spill_budget.soft_limit_bytes(),
        }
    );
    assert!(spill_decision.requires_runtime_action());
    assert!(!spill_decision.requests_tier_b());

    let tier_b_budget = memory_budget(mapped_bytes / 2);
    let tier_b_decision = safepoint.classify_memory_budget(tier_b_budget, 0, 0);
    assert_eq!(tier_b_decision.request(), request);
    assert_eq!(
        tier_b_decision.response(),
        HeapMemoryBudgetResponse::InstallTierB {
            desired_reclaim_bytes: mapped_bytes - tier_b_budget.soft_limit_bytes(),
            available_reclaim_bytes: 0,
            projected_resident_bytes: mapped_bytes,
            over_budget_bytes: mapped_bytes - tier_b_budget.max_resident_bytes(),
        }
    );
    assert!(tier_b_decision.requires_runtime_action());
    assert!(tier_b_decision.requests_tier_b());

    assert_eq!(
        AllocationSafepointState::default().last_memory_budget_decision(loose_budget, 0, 0),
        None
    );
}

#[test]
fn runtime_allocators_report_unused_tail_advice() {
    let mut worker =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(65536).expect("worker creates");
    worker.aos_alloc_thunk().expect("worker allocates");
    let worker_supported_tail_advice_bytes = worker.supported_unused_tail_advice_bytes();

    let worker_report = worker.advise_unused_tail(MemoryAdviceKind::Dead);

    assert_eq!(worker_report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(worker_report.chunks(), 1);
    assert!(worker_report.requested_bytes() > 0);
    #[cfg(target_os = "linux")]
    assert!(worker_supported_tail_advice_bytes > 0);
    #[cfg(not(target_os = "linux"))]
    assert_eq!(worker_supported_tail_advice_bytes, 0);
    assert!(worker_supported_tail_advice_bytes <= worker_report.requested_bytes());
    assert_eq!(
        worker_report.applied()
            + worker_report.unsupported()
            + worker_report.empty_ranges()
            + worker_report.rejected(),
        1
    );

    let mut permanent =
        PermanentSharedAllocator::with_initial_chunk_bytes(65536).expect("permanent creates");
    permanent
        .test_alloc_string(1)
        .expect("permanent string allocates");
    let permanent_supported_tail_advice_bytes = permanent.supported_unused_tail_advice_bytes();

    let permanent_report = permanent.advise_unused_tail(MemoryAdviceKind::Dead);

    assert_eq!(permanent_report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(permanent_report.chunks(), 1);
    assert!(permanent_report.requested_bytes() > 0);
    #[cfg(target_os = "linux")]
    assert!(permanent_supported_tail_advice_bytes > 0);
    #[cfg(not(target_os = "linux"))]
    assert_eq!(permanent_supported_tail_advice_bytes, 0);
    assert!(permanent_supported_tail_advice_bytes <= permanent_report.requested_bytes());
    assert_eq!(
        permanent_report.applied()
            + permanent_report.unsupported()
            + permanent_report.empty_ranges()
            + permanent_report.rejected(),
        1
    );
}

#[test]
fn worker_allocator_reset_drops_worker_chunks_without_touching_permanent_storage() {
    let mut worker =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("worker creates");
    let mut permanent =
        PermanentSharedAllocator::with_initial_chunk_bytes(128).expect("permanent creates");
    worker.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    worker.aos_alloc_thunk().expect("worker allocates");
    permanent
        .test_alloc_string(5)
        .expect("permanent string allocates");
    let worker_stats_before = worker.stats();
    let permanent_stats_before = permanent.stats();
    let permanent_safepoints_before = permanent.allocation_safepoints();

    let dropped_worker_stats = worker.reset_to_empty();

    assert_eq!(dropped_worker_stats, worker_stats_before);
    assert_eq!(worker.stats(), ArenaStats::default());
    assert_eq!(
        worker.allocation_safepoints(),
        AllocationSafepointState::default()
    );
    assert_eq!(worker.gc_stress_policy(), GcStressPolicy::every_safepoint());
    assert_eq!(permanent.stats(), permanent_stats_before);
    assert_eq!(
        permanent.allocation_safepoints(),
        permanent_safepoints_before
    );

    permanent
        .test_alloc_string(7)
        .expect("permanent allocator remains usable after worker reset");
    assert_eq!(permanent.allocation_safepoints().count(), 2);
    assert!(permanent.stats().used_bytes > permanent_stats_before.used_bytes);
}

#[test]
fn runtime_abi_declares_allocator_entrypoint_names() {
    let allocation_symbols = runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| symbol.role() == RuntimeHelperRole::Allocation)
        .map(|symbol| symbol.name())
        .collect::<BTreeSet<_>>();
    let runtime_entrypoint_symbols = runtime_allocation_entrypoints()
        .iter()
        .copied()
        .map(RuntimeAllocationEntryPoint::symbol_name)
        .collect::<BTreeSet<_>>();
    let runtime_signature_symbols = runtime_allocation_abi_signatures()
        .iter()
        .copied()
        .map(RuntimeAllocationAbiSignature::symbol_name)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        allocation_symbols,
        BTreeSet::from([
            "aos_alloc_attrs",
            "aos_alloc_cons",
            "aos_alloc_lambda",
            "aos_alloc_list",
            "aos_alloc_raw",
            "aos_alloc_string",
            "aos_alloc_thunk",
        ])
    );
    assert_eq!(runtime_entrypoint_symbols, allocation_symbols);
    assert_eq!(runtime_signature_symbols, allocation_symbols);
}

#[test]
fn runtime_allocator_selects_tier_a_allocation_vtable() {
    let default_allocator = RuntimeAllocator::default();
    let configured_allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");
    let thread_local_allocator = RuntimeAllocator::tier_a_thread_local();

    for allocator in [
        &default_allocator,
        &configured_allocator,
        &thread_local_allocator,
    ] {
        let vtable = allocator.allocation_vtable();

        assert_eq!(vtable.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(vtable.entrypoints(), runtime_allocation_entrypoints());
        assert_eq!(vtable.abi_signatures(), runtime_allocation_abi_signatures());
    }
}

#[test]
fn tier_a_thread_local_allocator_routes_allocations_and_reset() {
    ThreadLocalBumpArena::reset_current();
    let mut allocator = RuntimeAllocator::tier_a_thread_local();

    assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
    assert_eq!(allocator.stats(), ArenaStats::default());

    let allocation = allocator
        .aos_alloc_string(5)
        .expect("thread-local string allocates");
    let stats = allocator.stats();
    assert_eq!(
        ThreadLocalBumpArena::with_current(|arena| arena.stats()),
        stats
    );
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        1,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocString,
        allocation,
        stats,
    );

    let worker = thread::spawn(|| {
        ThreadLocalBumpArena::reset_current();
        let before = ThreadLocalBumpArena::with_current(|arena| arena.stats());
        let mut allocator = RuntimeAllocator::tier_a_thread_local();
        allocator
            .aos_alloc_thunk()
            .expect("worker thread-local thunk allocates");
        let after = allocator.stats();
        ThreadLocalBumpArena::reset_current();
        (before, after)
    })
    .join()
    .expect("worker thread joins");
    assert_eq!(worker.0, ArenaStats::default());
    assert!(worker.1.chunks > 0);
    assert_eq!(allocator.stats(), stats);

    let dropped = allocator.reset_to_empty();
    assert_eq!(dropped, stats);
    assert_eq!(allocator.stats(), ArenaStats::default());
    assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
    ThreadLocalBumpArena::reset_current();
}

#[test]
#[should_panic(expected = "thread already has an active thread-local runtime allocator")]
fn tier_a_thread_local_allocator_rejects_same_thread_sharing() {
    ThreadLocalBumpArena::reset_current();
    let _first = RuntimeAllocator::tier_a_thread_local();
    let _second = RuntimeAllocator::tier_a_thread_local();
}

#[test]
fn tier_a_thread_local_allocator_rejects_cross_thread_use() {
    ThreadLocalBumpArena::reset_current();
    let allocator = RuntimeAllocator::tier_a_thread_local();

    let rejected = thread::spawn(move || std::panic::catch_unwind(|| allocator.stats()).is_err())
        .join()
        .expect("worker thread joins");
    assert!(rejected);

    let replacement = RuntimeAllocator::tier_a_thread_local();
    assert_eq!(replacement.stats(), ArenaStats::default());
    drop(replacement);
    ThreadLocalBumpArena::reset_current();
}

#[test]
fn tier_a_thread_local_allocator_region_pop_rewinds_current_thread_arena() {
    ThreadLocalBumpArena::reset_current();
    let mut allocator = RuntimeAllocator::tier_a_thread_local();

    allocator
        .aos_alloc_raw(16, 8, 1)
        .expect("first raw allocation succeeds");
    let mark = allocator.region_mark();
    allocator
        .aos_alloc_raw(24, 8, 2)
        .expect("second raw allocation succeeds");
    let before = allocator.stats();
    assert!(before.used_bytes > mark.arena().cursor());

    let report = allocator
        .pop_caller_validated_region(mark, 0)
        .expect("region pop succeeds");

    assert_eq!(report.before_stats(), before);
    assert_eq!(report.after_stats(), allocator.stats());
    assert_eq!(allocator.allocation_safepoints(), mark.safepoints());
    assert_eq!(
        ThreadLocalBumpArena::with_current(|arena| arena.stats()),
        report.after_stats()
    );
    drop(allocator);
    ThreadLocalBumpArena::reset_current();
}

#[test]
fn tier_a_thread_local_allocator_records_gc_stress_poll_reason() {
    ThreadLocalBumpArena::reset_current();
    let mut allocator = RuntimeAllocator::tier_a_thread_local()
        .with_gc_stress_policy(GcStressPolicy::every_safepoint());

    allocator
        .aos_alloc_thunk()
        .expect("thread-local thunk allocates");

    let poll = allocator
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("thread-local safepoint records poll");
    assert_eq!(poll.sequence(), 1);
    assert_eq!(poll.tier(), RuntimeAllocatorTier::TierAOneShot);
    assert_eq!(
        poll.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert_eq!(poll.stats_after(), allocator.stats());
    drop(allocator);
    ThreadLocalBumpArena::reset_current();
}
