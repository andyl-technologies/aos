//! Shared fixtures for the runtime allocator tests.

use std::collections::BTreeSet;
use std::thread;

use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};
use crate::heap::arena::HeapObjectKind;

use super::*;

fn assert_last_safepoint(
    state: AllocationSafepointState,
    sequence: u64,
    tier: RuntimeAllocatorTier,
    entrypoint: RuntimeAllocationEntryPoint,
    allocation: ArenaAllocation,
    stats: ArenaStats,
) {
    assert_eq!(state.count(), sequence);
    let event = state.last().expect("safepoint records");
    assert_eq!(event.sequence(), sequence);
    assert_eq!(event.tier(), tier);
    assert_eq!(event.entrypoint(), entrypoint);
    assert_eq!(event.request().entrypoint(), entrypoint);
    assert_eq!(event.kind(), allocation.kind);
    assert_eq!(event.requested_size(), allocation.requested_size);
    assert_eq!(event.reserved_size(), allocation.reserved_size);
    assert_eq!(event.stats_after(), stats);
    assert_eq!(event.heap_chunks_after(), stats.chunks);
    assert_eq!(event.heap_used_bytes_after(), stats.used_bytes);
    assert_eq!(event.heap_reserved_bytes_after(), stats.reserved_bytes);
    assert_eq!(event.heap_mapped_bytes_after(), stats.mapped_bytes);
    assert_eq!(event.gc_poll_reason(), None);
    assert_eq!(event.collector_poll(), None);
    assert_eq!(state.last_safepoint_collector_poll(), None);
}

fn assert_last_request_safepoint(
    state: AllocationSafepointState,
    sequence: u64,
    tier: RuntimeAllocatorTier,
    request: RuntimeAllocationRequest,
    allocation: ArenaAllocation,
    stats: ArenaStats,
) {
    assert_last_safepoint(
        state,
        sequence,
        tier,
        request.entrypoint(),
        allocation,
        stats,
    );
    let event = state.last().expect("safepoint records");
    assert_eq!(event.request(), request);
}

fn memory_budget(bytes: usize) -> HeapMemoryBudget {
    HeapMemoryBudget::new(bytes).expect("budget is non-zero")
}

mod part_1;
mod part_2;
