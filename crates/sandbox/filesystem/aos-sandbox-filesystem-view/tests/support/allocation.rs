//! Single-thread, harness-free requested-byte and allocation-call accounting.
//!
//! Live bytes are counted globally, including allocations before a measured
//! phase. A phase therefore safely observes frees of older allocations. Sizes
//! are Rust layout requests, not allocator overhead, RSS, or realloc's internal
//! old/new storage overlap. Allocation-call counts preserve the original
//! `semantic_no_alloc` attempted-allocation contract. Nested tracking is rejected.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

static TRACKING: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static INVALID: AtomicBool = AtomicBool::new(false);

pub(crate) struct CountingAllocator;

fn replace_bytes(old: usize, new: usize) {
    match LIVE.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
        live.checked_sub(old)?.checked_add(new)
    }) {
        Ok(previous) => {
            // The checked update above proves this arithmetic fits.
            PEAK.fetch_max(previous - old + new, Ordering::SeqCst);
        }
        Err(_) => INVALID.store(true, Ordering::SeqCst),
    }
}

fn count_call() {
    if TRACKING.load(Ordering::SeqCst)
        && CALLS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |calls| {
                calls.checked_add(1)
            })
            .is_err()
    {
        INVALID.store(true, Ordering::SeqCst);
    }
}

// SAFETY: All allocator operations delegate their original pointer/layout to
// System. Atomics never allocate or panic. Failed alloc/realloc preserves live
// accounting; dealloc always removes the original requested layout size.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_call();
        // SAFETY: The caller's valid layout is forwarded unchanged.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            replace_bytes(0, layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_call();
        // SAFETY: The caller's valid layout is forwarded unchanged.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            replace_bytes(0, layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller's live pointer and original layout are unchanged.
        unsafe { System.dealloc(pointer, layout) };
        replace_bytes(layout.size(), 0);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_call();
        // SAFETY: The original pointer/layout and requested size are unchanged.
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        if !replacement.is_null() {
            replace_bytes(layout.size(), size);
        }
        replacement
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(crate) struct AllocationPhase {
    pub baseline_requested_bytes: usize,
    pub live_requested_bytes: usize,
    pub peak_requested_bytes: usize,
    pub allocation_calls: usize,
    pub accounting_valid: bool,
}

pub(crate) fn live_requested_bytes() -> usize {
    LIVE.load(Ordering::SeqCst)
}

struct TrackingGuard;

impl Drop for TrackingGuard {
    fn drop(&mut self) {
        TRACKING.store(false, Ordering::SeqCst);
    }
}

pub(crate) fn measure<T>(operation: impl FnOnce() -> T) -> (T, AllocationPhase) {
    assert!(
        !TRACKING.swap(true, Ordering::SeqCst),
        "nested allocation tracking"
    );
    let guard = TrackingGuard;
    let baseline = live_requested_bytes();
    CALLS.store(0, Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);

    let result = operation();
    drop(guard);
    let phase = AllocationPhase {
        baseline_requested_bytes: baseline,
        live_requested_bytes: live_requested_bytes(),
        peak_requested_bytes: PEAK.load(Ordering::SeqCst),
        allocation_calls: CALLS.load(Ordering::SeqCst),
        accounting_valid: !INVALID.load(Ordering::SeqCst),
    };
    assert!(
        phase.accounting_valid,
        "requested-byte accounting overflow/underflow"
    );
    (result, phase)
}

pub(crate) fn measure_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let (result, phase) = measure(operation);
    (result, phase.allocation_calls)
}
