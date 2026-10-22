//! Measures allocation calls on the current thread for metadata-path proofs.
//!
//! The allocator wrapper exists only in test artifacts. It checks the RFC's
//! explicit allocation constraint, including the first touched inode.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
}

fn record() {
    let _ = ENABLED.try_with(|enabled| {
        if enabled.get() {
            let _ = CALLS.try_with(|calls| calls.set(calls.get().saturating_add(1)));
        }
    });
}

// SAFETY: every operation forwards its original arguments to System unchanged.
// The nonallocating, thread-local counter never inspects or retains pointers.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: the caller's valid layout is forwarded to System unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: the caller's valid layout is forwarded to System unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: System receives the same allocated pointer and layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        // SAFETY: the caller's pointer, prior layout and new size are unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

pub(super) fn measure<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    assert!(!ENABLED.with(Cell::get), "nested allocation measurement");
    CALLS.with(|calls| calls.set(0));
    ENABLED.with(|enabled| enabled.set(true));

    struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            ENABLED.with(|enabled| enabled.set(false));
        }
    }

    let guard = Guard;
    let result = operation();
    drop(guard);
    (result, CALLS.with(Cell::get))
}
