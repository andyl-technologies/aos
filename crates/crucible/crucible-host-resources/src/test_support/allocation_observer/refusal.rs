//! Refuses one exact test allocation before System owns any backing storage.
//!
//! Fixed thread-local state affects only the calling thread and one matching
//! non-reallocation request. The scoped action must use fallible allocation;
//! infallible Rust allocation handles a null result by aborting the process.

use std::alloc::Layout;
use std::cell::Cell;

use super::TestAllocationObserver;

#[derive(Clone, Copy)]
struct State {
    active: bool,
    layout: Option<Layout>,
    refused: bool,
}

const EMPTY: State = State {
    active: false,
    layout: None,
    refused: false,
};

thread_local! {
    static STATE: Cell<State> = const { Cell::new(EMPTY) };
}

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        let _ = STATE.try_with(|state| state.set(EMPTY));
    }
}

/// Refuses overlapping allocation-failure scopes on the same thread.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocationRefusalSetupError {
    /// An outer action still owns this thread's refusal scope.
    #[error("an allocation refusal scope is already active on this thread")]
    AlreadyActive,
}

impl TestAllocationObserver {
    /// Refuses the first allocation matching the exact size and alignment.
    ///
    /// Only test binaries selecting this allocator observe the injection. The
    /// action must allocate fallibly: an infallible allocation can abort after
    /// refusal. Nonmatching requests and reallocations retain their normal
    /// behavior. The returned flag confirms that the intended condition actually
    /// occurred. Successful System entries can be counted independently using
    /// [`Self::count`]; an injected null return is not a System allocation.
    ///
    /// This controlled test failure establishes no physical memory pressure,
    /// native resource entitlement, or production allocator behavior.
    ///
    /// # Errors
    /// Refuses nesting on this thread without entering the nested action or
    /// changing the original injection, including after its one refusal fires.
    ///
    /// # Panics
    /// Propagates an action panic after clearing the refusal state.
    pub fn refuse_one_allocation<T>(
        layout: Layout,
        action: impl FnOnce() -> T,
    ) -> Result<(T, bool), AllocationRefusalSetupError> {
        STATE.with(|state| {
            if state.get().active {
                return Err(AllocationRefusalSetupError::AlreadyActive);
            }
            state.set(State {
                active: true,
                layout: Some(layout),
                refused: false,
            });
            Ok(())
        })?;
        let _reset = Reset;

        let value = action();
        let refused = STATE.with(|state| state.get().refused);
        Ok((value, refused))
    }
}

pub(super) fn refuse(layout: Layout) -> bool {
    STATE
        .try_with(|state| {
            let mut current = state.get();
            let matches = current.layout.is_some_and(|expected| {
                layout.size() == expected.size() && layout.align() == expected.align()
            });
            if !matches {
                return false;
            }
            current.layout = None;
            current.refused = true;
            state.set(current);
            true
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These scalar controls check hook lifetime. The store's real fallible Vec
    // control separately witnesses entry through the selected global allocator.
    #[test]
    fn exact_layout_fires_once_and_nested_scopes_cannot_replace_it() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        let other = Layout::from_size_align(64, 16).unwrap();
        let ((first, second), reached) =
            TestAllocationObserver::refuse_one_allocation(layout, || {
                assert!(!refuse(other));
                assert_eq!(
                    TestAllocationObserver::refuse_one_allocation(other, || panic!(
                        "nested action"
                    )),
                    Err(AllocationRefusalSetupError::AlreadyActive)
                );
                let first = refuse(layout);
                assert_eq!(
                    TestAllocationObserver::refuse_one_allocation(other, || panic!(
                        "nested action"
                    )),
                    Err(AllocationRefusalSetupError::AlreadyActive)
                );
                (first, refuse(layout))
            })
            .unwrap();

        assert!(first);
        assert!(!second);
        assert!(reached);
        assert!(!refuse(layout));
    }

    #[test]
    fn unmatched_action_and_unwind_clear_the_original_scope() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        let (_, reached) = TestAllocationObserver::refuse_one_allocation(layout, || ()).unwrap();
        assert!(!reached);
        assert!(!refuse(layout));

        let result = std::panic::catch_unwind(|| {
            TestAllocationObserver::refuse_one_allocation(layout, || {
                panic!("intentional action unwind before any selected allocation")
            })
        });
        assert!(result.is_err());
        assert!(!refuse(layout));
        let (_, reached) =
            TestAllocationObserver::refuse_one_allocation(layout, || refuse(layout)).unwrap();
        assert!(reached);
    }

    #[test]
    fn another_threads_matching_request_cannot_consume_the_original() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Thread construction itself may allocate the selected layout. Create
        // it before arming, then exchange only fixed atomic observations.
        let start = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let worker_start = start.clone();
        let worker_done = done.clone();
        let worker = std::thread::spawn(move || {
            while !worker_start.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            let refused = refuse(layout);
            worker_done.store(true, Ordering::Release);
            refused
        });
        let (_, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
            start.store(true, Ordering::Release);
            while !done.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            assert!(refuse(layout));
        })
        .unwrap();

        assert!(!worker.join().unwrap());
        assert!(reached);
        assert!(!refuse(layout));
    }
}
