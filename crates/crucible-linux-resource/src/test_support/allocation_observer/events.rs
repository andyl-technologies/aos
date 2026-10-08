//! Records fixed thread-local native allocation and physical close events.
//!
//! The ordered 64-entry buffer preserves the original bootstrap test's scope.
//! Its synchronous action runs outside hooks; hooks record scalar layouts only.
//! Overflow, reallocation and missing events invalidate an original trace.

use std::alloc::Layout;
use std::cell::Cell;

use super::TestAllocationObserver;

const CAPACITY: usize = 64;

/// Records one original allocator request or completed physical free.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationEvent {
    /// Identifies allocation rather than a completed System deallocation.
    pub allocated: bool,
    /// Original requested allocation size.
    pub bytes: usize,
    /// Original native allocation alignment.
    pub alignment: usize,
}

/// Retains the original event order in a fixed 64-entry scalar buffer.
#[derive(Clone, Copy, Debug)]
pub struct AllocationEvents {
    events: [AllocationEvent; CAPACITY],
    /// Retained allocation and deallocation event entries, at most 64.
    pub count: usize,
    /// Native reallocation entries; these invalidate the original fixed trace.
    pub reallocations: usize,
    /// Indicates event capacity or native reallocation count saturation.
    pub overflow: bool,
}

impl AllocationEvents {
    /// Iterates over recorded scalar events in original native order.
    pub fn entries(&self) -> impl Iterator<Item = AllocationEvent> + '_ {
        self.events.iter().take(self.count).copied()
    }
}

#[derive(Clone, Copy)]
struct State {
    armed: bool,
    report: AllocationEvents,
}

const EMPTY: State = State {
    armed: false,
    report: AllocationEvents {
        events: [AllocationEvent {
            allocated: false,
            bytes: 0,
            alignment: 0,
        }; CAPACITY],
        count: 0,
        reallocations: 0,
        overflow: false,
    },
};

thread_local! {
    static EVENTS: Cell<State> = const { Cell::new(EMPTY) };
}

/// Refuses nested or unavailable thread-local native event capture.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocationEventsSetupError {
    /// The current thread already owns an active event capture.
    #[error("allocation events are already armed on this thread")]
    AlreadyArmed,
    /// Thread-local state cannot be accessed during teardown.
    #[error("allocation event capture is unavailable")]
    Unavailable,
}

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        let _ = EVENTS.try_with(|cell| cell.set(EMPTY));
    }
}

impl TestAllocationObserver {
    /// Captures at most 64 ordered native allocation and close events.
    ///
    /// Only the action's current thread contributes events. Allocation entries
    /// follow the original System request; deallocation entries follow actual
    /// System free. Native reallocations are reported separately and must be
    /// rejected before accepting an original allocation/deallocation trace.
    /// Hooks copy scalar layouts without allocating, blocking or reading storage.
    /// Return and unwind clear all state; nested capture preserves the outer arm.
    ///
    /// # Errors
    /// Refuses nested capture or unavailable thread-local state.
    ///
    /// # Panics
    /// Propagates an action panic after disarming and clearing the event buffer.
    pub fn capture_allocation_events<T>(
        action: impl FnOnce() -> T,
    ) -> Result<(T, AllocationEvents), AllocationEventsSetupError> {
        EVENTS
            .try_with(|cell| {
                if cell.get().armed {
                    return Err(AllocationEventsSetupError::AlreadyArmed);
                }
                cell.set(State {
                    armed: true,
                    ..EMPTY
                });
                Ok(())
            })
            .map_err(|_| AllocationEventsSetupError::Unavailable)??;
        let _reset = Reset;
        let value = action();
        let report = EVENTS
            .try_with(|cell| cell.replace(EMPTY).report)
            .map_err(|_| AllocationEventsSetupError::Unavailable)?;
        Ok((value, report))
    }
}

pub(super) fn record(allocated: bool, layout: Layout, reallocation: bool) {
    let _ = EVENTS.try_with(|cell| {
        let mut state = cell.get();
        if !state.armed {
            return;
        }
        if reallocation {
            state.report.overflow |= state.report.reallocations == usize::MAX;
            state.report.reallocations = state.report.reallocations.saturating_add(1);
        } else if let Some(event) = state.report.events.get_mut(state.report.count) {
            *event = AllocationEvent {
                allocated,
                bytes: layout.size(),
                alignment: layout.align(),
            };
            state.report.count += 1;
        } else {
            state.report.overflow = true;
        }
        cell.set(state);
    });
}
