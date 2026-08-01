//! Process-wide admission control for live QEMU callbacks during teardown.
//!
//! Every production callback takes a short in-flight token before touching
//! callback-owned or shared-memory state. The control worker closes admission,
//! wakes parked execution, and waits for the count to reach zero before it
//! publishes `Done`. Sequentially consistent operations make the close versus
//! enter race explicit and keep the teardown proof independent of host time.

use std::sync::atomic::{AtomicU64, Ordering};

const CLOSED: u64 = 1_u64 << 63;
const IN_FLIGHT_MASK: u64 = !CLOSED;

/// Shared callback admission and in-flight accounting state.
#[derive(Debug, Default)]
pub(crate) struct LiveCallbackQuiescence {
    state: AtomicU64,
}

impl LiveCallbackQuiescence {
    /// Creates an open callback admission gate.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    /// Admits one callback unless teardown has closed the gate.
    pub(crate) fn enter(self: &std::sync::Arc<Self>) -> Option<LiveCallbackInFlight> {
        self.enter_with_hook(|| {})
    }

    /// Prevents every later callback from beginning work.
    pub(crate) fn close(&self) {
        self.state.fetch_or(CLOSED, Ordering::SeqCst);
    }

    /// Waits causally until every callback admitted before close has returned.
    pub(crate) fn wait_until_drained(&self) {
        while self.state.load(Ordering::SeqCst) & IN_FLIGHT_MASK != 0 {
            std::thread::yield_now();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_closed(&self) -> bool {
        self.state.load(Ordering::SeqCst) & CLOSED != 0
    }

    fn enter_with_hook(
        self: &std::sync::Arc<Self>,
        after_initial_load: impl FnOnce(),
    ) -> Option<LiveCallbackInFlight> {
        let mut observed = self.state.load(Ordering::SeqCst);
        after_initial_load();
        loop {
            if observed & CLOSED != 0 {
                return None;
            }
            let count = observed & IN_FLIGHT_MASK;
            let Some(next_count) = count.checked_add(1) else {
                std::process::abort();
            };
            if next_count > IN_FLIGHT_MASK {
                std::process::abort();
            }
            match self.state.compare_exchange(
                observed,
                next_count,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_previous) => {
                    return Some(LiveCallbackInFlight {
                        quiescence: std::sync::Arc::clone(self),
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }
}

/// RAII proof that one callback is included in teardown's drain count.
pub(crate) struct LiveCallbackInFlight {
    quiescence: std::sync::Arc<LiveCallbackQuiescence>,
}

impl Drop for LiveCallbackInFlight {
    fn drop(&mut self) {
        let previous = self.quiescence.state.fetch_sub(1, Ordering::SeqCst);
        if previous & IN_FLIGHT_MASK == 0 {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn close_rejects_new_callbacks_and_drain_waits_for_prior_guard() {
        let quiescence = Arc::new(LiveCallbackQuiescence::new());
        let guard = quiescence
            .enter()
            .unwrap_or_else(|| panic!("open gate should admit callback"));
        quiescence.close();
        assert!(quiescence.is_closed());
        assert!(quiescence.enter().is_none());

        let waiter = Arc::clone(&quiescence);
        let joined = std::thread::spawn(move || waiter.wait_until_drained());
        assert!(!joined.is_finished());
        drop(guard);
        joined
            .join()
            .unwrap_or_else(|_panic| panic!("drain waiter should finish"));
    }

    #[test]
    fn close_between_admission_load_and_cas_rejects_the_late_entry() {
        let quiescence = Arc::new(LiveCallbackQuiescence::new());
        let loaded = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let callback_quiescence = Arc::clone(&quiescence);
        let callback_loaded = Arc::clone(&loaded);
        let callback_resume = Arc::clone(&resume);
        let callback = std::thread::spawn(move || {
            callback_quiescence.enter_with_hook(|| {
                callback_loaded.wait();
                callback_resume.wait();
            })
        });

        loaded.wait();
        quiescence.close();
        quiescence.wait_until_drained();
        resume.wait();

        let admission = callback
            .join()
            .unwrap_or_else(|_panic| panic!("callback admission thread should finish"));
        assert!(admission.is_none());
        assert!(quiescence.is_closed());
    }
}
