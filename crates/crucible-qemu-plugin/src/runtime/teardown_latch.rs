//! Owns the sole terminal trigger in a fixed, prebirth-priced allocation.
//!
//! The teardown worker consumes one cause. Competing publications preserve that
//! first cause without allocating a queue, and consumer abandonment closes the
//! latch without implying callback, descriptor, or runtime retirement.
// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Condvar, Mutex};

use super::LiveRuntimeTeardownTrigger;

/// Publishes a terminal proof to the actual selected trigger owner.
pub(super) trait TriggerPublisher {
    /// Publishes to the actual retained trigger endpoint.
    ///
    /// # Errors
    /// Preserves the actual disconnected, closed, or poisoned endpoint result.
    fn publish(&self, trigger: LiveRuntimeTeardownTrigger) -> Result<(), ()>;
}

/// Receives the first terminal proof through its actual owning endpoint.
pub(super) trait TriggerConsumer {
    /// Receives through the actual retained endpoint without replacing its cause.
    ///
    /// # Errors
    /// Preserves actual abandonment, disconnection, or poison.
    fn receive_trigger(&self) -> Result<LiveRuntimeTeardownTrigger, ()>;
}

#[derive(Default)]
struct State {
    pending: Option<LiveRuntimeTeardownTrigger>,
    consumed: bool,
    closed: bool,
}

/// Retains the sole pending cause in its actual prebirth-priced shared body.
pub(super) struct LiveRuntimeTeardownRouter {
    state: Mutex<State>,
    available: Condvar,
    #[cfg(test)]
    test_sender: Option<std::sync::mpsc::Sender<LiveRuntimeTeardownTrigger>>,
}

/// Owns the sole consumer and closes publication when that consumer leaves.
pub(super) struct TeardownConsumer {
    router: Arc<LiveRuntimeTeardownRouter>,
}

impl TeardownConsumer {
    /// Receives the retained first cause through the actual same latch.
    ///
    /// # Errors
    /// Preserves the original closed or poisoned latch refusal.
    pub(super) fn receive(&self) -> Result<LiveRuntimeTeardownTrigger, ()> {
        self.router.receive()
    }
}

impl Drop for TeardownConsumer {
    fn drop(&mut self) {
        self.router.close();
    }
}

impl TriggerPublisher for Arc<LiveRuntimeTeardownRouter> {
    fn publish(&self, trigger: LiveRuntimeTeardownTrigger) -> Result<(), ()> {
        self.send(trigger)
    }
}

impl TriggerConsumer for TeardownConsumer {
    fn receive_trigger(&self) -> Result<LiveRuntimeTeardownTrigger, ()> {
        self.receive()
    }
}

#[cfg(test)]
impl TriggerPublisher for std::sync::mpsc::Sender<LiveRuntimeTeardownTrigger> {
    fn publish(&self, trigger: LiveRuntimeTeardownTrigger) -> Result<(), ()> {
        self.send(trigger).map_err(|_| ())
    }
}

#[cfg(test)]
impl TriggerConsumer for std::sync::mpsc::Receiver<LiveRuntimeTeardownTrigger> {
    fn receive_trigger(&self) -> Result<LiveRuntimeTeardownTrigger, ()> {
        self.recv().map_err(|_| ())
    }
}

impl LiveRuntimeTeardownRouter {
    /// Creates the actual fixed owner after its complete allocation is admitted.
    pub(super) fn owned() -> (Arc<Self>, TeardownConsumer) {
        let router = Arc::new(Self {
            state: Mutex::new(State::default()),
            available: Condvar::new(),
            #[cfg(test)]
            test_sender: None,
        });
        // This is the sole consumer constructor. Its fields stay private and
        // it is not Clone; publishers cannot manufacture another receiver.
        let consumer = TeardownConsumer {
            router: Arc::clone(&router),
        };
        (router, consumer)
    }

    /// Routes isolated callback fixtures into their explicitly owned observer.
    #[cfg(test)]
    pub(super) fn new(sender: std::sync::mpsc::Sender<LiveRuntimeTeardownTrigger>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            available: Condvar::new(),
            test_sender: Some(sender),
        })
    }

    /// Publishes the first cause without replacing a concurrently retained cause.
    ///
    /// # Errors
    /// Returns an error for a closed or poisoned actual owner. A later duplicate
    /// while the first cause is pending succeeds without creating another entry.
    pub(super) fn send(&self, trigger: LiveRuntimeTeardownTrigger) -> Result<(), ()> {
        #[cfg(test)]
        if let Some(sender) = self.test_sender.as_ref() {
            return sender.send(trigger).map_err(|_| ());
        }
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.closed {
            return Err(());
        }
        if !state.consumed && state.pending.is_none() {
            state.pending = Some(trigger);
            self.available.notify_one();
        }
        Ok(())
    }

    /// Waits for the sole cause without claiming the consumer has left.
    ///
    /// # Errors
    /// Returns an error for poison or actual consumer abandonment. Closing this
    /// latch does not release a worker quiescence hold or prove physical return.
    fn receive(&self) -> Result<LiveRuntimeTeardownTrigger, ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        loop {
            if let Some(trigger) = state.pending.take() {
                state.consumed = true;
                return Ok(trigger);
            }
            if state.closed || state.consumed {
                return Err(());
            }
            state = self.available.wait(state).map_err(|_| ())?;
        }
    }

    /// Records actual consumer abandonment without inventing a terminal cause.
    pub(super) fn close(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closed = true;
        self.available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cause(diagnostic: &str) -> LiveRuntimeTeardownTrigger {
        LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: diagnostic.to_owned(),
        }
    }

    #[test]
    fn competing_publications_preserve_the_first_actual_cause() {
        let (router, consumer) = LiveRuntimeTeardownRouter::owned();

        assert!(router.send(cause("first")).is_ok());
        assert!(router.send(cause("second")).is_ok());
        let trigger = router
            .receive()
            .unwrap_or_else(|()| panic!("published cause should be retained"));

        assert!(matches!(
            trigger,
            LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "first"
        ));
        // The old receiver stayed connected during teardown. Preserve that
        // successful duplicate send until the actual consumer leaves.
        assert!(router.send(cause("during teardown")).is_ok());
        assert!(router.receive().is_err());

        drop(consumer);
        assert!(router.send(cause("after teardown")).is_err());
    }

    #[test]
    fn abandonment_closes_without_fabricating_a_shutdown_trigger() {
        let (router, consumer) = LiveRuntimeTeardownRouter::owned();

        drop(consumer);

        assert!(router.receive().is_err());
        assert!(router.send(cause("late")).is_err());
    }

    #[test]
    fn actual_closed_owner_retains_an_already_published_cause() {
        let (router, consumer) = LiveRuntimeTeardownRouter::owned();
        assert!(router.send(cause("retained")).is_ok());

        drop(consumer);
        let trigger = router
            .receive()
            .unwrap_or_else(|()| panic!("closing must preserve the pending cause"));

        assert!(matches!(
            trigger,
            LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "retained"
        ));
    }

    #[test]
    fn concurrent_publishers_select_one_cause_without_a_second_queue_entry() {
        let (router, consumer) = LiveRuntimeTeardownRouter::owned();
        let ready = std::sync::Barrier::new(2);

        std::thread::scope(|scope| {
            for diagnostic in ["first contender", "second contender"] {
                let router = &router;
                let ready = &ready;
                scope.spawn(move || {
                    ready.wait();
                    assert!(router.send(cause(diagnostic)).is_ok());
                });
            }
        });
        let trigger = consumer
            .receive()
            .unwrap_or_else(|()| panic!("one actual contender must remain selected"));

        assert!(matches!(
            trigger,
            LiveRuntimeTeardownTrigger::RunControlFault { diagnostic }
                if diagnostic == "first contender" || diagnostic == "second contender"
        ));
        assert!(consumer.receive().is_err());
        assert!(router.send(cause("while consumer retained")).is_ok());

        drop(consumer);
        assert!(router.send(cause("after consumer returned")).is_err());
    }
}
