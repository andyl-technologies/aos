//! Hostward publication wake on the node slot's publication futex word.
//!
//! The plugin publishes node state under the `publish_gen` seqlock and the
//! control-boundary ACK word. A host thread that is waiting for the next such
//! publication parks on `host_publication_signal` instead of sleeping for a
//! fixed poll interval:
//!
//! ```text
//! writer (plugin)                       waiter (host)
//! close publication / ACK               waiters += 1            (SeqCst)
//! signal += 1               (SeqCst)    if signal != observed -> return
//! if waiters != 0 -> FUTEX_WAKE         FUTEX_WAIT(signal, observed, timeout)
//!                                       waiters -= 1
//! ```
//!
//! Both sides use sequentially consistent operations, so either the waiter
//! sees the new signal value before parking or the writer sees the waiter and
//! wakes it; the kernel's expected-value comparison closes the remaining gap.
//!
//! The word is a notification only. It carries no time, permission, or
//! publication content: every wake is followed by the waiter's ordinary
//! coherent snapshot and validation. A failed wake is ignored because the
//! waiter's bounded timeout is the liveness backstop, never the normal path.

use std::time::Duration;

use super::control_boundary_wait::wait_word_with_timeout;
use super::*;

/// Result of one bounded wait for the next hostward node publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPublicationWaitOutcome {
    /// A publication completed after `observed` was sampled; no wait occurred.
    AlreadyPublished,
    /// A publication woke the waiter; the caller must re-read the slot.
    Woken,
    /// A signal interrupted the wait; the caller's deadline remains in force.
    Interrupted,
    /// The liveness backstop elapsed without a publication wake.
    TimedOut,
}

impl NodeSlot {
    /// Returns the current hostward publication signal value.
    ///
    /// A host samples this before reading the slot and passes it to
    /// [`Self::wait_host_publication`], so a publication between the read and
    /// the wait is never slept through.
    #[must_use]
    pub fn host_publication_signal(&self) -> u32 {
        self.host_publication_signal.load(Ordering::SeqCst)
    }

    /// Waits once for a node publication after `observed`, at most `backstop`.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] for an unexpected futex error or a timeout that
    /// cannot be represented. Non-Linux tooling builds cannot park and report
    /// an unsupported wait.
    pub fn wait_host_publication(
        &self,
        observed: u32,
        backstop: Duration,
    ) -> Result<HostPublicationWaitOutcome, FutexError> {
        self.host_publication_waiters.fetch_add(1, Ordering::SeqCst);
        let outcome = if self.host_publication_signal.load(Ordering::SeqCst) == observed {
            wait_word_with_timeout(
                &self.host_publication_signal,
                observed,
                backstop,
                "host publication FUTEX_WAIT",
            )
            .map(|outcome| match outcome {
                ControlBoundaryWaitOutcome::ValueChanged => {
                    HostPublicationWaitOutcome::AlreadyPublished
                }
                ControlBoundaryWaitOutcome::Woken => HostPublicationWaitOutcome::Woken,
                ControlBoundaryWaitOutcome::Interrupted => HostPublicationWaitOutcome::Interrupted,
                ControlBoundaryWaitOutcome::TimedOut => HostPublicationWaitOutcome::TimedOut,
            })
        } else {
            Ok(HostPublicationWaitOutcome::AlreadyPublished)
        };
        self.host_publication_waiters.fetch_sub(1, Ordering::SeqCst);
        outcome
    }

    /// Closes one node-state publication and notifies parked host waiters.
    pub(super) fn close_node_publication(&self) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.signal_host_publication();
    }

    /// Notifies parked host waiters that a coherent publication completed.
    pub(super) fn signal_host_publication(&self) {
        self.host_publication_signal.fetch_add(1, Ordering::SeqCst);
        if self.host_publication_waiters.load(Ordering::SeqCst) != 0 {
            // Notification only: the waiter's bounded timeout covers a failed wake.
            let _ = futex::futex_wake_nonprivate(&self.host_publication_signal, 0x7fff_ffff);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_publication_after_sampling_is_never_slept_through() -> TestResult {
        let slot = NodeSlot::new(KIND_VM);
        let observed = slot.host_publication_signal();

        slot.mark_running();

        // The backstop is far beyond the test's run time, so only the
        // pre-park comparison can end this wait.
        let outcome = slot.wait_host_publication(observed, Duration::from_secs(3600))?;
        assert_eq!(outcome, HostPublicationWaitOutcome::AlreadyPublished);
        assert_eq!(slot.host_publication_waiters.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn the_backstop_bounds_a_wait_without_publication() -> TestResult {
        let slot = NodeSlot::new(KIND_VM);
        let observed = slot.host_publication_signal();

        let outcome = slot.wait_host_publication(observed, Duration::from_millis(1))?;

        assert_eq!(outcome, HostPublicationWaitOutcome::TimedOut);
        assert_eq!(slot.host_publication_signal(), observed);
        Ok(())
    }

    #[test]
    fn a_node_publication_wakes_a_parked_host() -> TestResult {
        let slot = Arc::new(NodeSlot::new(KIND_VM));
        let observed = slot.host_publication_signal();
        let waiter = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || slot.wait_host_publication(observed, Duration::from_secs(3600)))
        };
        // Publish only once the waiter is registered, so the writer sees it
        // and wakes it rather than relying on the backstop.
        while slot.host_publication_waiters.load(Ordering::SeqCst) == 0 {
            std::hint::spin_loop();
        }

        slot.mark_done();

        let outcome = waiter.join().map_err(|_| "waiter thread panicked")??;
        assert!(matches!(
            outcome,
            HostPublicationWaitOutcome::Woken | HostPublicationWaitOutcome::AlreadyPublished
        ));
        assert_ne!(slot.host_publication_signal(), observed);
        Ok(())
    }

    #[test]
    fn a_control_acknowledgement_signals_the_host() -> TestResult {
        let slot = NodeSlot::new(KIND_VM);
        // An even token is a pending host request; the plugin acknowledges it.
        slot.control_boundary_ack.store(2, Ordering::Release);
        let observed = slot.host_publication_signal();

        slot.acknowledge_control_boundary_and_notify()?;

        assert_eq!(slot.control_boundary_token(), 3);
        assert_ne!(slot.host_publication_signal(), observed);
        Ok(())
    }
}
