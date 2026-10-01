//! Reports opt-in test phases using the operation's actual injected clock.
//!
//! Observations add no storage operation, exclusion or publication authority.
//! Their local scope origins never change the original request deadline.

use crate::store::Clock;
use std::time::Duration;

/// Reports opt-in native test phases without supplying publication authority.
pub(crate) struct PhaseTrace<'a, C: Clock> {
    clock: &'a C,
    reference: String,
    candidate: Option<terrane_core::identity::Digest>,
    started: Duration,
    last: Duration,
    enabled: bool,
}

impl<'a, C: Clock> PhaseTrace<'a, C> {
    /// Starts an opt-in observation from the supplied injected clock.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(crate) fn new(
        clock: &'a C,
        reference: &str,
        candidate: Option<terrane_core::identity::Digest>,
        started: Option<Duration>,
        phase: &str,
    ) -> Self {
        let enabled = std::env::var_os("TERRANE_REF_PHASE_TRACE").is_some();
        let now = if enabled {
            clock.monotonic()
        } else {
            Duration::ZERO
        };
        let mut trace = Self {
            clock,
            reference: reference.to_owned(),
            candidate,
            started: started.unwrap_or(now),
            last: now,
            enabled,
        };
        trace.mark(phase);
        trace
    }

    /// Reports one actual phase boundary when test tracing is enabled.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(crate) fn mark(&mut self, phase: &str) {
        if !self.enabled {
            return;
        }
        let now = self.clock.monotonic();
        eprintln!(
            "ref-phase ref={} candidate={:?} start={:?} at={:?} elapsed={:?} delta={:?} phase={phase}",
            self.reference,
            self.candidate,
            self.started,
            now,
            now.checked_sub(self.started),
            now.checked_sub(self.last),
        );
        self.last = now;
    }
}

impl<C: Clock> Drop for PhaseTrace<'_, C> {
    fn drop(&mut self) {
        self.mark("scope-exit");
    }
}
