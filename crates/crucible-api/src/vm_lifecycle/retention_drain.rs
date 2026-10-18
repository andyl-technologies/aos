//! Non-destructive settlement of a production world's final boundary.
//!
//! A world that stops at a stable boundary may be kept as a hot-fork template
//! instead of being torn down. Its attempt must still seal exactly the log a
//! shutdown would have produced. [`ProductionVmLifecycleLoop::drain_final_boundary_for_retention`]
//! settles that boundary without teardown, and declines without side effects
//! whenever ordinary shutdown would report a lifecycle error or discard
//! teardown-only state, so the caller then shuts down as before and observes
//! the same outcome.

use super::*;

impl ProductionVmLifecycleLoop {
    /// Settles the final committed boundary and keeps the world running.
    ///
    /// Returns `Ok(None)`, changing nothing, when the world is not retainable:
    /// it holds unconsumed branch effect choices or signal-fault branches,
    /// unexhausted fault or campaign-effect replay, unconsumed search
    /// overrides, debugger ownership, failed node-lease cleanup, a retained
    /// log that starts after genesis, or scheduler state only teardown may
    /// discard. Otherwise returns the entries that [`QuantumLoop::shutdown`]
    /// would publish for this boundary, already appended to the log. Callers
    /// retain the world only when that list is empty.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fault runtime lock is poisoned or
    /// the boundary cannot be settled. The world must then be shut down.
    pub fn drain_final_boundary_for_retention(
        &mut self,
    ) -> Result<Option<Vec<SchedulerEventLogEntry>>, SchedulerError> {
        if !self.final_boundary_retainable()? {
            return Ok(None);
        }
        self.inner.drain_final_boundary()
    }

    /// Mirrors the checks [`QuantumLoop::shutdown`] reports as failures.
    fn final_boundary_retainable(&self) -> Result<bool, SchedulerError> {
        if self.inner.loop_impl().pending_branch_effect_choice_count() != 0
            || !self.signal_fault_branches.is_empty()
            || self.debug_gateway.is_some()
            || self.debug_attach.is_some()
            || self.debug_gateway_teardown_required
            || self.indeterminate_debug_candidate.is_some()
            || self.node_lease_cleanup_failed
            || self.inner.loop_impl().event_log().retained_base_events() != 0
            || self
                .inner
                .network_output_interceptor()
                .verify_campaign_effect_replay_exhausted()
                .is_err()
        {
            return Ok(false);
        }
        if !self.fault_replay_installed && !self.fault_search_overrides_installed {
            return Ok(true);
        }

        let runtime = self
            .fault_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        let replay_exhausted =
            !self.fault_replay_installed || runtime.verify_replay_exhausted().is_ok();
        let overrides_consumed = !self.fault_search_overrides_installed
            || runtime.verify_search_overrides_consumed().is_ok();
        Ok(replay_exhausted && overrides_consumed)
    }
}

#[cfg(test)]
mod tests;
