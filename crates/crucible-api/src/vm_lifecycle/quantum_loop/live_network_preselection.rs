//! Completes deferred production evidence after a live-network choice resolves.

use super::*;

impl ProductionVmLifecycleLoop {
    pub(super) fn finish_quantum_after_backend(
        &mut self,
        mut outcome: QuantumOutcome,
        prefix: PendingLiveNetworkPrefix,
    ) -> Result<QuantumOutcome, SchedulerError> {
        let PendingLiveNetworkPrefix {
            decisions,
            appends,
            discoveries,
            signal_fault_frontier_start,
        } = prefix;
        let observations = Arc::clone(&self.storage_fault_observations);
        let mut queued = observations
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault observation journal lock is poisoned"),
            })?;
        let storage_observations = queued.drain_ready(
            self.inner
                .loop_impl()
                .condition_event_log_prefix()
                .point()
                .at()
                .ticks,
        );
        if !storage_observations.is_empty() {
            let append = self
                .inner
                .loop_impl_mut()
                .append_fault_observations(storage_observations)?;
            merge_event_log_append(&mut outcome, append);
        }
        drop(queued);

        let pending_search_choices = self
            .fault_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?
            .drain_search_choices();
        self.inner
            .loop_impl_mut()
            .record_pending_signal_fault_search_frontiers(pending_search_choices)?;
        if !decisions.is_empty() {
            let mut prefix_decisions = decisions;
            prefix_decisions.extend(std::mem::take(&mut outcome.decisions));
            outcome.decisions = prefix_decisions;
        }
        if !discoveries.is_empty() {
            let mut prefix_discoveries = discoveries;
            prefix_discoveries.extend(std::mem::take(&mut outcome.discovered_choices));
            outcome.discovered_choices = prefix_discoveries;
        }
        prepend_event_log_appends(&mut outcome, appends);
        for append in self.settle_trigger_graph()? {
            merge_event_log_append(&mut outcome, append);
        }
        self.append_live_signal_fault_campaign_discoveries(
            signal_fault_frontier_start,
            &mut outcome,
        )?;
        self.capture_debug_runtime_evidence()?;
        Ok(outcome)
    }
}
