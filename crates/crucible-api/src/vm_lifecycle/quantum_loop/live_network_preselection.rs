//! Completes deferred production evidence after a live-network choice resolves.

use super::*;

impl ProductionVmLifecycleLoop {
    pub(super) fn finish_quantum_after_backend(
        &mut self,
        mut outcome: QuantumOutcome,
        pre_quantum_decisions: Vec<Decision>,
        pre_quantum_appends: Vec<SchedulerEventLogAppend>,
        signal_fault_frontier_start: usize,
    ) -> Result<QuantumOutcome, SchedulerError> {
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
        if !pre_quantum_decisions.is_empty() {
            let mut decisions = pre_quantum_decisions;
            decisions.extend(std::mem::take(&mut outcome.decisions));
            outcome.decisions = decisions;
        }
        prepend_event_log_appends(&mut outcome, pre_quantum_appends);
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
