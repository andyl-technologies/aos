//! Bounded coherent publication acquisition before host supervision effects.

use super::*;

impl QemuLiveHostIoRuntime {
    pub(super) fn try_node_snapshot(
        &self,
    ) -> Result<Option<crucible_shmem::NodeSlotSnapshot>, QemuAsyncDriverRuntimeError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .try_snapshot())
    }

    /// Keeps an inherited stopped report outside the new RUN's completion.
    pub(super) fn native_console_run_report_pending(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.console_custody.is_some() && self.scheduler_input_publish_generation.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Waits up to one poll interval for the node slot to publish again.
    ///
    /// The plugin does not wake the host when it publishes a boundary, so a
    /// fixed sleep makes every RUN pay a whole interval after the guest has
    /// already stopped. Probing at doubling steps from
    /// [`MINIMUM_PUBLICATION_POLL`] returns within a few microseconds of a new
    /// publication, while an unchanged slot still waits the full interval.
    /// Returns whether the publication changed.
    pub(super) fn wait_for_publication_change(
        &mut self,
        observed: &crucible_shmem::NodeSlotSnapshot,
        remaining: Duration,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let budget = self.poll_interval.min(remaining);
        let mut waited = Duration::ZERO;
        let mut step = MINIMUM_PUBLICATION_POLL;
        while waited < budget {
            let pause = step.min(budget.saturating_sub(waited));
            self.wait_for_poll_interval_capped(pause, pause);
            waited = waited.saturating_add(pause);
            step = step.saturating_mul(2);

            // A contended read means a publication is in progress.
            let changed = self.try_node_snapshot()?.is_none_or(|current| {
                current.publish_gen != observed.publish_gen
                    || current.control_boundary_ack != observed.control_boundary_ack
            });
            if changed {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Retries only under a caller's already-existing control deadline.
    pub(super) fn wait_node_snapshot(
        &mut self,
        mut remaining_budget: impl FnMut() -> Option<Duration>,
    ) -> Result<Option<crucible_shmem::NodeSlotSnapshot>, QemuAsyncDriverRuntimeError> {
        while let Some(remaining) = remaining_budget() {
            if remaining.is_zero() {
                break;
            }
            if let Some(snapshot) = self.try_node_snapshot()? {
                return Ok(Some(snapshot));
            }
            self.wait_for_poll_interval(remaining);
        }
        Ok(None)
    }

    pub(super) fn prepare_publication_budget(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if !self.advance_wait_deadline.start(timeout) {
            return Err(QemuAsyncDriverRuntimeError::new(
                "start advance completion deadline",
                "timeout deadline overflow",
            ));
        }
        self.wait_observation.begin(timeout);
        self.device_wake_publish_generation = None;
        self.checkpoint_idle_coordinate = None;
        self.advance_initial_state_observed = false;
        self.initial_advance_wake_pending = true;
        self.advance_completion_prepared = true;
        Ok(())
    }

    /// Does not service devices, publish a ceiling, or signal either wake path.
    pub(super) fn poll_node_publication(
        &mut self,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let remaining = self.advance_wait_deadline.remaining().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "await node publication",
                "advance budget was not prepared",
            )
        })?;
        let slice = self
            .advance_completion_poll_slice
            .map_or(remaining, |slice| slice.min(remaining));
        let slice_deadline = HostSupervisionDeadline::start(slice);
        loop {
            let remaining = self.advance_wait_deadline.remaining().ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new(
                    "await node publication",
                    "advance budget disappeared",
                )
            })?;
            if remaining.is_zero() {
                return Ok(QemuAsyncWaitOutcome::TimedOut);
            }
            if self.try_node_snapshot()?.is_some() {
                return Ok(QemuAsyncWaitOutcome::Completed);
            }
            let Some(slice_remaining) = slice_deadline
                .remaining()
                .filter(|remaining| !remaining.is_zero())
            else {
                return Ok(QemuAsyncWaitOutcome::Pending);
            };
            self.wait_for_poll_interval(remaining.min(slice_remaining));
        }
    }
}
