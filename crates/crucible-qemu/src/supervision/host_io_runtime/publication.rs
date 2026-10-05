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
