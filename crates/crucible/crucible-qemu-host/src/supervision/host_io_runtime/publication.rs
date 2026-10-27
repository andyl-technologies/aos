//! Bounded coherent publication acquisition before host supervision effects.

use std::time::Instant;

use super::*;

/// Reads wall time only to bound and account host waits.
// crucible-lint: allow clippy-disallowed-method -- host wait budgets and diagnostics never enter guest clocks, deadlines, or results.
#[allow(clippy::disallowed_methods)]
fn host_wait_clock() -> Instant {
    Instant::now()
}

/// Returns wall time elapsed since `started` for host wait accounting.
// crucible-lint: allow clippy-disallowed-method -- host wait budgets and diagnostics never enter guest clocks, deadlines, or results.
#[allow(clippy::disallowed_methods)]
fn host_wait_elapsed(started: Instant) -> Duration {
    started.elapsed()
}

impl QemuLiveHostIoRuntime {
    pub(super) fn try_node_snapshot(
        &self,
    ) -> Result<Option<crucible_qemu_shmem::NodeSlotSnapshot>, QemuAsyncDriverRuntimeError> {
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

    /// Parks until the plugin publishes again or `backstop` elapses.
    ///
    /// The plugin increments the slot's hostward publication signal after
    /// every node publication and control acknowledgement (shared-memory ABI
    /// 33). A publication since the previous wait returns at once, so the
    /// caller re-reads the slot instead of sleeping through it; otherwise the
    /// thread parks on the signal word. The backstop is only a liveness bound
    /// for writers that publish without signalling, never the normal wake.
    pub(super) fn wait_for_node_publication(&mut self, backstop: Duration) {
        let Ok(slot) = self.region.node_slot(self.vm_slot) else {
            // The next slot read reports the mapping error under its deadline.
            crate::supervision::host_wait_counters::record_sleep(backstop);
            thread::sleep(backstop);
            return;
        };
        let current = slot.host_publication_signal();
        if self.publication_signal_at_last_wait != Some(current) {
            self.publication_signal_at_last_wait = Some(current);
            return;
        }

        let started = host_wait_clock();
        let outcome = slot.wait_host_publication(current, backstop);
        let waited = host_wait_elapsed(started);
        let timed_out = match outcome {
            Ok(crucible_qemu_shmem::HostPublicationWaitOutcome::TimedOut) => true,
            Ok(_) => false,
            Err(_) => {
                // An unexpected futex failure falls back to the bounded sleep.
                let rest = backstop.saturating_sub(waited);
                crate::supervision::host_wait_counters::record_sleep(rest);
                thread::sleep(rest);
                true
            }
        };
        crate::supervision::host_wait_counters::record_futex_wait(waited, timed_out);
        self.publication_signal_at_last_wait = Some(slot.host_publication_signal());
    }

    /// Waits up to one poll interval for the node slot to publish again.
    ///
    /// Each wait parks on the hostward publication signal, so it returns as
    /// soon as the plugin publishes, while an unchanged slot still waits the
    /// full interval. Returns whether the publication changed.
    pub(super) fn wait_for_publication_change(
        &mut self,
        observed: &crucible_qemu_shmem::NodeSlotSnapshot,
        remaining: Duration,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let budget = self.poll_interval.min(remaining);
        let started = host_wait_clock();
        loop {
            let pause = budget.saturating_sub(host_wait_elapsed(started));
            if pause.is_zero() {
                break;
            }
            self.wait_for_poll_interval_capped(pause, pause);

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
    ) -> Result<Option<crucible_qemu_shmem::NodeSlotSnapshot>, QemuAsyncDriverRuntimeError> {
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
