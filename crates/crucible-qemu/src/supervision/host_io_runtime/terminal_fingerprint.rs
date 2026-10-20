//! Terminal-only retirement of an original same-boundary console input grant.
//!
//! The node and runtime must retain the same accepted completion and unchanged
//! physical coordinate. A completed full-body Acceptance precedes the distinct
//! fingerprint Observation; no new RUN, input or guest time is authorized.

use super::*;

impl QemuLiveHostIoRuntime {
    pub(super) fn fence_terminal_console_regrant(
        &mut self,
        completed: Option<crate::QemuCompletedQuantumBoundary>,
        at: crucible::Icount,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        #[cfg(target_os = "linux")]
        {
            let Some(custody) = self.console_custody.clone() else {
                return Ok(());
            };
            let deadline = HostSupervisionDeadline::start(timeout);
            let (pending, snapshot) = self.terminal_regrant_pending_within(
                &custody,
                &deadline,
                "original coherent publication is unavailable",
            )?;
            if !pending {
                return Ok(());
            }

            let completed = completed
                .ok_or_else(|| terminal_error("node lacks its original completed receipt"))?;
            if self.completed_boundary != Some(completed) {
                return Err(terminal_error("node and runtime completed receipts differ"));
            }
            completed
                .validate_terminal_coordinate(
                    self.region.backing_identity(),
                    self.vm_slot,
                    at,
                    snapshot,
                )
                .map_err(|source| terminal_error(source.to_string()))?;
            if !deadline.has_time_remaining() {
                return Err(terminal_error(
                    "original terminal preparation deadline expired",
                ));
            }

            // Reuse the original zero-length full-body pump. It alone consumes
            // the native prefix and retires covered issued receipts. Existing
            // pending pairs were refused above, rather than rewritten here.
            self.fence_terminal_console_completion(&snapshot, &deadline)?;
            let (still_pending, after) = self.terminal_regrant_pending_within(
                &custody,
                &deadline,
                "completed terminal publication is unavailable",
            )?;
            completed
                .validate_terminal_coordinate(
                    self.region.backing_identity(),
                    self.vm_slot,
                    at,
                    after,
                )
                .map_err(|source| terminal_error(source.to_string()))?;
            if still_pending {
                return Err(terminal_error(
                    "original grant remained issued after Acceptance",
                ));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (completed, at, timeout);
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
impl QemuLiveHostIoRuntime {
    /// Joins grant custody with one coherent slot snapshot under `deadline`.
    ///
    /// The join compares a fresh slot read with `snapshot`, so a plugin
    /// republication between the two reads refuses it as unavailable. The
    /// join is read-only, so it retries with a new snapshot under the same
    /// deadline. Every other refusal stays fatal.
    fn terminal_regrant_pending_within(
        &mut self,
        custody: &crate::native_console_owner::ConsoleLaunchCustody,
        deadline: &HostSupervisionDeadline,
        unavailable: &'static str,
    ) -> Result<(bool, crucible_shmem::NodeSlotSnapshot), QemuAsyncDriverRuntimeError> {
        loop {
            let snapshot = self
                .wait_node_snapshot(|| deadline.remaining())?
                .ok_or_else(|| terminal_error(unavailable))?;
            match custody.terminal_regrant_pending(&self.region, snapshot) {
                Ok(pending) => return Ok((pending, snapshot)),
                Err(crate::native_console_owner::ConsoleOwnerError::Unavailable) => {
                    let Some(remaining) = deadline.remaining().filter(|left| !left.is_zero())
                    else {
                        return Err(terminal_error(unavailable));
                    };
                    self.wait_for_clamp_ack_poll(remaining);
                }
                Err(source) => return Err(terminal_error(source.to_string())),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn terminal_error(message: impl Into<String>) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new("prepare terminal console fingerprint", message)
}
