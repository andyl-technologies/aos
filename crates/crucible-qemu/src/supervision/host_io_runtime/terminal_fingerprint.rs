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
            let snapshot = self
                .wait_node_snapshot(|| deadline.remaining())?
                .ok_or_else(|| terminal_error("original coherent publication is unavailable"))?;
            let pending = custody
                .terminal_regrant_pending(&self.region, snapshot)
                .map_err(|source| terminal_error(source.to_string()))?;
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
            let after = self
                .wait_node_snapshot(|| deadline.remaining())?
                .ok_or_else(|| terminal_error("completed terminal publication is unavailable"))?;
            completed
                .validate_terminal_coordinate(
                    self.region.backing_identity(),
                    self.vm_slot,
                    at,
                    after,
                )
                .map_err(|source| terminal_error(source.to_string()))?;
            if custody
                .terminal_regrant_pending(&self.region, after)
                .map_err(|source| terminal_error(source.to_string()))?
            {
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
fn terminal_error(message: impl Into<String>) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new("prepare terminal console fingerprint", message)
}
