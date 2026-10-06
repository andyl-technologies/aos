//! Live cleanup budgets across the five process-containment phases.

use std::time::Instant;

use crucible_linux_resource::host_supervision::HostOperationClass;

use super::*;

impl QemuNodeShutdownTarget<'_> {
    // Host time bounds physical cleanup only; it never orders guest events.
    // crucible-lint: allow host-nondeterminism-state -- cleanup retains process ownership until authenticated reap.
    // crucible-lint: allow clippy-disallowed-method -- monotonic host time bounds physical cleanup phases without changing modeled state.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn wait_for_live_exit(&mut self) -> Result<QemuChildWait, QemuShutdownTargetError> {
        let guard = self.guard.ok_or_else(|| {
            QemuShutdownTargetError::new("wait for cleanup", "live cleanup guard is absent")
        })?;
        let supervisor = self.supervisor.ok_or_else(|| {
            QemuShutdownTargetError::new("wait for cleanup", "live cleanup owner is absent")
        })?;
        let started = Instant::now();
        loop {
            guard.wait_slice().map_err(|source| {
                QemuShutdownTargetError::new("wait for cleanup", source.to_string())
            })?;
            if self.child.reaped() || self.child.try_wait_natural_exit()?.is_some() {
                return Ok(QemuChildWait::Exited);
            }

            // Each phase gets a fifth of the current finite class allowance.
            // Recompute after updates without restarting this phase or the
            // enclosing cleanup operation. Exhaustion advances containment;
            // the original total deadline still bounds the complete ladder.
            let (_, budgets) = supervisor.budgets().map_err(|source| {
                QemuShutdownTargetError::new("observe cleanup policy", source.to_string())
            })?;
            let budget = budgets.classes[HostOperationClass::Cleanup as usize];
            let allowance = [budget.total_timeout, budget.progress_timeout]
                .into_iter()
                .flatten()
                .min()
                .ok_or_else(|| {
                    QemuShutdownTargetError::new(
                        "observe cleanup policy",
                        "cleanup has no finite class allowance",
                    )
                })?;
            if started.elapsed() >= allowance / 5 {
                return Ok(QemuChildWait::StillRunning);
            }
            guard.wait_for_change().map_err(|source| {
                QemuShutdownTargetError::new("wait for cleanup", source.to_string())
            })?;
        }
    }
}
