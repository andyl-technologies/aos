//! Retains one child cleanup Original and its physical shutdown disposition.
//!
//! Reporting logical failure never restarts the guard or the ladder. Reap and
//! completion are journaled before the guard is retired; later factual closure
//! retains negative health independently of physical resource return.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};

#[derive(Debug)]
/// Owns the sole cleanup entry and all bounded child-shutdown observations.
pub(super) struct ChildShutdown {
    progress: crate::shutdown::QemuShutdownProgress,
    begin_attempted: bool,
    begin_returned: bool,
    guard: Option<HostOperationGuard>,
    begin_failure: Option<HostSupervisionError>,
    observations: [(Option<HostSupervisionError>, Option<HostSupervisionError>); 5],
    completion_attempted: bool,
    completion_returned: bool,
    completion_effect: bool,
    completion_failure: Option<HostSupervisionError>,
    ladder_attempted: bool,
    history_version: u8,
    reported_version: u8,
}

impl ChildShutdown {
    /// Creates the unentered owner before the containing node is published.
    pub(super) const fn new() -> Self {
        Self {
            progress: crate::shutdown::QemuShutdownProgress::new(),
            begin_attempted: false,
            begin_returned: false,
            guard: None,
            begin_failure: None,
            observations: [(None, None); 5],
            completion_attempted: false,
            completion_returned: false,
            completion_effect: false,
            completion_failure: None,
            ladder_attempted: false,
            history_version: 0,
            reported_version: 0,
        }
    }

    fn begin(&mut self, supervisor: Option<&HostOperationSupervisor>) {
        if self.begin_attempted {
            return;
        }
        self.begin_attempted = true;
        self.history_version += 1;
        match supervisor
            .map(|owner| owner.begin(HostOperationClass::Cleanup))
            .transpose()
        {
            Ok(guard) => self.guard = guard,
            Err(first) => self.begin_failure = Some(first),
        }
        self.begin_returned = true;
    }

    fn failed(&self) -> bool {
        (self.begin_attempted && !self.begin_returned)
            || (self.completion_attempted && !self.completion_returned)
            || self.begin_failure.is_some()
            || self
                .observations
                .iter()
                .any(|(before, after)| before.is_some() || after.is_some())
            || self.completion_failure.is_some()
            || self.progress.failed()
    }

    /// Preserves logical failure independently of physical resource closure.
    ///
    /// # Errors
    /// Returns the saved Original, rung, completion or interrupted disposition.
    pub(super) fn health(&self) -> Result<(), QemuNodeError> {
        if (self.begin_attempted && !self.begin_returned)
            || (self.completion_attempted && !self.completion_returned)
        {
            return Err(QemuNodeError::from_shutdown(
                crate::QemuShutdownError::Uncertain {
                    rung: if !self.begin_returned {
                        QemuShutdownRung::ControlQuit
                    } else {
                        QemuShutdownRung::Reap
                    },
                },
            ));
        }
        if self.begin_failure.is_some()
            || self
                .observations
                .iter()
                .any(|(before, after)| before.is_some() || after.is_some())
            || self.completion_failure.is_some()
        {
            return Err(QemuNodeError::ShutdownOriginal {
                begin: self.begin_failure,
                observations: self.observations,
                completion_effect: self.completion_effect,
                completion: self.completion_failure,
                report: self.progress.report(),
            });
        }
        match self.progress.failure() {
            Some(source) => Err(QemuNodeError::from_shutdown(source)),
            None => Ok(()),
        }
    }

    fn complete(&mut self) {
        if self.completion_attempted {
            return;
        }
        self.completion_attempted = true;
        self.history_version += 1;
        if let Some(guard) = &self.guard {
            let (effect, result) = guard.complete_observed();
            // The effect marker survives an independent completion post refusal.
            self.completion_effect = effect;
            self.completion_failure = result.err();
        }
        self.completion_returned = true;
        // No command borrower survives this point. The saved raw result is
        // history; dropping the completed/expired guard does not grant new work
        // and avoids retaining one operation record for each closed node.
        self.guard = None;
    }

    /// Continues the same child closure without renewing its Original.
    ///
    /// # Errors
    /// Returns each new logical failure journal before factual closure, or the
    /// saved refusal while the actual child remains live or indeterminate.
    pub(super) fn close(
        &mut self,
        child: &mut QemuNodeProcessControl,
        channels: &mut QemuNodeChannels,
        lifecycle_state: &mut QemuNodeLifecycleState,
        policy: QemuShutdownPolicy,
        supervisor: Option<&HostOperationSupervisor>,
    ) -> Result<QemuShutdownReport, QemuNodeError> {
        let previously_reaped = self.progress.reaped;
        // This is the actual retained child's nonblocking physical status, not
        // permission for another command. It remains observable after expiry.
        if child.reaped() {
            self.progress.observe_reaped();
        } else if self.begin_attempted {
            match child.try_wait_natural_exit() {
                Ok(_) if child.reaped() => self.progress.observe_reaped(),
                Ok(_) => {}
                Err(source) => {
                    if self.progress.retain_observation_failure(source) {
                        self.history_version += 1;
                    }
                }
            }
        }
        if !self.progress.reaped {
            self.begin(supervisor);
            if self.begin_returned && self.begin_failure.is_none() {
                if !self.ladder_attempted {
                    self.ladder_attempted = true;
                    self.history_version += 1;
                }
                let mut target = QemuNodeShutdownTarget {
                    child: &mut *child,
                    plugin_control: channels.plugin_control.as_mut(),
                    qmp_machine_control: channels.qmp_machine_control.as_mut(),
                    supervisor,
                    guard: self.guard.as_ref(),
                    observations: &mut self.observations,
                    history_version: &mut self.history_version,
                };
                // The progress owner saves every output before this result is
                // interpreted. A negative or unwind never rewinds its cursor.
                self.progress.advance(&mut target, policy);
            }
        }
        if child.reaped() {
            self.progress.observe_reaped();
        }
        if self.progress.reaped {
            self.complete();
            channels
                .qmp_machine_control
                .retire_process_scoped_endpoints_after_reap();
            *lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
        }
        // Only the physical-close API acknowledges delivery of history.
        // The same journal's health query remains negative thereafter.
        if self.failed() && (!self.progress.reaped || self.reported_version != self.history_version)
        {
            self.reported_version = self.history_version;
            self.health()?;
        }
        if previously_reaped {
            return Ok(QemuShutdownReport {
                attempts: Vec::new(),
                failures: Vec::new(),
                reaped: true,
                leaked: false,
            });
        }
        Ok(self.progress.report())
    }
}

impl QemuNodeShutdownTarget<'_> {
    /// Checks copyable unit/reap outputs under the same saved-guard bracket.
    ///
    /// Owning outputs must use the observed form so a refused post retains them.
    ///
    /// # Errors
    /// Returns the first effect failure, or the saved Original pre/post refusal.
    pub(super) fn under_original<T: Copy>(
        &mut self,
        rung: QemuShutdownRung,
        effect: impl FnOnce(&mut Self) -> Result<T, QemuShutdownTargetError>,
    ) -> Result<T, QemuShutdownTargetError> {
        let (output, status) = self.under_original_observed(rung, effect);
        status?;
        output.ok_or_else(|| {
            QemuShutdownTargetError::new("child cleanup rung", "returned output is absent")
        })
    }

    /// Saves the actual returned work output before its independent postcheck.
    ///
    /// # Errors
    /// The status retains the first pre/effect failure or independent post,
    /// while an output remains present only if the actual effect returned one.
    pub(super) fn under_original_observed<T>(
        &mut self,
        rung: QemuShutdownRung,
        effect: impl FnOnce(&mut Self) -> Result<T, QemuShutdownTargetError>,
    ) -> (Option<T>, Result<(), QemuShutdownTargetError>) {
        let index = match rung {
            QemuShutdownRung::ControlQuit => 0,
            QemuShutdownRung::QmpQuit => 1,
            QemuShutdownRung::Sigterm => 2,
            QemuShutdownRung::Sigkill => 3,
            QemuShutdownRung::Reap => 4,
        };
        let original = self.guard;
        let before = original.and_then(|original| original.wait_slice().err());
        let work = match before {
            Some(first) => {
                if self.observations[index].0.is_none() {
                    self.observations[index].0 = Some(first);
                    *self.history_version += 1;
                }
                Err(QemuShutdownTargetError::new(
                    "enter child cleanup rung",
                    first.to_string(),
                ))
            }
            None => effect(self),
        };
        // Preserve disposition before the independently fallible post. A
        // refused entry suppresses work but still executes this same bracket.
        let (output, first) = match work {
            Ok(output) => (Some(output), None),
            Err(first) => (None, Some(first)),
        };
        let after = original.and_then(|original| original.wait_slice().err());
        if let Some(after) = after {
            if self.observations[index].1.is_none() {
                self.observations[index].1 = Some(after);
                *self.history_version += 1;
            }
        }
        let status = match (first, after) {
            (Some(first), _) => Err(first),
            (None, Some(after)) => Err(QemuShutdownTargetError::new(
                "post child cleanup rung",
                after.to_string(),
            )),
            (None, None) => Ok(()),
        };
        (output, status)
    }
}

#[cfg(test)]
mod tests;
