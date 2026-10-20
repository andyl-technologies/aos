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
enum CleanupOriginal {
    Owned {
        original: HostOperationGuard,
        supervisor: HostOperationSupervisor,
    },
    #[cfg(target_os = "linux")]
    Target(crate::linux_attempt_host::TargetCleanupOriginal),
    #[cfg(target_os = "linux")]
    Source(crate::linux_attempt_host::SourceCleanupOriginal),
}

impl CleanupOriginal {
    fn original(&self) -> &HostOperationGuard {
        match self {
            Self::Owned { original, .. } => original,
            #[cfg(target_os = "linux")]
            Self::Target(original) => original.original(),
            #[cfg(target_os = "linux")]
            Self::Source(original) => original.original(),
        }
    }

    fn view(&self) -> crate::ram_control::RamCleanupOriginal<'_> {
        match self {
            Self::Owned {
                original,
                supervisor,
            } => crate::ram_control::RamCleanupOriginal::direct(original, supervisor),
            #[cfg(target_os = "linux")]
            Self::Target(original) => crate::ram_control::RamCleanupOriginal::target(original),
            #[cfg(target_os = "linux")]
            Self::Source(original) => crate::ram_control::RamCleanupOriginal::source(original),
        }
    }
}

#[derive(Debug)]
/// Owns the sole cleanup entry and all bounded child-shutdown observations.
pub(super) struct ChildShutdown {
    progress: crate::shutdown::QemuShutdownProgress,
    begin_attempted: bool,
    begin_returned: bool,
    guard: Option<CleanupOriginal>,
    ram: super::ram_cleanup::RamCleanup,
    begin_failure: Option<HostSupervisionError>,
    observations: [(Option<HostSupervisionError>, Option<HostSupervisionError>); 5],
    completion_attempted: bool,
    completion_returned: bool,
    completion_effect: bool,
    completion_failure: Option<HostSupervisionError>,
    ladder_attempted: bool,
    history_pending: bool,
}

impl ChildShutdown {
    /// Creates the unentered owner before the containing node is published.
    pub(super) const fn new() -> Self {
        Self {
            progress: crate::shutdown::QemuShutdownProgress::new(),
            begin_attempted: false,
            begin_returned: false,
            guard: None,
            ram: super::ram_cleanup::RamCleanup::new(),
            begin_failure: None,
            observations: [(None, None); 5],
            completion_attempted: false,
            completion_returned: false,
            completion_effect: false,
            completion_failure: None,
            ladder_attempted: false,
            history_pending: false,
        }
    }

    pub(super) fn retain_ram_refusal(&mut self, first: QemuNodeError) {
        self.ram.retain_stage(first);
        self.history_pending |= self.ram.take_unreported();
    }

    pub(super) fn entered(&self) -> bool {
        self.begin_attempted
    }

    #[cfg(target_os = "linux")]
    pub(super) fn retain_target_original(
        &mut self,
        original: crate::linux_attempt_host::TargetCleanupOriginal,
    ) {
        if !self.begin_attempted {
            self.begin_failure = original
                .checked_original()
                .and_then(|original| original.verify_operation_class(HostOperationClass::Cleanup))
                .err();
            self.guard = Some(CleanupOriginal::Target(original));
            self.begin_attempted = true;
            self.begin_returned = true;
            self.history_pending = true;
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn retain_source_original(
        &mut self,
        original: crate::linux_attempt_host::SourceCleanupOriginal,
    ) {
        if !self.begin_attempted {
            self.begin_failure = original
                .checked_original()
                .and_then(|original| original.verify_operation_class(HostOperationClass::Cleanup))
                .err();
            self.guard = Some(CleanupOriginal::Source(original));
            self.begin_attempted = true;
            self.begin_returned = true;
            self.history_pending = true;
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn from_ram(
        ram: super::ram_cleanup::RamCleanup,
        original: Option<crate::linux_attempt_host::TargetCleanupOriginal>,
    ) -> Self {
        let mut retained = Self::new();
        retained.ram = ram;
        if let Some(original) = original {
            retained.retain_target_original(original);
        }
        retained
    }

    fn begin(&mut self, supervisor: Option<&HostOperationSupervisor>) {
        if self.begin_attempted {
            return;
        }
        self.begin_attempted = true;
        self.history_pending = true;
        match supervisor
            .map(|owner| owner.begin(HostOperationClass::Cleanup))
            .transpose()
        {
            Ok(guard) => {
                self.guard =
                    guard
                        .zip(supervisor)
                        .map(|(original, supervisor)| CleanupOriginal::Owned {
                            original,
                            supervisor: supervisor.clone(),
                        })
            }
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
            || self.ram.failed()
    }

    /// Preserves logical failure independently of physical resource closure.
    ///
    /// # Errors
    /// Returns the saved Original, rung, completion or interrupted disposition.
    pub(super) fn health(&self) -> Result<(), QemuNodeError> {
        match (self.process_health(), self.ram.failure()) {
            (Ok(()), None) => Ok(()),
            (Err(first), None) | (Ok(()), Some(first)) => Err(first),
            (Err(first), Some(ram)) => Err(QemuNodeError::ShutdownAndRam {
                first: Box::new(first),
                ram: Box::new(ram),
            }),
        }
    }

    fn process_health(&self) -> Result<(), QemuNodeError> {
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
        self.history_pending = true;
        if let Some(CleanupOriginal::Owned {
            original: guard, ..
        }) = &self.guard
        {
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

    pub(super) fn physically_returned(&self) -> bool {
        self.completion_returned
    }

    /// Completes only after every actual RAM body and controller has returned.
    pub(super) fn finish_ram(
        &mut self,
        close: impl FnOnce(
            Option<crate::ram_control::RamCleanupOriginal<'_>>,
            &mut super::ram_cleanup::RamCleanup,
        ) -> bool,
    ) -> Result<(), QemuNodeError> {
        let returned = close(
            self.guard.as_ref().map(CleanupOriginal::view),
            &mut self.ram,
        );
        self.history_pending |= self.ram.take_unreported();
        if returned {
            self.complete();
        }
        if self.failed() && (!returned || self.history_pending) {
            self.history_pending = false;
            self.health()?;
        }
        if returned {
            Ok(())
        } else {
            Err(QemuNodeError::RamCleanupPending)
        }
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
        self.close_mode(child, channels, lifecycle_state, policy, supervisor, false)
    }

    /// Preserves the same cleanup state when an indeterminate node is retained.
    pub(super) fn contain(
        &mut self,
        child: &mut QemuNodeProcessControl,
        channels: &mut QemuNodeChannels,
        lifecycle_state: &mut QemuNodeLifecycleState,
        policy: QemuShutdownPolicy,
        supervisor: Option<&HostOperationSupervisor>,
    ) -> Result<QemuShutdownReport, QemuNodeError> {
        self.close_mode(child, channels, lifecycle_state, policy, supervisor, true)
    }

    fn close_mode(
        &mut self,
        child: &mut QemuNodeProcessControl,
        channels: &mut QemuNodeChannels,
        lifecycle_state: &mut QemuNodeLifecycleState,
        policy: QemuShutdownPolicy,
        supervisor: Option<&HostOperationSupervisor>,
        containment: bool,
    ) -> Result<QemuShutdownReport, QemuNodeError> {
        let output = self.close_process(
            child,
            Some(channels.plugin_control.as_mut()),
            Some(channels.qmp_machine_control.as_mut()),
            policy,
            supervisor,
            containment,
        );
        if child.reaped() {
            channels
                .qmp_machine_control
                .retire_process_scoped_endpoints_after_reap();
            *lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
        }
        output
    }

    pub(super) fn close_unconstructed(
        &mut self,
        child: &mut QemuNodeProcessControl,
        supervisor: Option<&HostOperationSupervisor>,
    ) -> Result<QemuShutdownReport, QemuNodeError> {
        self.close_process(
            child,
            None,
            None,
            QemuShutdownPolicy {
                control_quit_wait: Duration::ZERO,
                qmp_quit_wait: Duration::ZERO,
                sigterm_wait: Duration::ZERO,
                sigkill_wait: DROP_REAP_DEADLINE,
                reap_wait: DROP_REAP_DEADLINE,
            },
            supervisor,
            true,
        )
    }

    fn close_process<'plugin, 'qmp>(
        &mut self,
        child: &mut QemuNodeProcessControl,
        plugin_control: Option<&mut (dyn QemuPluginIpcControlChannel + 'plugin)>,
        qmp_machine_control: Option<&mut (dyn QemuQmpMachineControlChannel + 'qmp)>,
        policy: QemuShutdownPolicy,
        supervisor: Option<&HostOperationSupervisor>,
        containment: bool,
    ) -> Result<QemuShutdownReport, QemuNodeError> {
        let previously_reaped = self.progress.reaped;
        self.begin(supervisor);
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
                        self.history_pending = true;
                    }
                }
            }
        }
        if !self.progress.reaped {
            self.begin(supervisor);
            if self.begin_returned && self.begin_failure.is_none() {
                if !self.ladder_attempted {
                    self.ladder_attempted = true;
                    self.history_pending = true;
                }
                let mut target = QemuNodeShutdownTarget {
                    child: &mut *child,
                    plugin_control,
                    qmp_machine_control,
                    supervisor,
                    guard: self.guard.as_ref().map(CleanupOriginal::original),
                    observations: &mut self.observations,
                    history_pending: &mut self.history_pending,
                };
                // The progress owner saves every output before this result is
                // interpreted. A negative or unwind never rewinds its cursor.
                if containment {
                    self.progress.advance_containment(&mut target, policy);
                } else {
                    self.progress.advance(&mut target, policy);
                }
            }
        }
        if child.reaped() {
            self.progress.observe_reaped();
        }
        // Only the physical-close API acknowledges delivery of history.
        // The same journal's health query remains negative thereafter.
        if self.failed() && (!self.progress.reaped || self.history_pending) {
            self.history_pending = false;
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

impl QemuNodeShutdownTarget<'_, '_, '_> {
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
                    *self.history_pending = true;
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
                *self.history_pending = true;
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
