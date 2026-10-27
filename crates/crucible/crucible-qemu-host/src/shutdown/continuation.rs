//! Fixed-capacity progress for one shutdown ladder and one child generation.
//!
//! A rung is marked entered before either its command or wait. A panic keeps
//! that marker, so a later physical observation cannot silently resend it.

use super::*;
use crucible_host_resources::host_supervision::HostSupervisionError;

#[derive(Clone, Copy, Debug)]
enum Failure {
    Target(usize),
    Leaked,
}

#[derive(Debug)]
/// Stores rung progress in the launch's original prepaid report cells.
pub(crate) struct QemuShutdownProgress {
    next: usize,
    entered: Option<QemuShutdownRung>,
    journal: ShutdownJournal,
    failure: Option<Failure>,
    /// Actual target or retained process observation of physical reap.
    pub(crate) reaped: bool,
    reap_attempted: bool,
}

impl QemuShutdownProgress {
    /// Creates standalone component progress before any target effect.
    pub(crate) fn new() -> Self {
        Self::with_journal(ShutdownJournal::component())
    }

    /// Takes the native launch's existing storage; absence permits no effect.
    pub(crate) fn from_launch(cleanup: &crate::launch_cleanup::LaunchCleanup) -> Self {
        Self::with_journal(
            cleanup
                .claim_shutdown_journal()
                .unwrap_or_else(ShutdownJournal::empty),
        )
    }

    fn with_journal(journal: ShutdownJournal) -> Self {
        Self {
            next: 0,
            entered: None,
            journal,
            failure: None,
            reaped: false,
            reap_attempted: false,
        }
    }

    /// Saves a physical observation without erasing logical failure.
    pub(crate) fn observe_reaped(&mut self) {
        self.reaped = true;
    }

    /// Reports saved failure or an entered invocation without a return.
    pub(crate) fn failed(&self) -> bool {
        !self.journal.available() || self.entered.is_some() || self.failure.is_some()
    }

    /// Saves the first independent parent-observation error before status use.
    pub(crate) fn retain_observation_failure(&mut self, source: QemuShutdownTargetError) -> bool {
        if !self.journal.available() || self.journal.failure(5).is_some() {
            return false;
        }
        self.journal.record_failure(
            5,
            QemuShutdownFailure {
                rung: QemuShutdownRung::Reap,
                source,
            },
        );
        if self.failure.is_none() {
            self.failure = Some(Failure::Target(5));
        }
        true
    }

    /// Projects the retained typed failure with its actual preceding outputs.
    pub(crate) fn failure(&self) -> Option<QemuShutdownError> {
        if !self.journal.available() {
            return Some(QemuShutdownError::StorageUnavailable);
        }
        if let Some(rung) = self.entered {
            return Some(QemuShutdownError::Uncertain { rung });
        }
        match self.failure {
            Some(Failure::Target(index)) => self.journal.failure(index).and_then(|failure| {
                Some(QemuShutdownError::Target {
                    rung: failure.rung,
                    source: self.journal.refusal(index)?,
                    report: self.report(),
                })
            }),
            Some(Failure::Leaked) => Some(QemuShutdownError::LeakedChild {
                report: self.report(),
            }),
            None => None,
        }
    }

    /// Projects the existing public report without consuming retained progress.
    pub(crate) fn report(&self) -> QemuShutdownReport {
        self.journal
            .report(self.reaped, matches!(self.failure, Some(Failure::Leaked)))
    }

    /// Retains the same cleanup Original's pre/post observations in prepaid cells.
    pub(crate) fn original_observations(
        &self,
        observations: &[(Option<HostSupervisionError>, Option<HostSupervisionError>); 5],
    ) -> QemuShutdownObservations {
        self.journal.original_observations(observations)
    }

    /// Advances the same ladder and returns its ordinary public output.
    ///
    /// # Errors
    /// Returns the saved target, reap or uncertain entered disposition.
    pub(crate) fn run<T: QemuShutdownTarget>(
        &mut self,
        target: &mut T,
        policy: QemuShutdownPolicy,
    ) -> Result<QemuShutdownReport, QemuShutdownError> {
        self.advance(target, policy);
        match self.failure() {
            Some(first) => Err(first),
            None => Ok(self.report()),
        }
    }

    /// Saves each attempted effect and returned output before interpretation.
    /// Continues the same ladder without introducing polite guest commands.
    ///
    /// Existing entered/failed/reaped phases retain their exact disposition.
    pub(crate) fn advance_containment<T: QemuShutdownTarget>(
        &mut self,
        target: &mut T,
        policy: QemuShutdownPolicy,
    ) {
        if self.entered.is_none() && !self.failed() {
            self.next = self.next.max(3);
        }
        self.advance(target, policy);
    }

    pub(crate) fn advance<T: QemuShutdownTarget>(
        &mut self,
        target: &mut T,
        policy: QemuShutdownPolicy,
    ) {
        if target.child_reaped() {
            self.observe_reaped();
        }
        if self.failed() || self.reaped {
            return;
        }
        let rungs = [
            (QemuShutdownRung::ControlQuit, policy.control_quit_wait),
            (QemuShutdownRung::QmpQuit, policy.qmp_quit_wait),
            (QemuShutdownRung::Sigterm, policy.sigterm_wait),
            (QemuShutdownRung::Sigkill, policy.sigkill_wait),
        ];
        while let Some(&(rung, wait)) = rungs.get(self.next) {
            // A prior returned exit survives even an interrupted factual
            // observer; resuming this owner cannot enter another command.
            if (0..4)
                .filter_map(|index| self.journal.attempt(index))
                .any(|attempt| attempt.child == QemuChildWait::Exited)
            {
                break;
            }
            if target.child_reaped() {
                self.observe_reaped();
                break;
            }
            let index = self.next;
            self.next += 1;
            self.entered = Some(rung);
            let effect = execute_shutdown_rung(target, rung);
            let effect_failed = effect.is_err();
            if let Err(source) = effect {
                self.journal
                    .record_failure(index, QemuShutdownFailure { rung, source });
            }
            // The actual child can be reaped even when the independent post
            // refused. Preserve that error and stop before another effect.
            if target.child_reaped() {
                self.observe_reaped();
                self.entered = None;
                break;
            }
            if effect_failed {
                self.entered = None;
                continue;
            }
            let (output, status) = target.wait_for_exit_observed(rung, wait);
            self.journal.record_attempt(
                index,
                QemuShutdownAttempt {
                    rung,
                    wait,
                    child: output.unwrap_or(QemuChildWait::StillRunning),
                },
            );
            if let Err(source) = status {
                self.journal
                    .record_failure(index, QemuShutdownFailure { rung, source });
            }
            self.entered = None;
            if target.child_reaped() {
                self.observe_reaped();
                break;
            }
            if output == Some(QemuChildWait::Exited) {
                break;
            }
        }
        // No subsequent call repeats a final reap wait or restarts its bound.
        if target.child_reaped() {
            self.observe_reaped();
        }
        if !self.reaped && !self.reap_attempted {
            self.reap_attempted = true;
            self.entered = Some(QemuShutdownRung::Reap);
            match target.reap(policy.reap_wait) {
                Ok(QemuReap::Reaped) => self.reaped = true,
                Ok(QemuReap::StillAlive) => self.failure = Some(Failure::Leaked),
                Err(source) => {
                    self.journal.record_failure(
                        4,
                        QemuShutdownFailure {
                            rung: QemuShutdownRung::Reap,
                            source,
                        },
                    );
                    self.failure = Some(Failure::Target(4));
                }
            }
            self.entered = None;
        }
    }
}

#[cfg(test)]
mod tests;
