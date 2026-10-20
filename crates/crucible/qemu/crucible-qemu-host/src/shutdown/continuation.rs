//! Fixed-capacity progress for one shutdown ladder and one child generation.
//!
//! A rung is marked entered before either its command or wait. A panic keeps
//! that marker, so a later physical observation cannot silently resend it.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Failure {
    Target(usize),
    Leaked,
}

#[derive(Debug)]
/// Stores fixed per-rung receipts without a second heap-backed report owner.
pub(crate) struct QemuShutdownProgress {
    next: usize,
    entered: Option<QemuShutdownRung>,
    attempts: [Option<QemuShutdownAttempt>; 4],
    failures: [Option<QemuShutdownFailure>; 6],
    failure: Option<Failure>,
    /// Actual target or retained process observation of physical reap.
    pub(crate) reaped: bool,
    reap_attempted: bool,
}

impl QemuShutdownProgress {
    /// Creates unentered progress for one actual child generation.
    pub(crate) const fn new() -> Self {
        Self {
            next: 0,
            entered: None,
            attempts: [None; 4],
            failures: [const { None }; 6],
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
        self.entered.is_some() || self.failure.is_some()
    }

    /// Saves the first independent parent-observation error before status use.
    pub(crate) fn retain_observation_failure(&mut self, source: QemuShutdownTargetError) -> bool {
        if self.failures[5].is_some() {
            return false;
        }
        self.failures[5] = Some(QemuShutdownFailure {
            rung: QemuShutdownRung::Reap,
            source,
        });
        if self.failure.is_none() {
            self.failure = Some(Failure::Target(5));
        }
        true
    }

    /// Projects the retained typed failure with its actual preceding outputs.
    pub(crate) fn failure(&self) -> Option<QemuShutdownError> {
        if let Some(rung) = self.entered {
            return Some(QemuShutdownError::Uncertain { rung });
        }
        match self.failure {
            Some(Failure::Target(index)) => {
                self.failures[index]
                    .as_ref()
                    .map(|failure| QemuShutdownError::Target {
                        rung: failure.rung,
                        source: failure.source.clone(),
                        report: self.report(),
                    })
            }
            Some(Failure::Leaked) => Some(QemuShutdownError::LeakedChild {
                report: self.report(),
            }),
            None => None,
        }
    }

    /// Projects the existing public report without consuming retained progress.
    pub(crate) fn report(&self) -> QemuShutdownReport {
        QemuShutdownReport {
            attempts: self.attempts.iter().flatten().copied().collect(),
            failures: self.failures.iter().flatten().cloned().collect(),
            reaped: self.reaped,
            leaked: matches!(self.failure, Some(Failure::Leaked)),
        }
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
            if self
                .attempts
                .iter()
                .flatten()
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
                self.failures[index] = Some(QemuShutdownFailure { rung, source });
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
            self.attempts[index] = Some(QemuShutdownAttempt {
                rung,
                wait,
                child: output.unwrap_or(QemuChildWait::StillRunning),
            });
            if let Err(source) = status {
                self.failures[index] = Some(QemuShutdownFailure { rung, source });
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
                    self.failures[4] = Some(QemuShutdownFailure {
                        rung: QemuShutdownRung::Reap,
                        source,
                    });
                    self.failure = Some(Failure::Target(4));
                }
            }
            self.entered = None;
        }
    }
}

#[cfg(test)]
mod tests;
