//! Keeps one source's cancellation, physical join and borrowed-original history.

use super::*;
use crucible_engine::BackendOperationalCause;

/// Preserves a source's raw return history independently of physical join.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("RAM source return refused: {self:?}")]
pub struct QemuRamSourceStopHistory {
    /// Same actual creation Original's independent pre/post observations.
    pub birth: (Option<HostSupervisionError>, Option<HostSupervisionError>),
    /// First actual cancellation transport failure.
    pub cancellation: Option<BackendOperationalCause>,
    /// First same-original failures around cancellation, waiting, and joining.
    pub observations: [(Option<HostSupervisionError>, Option<HostSupervisionError>); 3],
    /// The original failure returned by the actual joined worker.
    pub worker: Option<QemuRamWorkerFailure>,
    /// Actual caught panic payload and original loan, retained after body removal.
    pub panic: Option<QemuRamWorkerPanic>,
    /// First unexpected actual native join result, independent of Original status.
    pub native: Option<NativeJoinError>,
    /// Latest attempted libc status, including known busy or physical zero.
    pub native_status: Option<i32>,
    /// Whether an entered cancellation or join has no returned disposition.
    pub uncertain: bool,
}

#[derive(Debug)]
pub(super) struct StopState {
    cancel_entered: bool,
    cancel_returned: bool,
    join_returned: bool,
    outcome_captured: bool,
    history: QemuRamSourceStopHistory,
    version: u8,
    reported: u8,
}

impl StopState {
    /// Observes this source's recorded physical join or explicit no-birth return.
    pub(super) const fn join_returned(&self) -> bool {
        self.join_returned
    }

    pub(super) const fn new() -> Self {
        Self {
            cancel_entered: false,
            cancel_returned: false,
            join_returned: false,
            outcome_captured: false,
            history: QemuRamSourceStopHistory {
                birth: (None, None),
                cancellation: None,
                observations: [(None, None); 3],
                worker: None,
                panic: None,
                native: None,
                native_status: None,
                uncertain: false,
            },
            version: 0,
            reported: 0,
        }
    }

    fn observe(&mut self, index: usize, after: bool, failure: Option<HostSupervisionError>) {
        let slot = if after {
            &mut self.history.observations[index].1
        } else {
            &mut self.history.observations[index].0
        };
        if slot.is_none() && failure.is_some() {
            *slot = failure;
            self.version += 1;
        }
    }

    fn failed(&self) -> bool {
        self.history.birth.0.is_some()
            || self.history.birth.1.is_some()
            || self.history.cancellation.is_some()
            || self.history.worker.is_some()
            || self.history.panic.is_some()
            || self.history.native.is_some()
            || self.history.uncertain
            || self
                .history
                .observations
                .iter()
                .any(|(pre, post)| pre.is_some() || post.is_some())
    }
}

impl QemuRamSourceService {
    /// Cancels and joins this same source under its caller's saved Cleanup.
    ///
    /// The service never moves on refusal. A nonblocking native query can
    /// observe task/TLS return after expiry; waiting still requires the same
    /// live Original. The boolean records actual physical join before post.
    ///
    /// # Errors
    /// The status preserves cancellation, worker and same-original refusals.
    /// Newly observed failure is delivered before the caller may remove a joined
    /// body. A later factual close leaves the saved history unchanged.
    pub fn stop(
        &mut self,
        original: Option<crate::ram_control::RamCleanupOriginal<'_>>,
    ) -> (bool, Result<(), QemuRamSourceStopHistory>) {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.native.belongs_to_current_process())
        {
            self.stop
                .history
                .native
                .get_or_insert(NativeJoinError::ForeignProcess);
            return (false, Err(self.stop.history.clone()));
        }
        if self.stop.history.birth != (self.birth_before, self.birth_after) {
            self.stop.history.birth = (self.birth_before, self.birth_after);
            self.stop.version += 1;
        }
        if !self.spawn_attempted {
            self.failure.no_birth(None);
            self.stop.join_returned = true;
            self.capture_returned_outcome();
            return self.stop_observation();
        }
        if self.spawn_returned && !self.worker_started {
            self.stop.join_returned = true;
            self.capture_returned_outcome();
            return self.stop_observation();
        }
        if !self.stop.cancel_entered {
            let before = self.stop_original_check(original).err();
            self.stop.observe(0, false, before);
            self.stop.cancel_entered = true;
            self.cancellation.store(true, Ordering::Release);
            if let Err(first) = self.wake.shutdown(Shutdown::Both) {
                self.stop.history.cancellation = Some(BackendOperationalCause::new(first));
                self.stop.version += 1;
            }
            self.stop.cancel_returned = true;
            let after = self.stop_original_check(original).err();
            self.stop.observe(0, true, after);
        }
        if !self.stop.cancel_returned {
            if !self.stop.history.uncertain {
                self.stop.history.uncertain = true;
                self.stop.version += 1;
            }
            return self.stop_observation();
        }

        loop {
            if self.stop.join_returned {
                self.capture_returned_outcome();
                return self.stop_observation();
            }
            let before = self.stop_original_check(original).err();
            self.stop.observe(2, false, before);
            let observed = match self.worker.as_mut() {
                Some(worker) => {
                    let observed = worker.native.poll();
                    self.stop.history.native_status = worker.native.last_status();
                    observed
                }
                None => Err(NativeJoinError::MissingOwner),
            };
            match observed {
                Ok(NativeJoinObservation::Returned) => {
                    // The native owner latched zero before this independent
                    // status and result observation; no subsequent poll joins.
                    self.stop.join_returned = true;
                    if let Some(join) = &mut self.launch_join {
                        join.joined();
                    }
                    self.capture_returned_outcome();
                    drop(self.worker.take());
                }
                Ok(NativeJoinObservation::Pending) => {}
                Err(first) => {
                    if self.stop.history.native.is_none() {
                        self.stop.history.native = Some(first);
                        self.stop.version += 1;
                    }
                }
            }
            let after = self.stop_original_check(original).err();
            self.stop.observe(2, true, after);
            if self.stop.join_returned
                || self.stop.history.native.is_some()
                || before.is_some()
                || after.is_some()
            {
                return self.stop_observation();
            }

            let before = self.stop_original_check(original);
            self.stop.observe(1, false, before.as_ref().err().copied());
            if let Ok(slice) = before {
                thread::sleep(slice.min(Duration::from_millis(20)));
            }
            let after = self.stop_original_check(original);
            self.stop.observe(1, true, after.as_ref().err().copied());
            if before.is_err() || after.is_err() {
                // No effect follows refused entry. The independently evaluated
                // post is retained even when the precheck already refused.
                return self.stop_observation();
            }
        }
    }

    fn capture_returned_outcome(&mut self) {
        if self.stop.outcome_captured {
            return;
        }
        let outcome = match self.worker.as_ref() {
            Some(worker) => worker.outcome.snapshot(),
            None => self.failure.snapshot(),
        };
        if let Some(first) = outcome.failure
            && self.stop.history.worker.is_none()
        {
            self.stop.history.worker = Some(first);
            self.stop.version += 1;
        }
        if let Some(panic) = outcome.panic
            && self.stop.history.panic.is_none()
        {
            self.stop.history.panic = Some(panic);
            self.stop.version += 1;
        }
        self.stop.outcome_captured = outcome.delivered;
        if (!outcome.delivered || outcome.uncertain) && !self.stop.history.uncertain {
            self.stop.history.uncertain = true;
            self.stop.version += 1;
        }
    }

    fn stop_original_check(
        &self,
        original: Option<crate::ram_control::RamCleanupOriginal<'_>>,
    ) -> Result<Duration, HostSupervisionError> {
        let original = original.ok_or(HostSupervisionError::Unavailable)?;
        original.wait_slice()
    }

    fn stop_observation(&mut self) -> (bool, Result<(), QemuRamSourceStopHistory>) {
        let joined = self.stop.join_returned;
        let failure = self.stop.failed()
            && (!joined || !self.stop.outcome_captured || self.stop.reported != self.stop.version);
        if failure {
            self.stop.reported = self.stop.version;
            (joined, Err(self.stop.history.clone()))
        } else {
            (joined, Ok(()))
        }
    }
}

#[cfg(test)]
mod tests;
