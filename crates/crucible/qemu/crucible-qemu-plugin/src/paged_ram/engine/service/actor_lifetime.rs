//! Retains the isolated actor's original failure through native role disposition.

use super::*;
use crucible_qemu_protocol::ram_control::{RamControlFaultActorFailure, RamControlFaultActorReport};

#[derive(Default)]
pub(in crate::paged_ram::engine) struct ActorLifetime {
    state: Mutex<ActorState>,
}

#[derive(Default)]
struct ActorState {
    thread_id: u64,
    exit_requested: bool,
    failure: Option<RamError>,
    cleanup_failure: Option<RamError>,
    membership_released: bool,
}

impl ActorLifetime {
    pub(in crate::paged_ram::engine) fn admitted(&self, thread_id: u64) -> Result<(), RamError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RamError::Invariant("fault actor lifetime poisoned"))?;
        state.thread_id = thread_id;
        // Native admission starts a new membership without erasing failure history.
        state.membership_released = false;
        Ok(())
    }

    pub(in crate::paged_ram::engine) fn request_exit(&self) -> Result<(), RamError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("fault actor request unavailable"))?;
        if state.thread_id == 0 || state.failure.is_some() || state.membership_released {
            return Err(RamError::Invariant("fault actor is not live"));
        }
        state.exit_requested = true;
        Ok(())
    }

    pub(in crate::paged_ram::engine) fn poll(&self) -> Result<(), RamError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RamError::Invariant("fault actor poll publication poisoned"))?;
        if let Some(first) = &state.failure {
            return Err(first.clone());
        }
        if state.exit_requested {
            return Err(RamError::FaultActorTestExit);
        }
        Ok(())
    }

    pub(in crate::paged_ram::engine) fn failed(&self, failure: RamError) {
        let mut state = self.disposition_history();
        // The first concrete cause remains retained after the worker returns.
        if state.failure.is_none() {
            state.failure = Some(failure);
        }
    }

    pub(in crate::paged_ram::engine) fn released(&self) {
        self.disposition_history().membership_released = true;
    }

    pub(in crate::paged_ram::engine) fn cleanup_failed(&self, failure: RamError) {
        let mut state = self.disposition_history();
        if state.cleanup_failure.is_none() {
            state.cleanup_failure = Some(failure.clone());
        }
        if state.failure.is_none() {
            state.failure = Some(failure);
        }
    }

    // Recording failure or actual release must not bypass native cleanup when
    // the journal is poisoned. Entry, polling and observation still refuse it.
    fn disposition_history(&self) -> std::sync::MutexGuard<'_, ActorState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(in crate::paged_ram::engine) fn report(
        &self,
        worker_generation: u64,
    ) -> Result<Option<RamControlFaultActorReport>, RamError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("fault actor report unavailable"))?;
        if state.thread_id == 0 || (state.membership_released && state.failure.is_none()) {
            return Ok(None);
        }
        let failure = state.failure.as_ref().map(|failure| match failure {
            RamError::FaultActorTestExit => RamControlFaultActorFailure::RequestedExit,
            RamError::Io(source) => RamControlFaultActorFailure::Io {
                errno: source.raw_os_error().unwrap_or(0),
            },
            _ => RamControlFaultActorFailure::Other,
        });
        Ok(Some(RamControlFaultActorReport {
            worker_generation,
            thread_id: state.thread_id,
            exit_requested: state.exit_requested,
            failure,
            membership_released: state.membership_released,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_cause_remains_independent_of_the_original_actor_failure() {
        let state = ActorLifetime::default();
        state.admitted(123).unwrap();
        let first = RamError::from(std::io::Error::from_raw_os_error(libc::EIO));
        let cleanup = RamError::from(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));

        state.failed(first.clone());
        state.cleanup_failed(cleanup.clone());
        state.cleanup_failed(RamError::Invariant("later cleanup refusal"));

        let retained = state.state.lock().unwrap();
        assert_eq!(retained.failure.as_ref(), Some(&first));
        assert_eq!(retained.cleanup_failure.as_ref(), Some(&cleanup));
    }

    #[test]
    fn original_failure_terminates_later_actor_polls() {
        let state = ActorLifetime::default();
        state.admitted(123).unwrap();
        assert!(state.poll().is_ok());

        let first = RamError::from(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        state.failed(first.clone());

        assert_eq!(state.poll(), Err(first.clone()));
        assert!(state.request_exit().is_err());
        state.released();
        assert_eq!(state.poll(), Err(first));
    }

    #[test]
    fn poisoned_history_retains_failure_and_release_without_reopening_entry() {
        let state = ActorLifetime::default();
        state.admitted(123).unwrap();
        let poisoned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _history = state.state.lock().unwrap();
                    panic!("poison the private history");
                })
                .join()
        });
        assert!(poisoned.is_err());
        assert!(state.admitted(124).is_err());
        assert!(state.poll().is_err());
        assert!(state.request_exit().is_err());
        assert!(state.report(7).is_err());

        let first = RamError::from(std::io::Error::from_raw_os_error(libc::EIO));
        state.failed(first.clone());
        state.failed(RamError::FaultActorTestExit);
        state.released();

        let Err(poisoned) = state.state.lock() else {
            panic!("history must remain poisoned");
        };
        let retained = poisoned.into_inner();
        assert_eq!(retained.thread_id, 123);
        assert_eq!(retained.failure.as_ref(), Some(&first));
        assert!(retained.membership_released);
        assert!(!retained.exit_requested);
        drop(retained);
        assert!(state.report(7).is_err());
    }

    #[test]
    fn busy_history_refuses_diagnostics_and_exit_without_mutating_it() {
        let state = ActorLifetime::default();
        state.admitted(123).unwrap();
        let retained = state.state.lock().unwrap();

        assert!(state.report(7).is_err());
        assert!(state.request_exit().is_err());
        assert!(!retained.exit_requested);
        assert!(retained.failure.is_none());
    }

    #[test]
    fn clean_fork_restarts_publish_the_current_live_thread() {
        let state = ActorLifetime::default();
        assert!(state.report(7).unwrap().is_none());

        for thread_id in [123, 124, 125] {
            state.admitted(thread_id).unwrap();

            let report = state
                .report(7)
                .unwrap()
                .expect("current actor remains observable");
            assert_eq!(report.worker_generation, 7);
            assert_eq!(report.thread_id, thread_id);
            assert!(!report.membership_released);
            assert!(!report.exit_requested);
            assert!(report.failure.is_none());
            assert!(state.poll().is_ok());

            state.released();
            assert!(state.report(7).unwrap().is_none());
        }

        state.admitted(126).unwrap();
        state.request_exit().expect("restarted actor is live");
        assert!(matches!(state.poll(), Err(RamError::FaultActorTestExit)));
        state.failed(std::io::Error::from_raw_os_error(libc::EIO).into());
        state.failed(RamError::FaultActorTestExit);
        state.released();

        let report = state
            .report(7)
            .unwrap()
            .expect("failure remains observable");
        assert_eq!(report.thread_id, 126);
        assert!(report.membership_released);
        assert!(report.exit_requested);
        assert_eq!(
            report.failure,
            Some(RamControlFaultActorFailure::Io { errno: libc::EIO })
        );
        assert!(state.request_exit().is_err());
    }

    #[test]
    fn terminal_report_keeps_original_io_cause_until_role_release() {
        let state = ActorLifetime::default();
        assert!(state.request_exit().is_err());
        state.admitted(123).unwrap();
        state.failed(std::io::Error::from_raw_os_error(libc::EIO).into());
        state.failed(RamError::FaultActorTestExit);
        assert!(state.request_exit().is_err());

        let before = state
            .report(7)
            .unwrap()
            .unwrap_or_else(|| panic!("admitted actor report"));
        assert_eq!(
            before.failure,
            Some(RamControlFaultActorFailure::Io { errno: libc::EIO })
        );
        assert!(!before.membership_released);
        state.released();
        let after = state
            .report(7)
            .unwrap()
            .unwrap_or_else(|| panic!("retained terminal report"));
        assert!(after.membership_released);
        assert_eq!(after.failure, before.failure);
    }

    #[test]
    fn requested_exit_is_returned_by_the_actor_poll() {
        let state = ActorLifetime::default();
        state.admitted(456).unwrap();
        assert!(state.poll().is_ok());
        state
            .request_exit()
            .unwrap_or_else(|error| panic!("live actor request: {error}"));
        assert!(matches!(state.poll(), Err(RamError::FaultActorTestExit)));
        let before = state
            .report(8)
            .unwrap()
            .unwrap_or_else(|| panic!("live report"));
        assert!(before.exit_requested);
        assert!(before.failure.is_none());
        state.failed(RamError::FaultActorTestExit);
        state.released();
        let after = state
            .report(8)
            .unwrap()
            .unwrap_or_else(|| panic!("terminal report"));
        assert_eq!(
            after.failure,
            Some(RamControlFaultActorFailure::RequestedExit)
        );
        assert!(after.membership_released);
    }
}
